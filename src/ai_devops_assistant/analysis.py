"""Shared pipeline tail: rules baseline -> guarded LLM call -> schema validation -> grounding -> merge."""

from __future__ import annotations

import re
import time
from typing import Any, Literal

from pydantic import ValidationError

from ai_devops_assistant.config import Settings
from ai_devops_assistant.guardrails import Budget, estimate_tokens
from ai_devops_assistant.models import AIAnalysis, Category, Diagnosis, Finding, LLMDiagnosis, Usage
from ai_devops_assistant.observability import log_event
from ai_devops_assistant.prompts import SYSTEM_PROMPT, build_user_prompt, request_schema
from ai_devops_assistant.providers import LLMRequest, Provider, ProviderError
from ai_devops_assistant.redaction import redact
from ai_devops_assistant.sanitize import risky_command_reasons

Kind = Literal["ci", "k8s", "terraform"]
_WS = re.compile(r"\s+")


def _norm(text: str) -> str:
    return _WS.sub(" ", text).strip().casefold()


def ground_quotes(quotes: list[str], evidence_text: str) -> tuple[list[str], int]:
    """Keep only quotes that literally occur in the evidence we sent. Returns (kept, dropped_count)."""
    haystack = _norm(evidence_text)
    kept: list[str] = []
    dropped = 0
    for q in quotes:
        nq = _norm(q)
        if len(nq) >= 6 and nq in haystack:
            kept.append(q.strip())
        else:
            dropped += 1
    return kept, dropped


def _scrub(text: str) -> str:
    """Model output is redacted too, in case it echoes or invents a secret-looking value."""
    return redact(text).text


def validate_llm_output(data: dict[str, Any]) -> LLMDiagnosis:
    """Strict schema validation. Raises ``ValidationError`` for anything unexpected."""
    return LLMDiagnosis.model_validate(data)


def build_ai_analysis(raw: dict[str, Any], evidence_text: str, provider_name: str, model: str) -> AIAnalysis:
    parsed = validate_llm_output(raw)
    quotes, dropped = ground_quotes(parsed.evidence_quotes, evidence_text)
    commands = [_scrub(c.strip()) for c in parsed.suggested_commands if c.strip()]
    flagged = [f"{c}  <- {', '.join(r)}" for c in commands if (r := risky_command_reasons(c))]
    confidence = parsed.confidence
    # An answer that cites nothing verifiable is capped at "low" confidence.
    if parsed.evidence_quotes and not quotes:
        confidence = "low"
    return AIAnalysis(
        provider=provider_name,
        model=model,
        category=parsed.category,
        root_cause=_scrub(parsed.root_cause),
        confidence=confidence,
        fix_steps=[_scrub(s) for s in parsed.fix_steps],
        suggested_commands=commands,
        suggested_patch=_scrub(parsed.suggested_patch) if parsed.suggested_patch else None,
        grounded_quotes=[_scrub(q) for q in quotes],
        ungrounded_quotes=dropped,
        flagged_commands=flagged,
    )


def _baseline_summary(findings: list[Finding]) -> dict[str, Any]:
    """Only static, rule-authored fields go into the prompt outside the untrusted data block."""
    return {
        "matched_rules": [
            {"rule_id": f.rule_id, "category": f.category.value, "title": f.title, "confidence": f.confidence}
            for f in findings[:3]
        ]
        or "no deterministic rule matched",
    }


def finalize(
    *,
    kind: Kind,
    target: str,
    findings: list[Finding],
    evidence_text: str,
    settings: Settings,
    provider: Provider | None,
    provider_notices: list[str],
    redactions: dict[str, int],
    truncated: bool,
    input_bytes: int,
    case_id: str | None = None,
) -> Diagnosis:
    notices = list(provider_notices)
    usage = Usage()
    ai: AIAnalysis | None = None
    primary = findings[0] if findings else None

    call_llm = provider is not None
    if provider is not None and settings.llm_when == "unknown" and primary and primary.confidence != "low":
        call_llm = False
        notices.append("Rules matched with sufficient confidence; the model was skipped (llm_when=unknown).")

    if provider is not None and call_llm:
        budget = Budget(settings.max_input_tokens, settings.max_output_tokens, settings.max_cost_usd)
        user_prompt = build_user_prompt(kind, evidence_text, _baseline_summary(findings))
        est_in = estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(user_prompt)
        price = settings.price_per_mtok(provider.model)
        worst_cost = (
            None if price is None else (est_in * price[0] + budget.max_output_tokens * price[1]) / 1_000_000
        )
        usage.estimated_input_tokens_before_call = est_in
        ok, why = budget.allows(est_in, worst_cost)
        if not ok:
            notices.append(
                f"Model call skipped by cost guardrail: {why}. Showing the rules-based result only."
            )
            log_event("llm_skipped_budget", reason=why, estimated_input_tokens=est_in)
        else:
            request = LLMRequest(
                system=SYSTEM_PROMPT,
                user=user_prompt,
                schema=request_schema(),
                max_output_tokens=budget.max_output_tokens,
                case_id=case_id,
                hints={
                    "category": primary.category.value if primary else "unknown",
                    "root_cause": primary.root_cause if primary else "",
                    "fix_steps": primary.fix_steps if primary else [],
                    "first_evidence": primary.evidence[0].excerpt if primary and primary.evidence else "",
                },
            )
            started = time.monotonic()
            try:
                response = provider.complete(request)
            except ProviderError as exc:
                notices.append(f"Model call failed ({exc}); showing the rules-based result only.")
                log_event("llm_error", provider=provider.name, error=str(exc))
            else:
                usage.llm_calls = 1
                usage.input_tokens = response.input_tokens
                usage.output_tokens = response.output_tokens
                usage.latency_ms = int((time.monotonic() - started) * 1000)
                usage.estimated_cost_usd = (
                    None
                    if price is None
                    else round(
                        (response.input_tokens * price[0] + response.output_tokens * price[1]) / 1_000_000, 6
                    )
                )
                log_event(
                    "llm_call",
                    provider=response.provider,
                    model=response.model,
                    input_tokens=response.input_tokens,
                    output_tokens=response.output_tokens,
                    estimated_cost_usd=usage.estimated_cost_usd,
                    latency_ms=usage.latency_ms,
                )
                try:
                    ai = build_ai_analysis(response.data, evidence_text, response.provider, response.model)
                except ValidationError as exc:
                    notices.append(
                        "The model reply failed strict schema validation and was discarded "
                        f"({exc.error_count()} problems). Showing the rules-based result only."
                    )
                    log_event("llm_rejected_schema", errors=exc.error_count())
    elif provider is None and usage.llm_calls == 0:
        usage.estimated_cost_usd = 0.0

    if ai is not None and ai.ungrounded_quotes:
        notices.append(
            f"{ai.ungrounded_quotes} evidence quote(s) from the model could not be found in the input "
            "and were dropped; treat the AI analysis with extra caution."
        )

    category, confidence = Category.UNKNOWN, "low"
    if primary and primary.confidence in ("medium", "high"):
        category, confidence = primary.category, primary.confidence
    elif ai is not None and ai.category != Category.UNKNOWN:
        category, confidence = ai.category, ai.confidence
    elif primary:
        category, confidence = primary.category, primary.confidence

    if primary and ai and ai.category not in (primary.category, Category.UNKNOWN):
        notices.append(
            f"The model's category ({ai.category.value}) differs from the rules engine ({primary.category.value}). "
            "Both are shown; verify against the evidence."
        )

    summary = (
        primary.title
        if primary
        else (ai.root_cause.split(".")[0] if ai else "No known failure signature matched")
    )
    return Diagnosis(
        kind=kind,
        target=target,
        mode="rules+llm" if ai is not None else "rules-only",
        category=category,
        confidence=confidence,
        summary=summary,
        findings=findings,
        ai=ai,
        notices=notices,
        usage=usage,
        redactions=redactions,
        truncated=truncated,
        input_bytes=input_bytes,
        sent_bytes=len(evidence_text.encode("utf-8", "replace")),
    )
