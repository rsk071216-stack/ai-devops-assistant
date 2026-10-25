"""CI triage pipeline: clean -> redact -> rules -> truncate -> (guarded) model -> merged diagnosis."""

from __future__ import annotations

from ai_devops_assistant.analysis import finalize
from ai_devops_assistant.ci.rules import CI_RULES
from ai_devops_assistant.config import Settings
from ai_devops_assistant.engine import run_rules
from ai_devops_assistant.guardrails import clean_log, truncate_log
from ai_devops_assistant.models import Diagnosis
from ai_devops_assistant.observability import log_event
from ai_devops_assistant.providers import Provider
from ai_devops_assistant.redaction import redact


def triage_log(
    raw_log: str,
    *,
    settings: Settings,
    provider: Provider | None,
    provider_notices: list[str] | None = None,
    target: str = "ci-log",
    case_id: str | None = None,
) -> Diagnosis:
    """Diagnose one CI log. Secrets are removed before rules, rendering or any model call."""
    input_bytes = len(raw_log.encode("utf-8", "replace"))
    cleaned = clean_log(raw_log)
    redaction = redact(cleaned)
    log_event("redaction_done", redactions=redaction.counts, input_bytes=input_bytes)

    findings = run_rules(CI_RULES, redaction.text)
    log_event("rules_done", matched=[f.rule_id for f in findings[:5]])

    truncation = truncate_log(redaction.text, settings.max_log_bytes)
    if truncation.truncated:
        log_event("log_truncated", original_bytes=truncation.original_bytes, kept_bytes=truncation.kept_bytes)

    return finalize(
        kind="ci",
        target=target,
        findings=findings,
        evidence_text=truncation.text,
        settings=settings,
        provider=provider,
        provider_notices=provider_notices or [],
        redactions=redaction.counts,
        truncated=truncation.truncated,
        input_bytes=input_bytes,
        case_id=case_id,
    )
