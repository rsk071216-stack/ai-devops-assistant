"""Kubernetes diagnosis pipeline: redact bundle -> rules -> compact evidence text -> guarded model -> merge."""

from __future__ import annotations

from collections import Counter
from typing import Any

from ai_devops_assistant.analysis import finalize
from ai_devops_assistant.config import Settings
from ai_devops_assistant.guardrails import clean_log, truncate_log
from ai_devops_assistant.k8s.bundle import K8sBundle
from ai_devops_assistant.k8s.facts import pod_facts
from ai_devops_assistant.k8s.rules import diagnose_bundle
from ai_devops_assistant.models import Diagnosis
from ai_devops_assistant.observability import log_event
from ai_devops_assistant.providers import Provider
from ai_devops_assistant.redaction import redact

_TEXT_FIELDS = ("describe", "events", "logs", "previous_logs")


def _redact_obj(obj: Any, counts: Counter[str]) -> Any:
    """Redact every string leaf of a JSON-like structure; env vars are redacted by NAME=value."""
    if isinstance(obj, str):
        r = redact(obj)
        counts.update(r.counts)
        return r.text
    if isinstance(obj, list):
        return [_redact_obj(v, counts) for v in obj]
    if isinstance(obj, dict):
        if set(obj) >= {"name", "value"} and isinstance(obj["value"], str):
            r = redact(f"{obj['name']}={obj['value']}")
            counts.update(r.counts)
            prefix = f"{obj['name']}="
            value = r.text[len(prefix) :] if r.text.startswith(prefix) else "[REDACTED:env_value]"
            return {**{k: _redact_obj(v, counts) for k, v in obj.items() if k != "value"}, "value": value}
        return {k: _redact_obj(v, counts) for k, v in obj.items()}
    return obj


def redact_bundle(bundle: K8sBundle) -> tuple[K8sBundle, dict[str, int]]:
    counts: Counter[str] = Counter()
    data = bundle.model_dump()
    for name in _TEXT_FIELDS:
        r = redact(clean_log(data[name]))
        counts.update(r.counts)
        data[name] = r.text
    for name in ("pod", "deployment", "services", "endpoints"):
        data[name] = _redact_obj(data[name], counts)
    return K8sBundle.model_validate(data), dict(sorted(counts.items()))


def build_evidence_text(bundle: K8sBundle) -> str:
    """Compact, redacted text for the model: structured facts first, then raw excerpts."""
    facts = pod_facts(bundle)
    lines = [f"== target == {bundle.target} (namespace {bundle.namespace})"]
    if bundle.owner_chain:
        lines.append("== owner chain == " + " -> ".join(bundle.owner_chain))
    lines.append(f"== pod == {facts.name or '?'} phase={facts.phase or '?'} scheduled={facts.scheduled}")
    for c in facts.containers:
        lines.append(
            f"container {c.name}: image={c.image} ready={c.ready} restarts={c.restart_count} "
            f"waiting={c.waiting_reason or '-'} terminated={c.terminated_reason or '-'} exit={c.exit_code} "
            f"mem(limit/request)={c.mem_limit or '-'}/{c.mem_request or '-'} cpu(limit/request)={c.cpu_limit or '-'}/{c.cpu_request or '-'} "
            f"ports={c.ports}"
        )
        for kind in ("liveness", "readiness", "startup"):
            p = getattr(c, kind)
            if p:
                lines.append(
                    f"  {kind}: {p.kind} {p.path}:{p.port} delay={p.initial_delay}s timeout={p.timeout}s "
                    f"period={p.period}s failureThreshold={p.failure_threshold}"
                )
    if bundle.missing_refs:
        lines.append("== referenced objects that do not exist == " + ", ".join(bundle.missing_refs))
    for svc in bundle.services:
        lines.append(
            f"service {svc.get('metadata', {}).get('name')}: selector={svc.get('spec', {}).get('selector')}"
        )
    if facts.labels:
        lines.append(f"pod labels: {facts.labels}")
    for title, text in (
        ("events", bundle.events),
        ("describe", bundle.describe),
        ("previous logs", bundle.previous_logs),
        ("logs", bundle.logs),
    ):
        if text.strip():
            lines.append(f"== {title} ==\n{text.strip()}")
    return "\n".join(lines)


def diagnose_k8s(
    bundle: K8sBundle,
    *,
    settings: Settings,
    provider: Provider | None,
    provider_notices: list[str] | None = None,
    case_id: str | None = None,
) -> Diagnosis:
    input_bytes = len(bundle.model_dump_json().encode("utf-8"))
    safe, counts = redact_bundle(bundle)
    log_event("redaction_done", redactions=counts, input_bytes=input_bytes)
    findings = diagnose_bundle(safe)
    log_event("rules_done", matched=[f.rule_id for f in findings[:5]])
    truncation = truncate_log(build_evidence_text(safe), settings.max_log_bytes)
    return finalize(
        kind="k8s",
        target=bundle.target,
        findings=findings,
        evidence_text=truncation.text,
        settings=settings,
        provider=provider,
        provider_notices=provider_notices or [],
        redactions=counts,
        truncated=truncation.truncated,
        input_bytes=input_bytes,
        case_id=case_id,
    )
