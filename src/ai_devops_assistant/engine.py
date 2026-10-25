"""A tiny deterministic signature engine shared by the CI and Kubernetes text analyzers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ai_devops_assistant.models import Category, Confidence, Evidence, Finding

_SAFE_VALUE_RE = re.compile(r"[^A-Za-z0-9_./:@\-=+, ]")


def clean_value(value: str, limit: int = 80) -> str:
    """Values extracted from logs are inserted into prose; keep them short and boring."""
    return _SAFE_VALUE_RE.sub("", value)[:limit]


@dataclass(frozen=True)
class LogRule:
    id: str
    category: Category
    title: str
    patterns: tuple[re.Pattern[str], ...]
    root_cause: str
    fix_steps: tuple[str, ...]
    commands: tuple[str, ...] = ()
    patch: str | None = None
    confidence: Confidence = "high"
    priority: int = 50
    severity: str = "medium"
    # Optional: collect extra values (group "x") from every matching line, exposed as {names}.
    collect: re.Pattern[str] | None = None
    # Optional: a pattern searched in the 4 lines after the match to add context (group "x" -> {where}).
    locate: re.Pattern[str] | None = None
    tags: tuple[str, ...] = field(default=())


def rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_LEFTOVER_RE = re.compile(r"\{(?:x|c|n|l|names|where)\}")


def _render(template: str, values: dict[str, str]) -> str:
    """Replace ``{key}`` tokens only; any other braces (GitHub expressions, YAML) stay untouched."""
    out = template
    for key, value in values.items():
        out = out.replace("{" + key + "}", value)
    return _LEFTOVER_RE.sub("<see log>", out)


def run_rules(
    rules: tuple[LogRule, ...], text: str, *, max_lines: int = 200_000, max_evidence: int = 3
) -> list[Finding]:
    """Match every rule against ``text`` (already redacted). Returns findings ranked by priority."""
    lines = text.split("\n")[:max_lines]
    scored: list[tuple[int, int, Finding]] = []
    for rule in rules:
        hits: list[tuple[int, re.Match[str]]] = []
        for idx, line in enumerate(lines):
            for pat in rule.patterns:
                if m := pat.search(line):
                    hits.append((idx, m))
                    break
            if len(hits) >= max_evidence * 4:
                break
        if not hits:
            continue
        first_idx, first = hits[0]
        values = {k: clean_value(v) for k, v in first.groupdict().items() if v}
        if rule.collect is not None:
            seen: list[str] = []
            for line in lines:
                if (cm := rule.collect.search(line)) and (name := clean_value(cm.group("x"))) not in seen:
                    seen.append(name)
            values["names"] = ", ".join(seen[:5]) + (f" (+{len(seen) - 5} more)" if len(seen) > 5 else "")
        if rule.locate is not None:
            for line in lines[first_idx : first_idx + 5]:
                if lm := rule.locate.search(line):
                    values["where"] = clean_value(lm.group(0), 120)
                    break
        values.setdefault("where", "the failing step")
        evidence = [
            Evidence(source=f"log line {i + 1}", excerpt=lines[i].strip()[:300])
            for i, _ in hits[:max_evidence]
        ]
        finding = Finding(
            rule_id=rule.id,
            category=rule.category,
            title=rule.title,
            root_cause=_render(rule.root_cause, values),
            fix_steps=[_render(s, values) for s in rule.fix_steps],
            suggested_commands=[_render(c, values) for c in rule.commands],
            suggested_patch=rule.patch,
            confidence=rule.confidence,
            evidence=evidence,
            severity=rule.severity,
        )
        scored.append((-rule.priority, first_idx, finding))
    scored.sort(key=lambda t: (t[0], t[1]))
    return [f for _, _, f in scored]
