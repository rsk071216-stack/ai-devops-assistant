"""Eval harness: run the golden dataset through the real pipeline and score it.

Modes:
  rules  - deterministic analyzers only (no provider). This is the published, reproducible number.
  mock   - the full pipeline with the MockProvider replaying recorded answers (tests plumbing: prompt build,
           schema validation, grounding, merge). It does NOT measure model quality.
  live   - the same pipeline with a real provider; needs an API key, costs money, never run on push.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ai_devops_assistant.ci.triage import triage_log
from ai_devops_assistant.config import Settings
from ai_devops_assistant.k8s.bundle import K8sBundle
from ai_devops_assistant.k8s.diagnose import diagnose_k8s
from ai_devops_assistant.models import Diagnosis
from ai_devops_assistant.providers import Provider, build_provider
from ai_devops_assistant.providers.mock import MockProvider
from ai_devops_assistant.terraform.review import review_plan


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    input: str
    expected_category: str
    fix_keywords: tuple[str, ...]
    difficulty: str = "standard"  # "standard" = within rule coverage, "novel" = deliberately outside it
    description: str = ""


@dataclass
class CaseResult:
    case: Case
    predicted: str
    category_ok: bool
    fix_ok: bool
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float | None = 0.0
    notices: list[str] = field(default_factory=list)


@dataclass
class EvalReport:
    mode: str
    results: list[CaseResult]

    def _rate(self, items: list[CaseResult], attr: str) -> float:
        return sum(getattr(r, attr) for r in items) / len(items) if items else 0.0

    def groups(self, key: str) -> dict[str, list[CaseResult]]:
        out: dict[str, list[CaseResult]] = defaultdict(list)
        for r in self.results:
            out[getattr(r.case, key) if key != "category" else r.case.expected_category].append(r)
        return dict(sorted(out.items()))

    def metrics(self) -> dict[str, Any]:
        std = [r for r in self.results if r.case.difficulty == "standard"]
        novel = [r for r in self.results if r.case.difficulty == "novel"]
        return {
            "mode": self.mode,
            "cases": len(self.results),
            "category_accuracy": round(self._rate(self.results, "category_ok"), 4),
            "fix_hit_rate": round(self._rate(self.results, "fix_ok"), 4),
            "standard_category_accuracy": round(self._rate(std, "category_ok"), 4),
            "novel_category_accuracy": round(self._rate(novel, "category_ok"), 4),
            "per_kind": {k: round(self._rate(v, "category_ok"), 4) for k, v in self.groups("kind").items()},
            "per_category": {
                k: round(self._rate(v, "category_ok"), 4) for k, v in self.groups("category").items()
            },
            "tokens_in": sum(r.tokens_in for r in self.results),
            "tokens_out": sum(r.tokens_out for r in self.results),
        }

    def failures(self) -> list[CaseResult]:
        return [r for r in self.results if not (r.category_ok and r.fix_ok)]


def load_cases(root: Path, suite: str = "all") -> list[Case]:
    raw = json.loads((root / "dataset" / "cases.json").read_text(encoding="utf-8"))
    cases = [
        Case(
            id=c["id"],
            kind=c["kind"],
            input=c["input"],
            expected_category=c["expected_category"],
            fix_keywords=tuple(c.get("fix_keywords", [])),
            difficulty=c.get("difficulty", "standard"),
            description=c.get("description", ""),
        )
        for c in raw
    ]
    return [c for c in cases if suite in ("all", c.kind)]


def _answer_text(d: Diagnosis) -> str:
    parts: list[str] = []
    for f in d.findings[:1]:
        parts += [f.root_cause, *f.fix_steps, *f.suggested_commands, f.suggested_patch or ""]
    if d.ai:
        parts += [d.ai.root_cause, *d.ai.fix_steps, *d.ai.suggested_commands, d.ai.suggested_patch or ""]
    return "\n".join(parts).lower()


def run_case(case: Case, root: Path, settings: Settings, provider: Provider | None) -> Diagnosis:
    path = root / "dataset" / case.input
    if case.kind == "ci":
        return triage_log(
            path.read_text(encoding="utf-8"),
            settings=settings,
            provider=provider,
            target=case.id,
            case_id=case.id,
        )
    if case.kind == "k8s":
        return diagnose_k8s(K8sBundle.load(path), settings=settings, provider=provider, case_id=case.id)
    if case.kind == "terraform":
        plan = json.loads(path.read_text(encoding="utf-8"))
        return review_plan(plan, settings=settings, provider=provider, target=case.id, case_id=case.id)
    raise ValueError(f"unknown case kind {case.kind}")


def run_eval(root: Path, mode: str = "rules", suite: str = "all", settings: Settings | None = None,
             max_cases: int | None = None, max_total_cost_usd: float | None = None) -> EvalReport:  # fmt: skip
    base = settings or Settings()
    cases = load_cases(root, suite)[:max_cases]
    provider: Provider | None
    if mode == "rules":
        provider = None
        s = replace(base, rules_only=True)
    elif mode == "mock":
        recorded = json.loads((root / "recorded" / "responses.json").read_text(encoding="utf-8"))
        provider = MockProvider(recorded=recorded)
        s = base
    elif mode == "live":
        s = base
        provider, notices = build_provider(s)
        if provider is None:
            raise RuntimeError("live mode needs a configured provider: " + " ".join(notices))
    else:
        raise ValueError(f"unknown eval mode {mode}")

    results: list[CaseResult] = []
    spent = 0.0
    for case in cases:
        if mode == "live" and max_total_cost_usd is not None and spent >= max_total_cost_usd:
            break
        d = run_case(case, root, s, provider)
        answer = _answer_text(d)
        results.append(
            CaseResult(
                case=case,
                predicted=d.category.value,
                category_ok=d.category.value == case.expected_category,
                fix_ok=all(k.lower() in answer for k in case.fix_keywords),
                tokens_in=d.usage.input_tokens,
                tokens_out=d.usage.output_tokens,
                cost=d.usage.estimated_cost_usd,
                notices=d.notices,
            )
        )
        spent += d.usage.estimated_cost_usd or 0.0
    return EvalReport(mode=mode, results=results)


def check_thresholds(report: EvalReport, thresholds: dict[str, Any]) -> list[str]:
    """Return human-readable regressions (empty list means the gate passes)."""
    spec = thresholds.get(report.mode, {})
    m = report.metrics()
    problems: list[str] = []
    for key in ("category_accuracy", "fix_hit_rate", "standard_category_accuracy", "novel_category_accuracy"):
        if key in spec and m[key] < spec[key]:
            problems.append(f"{report.mode}: {key} {m[key]:.3f} < committed threshold {spec[key]:.3f}")
    for kind, minimum in spec.get("per_kind", {}).items():
        got = m["per_kind"].get(kind)
        if got is not None and got < minimum:
            problems.append(f"{report.mode}: per-kind accuracy for {kind} {got:.3f} < {minimum:.3f}")
    if "min_cases" in spec and m["cases"] < spec["min_cases"]:
        problems.append(f"{report.mode}: only {m['cases']} cases, need at least {spec['min_cases']}")
    return problems


def render_summary(reports: list[EvalReport], problems: list[str]) -> str:
    lines = ["## Offline eval results", ""]
    lines.append(
        "Scores are for the committed offline dataset only. They are NOT a measurement of any live model."
    )
    lines.append("")
    lines += ["| Mode | Cases | Category accuracy | Fix elements present | Standard cases | Novel cases (outside rule coverage) |",
              "| --- | ---: | ---: | ---: | ---: | ---: |"]  # fmt: skip
    for r in reports:
        m = r.metrics()
        lines.append(
            f"| {r.mode} | {m['cases']} | {m['category_accuracy']:.1%} | {m['fix_hit_rate']:.1%} | "
            f"{m['standard_category_accuracy']:.1%} | {m['novel_category_accuracy']:.1%} |"
        )
    for r in reports:
        m = r.metrics()
        lines += [
            "",
            f"### Per-category accuracy ({r.mode})",
            "",
            "| Category | Cases | Accuracy |",
            "| --- | ---: | ---: |",
        ]
        for cat, items in r.groups("category").items():
            lines.append(f"| {cat} | {len(items)} | {sum(i.category_ok for i in items) / len(items):.0%} |")
        lines += ["", "| Kind | Accuracy |", "| --- | ---: |"]
        lines += [f"| {k} | {v:.1%} |" for k, v in m["per_kind"].items()]
        bad = r.failures()
        if bad:
            lines += ["", f"<details><summary>{r.mode}: {len(bad)} case(s) not fully correct</summary>", ""]
            lines += [
                f"- `{b.case.id}`: expected `{b.case.expected_category}`, got `{b.predicted}`, fix elements {'ok' if b.fix_ok else 'MISSING'}"
                for b in bad
            ]
            lines += ["", "</details>"]
    lines += ["", "Gate: " + ("PASSED" if not problems else "FAILED")]
    lines += [f"- {p}" for p in problems]
    return "\n".join(lines) + "\n"
