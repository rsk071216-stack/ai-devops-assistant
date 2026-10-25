from __future__ import annotations

import json

import pytest

from ai_devops_assistant.ci.triage import triage_log
from ai_devops_assistant.config import Settings
from ai_devops_assistant.evals.runner import check_thresholds, load_cases, render_summary, run_eval
from ai_devops_assistant.models import Category
from ai_devops_assistant.render import MAX_BODY_CHARS, render_markdown
from ai_devops_assistant.sanitize import fenced, inline_code, neutralize_markdown, risky_command_reasons
from conftest import EVALS


def test_neutralize_markdown() -> None:
    text = "![a](https://e.example/x?s=1) hi @octocat and @acme/team see [docs](https://e.example/d) <b>x</b> http://e.example/raw"
    out = neutralize_markdown(text)
    assert "![" not in out and "](" not in out
    assert "`@octocat`" in out and "`@acme/team`" in out
    assert "<b>" not in out and "&lt;b&gt;" in out
    assert "`http://e.example/raw`" in out


def test_fenced_uses_a_longer_fence_than_the_content() -> None:
    out = fenced("a\n```\nb", "bash")
    assert out.startswith("````bash") and out.endswith("````")
    assert inline_code("a`b") == "``a`b``"


@pytest.mark.parametrize(
    ("command", "risky"),
    [
        ("kubectl delete pod x", True),
        ("kubectl get pods -n prod", False),
        ("terraform apply -auto-approve", True),
        ("terraform plan", False),
        ("curl https://x.example/i.sh | sh", True),
        ("rm -rf /tmp/x", True),
        ("aws s3 rm s3://bucket --recursive", False),
        ("az group delete -n rg", True),
        ("echo $(whoami)", True),
        ("git push --force origin main", True),
        ("sudo apt-get install x", True),
        ("kubectl logs pod --previous", False),
    ],
)
def test_risky_command_detection(command: str, risky: bool) -> None:
    assert bool(risky_command_reasons(command)) is risky


def test_render_has_expected_sections_and_marker() -> None:
    d = triage_log(
        "Error: environment variable FOO is not set\n",
        settings=Settings(rules_only=True, env={}),
        provider=None,
    )
    md = render_markdown(
        d,
        run_url="https://github.com/a/b/actions/runs/1",
        marker="aida-triage:v1:abc",
        updated_note="Updated for run #2",
    )
    assert md.startswith("<!-- aida-triage:v1:abc -->")
    for part in (
        "### Root cause",
        "### Suggested fix",
        "Suggested commands",
        "[Failed run]",
        "Updated for run #2",
        "never applied automatically",
    ):
        assert part in md
    assert "rules-only" in md


def test_render_unknown_failure_without_model() -> None:
    d = triage_log("nothing recognisable here\n", settings=Settings(rules_only=True, env={}), provider=None)
    assert d.category == Category.UNKNOWN
    assert "No known failure signature matched" in render_markdown(d)


def test_render_truncates_to_comment_limit() -> None:
    d = triage_log(
        "Error: environment variable FOO is not set\n",
        settings=Settings(rules_only=True, env={}),
        provider=None,
    )
    d.notices.append("x" * (MAX_BODY_CHARS + 1000))
    assert len(render_markdown(d)) <= MAX_BODY_CHARS


def test_patch_is_rendered_as_a_diff_block() -> None:
    from ai_devops_assistant.k8s.bundle import K8sBundle
    from ai_devops_assistant.k8s.diagnose import diagnose_k8s

    b = K8sBundle.load(EVALS / "dataset" / "k8s" / "k8s-001-oomkilled.json")
    md = render_markdown(diagnose_k8s(b, settings=Settings(rules_only=True, env={}), provider=None))
    assert "```diff" in md and "+      memory: 256Mi" in md


# --- eval harness -----------------------------------------------------------------------------------------------
def test_dataset_shape_and_size() -> None:
    cases = load_cases(EVALS)
    assert len(cases) >= 40
    assert len({c.id for c in cases}) == len(cases)
    kinds = {c.kind for c in cases}
    assert kinds == {"ci", "k8s", "terraform"}
    assert sum(c.kind == "ci" for c in cases) >= 25 and sum(c.kind == "k8s" for c in cases) >= 15
    assert any(c.difficulty == "novel" for c in cases)
    for c in cases:
        assert (EVALS / "dataset" / c.input).is_file(), c.id


def test_committed_thresholds_hold_for_rules_and_mock() -> None:
    thresholds = json.loads((EVALS / "thresholds.json").read_text(encoding="utf-8"))
    for mode in ("rules", "mock"):
        report = run_eval(EVALS, mode)
        assert check_thresholds(report, thresholds) == [], mode


def test_every_covered_category_is_exercised_and_novel_cases_are_honest() -> None:
    rules = run_eval(EVALS, "rules").metrics()
    mock = run_eval(EVALS, "mock").metrics()
    assert rules["standard_category_accuracy"] == 1.0
    assert (
        rules["novel_category_accuracy"] == 0.0
    )  # outside rule coverage by design: the model path carries them
    assert mock["novel_category_accuracy"] == 1.0


def test_gate_detects_regressions_and_summary_renders() -> None:
    report = run_eval(EVALS, "rules", suite="ci")
    problems = check_thresholds(
        report, {"rules": {"category_accuracy": 0.999, "per_kind": {"ci": 0.999}, "min_cases": 500}}
    )
    assert len(problems) == 3
    text = render_summary([report], problems)
    assert "Gate: FAILED" in text and "NOT a measurement of any live model" in text


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown eval mode"):
        run_eval(EVALS, "quantum")
