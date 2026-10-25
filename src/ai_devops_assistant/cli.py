"""Command line interface: aida ci-triage | k8s-diagnose | tf-review | eval | redact."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer

from ai_devops_assistant import __version__
from ai_devops_assistant.ci.github import GitHubClient, GitHubError, dedup_marker
from ai_devops_assistant.ci.triage import triage_log
from ai_devops_assistant.config import DEFAULT_MAX_LOG_BYTES, PROVIDER_CHOICES, Settings
from ai_devops_assistant.evals.runner import check_thresholds, render_summary, run_eval
from ai_devops_assistant.k8s.bundle import K8sBundle
from ai_devops_assistant.k8s.collector import CollectionError, Collector, ForbiddenCommandError, KubectlRunner
from ai_devops_assistant.k8s.diagnose import diagnose_k8s
from ai_devops_assistant.models import Diagnosis
from ai_devops_assistant.observability import configure_logging
from ai_devops_assistant.providers import Provider, build_provider
from ai_devops_assistant.redaction import redact
from ai_devops_assistant.render import render_markdown
from ai_devops_assistant.sanitize import neutralize_markdown
from ai_devops_assistant.terraform.review import review_plan

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Rules-first AI assistant: diagnose CI failures, Kubernetes problems and Terraform plan risk. "
    "Works fully offline; a model is optional and its output is validated, never executed.",
)

ProviderOpt = Annotated[
    str, typer.Option("--provider", help=f"One of: {', '.join(PROVIDER_CHOICES)}. 'auto' picks by env.")
]
ModelOpt = Annotated[
    str | None,
    typer.Option("--model", help="Model id (default claude-sonnet-5-5 for anthropic; env AIDA_MODEL)."),
]
RulesOnlyOpt = Annotated[bool, typer.Option("--rules-only", help="Never call a model.")]
ExplainOpt = Annotated[bool, typer.Option("--explain", help="Show which evidence supported the diagnosis.")]
FormatOpt = Annotated[str, typer.Option("--format", help="markdown or json.")]
OutputOpt = Annotated[
    Path | None, typer.Option("--output", "-o", help="Write the result here instead of stdout.")
]
MaxBytesOpt = Annotated[int, typer.Option("--max-log-bytes", help="Max bytes of evidence sent to a model.")]
MaxCostOpt = Annotated[
    float,
    typer.Option("--max-cost-usd", help="Per-run worst-case cost cap; the model call is skipped above it."),
]
LlmWhenOpt = Annotated[
    str, typer.Option("--llm-when", help="'always' or 'unknown' (only when no rule matched confidently).")
]
LogLevelOpt = Annotated[
    str, typer.Option("--log-level", help="Structured JSON logs on stderr: DEBUG, INFO, WARNING.")
]


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(code=2)


def _settings(
    provider: str, model: str | None, rules_only: bool, llm_when: str, max_log_bytes: int, max_cost_usd: float
) -> Settings:
    if provider not in PROVIDER_CHOICES:
        raise _fail(f"--provider must be one of {', '.join(PROVIDER_CHOICES)}")
    if llm_when not in ("always", "unknown"):
        raise _fail("--llm-when must be 'always' or 'unknown'")
    return Settings(
        provider=provider,
        model=model,
        rules_only=rules_only,
        llm_when=llm_when,
        max_log_bytes=max_log_bytes,
        max_cost_usd=max_cost_usd,
    )


def _emit(d: Diagnosis, fmt: str, explain: bool, output: Path | None, **render_kwargs: str | None) -> str:
    if fmt not in ("markdown", "json"):
        raise _fail("--format must be markdown or json")
    text = (
        d.model_dump_json(indent=2) + "\n"
        if fmt == "json"
        else render_markdown(d, explain=explain, **render_kwargs)
    )
    if output:
        output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return text


def _github_outputs(**values: str) -> None:
    """Expose results to later workflow steps; values are single-line and sanitised."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for key, value in values.items():
            fh.write(f"{key}={value.replace(chr(10), ' ')[:500]}\n")


def _step_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


def _version(value: bool) -> None:
    if value:
        typer.echo(f"ai-devops-assistant {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit.")
    ] = False,
) -> None:
    """Rules-first AI assistant for DevOps failures."""


@app.command("ci-triage")
def ci_triage(
    log_file: Annotated[
        Path | None, typer.Option("--log-file", help="Triage a saved log file (offline).")
    ] = None,
    repo: Annotated[
        str | None, typer.Option("--repo", help="OWNER/NAME (default: $GITHUB_REPOSITORY).")
    ] = None,
    run_id: Annotated[int | None, typer.Option("--run-id", help="Failed workflow run id to triage.")] = None,
    post: Annotated[
        str,
        typer.Option(
            "--post", help="none | auto | pr | issue. auto = PR comment if the run has a PR, else an issue."
        ),
    ] = "none",
    provider: ProviderOpt = "auto",
    model: ModelOpt = None,
    rules_only: RulesOnlyOpt = False,
    llm_when: LlmWhenOpt = "always",
    max_log_bytes: MaxBytesOpt = DEFAULT_MAX_LOG_BYTES,
    max_cost_usd: MaxCostOpt = 0.10,
    explain: ExplainOpt = False,
    fmt: FormatOpt = "markdown",
    output: OutputOpt = None,
    log_level: LogLevelOpt = "WARNING",
) -> None:
    """Diagnose a failed GitHub Actions run (or a saved log) and optionally post one updating comment/issue."""
    configure_logging(log_level)
    if (log_file is None) == (run_id is None):
        raise _fail("give exactly one of --log-file or --run-id")
    if post not in ("none", "auto", "pr", "issue"):
        raise _fail("--post must be none, auto, pr or issue")
    settings = _settings(provider, model, rules_only, llm_when, max_log_bytes, max_cost_usd)
    llm, notices = build_provider(settings)

    if log_file is not None:
        if post != "none":
            raise _fail("--post needs --run-id (a saved log has nowhere to post)")
        try:
            raw = log_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise _fail(f"cannot read {log_file}: {exc.strerror}") from exc
        d = triage_log(raw, settings=settings, provider=llm, provider_notices=notices, target=log_file.name)
        _emit(d, fmt, explain, output)
        return

    repo = repo or os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not repo or not token or run_id is None:
        raise _fail("--run-id needs --repo (or GITHUB_REPOSITORY) and GITHUB_TOKEN in the environment")
    _triage_run(repo, token, run_id, settings, llm, notices, post, explain, fmt, output)


def _triage_run(
    repo: str,
    token: str,
    run_id: int,
    settings: Settings,
    llm: Provider | None,
    notices: list[str],
    post: str,
    explain: bool,
    fmt: str,
    output: Path | None,
) -> None:
    try:
        gh = GitHubClient(repo, token, api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        run = gh.get_run(run_id)
        jobs = gh.failed_jobs(run_id)
        if not jobs:
            typer.echo(
                "No failed jobs found for this run (cancelled or skipped); nothing to triage.", err=True
            )
            _github_outputs(category="none", url="")
            return
        sections = []
        for job in jobs:
            steps = ", ".join(job.failed_steps) or "unknown step"
            sections.append(f"=== job: {job.name} | failed step(s): {steps} ===\n{gh.job_log(job.id)}")
        d = triage_log(
            "\n".join(sections),
            settings=settings,
            provider=llm,
            provider_notices=notices,
            target=f"run {run_id}",
        )
        workflow, branch = str(run.get("name", "workflow")), str(run.get("head_branch", ""))
        marker = dedup_marker(workflow, branch)
        run_url = str(run.get("html_url", ""))
        note = f"Updated for run #{run.get('run_number')} (attempt {run.get('run_attempt', 1)})"
        text = _emit(d, fmt, explain, output, run_url=run_url, marker=marker, updated_note=note)
        _step_summary(text if fmt == "markdown" else "")

        url = ""
        if post != "none" and fmt == "markdown":
            prs = gh.pull_requests_for_run(run)
            if post in ("auto", "pr") and prs:
                url = gh.upsert_pr_comment(prs[0], text, marker)
            elif post in ("auto", "issue"):
                title = neutralize_markdown(f"CI failure triage: {workflow} on {branch}")[:120]
                url = gh.upsert_issue(title, text, marker)
            else:
                typer.echo("--post pr requested but this run has no pull request; nothing posted.", err=True)
            if url:
                typer.echo(f"Posted triage: {url}", err=True)
        _github_outputs(category=d.category.value, url=url, mode=d.mode)
    except GitHubError as exc:
        raise _fail(str(exc)) from exc


@app.command("k8s-diagnose")
def k8s_diagnose(
    target: Annotated[
        str | None, typer.Argument(help="pod/NAME or deployment/NAME (omit with --fixture).")
    ] = None,
    namespace: Annotated[str, typer.Option("--namespace", "-n")] = "default",
    fixture: Annotated[
        Path | None, typer.Option("--fixture", help="Saved evidence bundle (JSON); no cluster needed.")
    ] = None,
    save_bundle: Annotated[
        Path | None, typer.Option("--save-bundle", help="Write the collected evidence bundle to this file.")
    ] = None,
    kube_context: Annotated[str | None, typer.Option("--context", help="kubectl context name.")] = None,
    kubectl: Annotated[str, typer.Option("--kubectl", help="Path to the kubectl binary.")] = "kubectl",
    provider: ProviderOpt = "auto",
    model: ModelOpt = None,
    rules_only: RulesOnlyOpt = False,
    llm_when: LlmWhenOpt = "always",
    max_log_bytes: MaxBytesOpt = DEFAULT_MAX_LOG_BYTES,
    max_cost_usd: MaxCostOpt = 0.10,
    explain: ExplainOpt = False,
    fmt: FormatOpt = "markdown",
    output: OutputOpt = None,
    log_level: LogLevelOpt = "WARNING",
) -> None:
    """Collect read-only evidence for a pod/deployment (or load a fixture) and diagnose it."""
    configure_logging(log_level)
    settings = _settings(provider, model, rules_only, llm_when, max_log_bytes, max_cost_usd)
    llm, notices = build_provider(settings)
    if fixture is not None:
        try:
            bundle = K8sBundle.load(fixture)
        except (OSError, ValueError) as exc:
            raise _fail(f"cannot load fixture {fixture}: {exc}") from exc
    elif target:
        try:
            runner = KubectlRunner(executable=kubectl, context=kube_context)
            bundle = Collector(runner, namespace=namespace).collect(target)
        except (CollectionError, ForbiddenCommandError) as exc:
            raise _fail(str(exc)) from exc
    else:
        raise _fail("give a TARGET (pod/NAME or deployment/NAME) or --fixture")
    if save_bundle:
        bundle.save(save_bundle)
    d = diagnose_k8s(bundle, settings=settings, provider=llm, provider_notices=notices)
    _emit(d, fmt, explain, output)


@app.command("tf-review")
def tf_review(
    plan: Annotated[Path, typer.Argument(help="Output of `terraform show -json tfplan`.")],
    provider: ProviderOpt = "auto",
    model: ModelOpt = None,
    rules_only: RulesOnlyOpt = False,
    llm_when: LlmWhenOpt = "always",
    max_cost_usd: MaxCostOpt = 0.10,
    explain: ExplainOpt = False,
    fmt: FormatOpt = "markdown",
    output: OutputOpt = None,
    log_level: LogLevelOpt = "WARNING",
) -> None:
    """Review a Terraform plan for destroys, public exposure and IAM widening."""
    configure_logging(log_level)
    settings = _settings(provider, model, rules_only, llm_when, DEFAULT_MAX_LOG_BYTES, max_cost_usd)
    llm, notices = build_provider(settings)
    try:
        data = json.loads(plan.read_text(encoding="utf-8"))
        d = review_plan(data, settings=settings, provider=llm, provider_notices=notices, target=plan.name)
    except (OSError, ValueError) as exc:
        raise _fail(f"cannot review {plan}: {exc}") from exc
    _emit(d, fmt, explain, output)


@app.command("eval")
def eval_cmd(
    mode: Annotated[str, typer.Option("--mode", help="rules | mock | live | all (rules+mock).")] = "all",
    suite: Annotated[str, typer.Option("--suite", help="all | ci | k8s | terraform.")] = "all",
    evals_dir: Annotated[Path, typer.Option("--dir", help="Evals directory.")] = Path("evals"),
    check: Annotated[
        bool, typer.Option("--check", help="Exit 1 if accuracy is below evals/thresholds.json.")
    ] = False,
    summary_file: Annotated[
        Path | None,
        typer.Option("--summary-file", help="Append a markdown table (e.g. $GITHUB_STEP_SUMMARY)."),
    ] = None,
    json_out: Annotated[Path | None, typer.Option("--json-out", help="Write metrics as JSON.")] = None,
    max_cases: Annotated[
        int | None, typer.Option("--max-cases", help="Limit cases (useful for live runs).")
    ] = None,
    max_total_cost_usd: Annotated[
        float | None, typer.Option("--max-total-cost-usd", help="Stop a live run once this much is spent.")
    ] = None,
    provider: ProviderOpt = "auto",
    model: ModelOpt = None,
) -> None:
    """Score the golden dataset. 'rules' and 'mock' are offline; 'live' calls a real provider."""
    modes = ["rules", "mock"] if mode == "all" else [mode]
    if mode not in ("all", "rules", "mock", "live"):
        raise _fail("--mode must be rules, mock, live or all")
    settings = Settings(provider=provider, model=model)
    thresholds = json.loads((evals_dir / "thresholds.json").read_text(encoding="utf-8"))
    reports = []
    problems: list[str] = []
    for m in modes:
        try:
            report = run_eval(evals_dir, m, suite, settings, max_cases, max_total_cost_usd)
        except (OSError, RuntimeError, ValueError) as exc:
            raise _fail(str(exc)) from exc
        reports.append(report)
        problems += check_thresholds(report, thresholds) if (check and m != "live") else []
    text = render_summary(reports, problems)
    sys.stdout.write(text)
    if summary_file:
        with summary_file.open("a", encoding="utf-8") as fh:
            fh.write(text)
    if json_out:
        json_out.write_text(json.dumps([r.metrics() for r in reports], indent=2) + "\n", encoding="utf-8")
    if problems:
        raise typer.Exit(code=1)


@app.command("redact")
def redact_cmd(
    file: Annotated[Path | None, typer.Argument(help="File to redact (default: stdin).")] = None,
) -> None:
    """Print the input with secrets redacted (what would be sent to a model). Counts go to stderr."""
    text = file.read_text(encoding="utf-8", errors="replace") if file else sys.stdin.read()
    result = redact(text)
    sys.stdout.write(result.text)
    typer.echo(f"redacted {result.total} value(s): {json.dumps(result.counts)}", err=True)


if __name__ == "__main__":  # pragma: no cover
    app()
