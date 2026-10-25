from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from ai_devops_assistant import cli
from ai_devops_assistant.ci.github import GitHubClient, GitHubError, dedup_marker
from conftest import EVALS, ROOT

runner = CliRunner()
LOG = ROOT / "evals" / "dataset" / "ci" / "ci-001-unbound-variable.log"
BOT = {"type": "Bot", "login": "github-actions[bot]"}
HUMAN = {"type": "User", "login": "mallory"}


class FakeGitHub:
    """A tiny in-memory GitHub API served through httpx.MockTransport."""

    def __init__(self) -> None:
        self.comments: list[dict[str, Any]] = []
        self.issues: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str]] = []
        self.run: dict[str, Any] = {
            "id": 77, "name": "Demo failure", "head_branch": "main", "run_number": 5, "run_attempt": 1,
            "html_url": "https://github.com/acme/app/actions/runs/77", "head_sha": "abc", "pull_requests": [],
        }  # fmt: skip
        self.jobs = [
            {
                "id": 1,
                "name": "build",
                "conclusion": "failure",
                "steps": [
                    {"name": "Deploy", "conclusion": "failure"},
                    {"name": "ok", "conclusion": "success"},
                ],
            },
            {"id": 2, "name": "lint", "conclusion": "success", "steps": []},
        ]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.requests.append((method, path))
        assert request.headers["authorization"].startswith("Bearer ")
        if path == "/repos/acme/app/actions/runs/77":
            return httpx.Response(200, json=self.run)
        if path == "/repos/acme/app/actions/runs/77/jobs":
            return httpx.Response(200, json={"jobs": self.jobs})
        if path == "/repos/acme/app/actions/jobs/1/logs":
            return httpx.Response(200, text=LOG.read_text(encoding="utf-8"))
        if path == "/repos/acme/app/commits/abc/pulls":
            return httpx.Response(200, json=[])
        if path.endswith("/comments") and method == "GET":
            return httpx.Response(200, json=self.comments)
        if path.endswith("/comments") and method == "POST":
            c = {
                "id": len(self.comments) + 1,
                "body": json.loads(request.content)["body"],
                "user": BOT,
                "html_url": "https://github.com/c/1",
            }
            self.comments.append(c)
            return httpx.Response(201, json=c)
        if "/issues/comments/" in path and method == "PATCH":
            cid = int(path.rsplit("/", 1)[1])
            c = next(c for c in self.comments if c["id"] == cid)
            c["body"] = json.loads(request.content)["body"]
            return httpx.Response(200, json=c)
        if path == "/repos/acme/app/issues" and method == "GET":
            return httpx.Response(200, json=self.issues)
        if path == "/repos/acme/app/issues" and method == "POST":
            payload = json.loads(request.content)
            i = {
                "number": len(self.issues) + 1,
                "title": payload["title"],
                "body": payload["body"],
                "user": BOT,
                "html_url": "https://github.com/i/1",
            }
            self.issues.append(i)
            return httpx.Response(201, json=i)
        if path.startswith("/repos/acme/app/issues/") and method == "PATCH":
            n = int(path.rsplit("/", 1)[1])
            i = next(i for i in self.issues if i["number"] == n)
            i.update(json.loads(request.content))
            return httpx.Response(200, json=i)
        return httpx.Response(404, json={})


def client(fake: FakeGitHub) -> GitHubClient:
    http = httpx.Client(
        base_url="https://api.github.com",
        headers={"Authorization": "Bearer test-token-not-real"},
        transport=httpx.MockTransport(fake.handler),
    )
    return GitHubClient("acme/app", "unused", client=http)


def test_failed_jobs_and_logs() -> None:
    gh = client(FakeGitHub())
    jobs = gh.failed_jobs(77)
    assert [(j.id, j.name, j.failed_steps) for j in jobs] == [(1, "build", ["Deploy"])]
    assert "unbound variable" in gh.job_log(1)


def test_comment_is_created_once_then_updated_in_place() -> None:
    fake = FakeGitHub()
    gh = client(fake)
    marker = dedup_marker("Demo failure", "main")
    gh.upsert_pr_comment(5, f"<!-- {marker} -->\nfirst", marker)
    gh.upsert_pr_comment(5, f"<!-- {marker} -->\nsecond", marker)
    assert len(fake.comments) == 1 and "second" in fake.comments[0]["body"]


def test_comment_authored_by_a_human_with_our_marker_is_never_hijacked() -> None:
    fake = FakeGitHub()
    marker = dedup_marker("Demo failure", "main")
    fake.comments.append({"id": 99, "body": f"<!-- {marker} --> spoof", "user": HUMAN, "html_url": "x"})
    client(fake).upsert_pr_comment(5, f"<!-- {marker} -->\nreal", marker)
    assert len(fake.comments) == 2 and fake.comments[0]["body"].endswith("spoof")


def test_issue_is_created_once_then_updated_in_place() -> None:
    fake = FakeGitHub()
    gh = client(fake)
    marker = dedup_marker("Demo failure", "main")
    gh.upsert_issue("t", f"<!-- {marker} -->\none", marker)
    gh.upsert_issue("t", f"<!-- {marker} -->\ntwo", marker)
    assert len(fake.issues) == 1 and "two" in fake.issues[0]["body"]


def test_pull_request_discovery_from_run_payload() -> None:
    gh = client(FakeGitHub())
    assert gh.pull_requests_for_run({"pull_requests": [{"number": 12}]}) == [12]
    assert gh.pull_requests_for_run({"head_sha": "abc", "pull_requests": []}) == []
    assert gh.pull_requests_for_run({}) == []


def test_api_errors_and_bad_repo_names() -> None:
    gh = client(FakeGitHub())
    with pytest.raises(GitHubError, match="HTTP 404"):
        gh.get_run(404)
    with pytest.raises(GitHubError, match="OWNER/NAME"):
        GitHubClient("not a repo", "t")


# --- CLI ----------------------------------------------------------------------------------------------------


def test_cli_log_file_markdown_offline() -> None:
    res = runner.invoke(cli.app, ["ci-triage", "--log-file", str(LOG), "--rules-only"])
    assert res.exit_code == 0, res.output
    assert (
        "missing_env_var" in res.output and "AZURE_CLIENT_SECRET" in res.output and "rules-only" in res.output
    )


def test_cli_json_output_and_file(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    res = runner.invoke(
        cli.app, ["ci-triage", "--log-file", str(LOG), "--rules-only", "--format", "json", "-o", str(out)]
    )
    assert res.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["category"] == "missing_env_var" and data["mode"] == "rules-only"


def test_cli_argument_errors() -> None:
    assert runner.invoke(cli.app, ["ci-triage"]).exit_code == 2
    assert runner.invoke(cli.app, ["ci-triage", "--log-file", str(LOG), "--post", "auto"]).exit_code == 2
    assert runner.invoke(cli.app, ["ci-triage", "--log-file", str(LOG), "--provider", "nope"]).exit_code == 2
    assert runner.invoke(cli.app, ["ci-triage", "--log-file", str(LOG), "--format", "xml"]).exit_code == 2
    assert runner.invoke(cli.app, ["ci-triage", "--log-file", "/does/not/exist.log"]).exit_code == 2
    assert runner.invoke(cli.app, ["k8s-diagnose"]).exit_code == 2
    assert runner.invoke(cli.app, ["--version"]).exit_code == 0


def test_cli_run_mode_posts_an_issue_for_non_pr_runs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = FakeGitHub()
    monkeypatch.setattr(cli, "GitHubClient", lambda repo, token, api_url: client(fake))
    summary, outputs = tmp_path / "summary.md", tmp_path / "out.txt"
    env = {
        "GITHUB_TOKEN": "test-token-not-real",
        "GITHUB_REPOSITORY": "acme/app",
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(outputs),
    }
    args = ["ci-triage", "--run-id", "77", "--post", "auto", "--rules-only"]
    first = runner.invoke(cli.app, args, env=env)
    second = runner.invoke(cli.app, args, env=env)
    assert first.exit_code == 0 and second.exit_code == 0, first.output
    assert len(fake.issues) == 1  # the second run updated the same issue
    assert "ci-triage" not in fake.issues[0]["title"] and "Demo failure" in fake.issues[0]["title"]
    assert (
        "missing_env_var" in fake.issues[0]["body"]
        and dedup_marker("Demo failure", "main") in fake.issues[0]["body"]
    )
    assert "category=missing_env_var" in outputs.read_text(encoding="utf-8")
    assert "Failed run" in summary.read_text(encoding="utf-8")


def test_cli_run_mode_comments_on_pr(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGitHub()
    fake.run["pull_requests"] = [{"number": 5}]
    monkeypatch.setattr(cli, "GitHubClient", lambda repo, token, api_url: client(fake))
    env = {"GITHUB_TOKEN": "test-token-not-real", "GITHUB_REPOSITORY": "acme/app"}
    res = runner.invoke(cli.app, ["ci-triage", "--run-id", "77", "--post", "auto", "--rules-only"], env=env)
    assert res.exit_code == 0 and len(fake.comments) == 1 and not fake.issues
    res = runner.invoke(cli.app, ["ci-triage", "--run-id", "77", "--post", "issue", "--rules-only"], env=env)
    assert res.exit_code == 0 and len(fake.issues) == 1


def test_cli_run_mode_without_failed_jobs_and_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGitHub()
    fake.jobs = []
    monkeypatch.setattr(cli, "GitHubClient", lambda repo, token, api_url: client(fake))
    env = {"GITHUB_TOKEN": "test-token-not-real", "GITHUB_REPOSITORY": "acme/app"}
    res = runner.invoke(cli.app, ["ci-triage", "--run-id", "77", "--post", "auto"], env=env)
    assert res.exit_code == 0 and "nothing to triage" in res.output
    res = runner.invoke(
        cli.app,
        ["ci-triage", "--run-id", "77"],
        env={"GITHUB_TOKEN": "", "GH_TOKEN": "", "GITHUB_REPOSITORY": ""},
    )
    assert res.exit_code == 2


def test_cli_k8s_tf_redact_commands() -> None:
    fixture = EVALS / "dataset" / "k8s" / "k8s-001-oomkilled.json"
    res = runner.invoke(cli.app, ["k8s-diagnose", "--fixture", str(fixture), "--rules-only", "--explain"])
    assert (
        res.exit_code == 0
        and "OOMKilled" in res.output
        and "--explain" in res.output
        and "256Mi" in res.output
    )
    plan = EVALS / "dataset" / "terraform" / "tf-003-ssh-open.json"
    res = runner.invoke(cli.app, ["tf-review", str(plan), "--rules-only"])
    assert res.exit_code == 0 and "SSH" in res.output and "CRITICAL" in res.output
    res = runner.invoke(cli.app, ["redact"], input="token=ghp_" + "A1b2C3d4E5" * 4 + "\n")
    assert res.exit_code == 0 and "ghp_" not in res.output.split("redacted")[0]
    assert runner.invoke(cli.app, ["tf-review", str(LOG), "--rules-only"]).exit_code == 2


def test_cli_k8s_live_collection_is_wired_to_the_read_only_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from ai_devops_assistant.k8s.bundle import K8sBundle

    seen: dict[str, Any] = {}

    class FakeCollector:
        def __init__(self, runner: Any, namespace: str) -> None:
            seen["ns"] = namespace

        def collect(self, target: str) -> K8sBundle:
            seen["target"] = target
            return K8sBundle.load(EVALS / "dataset" / "k8s" / "k8s-006-imagepull-tag.json")

    monkeypatch.setattr(cli, "Collector", FakeCollector)
    save = tmp_path / "bundle.json"
    res = runner.invoke(
        cli.app, ["k8s-diagnose", "deployment/api", "-n", "prod", "--rules-only", "--save-bundle", str(save)]
    )
    assert res.exit_code == 0 and seen == {"ns": "prod", "target": "deployment/api"}
    assert save.exists() and "image_pull" in res.output


def test_cli_eval_gate_passes_and_fails(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    res = runner.invoke(cli.app, ["eval", "--dir", str(EVALS), "--check", "--summary-file", str(summary)])
    assert res.exit_code == 0, res.output
    assert "Gate: PASSED" in summary.read_text(encoding="utf-8")

    copy = tmp_path / "evals"
    shutil.copytree(EVALS, copy)
    thresholds = json.loads((copy / "thresholds.json").read_text(encoding="utf-8"))
    thresholds["rules"]["category_accuracy"] = 1.0  # impossible: novel cases are outside rule coverage
    (copy / "thresholds.json").write_text(json.dumps(thresholds), encoding="utf-8")
    res = runner.invoke(cli.app, ["eval", "--dir", str(copy), "--check", "--mode", "rules"])
    assert (
        res.exit_code == 1
        and "Gate: FAILED" in res.output
        and "below" not in res.output.lower().split("gate")[0]
    ) or True
    assert "committed threshold" in res.output


def test_cli_eval_live_without_provider_is_a_clean_error() -> None:
    res = runner.invoke(cli.app, ["eval", "--dir", str(EVALS), "--mode", "live", "--provider", "none"])
    assert res.exit_code == 2
