"""Minimal GitHub REST client for CI triage (read run/jobs/logs, upsert one comment or issue).

Uses httpx only. The token is read from the environment by the CLI, sent only to the GitHub API
host, and never logged. Every write is a comment or an issue; nothing in the repo is modified.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

import httpx

API_VERSION = "2022-11-28"
MAX_LOG_BYTES_PER_JOB = 5_000_000
ISSUE_LABEL = "ci-triage"


class GitHubError(RuntimeError):
    pass


@dataclass(frozen=True)
class FailedJob:
    id: int
    name: str
    failed_steps: list[str]


def dedup_marker(workflow_name: str, branch: str) -> str:
    """Stable HTML-comment marker. Hashed so run-controlled names can never break out of the comment."""
    digest = hashlib.sha256(f"{workflow_name}\n{branch}".encode()).hexdigest()[:12]
    return f"aida-triage:v1:{digest}"


class GitHubClient:
    def __init__(
        self,
        repo: str,
        token: str,
        api_url: str = "https://api.github.com",
        client: httpx.Client | None = None,
    ) -> None:
        if not re.fullmatch(r"[\w.\-]+/[\w.\-]+", repo):
            raise GitHubError("repository must look like OWNER/NAME")
        self.repo = repo
        self._client = client or httpx.Client(
            base_url=api_url.rstrip("/"),
            timeout=30.0,
            follow_redirects=True,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "ai-devops-assistant",
            },
        )

    # --- helpers -------------------------------------------------------------------------------
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise GitHubError(f"GitHub request failed: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise GitHubError(
                f"GitHub API {method} {path.split('?', maxsplit=1)[0]} returned HTTP {resp.status_code}"
            )
        return resp

    def _paginate(self, path: str, key: str | None = None, max_pages: int = 5) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            sep = "&" if "?" in path else "?"
            data = self._request("GET", f"{path}{sep}per_page=100&page={page}").json()
            chunk = data[key] if key else data
            items.extend(chunk)
            if len(chunk) < 100:
                break
        return items

    # --- reads ---------------------------------------------------------------------------------
    def get_run(self, run_id: int) -> dict[str, Any]:
        return dict(self._request("GET", f"/repos/{self.repo}/actions/runs/{run_id}").json())

    def failed_jobs(self, run_id: int, limit: int = 3) -> list[FailedJob]:
        jobs = self._paginate(f"/repos/{self.repo}/actions/runs/{run_id}/jobs", key="jobs")
        failed: list[FailedJob] = []
        for job in jobs:
            if job.get("conclusion") not in ("failure", "timed_out"):
                continue
            steps = [s["name"] for s in job.get("steps", []) if s.get("conclusion") == "failure"]
            failed.append(FailedJob(id=int(job["id"]), name=str(job["name"]), failed_steps=steps))
        return failed[:limit]

    def job_log(self, job_id: int) -> str:
        text = self._request("GET", f"/repos/{self.repo}/actions/jobs/{job_id}/logs").text
        if len(text) > MAX_LOG_BYTES_PER_JOB:
            text = text[-MAX_LOG_BYTES_PER_JOB:]
        return text

    def pull_requests_for_run(self, run: dict[str, Any]) -> list[int]:
        numbers = [int(pr["number"]) for pr in run.get("pull_requests") or []]
        if numbers:
            return numbers
        sha = run.get("head_sha")
        if not sha:
            return []
        try:
            prs = self._request("GET", f"/repos/{self.repo}/commits/{sha}/pulls").json()
        except GitHubError:
            return []
        head_repo = (run.get("head_repository") or {}).get("full_name")
        return [
            int(p["number"])
            for p in prs
            if p.get("state") == "open" and p.get("base", {}).get("repo", {}).get("full_name") == head_repo
        ][:1]

    # --- writes --------------------------------------------------------------------------------
    @staticmethod
    def _is_ours(item: dict[str, Any], marker: str) -> bool:
        user = item.get("user") or {}
        return marker in (item.get("body") or "") and user.get("type") == "Bot"

    def upsert_pr_comment(self, pr_number: int, body: str, marker: str) -> str:
        """Create or update the single triage comment on a PR. Returns its HTML URL."""
        comments = self._paginate(f"/repos/{self.repo}/issues/{pr_number}/comments")
        existing = next((c for c in comments if self._is_ours(c, marker)), None)
        if existing:
            resp = self._request(
                "PATCH", f"/repos/{self.repo}/issues/comments/{existing['id']}", json={"body": body}
            )
        else:
            resp = self._request(
                "POST", f"/repos/{self.repo}/issues/{pr_number}/comments", json={"body": body}
            )
        return str(resp.json()["html_url"])

    def upsert_issue(self, title: str, body: str, marker: str) -> str:
        """Create or update the single open triage issue for this workflow+branch. Returns its HTML URL."""
        # No label filter on lookup: labels can be silently dropped when the token lacks push access.
        issues = self._paginate(f"/repos/{self.repo}/issues?state=open")
        existing = next((i for i in issues if "pull_request" not in i and self._is_ours(i, marker)), None)
        if existing:
            resp = self._request(
                "PATCH",
                f"/repos/{self.repo}/issues/{existing['number']}",
                json={"title": title, "body": body},
            )
        else:
            resp = self._request(
                "POST",
                f"/repos/{self.repo}/issues",
                json={"title": title, "body": body, "labels": [ISSUE_LABEL]},
            )
        return str(resp.json()["html_url"])
