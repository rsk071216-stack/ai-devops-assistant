"""MCP server: tool surface is fixed, read-only and deterministic. Skipped if the optional extra is absent."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from conftest import EVALS, rand

pytest.importorskip("mcp")

from ai_devops_assistant import mcp_server

EXPECTED_TOOLS = {
    "triage_ci_log",
    "diagnose_k8s_workload",
    "diagnose_k8s_bundle",
    "review_terraform_plan",
    "redact_text",
}


def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    server = mcp_server.build_server()
    result = asyncio.run(server.call_tool(name, args))
    assert not result.is_error
    return dict(result.structured_content or {})


def test_exposed_tools_are_exactly_the_read_only_set() -> None:
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == EXPECTED_TOOLS
    assert not any(w in t.name for t in tools for w in ("apply", "delete", "patch", "exec", "write"))


def test_ci_log_tool_redacts_and_diagnoses() -> None:
    token = "ghp_" + rand(36)
    log = (EVALS / "dataset" / "ci" / "ci-001-unbound-variable.log").read_text(
        encoding="utf-8"
    ) + f"token {token}\n"
    out = call("triage_ci_log", {"log_text": log})
    assert out["category"] == "missing_env_var" and out["mode"] == "rules-only"
    assert token not in json.dumps(out)


def test_k8s_bundle_and_terraform_tools() -> None:
    bundle = (EVALS / "dataset" / "k8s" / "k8s-001-oomkilled.json").read_text(encoding="utf-8")
    assert call("diagnose_k8s_bundle", {"bundle_json": bundle})["category"] == "oom_killed"
    plan = (EVALS / "dataset" / "terraform" / "tf-003-ssh-open.json").read_text(encoding="utf-8")
    assert call("review_terraform_plan", {"plan_json": plan})["category"] == "public_exposure"


def test_oversized_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="larger than"):
        mcp_server.redact_text("x" * (mcp_server.MAX_INPUT_BYTES + 1))
