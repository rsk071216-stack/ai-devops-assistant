"""MCP server exposing the read-only diagnosis tools to an MCP client (Claude Desktop, Claude Code, IDEs).

The tools are deterministic (rules-only) on purpose: the client already has a model, so the server returns
redacted, structured evidence and a baseline diagnosis for that model to reason over. No tool writes to a
cluster, repository or file. Install with: pip install "ai-devops-assistant[mcp]"
"""

from __future__ import annotations

import json
from typing import Any

from ai_devops_assistant.ci.triage import triage_log
from ai_devops_assistant.config import Settings
from ai_devops_assistant.k8s.bundle import K8sBundle
from ai_devops_assistant.k8s.collector import CollectionError, Collector, ForbiddenCommandError, KubectlRunner
from ai_devops_assistant.k8s.diagnose import diagnose_k8s
from ai_devops_assistant.redaction import redact
from ai_devops_assistant.terraform.review import review_plan

MAX_INPUT_BYTES = 2_000_000
_SETTINGS = Settings(rules_only=True, env={})


def _check_size(text: str) -> None:
    if len(text.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        raise ValueError(f"input is larger than {MAX_INPUT_BYTES} bytes")


def triage_ci_log(log_text: str) -> dict[str, Any]:
    """Diagnose a CI log. Secrets are redacted first; returns category, root cause, fix steps and evidence."""
    _check_size(log_text)
    return triage_log(log_text, settings=_SETTINGS, provider=None).model_dump(mode="json")


def diagnose_k8s_workload(target: str, namespace: str = "default") -> dict[str, Any]:
    """Collect read-only evidence for pod/NAME or deployment/NAME with kubectl and diagnose it."""
    try:
        bundle = Collector(KubectlRunner(), namespace=namespace).collect(target)
    except (CollectionError, ForbiddenCommandError) as exc:
        raise ValueError(str(exc)) from exc
    return diagnose_k8s(bundle, settings=_SETTINGS, provider=None).model_dump(mode="json")


def diagnose_k8s_bundle(bundle_json: str) -> dict[str, Any]:
    """Diagnose a saved evidence bundle (JSON produced by `aida k8s-diagnose --save-bundle`)."""
    _check_size(bundle_json)
    bundle = K8sBundle.model_validate(json.loads(bundle_json))
    return diagnose_k8s(bundle, settings=_SETTINGS, provider=None).model_dump(mode="json")


def review_terraform_plan(plan_json: str) -> dict[str, Any]:
    """Review `terraform show -json` output for destroys, public exposure and IAM widening."""
    _check_size(plan_json)
    return review_plan(json.loads(plan_json), settings=_SETTINGS, provider=None).model_dump(mode="json")


def redact_text(text: str) -> dict[str, Any]:
    """Redact secrets from text before sharing it anywhere."""
    _check_size(text)
    result = redact(text)
    return {"text": result.text, "redactions": result.counts}


def build_server() -> Any:
    """Create the MCP server (imported lazily so the base package works without the optional extra)."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(
        name="ai-devops-assistant",
        instructions=(
            "Read-only DevOps diagnosis tools. Inputs are redacted before analysis. Results are deterministic "
            "baselines: verify against the evidence and never run suggested commands without review."
        ),
    )
    for fn in (triage_ci_log, diagnose_k8s_workload, diagnose_k8s_bundle, review_terraform_plan, redact_text):
        server.add_tool(fn)
    return server


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
