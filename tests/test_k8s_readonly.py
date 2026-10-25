"""The Kubernetes collector is read-only by construction. These tests pin that guarantee."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ai_devops_assistant.k8s import collector
from ai_devops_assistant.k8s.collector import (
    ALLOWED_VERBS,
    CollectionError,
    Collector,
    ForbiddenCommandError,
    KubectlRunner,
    validate_args,
)

pytestmark = pytest.mark.readonly

ALLOWED = [
    ["get", "pod", "api-1", "-n", "prod", "-o", "json"],
    ["get", "pods", "-n", "prod", "-l", "app=api,tier=backend", "-o", "json"],
    ["describe", "pod", "api-1", "-n", "prod"],
    ["logs", "api-1", "-n", "prod", "-c", "api", "--previous", "--tail=200"],
    [
        "get",
        "events",
        "-n",
        "prod",
        "--field-selector",
        "involvedObject.name=api-1",
        "--sort-by=.lastTimestamp",
    ],
    ["get", "secret", "db-creds", "-n", "prod", "-o", "name"],
    ["get", "services", "-n", "prod", "-o", "json"],
]

FORBIDDEN = [
    ["delete", "pod", "api-1"],
    ["apply", "-f", "x.yaml"],
    ["exec", "api-1", "--", "sh"],
    ["edit", "deployment", "api"],
    ["patch", "deployment", "api", "-p", "{}"],
    ["scale", "deployment", "api", "--replicas=0"],
    ["rollout", "restart", "deployment/api"],
    ["port-forward", "pod/api-1", "8080:8080"],
    ["cp", "api-1:/etc/passwd", "."],
    ["drain", "node1"],
    ["config", "view", "--raw"],
    ["auth", "can-i", "*", "*"],
    ["create", "secret", "generic", "x"],
    ["run", "x", "--image=busybox"],
    ["label", "pod", "api-1", "a=b"],
    ["get", "pod", "api-1", "-w"],
    ["get", "pod", "api-1", "--watch"],
    ["logs", "api-1", "-f"],
    ["logs", "api-1", "--follow"],
    ["get", "pod", "api-1", "--raw=/api/v1"],
    ["get", "pod", "api-1", "--token=abc"],
    ["get", "pod", "api-1", "--as=system:admin"],
    ["get", "pod", "api-1", "--server=https://evil.example"],
    ["get", "pod", "api-1", "--kubeconfig=/tmp/other"],
    ["get", "pod", "api-1", "-o", "yaml"],
    ["get", "pod", "api-1", "-o", "jsonpath={.spec}"],
    ["get", "secret", "db-creds", "-o", "json"],
    ["get", "secrets", "-n", "prod"],
    ["get", "secret", "db-creds", "-o", "yaml"],
    ["describe", "secret", "db-creds"],
    ["get", "pod,secret", "-n", "prod"],
    ["get", "clusterrolebindings"],
    ["get", "pod", "a; rm -rf /"],
    ["get", "pod", "$(id)"],
    ["get", "pod", "a\nb"],
    ["get", "pod", "x", "-n", "a b;c"],
    [],
    ["get"],
    ["logs"],
    ["logs", "a", "b"],
]


@pytest.mark.parametrize("args", ALLOWED)
def test_allowed_commands_validate(args: list[str]) -> None:
    validate_args(args)


@pytest.mark.parametrize("args", FORBIDDEN)
def test_forbidden_commands_are_rejected(args: list[str]) -> None:
    with pytest.raises(ForbiddenCommandError):
        validate_args(args)


@pytest.mark.parametrize("args", FORBIDDEN)
def test_forbidden_commands_never_spawn_a_process(args: list[str]) -> None:
    spawned: list[Any] = []

    def fake_run(*a: Any, **k: Any) -> subprocess.CompletedProcess[str]:
        spawned.append(a)
        return subprocess.CompletedProcess(a, 0, "", "")

    runner = KubectlRunner(runner=fake_run)
    with pytest.raises(ForbiddenCommandError):
        runner.run(*args)
    assert spawned == []
    assert runner.audit == []


def test_only_read_verbs_exist() -> None:
    assert frozenset({"get", "describe", "logs"}) == ALLOWED_VERBS


def test_runner_uses_no_shell_and_records_an_audit_trail() -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        return subprocess.CompletedProcess(cmd, 0, "ok", "")

    runner = KubectlRunner(executable="/usr/bin/kubectl", context="prod-cluster", runner=fake_run)
    assert runner.run("get", "pods", "-n", "prod") == "ok"
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["timeout"] > 0
    assert seen["cmd"][:3] == ["/usr/bin/kubectl", "--context", "prod-cluster"]
    assert runner.audit == ["kubectl get pods -n prod"]


def test_invalid_context_name_is_rejected() -> None:
    with pytest.raises(ForbiddenCommandError):
        KubectlRunner(context="prod; rm -rf /")


def test_kubectl_failure_and_timeout_become_collection_errors() -> None:
    def failing(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 1, "", "Error from server (NotFound)")

    def timing_out(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, 1)

    with pytest.raises(CollectionError, match="NotFound"):
        KubectlRunner(runner=failing).run("get", "pods")
    with pytest.raises(CollectionError):
        KubectlRunner(runner=timing_out).run("get", "pods")


def test_no_write_verbs_appear_anywhere_in_the_package() -> None:
    """Static guard: subprocess is only imported in the collector and no mutating kubectl verb is spelled out."""
    src = Path(collector.__file__).resolve().parents[1]
    offenders = []
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if path.name != "collector.py" and re.search(r"^\s*(import subprocess|from subprocess)", text, re.M):
            offenders.append(f"{path.name}: imports subprocess")
        if re.search(
            r"""["'](apply|delete|patch|exec|edit|replace|scale|annotate|label|cordon|drain)["']\s*,""", text
        ) and path.name not in ("sanitize.py",):
            offenders.append(f"{path.name}: spells a mutating verb as an argument")
    assert offenders == []


class FakeKubectl:
    """Replays canned kubectl output so the Collector runs without a cluster."""

    def __init__(self, pod: dict[str, Any], missing: set[str] | None = None) -> None:
        self.pod = pod
        self.missing = missing or set()
        self.audit: list[str] = []

    def run(self, *args: str) -> str:
        validate_args(list(args))
        self.audit.append(" ".join(args))
        if args[0] == "describe":
            return "Name: api-1\nNamespace: prod\nStatus: Running\n"
        if args[0] == "logs":
            return "line1\n"
        if args[:2] == ("get", "events"):
            return "LAST SEEN TYPE REASON OBJECT MESSAGE\n"
        if args[:2] == ("get", "configmap") and args[2] in self.missing:
            raise CollectionError("NotFound")
        if args[1] in ("configmap", "secret"):
            return f"{args[1]}/{args[2]}"
        return json.dumps(self.run_json(*args))

    def run_json(self, *args: str) -> dict[str, Any]:
        validate_args(list(args))
        if args[:2] == ("get", "pod"):
            return self.pod
        if args[:2] == ("get", "pods"):
            return {"items": [self.pod]}
        if args[:2] == ("get", "deployment"):
            return {"metadata": {"name": "api"}, "spec": {"selector": {"matchLabels": {"app": "api"}}}}
        if args[:2] == ("get", "replicaset"):
            return {"metadata": {"ownerReferences": [{"kind": "Deployment", "name": "api"}]}}
        if args[:2] == ("get", "services"):
            return {
                "items": [{"metadata": {"name": "api"}, "spec": {"selector": {"app": "api"}, "ports": []}}]
            }
        if args[:2] == ("get", "endpoints"):
            return {"items": [{"metadata": {"name": "api"}, "subsets": []}]}
        raise AssertionError(f"unexpected command {args}")


def _pod() -> dict[str, Any]:
    return {
        "metadata": {
            "name": "api-1",
            "namespace": "prod",
            "labels": {"app": "api"},
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "SECRETISH"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "api-rs"}],
        },
        "spec": {
            "containers": [
                {"name": "api", "image": "x", "envFrom": [{"configMapRef": {"name": "api-config"}}]}
            ],
            "volumes": [{"name": "s", "secret": {"secretName": "api-secret"}}],
        },
        "status": {
            "phase": "Running",
            "containerStatuses": [{"name": "api", "ready": False, "restartCount": 3}],
        },
    }


def test_collector_builds_a_bundle_using_only_allowed_commands() -> None:
    fake = FakeKubectl(_pod(), missing={"api-config"})
    bundle = Collector(fake, namespace="prod").collect("deployment/api")  # type: ignore[arg-type]
    assert bundle.owner_chain == ["Deployment/api", "ReplicaSet/api-rs", "Pod/api-1"]
    assert bundle.missing_refs == ["configmap/api-config"]
    assert "annotations" not in bundle.pod["metadata"]  # type: ignore[index]
    assert bundle.services and bundle.endpoints
    assert all(cmd.split()[0] in ALLOWED_VERBS for cmd in fake.audit)


def test_collector_rejects_unknown_target_kinds() -> None:
    with pytest.raises(CollectionError):
        Collector(FakeKubectl(_pod()), namespace="prod").collect("cronjob/x")  # type: ignore[arg-type]
