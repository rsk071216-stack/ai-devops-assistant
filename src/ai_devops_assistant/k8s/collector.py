"""Read-only evidence collector for Kubernetes.

Safety model: this module is the ONLY place that executes a subprocess in the whole package, and it can only
run `kubectl get|describe|logs` with a fixed allow-list of flags and resource types. There is no code path for
apply, delete, patch, exec, edit, scale, cp, port-forward or any other verb. Validation happens before
the process is spawned and is covered by tests (tests/test_k8s_readonly.py).
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from typing import Any

from ai_devops_assistant.k8s.bundle import K8sBundle

ALLOWED_VERBS = frozenset({"get", "describe", "logs"})
ALLOWED_RESOURCES = frozenset(
    {
        "pod", "pods", "po", "deployment", "deployments", "deploy", "replicaset", "replicasets", "rs",
        "statefulset", "statefulsets", "sts", "daemonset", "daemonsets", "ds", "job", "jobs", "cronjob",
        "cronjobs", "service", "services", "svc", "endpoints", "ep", "event", "events", "ev", "configmap",
        "configmaps", "cm", "secret", "secrets", "persistentvolumeclaim", "persistentvolumeclaims", "pvc",
        "persistentvolume", "persistentvolumes", "pv", "storageclass", "storageclasses", "sc", "node", "nodes",
    }
)  # fmt: skip
SECRET_RESOURCES = frozenset({"secret", "secrets"})
# flag -> takes a value
ALLOWED_FLAGS: dict[str, bool] = {
    "-n": True, "--namespace": True,
    "-o": True, "--output": True,
    "-l": True, "--selector": True,
    "-c": True, "--container": True,
    "--previous": False, "--all-containers": False, "--timestamps": False, "--prefix": False,
    "--tail": True, "--since": True, "--limit-bytes": True,
    "--field-selector": True, "--sort-by": True, "--show-labels": False,
}  # fmt: skip
ALLOWED_OUTPUTS = frozenset({"json", "name", "wide"})
_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/=,@+!\- ]{1,200}$")
_CONTEXT_RE = re.compile(r"^[A-Za-z0-9_.:/@\-]{1,200}$")
MAX_OUTPUT_BYTES = 2_000_000


class ForbiddenCommandError(ValueError):
    """Raised before any process is spawned when a command is outside the read-only allow-list."""


class CollectionError(RuntimeError):
    pass


def validate_args(args: list[str]) -> None:
    """Raise ForbiddenCommandError unless ``args`` is an allowed read-only kubectl invocation."""
    if not args:
        raise ForbiddenCommandError("empty kubectl command")
    verb = args[0]
    if verb not in ALLOWED_VERBS:
        raise ForbiddenCommandError(
            f"kubectl verb '{verb}' is not allowed (read-only: {sorted(ALLOWED_VERBS)})"
        )
    positional: list[str] = []
    flags: dict[str, str] = {}
    i = 1
    while i < len(args):
        tok = args[i]
        if not isinstance(tok, str) or not tok or "\n" in tok or "\x00" in tok:
            raise ForbiddenCommandError("invalid argument")
        if tok.startswith("-"):
            name, eq, inline = tok.partition("=")
            if name not in ALLOWED_FLAGS:
                raise ForbiddenCommandError(f"flag '{name}' is not allowed")
            if ALLOWED_FLAGS[name]:
                if eq:
                    value = inline
                else:
                    i += 1
                    if i >= len(args):
                        raise ForbiddenCommandError(f"flag '{name}' needs a value")
                    value = args[i]
                if not _VALUE_RE.match(value):
                    raise ForbiddenCommandError(f"value for '{name}' contains disallowed characters")
                flags[name] = value
            else:
                if eq:
                    raise ForbiddenCommandError(f"flag '{name}' takes no value")
                flags[name] = ""
        else:
            if not _VALUE_RE.match(tok):
                raise ForbiddenCommandError("argument contains disallowed characters")
            positional.append(tok)
        i += 1

    out = flags.get("-o") or flags.get("--output")
    if out is not None and out not in ALLOWED_OUTPUTS:
        raise ForbiddenCommandError(f"output format '{out}' is not allowed")

    if verb == "logs":
        if len(positional) != 1:
            raise ForbiddenCommandError("logs takes exactly one pod name")
        return
    if not positional:
        raise ForbiddenCommandError(f"'{verb}' needs a resource type")
    resource = positional[0].split("/")[0].split(",")[0].lower()
    if resource not in ALLOWED_RESOURCES:
        raise ForbiddenCommandError(f"resource type '{resource}' is not allowed")
    if resource in SECRET_RESOURCES and (verb != "get" or out != "name"):
        raise ForbiddenCommandError(
            "secrets may only be checked for existence with `get secret NAME -o name`"
        )
    if "," in positional[0] and any(r in SECRET_RESOURCES for r in positional[0].lower().split(",")):
        raise ForbiddenCommandError("secrets may not be combined with other resource types")


Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class KubectlRunner:
    """Executes validated kubectl commands with no shell, a timeout and an output cap."""

    def __init__(
        self,
        executable: str = "kubectl",
        context: str | None = None,
        timeout_s: float = 30.0,
        runner: Runner = subprocess.run,
    ) -> None:
        if context is not None and not _CONTEXT_RE.match(context):
            raise ForbiddenCommandError("invalid kube context name")
        self._exe = executable
        self._context = context
        self._timeout = timeout_s
        self._runner = runner
        self.audit: list[str] = []

    def run(self, *args: str) -> str:
        arglist = list(args)
        validate_args(arglist)
        cmd = [self._exe, *(["--context", self._context] if self._context else []), *arglist]
        self.audit.append("kubectl " + " ".join(arglist))
        try:
            proc = self._runner(
                cmd, capture_output=True, text=True, timeout=self._timeout, check=False, shell=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CollectionError(f"kubectl could not be run: {type(exc).__name__}") from exc
        if proc.returncode != 0:
            raise CollectionError((proc.stderr or "kubectl failed").strip()[:300])
        return proc.stdout[:MAX_OUTPUT_BYTES]

    def run_json(self, *args: str) -> dict[str, Any]:
        try:
            data = json.loads(self.run(*args))
        except ValueError as exc:
            raise CollectionError("kubectl did not return JSON") from exc
        if not isinstance(data, dict):
            raise CollectionError("unexpected kubectl JSON shape")
        return data


def _strip_pod(pod: dict[str, Any]) -> dict[str, Any]:
    """Drop fields that can hold secrets or noise (annotations carry last-applied-configuration)."""
    pod = json.loads(json.dumps(pod))
    meta = pod.get("metadata", {})
    for key in ("annotations", "managedFields"):
        meta.pop(key, None)
    return pod


def _pod_health_score(pod: dict[str, Any]) -> int:
    status = pod.get("status", {})
    score = 0 if status.get("phase") == "Running" else 10
    for cs in status.get("containerStatuses", []):
        score += int(cs.get("restartCount", 0))
        if not cs.get("ready"):
            score += 5
    return score


def _referenced_objects(pod: dict[str, Any]) -> list[tuple[str, str]]:
    refs: set[tuple[str, str]] = set()
    spec = pod.get("spec", {})
    for c in spec.get("containers", []) + spec.get("initContainers", []):
        for ef in c.get("envFrom", []):
            for key, kind in (("configMapRef", "configmap"), ("secretRef", "secret")):
                if key in ef and not ef[key].get("optional"):
                    refs.add((kind, ef[key]["name"]))
        for env in c.get("env", []):
            vf = env.get("valueFrom", {})
            for key, kind in (("configMapKeyRef", "configmap"), ("secretKeyRef", "secret")):
                if key in vf and not vf[key].get("optional"):
                    refs.add((kind, vf[key]["name"]))
    for vol in spec.get("volumes", []):
        if "configMap" in vol and not vol["configMap"].get("optional"):
            refs.add(("configmap", vol["configMap"]["name"]))
        if "secret" in vol and not vol["secret"].get("optional"):
            refs.add(("secret", vol["secret"]["secretName"]))
    return sorted(refs)


class Collector:
    def __init__(self, runner: KubectlRunner, namespace: str = "default", tail: int = 200) -> None:
        self.k = runner
        self.ns = namespace
        self.tail = tail

    def _try(self, *args: str) -> str:
        try:
            return self.k.run(*args)
        except CollectionError:
            return ""

    def collect(self, target: str) -> K8sBundle:
        kind, _, name = target.partition("/")
        if not name:
            kind, name = "pod", target
        kind = kind.lower()
        deployment: dict[str, Any] | None = None
        if kind in ("deployment", "deploy"):
            deployment = self.k.run_json("get", "deployment", name, "-n", self.ns, "-o", "json")
            match = deployment.get("spec", {}).get("selector", {}).get("matchLabels", {})
            if not match:
                raise CollectionError("deployment has no matchLabels selector")
            selector = ",".join(f"{k}={v}" for k, v in sorted(match.items()))
            pods = self.k.run_json("get", "pods", "-n", self.ns, "-l", selector, "-o", "json").get(
                "items", []
            )
            if not pods:
                raise CollectionError("deployment has no pods (check events: replicaset or quota problem)")
            pod = max(pods, key=_pod_health_score)
        elif kind in ("pod", "po"):
            pod = self.k.run_json("get", "pod", name, "-n", self.ns, "-o", "json")
        else:
            raise CollectionError("target must be pod/NAME or deployment/NAME")

        pod_name = pod["metadata"]["name"]
        chain = [f"Pod/{pod_name}"]
        owner = next(iter(pod["metadata"].get("ownerReferences", [])), None)
        while owner and len(chain) < 4:
            chain.insert(0, f"{owner['kind']}/{owner['name']}")
            if owner["kind"] != "ReplicaSet":
                break
            rs = self._try_json("get", "replicaset", owner["name"], "-n", self.ns, "-o", "json")
            owner = next(iter((rs or {}).get("metadata", {}).get("ownerReferences", [])), None)

        describe = self._try("describe", "pod", pod_name, "-n", self.ns)
        events = self._try(
            "get",
            "events",
            "-n",
            self.ns,
            "--field-selector",
            f"involvedObject.name={pod_name}",
            "--sort-by=.lastTimestamp",
        )
        statuses = pod.get("status", {}).get("containerStatuses", [])
        victim = max(statuses, key=lambda s: int(s.get("restartCount", 0)), default=None)
        cflag = ["-c", victim["name"]] if victim else ["--all-containers"]
        logs = self._try("logs", pod_name, "-n", self.ns, *cflag, f"--tail={self.tail}")
        previous = self._try("logs", pod_name, "-n", self.ns, *cflag, "--previous", f"--tail={self.tail}")

        services = self._try_json("get", "services", "-n", self.ns, "-o", "json") or {}
        endpoints = self._try_json("get", "endpoints", "-n", self.ns, "-o", "json") or {}
        missing = []
        for res_kind, res_name in _referenced_objects(pod):
            try:
                self.k.run("get", res_kind, res_name, "-n", self.ns, "-o", "name")
            except CollectionError:
                missing.append(f"{res_kind}/{res_name}")

        return K8sBundle(
            target=f"{kind}/{name}",
            namespace=self.ns,
            pod=_strip_pod(pod),
            deployment=_strip_pod(deployment) if deployment else None,
            describe=describe,
            events=events,
            logs=logs,
            previous_logs=previous,
            owner_chain=chain,
            services=[
                {
                    "metadata": {"name": s["metadata"]["name"]},
                    "spec": {
                        "selector": s.get("spec", {}).get("selector") or {},
                        "ports": s.get("spec", {}).get("ports", []),
                    },
                }
                for s in services.get("items", [])[:50]
            ],
            endpoints=[
                {
                    "metadata": {"name": e["metadata"]["name"]},
                    "subsets": [
                        {"addresses": [{"ip": "x"}]} for s in e.get("subsets") or [] if s.get("addresses")
                    ][:1],
                }
                for e in endpoints.get("items", [])[:50]
            ],
            missing_refs=missing,
            collected_with=list(self.k.audit),
        )

    def _try_json(self, *args: str) -> dict[str, Any] | None:
        try:
            return self.k.run_json(*args)
        except CollectionError:
            return None
