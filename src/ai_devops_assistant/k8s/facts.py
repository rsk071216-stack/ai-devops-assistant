"""Normalise a bundle into facts, from structured JSON when present and from `kubectl describe` text otherwise."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ai_devops_assistant.k8s.bundle import K8sBundle


@dataclass
class Probe:
    kind: str = ""  # http-get | tcp-socket | exec
    path: str = ""
    port: int | None = None
    initial_delay: int = 0
    timeout: int = 1
    period: int = 10
    failure_threshold: int = 3


@dataclass
class ContainerFacts:
    name: str
    image: str = ""
    waiting_reason: str = ""
    waiting_message: str = ""
    terminated_reason: str = ""
    exit_code: int | None = None
    restart_count: int = 0
    ready: bool | None = None
    mem_limit: str = ""
    mem_request: str = ""
    cpu_limit: str = ""
    cpu_request: str = ""
    ports: list[int] = field(default_factory=list)
    liveness: Probe | None = None
    readiness: Probe | None = None
    startup: Probe | None = None


@dataclass
class PodFacts:
    name: str = ""
    namespace: str = "default"
    phase: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    scheduled: bool | None = None
    containers: list[ContainerFacts] = field(default_factory=list)


_QTY_RE = re.compile(r"^(\d+(?:\.\d+)?)([A-Za-z]*)$")
_FACTORS = {"": 1, "k": 10**3, "K": 10**3, "M": 10**6, "G": 10**9, "T": 10**12,
            "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4}  # fmt: skip


def quantity_to_bytes(value: str) -> int | None:
    m = _QTY_RE.match(value.strip())
    if not m or m.group(2) not in _FACTORS:
        return None
    return int(float(m.group(1)) * _FACTORS[m.group(2)])


def bytes_to_mi(n: int) -> str:
    mi = max(1, round(n / 1024**2))
    return f"{mi}Mi" if mi < 1024 or mi % 1024 else f"{mi // 1024}Gi"


def _probe_from_json(p: dict[str, Any] | None) -> Probe | None:
    if not p:
        return None
    probe = Probe(
        initial_delay=int(p.get("initialDelaySeconds", 0)),
        timeout=int(p.get("timeoutSeconds", 1)),
        period=int(p.get("periodSeconds", 10)),
        failure_threshold=int(p.get("failureThreshold", 3)),
    )
    if "httpGet" in p:
        probe.kind, probe.path = "http-get", str(p["httpGet"].get("path", "/"))
        port = p["httpGet"].get("port")
        probe.port = (
            int(port) if isinstance(port, int) or (isinstance(port, str) and port.isdigit()) else None
        )
    elif "tcpSocket" in p:
        probe.kind = "tcp-socket"
        port = p["tcpSocket"].get("port")
        probe.port = (
            int(port) if isinstance(port, int) or (isinstance(port, str) and port.isdigit()) else None
        )
    elif "exec" in p:
        probe.kind = "exec"
    return probe


def _from_json(pod: dict[str, Any]) -> PodFacts:
    meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
    facts = PodFacts(
        name=meta.get("name", ""),
        namespace=meta.get("namespace", "default"),
        phase=status.get("phase", ""),
        labels=dict(meta.get("labels") or {}),
    )
    for cond in status.get("conditions", []):
        if cond.get("type") == "PodScheduled":
            facts.scheduled = cond.get("status") == "True"
    statuses = {
        s["name"]: s for s in status.get("containerStatuses", []) + status.get("initContainerStatuses", [])
    }
    for c in spec.get("containers", []) + spec.get("initContainers", []):
        res = c.get("resources", {})
        cf = ContainerFacts(
            name=c["name"],
            image=c.get("image", ""),
            mem_limit=res.get("limits", {}).get("memory", ""),
            mem_request=res.get("requests", {}).get("memory", ""),
            cpu_limit=res.get("limits", {}).get("cpu", ""),
            cpu_request=res.get("requests", {}).get("cpu", ""),
            ports=[int(p["containerPort"]) for p in c.get("ports", []) if "containerPort" in p],
            liveness=_probe_from_json(c.get("livenessProbe")),
            readiness=_probe_from_json(c.get("readinessProbe")),
            startup=_probe_from_json(c.get("startupProbe")),
        )
        st = statuses.get(c["name"], {})
        cf.restart_count = int(st.get("restartCount", 0))
        cf.ready = st.get("ready")
        state, last = st.get("state", {}), st.get("lastState", {})
        if "waiting" in state:
            cf.waiting_reason = state["waiting"].get("reason", "")
            cf.waiting_message = state["waiting"].get("message", "")
        term = state.get("terminated") or last.get("terminated") or {}
        cf.terminated_reason = term.get("reason", "")
        cf.exit_code = term.get("exitCode")
        facts.containers.append(cf)
    return facts


_PROBE_RE = re.compile(
    r"(?P<kind>http-get|tcp-socket|exec)\s*(?P<target>\S*)\s*(?:\[.*?\])?\s*delay=(?P<delay>\d+)s\s+timeout=(?P<timeout>\d+)s\s+"
    r"period=(?P<period>\d+)s\s+#success=\d+\s+#failure=(?P<failure>\d+)"
)


def _probe_from_text(line: str) -> Probe | None:
    m = _PROBE_RE.search(line)
    if not m:
        return None
    probe = Probe(
        kind=m["kind"],
        initial_delay=int(m["delay"]),
        timeout=int(m["timeout"]),
        period=int(m["period"]),
        failure_threshold=int(m["failure"]),
    )
    target = m["target"]
    if pm := re.search(r":(\d+)(/[^\s]*)?", target):
        probe.port = int(pm.group(1))
        probe.path = pm.group(2) or ""
    return probe


def _from_describe(text: str) -> PodFacts:
    facts = PodFacts()
    if m := re.search(r"^Name:\s+(\S+)", text, re.M):
        facts.name = m.group(1)
    if m := re.search(r"^Namespace:\s+(\S+)", text, re.M):
        facts.namespace = m.group(1)
    if m := re.search(r"^Status:\s+(\S+)", text, re.M):
        facts.phase = m.group(1)
    if m := re.search(r"^\s+PodScheduled\s+(True|False)", text, re.M):
        facts.scheduled = m.group(1) == "True"
    section = re.search(r"^Containers:\n(.*?)(?=^\S)", text, re.M | re.S)
    if not section:
        return facts
    blocks = re.split(r"(?m)^  (?=\S[^\n]*:\s*$)", section.group(1))
    for block in blocks:
        header = re.match(r"(\S[^\n]*):\s*\n", block)
        if not header:
            continue
        cf = ContainerFacts(name=header.group(1))
        body = block[header.end() :]

        def grab(pattern: str, body: str = body) -> str:
            m = re.search(pattern, body, re.M)
            return m.group(1).strip() if m else ""

        cf.image = grab(r"^\s+Image:\s+(\S+)")
        state_block = re.search(r"^    State:\s+(\w+)\n((?:      .*\n)*)", body, re.M)
        if state_block and state_block.group(1) == "Waiting":
            cf.waiting_reason = grab_in(state_block.group(2), r"Reason:\s+(\S+)")
        elif state_block and state_block.group(1) == "Terminated":
            cf.terminated_reason = grab_in(state_block.group(2), r"Reason:\s+(\S+)")
            cf.exit_code = _int(grab_in(state_block.group(2), r"Exit Code:\s+(\d+)"))
        last_block = re.search(r"^    Last State:\s+(\w+)\n((?:      .*\n)*)", body, re.M)
        if last_block and last_block.group(1) == "Terminated":
            cf.terminated_reason = cf.terminated_reason or grab_in(last_block.group(2), r"Reason:\s+(\S+)")
            if cf.exit_code is None:
                cf.exit_code = _int(grab_in(last_block.group(2), r"Exit Code:\s+(\d+)"))
        cf.restart_count = _int(grab(r"^\s+Restart Count:\s+(\d+)")) or 0
        ready = grab(r"^\s+Ready:\s+(True|False)")
        cf.ready = None if not ready else ready == "True"
        limits = re.search(r"^    Limits:\n((?:      .*\n)*)", body, re.M)
        requests = re.search(r"^    Requests:\n((?:      .*\n)*)", body, re.M)
        if limits:
            cf.mem_limit = grab_in(limits.group(1), r"memory:\s+(\S+)")
            cf.cpu_limit = grab_in(limits.group(1), r"cpu:\s+(\S+)")
        if requests:
            cf.mem_request = grab_in(requests.group(1), r"memory:\s+(\S+)")
            cf.cpu_request = grab_in(requests.group(1), r"cpu:\s+(\S+)")
        for port in re.findall(r"^\s+Port:\s+(\d+)/", body, re.M):
            cf.ports.append(int(port))
        for key, attr in (("Liveness", "liveness"), ("Readiness", "readiness"), ("Startup", "startup")):
            if m := re.search(rf"^\s+{key}:\s+(.*)$", body, re.M):
                setattr(cf, attr, _probe_from_text(m.group(1)))
        facts.containers.append(cf)
    return facts


def grab_in(text: str, pattern: str) -> str:
    m = re.search(pattern, text)
    return m.group(1).strip() if m else ""


def _int(value: str) -> int | None:
    return int(value) if value.isdigit() else None


def pod_facts(bundle: K8sBundle) -> PodFacts:
    """Prefer structured JSON; fall back to parsing `kubectl describe pod` output."""
    if bundle.pod:
        return _from_json(bundle.pod)
    return _from_describe(bundle.describe)
