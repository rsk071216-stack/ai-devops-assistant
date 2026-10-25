"""Deterministic Kubernetes failure analysis over an evidence bundle (works fully offline)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from ai_devops_assistant.engine import clean_value
from ai_devops_assistant.k8s.bundle import K8sBundle
from ai_devops_assistant.k8s.facts import (
    ContainerFacts,
    PodFacts,
    bytes_to_mi,
    pod_facts,
    quantity_to_bytes,
)
from ai_devops_assistant.models import Category, Evidence, Finding

_ERROR_LINE = re.compile(
    r"(?i)(error|fatal|panic|exception|traceback|refused|denied|cannot|can't|failed|not found|no such|invalid|killed)"
)


@dataclass
class _Ctx:
    bundle: K8sBundle
    facts: PodFacts
    text: str  # describe + events
    ns: str
    workload: str  # e.g. deployment/api

    def line(self, pattern: str, source: str = "events") -> Evidence | None:
        for chunk_name, chunk in (("events", self.bundle.events), ("describe", self.bundle.describe)):
            for ln in chunk.splitlines():
                if re.search(pattern, ln):
                    return Evidence(
                        source=chunk_name if source == "events" else source, excerpt=ln.strip()[:300]
                    )
        return None


def _workload_ref(b: K8sBundle) -> str:
    for item in b.owner_chain:
        kind, _, name = item.partition("/")
        if kind.lower() in ("deployment", "statefulset", "daemonset", "cronjob", "job"):
            return f"{kind.lower()}/{name}"
    return b.target.lower()


def _q(value: str) -> str:
    return clean_value(value, 120)


def _ev(source: str, text: str) -> Evidence:
    return Evidence(source=source, excerpt=text.strip()[:300])


# --------------------------------------------------------------------------------------------------
def _missing_config(c: _Ctx) -> Finding | None:
    patterns = [
        r"""(?i)(configmap|secret) ["']?([\w.\-]+)["']? not found""",
        r"""(?i)couldn't find key ([\w.\-]+) in (ConfigMap|Secret) ([\w./\-]+)""",
    ]
    kind = name = key = ""
    ev: Evidence | None = None
    for pat in patterns:
        for ln in c.text.splitlines():
            if m := re.search(pat, ln):
                ev = _ev("events", ln)
                if "find key" in pat:
                    key, kind, name = m.group(1), m.group(2).lower(), m.group(3).split("/")[-1]
                else:
                    kind, name = m.group(1).lower(), m.group(2)
                break
        if ev:
            break
    waiting = any(x.waiting_reason == "CreateContainerConfigError" for x in c.facts.containers)
    if not ev and c.bundle.missing_refs:
        kind, _, name = c.bundle.missing_refs[0].partition("/")
        ev = _ev("collector", f"{c.bundle.missing_refs[0]} does not exist in namespace {c.ns}")
    if not ev and not waiting:
        return None
    kind, name, key = _q(kind) or "configmap", _q(name) or "<name>", _q(key)
    resource = "secret" if kind == "secret" else "configmap"
    if key:
        cause = (
            f"The container references key `{key}` of {resource} `{name}`, but that key does not exist in it "
            f"(the {resource} exists, the key is missing or misspelled)."
        )
        create = f"kubectl -n {c.ns} get {resource} {name} -o jsonpath='{{.data}}'"
    else:
        cause = (
            f"The pod references {resource} `{name}` which does not exist in namespace `{c.ns}`, so the "
            "container cannot be created (CreateContainerConfigError / volume mount failure)."
        )
        create = (
            f"kubectl -n {c.ns} create secret generic {name} --from-literal=<KEY>=<value>"
            if resource == "secret"
            else f"kubectl -n {c.ns} create configmap {name} --from-literal=<KEY>=<value>"
        )
    return Finding(
        rule_id="k8s.missing_config_ref",
        category=Category.MISSING_CONFIG_REF,
        title=f"Missing {resource} `{name}`" + (f" key `{key}`" if key else ""),
        root_cause=cause,
        fix_steps=[
            f"Check which namespace the workload runs in and whether the {resource} exists there.",
            f"Create or restore `{name}` (from your GitOps source or secret manager), or correct the name in the manifest.",
            "If the reference is not essential, mark it `optional: true` so the pod can start without it.",
            "Pods in this state retry automatically once the object exists; no restart is needed.",
        ],
        suggested_commands=[
            f"kubectl -n {c.ns} get {resource} {name}",
            create,
            f"kubectl -n {c.ns} get pods -w",
        ],
        confidence="high",
        severity="high",
        evidence=[ev] if ev else [],
    )


def _oom(c: _Ctx) -> Finding | None:
    victim = next((x for x in c.facts.containers if x.terminated_reason == "OOMKilled"), None)
    ev = c.line(r"OOMKilled")
    if victim is None and ev is None:
        return None
    victim = victim or (c.facts.containers[0] if c.facts.containers else ContainerFacts(name="<container>"))
    limit_b = quantity_to_bytes(victim.mem_limit) if victim.mem_limit else None
    new_limit = bytes_to_mi(limit_b * 2) if limit_b else "512Mi"
    old = victim.mem_limit or "(none set)"
    cause = (
        f"Container `{victim.name}` was killed by the kernel OOM killer (exit code 137): it used more memory than "
        f"its limit of {old}. It restarts repeatedly, which shows up as CrashLoopBackOff."
    )
    patch = (
        "   resources:\n     limits:\n"
        + (f"-      memory: {victim.mem_limit}\n" if victim.mem_limit else "")
        + f"+      memory: {new_limit}"
    )
    runtime_hint = ""
    blob = f"{victim.image} {c.bundle.previous_logs} {c.bundle.logs}".lower()
    if any(w in blob for w in ("java", "jdk", "temurin", "outofmemoryerror")):
        runtime_hint = (
            "For a JVM set `-XX:MaxRAMPercentage=75` so the heap is sized from the container limit."
        )
    elif any(w in blob for w in ("node", "npm")):
        runtime_hint = "For Node.js set `--max-old-space-size` below the container limit (about 75 percent)."
    steps = [
        f"Raise the memory limit of `{victim.name}` (suggested {new_limit}, double the current limit) as a short-term fix.",
        "Measure real usage over a representative period before settling on a number (set requests close to typical usage).",
        "If usage grows without bound, investigate a leak or unbounded cache/queue instead of only raising the limit.",
    ]
    if runtime_hint:
        steps.append(runtime_hint)
    return Finding(
        rule_id="k8s.oom_killed",
        category=Category.OOM_KILLED,
        title=f"Container `{victim.name}` was OOMKilled (memory limit {old})",
        root_cause=cause,
        fix_steps=steps,
        suggested_commands=[
            f"kubectl -n {c.ns} top pod --containers",
            f"kubectl -n {c.ns} set resources {c.workload} -c {victim.name} --limits=memory={new_limit}",
        ],
        suggested_patch=patch,
        confidence="high",
        severity="high",
        evidence=[ev]
        if ev
        else [_ev("pod status", f"{victim.name}: reason=OOMKilled exitCode={victim.exit_code}")],
    )


def _image_pull(c: _Ctx) -> Finding | None:
    waiting = next(
        (
            x
            for x in c.facts.containers
            if x.waiting_reason in ("ErrImagePull", "ImagePullBackOff", "InvalidImageName")
        ),
        None,
    )
    ev = c.line(r"(?i)failed to pull image|ErrImagePull|ImagePullBackOff|InvalidImageName")
    if waiting is None and ev is None:
        return None
    msg = " ".join(ln for ln in c.text.splitlines() if re.search(r"(?i)pull|image", ln))
    image = waiting.image if waiting else ""
    if m := re.search(r"""(?i)pull(?:ing)? image ["']([^"']+)["']""", msg):
        image = m.group(1)
    image = _q(image) or "<image>"
    low = msg.lower()
    registry = (
        image.split("/")[0]
        if "/" in image and ("." in image.split("/")[0] or ":" in image.split("/")[0])
        else "docker.io"
    )
    if re.search(r"toomanyrequests|rate limit", low):
        title, cause = (
            "Registry rate limit while pulling the image",
            (
                f"The registry throttled the pull of `{image}` (anonymous pull limit). Nodes pull from shared IPs, so the limit is hit quickly."
            ),
        )
        steps = [
            "Authenticate pulls with an imagePullSecret.",
            "Mirror the image into your own registry (ACR/ECR/GHCR) and pull from there.",
            "Pin by digest so nodes can reuse the cached layer.",
        ]
    elif re.search(r"unauthorized|authentication required|pull access denied|denied|forbidden|401|403", low):
        title, cause = (
            "Not authorised to pull the image",
            (
                f"The kubelet could not authenticate to `{registry}` to pull `{image}`: the imagePullSecret is missing, "
                "wrong, expired, or the repository is private."
            ),
        )
        steps = [
            f"Create a registry secret in namespace `{c.ns}` and reference it from the pod spec or its ServiceAccount.",
            "If you use a cloud registry, grant the node/kubelet identity pull permission (AcrPull / ECR read) instead of static secrets.",
            "Check the secret has not expired (registry tokens and PATs expire).",
        ]
    elif re.search(r"not found|manifest unknown|name unknown|no such manifest|does not exist", low):
        title, cause = (
            "Image or tag does not exist",
            (
                f"The registry has no manifest for `{image}`: the tag was never pushed, was deleted, or the repository name is misspelled."
            ),
        )
        steps = [
            "Verify the exact image name and tag exist in the registry (case-sensitive).",
            "Check that the CI job that publishes this tag finished before the deployment rolled out.",
            "Prefer immutable references (digest) to avoid tags that move or disappear.",
        ]
    elif re.search(
        r"no such host|i/o timeout|dial tcp|connection refused|tls handshake|temporary failure", low
    ):
        title, cause = (
            "Nodes cannot reach the registry",
            (
                f"The node could not connect to `{registry}` to pull `{image}` (DNS, egress firewall, proxy or private-endpoint problem)."
            ),
        )
        steps = [
            "Test DNS and egress from a node or debug pod (read-only checks first).",
            "Check NetworkPolicy/NSG/firewall/NAT rules and any required proxy settings on the node.",
            "For private registries confirm the private endpoint or VPC route exists.",
        ]
    else:
        title, cause = (
            "Image pull is failing",
            f"The kubelet cannot pull `{image}`; see the event message for the exact registry error.",
        )
        steps = [
            "Read the full event message to see the registry error.",
            "Check image name, tag, registry reachability and credentials.",
        ]
    return Finding(
        rule_id="k8s.image_pull",
        category=Category.IMAGE_PULL,
        title=f"{title} (`{image}`)",
        root_cause=cause,
        fix_steps=steps,
        suggested_commands=[
            f"kubectl -n {c.ns} describe pod {c.facts.name or '<pod>'}",
            f"kubectl -n {c.ns} create secret docker-registry regcred --docker-server={registry} --docker-username=<user> --docker-password=<token>",
            f'kubectl -n {c.ns} patch serviceaccount default -p \'{{"imagePullSecrets": [{{"name": "regcred"}}]}}\'',
        ],
        suggested_patch="   spec:\n+    imagePullSecrets:\n+      - name: regcred",
        confidence="high",
        severity="high",
        evidence=[ev] if ev else [],
    )


def _pending(c: _Ctx) -> Finding | None:
    if c.facts.phase != "Pending" and not re.search(r"FailedScheduling", c.text):
        return None
    sched = [ln for ln in c.text.splitlines() if "FailedScheduling" in ln or "nodes are available" in ln]
    if not sched and c.facts.scheduled is not False:
        return None
    ln = sched[-1] if sched else ""
    msg = ln.split("preemption:")[0]
    total = 0
    if m := re.search(r"0/(\d+) nodes", msg):
        total = int(m.group(1))
    body = msg.split("available:", 1)[-1].strip().rstrip(".")
    segments: list[tuple[int, str]] = []
    for seg in re.split(r",\s*(?=\d+ )", body):
        if m := re.match(r"(\d+) (?:node\(s\) )?(.*)", seg.strip()):
            segments.append((int(m.group(1)), m.group(2)))
        elif seg.strip():
            segments.append((total or 1, seg.strip()))

    def classify(reason: str) -> Category:
        r = reason.lower()
        if "insufficient" in r:
            return Category.PENDING_RESOURCES
        if "persistentvolumeclaim" in r or "unbound" in r or "volume node affinity" in r or "pvc" in r:
            return Category.PENDING_PVC
        if (
            "taint" in r
            or "affinity" in r
            or "selector" in r
            or "anti-affinity" in r
            or "topology spread" in r
        ):
            return Category.PENDING_TAINT_AFFINITY
        return Category.UNKNOWN

    ranked = sorted(
        ((n, classify(r), r) for n, r in segments if classify(r) != Category.UNKNOWN),
        key=lambda t: (
            -t[0],
            [Category.PENDING_RESOURCES, Category.PENDING_PVC, Category.PENDING_TAINT_AFFINITY].index(t[1]),
        ),
    )
    if not ranked and re.search(r'persistentvolumeclaim "[^"]+" not found', c.text):
        ranked = [(total or 1, Category.PENDING_PVC, "persistentvolumeclaim not found")]
    if not ranked:
        return None
    n, cat, reason = ranked[0]
    ev = _ev("events", ln) if ln else None
    cont = c.facts.containers[0] if c.facts.containers else ContainerFacts(name="app")
    if cat == Category.PENDING_RESOURCES:
        res = re.search(r"Insufficient ([\w./\-]+)", reason)
        what = res.group(1) if res else "resources"
        req = {"cpu": cont.cpu_request, "memory": cont.mem_request}.get(what, "")
        return Finding(
            rule_id="k8s.pending.resources",
            category=cat,
            title=f"Pod cannot be scheduled: insufficient {what} on {n} of {total or '?'} nodes",
            root_cause=(
                f"No node has enough free {what} for this pod's request"
                + (f" ({what} request: {req})" if req else "")
                + ". The pod stays Pending until capacity appears or the request shrinks."
            ),
            fix_steps=[
                f"Compare the pod's {what} request with node allocatable and current allocation (commands below).",
                f"Lower the {what} request if it is over-provisioned (right-size from real usage).",
                "Otherwise add capacity: scale the node pool or enable the cluster autoscaler for this pool.",
                "Check ResourceQuota / LimitRange in the namespace as well.",
            ],
            suggested_commands=[
                "kubectl describe nodes | grep -A8 'Allocated resources'",
                f"kubectl -n {c.ns} get resourcequota,limitrange",
                f"kubectl -n {c.ns} top pods --containers",
            ],
            confidence="high",
            severity="high",
            evidence=[e for e in (ev,) if e],
        )
    if cat == Category.PENDING_PVC:
        pvc = re.search(r'persistentvolumeclaim "([^"]+)"', c.text)
        name = _q(pvc.group(1)) if pvc else "<pvc>"
        return Finding(
            rule_id="k8s.pending.pvc",
            category=cat,
            title=f"Pod is Pending because PersistentVolumeClaim `{name}` is not bound",
            root_cause=(
                "The pod needs a PersistentVolumeClaim that is missing or not bound, so the scheduler cannot place it. "
                "Typical causes: the PVC does not exist, no StorageClass can provision it (no default class, wrong name, "
                "provisioner failing), or the volume lives in a different zone than the available nodes."
            ),
            fix_steps=[
                "Check that the PVC exists in this namespace and look at its events for provisioning errors.",
                "Confirm `storageClassName` exists and a default StorageClass is set if the PVC omits it.",
                "For zonal disks use `volumeBindingMode: WaitForFirstConsumer` so the volume is created where the pod can run.",
            ],
            suggested_commands=[
                f"kubectl -n {c.ns} get pvc,pv",
                f"kubectl -n {c.ns} describe pvc {name}",
                "kubectl get storageclass",
            ],
            confidence="high",
            severity="high",
            evidence=[e for e in (ev,) if e],
        )
    taint = re.search(r"taint \{([^}]*)\}", reason)
    patch = None
    fix = [
        "Check which taints and labels the nodes have and decide whether the pod should run there.",
        "Add a matching toleration, or fix `nodeSelector` / node affinity to match real node labels.",
        "If no node should be tainted this way, remove the taint from the node pool.",
    ]
    cause = "The scheduler filtered out every node because of taints or node selection rules (taints, nodeSelector, affinity or topology spread)."
    if taint:
        key, _, val = taint.group(1).partition(":")
        key, val = _q(key.strip()), _q(val.strip())
        op = f'operator: "Equal"\n+      value: "{val}"' if val else 'operator: "Exists"'
        patch = (
            f'   spec:\n+    tolerations:\n+      - key: "{key}"\n+      {op}\n+        effect: "NoSchedule"'
        )
        cause = (
            f"Nodes are tainted with `{key}{'=' + val if val else ''}` and the pod has no matching toleration, so the "
            "scheduler skips them."
        )
    return Finding(
        rule_id="k8s.pending.taint_affinity",
        category=Category.PENDING_TAINT_AFFINITY,
        title="Pod cannot be scheduled: taints or node selection rules exclude every node",
        root_cause=cause,
        fix_steps=fix,
        suggested_commands=[
            "kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints",
            "kubectl get nodes --show-labels",
            f"kubectl -n {c.ns} get pod {c.facts.name or '<pod>'} -o jsonpath='{{.spec.nodeSelector}}'",
        ],
        suggested_patch=patch,
        confidence="high",
        severity="high",
        evidence=[e for e in (ev,) if e],
    )


def _probe(c: _Ctx) -> Finding | None:
    m = None
    ev_line = ""
    for ln in c.text.splitlines():
        if mm := re.search(r"(Liveness|Readiness|Startup) probe failed: (.*)", ln):
            m, ev_line = mm, ln
    if not m:
        return None
    kind, detail = m.group(1).lower(), m.group(2)
    probes = [(x, getattr(x, kind)) for x in c.facts.containers if getattr(x, kind) is not None]
    cont, probe = (
        probes[0]
        if probes
        else (c.facts.containers[0] if c.facts.containers else ContainerFacts(name="app"), None)
    )
    port_bad = bool(probe and probe.port and cont.ports and probe.port not in cont.ports)
    path = probe.path if probe and probe.path else "/healthz"
    port = probe.port if probe and probe.port else (cont.ports[0] if cont.ports else 8080)
    if re.search(r"statuscode: (\d+)", detail):
        code = re.search(r"statuscode: (\d+)", detail)
        status = int(code.group(1)) if code else 0
        why = (
            f"the endpoint `{path}` answers HTTP {status}, so the path is wrong"
            if status == 404
            else f"the app answers HTTP {status} on `{path}`: it is running but reports itself unhealthy (often a failing dependency)"
        )
    elif re.search(r"connection refused", detail):
        why = f"nothing is listening on port {port} when the probe runs: the app is still starting, crashed, or listens on a different port"
    elif re.search(r"deadline exceeded|timeout|timed out", detail, re.I):
        why = "the app does not answer within the probe timeout (slow start or overloaded)"
    else:
        why = "the probe check fails"
    if port_bad and probe is not None:
        why += f"; note the probe targets port {probe.port} but the container declares {cont.ports}"
    effect = (
        "the container is killed and restarted by the kubelet"
        if kind in ("liveness", "startup")
        else "the pod is removed from Service endpoints (Ready=False) and receives no traffic"
    )
    startup_yaml = (
        "     startupProbe:\n+      httpGet:\n+        path: "
        + path
        + "\n+        port: "
        + str(port)
        + "\n+      failureThreshold: 30\n+      periodSeconds: 10"
    )
    return Finding(
        rule_id="k8s.probe_failure",
        category=Category.PROBE_FAILURE,
        title=f"{kind.capitalize()} probe failing for container `{cont.name}`",
        root_cause=f"The {kind} probe of `{cont.name}` fails: {why}. As a result {effect}.",
        fix_steps=[
            f"Verify the probe target matches the app: path `{path}`, port {port} (port-forward and curl it).",
            "If the app needs time to start, add a `startupProbe` (below) instead of a long `initialDelaySeconds` on liveness.",
            "Keep liveness probes cheap and independent of downstream dependencies; use readiness for dependency checks.",
            "Raise `timeoutSeconds`/`failureThreshold` only if the endpoint is correct but slow.",
        ],
        suggested_commands=[
            f"kubectl -n {c.ns} port-forward pod/{c.facts.name or '<pod>'} {port}:{port}",
            f"curl -i localhost:{port}{path}",
            f"kubectl -n {c.ns} logs {c.facts.name or '<pod>'} -c {cont.name} --previous",
        ],
        suggested_patch=startup_yaml,
        confidence="high",
        severity="high",
        evidence=[_ev("events", ev_line)],
    )


def _selector_diff(selector: dict[str, str], labels: dict[str, str]) -> list[str]:
    diffs = []
    for k, v in selector.items():
        if k not in labels:
            diffs.append(f"selector `{k}={v}` but pod has no label `{k}`")
        elif labels[k] != v:
            diffs.append(f"selector `{k}={v}` but pod label is `{k}={labels[k]}`")
    return diffs


def _service_selector(c: _Ctx) -> Finding | None:
    labels = dict(c.facts.labels)
    if c.bundle.deployment:
        tmpl = c.bundle.deployment.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {})
        labels = labels or dict(tmpl)
    if not labels or not c.bundle.services:
        return None
    ep_by_name = {e.get("metadata", {}).get("name"): e for e in c.bundle.endpoints}
    workload_name = c.workload.split("/")[-1]
    for svc in c.bundle.services:
        name = svc.get("metadata", {}).get("name", "")
        selector = svc.get("spec", {}).get("selector") or {}
        if not selector or set(selector.items()) <= set(labels.items()):
            continue
        relevant = (
            workload_name in name
            or name in workload_name
            or any(k in labels for k in selector)
            or any(v in labels.values() for v in selector.values())
        )
        if not relevant:
            continue
        ep = ep_by_name.get(name)
        has_addresses = bool(ep and any(s.get("addresses") for s in ep.get("subsets") or []))
        if has_addresses:
            continue
        diffs = _selector_diff(selector, labels)
        fixed = {k: labels.get(k, v) for k, v in selector.items() if k in labels}
        patch_json = json.dumps({"spec": {"selector": fixed}}, separators=(",", ":")) if fixed else ""
        known_ep = ep is not None
        return Finding(
            rule_id="k8s.service_selector_mismatch",
            category=Category.SERVICE_SELECTOR_MISMATCH,
            title=f"Service `{name}` selects no pods (selector does not match pod labels)",
            root_cause=(
                f"Service `{name}` has no endpoints because its selector does not match the pods: "
                + "; ".join(diffs[:3])
                + ". Traffic to the Service fails (connection refused / 503) even though the pods run."
            ),
            fix_steps=[
                "Decide which side is right: the Service selector or the pod template labels, and make them identical.",
                "After the fix, confirm the Endpoints object lists pod IPs.",
                "Remember: Deployment `spec.selector` is immutable; prefer changing the Service selector.",
            ],
            suggested_commands=[
                f"kubectl -n {c.ns} get endpoints {name}",
                f"kubectl -n {c.ns} get pods --show-labels",
                *(
                    [f"kubectl -n {c.ns} patch service {name} --type merge -p '{patch_json}'"]
                    if patch_json
                    else []
                ),
            ],
            suggested_patch="\n".join(
                ["   selector:"]
                + [
                    f"-    {k}: {v}\n+    {k}: {labels[k]}"
                    for k, v in selector.items()
                    if k in labels and labels[k] != v
                ]
            ),
            confidence="high" if known_ep else "medium",
            severity="high",
            evidence=[_ev("service", f"{name}: selector={selector} pod labels={labels}")],
        )
    return None


_EXIT_HINTS = {
    0: "the process exited normally (code 0) although a Deployment expects a long-running process",
    1: "the application exited with a generic error (code 1); the last log lines usually say why",
    2: "the application rejected its arguments or configuration (code 2)",
    126: "the entrypoint is not executable (code 126)",
    127: "the command in `command`/`args`/ENTRYPOINT was not found (code 127)",
    137: "the process was SIGKILLed (code 137) without an OOMKilled reason (probe kill, preStop, node pressure)",
    139: "the process crashed with a segmentation fault (code 139)",
    143: "the process received SIGTERM (code 143) and exited",
}

_LOG_HINTS: tuple[tuple[str, str], ...] = (
    (
        r"(?i)(ECONNREFUSED|connection refused|could not connect to server|no such host|dial tcp.*refused)",
        "it cannot reach a dependency (database, cache or API): wrong host/port/DNS or the dependency is not up yet",
    ),
    (
        r"(?i)(exec format error)",
        "the image architecture does not match the node (for example arm64 image on amd64 nodes)",
    ),
    (
        r"(?i)(permission denied|read-only file system|EACCES)",
        "it lacks file permissions (runAsUser/fsGroup, readOnlyRootFilesystem or a mounted volume owned by root)",
    ),
    (r"(?i)(address already in use|EADDRINUSE)", "the port is already in use inside the pod"),
    (
        r"(?i)(ModuleNotFoundError|Cannot find module|ClassNotFoundException|no such file or directory)",
        "a file, module or class the image should contain is missing (wrong image build or wrong working directory/command)",
    ),
    (
        r"(?i)(password authentication failed|access denied for user|authentication failed|invalid credentials)",
        "the dependency rejects its credentials (wrong or rotated secret)",
    ),
    (
        r"(?i)(missing|required|not set).{0,40}(env|environment|variable|config)|(env|environment|variable).{0,40}(missing|required|not set)",
        "a required environment variable or config value is missing",
    ),
    (
        r"(?i)(invalid configuration|failed to parse|yaml|unmarshal|cannot unmarshal)",
        "its configuration file is invalid",
    ),
)


def _crash_loop(c: _Ctx) -> Finding | None:
    victim = next(
        (x for x in c.facts.containers if x.waiting_reason == "CrashLoopBackOff"),
        next((x for x in c.facts.containers if x.restart_count >= 3 and x.exit_code not in (None, 0)), None),
    )
    ev = c.line(r"(?i)back-off restarting failed container|CrashLoopBackOff")
    if victim is None and ev is None:
        return None
    victim = victim or (c.facts.containers[0] if c.facts.containers else ContainerFacts(name="app"))
    logs = c.bundle.previous_logs or c.bundle.logs
    last_errors = [ln.strip() for ln in logs.splitlines() if _ERROR_LINE.search(ln)][-3:]
    hint = ""
    for pat, text in _LOG_HINTS:
        if re.search(pat, logs):
            hint = text
            break
    exit_text = _EXIT_HINTS.get(victim.exit_code if victim.exit_code is not None else -1, "")
    cause = f"Container `{victim.name}` keeps exiting and the kubelet restarts it with back-off (CrashLoopBackOff, {victim.restart_count} restarts)."
    if exit_text:
        cause += f" Exit status: {exit_text}."
    if hint:
        cause += f" The logs indicate {hint}."
    evidence = [_ev("previous logs" if c.bundle.previous_logs else "logs", ln) for ln in last_errors]
    if ev:
        evidence.append(ev)
    steps = [
        "Read the previous container's logs (the crashed instance), not the current restart: `--previous`.",
        "Fix the error shown in the last log lines; the exit code narrows it down (see above).",
        "Compare the environment, ConfigMaps/Secrets and image tag with the last working revision.",
        "If the cause is unclear, roll back to the last good revision while you investigate.",
    ]
    if victim.exit_code in {127, 126}:
        steps.insert(
            1,
            "Check `command`/`args` in the pod spec against the image's real ENTRYPOINT and installed binaries.",
        )
    return Finding(
        rule_id="k8s.crash_loop",
        category=Category.CRASH_LOOP,
        title=f"Container `{victim.name}` is in CrashLoopBackOff",
        root_cause=cause,
        fix_steps=steps,
        suggested_commands=[
            f"kubectl -n {c.ns} logs {c.facts.name or '<pod>'} -c {victim.name} --previous",
            f"kubectl -n {c.ns} describe pod {c.facts.name or '<pod>'}",
            f"kubectl -n {c.ns} rollout history {c.workload}",
        ],
        confidence="medium" if not (hint or exit_text) else "high",
        severity="high",
        evidence=evidence,
    )


_CHECKS: tuple[tuple[int, Callable[[_Ctx], Finding | None]], ...] = (
    (90, _missing_config),
    (88, _oom),
    (86, _image_pull),
    (84, _pending),
    (80, _probe),
    (75, _service_selector),
    (60, _crash_loop),
)


def diagnose_bundle(bundle: K8sBundle) -> list[Finding]:
    """Run all checks on an already-redacted bundle; returns findings ranked by specificity."""
    facts = pod_facts(bundle)
    ctx = _Ctx(
        bundle=bundle,
        facts=facts,
        text=f"{bundle.describe}\n{bundle.events}",
        ns=clean_value(bundle.namespace or facts.namespace, 63) or "default",
        workload=_workload_ref(bundle),
    )
    found: list[tuple[int, Finding]] = []
    for priority, check in _CHECKS:
        if finding := check(ctx):
            found.append((priority, finding))
    found.sort(key=lambda t: -t[0])
    return [f for _, f in found]
