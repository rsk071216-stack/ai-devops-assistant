## Kubernetes diagnosis: Container `api` was OOMKilled (memory limit 128Mi)

Category: `oom_killed` | Confidence: **high** | Mode: **rules-only**

### Root cause

Container `api` was killed by the kernel OOM killer (exit code 137): it used more memory than its limit of 128Mi. It restarts repeatedly, which shows up as CrashLoopBackOff.

### Suggested fix

1. Raise the memory limit of `api` (suggested 256Mi, double the current limit) as a short-term fix.
2. Measure real usage over a representative period before settling on a number (set requests close to typical usage).
3. If usage grows without bound, investigate a leak or unbounded cache/queue instead of only raising the limit.

Suggested commands (review before running, nothing is executed for you):

```bash
kubectl -n prod top pod --containers
kubectl -n prod set resources deployment/api -c api --limits=memory=256Mi
```

Suggested change (illustrative diff, apply by hand):

```diff
   resources:
     limits:
-      memory: 128Mi
+      memory: 256Mi
```

<details><summary>Evidence</summary>

```
describe: Reason:       OOMKilled
```

</details>

### Other signals in the same input

- Container `api` is in CrashLoopBackOff (`k8s.crash_loop`)

### How this diagnosis was reached (`--explain`)

1. Input: 2394 bytes; sent for analysis: 1799 bytes; truncated: no.
2. Secrets redacted before analysis: none found.
3. Deterministic rules matched (highest priority first):
   - `k8s.oom_killed` -> oom_killed (high confidence)
     - describe: `Reason:       OOMKilled`
   - `k8s.crash_loop` -> crash_loop (high confidence)
     - events: `2m          Warning   BackOff            pod/api-7d9f6c8b5-x2k9p      Back-off restarting failed container api in pod api-7d9f6c8b5-x2k9p`
4. Model: not used.
5. Final category: `oom_killed` (high); mode: rules-only.

> Note: Rules-only mode was requested; no model was called.

---
<sub>ai-devops-assistant 0.1.0 | no model call (0 tokens, $0.00) | secrets redacted: 0 | 1799 of 2394 bytes analysed | Suggestions are never applied automatically: a human decides.</sub>
