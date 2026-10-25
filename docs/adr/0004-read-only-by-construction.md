# 0004. Read-only by construction

Status: Accepted

## Context

Diagnosis tools tend to grow "fix it for me" buttons. For a tool that reads untrusted text and talks to a model, an
auto-apply path is the highest-risk feature possible: prompt injection becomes remote code execution on a cluster.

## Decision

- The Kubernetes collector is the only place in the package that spawns a process. It validates every invocation
  *before* spawning, against an allow-list of verbs (`get`, `describe`, `logs`), flags and resource types, uses no
  shell, caps output and applies a timeout.
- Secrets can only be probed for existence (`get secret NAME -o name`); their values are never requested.
- There is no apply, delete, patch, exec, edit or port-forward code path, and no flag that enables one.
- Fixes are advice: commands and YAML are rendered in code blocks (risky-looking commands are flagged) and diffs are
  illustrative. Posting is limited to one PR comment or issue.
- Tests enforce this, including a static check that fails if `subprocess` is imported elsewhere or a mutating verb
  is spelled out as an argument.

## Consequences

- A fully compromised model reply can, at worst, display bad advice that a human has to choose to run.
- Users who want automatic remediation must build it separately, with their own approval gates.
- Some evidence needs commands the tool does not run (for example `kubectl exec`); the report suggests them
  instead of executing them.
