## CI failure triage: Cloud login via GitHub OIDC was rejected

Category: `oidc_permission` | Confidence: **high** | Mode: **rules-only**

### Root cause

The job could not exchange its GitHub OIDC token for cloud credentials. Either the workflow lacks `id-token: write`, or the cloud-side trust (IAM role trust policy / Entra federated credential) does not match this repository, branch, environment or pull-request subject.

### Suggested fix

1. Add `permissions: id-token: write` (and `contents: read`) to the job or workflow.
2. Compare the token subject with the trust condition. Typical subjects: `repo:OWNER/REPO:ref:refs/heads/main`, `repo:OWNER/REPO:environment:NAME`, `repo:OWNER/REPO:pull_request`.
3. Fork pull requests never receive an OIDC token; run cloud steps only on trusted events.
4. Confirm the role ARN / client-id / tenant-id inputs point to the intended role.

Suggested commands (review before running, nothing is executed for you):

```bash
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'
az ad app federated-credential list --id <app-object-id>
```

Suggested change (illustrative diff, apply by hand):

```diff
+permissions:
+  id-token: write   # lets the job request a GitHub OIDC token
+  contents: read
```

<details><summary>Evidence</summary>

```
log line 7: Error: Could not assume role with OIDC: Not authorized to perform sts:AssumeRoleWithWebIdentity
log line 8: ##[error]Could not assume role with OIDC: Not authorized to perform sts:AssumeRoleWithWebIdentity
```

</details>

### How this diagnosis was reached (`--explain`)

1. Input: 664 bytes; sent for analysis: 415 bytes; truncated: no.
2. Secrets redacted before analysis: github_token x1.
3. Deterministic rules matched (highest priority first):
   - `ci.oidc.assume_role_denied` -> oidc_permission (high confidence)
     - log line 7: `Error: Could not assume role with OIDC: Not authorized to perform sts:AssumeRoleWithWebIdentity`
     - log line 8: `##[error]Could not assume role with OIDC: Not authorized to perform sts:AssumeRoleWithWebIdentity`
4. Model: not used.
5. Final category: `oidc_permission` (high); mode: rules-only.

> Note: Rules-only mode was requested; no model was called.

---
<sub>ai-devops-assistant 0.1.0 | no model call (0 tokens, $0.00) | secrets redacted: 1 | 415 of 664 bytes analysed | Suggestions are never applied automatically: a human decides.</sub>
