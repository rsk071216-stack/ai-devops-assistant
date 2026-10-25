## Terraform plan risk review: 1 risk finding(s), worst: CRITICAL (1 create)

Category: `public_exposure` | Confidence: **high** | Mode: **rules-only**

| Severity | Finding | Why it matters |
| --- | --- | --- |
| CRITICAL | Ingress open to the internet: aws_security_group.bastion | A security group rule allows SSH (22) from 0.0.0.0/0 (anywhere). Anyone on the internet can reach it. |

### Reviewer checklist

1. Restrict `cidr_blocks` to known ranges (office/VPN/bastion) or reference another security group.
2. For SSH/RDP use SSM Session Manager or a bastion instead of public ingress.

> Note: Rules-only mode was requested; no model was called.

---
<sub>ai-devops-assistant 0.1.0 | no model call (0 tokens, $0.00) | secrets redacted: 0 | 326 of 467 bytes analysed | Suggestions are never applied automatically: a human decides.</sub>
