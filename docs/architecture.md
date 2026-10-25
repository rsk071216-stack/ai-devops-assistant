# Architecture

`ai-devops-assistant` (CLI name `aida`) diagnoses CI failures, Kubernetes problems and Terraform plan risk.
The design goal is a tool that is **useful with no API key, safe to point at untrusted logs, and testable offline**.

## Pipeline

Every analyzer (CI, Kubernetes, Terraform) ends in the same tail, implemented once in
[`analysis.py`](../src/ai_devops_assistant/analysis.py).

```mermaid
flowchart LR
    A[Collector<br/>log file, GitHub API,<br/>read-only kubectl,<br/>terraform show -json] --> B[Redactor<br/>secrets removed]
    B --> C[Rules engine<br/>deterministic signatures]
    B --> D[Truncation<br/>head + error window + tail]
    C --> E[Baseline diagnosis]
    D --> F{Provider configured<br/>and within budget?}
    E --> F
    F -- no --> H[Render]
    F -- yes --> G[LLM provider<br/>anthropic / openai_compatible / mock]
    G --> V[Strict schema validation<br/>+ quote grounding + output scrub]
    V --> H
    E --> H
    H --> O[PR comment / issue /<br/>stdout / job summary]
```

Key properties:

- The **rules engine always runs** and always produces the baseline. If there is no key, the model is over budget,
  the provider errors, or its reply fails validation, the user still gets the rules result plus a clear notice.
- The model sees **redacted, truncated** evidence only, inside a delimited data block.
- The model's reply must match a strict pydantic schema (`extra="forbid"`, enum categories, bounded lengths).
  Quoted evidence is checked mechanically against the input; ungrounded quotes are dropped and confidence is capped.
- Nothing the model returns is ever executed. Suggested commands are printed in a code block, and risky-looking ones
  are flagged.

## CI triage sequence

```mermaid
sequenceDiagram
    autonumber
    participant W as Failed workflow
    participant T as Triage workflow<br/>(workflow_run, default branch)
    participant A as aida (composite action)
    participant G as GitHub REST API
    participant L as LLM (optional)
    W->>T: workflow_run completed (failure)
    T->>A: uses: ./ (minimal permissions)
    A->>G: GET run, failed jobs, job logs
    G-->>A: logs (untrusted text)
    A->>A: clean, REDACT, run rules, truncate
    opt provider configured and within cost cap
        A->>L: one request: system prompt + fenced data block
        L-->>A: JSON (validated, grounded, scrubbed)
    end
    A->>G: upsert ONE comment (PR) or issue (no PR)
    Note over A,G: marker comment + bot-author check<br/>keep it a single, updating message
```

## Trust boundaries

```mermaid
flowchart TB
    subgraph Untrusted["Untrusted input"]
        LOGS[CI logs]
        K8S[kubectl output, pod logs]
        PLAN[Terraform plan JSON]
    end
    subgraph Local["Your runner / machine (trusted code)"]
        RED[Redactor]
        RULES[Rules engine]
        VAL[Schema validator + sanitizer]
        COL[kubectl allow-list<br/>get / describe / logs only]
    end
    subgraph External["Leaves the machine (optional)"]
        LLM[LLM API]
    end
    subgraph Humans["Human decision point"]
        PR[PR comment / issue / terminal]
    end
    LOGS --> RED
    K8S --> COL --> RED
    PLAN --> RED
    RED --> RULES
    RED -->|redacted + truncated + fenced| LLM
    LLM -->|JSON only| VAL
    RULES --> PR
    VAL --> PR
```

The only egress of log-derived data is the redacted, size-capped request to the model provider you configured.
There is no code path that writes to a cluster, a repository or a file other than the comment/issue body.

## Modules

| Module | Responsibility |
| --- | --- |
| `redaction.py` | Ordered, named redaction rules + entropy catch-all; idempotent; reports counts only |
| `guardrails.py` | ANSI/timestamp cleaning, head + error-window + tail truncation, per-run `Budget` |
| `engine.py`, `ci/rules.py` | Declarative signature engine and the CI failure signatures |
| `k8s/collector.py` | The only subprocess use in the package; allow-listed read-only kubectl |
| `k8s/facts.py`, `k8s/rules.py` | Normalise JSON or `describe` text into facts; Kubernetes failure analysis |
| `terraform/review.py` | Deterministic plan checks: destroy/replace, public exposure, IAM widening |
| `providers/` | `anthropic`, `openai_compatible`, `mock` behind one `complete()` interface |
| `prompts.py` | System prompt, fenced data block, strict request schema |
| `analysis.py` | Budget check, provider call, validation, grounding, merge into one `Diagnosis` |
| `sanitize.py`, `render.py` | Neutralise untrusted text for markdown; render comments |
| `ci/github.py` | Minimal REST client; one updating comment/issue, bot-author check |
| `evals/runner.py` | Golden-dataset scorer and regression gate |
| `mcp_server.py` | Optional MCP server exposing the read-only tools |

## Decisions

See the [ADR index](adr/README.md). Security details are in the [threat model](threat-model.md); how the numbers
are produced and what they do not mean is in [evals](evals.md).
