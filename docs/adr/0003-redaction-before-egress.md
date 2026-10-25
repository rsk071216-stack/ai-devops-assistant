# 0003. Redact before anything leaves the machine

Status: Accepted

## Context

Logs, environment dumps and manifests contain credentials by accident. The assistant sends text to a model and
posts text into pull requests, both of which are egress.

## Decision

A single redactor runs first in every pipeline, before rules, truncation, rendering and any provider call. It is a
list of named rules applied in order: specific token formats (cloud, source control, registries, LLM and SaaS keys),
structured credentials (JWT, bearer, PEM blocks including unterminated ones, URL passwords, connection strings),
contextual `NAME=value` assignments, Kubernetes `Secret` data, and finally a Shannon-entropy catch-all for long random
tokens. Replacements are `[REDACTED:<rule>]`, the function is idempotent, and only per-rule counts are ever reported.
Model output is redacted again on the way back. The collector drops fields known to carry secrets (annotations).

False positives are controlled with guards (placeholders, `${{ ... }}` references, stop-words such as `expired` or
`unbound`, git SHAs and sha256 digests never reach the entropy threshold).

## Alternatives considered

- Sending raw logs and trusting the provider: rejected, the exposure is the problem.
- An allow-list of safe lines: too lossy; it would remove the evidence the diagnosis needs.
- A secret scanner dependency: heavier, and it would not know the project's context rules. Pattern coverage here is
  small and testable.

## Consequences

- Test corpus of 70 cases generated at runtime from fake values (never real secrets).
- Limit: unlabeled, low-entropy secrets can slip through. Documented in the threat model; `--rules-only` is the
  answer for the most sensitive repositories.
