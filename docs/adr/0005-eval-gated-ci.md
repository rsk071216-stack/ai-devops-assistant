# 0005. Eval-gated CI with honest offline numbers

Status: Accepted

## Context

Rules and prompts change constantly. Without a regression harness, "improvements" silently break other cases, and
published accuracy figures are usually unverifiable marketing.

## Decision

- A golden dataset (70 cases: CI logs, Kubernetes bundles, Terraform plans) with expected category and key fix
  elements, committed with the code.
- `aida eval` scores two offline modes: `rules` (the real deterministic analyzers) and `mock` (the whole pipeline
  with recorded answers). `evals/thresholds.json` is committed; CI fails if any metric drops below it and writes the
  table to the job summary.
- Live-model evaluation is a separate, manual `workflow_dispatch` with an optional secret. It is never run on
  push, never committed, and no live-model figure is published without being measured.
- Documentation states what the numbers mean: standard cases were written alongside the rules, so 100% there is a
  regression result, not generalisation; novel cases show the rules' ceiling; the mock column checks plumbing only.

## Consequences

- Rule changes that lose coverage fail CI immediately and visibly.
- Raising quality means adding cases and raising thresholds in the same reviewed commit.
- The dataset is synthetic and small; it must be extended with anonymised real failures to say anything about
  production accuracy. This limit is stated in the README and in `docs/evals.md`.
