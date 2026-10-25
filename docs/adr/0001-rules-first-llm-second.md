# 0001. Rules first, LLM second

Status: Accepted

## Context

The common design for "AI log analysis" is to paste logs into a model. That makes the tool useless without a key,
impossible to test deterministically, expensive on every failure (including trivial ones), and unsafe when the log
is attacker-influenced. Most CI and Kubernetes failures fall into a small set of well-known patterns that a
signature can identify exactly.

## Decision

A deterministic analyzer (regex/structured signatures, plus Kubernetes facts parsed from JSON or `describe` text)
always runs first and always produces a baseline `Finding` with root cause, ordered fix steps, commands and, where
possible, an illustrative diff. The model is optional and runs second: it confirms, refines or corrects the baseline
and handles failures no rule matches. Results from both are shown separately; the final category is the rules
category when a rule matched with medium or high confidence, otherwise the model's.

## Consequences

- Full functionality, tests and demos work offline and with no key.
- Cost is bounded: `--llm-when unknown` calls the model only when no rule matched confidently.
- The model cannot silently override a precise rule; disagreement is surfaced as a notice.
- Rules need maintenance. This is mitigated by the eval suite and by the fact that a missing rule degrades to the
  model path rather than to nothing.
- Rule coverage is a ceiling for the offline numbers; the dataset contains novel cases to keep that visible.
