# Evaluation

The eval harness answers one question on every commit: **did a change make the assistant worse?** It does not
answer "how accurate is the model?" and the numbers below must not be read that way.

## What is measured

`evals/dataset/cases.json` lists 70 cases; each has an input fixture, an expected root-cause category and the key
fix elements (lower-case keywords) the answer must contain.

| Kind | Cases | Examples |
| --- | ---: | --- |
| CI logs | 43 | failing tests (pytest, jest, go), missing env var, expired token, Docker build errors (COPY, pull denied, apt, RUN), `terraform` init / validate / plan errors, HTTP 429, YAML errors, OIDC permission denied (AWS, Azure, missing `id-token`), `Resource not accessible`, non-executable script, dependency resolution, lint/type errors, OOM / disk full, DNS, job timeout, an image-scan gate failure (adapted from a real run of this repository's own CI, found when a Dependabot PR failed and the action triaged it) |
| Kubernetes bundles | 20 | CrashLoopBackOff (3 causes), OOMKilled (plain, JVM), ImagePullBackOff (tag, auth, rate limit), liveness / readiness probe failures, Pending (CPU, memory, taint, node selector, PVC), Service selector mismatch, missing ConfigMap / Secret key |
| Terraform plans | 7 | database destroy, bucket replacement, SSH open to the world, S3 public access block off, IAM wildcard, admin policy attachment, clean plan |

`difficulty: novel` marks 7 cases that are **deliberately outside rule coverage** (Go / Maven compile errors, a Helm
nil-pointer, an nginx typo, manifest schema validation, a pod evicted for ephemeral storage, a PodSecurity
admission denial). They exist to show where the rules stop and the model path is needed.

Scoring per case: `category_ok` (predicted category equals expected) and `fix_ok` (every keyword appears in the
primary finding and/or AI analysis text). The suite reports accuracy overall, per kind and per category, plus the
standard / novel split.

## Modes

| Mode | What runs | What it proves |
| --- | --- | --- |
| `rules` | Deterministic analyzers only, no provider | Reproducible regression baseline. **This is the published number.** |
| `mock` | Full pipeline with a `MockProvider` replaying recorded answers (`evals/recorded/responses.json`) for the novel cases and echoing the rules baseline otherwise | The plumbing works: prompt build, schema validation, grounding, merge, render. **It says nothing about model quality**: the recorded answers were written by hand. |
| `live` | Same pipeline with a real provider | A measurement of that model on this dataset, run by you (see below) |

## Results (offline suite, committed thresholds)

Produced by `aida eval` (also in every CI run's job summary):

| Mode | Cases | Category accuracy | Fix elements present | Standard cases | Novel cases |
| --- | ---: | ---: | ---: | ---: | ---: |
| rules | 70 | 90.0% | 90.0% | 100% | 0% |
| mock | 70 | 100% | 100% | 100% | 100% |

Read this honestly:

- The 100% on standard cases is a **regression suite result**, not a generalisation claim. The fixtures were written
  by the same author as the rules, so they are known to be covered. Real logs are messier; expect misses.
- Rules-only scores **0% on the novel cases by design**; that gap is the reason the LLM layer exists.
- The `mock` column is a plumbing check. It would show 100% even if every real model were poor.
- Per-category tables are in the job summary and in `aida eval` output.

## The CI gate

`evals/thresholds.json` is committed. `aida eval --check` exits non-zero if any metric falls below it (overall,
standard, novel for `mock`, per kind, or fewer than 40 cases). Changing a threshold is a reviewed diff, so lowering
quality is visible. CI also writes the results table to the job summary and uploads `eval-results.json`.

```bash
uv run aida eval --check                    # rules + mock, offline, fails on regression
uv run aida eval --mode rules --suite k8s   # one slice
```

## Running against a real model (manual)

This is the only way to get a live-model number, and it is not run automatically.

```bash
export ANTHROPIC_API_KEY=...      # your key; never commit it
uv run aida eval --mode live --provider anthropic --max-cases 20 --max-total-cost-usd 1.00
```

or run the **Eval (live model)** workflow (`workflow_dispatch`) after adding an `ANTHROPIC_API_KEY` repository
secret. Without the secret the workflow exits cleanly. Any OpenAI-compatible endpoint works too
(`AIDA_OPENAI_BASE_URL`, `--provider openai_compatible`).

Notes for interpreting a live run:

- Live runs use the same scorer, so category accuracy and keyword presence are comparable, but keyword matching is a
  coarse proxy for "a good fix". Read the failures.
- Results vary between runs and models. Report the model id, date and number of cases with any figure you quote.
- No live-model accuracy is claimed anywhere in this repository because none has been measured by the author.

## Extending the dataset

1. Add `evals/dataset/<kind>/<id>.<ext>` and an entry in `cases.json` (kind, input, expected_category, fix_keywords).
2. If the case is meant for the model path, add a recording to `evals/recorded/responses.json` whose
   `evidence_quotes` literally appear in the fixture.
3. Run `aida eval` and, if the new case is stable, raise the thresholds in the same commit.

Prefer real, anonymised failures over invented ones, and add a case for every misdiagnosis you find in practice.
