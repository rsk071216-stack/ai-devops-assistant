# Configuration

Flags win over environment variables. With nothing configured the tool runs rules-only.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | unset | Enables the `anthropic` provider (official SDK, structured output). Never logged. |
| `AIDA_MODEL` | `claude-sonnet-5-5` (anthropic) | Model id for any provider. `--model` overrides it. |
| `AIDA_OPENAI_BASE_URL` | unset | Base URL of an OpenAI-compatible endpoint, e.g. `http://localhost:11434/v1`. Enables `openai_compatible`. |
| `AIDA_OPENAI_API_KEY` | unset | Bearer token for that endpoint (optional for local servers). |
| `AIDA_OPENAI_MODEL` | `local-model` | Model name sent to that endpoint (if `AIDA_MODEL` is unset). |
| `AIDA_OPENAI_JSON_MODE` | `json_schema` | `json_schema`, `json_object` or `none`, depending on what the server supports. |
| `AIDA_MOCK_RESPONSES` | unset | Path to a recordings file for `--provider mock`. |
| `AIDA_PRICE_INPUT_PER_MTOK`, `AIDA_PRICE_OUTPUT_PER_MTOK` | built-in table | Override USD per million tokens used for cost estimates. |
| `GITHUB_TOKEN` / `GH_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_API_URL` | set by Actions | Used by `ci-triage --run-id`. |

## Provider selection (`--provider`)

| Value | Behaviour |
| --- | --- |
| `auto` (default) | `anthropic` if `ANTHROPIC_API_KEY` is set, else `openai_compatible` if `AIDA_OPENAI_BASE_URL` is set, else rules-only with a notice |
| `anthropic` | Official SDK; the reply is constrained with a JSON schema (`output_config.format`) and re-validated with pydantic |
| `openai_compatible` | `POST {base}/chat/completions` via httpx, temperature 0, bounded retries on 408/409/429/5xx |
| `mock` | Deterministic recorded answers for tests and the eval harness |
| `none` | Never call a model |

## Common flags

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--rules-only` | all | Never call a model, even if a key is present |
| `--llm-when {always,unknown}` | all | `unknown` calls the model only when no rule matched confidently (cheaper) |
| `--max-log-bytes N` | ci, k8s | Evidence bytes sent to a model (default 24000, about 6k tokens) |
| `--max-cost-usd X` | all | Worst-case cost cap per run (default 0.10); the call is skipped above it |
| `--explain` | all | Add the evidence trail: matched rules, redaction counts, truncation, validation result |
| `--format {markdown,json}` | all | Machine-readable output is the full `Diagnosis` model |
| `-o FILE` | all | Write the result to a file instead of stdout |
| `--log-level` | all | Structured JSON logs on stderr (events and counters only, never log content) |

## Commands

```text
aida ci-triage   --log-file FILE | --run-id N [--repo O/N] [--post none|auto|pr|issue]
aida k8s-diagnose [pod/NAME | deployment/NAME] [-n NS] [--fixture BUNDLE.json] [--save-bundle FILE] [--context CTX]
aida tf-review   PLAN.json
aida eval        [--mode rules|mock|live|all] [--suite all|ci|k8s|terraform] [--check] [--summary-file F]
aida redact      [FILE]              # show exactly what would be sent to a model
```

## GitHub Action inputs

| Input | Default | Notes |
| --- | --- | --- |
| `run-id` | `github.event.workflow_run.id` | Failed run to triage |
| `post` | `auto` | PR comment if the run has a PR, else an issue |
| `provider`, `model` | `auto`, empty | See above |
| `anthropic-api-key` | empty | Optional; empty means rules-only |
| `openai-base-url`, `openai-api-key` | empty | Optional OpenAI-compatible backend |
| `rules-only` | `false` | Force no model |
| `max-cost-usd` | `0.10` | Cost cap |
| `explain` | `false` | Include the evidence trail |

Outputs: `category`, `url`, `mode`.

### Minimal permissions for the consumer job

```yaml
permissions:
  actions: read          # download the failed jobs' logs
  contents: read         # check out the action code (or omit when using a published action by SHA)
  issues: write          # only needed for runs without a pull request
  pull-requests: write   # only needed to comment on pull requests
```

Use `workflow_run` so logs from untrusted pull requests are analysed without handing that code a write token.
