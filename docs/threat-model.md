# Threat model

Scope: the `aida` CLI, the composite GitHub Action, the optional MCP server and the container image.
Method: STRIDE-style walk over the data flow in [architecture](architecture.md). Each row names the control and the
test that pins it, so claims here can be checked.

## Assets

| Asset | Why it matters |
| --- | --- |
| Secrets in logs and manifests (tokens, keys, connection strings) | CI logs and pod env regularly contain them by accident |
| The cluster and repositories | A diagnosis tool must not become a way to change them |
| The reader's trust in the output | A confident wrong answer can cause harm if acted on blindly |
| Model API spend | An attacker who can trigger runs could inflate cost |

## Actors

- **Log author / attacker**: anyone who can influence log content (a pull request author, a dependency, a pod's app).
  Treated as fully untrusted.
- **Model provider**: trusted only with redacted, size-capped data you chose to send.
- **Operator**: the person who configures keys and permissions.

## Controls

### 1. Secrets must not leave the machine

| Threat | Control | Evidence |
| --- | --- | --- |
| Token or key in a log is sent to the LLM or posted in a comment | Redaction runs **before** rules, truncation, rendering and any provider call. Rules: AWS/GitHub/GitLab/npm/PyPI/Docker/Slack/Stripe/Anthropic/OpenAI/Google/Azure formats, JWT, bearer tokens, PEM private keys (including unterminated blocks), URL passwords, connection strings, `NAME=value` secrets, Kubernetes `Secret` data, and a Shannon-entropy catch-all | `tests/test_redaction.py` (70 cases, secrets generated at test time) including an end-to-end test that inspects the exact prompt sent to a provider |
| Model echoes or invents a secret | Model output is passed through the same redactor | `test_model_echoing_a_secret_is_scrubbed` |
| Secret in the bundle's JSON (env vars) | Env values are redacted as `NAME=value` pairs, annotations (`last-applied-configuration`) are dropped at collection | `test_secrets_in_pod_env_and_logs_are_redacted_before_analysis` |
| Logs record which secrets were found | Only counts per rule are logged or shown, never values | `test_counts_never_contain_secret_values` |

Honest limits: redaction is pattern-based. A secret with no recognisable shape, name or entropy (a short numeric PIN,
a hex key without a `key=` label) can pass through. Do not rely on it as the only control for highly sensitive
repositories; use `--rules-only` there.

### 2. Logs are untrusted input (prompt injection)

| Threat | Control | Evidence |
| --- | --- | --- |
| Log says "ignore previous instructions" and steers the model | System prompt declares delimited blocks to be data; evidence is confined to one fenced block with a random per-request id; the rules baseline outside the block contains only static, rule-authored strings | `tests/test_injection.py` |
| Log forges the block delimiters | Lookalike markers in the data are neutralised before fencing | `test_marker_spoofing_is_neutralised` |
| Model returns off-schema JSON, extra fields, a made-up category | Strict pydantic schema (`extra="forbid"`, enum, length bounds); on failure the reply is discarded and the rules result stands | `test_schema_violating_reply_is_discarded...` (7 shapes) |
| Model invents evidence | Each quoted excerpt must literally occur in the (redacted) input; failures are dropped and confidence is capped at `low` | `test_ungrounded_quotes_are_dropped...` |
| Model suggests a destructive command | Never executed. Printed in a code block; commands matching destructive patterns are flagged | `test_hostile_model_reply_is_rendered_inert`, and `no_exec` fixture that fails the test if any process is spawned |
| Model or log injects markdown into the PR comment (image beacons, mentions, links, raw HTML) | Untrusted prose is neutralised: images removed, links shown as inline code, `@mentions` backticked, HTML escaped; evidence is code-fenced with a fence longer than any backtick run inside | `tests/test_render_evals.py::test_neutralize_markdown` |
| Attacker spoofs the "update this comment" marker | The marker is a hash (never the workflow name) and only comments authored by a Bot account are updated | `test_comment_authored_by_a_human_with_our_marker_is_never_hijacked` |

### 3. Read-only by design

| Threat | Control | Evidence |
| --- | --- | --- |
| The tool (or a compromised prompt) changes cluster state | The kubectl wrapper accepts only `get`, `describe`, `logs`, a fixed flag allow-list and a fixed resource allow-list; validation runs **before** any process is spawned; no shell | `tests/test_k8s_readonly.py` (verbs, flags, secrets, injection characters, `-w`/`-f`, `--raw`, `--token`, ...) |
| Secret values read via kubectl | `secrets` may only be probed with `get secret NAME -o name` (existence); `describe secret` and `-o yaml/json` on secrets are rejected | same file |
| Another module quietly grows a write path | A static test fails if `subprocess` is imported outside the collector or a mutating verb appears as an argument anywhere | `test_no_write_verbs_appear_anywhere_in_the_package` |
| MCP exposes more than intended | The tool list is asserted exactly; all tools are rules-only and read-only | `tests/test_mcp_server.py` |

### 4. Cost and size guardrails

| Threat | Control | Evidence |
| --- | --- | --- |
| Huge log inflates the request | Per-line cap, then truncation to `--max-log-bytes` keeping the head, windows around errors and the tail | `test_truncation_keeps_head_error_window_and_tail` |
| Spend per run | At most **one** model call; input-token budget and worst-case cost cap (`--max-cost-usd`) are checked **before** the call; the call is skipped with a notice | `test_oversized_prompt_skips_the_model_call...`, `test_worst_case_cost_cap_skips_the_call` |
| Retry storms | SDK retries are bounded (2); no loops | provider tests |

Cost figures are estimates from a price table or env override; unknown models report cost as unknown instead of guessing.

### 5. Human in the loop

Output is a comment, an issue, or terminal text. There is no auto-apply, auto-merge, auto-approve or auto-label path.
Suggested patches are rendered as `diff` blocks to apply by hand. Every report states that suggestions are not applied
automatically and that model answers can be wrong.

## Workflow and supply-chain controls

- The triage workflow uses `workflow_run` and runs from the default branch, so it can analyse logs from untrusted pull
  requests **without** executing that code or exposing a write token to it.
- Permissions are declared per job and minimal: `actions: read`, `contents: read`, `issues: write`,
  `pull-requests: write`. The action takes inputs through environment variables, not shell interpolation.
- Actions are pinned by commit SHA, Python dependencies by `uv.lock`, base images by digest. Dependabot proposes updates
  with a 14-day cooldown. Images are scanned with Trivy and signed with cosign (keyless).
- No secret is needed by CI. The API key is optional and only ever supplied by the operator.

## Residual risks

| Risk | Status |
| --- | --- |
| Redaction misses an unlabeled, low-entropy secret | Accepted; documented; use `--rules-only` for sensitive repos |
| Model gives a plausible but wrong diagnosis | Accepted; mitigated by showing rules and model separately, grounding, confidence, and "verify before acting" |
| Provider retains data | Outside this tool's control; choose a provider/plan whose retention terms fit your policy |
| Rules mis-classify a novel failure | Accepted; see the honest eval numbers in [evals](evals.md) |
