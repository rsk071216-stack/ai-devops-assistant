# 0002. Provider interface and schema-constrained output

Status: Accepted

## Context

Teams use different model vendors, some require local or self-hosted models, and tests must not call the network.
Free-form model text is hard to validate and easy to manipulate through the input.

## Decision

- One small `Provider` protocol: `complete(LLMRequest) -> LLMResponse` returning a parsed JSON object plus token
  counts. Three implementations: `anthropic` (official SDK), `openai_compatible` (httpx, chat-completions shape,
  works with vLLM, Ollama, gateways), and `mock` (recorded responses).
- The default Anthropic model id is `claude-sonnet-5-5`, overridable with `--model` / `AIDA_MODEL`. The SDK is pinned in
  `uv.lock`; the version was chosen from PyPI release metadata (at least two weeks old) rather than "latest".
- Output is constrained by a JSON schema using the API's structured-output feature (`output_config.format`). Forced
  `tool_choice` is deliberately not used because current models reject it. The reply is **re-validated locally**
  with pydantic (`extra="forbid"`, enum category, bounded lengths), because a provider-side guarantee is not a
  substitute for validating untrusted output in your own process.
- Provider is chosen by configuration; no key means rules-only mode with an explicit notice.

## Consequences

- Swapping vendors is a config change; adding one is one small class.
- Tests exercise the real pipeline (prompting, validation, grounding, rendering) through the mock provider.
- Provider quirks are contained: the OpenAI-compatible backend lets the operator choose `json_schema`,
  `json_object` or `none` depending on server support.
- Cost is computed from a small price table that can be overridden; unknown models report "unknown" instead of a guess.
