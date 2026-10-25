"""Anthropic backend using the official SDK and structured outputs (JSON schema)."""

from __future__ import annotations

from typing import Any

import anthropic

from ai_devops_assistant.providers.base import LLMRequest, LLMResponse, ProviderError, parse_json_object


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self, model: str, api_key: str | None = None, timeout_s: float = 60.0, client: Any = None
    ) -> None:
        self.model = model
        # Keys come from the environment (ANTHROPIC_API_KEY) unless injected; they are never logged.
        self._client: Any = client or anthropic.Anthropic(api_key=api_key, timeout=timeout_s, max_retries=2)

    def complete(self, request: LLMRequest) -> LLMResponse:
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=request.max_output_tokens,
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
                # Structured output: the API constrains the reply to this JSON schema.
                output_config={"format": {"type": "json_schema", "schema": request.schema}},
            )
        except anthropic.APIError as exc:
            raise ProviderError(f"anthropic request failed: {type(exc).__name__}") from exc

        if getattr(response, "stop_reason", None) == "refusal":
            raise ProviderError("model refused the request")
        text = "".join(b.text for b in response.content if getattr(b, "type", "") == "text")
        data = parse_json_object(text)
        usage = response.usage
        return LLMResponse(
            data=data,
            input_tokens=int(usage.input_tokens),
            output_tokens=int(usage.output_tokens),
            model=self.model,
            provider=self.name,
        )
