"""Generic chat-completions backend over httpx (OpenAI-style APIs, vLLM, Ollama, LM Studio, gateways)."""

from __future__ import annotations

import time
from typing import Any

import httpx

from ai_devops_assistant.providers.base import LLMRequest, LLMResponse, ProviderError, parse_json_object

_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504}


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str | None = None,
        timeout_s: float = 60.0,
        json_mode: str = "json_schema",
        client: httpx.Client | None = None,
        max_retries: int = 2,
    ) -> None:
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._json_mode = json_mode  # "json_schema" | "json_object" | "none"
        self._max_retries = max_retries
        self._client = client or httpx.Client(timeout=timeout_s)

    def _response_format(self, schema: dict[str, Any]) -> dict[str, Any] | None:
        if self._json_mode == "json_schema":
            return {
                "type": "json_schema",
                "json_schema": {"name": "diagnosis", "schema": schema, "strict": True},
            }
        if self._json_mode == "json_object":
            return {"type": "json_object"}
        return None

    def _post_with_retries(self, body: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            last = attempt == self._max_retries
            try:
                resp = self._client.post(self._url, json=body, headers=headers)
            except httpx.HTTPError as exc:
                if last:
                    raise ProviderError(f"request failed: {type(exc).__name__}") from exc
                time.sleep(0.5 * 2**attempt)
                continue
            if resp.status_code in _RETRY_STATUS and not last:
                time.sleep(0.5 * 2**attempt)
                continue
            return resp
        raise ProviderError("request failed")  # pragma: no cover

    def complete(self, request: LLMRequest) -> LLMResponse:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": request.max_output_tokens,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
        }
        if fmt := self._response_format(request.schema):
            body["response_format"] = fmt
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        resp = self._post_with_retries(body, headers)
        if resp.status_code >= 400:
            raise ProviderError(f"endpoint returned HTTP {resp.status_code}")
        try:
            payload = resp.json()
            content = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("unexpected response shape from endpoint") from exc
        if not isinstance(content, str):
            raise ProviderError("endpoint returned non-text content")
        return LLMResponse(
            data=parse_json_object(content),
            input_tokens=int(usage.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage.get("completion_tokens", 0) or 0),
            model=self.model,
            provider=self.name,
        )
