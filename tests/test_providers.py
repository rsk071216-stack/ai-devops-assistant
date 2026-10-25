from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from ai_devops_assistant.config import Settings
from ai_devops_assistant.prompts import SYSTEM_PROMPT, request_schema
from ai_devops_assistant.providers import LLMRequest, ProviderError, build_provider
from ai_devops_assistant.providers.anthropic_provider import AnthropicProvider
from ai_devops_assistant.providers.base import parse_json_object
from ai_devops_assistant.providers.mock import MockProvider
from ai_devops_assistant.providers.openai_compatible import OpenAICompatibleProvider

REQ = LLMRequest(system=SYSTEM_PROMPT, user="data", schema=request_schema(), max_output_tokens=500)
REPLY: dict[str, Any] = {
    "category": "unknown", "root_cause": "x", "confidence": "low", "fix_steps": [],
    "suggested_commands": [], "evidence_quotes": [], "suggested_patch": None,
}  # fmt: skip


class FakeAnthropicClient:
    def __init__(
        self, text: str = json.dumps(REPLY), stop_reason: str = "end_turn", error: Exception | None = None
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._text, self._stop, self._error = text, stop_reason, error
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self._error:
            raise self._error
        return SimpleNamespace(
            stop_reason=self._stop,
            content=[SimpleNamespace(type="text", text=self._text)],
            usage=SimpleNamespace(input_tokens=1200, output_tokens=180),
        )


def test_anthropic_provider_uses_structured_output_and_reports_usage() -> None:
    client = FakeAnthropicClient()
    resp = AnthropicProvider("claude-sonnet-5-5", client=client).complete(REQ)
    call = client.calls[0]
    assert call["model"] == "claude-sonnet-5-5"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert call["output_config"]["format"]["schema"]["additionalProperties"] is False
    assert "tools" not in call and "tool_choice" not in call  # forced tool use is rejected by newer models
    assert "temperature" not in call
    assert (resp.input_tokens, resp.output_tokens) == (1200, 180)
    assert resp.data["category"] == "unknown"


def test_anthropic_refusal_and_bad_json_become_provider_errors() -> None:
    with pytest.raises(ProviderError, match="refused"):
        AnthropicProvider("m", client=FakeAnthropicClient(stop_reason="refusal")).complete(REQ)
    with pytest.raises(ProviderError, match="not valid JSON"):
        AnthropicProvider("m", client=FakeAnthropicClient(text="nope")).complete(REQ)


def test_anthropic_api_errors_are_wrapped() -> None:
    import anthropic

    err = anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))  # type: ignore[arg-type]
    with pytest.raises(ProviderError, match="APIConnectionError"):
        AnthropicProvider("m", client=FakeAnthropicClient(error=err)).complete(REQ)


def _oa(handler: Any, **kwargs: Any) -> OpenAICompatibleProvider:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return OpenAICompatibleProvider("local-model", base_url="http://llm.local/v1", client=client, **kwargs)


def _chat(content: str) -> dict[str, Any]:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 900, "completion_tokens": 120},
    }


def test_openai_compatible_success_and_request_shape() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["body"], seen["auth"] = (
            str(request.url),
            json.loads(request.content),
            request.headers.get("authorization"),
        )
        return httpx.Response(200, json=_chat("```json\n" + json.dumps(REPLY) + "\n```"))

    resp = _oa(handler, api_key="local-key").complete(REQ)
    assert seen["url"] == "http://llm.local/v1/chat/completions"
    assert seen["body"]["response_format"]["type"] == "json_schema"
    assert seen["body"]["temperature"] == 0
    assert seen["auth"] == "Bearer local-key"
    assert resp.input_tokens == 900 and resp.data["root_cause"] == "x"


def test_openai_compatible_json_mode_variants_and_no_key() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        assert "authorization" not in request.headers
        return httpx.Response(200, json=_chat(json.dumps(REPLY)))

    _oa(handler, json_mode="json_object").complete(REQ)
    _oa(handler, json_mode="none").complete(REQ)
    assert bodies[0]["response_format"] == {"type": "json_object"}
    assert "response_format" not in bodies[1]


def test_openai_compatible_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda _s: None)
    statuses = iter([429, 503, 200])

    def handler(request: httpx.Request) -> httpx.Response:
        status = next(statuses)
        return httpx.Response(status, json=_chat(json.dumps(REPLY)) if status == 200 else {})

    assert _oa(handler).complete(REQ).data["category"] == "unknown"


def test_openai_compatible_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda _s: None)
    with pytest.raises(ProviderError, match="HTTP 500"):
        _oa(lambda r: httpx.Response(500)).complete(REQ)
    with pytest.raises(ProviderError, match="HTTP 401"):
        _oa(lambda r: httpx.Response(401)).complete(REQ)
    with pytest.raises(ProviderError, match="unexpected response shape"):
        _oa(lambda r: httpx.Response(200, json={"nope": 1})).complete(REQ)
    with pytest.raises(ProviderError, match="non-text"):
        _oa(lambda r: httpx.Response(200, json={"choices": [{"message": {"content": None}}]})).complete(REQ)

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with pytest.raises(ProviderError, match="ConnectError"):
        _oa(boom).complete(REQ)


def test_parse_json_object_edge_cases() -> None:
    assert parse_json_object('{"a": 1}') == {"a": 1}
    assert parse_json_object('```\n{"a": 1}\n```') == {"a": 1}
    with pytest.raises(ProviderError):
        parse_json_object("[1, 2]")


def test_mock_provider_recorded_fixed_and_echo() -> None:
    rec = MockProvider(recorded={"case-1": {**REPLY, "root_cause": "recorded"}})
    assert rec.complete(LLMRequest("s", "u", {}, 10, case_id="case-1")).data["root_cause"] == "recorded"
    echo = rec.complete(
        LLMRequest(
            "s",
            "u",
            {},
            10,
            case_id="other",
            hints={"category": "crash_loop", "root_cause": "r", "first_evidence": "ev"},
        )
    )
    assert echo.data["category"] == "crash_loop" and echo.data["evidence_quotes"] == ["ev"]
    assert MockProvider(fixed=REPLY).complete(REQ).data == REPLY
    assert len(rec.calls) == 2


def test_mock_provider_from_file(tmp_path: Any) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"c": REPLY}), encoding="utf-8")
    assert MockProvider.from_file(path).complete(LLMRequest("s", "u", {}, 10, case_id="c")).data == REPLY
    with pytest.raises(ProviderError):
        MockProvider.from_file(tmp_path / "missing.json")


def test_request_schema_is_strict() -> None:
    schema = request_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


class TestProviderSelection:
    def test_no_key_means_rules_only_with_a_clear_notice(self) -> None:
        provider, notices = build_provider(Settings(env={}))
        assert provider is None
        assert "rules-only" in notices[0] and "ANTHROPIC_API_KEY" in notices[0]

    def test_explicit_rules_only_wins_over_a_key(self) -> None:
        provider, notices = build_provider(Settings(rules_only=True, env={"ANTHROPIC_API_KEY": "k"}))
        assert provider is None and "Rules-only mode was requested" in notices[0]

    def test_anthropic_selected_by_key_with_default_model(self) -> None:
        provider, _ = build_provider(Settings(env={"ANTHROPIC_API_KEY": "test-key-not-real"}))
        assert provider is not None and provider.name == "anthropic" and provider.model == "claude-sonnet-5-5"

    def test_model_override_by_env_and_flag(self) -> None:
        env = {"ANTHROPIC_API_KEY": "k", "AIDA_MODEL": "claude-haiku-5-5"}
        assert build_provider(Settings(env=env))[0].model == "claude-haiku-5-5"  # type: ignore[union-attr]
        assert build_provider(Settings(model="claude-opus-5-5", env=env))[0].model == "claude-opus-5-5"  # type: ignore[union-attr]

    def test_openai_compatible_by_base_url(self) -> None:
        provider, _ = build_provider(
            Settings(env={"AIDA_OPENAI_BASE_URL": "http://localhost:11434/v1", "AIDA_OPENAI_MODEL": "llama"})
        )
        assert provider is not None and provider.name == "openai_compatible" and provider.model == "llama"

    def test_explicit_provider_without_credentials_falls_back(self) -> None:
        assert build_provider(Settings(provider="anthropic", env={}))[0] is None
        assert build_provider(Settings(provider="openai_compatible", env={}))[0] is None

    def test_mock_and_unknown(self) -> None:
        provider, notices = build_provider(Settings(provider="mock", env={}))
        assert provider is not None and provider.name == "mock" and "not model output" in notices[0]
        assert build_provider(Settings(provider="bogus", env={}))[0] is None

    def test_mock_with_recordings_file(self, tmp_path: Any) -> None:
        path = tmp_path / "r.json"
        path.write_text("{}", encoding="utf-8")
        provider, _ = build_provider(Settings(provider="mock", env={"AIDA_MOCK_RESPONSES": str(path)}))
        assert provider is not None

    def test_price_overrides(self) -> None:
        assert Settings(env={}).price_per_mtok("claude-sonnet-5-5") == (2.0, 10.0)
        assert Settings(env={}).price_per_mtok("some-local-model") is None
        env = {"AIDA_PRICE_INPUT_PER_MTOK": "1.5", "AIDA_PRICE_OUTPUT_PER_MTOK": "3"}
        assert Settings(env=env).price_per_mtok("anything") == (1.5, 3.0)
        assert (
            Settings(
                env={"AIDA_PRICE_INPUT_PER_MTOK": "x", "AIDA_PRICE_OUTPUT_PER_MTOK": "1"}
            ).price_per_mtok("m")
            is None
        )
