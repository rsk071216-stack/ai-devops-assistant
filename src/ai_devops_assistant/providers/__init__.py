"""Model backends behind one small interface."""

from __future__ import annotations

from pathlib import Path

from ai_devops_assistant.config import Settings
from ai_devops_assistant.providers.base import LLMRequest, LLMResponse, Provider, ProviderError

__all__ = ["LLMRequest", "LLMResponse", "Provider", "ProviderError", "build_provider"]


def build_provider(settings: Settings) -> tuple[Provider | None, list[str]]:
    """Return ``(provider, notices)``. ``provider`` is None for rules-only mode."""
    name = settings.resolved_provider()
    env = settings.env
    notices: list[str] = []
    if name == "none":
        if settings.rules_only:
            notices.append("Rules-only mode was requested; no model was called.")
        else:
            notices.append(
                "No LLM provider configured (set ANTHROPIC_API_KEY or AIDA_OPENAI_BASE_URL): "
                "running in rules-only mode. The deterministic diagnosis above needs no API key."
            )
        return None, notices

    model = settings.resolved_model(name)
    if name == "anthropic":
        if not env.get("ANTHROPIC_API_KEY"):
            return None, ["Provider 'anthropic' selected but ANTHROPIC_API_KEY is not set: rules-only mode."]
        from ai_devops_assistant.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(
            model, api_key=env["ANTHROPIC_API_KEY"], timeout_s=settings.request_timeout_s
        ), notices
    if name == "openai_compatible":
        base = env.get("AIDA_OPENAI_BASE_URL")
        if not base:
            return None, [
                "Provider 'openai_compatible' selected but AIDA_OPENAI_BASE_URL is not set: rules-only mode."
            ]
        from ai_devops_assistant.providers.openai_compatible import OpenAICompatibleProvider

        return (
            OpenAICompatibleProvider(
                model,
                base_url=base,
                api_key=env.get("AIDA_OPENAI_API_KEY"),
                timeout_s=settings.request_timeout_s,
                json_mode=env.get("AIDA_OPENAI_JSON_MODE", "json_schema"),
            ),
            notices,
        )
    if name == "mock":
        from ai_devops_assistant.providers.mock import MockProvider

        path = env.get("AIDA_MOCK_RESPONSES")
        if path and Path(path).is_file():
            return MockProvider.from_file(Path(path)), notices
        return MockProvider(), [*notices, "Mock provider: responses are deterministic and not model output."]
    return None, [f"Unknown provider '{name}': rules-only mode."]
