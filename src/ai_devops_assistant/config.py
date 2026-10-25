"""Configuration resolved from CLI flags and environment variables (flags win)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"
DEFAULT_MAX_LOG_BYTES = 24_000

# USD per million tokens (input, output). Estimates only; override with AIDA_PRICE_INPUT_PER_MTOK /
# AIDA_PRICE_OUTPUT_PER_MTOK. Unknown models report cost as unknown instead of guessing.
PRICE_TABLE: dict[str, tuple[float, float]] = {
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-opus-5-5": (4.0, 20.0),
    "claude-haiku-5-5": (0.10, 0.50),
}

PROVIDER_CHOICES = ("auto", "anthropic", "openai_compatible", "mock", "none")


@dataclass(frozen=True)
class Settings:
    provider: str = "auto"
    model: str | None = None
    max_log_bytes: int = DEFAULT_MAX_LOG_BYTES
    max_input_tokens: int = 12_000
    max_output_tokens: int = 1_500
    max_cost_usd: float = 0.10
    rules_only: bool = False
    llm_when: str = "always"  # "always" | "unknown" (only call the model when rules found nothing)
    request_timeout_s: float = 60.0
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))

    def resolved_provider(self) -> str:
        """Pick the provider; ``none`` means rules-only."""
        if self.rules_only:
            return "none"
        if self.provider != "auto":
            return self.provider
        if self.env.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        if self.env.get("AIDA_OPENAI_BASE_URL"):
            return "openai_compatible"
        return "none"

    def resolved_model(self, provider: str) -> str:
        if self.model:
            return self.model
        if env_model := self.env.get("AIDA_MODEL"):
            return env_model
        if provider == "anthropic":
            return DEFAULT_ANTHROPIC_MODEL
        if provider == "openai_compatible":
            return self.env.get("AIDA_OPENAI_MODEL", "local-model")
        return "mock-model"

    def price_per_mtok(self, model: str) -> tuple[float, float] | None:
        try:
            if "AIDA_PRICE_INPUT_PER_MTOK" in self.env and "AIDA_PRICE_OUTPUT_PER_MTOK" in self.env:
                return (
                    float(self.env["AIDA_PRICE_INPUT_PER_MTOK"]),
                    float(self.env["AIDA_PRICE_OUTPUT_PER_MTOK"]),
                )
        except ValueError:
            return None
        return PRICE_TABLE.get(model)
