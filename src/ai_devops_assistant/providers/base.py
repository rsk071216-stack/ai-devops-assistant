"""Provider interface. A provider turns one prompt into one JSON object plus token counts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol


class ProviderError(RuntimeError):
    """Any failure talking to a model backend. Callers fall back to the rules-only result."""


@dataclass(frozen=True)
class LLMRequest:
    system: str
    user: str
    schema: dict[str, Any]
    max_output_tokens: int
    # Only used by the mock provider (recorded responses are keyed by eval case id).
    case_id: str | None = None
    # Deterministic hints for the mock provider; never part of a real prompt.
    hints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LLMResponse:
    data: dict[str, Any]
    input_tokens: int
    output_tokens: int
    model: str
    provider: str


class Provider(Protocol):
    name: str
    model: str

    def complete(self, request: LLMRequest) -> LLMResponse: ...


_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.S)


def parse_json_object(text: str) -> dict[str, Any]:
    """Parse a model reply that should be a single JSON object (tolerates a code fence)."""
    candidate = text.strip()
    if m := _FENCE_RE.match(candidate):
        candidate = m.group(1)
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ProviderError("model reply was not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProviderError("model reply was JSON but not an object")
    return value
