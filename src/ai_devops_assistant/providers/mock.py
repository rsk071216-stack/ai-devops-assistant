"""Deterministic mock provider: recorded responses for tests and the offline eval suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai_devops_assistant.guardrails import estimate_tokens
from ai_devops_assistant.providers.base import LLMRequest, LLMResponse, ProviderError


class MockProvider:
    """Returns a recorded response per ``case_id``; otherwise echoes the rules baseline.

    This never claims to measure model quality. It exercises the real pipeline
    (prompt building, schema validation, grounding checks, merging, rendering).
    """

    name = "mock"
    model = "mock-model"

    def __init__(
        self, recorded: dict[str, dict[str, Any]] | None = None, fixed: dict[str, Any] | None = None
    ) -> None:
        self._recorded = recorded or {}
        self._fixed = fixed
        self.calls: list[LLMRequest] = []

    @classmethod
    def from_file(cls, path: Path) -> MockProvider:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProviderError(f"cannot read mock responses: {path}") from exc
        return cls(recorded=data)

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        if self._fixed is not None:
            data = self._fixed
        elif request.case_id and request.case_id in self._recorded:
            data = self._recorded[request.case_id]
        else:
            data = self._echo_baseline(request)
        return LLMResponse(
            data=data,
            input_tokens=estimate_tokens(request.system + request.user),
            output_tokens=estimate_tokens(json.dumps(data)),
            model=self.model,
            provider=self.name,
        )

    @staticmethod
    def _echo_baseline(request: LLMRequest) -> dict[str, Any]:
        h = request.hints
        return {
            "category": h.get("category", "unknown"),
            "root_cause": h.get("root_cause", "Mock provider: no recorded response for this input."),
            "confidence": "low",
            "fix_steps": list(h.get("fix_steps", ["Review the evidence manually."]))[:8],
            "suggested_commands": [],
            "evidence_quotes": [h["first_evidence"]] if h.get("first_evidence") else [],
            "suggested_patch": None,
        }
