from __future__ import annotations

from typing import Any

from ai_devops_assistant.analysis import finalize, ground_quotes
from ai_devops_assistant.ci.triage import triage_log
from ai_devops_assistant.config import Settings
from ai_devops_assistant.guardrails import Budget, clean_log, estimate_tokens, truncate_log
from ai_devops_assistant.models import Category
from ai_devops_assistant.observability import JsonFormatter, configure_logging, log_event
from ai_devops_assistant.providers import ProviderError
from ai_devops_assistant.providers.base import LLMRequest, LLMResponse
from ai_devops_assistant.providers.mock import MockProvider

OK_REPLY: dict[str, Any] = {
    "category": "build_error", "root_cause": "Compile error in main.go.", "confidence": "medium",
    "fix_steps": ["Declare cfg."], "suggested_commands": [], "evidence_quotes": ["undefined: cfg"], "suggested_patch": None,
}  # fmt: skip


def big_log(n: int = 4000) -> str:
    head = ["START environment=ci runner=ubuntu-24.04"]
    body = [f"step {i}: compiling module {i} ok" for i in range(n)]
    body[n // 2] = "ERROR: boom in the middle: undefined: cfg"
    return "\n".join([*head, *body, "FINAL: process exited with code 3"])


def test_truncation_keeps_head_error_window_and_tail() -> None:
    text = big_log()
    result = truncate_log(text, 6000)
    assert result.truncated
    assert result.kept_bytes <= 6000 + 400
    assert "START environment=ci" in result.text
    assert "ERROR: boom in the middle" in result.text
    assert "FINAL: process exited with code 3" in result.text
    assert "lines omitted" in result.text
    assert result.omitted_lines > 3000


def test_truncation_is_a_noop_for_small_input() -> None:
    result = truncate_log("a\nb\nc", 1000)
    assert not result.truncated and result.text == "a\nb\nc" and result.omitted_lines == 0


def test_clean_log_strips_ansi_timestamps_and_caps_long_lines() -> None:
    raw = "2026-10-21T09:12:00.1234567Z \x1b[31mError:\x1b[0m bad\r\n" + "x" * 5000
    cleaned = clean_log(raw)
    assert cleaned.startswith("Error: bad")
    assert "\x1b" not in cleaned
    assert "line truncated" in cleaned.splitlines()[1]


def test_budget_blocks_large_or_expensive_calls() -> None:
    b = Budget(max_input_tokens=1000, max_output_tokens=100, max_cost_usd=0.01)
    assert b.allows(500, 0.001) == (True, "")
    assert not b.allows(5000, 0.001)[0]
    assert not b.allows(500, 0.5)[0]
    assert b.allows(500, None)[0]  # unknown price: token cap still applies
    assert estimate_tokens("a" * 400) == 100


def test_oversized_prompt_skips_the_model_call_and_keeps_rules_result() -> None:
    provider = MockProvider(fixed=OK_REPLY)
    settings = Settings(provider="mock", env={}, max_input_tokens=50)
    d = triage_log(
        "Error: environment variable FOO is not set\n" + "x\n" * 100, settings=settings, provider=provider
    )
    assert provider.calls == []
    assert d.mode == "rules-only" and d.usage.llm_calls == 0
    assert any("cost guardrail" in n for n in d.notices)
    assert d.category == Category.MISSING_ENV_VAR


def test_worst_case_cost_cap_skips_the_call() -> None:
    provider = MockProvider(fixed=OK_REPLY)
    settings = Settings(
        provider="mock",
        model="claude-opus-5-5",
        env={"AIDA_PRICE_INPUT_PER_MTOK": "1000", "AIDA_PRICE_OUTPUT_PER_MTOK": "1000"},
        max_cost_usd=0.001,
    )

    class Priced(MockProvider):
        model = "claude-opus-5-5"

    d = triage_log("some failure\nEnd", settings=settings, provider=Priced(fixed=OK_REPLY))
    assert d.usage.llm_calls == 0 and provider.calls == []
    assert any("cost" in n for n in d.notices)


def test_unknown_failure_uses_the_model_answer_and_counts_tokens() -> None:
    provider = MockProvider(fixed=OK_REPLY)
    d = triage_log(
        "cmd/main.go:42:13: undefined: cfg\n", settings=Settings(provider="mock", env={}), provider=provider
    )
    assert d.findings == []
    assert d.mode == "rules+llm" and d.category == Category.BUILD_ERROR
    assert d.usage.llm_calls == 1 and d.usage.input_tokens > 0 and d.usage.output_tokens > 0
    assert d.ai is not None and d.ai.grounded_quotes == ["undefined: cfg"]
    assert d.usage.estimated_cost_usd is None  # mock-model has no price: reported as unknown, never guessed


def test_cost_is_estimated_when_the_model_is_priced() -> None:
    class Priced(MockProvider):
        model = "claude-sonnet-5-5"

    d = triage_log(
        "cmd/main.go:42:13: undefined: cfg\n",
        settings=Settings(provider="mock", env={}),
        provider=Priced(fixed=OK_REPLY),
    )
    assert d.usage.estimated_cost_usd is not None and 0 < d.usage.estimated_cost_usd < 0.01


def test_llm_when_unknown_skips_the_model_when_rules_are_confident() -> None:
    provider = MockProvider(fixed=OK_REPLY)
    settings = Settings(provider="mock", env={}, llm_when="unknown")
    d = triage_log("Error: environment variable FOO is not set\n", settings=settings, provider=provider)
    assert provider.calls == [] and any("skipped" in n for n in d.notices)


def test_provider_failure_falls_back_to_rules() -> None:
    class Broken:
        name, model = "broken", "m"

        def complete(self, request: LLMRequest) -> LLMResponse:
            raise ProviderError("HTTP 500")

    d = triage_log(
        "Error: environment variable FOO is not set\n",
        settings=Settings(provider="mock", env={}),
        provider=Broken(),
    )
    assert d.mode == "rules-only" and d.category == Category.MISSING_ENV_VAR
    assert any("Model call failed" in n for n in d.notices)


def test_disagreeing_model_is_flagged_but_rules_category_wins() -> None:
    reply = {**OK_REPLY, "category": "network_error", "evidence_quotes": []}
    d = triage_log(
        "Error: environment variable FOO is not set\n",
        settings=Settings(provider="mock", env={}),
        provider=MockProvider(fixed=reply),
    )
    assert d.category == Category.MISSING_ENV_VAR
    assert any("differs from the rules engine" in n for n in d.notices)


def test_ground_quotes_normalises_whitespace_and_rejects_short_quotes() -> None:
    kept, dropped = ground_quotes(["Error:   boom\nnow", "ok", "never seen"], "x Error: boom now y")
    assert kept == ["Error:   boom\nnow"] and dropped == 2


def test_finalize_without_findings_or_provider() -> None:
    d = finalize(
        kind="ci", target="t", findings=[], evidence_text="", settings=Settings(env={}), provider=None,
        provider_notices=["n"], redactions={}, truncated=False, input_bytes=0,
    )  # fmt: skip
    assert d.category == Category.UNKNOWN and d.mode == "rules-only" and d.summary


def test_json_logging_contains_metadata_only(capsys: Any) -> None:
    configure_logging("INFO")
    log_event("llm_call", provider="mock", input_tokens=5)
    err = capsys.readouterr().err
    assert '"event": "llm_call"' in err and '"input_tokens": 5' in err
    import logging

    record = logging.LogRecord("aida", logging.INFO, "f", 1, "hello", (), None)
    assert '"event": "hello"' in JsonFormatter().format(record)
    configure_logging("WARNING", json_logs=False)
