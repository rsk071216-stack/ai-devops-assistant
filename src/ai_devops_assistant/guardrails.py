"""Size and cost guardrails: log cleaning, head/error-window/tail truncation, budgets."""

from __future__ import annotations

import re
from dataclasses import dataclass

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
TIMESTAMP_RE = re.compile(r"^﻿?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ")
ERROR_RE = re.compile(
    r"(?i)(\berror\b|\bfail(?:ed|ure|s)?\b|exception|\bfatal\b|panic|traceback|denied|forbidden|"
    r"unauthorized|exit code|oomkilled|crashloop|\bkilled\b|timed? ?out|not found|##\[error\]|"
    r"cannot|unable to|refused|invalid|\bE\d{3,}\b)"
)
STRONG_ERROR_RE = re.compile(
    r"(?i)(##\[error\]|\bfatal\b|traceback|panic:|^error[: ]|\berror:|exit code [1-9])"
)

# Rough heuristic: ~4 characters per token for English/log text. Labelled as an estimate everywhere.
CHARS_PER_TOKEN = 4
MAX_LINE_CHARS = 1500


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // CHARS_PER_TOKEN)


def clean_log(text: str) -> str:
    """Strip ANSI escapes, runner timestamps and carriage returns; cap pathological line lengths."""
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = TIMESTAMP_RE.sub("", ANSI_RE.sub("", raw)).rstrip()
        if len(line) > MAX_LINE_CHARS:
            line = line[:MAX_LINE_CHARS] + f" ... [line truncated, {len(raw) - MAX_LINE_CHARS} chars]"
        lines.append(line)
    return "\n".join(lines)


@dataclass(frozen=True)
class TruncationResult:
    text: str
    truncated: bool
    original_bytes: int
    kept_bytes: int
    omitted_lines: int


def truncate_log(
    text: str, max_bytes: int, *, head_share: float = 0.10, tail_share: float = 0.30
) -> TruncationResult:
    """Keep the head, the lines around errors, and the tail within ``max_bytes``.

    Rationale: the head holds the environment and the command being run, the tail
    holds the final failure and exit code, and the real cause is usually in a window
    around an error line in between. Dropped regions are replaced by a marker so the
    model (and the reader) knows text was omitted.
    """
    original = len(text.encode("utf-8", "replace"))
    if original <= max_bytes:
        return TruncationResult(text, False, original, original, 0)

    lines = text.split("\n")
    sizes = [len(ln.encode("utf-8", "replace")) + 1 for ln in lines]
    keep = [False] * len(lines)

    def take(idx: int, budget: list[int]) -> bool:
        if keep[idx]:
            return True
        if sizes[idx] > budget[0]:
            return False
        keep[idx] = True
        budget[0] -= sizes[idx]
        return True

    # Reserve room for the omission markers.
    marker_reserve = 200
    head_budget = [int(max_bytes * head_share)]
    tail_budget = [int(max_bytes * tail_share)]
    window_budget = [max(0, max_bytes - head_budget[0] - tail_budget[0] - marker_reserve)]

    for i in range(len(lines)):
        if not take(i, head_budget):
            break
    for i in range(len(lines) - 1, -1, -1):
        if not take(i, tail_budget):
            break

    # Error windows: strong errors first, latest first (the final failure is usually the cause chain end),
    # then weak error lines. Each hit keeps 6 lines before and 4 after.
    strong = [i for i, ln in enumerate(lines) if STRONG_ERROR_RE.search(ln)]
    weak = [i for i, ln in enumerate(lines) if ERROR_RE.search(ln) and i not in set(strong)]
    for idx in [*reversed(strong), *reversed(weak)]:
        if window_budget[0] <= 0:
            break
        for j in range(max(0, idx - 6), min(len(lines), idx + 5)):
            take(j, window_budget)

    out: list[str] = []
    omitted_total = 0
    gap = 0
    for i, ln in enumerate(lines):
        if keep[i]:
            if gap:
                out.append(f"... [{gap} lines omitted] ...")
                omitted_total += gap
                gap = 0
            out.append(ln)
        else:
            gap += 1
    if gap:
        out.append(f"... [{gap} lines omitted] ...")
        omitted_total += gap
    result = "\n".join(out)
    return TruncationResult(result, True, original, len(result.encode("utf-8", "replace")), omitted_total)


@dataclass(frozen=True)
class Budget:
    """Per-run spend limits. The assistant makes at most ONE model call per run."""

    max_input_tokens: int = 12_000
    max_output_tokens: int = 1_500
    max_cost_usd: float = 0.10

    def allows(self, input_tokens: int, cost_usd: float | None) -> tuple[bool, str]:
        if input_tokens > self.max_input_tokens:
            return (
                False,
                f"estimated input {input_tokens} tokens exceeds the {self.max_input_tokens} token budget",
            )
        if cost_usd is not None and cost_usd > self.max_cost_usd:
            return (
                False,
                f"estimated worst-case cost ${cost_usd:.4f} exceeds the ${self.max_cost_usd:.2f} budget",
            )
        return True, ""
