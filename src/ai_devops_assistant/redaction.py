"""Secret redaction. Runs before ANY text leaves the machine (LLM call, PR comment, issue).

Design: ordered, named rules. Specific token formats first, then contextual
``name=value`` rules, then a high-entropy catch-all. Output is stable and
idempotent (``redact(redact(x)) == redact(x)``). Only counts per rule are
reported, never the secret values themselves.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

PLACEHOLDER = "[REDACTED:{name}]"
_ALREADY = "[REDACTED"


@dataclass(frozen=True)
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


@dataclass(frozen=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    # Group whose content is replaced; 0 replaces the whole match.
    group: int = 0
    guard: Callable[[str], bool] | None = None


def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_NOT_SECRET_WORDS = frozenset(
    {
        "true", "false", "null", "none", "undefined", "changeme", "expired", "invalid", "missing",
        "required", "empty", "denied", "revoked", "unauthorized", "forbidden", "unknown", "success",
        "successfully", "provided", "specified", "supplied", "configured", "present", "failed",
        "available", "unbound", "unset", "blank", "absent", "optional", "disabled", "enabled", "default", "mismatch", "rejected", "malformed", "refreshed", "obtained", "retrieved",
    }
)  # fmt: skip


def _not_placeholder_or_ref(value: str) -> bool:
    """Skip values that are already masked or are variable references, not literals."""
    v = value.strip("\"'")
    if v.startswith((_ALREADY, "$", "{{", "<", "***", "%(", "${")):
        return False
    return not (v.lower() in _NOT_SECRET_WORDS or set(v) <= {"*", "x", "X"})


_SECRET_NAME = (
    r"[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|credential|authorization)[A-Za-z0-9_.\-]*"
)

_RULES: tuple[_Rule, ...] = (
    # Private keys: whole PEM block, or an unterminated BEGIN line followed by base64 body.
    _Rule(
        "private_key",
        _rx(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
            re.S,
        ),
    ),
    _Rule(
        "private_key", _rx(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,6000}?(?=\n\s*\n|\Z)")
    ),
    # Cloud vendor tokens
    _Rule("aws_access_key_id", _rx(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b")),
    _Rule(
        "aws_secret_access_key",
        _rx(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"),
        group=1,
    ),
    _Rule(
        "aws_session_token",
        _rx(r"(?i)aws[_\-]?session[_\-]?token[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40,})"),
        group=1,
    ),
    _Rule("azure_storage_key", _rx(r"(?i)AccountKey=([A-Za-z0-9+/=]{20,})"), group=1),
    _Rule("azure_shared_access_key", _rx(r"(?i)SharedAccessKey=([A-Za-z0-9+/=]{20,})"), group=1),
    _Rule("azure_sas_signature", _rx(r"(?i)[?&;]sig=([A-Za-z0-9%+/=]{20,})"), group=1),
    _Rule("azure_client_secret", _rx(r"\b[A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{30,40}\b")),
    _Rule("google_api_key", _rx(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # Source control and registry tokens
    _Rule("github_token", _rx(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b")),
    _Rule("github_token", _rx(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    _Rule("gitlab_token", _rx(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    _Rule("npm_token", _rx(r"\bnpm_[A-Za-z0-9]{36}\b")),
    _Rule("pypi_token", _rx(r"\bpypi-[A-Za-z0-9_\-]{50,}\b")),
    _Rule("docker_pat", _rx(r"\bdckr_pat_[A-Za-z0-9_\-]{20,}\b")),
    _Rule("terraform_cloud_token", _rx(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b")),
    # LLM and SaaS keys
    _Rule("anthropic_api_key", _rx(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    _Rule("openai_api_key", _rx(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    _Rule("slack_token", _rx(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    _Rule("stripe_key", _rx(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    _Rule("sendgrid_key", _rx(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    # Generic structured credentials
    _Rule("jwt", _rx(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    _Rule("bearer_token", _rx(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/\-]{16,}=*)"), group=1),
    _Rule("url_credentials", _rx(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@\"']+:([^\s@/\"']+)@"), group=1),
    _Rule(
        "connection_string_secret",
        _rx(r"(?i)\b(?:password|pwd)\s*=\s*([^;\s\"']+)"),
        group=1,
        guard=_not_placeholder_or_ref,
    ),
    # Contextual NAME=value / NAME: value assignments
    _Rule(
        "named_secret",
        _rx(rf"(?i)\b{_SECRET_NAME}[\"']?\s*[:=]\s*[\"']?([^\s\"',;&]{{6,}})"),
        group=1,
        guard=_not_placeholder_or_ref,
    ),
)

# Secret/stringData blocks in `kubectl get secret -o yaml` style output.
_K8S_SECRET_DOC = re.compile(r"(?m)^kind:\s*Secret\s*$")
_K8S_DATA_BLOCK = re.compile(r"(?m)^(data|stringData):\s*$")
_K8S_DATA_LINE = re.compile(r"^(\s+)([A-Za-z0-9_.\-]+):\s*(\S.*)$")

_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+_=\-]{32,}")
_ENTROPY_THRESHOLD = 4.2


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


def _looks_random(token: str) -> bool:
    if token.startswith(_ALREADY):
        return False
    classes = sum(
        (
            any(c.islower() for c in token),
            any(c.isupper() for c in token),
            any(c.isdigit() for c in token),
        )
    )
    return classes >= 3 and shannon_entropy(token) >= _ENTROPY_THRESHOLD


def _apply_rule(text: str, rule: _Rule, counts: Counter[str]) -> str:
    placeholder = PLACEHOLDER.format(name=rule.name)

    def repl(match: re.Match[str]) -> str:
        secret = match.group(rule.group)
        if secret is None or secret.startswith(_ALREADY):
            return match.group(0)
        if rule.guard is not None and not rule.guard(secret):
            return match.group(0)
        counts[rule.name] += 1
        if rule.group == 0:
            return placeholder
        start, end = match.span(rule.group)
        offset = match.start()
        whole = match.group(0)
        return whole[: start - offset] + placeholder + whole[end - offset :]

    return rule.pattern.sub(repl, text)


def _redact_k8s_secret_data(text: str, counts: Counter[str]) -> str:
    if not _K8S_SECRET_DOC.search(text):
        return text
    out: list[str] = []
    in_block = False
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        if _K8S_DATA_BLOCK.match(stripped):
            in_block = True
            out.append(line)
            continue
        if in_block:
            m = _K8S_DATA_LINE.match(stripped)
            if m and not m.group(3).startswith(_ALREADY):
                counts["k8s_secret_value"] += 1
                out.append(f"{m.group(1)}{m.group(2)}: {PLACEHOLDER.format(name='k8s_secret_value')}\n")
                continue
            if not m:
                in_block = False
        out.append(line)
    return "".join(out)


def _redact_entropy(text: str, counts: Counter[str]) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        if _looks_random(token):
            counts["high_entropy_string"] += 1
            return PLACEHOLDER.format(name="high_entropy_string")
        return token

    return _ENTROPY_CANDIDATE.sub(repl, text)


def redact(text: str, *, entropy: bool = True) -> RedactionResult:
    """Return ``text`` with secrets replaced by ``[REDACTED:<rule>]`` placeholders."""
    counts: Counter[str] = Counter()
    out = _redact_k8s_secret_data(text, counts)
    for rule in _RULES:
        out = _apply_rule(out, rule, counts)
    if entropy:
        out = _redact_entropy(out, counts)
    return RedactionResult(text=out, counts=dict(sorted(counts.items())))


def rule_names() -> list[str]:
    """Names of all redaction rules (used in docs and tests)."""
    names = {r.name for r in _RULES} | {"k8s_secret_value", "high_entropy_string"}
    return sorted(names)
