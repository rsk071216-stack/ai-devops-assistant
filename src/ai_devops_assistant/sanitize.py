"""Output hardening: model and log text is untrusted when it is rendered into PR comments/issues.

Nothing here executes anything. It only neutralises markdown/HTML tricks (mentions, images,
links, raw HTML) and flags risky-looking suggested commands so a human reads them with care.
"""

from __future__ import annotations

import re

_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]*)\)")
_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)[^)]*\)")
_MENTION_RE = re.compile(r"(?<![\w`/])@([A-Za-z0-9][A-Za-z0-9_\-/]*)")
_HTML_TAG_RE = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9]*)([^>]*)>")
_BARE_URL_RE = re.compile(r"(?<![`(])\bhttps?://\S+")

_RISKY_COMMAND_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\brm\s+-[a-zA-Z]*[rf]"), "recursive/forced delete"),
    (
        re.compile(r"\bkubectl\s+(delete|drain|cordon|replace|patch|apply|scale|exec|edit|rollout\s+undo)\b"),
        "changes the cluster",
    ),
    (
        re.compile(r"\bterraform\s+(apply|destroy|taint|import|state\s+(rm|mv))\b"),
        "changes infrastructure or state",
    ),
    (re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b"), "pipes a download into a shell"),
    (re.compile(r"\bgit\s+push\b.*--force|\bgit\s+reset\s+--hard"), "rewrites git history"),
    (re.compile(r"\bchmod\s+(-R\s+)?7[0-9]{2}\b|\bchown\s+-R\b"), "broad permission change"),
    (
        re.compile(r"\b(aws|az|gcloud)\b.*\b(delete|destroy|remove|terminate|purge)\b"),
        "deletes cloud resources",
    ),
    (re.compile(r"\bdocker\s+(system\s+prune|rm\s+-f)\b"), "deletes containers/images"),
    (re.compile(r"[;&|]\s*(sudo\s+)?(sh|bash)\s+-c\b|\$\(|`"), "command substitution or chained shell"),
    (re.compile(r"\bsudo\b"), "needs elevated privileges"),
)


def neutralize_markdown(text: str) -> str:
    """Make untrusted prose safe to embed in a GitHub comment.

    - images are replaced by their alt text (blocks zero-click exfiltration via image URLs)
    - links keep their text but the URL is shown as inline code (not clickable)
    - @mentions are wrapped in backticks (no notifications to arbitrary users)
    - raw HTML tags are escaped
    """
    out = _IMAGE_RE.sub(lambda m: f"[image removed: {m.group(1)[:40]}]", text)
    out = _LINK_RE.sub(lambda m: f"{m.group(1)} (`{m.group(2)}`)", out)
    out = _HTML_TAG_RE.sub(lambda m: f"&lt;{m.group(1)}{m.group(2)}{m.group(3)}&gt;", out)
    out = _BARE_URL_RE.sub(lambda m: f"`{m.group(0)}`", out)
    return _MENTION_RE.sub(lambda m: f"`@{m.group(1)}`", out)


def fenced(text: str, lang: str = "") -> str:
    """Code-fence ``text`` with a fence longer than any backtick run inside it."""
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text.rstrip()}\n{fence}"


def inline_code(text: str) -> str:
    """Render a single line as inline code safely."""
    clean = text.replace("\n", " ").replace("\r", " ")
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", clean)), default=0)
    tick = "`" * (longest + 1)
    pad = " " if clean.startswith("`") or clean.endswith("`") else ""
    return f"{tick}{pad}{clean}{pad}{tick}"


def risky_command_reasons(command: str) -> list[str]:
    """Return human-readable reasons a suggested command deserves extra scrutiny."""
    return [reason for pattern, reason in _RISKY_COMMAND_PATTERNS if pattern.search(command)]
