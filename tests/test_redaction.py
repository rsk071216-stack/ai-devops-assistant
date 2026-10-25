"""Redaction corpus: every secret is fake and generated at test time."""

from __future__ import annotations

import hashlib

import pytest

from ai_devops_assistant.ci.triage import triage_log
from ai_devops_assistant.config import Settings
from ai_devops_assistant.redaction import PLACEHOLDER, redact, rule_names, shannon_entropy
from conftest import fake_secrets, rand, secret_value

pytestmark = pytest.mark.redaction

SECRETS = fake_secrets()


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_each_secret_type_is_removed(name: str) -> None:
    secret = SECRETS[name]
    core = secret_value(name, secret)
    log = f"before line\nstep output {secret} trailing text\nafter line"
    result = redact(log)
    assert core not in result.text, f"{name} leaked"
    assert "[REDACTED:" in result.text
    assert "before line" in result.text
    assert "after line" in result.text
    assert result.total >= 1


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_redaction_is_idempotent(name: str) -> None:
    once = redact(f"x {SECRETS[name]} y").text
    assert redact(once).text == once


def test_all_secrets_in_one_log() -> None:
    log = "\n".join(f"line {i}: {s}" for i, s in enumerate(SECRETS.values()))
    out = redact(log).text
    for name, secret in SECRETS.items():
        assert secret_value(name, secret) not in out, name


def test_multiline_private_key_is_removed_entirely() -> None:
    key = SECRETS["private_key"]
    out = redact(f"head\n{key}\ntail").text
    for body_line in key.splitlines()[1:-1]:
        assert body_line not in out
    assert "head" in out and "tail" in out


def test_unterminated_private_key_block_is_still_removed() -> None:
    body = "\n".join(rand(64, seed=i) for i in range(4))
    out = redact(f"-----BEGIN PRIVATE KEY-----\n{body}\n").text
    assert body.splitlines()[0] not in out


def test_url_password_keeps_user_and_host() -> None:
    out = redact(f"connecting to postgres://appuser:{rand(12)}@db.example:5432/app").text
    assert "postgres://appuser:" in out
    assert "@db.example:5432/app" in out


@pytest.mark.parametrize(
    "benign",
    [
        "commit " + hashlib.sha1(b"x").hexdigest(),  # noqa: S324 - fixture only
        "image sha256:" + hashlib.sha256(b"x").hexdigest(),
        "request id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 finished",
        "/home/runner/work/payments-api/payments-api/src/app/very_long_module_name_for_billing_logic.py",
        "test_a_very_long_descriptive_function_name_that_exceeds_thirty_two_characters PASSED",
        "token: expired",
        "AZURE_CLIENT_SECRET: unbound variable",
        "password: required",
        "Error: environment variable DATABASE_URL is not set",
        "secret: ${{ secrets.DEPLOY_KEY }}",
        "TOKEN: ***",
        "GITHUB_TOKEN: [REDACTED:github_token]",
        "Run actions/checkout@v7 (3d3c42e5aac5ba805825da76410c181273ba90b1)",
    ],
)
def test_benign_text_is_preserved(benign: str) -> None:
    assert redact(benign).text == benign


def test_entropy_catch_all_flags_random_blob_but_can_be_disabled() -> None:
    blob = rand(48)
    assert blob not in redact(f"value {blob}").text
    assert blob in redact(f"value {blob}", entropy=False).text
    assert shannon_entropy(blob) > 4.2
    assert shannon_entropy("") == 0.0


def test_k8s_secret_manifest_values_are_redacted() -> None:
    manifest = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  password: cGFzc3dvcmQxMjM0NTY=\n  user: YWRtaW4=\ntype: Opaque\n"
    out = redact(manifest).text
    assert "cGFzc3dvcmQxMjM0NTY=" not in out
    assert "YWRtaW4=" not in out
    assert "name: db" in out and "type: Opaque" in out


def test_counts_never_contain_secret_values() -> None:
    result = redact(SECRETS["github_token"] + " " + SECRETS["jwt"])
    assert set(result.counts) <= set(rule_names())
    assert all(isinstance(v, int) for v in result.counts.values())


def test_placeholder_format() -> None:
    assert PLACEHOLDER.format(name="x") == "[REDACTED:x]"


def test_end_to_end_no_secret_reaches_rendered_output_or_model_prompt(offline_settings: Settings) -> None:
    from ai_devops_assistant.providers.mock import MockProvider
    from ai_devops_assistant.render import render_markdown

    full = [SECRETS["github_token"], SECRETS["aws_access_key_id"], SECRETS["jwt"], SECRETS["url_password"]]
    secrets = [*full[:3], secret_value("url_password", SECRETS["url_password"])]
    log = "Error: environment variable DATABASE_URL is not set\n" + "\n".join(f"debug {s}" for s in full)
    provider = MockProvider()
    d = triage_log(log, settings=Settings(provider="mock", env={}), provider=provider)
    rendered = render_markdown(d, explain=True) + d.model_dump_json()
    prompt = "".join(c.user for c in provider.calls)
    for s in secrets:
        assert s not in rendered
        assert s not in prompt
    assert sum(d.redactions.values()) >= len(secrets)
