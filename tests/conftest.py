"""Shared fixtures. Every "secret" in this test-suite is generated at runtime from random characters."""

from __future__ import annotations

import base64
import json
import random
import string
from pathlib import Path

import pytest

from ai_devops_assistant.config import Settings

ROOT = Path(__file__).resolve().parents[1]
EVALS = ROOT / "evals"

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits


def rand(n: int, alphabet: str = ALNUM, seed: int = 7) -> str:
    rng = random.Random(f"{seed}-{n}-{alphabet[:5]}")
    return "".join(rng.choice(alphabet) for _ in range(n))


def b64(n_bytes: int, seed: int = 11) -> str:
    rng = random.Random(seed)
    return base64.b64encode(bytes(rng.randrange(256) for _ in range(n_bytes))).decode()


def b64url(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def fake_secrets() -> dict[str, str]:
    """name -> a fake secret string that must never survive redaction."""
    pem_body = "\n".join(b64(48, seed=i) for i in range(5))
    return {
        "aws_access_key_id": "AKIA" + rand(16, UPPER_DIGITS),
        "github_token": "ghp_" + rand(36),
        "github_token_fine": "github_pat_" + rand(22) + "_" + rand(40),
        "gitlab_token": "glpat-" + rand(20),
        "anthropic_api_key": "sk-ant-api03-" + rand(40, ALNUM + "_-"),
        "openai_api_key": "sk-proj-" + rand(48, ALNUM + "_-"),
        "slack_token": "xoxb-" + rand(12, string.digits) + "-" + rand(24),
        "stripe_key": "sk_live_" + rand(24),
        "npm_token": "npm_" + rand(36),
        "google_api_key": "AIza" + rand(35, ALNUM + "_-"),
        "azure_client_secret": rand(3) + "8Q~" + rand(34, ALNUM + "_.~-"),
        "jwt": f"{b64url({'alg': 'RS256', 'typ': 'JWT'})}.{b64url({'sub': 'user-1', 'iss': 'https://issuer.example'})}.{rand(43, ALNUM + '_-')}",
        "private_key": f"-----BEGIN RSA PRIVATE KEY-----\n{pem_body}\n-----END RSA PRIVATE KEY-----",
        "private_key_openssh": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{pem_body}\n-----END OPENSSH PRIVATE KEY-----",
        "azure_storage_connection": f"DefaultEndpointsProtocol=https;AccountName=acmedata;AccountKey={b64(64)};EndpointSuffix=core.windows.net",
        "service_bus": f"Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey={b64(32)}",
        "sas_url": f"https://acmedata.blob.core.windows.net/c/f.zip?sv=2024-01-01&sig={rand(30, ALNUM)}%3D&se=2027-01-01",
        "url_password": f"postgres://appuser:{rand(14)}@db.internal.example:5432/app",
        "bearer": "Bearer " + rand(40, ALNUM + "._-"),
        "password_assignment": f"DB_PASSWORD={rand(16)}",
        "json_password": f'{{"password": "{rand(18)}"}}',
        "aws_secret_key": "aws_secret_access_key = " + rand(40, ALNUM + "/+"),
        "api_key_header": f"x-api-key: {rand(32)}",
        "entropy_blob": rand(48, ALNUM),
    }


def secret_value(name: str, text: str) -> str:
    """The sensitive core of a fake secret (what must be absent from the output)."""
    if name == "url_password":
        return text.split(":")[2].split("@", maxsplit=1)[0]
    if name in ("password_assignment", "aws_secret_key", "api_key_header", "bearer"):
        return text.replace(" = ", "=").replace(": ", "=").split("=", 1)[-1].replace("Bearer ", "")
    if name == "json_password":
        return str(json.loads(text)["password"])
    if name == "azure_storage_connection":
        return text.split("AccountKey=")[1].split(";", maxsplit=1)[0]
    if name == "service_bus":
        return text.split("SharedAccessKey=")[1]
    if name == "sas_url":
        return text.split("sig=")[1].split("%3D", maxsplit=1)[0]
    if name.startswith("private_key"):
        return text.splitlines()[1]
    return text


@pytest.fixture
def offline_settings() -> Settings:
    """Rules-only settings with an empty environment: no key can leak in from the developer's shell."""
    return Settings(rules_only=True, env={})


@pytest.fixture
def mock_settings() -> Settings:
    return Settings(provider="mock", env={})
