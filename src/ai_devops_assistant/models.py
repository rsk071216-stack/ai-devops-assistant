"""Pydantic models shared by every analyzer, provider and renderer."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Confidence = Literal["low", "medium", "high"]


class Category(StrEnum):
    """Root-cause taxonomy. One flat enum keeps the LLM output schema strict."""

    # CI
    TEST_FAILURE = "test_failure"
    MISSING_ENV_VAR = "missing_env_var"
    EXPIRED_CREDENTIALS = "expired_credentials"
    DOCKER_BUILD = "docker_build"
    TERRAFORM_INIT = "terraform_init"
    TERRAFORM_VALIDATE = "terraform_validate"
    TERRAFORM_PLAN = "terraform_plan"
    RATE_LIMIT = "rate_limit"
    YAML_SYNTAX = "yaml_syntax"
    OIDC_PERMISSION = "oidc_permission"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"
    DEPENDENCY_RESOLUTION = "dependency_resolution"
    LINT_OR_TYPECHECK = "lint_or_typecheck"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    BUILD_ERROR = "build_error"
    CONFIG_ERROR = "config_error"
    # Kubernetes
    CRASH_LOOP = "crash_loop"
    OOM_KILLED = "oom_killed"
    IMAGE_PULL = "image_pull"
    PROBE_FAILURE = "probe_failure"
    PENDING_RESOURCES = "pending_resources"
    PENDING_TAINT_AFFINITY = "pending_taint_affinity"
    PENDING_PVC = "pending_pvc"
    SERVICE_SELECTOR_MISMATCH = "service_selector_mismatch"
    MISSING_CONFIG_REF = "missing_config_ref"
    EVICTED_NODE_PRESSURE = "evicted_node_pressure"
    ADMISSION_DENIED = "admission_denied"
    # Terraform plan review
    DESTROY_OR_REPLACE = "destroy_or_replace"
    PUBLIC_EXPOSURE = "public_exposure"
    IAM_WIDENING = "iam_widening"
    NO_RISK_FOUND = "no_risk_found"
    # Fallback
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    """A quoted piece of the (already redacted) input that supports a finding."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(description="Where it came from, e.g. 'log line 42' or 'events'.")
    excerpt: str


class Finding(BaseModel):
    """One deterministic diagnosis produced by a rule."""

    rule_id: str
    category: Category
    title: str
    root_cause: str
    fix_steps: list[str] = Field(default_factory=list)
    suggested_commands: list[str] = Field(default_factory=list)
    suggested_patch: str | None = None
    confidence: Confidence = "medium"
    evidence: list[Evidence] = Field(default_factory=list)
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"


class LLMDiagnosis(BaseModel):
    """Strict schema the model must return. Anything else is rejected."""

    model_config = ConfigDict(extra="forbid")

    category: Category
    root_cause: str = Field(max_length=1200)
    confidence: Confidence
    fix_steps: list[str] = Field(max_length=8)
    suggested_commands: list[str] = Field(default_factory=list, max_length=6)
    evidence_quotes: list[str] = Field(default_factory=list, max_length=6)
    suggested_patch: str | None = Field(default=None, max_length=4000)


class AIAnalysis(BaseModel):
    """The validated, sanitised and grounding-checked model answer."""

    provider: str
    model: str
    category: Category
    root_cause: str
    confidence: Confidence
    fix_steps: list[str]
    suggested_commands: list[str]
    suggested_patch: str | None = None
    grounded_quotes: list[str] = Field(default_factory=list)
    ungrounded_quotes: int = 0
    flagged_commands: list[str] = Field(default_factory=list)


class Usage(BaseModel):
    """Token and cost counters. Cost is an estimate from a configurable price table."""

    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float | None = 0.0
    estimated_input_tokens_before_call: int = 0
    latency_ms: int = 0


class Diagnosis(BaseModel):
    """Final result of a triage run, independent of how it is rendered."""

    kind: Literal["ci", "k8s", "terraform"]
    target: str
    mode: Literal["rules-only", "rules+llm"]
    category: Category
    confidence: Confidence
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    ai: AIAnalysis | None = None
    notices: list[str] = Field(default_factory=list)
    usage: Usage = Field(default_factory=Usage)
    redactions: dict[str, int] = Field(default_factory=dict)
    truncated: bool = False
    input_bytes: int = 0
    sent_bytes: int = 0

    @property
    def primary(self) -> Finding | None:
        return self.findings[0] if self.findings else None
