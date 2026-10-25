"""Evidence bundle: the single data shape produced by the live collector and by saved fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class K8sBundle(BaseModel):
    """Read-only evidence for one workload. Secrets are never included, only names of missing references."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(description="e.g. 'pod/api-7d9f' or 'deployment/api'")
    namespace: str = "default"
    pod: dict[str, Any] | None = Field(
        default=None, description="kubectl get pod -o json (the unhealthy pod)"
    )
    deployment: dict[str, Any] | None = Field(default=None, description="kubectl get deployment -o json")
    describe: str = ""
    events: str = ""
    logs: str = ""
    previous_logs: str = ""
    owner_chain: list[str] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    endpoints: list[dict[str, Any]] = Field(default_factory=list)
    missing_refs: list[str] = Field(
        default_factory=list, description="e.g. 'configmap/app-config' verified absent"
    )
    collected_with: list[str] = Field(default_factory=list, description="kubectl commands used (audit trail)")

    @classmethod
    def load(cls, path: Path) -> K8sBundle:
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def save(self, path: Path) -> None:
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")
