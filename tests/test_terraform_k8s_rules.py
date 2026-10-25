from __future__ import annotations

import json
from typing import Any

import pytest

from ai_devops_assistant.config import Settings
from ai_devops_assistant.k8s.bundle import K8sBundle
from ai_devops_assistant.k8s.diagnose import diagnose_k8s, redact_bundle
from ai_devops_assistant.k8s.facts import bytes_to_mi, pod_facts, quantity_to_bytes
from ai_devops_assistant.k8s.rules import diagnose_bundle
from ai_devops_assistant.models import Category
from ai_devops_assistant.providers.mock import MockProvider
from ai_devops_assistant.terraform.review import analyze_plan, review_plan
from conftest import EVALS

OFF = Settings(rules_only=True, env={})


def plan_of(*changes: dict[str, Any]) -> dict[str, Any]:
    return {"resource_changes": list(changes)}


def rc(
    address: str, rtype: str, actions: list[str], before: Any = None, after: Any = None, **extra: Any
) -> dict[str, Any]:
    return {
        "address": address,
        "type": rtype,
        "change": {"actions": actions, "before": before, "after": after, **extra},
    }


def categories(plan: dict[str, Any]) -> set[str]:
    findings, _ = analyze_plan(plan)
    return {f.rule_id for f in findings}


# --- terraform ------------------------------------------------------------------------------------------------
def test_destroy_of_stateful_resource_is_critical_and_replacement_names_the_trigger() -> None:
    findings, counts = analyze_plan(
        plan_of(
            rc(
                "aws_db_instance.a",
                "aws_db_instance",
                ["delete", "create"],
                {},
                {},
                replace_paths=[["engine_version"]],
            )
        )
    )
    assert findings[0].severity == "critical" and "engine_version" in findings[0].root_cause
    assert counts["replace"] == 1


def test_security_group_ports() -> None:
    def sg(port: int, cidr: str = "0.0.0.0/0") -> dict[str, Any]:
        return rc(
            "aws_security_group.a",
            "aws_security_group",
            ["create"],
            None,
            {"ingress": [{"from_port": port, "to_port": port, "protocol": "tcp", "cidr_blocks": [cidr]}]},
        )

    sev = {p: analyze_plan(plan_of(sg(p)))[0][0].severity for p in (22, 5432, 8080, 443)}
    assert sev == {22: "critical", 5432: "critical", 8080: "high", 443: "low"}
    assert analyze_plan(plan_of(sg(22, "10.0.0.0/8")))[0] == []


def test_all_ports_open_and_standalone_rules() -> None:
    all_ports = rc(
        "aws_security_group_rule.a",
        "aws_security_group_rule",
        ["create"],
        None,
        {"type": "ingress", "from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]},
    )
    assert analyze_plan(plan_of(all_ports))[0][0].severity == "critical"
    v2 = rc(
        "aws_vpc_security_group_ingress_rule.a",
        "aws_vpc_security_group_ingress_rule",
        ["create"],
        None,
        {"cidr_ipv4": "0.0.0.0/0", "from_port": 3389, "to_port": 3389, "ip_protocol": "tcp"},
    )
    assert "RDP" in analyze_plan(plan_of(v2))[0][0].root_cause


def test_public_data_stores() -> None:
    cases = [
        rc("aws_s3_bucket_acl.a", "aws_s3_bucket_acl", ["create"], None, {"acl": "public-read"}),
        rc(
            "aws_db_instance.a",
            "aws_db_instance",
            ["update"],
            {"publicly_accessible": False},
            {"publicly_accessible": True},
        ),
        rc(
            "azurerm_storage_account.a",
            "azurerm_storage_account",
            ["update"],
            {},
            {"allow_nested_items_to_be_public": True, "public_network_access_enabled": True},
        ),
        rc(
            "aws_s3_bucket_policy.a",
            "aws_s3_bucket_policy",
            ["create"],
            None,
            {
                "policy": json.dumps(
                    {
                        "Statement": [
                            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
                        ]
                    }
                )
            },
        ),
        rc(
            "azurerm_postgresql_flexible_server.a",
            "azurerm_postgresql_flexible_server",
            ["update"],
            {},
            {"public_network_access_enabled": True},
        ),
    ]
    for case in cases:
        assert any(f.category == Category.PUBLIC_EXPOSURE for f in analyze_plan(plan_of(case))[0]), case[
            "address"
        ]
    conditional = rc(
        "aws_s3_bucket_policy.b",
        "aws_s3_bucket_policy",
        ["create"],
        None,
        {
            "policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                            "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
                        }
                    ]
                }
            )
        },
    )
    assert analyze_plan(plan_of(conditional))[0] == []


def test_azure_nsg_open_inbound() -> None:
    nsg = rc(
        "azurerm_network_security_rule.a",
        "azurerm_network_security_rule",
        ["create"],
        None,
        {
            "direction": "Inbound",
            "access": "Allow",
            "source_address_prefix": "*",
            "destination_port_range": "3389",
        },
    )
    assert analyze_plan(plan_of(nsg))[0][0].severity == "critical"


def test_iam_checks_only_flag_newly_added_wildcards() -> None:
    wild = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    narrow = json.dumps(
        {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::x/*"}]}
    )
    assert (
        categories(
            plan_of(rc("aws_iam_policy.a", "aws_iam_policy", ["update"], {"policy": wild}, {"policy": wild}))
        )
        == set()
    )
    assert categories(
        plan_of(rc("aws_iam_policy.a", "aws_iam_policy", ["update"], {"policy": narrow}, {"policy": wild}))
    ) == {"tf.iam.wildcard"}
    svc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    assert (
        analyze_plan(plan_of(rc("aws_iam_policy.a", "aws_iam_policy", ["create"], None, {"policy": svc})))[0][
            0
        ].severity
        == "high"
    )


def test_trust_policy_admin_attachment_and_cloud_roles() -> None:
    trust = json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    )
    assert "tf.iam.trust_any" in categories(
        plan_of(rc("aws_iam_role.a", "aws_iam_role", ["create"], None, {"assume_role_policy": trust}))
    )
    owner = rc(
        "azurerm_role_assignment.a",
        "azurerm_role_assignment",
        ["create"],
        None,
        {"role_definition_name": "Owner", "scope": "/subscriptions/0000"},
    )
    assert analyze_plan(plan_of(owner))[0][0].severity == "critical"
    gcp = rc(
        "google_project_iam_member.a", "google_project_iam_member", ["create"], None, {"role": "roles/owner"}
    )
    assert analyze_plan(plan_of(gcp))[0][0].severity == "critical"


def test_deletion_protection_removed() -> None:
    change = rc(
        "aws_db_instance.a",
        "aws_db_instance",
        ["update"],
        {"deletion_protection": True},
        {"deletion_protection": False},
    )
    assert "tf.deletion_protection_off" in categories(plan_of(change))


def test_noop_and_invalid_plans() -> None:
    assert analyze_plan(plan_of(rc("a.b", "aws_s3_bucket", ["no-op"], {}, {})))[0] == []
    with pytest.raises(ValueError, match="resource_changes"):
        analyze_plan({"nope": 1})


def test_review_plan_clean_plan_skips_the_model() -> None:
    provider = MockProvider()
    d = review_plan(
        plan_of(rc("aws_sns_topic.a", "aws_sns_topic", ["create"], None, {})),
        settings=Settings(provider="mock", env={}),
        provider=provider,
    )
    assert d.category == Category.NO_RISK_FOUND and provider.calls == [] and "No destroy" in d.summary


def test_review_plan_with_model_summary() -> None:
    reply = {
        "category": "destroy_or_replace",
        "root_cause": "The database is deleted.",
        "confidence": "high",
        "fix_steps": ["Snapshot first."],
        "suggested_commands": [],
        "evidence_quotes": [],
        "suggested_patch": None,
    }
    plan = json.loads(
        (EVALS / "dataset" / "terraform" / "tf-001-destroy-database.json").read_text(encoding="utf-8")
    )
    d = review_plan(plan, settings=Settings(provider="mock", env={}), provider=MockProvider(fixed=reply))
    assert d.mode == "rules+llm" and d.category == Category.DESTROY_OR_REPLACE and d.ai is not None


# --- kubernetes ------------------------------------------------------------------------------------------------
def bundle(name: str) -> K8sBundle:
    return K8sBundle.load(EVALS / "dataset" / "k8s" / f"{name}.json")


def test_oom_recommendation_doubles_the_limit_with_exact_commands() -> None:
    f = diagnose_bundle(bundle("k8s-001-oomkilled"))[0]
    assert f.category == Category.OOM_KILLED
    assert "--limits=memory=256Mi" in " ".join(
        f.suggested_commands
    ) and "set resources deployment/api" in " ".join(f.suggested_commands)
    assert (
        f.suggested_patch
        and "-      memory: 128Mi" in f.suggested_patch
        and "+      memory: 256Mi" in f.suggested_patch
    )


def test_describe_only_bundle_without_json_still_diagnoses() -> None:
    b = bundle("k8s-012-pending-memory")
    assert b.pod is None
    f = diagnose_bundle(b)[0]
    assert f.category == Category.PENDING_RESOURCES and "memory" in f.title


def test_service_selector_patch_uses_the_pod_labels() -> None:
    f = diagnose_bundle(bundle("k8s-016-service-selector"))[0]
    assert f.category == Category.SERVICE_SELECTOR_MISMATCH
    assert '{"spec":{"selector":{"app":"api-server","tier":"backend"}}}' in " ".join(f.suggested_commands)


def test_taint_toleration_snippet_is_exact() -> None:
    f = diagnose_bundle(bundle("k8s-013-pending-taint"))[0]
    assert (
        f.suggested_patch and 'key: "dedicated"' in f.suggested_patch and 'value: "gpu"' in f.suggested_patch
    )


def test_probe_port_mismatch_is_called_out() -> None:
    f = diagnose_bundle(bundle("k8s-010-readiness-port"))[0]
    assert "declares [3000]" in f.root_cause


def test_healthy_pod_yields_no_findings() -> None:
    b = bundle("k8s-016-service-selector")
    b = b.model_copy(update={"services": [], "endpoints": []})
    assert diagnose_bundle(b) == []


def test_multiple_findings_are_ranked_by_specificity() -> None:
    b = bundle("k8s-001-oomkilled")
    findings = diagnose_bundle(b)
    assert findings[0].category == Category.OOM_KILLED
    assert Category.CRASH_LOOP in [f.category for f in findings]


def test_secrets_in_pod_env_and_logs_are_redacted_before_analysis() -> None:
    from conftest import rand

    token = "ghp_" + rand(36)
    b = bundle("k8s-003-crashloop-missing-env")
    assert b.pod is not None
    b.pod["spec"]["containers"][0]["env"] = [
        {"name": "GITHUB_TOKEN", "value": token},
        {"name": "LOG_LEVEL", "value": "info"},
    ]
    b = b.model_copy(
        update={"previous_logs": b.previous_logs + f"auth header Bearer {rand(30)}\nusing {token}\n"}
    )
    provider = MockProvider()
    d = diagnose_k8s(b, settings=Settings(provider="mock", env={}), provider=provider)
    safe, counts = redact_bundle(b)
    assert token not in safe.model_dump_json() and counts
    assert token not in provider.calls[0].user and token not in d.model_dump_json()
    assert '"value": "info"' in safe.model_dump_json(indent=1) or "info" in safe.model_dump_json()


def test_quantity_helpers() -> None:
    assert quantity_to_bytes("128Mi") == 128 * 1024**2
    assert quantity_to_bytes("1G") == 10**9
    assert quantity_to_bytes("lots") is None
    assert bytes_to_mi(256 * 1024**2) == "256Mi" and bytes_to_mi(2 * 1024**3) == "2Gi"


def test_pod_facts_from_json_and_describe_agree() -> None:
    with_json = bundle("k8s-001-oomkilled")
    from_json = pod_facts(with_json).containers[0]
    from_text = pod_facts(with_json.model_copy(update={"pod": None})).containers[0]
    for attr in (
        "name",
        "image",
        "mem_limit",
        "mem_request",
        "restart_count",
        "terminated_reason",
        "exit_code",
        "waiting_reason",
    ):
        assert getattr(from_json, attr) == getattr(from_text, attr), attr
