"""Terraform plan risk review: deterministic checks over `terraform show -json` output, model summary second."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ai_devops_assistant.analysis import finalize
from ai_devops_assistant.config import Settings
from ai_devops_assistant.engine import clean_value
from ai_devops_assistant.models import Category, Diagnosis, Evidence, Finding
from ai_devops_assistant.observability import log_event
from ai_devops_assistant.providers import Provider
from ai_devops_assistant.redaction import redact

Change = dict[str, Any]

STATEFUL_TYPES = frozenset(
    {
        "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table", "aws_s3_bucket", "aws_efs_file_system",
        "aws_ebs_volume", "aws_kms_key", "aws_elasticache_cluster", "aws_elasticache_replication_group",
        "aws_opensearch_domain", "aws_elasticsearch_domain", "aws_redshift_cluster", "aws_secretsmanager_secret",
        "azurerm_mssql_database", "azurerm_mssql_server", "azurerm_postgresql_flexible_server",
        "azurerm_mysql_flexible_server", "azurerm_storage_account", "azurerm_key_vault", "azurerm_cosmosdb_account",
        "azurerm_managed_disk", "google_sql_database_instance", "google_storage_bucket", "google_kms_crypto_key",
    }
)  # fmt: skip
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 6379: "Redis",
                   27017: "MongoDB", 9200: "Elasticsearch", 2375: "Docker API", 5984: "CouchDB"}  # fmt: skip
OPEN_CIDRS = {"0.0.0.0/0", "::/0", "*", "Internet", "Any"}
ADMIN_POLICY_SUFFIXES = ("/AdministratorAccess", "/PowerUserAccess", "/IAMFullAccess")
RISKY_AZURE_ROLES = {"Owner": "critical", "User Access Administrator": "high", "Contributor": "high"}
RISKY_GCP_ROLES = {"roles/owner": "critical", "roles/editor": "high", "roles/iam.securityAdmin": "high"}

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CAT_RANK = {Category.IAM_WIDENING: 0, Category.PUBLIC_EXPOSURE: 1, Category.DESTROY_OR_REPLACE: 2}


def _after(rc: Change) -> dict[str, Any]:
    return rc.get("change", {}).get("after") or {}


def _before(rc: Change) -> dict[str, Any]:
    return rc.get("change", {}).get("before") or {}


def _actions(rc: Change) -> list[str]:
    return list(rc.get("change", {}).get("actions", []))


def _is_replace(actions: list[str]) -> bool:
    return "delete" in actions and "create" in actions


def _finding(
    rc: Change, rule_id: str, cat: Category, severity: str, title: str, why: str, fix: list[str], ev: str
) -> Finding:
    addr = clean_value(str(rc.get("address", "?")), 120)
    return Finding(
        rule_id=rule_id,
        category=cat,
        title=f"{title}: {addr}",
        root_cause=why,
        fix_steps=fix,
        confidence="high",
        severity=severity,
        evidence=[Evidence(source=addr, excerpt=ev[:300])],
    )


# --- destroy / replace ------------------------------------------------------------------------------
def check_destroy(rc: Change) -> list[Finding]:
    actions = _actions(rc)
    if "delete" not in actions:
        return []
    stateful = rc.get("type") in STATEFUL_TYPES
    replace = _is_replace(actions)
    paths = rc.get("change", {}).get("replace_paths") or []
    forced = ", ".join(".".join(str(p) for p in path) for path in paths[:3])
    what = "replaced (destroyed and re-created)" if replace else "destroyed"
    why = f"This plan will have the resource {what}."
    if replace and forced:
        why += f" The replacement is forced by a change to: {forced}."
    if stateful:
        why += " It holds data or keys: destroying it can cause data loss or an outage."
    fix = [
        "Confirm the destroy is intended; if not, find which attribute change forces replacement and revert it.",
        "Take a backup or snapshot first and check `prevent_destroy` / deletion protection.",
    ]
    if replace:
        fix.append(
            "Prefer an in-place alternative (new resource + migrate + `moved` block) for stateful resources."
        )
    return [
        _finding(
            rc, "tf.destroy_or_replace", Category.DESTROY_OR_REPLACE, "critical" if stateful else "high",
            "Replacement planned" if replace else "Destroy planned", why, fix, f"actions={actions}",
        )
    ]  # fmt: skip


def check_deletion_protection(rc: Change) -> list[Finding]:
    b, a = _before(rc), _after(rc)
    for key in ("deletion_protection", "delete_protection", "prevent_deletion"):
        if b.get(key) is True and a.get(key) is False:
            return [
                _finding(
                    rc, "tf.deletion_protection_off", Category.DESTROY_OR_REPLACE, "high",
                    "Deletion protection disabled", f"`{key}` changes from true to false, removing a safety net against accidental deletion.",
                    ["Keep protection on unless a planned decommission needs it; re-enable right after."], f"{key}: true -> false",
                )
            ]  # fmt: skip
    return []


# --- public exposure --------------------------------------------------------------------------------
def _port_risk(from_port: int | None, to_port: int | None, proto: str) -> tuple[str, str]:
    if proto in ("-1", "all", "*") or (from_port in (0, None) and to_port in (65535, None)):
        return "critical", "all ports"
    lo, hi = from_port or 0, to_port or from_port or 0
    hits = [f"{SENSITIVE_PORTS[p]} ({p})" for p in SENSITIVE_PORTS if lo <= p <= hi]
    if hits:
        return "critical", ", ".join(hits)
    if {lo, hi} <= {80, 443}:
        return "low", f"web ports {lo}-{hi}"
    return "high", f"ports {lo}-{hi}"


def check_security_group(rc: Change) -> list[Finding]:
    t, a = rc.get("type"), _after(rc)
    if "delete" in _actions(rc) and "create" not in _actions(rc):
        return []
    rules: list[dict[str, Any]] = []
    if t == "aws_security_group":
        rules = [r for r in a.get("ingress") or [] if isinstance(r, dict)]
    elif t == "aws_security_group_rule" and a.get("type") == "ingress":
        rules = [a]
    elif t == "aws_vpc_security_group_ingress_rule":
        rules = [{"cidr_blocks": [a.get("cidr_ipv4")] if a.get("cidr_ipv4") else [], "ipv6_cidr_blocks": [a.get("cidr_ipv6")] if a.get("cidr_ipv6") else [],
                  "from_port": a.get("from_port"), "to_port": a.get("to_port"), "protocol": a.get("ip_protocol", "tcp")}]  # fmt: skip
    out: list[Finding] = []
    for r in rules:
        cidrs = list(r.get("cidr_blocks") or []) + list(r.get("ipv6_cidr_blocks") or [])
        if not OPEN_CIDRS & set(cidrs):
            continue
        sev, what = _port_risk(r.get("from_port"), r.get("to_port"), str(r.get("protocol", "tcp")))
        out.append(
            _finding(
                rc, "tf.public.security_group_open", Category.PUBLIC_EXPOSURE, sev, "Ingress open to the internet",
                f"A security group rule allows {what} from 0.0.0.0/0 (anywhere). Anyone on the internet can reach it.",
                ["Restrict `cidr_blocks` to known ranges (office/VPN/bastion) or reference another security group.",
                 "For SSH/RDP use SSM Session Manager or a bastion instead of public ingress."],
                f"cidr={cidrs} ports={r.get('from_port')}-{r.get('to_port')} protocol={r.get('protocol')}",
            )
        )  # fmt: skip
    return out


def check_azure_nsg(rc: Change) -> list[Finding]:
    if rc.get("type") not in ("azurerm_network_security_rule", "azurerm_network_security_group"):
        return []
    a = _after(rc)
    rules = a.get("security_rule") if rc["type"] == "azurerm_network_security_group" else [a]
    out: list[Finding] = []
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        src = {r.get("source_address_prefix")} | set(r.get("source_address_prefixes") or [])
        if r.get("direction") == "Inbound" and r.get("access") == "Allow" and OPEN_CIDRS & src:
            port = str(r.get("destination_port_range", "*"))
            sev = "critical" if port in ("*", "22", "3389") else "high"
            out.append(
                _finding(
                    rc, "tf.public.nsg_open", Category.PUBLIC_EXPOSURE, sev, "NSG inbound rule open to the internet",
                    f"An inbound Allow rule accepts traffic on port {clean_value(port)} from any source.",
                    ["Limit `source_address_prefix` to trusted ranges or service tags.", "Use Bastion/JIT access for management ports."],
                    f"source={sorted(x for x in src if x)} port={port}",
                )
            )  # fmt: skip
    return out


def check_public_data_stores(rc: Change) -> list[Finding]:
    t, a, b = rc.get("type"), _after(rc), _before(rc)
    if "delete" in _actions(rc) and "create" not in _actions(rc):
        return []
    out: list[Finding] = []
    if t == "aws_s3_bucket_public_access_block" and any(
        a.get(k) is False
        for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    ):
        off = [
            k
            for k in (
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            )
            if a.get(k) is False
        ]
        out.append(_finding(rc, "tf.public.s3_block_off", Category.PUBLIC_EXPOSURE, "critical", "S3 public access protection turned off",
                            f"The bucket's public access block is disabled for: {', '.join(off)}. Objects can become world-readable.",
                            ["Set all four public access block settings to true unless the bucket is intentionally a public website.",
                             "Enable account-level S3 Block Public Access as a backstop."], f"{', '.join(k + '=false' for k in off)}"))  # fmt: skip
    if t in ("aws_s3_bucket_acl", "aws_s3_bucket") and str(a.get("acl", "")).startswith("public-read"):
        out.append(_finding(rc, "tf.public.s3_acl", Category.PUBLIC_EXPOSURE, "critical", "S3 bucket ACL is public",
                            f"The bucket ACL is `{clean_value(str(a['acl']))}`, which grants read access to everyone.",
                            ["Use `private` and serve public content via CloudFront with an origin access control."], f"acl={a['acl']}"))  # fmt: skip
    if t == "aws_s3_bucket_policy" and _policy_allows_public(a.get("policy")):
        out.append(_finding(rc, "tf.public.s3_policy", Category.PUBLIC_EXPOSURE, "critical", "Bucket policy grants access to everyone",
                            "The bucket policy contains an Allow statement with Principal `*` and no restricting condition.",
                            ["Scope the principal to specific accounts/roles or add `aws:SourceArn`/`aws:PrincipalOrgID` conditions."], "Principal=*"))  # fmt: skip
    if (
        t in ("aws_db_instance", "aws_rds_cluster_instance")
        and a.get("publicly_accessible") is True
        and b.get("publicly_accessible") is not True
    ):
        out.append(_finding(rc, "tf.public.rds", Category.PUBLIC_EXPOSURE, "critical", "Database made publicly accessible",
                            "`publicly_accessible = true` gives the database a public endpoint; combined with a permissive security group it is reachable from the internet.",
                            ["Keep databases in private subnets; reach them through a bastion, VPN or private endpoint."], "publicly_accessible=true"))  # fmt: skip
    if t == "azurerm_storage_account":
        if a.get("allow_nested_items_to_be_public") is True or a.get("allow_blob_public_access") is True:
            out.append(_finding(rc, "tf.public.azure_blob", Category.PUBLIC_EXPOSURE, "high", "Storage account allows public blob access",
                                "Public blob access is enabled on the account, so individual containers can be made world-readable.",
                                ["Set `allow_nested_items_to_be_public = false` and use SAS tokens or private endpoints."], "allow_nested_items_to_be_public=true"))  # fmt: skip
        if (
            a.get("public_network_access_enabled") is True
            and b.get("public_network_access_enabled") is not True
        ):
            out.append(_finding(rc, "tf.public.azure_network", Category.PUBLIC_EXPOSURE, "high", "Storage account reachable from the public network",
                                "`public_network_access_enabled = true` exposes the data plane endpoint to the internet (firewall rules may still limit it).",
                                ["Prefer private endpoints and set the default network rule to Deny."], "public_network_access_enabled=true"))  # fmt: skip
    if (
        t
        in (
            "azurerm_postgresql_flexible_server",
            "azurerm_mssql_server",
            "azurerm_mysql_flexible_server",
            "azurerm_key_vault",
        )
        and a.get("public_network_access_enabled") is True
        and b.get("public_network_access_enabled") is not True
    ):
        out.append(_finding(rc, "tf.public.azure_db", Category.PUBLIC_EXPOSURE, "high", "Data service reachable from the public network",
                            "`public_network_access_enabled = true` exposes the service endpoint to the internet.",
                            ["Use private endpoints / VNet integration and disable public network access."], "public_network_access_enabled=true"))  # fmt: skip
    return out


# --- IAM widening -----------------------------------------------------------------------------------
def _statements(policy: Any) -> list[dict[str, Any]]:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return []
    if not isinstance(policy, dict):
        return []
    stmts = policy.get("Statement", [])
    return [s for s in ([stmts] if isinstance(stmts, dict) else stmts) if isinstance(s, dict)]


def _as_list(value: Any) -> list[str]:
    return [value] if isinstance(value, str) else [str(v) for v in value or []]


def _wildcard_findings(policy: Any) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for s in _statements(policy):
        if s.get("Effect") != "Allow":
            continue
        actions, resources = _as_list(s.get("Action")), _as_list(s.get("Resource"))
        full = "*" in actions
        svc = [a for a in actions if a.endswith(":*")]
        if full and "*" in resources:
            found.add(("critical", "Action `*` on Resource `*` (full administrator)"))
        elif full:
            found.add(("high", "Action `*` on the listed resources"))
        elif svc and "*" in resources:
            found.add(("high", f"{', '.join(svc[:3])} on Resource `*`"))
    return found


def _policy_allows_public(policy: Any) -> bool:
    for s in _statements(policy):
        principal = s.get("Principal")
        public = principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS")))
        if s.get("Effect") == "Allow" and public and not s.get("Condition"):
            return True
    return False


def check_iam(rc: Change) -> list[Finding]:
    t, a, b = rc.get("type"), _after(rc), _before(rc)
    if "delete" in _actions(rc) and "create" not in _actions(rc):
        return []
    out: list[Finding] = []
    if t in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
        new = _wildcard_findings(a.get("policy")) - _wildcard_findings(b.get("policy"))
        for sev, desc in sorted(new, key=lambda x: _SEV[x[0]]):
            out.append(_finding(rc, "tf.iam.wildcard", Category.IAM_WIDENING, sev, "IAM policy widened",
                                f"The policy now allows {desc}. This grants far more access than least privilege requires.",
                                ["Replace wildcards with the specific actions and resource ARNs the workload needs.",
                                 "Validate with IAM Access Analyzer policy validation before applying."], desc.replace("`", "")))  # fmt: skip
    if t in (
        "aws_iam_role_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
        "aws_iam_policy_attachment",
    ):
        arn = str(a.get("policy_arn", ""))
        if arn.endswith(ADMIN_POLICY_SUFFIXES):
            out.append(_finding(rc, "tf.iam.admin_policy", Category.IAM_WIDENING, "critical", "Admin-level managed policy attached",
                                f"`{clean_value(arn.rsplit('/', 1)[-1])}` is attached, which grants broad or full account access.",
                                ["Create a scoped customer-managed policy instead of attaching an AWS admin policy."], f"policy_arn={arn}"))  # fmt: skip
    if t == "aws_iam_role":
        pol = a.get("assume_role_policy")
        for s in _statements(pol):
            principal = s.get("Principal")
            public = principal == "*" or (
                isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))
            )
            if s.get("Effect") == "Allow" and public:
                sev = "high" if s.get("Condition") else "critical"
                out.append(_finding(rc, "tf.iam.trust_any", Category.IAM_WIDENING, sev, "Role can be assumed by any principal",
                                    "The trust policy allows Principal `*`" + (" (with a condition, verify it is tight)" if s.get("Condition") else " with no condition") + ".",
                                    ["Trust only specific account roots, roles or OIDC subjects, and add `sts:ExternalId` or `aws:PrincipalOrgID` conditions."], "Principal=*"))  # fmt: skip
        if _wildcard_findings(a.get("inline_policy")) - _wildcard_findings(b.get("inline_policy")):
            out.append(_finding(rc, "tf.iam.wildcard", Category.IAM_WIDENING, "high", "IAM role inline policy widened",
                                "An inline policy on the role grants wildcard actions.", ["Scope actions and resources."], "inline_policy wildcard"))  # fmt: skip
    if t == "azurerm_role_assignment":
        role = str(a.get("role_definition_name", ""))
        scope = str(a.get("scope", ""))
        if role in RISKY_AZURE_ROLES:
            broad = scope.count("/") <= 2 or "resourceGroups" not in scope
            sev = RISKY_AZURE_ROLES[role] if broad else "medium"
            out.append(_finding(rc, "tf.iam.azure_role", Category.IAM_WIDENING, sev, f"Privileged Azure role `{clean_value(role)}` assigned",
                                f"`{clean_value(role)}` is granted at scope `{clean_value(scope, 100)}`" + (" (subscription or management group wide)." if broad else "."),
                                ["Use a narrower built-in or custom role at the smallest scope that works."], f"role={role} scope={scope}"))  # fmt: skip
    if t in ("google_project_iam_member", "google_project_iam_binding", "google_organization_iam_member"):
        role = str(a.get("role", ""))
        if role in RISKY_GCP_ROLES:
            out.append(_finding(rc, "tf.iam.gcp_role", Category.IAM_WIDENING, RISKY_GCP_ROLES[role], f"Primitive/admin GCP role `{clean_value(role)}` granted",
                                f"`{clean_value(role)}` is a very broad role.", ["Grant a predefined or custom role scoped to the needed services."], f"role={role}"))  # fmt: skip
    return out


CHECKS: tuple[Callable[[Change], list[Finding]], ...] = (
    check_destroy,
    check_deletion_protection,
    check_security_group,
    check_azure_nsg,
    check_public_data_stores,
    check_iam,
)


def analyze_plan(plan: dict[str, Any]) -> tuple[list[Finding], dict[str, int]]:
    """Return (findings sorted by severity, change counts)."""
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise ValueError("not a `terraform show -json` plan: missing resource_changes")
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "no-op": 0}
    findings: list[Finding] = []
    for rc in changes:
        actions = _actions(rc)
        if _is_replace(actions):
            counts["replace"] += 1
        elif "delete" in actions:
            counts["delete"] += 1
        elif "create" in actions:
            counts["create"] += 1
        elif "update" in actions:
            counts["update"] += 1
        else:
            counts["no-op"] += 1
        if actions in (["no-op"], ["read"], []):
            continue
        for check in CHECKS:
            findings.extend(check(rc))
    findings.sort(key=lambda f: (_SEV[f.severity], _CAT_RANK.get(f.category, 9)))
    return findings, counts


def _evidence_text(findings: list[Finding], counts: dict[str, int]) -> str:
    lines = ["Plan change counts: " + ", ".join(f"{k}={v}" for k, v in counts.items())]
    for f in findings[:30]:
        lines.append(
            f"[{f.severity}] {f.rule_id} {f.title} | {f.root_cause} | evidence: {f.evidence[0].excerpt if f.evidence else ''}"
        )
    return "\n".join(lines)


def review_plan(
    plan: dict[str, Any],
    *,
    settings: Settings,
    provider: Provider | None,
    provider_notices: list[str] | None = None,
    target: str = "terraform-plan",
    case_id: str | None = None,
) -> Diagnosis:
    findings, counts = analyze_plan(plan)
    red = redact(_evidence_text(findings, counts))
    log_event("tf_rules_done", findings=len(findings), counts=counts)
    notices = list(provider_notices or [])
    if not findings:
        provider = None
        notices = [n for n in notices if "rules-only" not in n]
        notices.append("No risky changes were found by the deterministic checks; the model was not called.")
    d = finalize(
        kind="terraform",
        target=target,
        findings=findings,
        evidence_text=red.text,
        settings=settings,
        provider=provider,
        provider_notices=notices,
        redactions=red.counts,
        truncated=False,
        input_bytes=len(json.dumps(plan).encode("utf-8")),
        case_id=case_id,
    )
    parts = ", ".join(f"{v} {k}" for k, v in counts.items() if v and k != "no-op")
    if findings:
        worst = findings[0]
        d.category = worst.category
        d.confidence = "high"
        d.summary = f"{len(findings)} risk finding(s), worst: {worst.severity.upper()} ({parts})"
    else:
        d.category = Category.NO_RISK_FOUND
        d.confidence = "medium"
        d.summary = f"No destroy, public exposure or IAM widening detected ({parts or 'no changes'})"
    return d
