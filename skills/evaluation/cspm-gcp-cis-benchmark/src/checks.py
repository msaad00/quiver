"""
CIS GCP Foundations Benchmark v3.0 — Automated Assessment

30 CIS controls across IAM, Storage, Logging, Networking, Compute,
Cloud SQL, and BigQuery. Read-only: requires roles/viewer +
roles/iam.securityReviewer.

Frameworks:
    CIS GCP Foundations v3.0
    NIST CSF 2.0: PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, PR.DS-1, PR.DS-2,
                  DE.AE-3, DE.AE-5, DE.CM-1
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "cspm-gcp-cis-benchmark"
BENCHMARK_NAME = "CIS GCP Foundations Benchmark v3.0"
PROVIDER_NAME = "GCP"
OUTPUT_FORMATS = ("native", "ocsf")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    control_id: str
    title: str
    section: str
    severity: str
    status: str
    detail: str = ""
    nist_csf: str = ""
    resources: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Section 1 — IAM
# ---------------------------------------------------------------------------


def check_1_1_no_gmail_accounts(crm_client, project_id: str) -> Finding:
    """CIS 1.1 — Corporate credentials only (no personal Gmail)."""
    try:
        policy = crm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
        gmail_members = []
        for binding in policy.bindings:
            for member in binding.members:
                if "gmail.com" in member.lower():
                    gmail_members.append(f"{member} -> {binding.role}")
        return Finding(
            control_id="1.1",
            title="No personal Gmail accounts",
            section="iam",
            severity="HIGH",
            status="FAIL" if gmail_members else "PASS",
            detail=f"{len(gmail_members)} personal Gmail accounts in IAM"
            if gmail_members
            else "No personal Gmail accounts",
            nist_csf="PR.AC-1",
            resources=gmail_members,
        )
    except Exception as e:
        return Finding(
            control_id="1.1",
            title="No personal Gmail accounts",
            section="iam",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_1_3_no_sa_keys(iam_client, project_id: str) -> Finding:
    """CIS 1.3 — No user-managed service account keys."""
    try:
        request = {"name": f"projects/{project_id}"}
        service_accounts = list(iam_client.list_service_accounts(request=request))
        sas_with_keys = []
        for sa in service_accounts:
            keys = list(
                iam_client.list_service_account_keys(
                    request={"name": sa.name, "key_types": ["USER_MANAGED"]}
                )
            )
            if keys:
                sas_with_keys.append(f"{sa.email} ({len(keys)} keys)")
        return Finding(
            control_id="1.3",
            title="No user-managed SA keys",
            section="iam",
            severity="HIGH",
            status="FAIL" if sas_with_keys else "PASS",
            detail=f"{len(sas_with_keys)} SAs with user-managed keys"
            if sas_with_keys
            else "No user-managed keys found",
            nist_csf="PR.AC-1",
            resources=sas_with_keys,
        )
    except Exception as e:
        return Finding(
            control_id="1.3",
            title="No user-managed SA keys",
            section="iam",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_1_4_sa_key_rotation(iam_client, project_id: str) -> Finding:
    """CIS 1.4 — Service account key rotation within 90 days."""
    try:
        now = datetime.now(timezone.utc)
        request = {"name": f"projects/{project_id}"}
        service_accounts = list(iam_client.list_service_accounts(request=request))
        old_keys = []
        for sa in service_accounts:
            keys = list(
                iam_client.list_service_account_keys(
                    request={"name": sa.name, "key_types": ["USER_MANAGED"]}
                )
            )
            for key in keys:
                created = key.valid_after_time
                if created and (now - created.replace(tzinfo=timezone.utc)).days > 90:
                    old_keys.append(f"{sa.email}: key {key.name.split('/')[-1]}")
        return Finding(
            control_id="1.4",
            title="SA key rotation (90 days)",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if old_keys else "PASS",
            detail=f"{len(old_keys)} keys older than 90 days"
            if old_keys
            else "All keys within 90 days",
            nist_csf="PR.AC-1",
            resources=old_keys,
        )
    except Exception as e:
        return Finding(
            control_id="1.4",
            title="SA key rotation (90 days)",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


# ---------------------------------------------------------------------------
# Section 2 — Storage
# ---------------------------------------------------------------------------


def check_2_3_no_public_buckets(storage_client, project_id: str) -> Finding:
    """CIS 2.3 — No public buckets."""
    try:
        buckets = list(storage_client.list_buckets(project=project_id))
        public_buckets = []
        for bucket in buckets:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                if (
                    "allUsers" in binding["members"]
                    or "allAuthenticatedUsers" in binding["members"]
                ):
                    public_buckets.append(f"{bucket.name} -> {binding['role']}")
        return Finding(
            control_id="2.3",
            title="No public buckets",
            section="storage",
            severity="CRITICAL",
            status="FAIL" if public_buckets else "PASS",
            detail=f"{len(public_buckets)} public bucket bindings"
            if public_buckets
            else "No public buckets",
            nist_csf="PR.AC-3",
            resources=public_buckets,
        )
    except Exception as e:
        return Finding(
            control_id="2.3",
            title="No public buckets",
            section="storage",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


def check_2_1_uniform_access(storage_client, project_id: str) -> Finding:
    """CIS 2.1 — Uniform bucket-level access."""
    try:
        buckets = list(storage_client.list_buckets(project=project_id))
        legacy_acl = []
        for bucket in buckets:
            if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                legacy_acl.append(bucket.name)
        return Finding(
            control_id="2.1",
            title="Uniform bucket-level access",
            section="storage",
            severity="HIGH",
            status="FAIL" if legacy_acl else "PASS",
            detail=f"{len(legacy_acl)} buckets with legacy ACL"
            if legacy_acl
            else "All buckets use uniform access",
            nist_csf="PR.AC-3",
            resources=legacy_acl,
        )
    except Exception as e:
        return Finding(
            control_id="2.1",
            title="Uniform bucket-level access",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


# ---------------------------------------------------------------------------
# Section 3 — Logging
# ---------------------------------------------------------------------------


def _iter_audit_configs(policy) -> list:
    configs = getattr(policy, "audit_configs", None)
    if configs is None and isinstance(policy, dict):
        configs = policy.get("audit_configs")
    return list(configs or [])


def _iter_audit_log_configs(config) -> list:
    audit_log_configs = getattr(config, "audit_log_configs", None)
    if audit_log_configs is None and isinstance(config, dict):
        audit_log_configs = config.get("audit_log_configs")
    return list(audit_log_configs or [])


def check_3_1_audit_logging_all_services(crm_client, project_id: str) -> Finding:
    """CIS 3.1 — Audit logging enabled for all services."""
    try:
        policy = crm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
        required = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
        configured: set[str] = set()
        exemptions: list[str] = []

        for config in _iter_audit_configs(policy):
            service = getattr(config, "service", None)
            if service is None and isinstance(config, dict):
                service = config.get("service")
            if service != "allServices":
                continue
            for log_config in _iter_audit_log_configs(config):
                log_type = getattr(log_config, "log_type", None)
                if log_type is None and isinstance(log_config, dict):
                    log_type = log_config.get("log_type")
                if log_type:
                    configured.add(str(log_type))
                exempted_members = getattr(log_config, "exempted_members", None)
                if exempted_members is None and isinstance(log_config, dict):
                    exempted_members = log_config.get("exempted_members")
                for member in exempted_members or []:
                    exemptions.append(f"{log_type}:{member}")

        missing = sorted(required - configured)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if exemptions:
            details.append(f"{len(exemptions)} exempted member(s)")

        return Finding(
            control_id="3.1",
            title="Audit logging for all services",
            section="logging",
            severity="HIGH",
            status="FAIL" if details else "PASS",
            detail="; ".join(details)
            if details
            else "Admin Read, Data Read, and Data Write enabled for allServices",
            nist_csf="DE.AE-3",
            resources=missing + exemptions,
        )
    except Exception as e:
        return Finding(
            control_id="3.1",
            title="Audit logging for all services",
            section="logging",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


# ---------------------------------------------------------------------------
# Section 4 — Networking
# ---------------------------------------------------------------------------


def check_4_1_default_network_deleted(network_client, project_id: str) -> Finding:
    """CIS 4.1 — Default network should be deleted."""
    try:
        request = {"project": project_id}
        networks = list(network_client.list(request=request))
        default_networks = [
            network.name for network in networks if getattr(network, "name", "") == "default"
        ]
        return Finding(
            control_id="4.1",
            title="Default network deleted",
            section="networking",
            severity="HIGH",
            status="FAIL" if default_networks else "PASS",
            detail="Default VPC network still exists"
            if default_networks
            else "Default VPC network not present",
            nist_csf="PR.AC-5",
            resources=default_networks,
        )
    except Exception as e:
        return Finding(
            control_id="4.1",
            title="Default network deleted",
            section="networking",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


def check_4_2_no_unrestricted_ssh_rdp(compute_client, project_id: str) -> Finding:
    """CIS 4.2 — No unrestricted SSH/RDP in firewall rules."""
    try:
        request = {"project": project_id}
        firewalls = compute_client.list(request=request)
        open_rules = []
        for rule in firewalls:
            if rule.direction != "INGRESS" or rule.disabled:
                continue
            for allowed in rule.allowed or []:
                ports: list[int] = []
                for p in allowed.ports or []:
                    if "-" in p:
                        low, high = p.split("-")
                        ports.extend(range(int(low), int(high) + 1))
                    else:
                        ports.append(int(p))
                if (22 in ports or 3389 in ports) and "0.0.0.0/0" in (rule.source_ranges or []):
                    open_rules.append(
                        f"{rule.name}: {allowed.ip_protocol}/{','.join(allowed.ports or [])}"
                    )
        return Finding(
            control_id="4.2",
            title="No unrestricted SSH/RDP",
            section="networking",
            severity="HIGH",
            status="FAIL" if open_rules else "PASS",
            detail=f"{len(open_rules)} rules allow 0.0.0.0/0 on SSH/RDP"
            if open_rules
            else "No unrestricted SSH/RDP",
            nist_csf="PR.AC-5",
            resources=open_rules,
        )
    except Exception as e:
        return Finding(
            control_id="4.2",
            title="No unrestricted SSH/RDP",
            section="networking",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


def check_4_3_vpc_flow_logs(compute_client, project_id: str) -> Finding:
    """CIS 4.3 — VPC flow logs enabled on all subnets."""
    try:
        request = {"project": project_id}
        subnets = []
        for region_subnets in compute_client.aggregated_list(request=request):
            for subnet in region_subnets.subnetworks or []:
                subnets.append(subnet)
        no_logs = [
            s.name for s in subnets if not getattr(s, "log_config", None) or not s.log_config.enable
        ]
        return Finding(
            control_id="4.3",
            title="VPC flow logs on all subnets",
            section="networking",
            severity="MEDIUM",
            status="FAIL" if no_logs else "PASS",
            detail=f"{len(no_logs)} subnets without flow logs"
            if no_logs
            else "All subnets have flow logs",
            nist_csf="DE.CM-1",
            resources=no_logs,
        )
    except Exception as e:
        return Finding(
            control_id="4.3",
            title="VPC flow logs on all subnets",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


def check_4_4_private_google_access(compute_client, project_id: str) -> Finding:
    """CIS 4.4 — Private Google Access enabled on all subnets."""
    try:
        request = {"project": project_id}
        subnets = []
        for region_subnets in compute_client.aggregated_list(request=request):
            for subnet in region_subnets.subnetworks or []:
                subnets.append(subnet)
        missing_pga = [s.name for s in subnets if not getattr(s, "private_ip_google_access", False)]
        return Finding(
            control_id="4.4",
            title="Private Google Access on all subnets",
            section="networking",
            severity="MEDIUM",
            status="FAIL" if missing_pga else "PASS",
            detail=f"{len(missing_pga)} subnets without Private Google Access"
            if missing_pga
            else "All subnets enable Private Google Access",
            nist_csf="PR.AC-5",
            resources=missing_pga,
        )
    except Exception as e:
        return Finding(
            control_id="4.4",
            title="Private Google Access on all subnets",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


# ---------------------------------------------------------------------------
# Section 1 — IAM (additional)
# ---------------------------------------------------------------------------


_SA_ADMIN_ROLES = {
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountUser",
}

_KMS_ADMIN_ROLES = {
    "roles/cloudkms.admin",
    "roles/cloudkms.cryptoKeyEncrypterDecrypter",
    "roles/cloudkms.cryptoKeyEncrypter",
    "roles/cloudkms.cryptoKeyDecrypter",
}


def _members_per_role(policy, role_set: set[str]) -> dict[str, set[str]]:
    """Group members by the subset of `role_set` they hold in this policy."""
    out: dict[str, set[str]] = {}
    for binding in getattr(policy, "bindings", []) or []:
        role = getattr(binding, "role", None)
        if role is None and isinstance(binding, dict):
            role = binding.get("role")
        if role not in role_set:
            continue
        members = getattr(binding, "members", None)
        if members is None and isinstance(binding, dict):
            members = binding.get("members")
        for m in members or []:
            out.setdefault(m, set()).add(role)
    return out


def check_1_5_separation_sa_admin(crm_client, project_id: str) -> Finding:
    """CIS 1.5 — Separation of duties for service account admin roles.

    No principal should hold *both* serviceAccountAdmin and serviceAccountUser.
    """
    try:
        policy = crm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
        per_member = _members_per_role(policy, _SA_ADMIN_ROLES)
        offenders = sorted(m for m, roles in per_member.items() if len(roles) > 1)
        return Finding(
            control_id="1.5",
            title="Separation of duties for SA admin roles",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} principals hold both serviceAccountAdmin and serviceAccountUser"
                if offenders
                else "No principal holds both SA admin and SA user roles"
            ),
            nist_csf="PR.AC-4",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="1.5",
            title="Separation of duties for SA admin roles",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-4",
        )


def check_1_6_disable_sa_key_creation(orgpolicy_client, project_id: str) -> Finding:
    """CIS 1.6 — Org policy disables service account key creation."""
    try:
        constraint = "constraints/iam.disableServiceAccountKeyCreation"
        policy = orgpolicy_client.get_org_policy(
            request={"resource": f"projects/{project_id}", "constraint": constraint}
        )
        boolean_policy = getattr(policy, "boolean_policy", None)
        if boolean_policy is None and isinstance(policy, dict):
            boolean_policy = policy.get("boolean_policy")
        enforced = bool(getattr(boolean_policy, "enforced", False)) if boolean_policy else False
        if isinstance(boolean_policy, dict):
            enforced = bool(boolean_policy.get("enforced", False))
        return Finding(
            control_id="1.6",
            title="Org policy disables SA key creation",
            section="iam",
            severity="MEDIUM",
            status="PASS" if enforced else "FAIL",
            detail=(
                "iam.disableServiceAccountKeyCreation enforced"
                if enforced
                else "iam.disableServiceAccountKeyCreation NOT enforced"
            ),
            nist_csf="PR.AC-1",
            resources=[constraint],
        )
    except Exception as e:
        return Finding(
            control_id="1.6",
            title="Org policy disables SA key creation",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_1_11_separation_kms(crm_client, project_id: str) -> Finding:
    """CIS 1.11 — Separation of duties for KMS-related roles."""
    try:
        policy = crm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
        per_member = _members_per_role(policy, _KMS_ADMIN_ROLES)
        offenders = sorted(
            f"{m} -> {sorted(roles)}"
            for m, roles in per_member.items()
            if "roles/cloudkms.admin" in roles and len(roles) > 1
        )
        return Finding(
            control_id="1.11",
            title="Separation of duties for KMS roles",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} principals hold cloudkms.admin and crypto-key roles"
                if offenders
                else "No principal holds both cloudkms.admin and a crypto-key role"
            ),
            nist_csf="PR.AC-4",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="1.11",
            title="Separation of duties for KMS roles",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-4",
        )


def check_1_12_kms_keys_not_public(kms_client, project_id: str) -> Finding:
    """CIS 1.12 — KMS keys not anonymously / publicly accessible."""
    try:
        public_keys: list[str] = []
        locations = list(
            kms_client.list_key_rings(request={"parent": f"projects/{project_id}/locations/-"})
        )
        for ring in locations:
            ring_name = getattr(ring, "name", None) or (
                ring.get("name") if isinstance(ring, dict) else ""
            )
            if not ring_name:
                continue
            keys = list(kms_client.list_crypto_keys(request={"parent": ring_name}))
            for key in keys:
                key_name = getattr(key, "name", None) or (
                    key.get("name") if isinstance(key, dict) else ""
                )
                policy = kms_client.get_iam_policy(request={"resource": key_name})
                for binding in getattr(policy, "bindings", []) or []:
                    members = getattr(binding, "members", None)
                    if members is None and isinstance(binding, dict):
                        members = binding.get("members")
                    members = members or []
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public_keys.append(str(key_name))
                        break
        return Finding(
            control_id="1.12",
            title="KMS keys not publicly accessible",
            section="iam",
            severity="CRITICAL",
            status="FAIL" if public_keys else "PASS",
            detail=(
                f"{len(public_keys)} KMS keys exposed to allUsers/allAuthenticatedUsers"
                if public_keys
                else "No KMS keys exposed to public principals"
            ),
            nist_csf="PR.AC-3",
            resources=public_keys,
        )
    except Exception as e:
        return Finding(
            control_id="1.12",
            title="KMS keys not publicly accessible",
            section="iam",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


def check_1_13_api_keys_restricted(apikeys_client, project_id: str) -> Finding:
    """CIS 1.13 — API keys carry application + API restrictions."""
    try:
        keys = list(
            apikeys_client.list_keys(request={"parent": f"projects/{project_id}/locations/global"})
        )
        unrestricted: list[str] = []
        for key in keys:
            name = getattr(key, "name", None) or (key.get("name") if isinstance(key, dict) else "")
            display = getattr(key, "display_name", None) or (
                key.get("display_name") if isinstance(key, dict) else ""
            )
            label = display or name
            restrictions = getattr(key, "restrictions", None)
            if restrictions is None and isinstance(key, dict):
                restrictions = key.get("restrictions")
            if not restrictions:
                unrestricted.append(str(label))
                continue
            api_targets = getattr(restrictions, "api_targets", None)
            if api_targets is None and isinstance(restrictions, dict):
                api_targets = restrictions.get("api_targets")
            has_app_restrictions = any(
                bool(
                    getattr(restrictions, attr, None)
                    or (restrictions.get(attr) if isinstance(restrictions, dict) else None)
                )
                for attr in (
                    "browser_key_restrictions",
                    "server_key_restrictions",
                    "android_key_restrictions",
                    "ios_key_restrictions",
                )
            )
            if not has_app_restrictions or not api_targets:
                unrestricted.append(str(label))
        return Finding(
            control_id="1.13",
            title="API keys carry usage restrictions",
            section="iam",
            severity="MEDIUM",
            status="FAIL" if unrestricted else "PASS",
            detail=(
                f"{len(unrestricted)} API keys missing application or API restrictions"
                if unrestricted
                else "All API keys carry both application and API restrictions"
            ),
            nist_csf="PR.AC-1",
            resources=unrestricted,
        )
    except Exception as e:
        return Finding(
            control_id="1.13",
            title="API keys carry usage restrictions",
            section="iam",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_1_14_essential_contacts(contacts_client, project_id: str) -> Finding:
    """CIS 1.14 — Essential Contacts configured for security categories."""
    try:
        required = {"SECURITY", "TECHNICAL", "LEGAL", "SUSPENSION"}
        contacts = list(contacts_client.list_contacts(request={"parent": f"projects/{project_id}"}))
        seen: set[str] = set()
        for contact in contacts:
            categories = getattr(contact, "notification_category_subscriptions", None)
            if categories is None and isinstance(contact, dict):
                categories = contact.get("notification_category_subscriptions")
            for c in categories or []:
                seen.add(str(c).upper())
        missing = sorted(required - seen)
        return Finding(
            control_id="1.14",
            title="Essential Contacts configured",
            section="iam",
            severity="LOW",
            status="FAIL" if missing else "PASS",
            detail=(
                f"missing essential contact categories: {', '.join(missing)}"
                if missing
                else "All required essential contact categories configured"
            ),
            nist_csf="DE.AE-5",
            resources=missing,
        )
    except Exception as e:
        return Finding(
            control_id="1.14",
            title="Essential Contacts configured",
            section="iam",
            severity="LOW",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-5",
        )


# ---------------------------------------------------------------------------
# Section 2 — Logging & Monitoring
# ---------------------------------------------------------------------------


def check_2_2_log_sink_configured(logging_client, project_id: str) -> Finding:
    """CIS 2.2 — At least one log sink covers all log entries (filter empty)."""
    try:
        sinks = list(logging_client.list_sinks(request={"parent": f"projects/{project_id}"}))
        catch_all = []
        for sink in sinks:
            sink_filter = getattr(sink, "filter", None)
            if sink_filter is None and isinstance(sink, dict):
                sink_filter = sink.get("filter")
            destination = getattr(sink, "destination", None) or (
                sink.get("destination") if isinstance(sink, dict) else ""
            )
            if not sink_filter:
                catch_all.append(str(destination))
        return Finding(
            control_id="2.2",
            title="Log sink covers all entries",
            section="logging",
            severity="HIGH",
            status="PASS" if catch_all else "FAIL",
            detail=(
                f"{len(catch_all)} catch-all sink(s) configured"
                if catch_all
                else "No log sink with empty filter (catch-all) found"
            ),
            nist_csf="DE.AE-3",
            resources=catch_all,
        )
    except Exception as e:
        return Finding(
            control_id="2.2",
            title="Log sink covers all entries",
            section="logging",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


def _has_metric_with_filter(logging_client, project_id: str, needle: str) -> bool:
    metrics = list(logging_client.list_log_metrics(request={"parent": f"projects/{project_id}"}))
    for metric in metrics:
        f = getattr(metric, "filter", None)
        if f is None and isinstance(metric, dict):
            f = metric.get("filter")
        if f and needle in f:
            return True
    return False


def check_2_4_log_metric_project_ownership(logging_client, project_id: str) -> Finding:
    """CIS 2.4 — Log metric filter for project ownership assignment changes."""
    try:
        needle = "SetIamPolicy"
        present = _has_metric_with_filter(logging_client, project_id, needle)
        return Finding(
            control_id="2.4",
            title="Log metric filter for project ownership changes",
            section="logging",
            severity="MEDIUM",
            status="PASS" if present else "FAIL",
            detail=(
                "Metric filter on SetIamPolicy is present"
                if present
                else "No metric filter on SetIamPolicy found"
            ),
            nist_csf="DE.AE-3",
        )
    except Exception as e:
        return Finding(
            control_id="2.4",
            title="Log metric filter for project ownership changes",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


def check_2_7_log_metric_vpc_changes(logging_client, project_id: str) -> Finding:
    """CIS 2.7 — Log metric filter for VPC network changes."""
    try:
        needle = "compute.networks"
        present = _has_metric_with_filter(logging_client, project_id, needle)
        return Finding(
            control_id="2.7",
            title="Log metric filter for VPC network changes",
            section="logging",
            severity="MEDIUM",
            status="PASS" if present else "FAIL",
            detail=(
                "Metric filter on compute.networks is present"
                if present
                else "No metric filter on compute.networks found"
            ),
            nist_csf="DE.AE-3",
        )
    except Exception as e:
        return Finding(
            control_id="2.7",
            title="Log metric filter for VPC network changes",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


def check_2_10_log_metric_audit_config(logging_client, project_id: str) -> Finding:
    """CIS 2.10 — Log metric filter for audit-config changes."""
    try:
        needle = "AuditConfig"
        present = _has_metric_with_filter(logging_client, project_id, needle)
        return Finding(
            control_id="2.10",
            title="Log metric filter for audit-config changes",
            section="logging",
            severity="MEDIUM",
            status="PASS" if present else "FAIL",
            detail=(
                "Metric filter on AuditConfig changes is present"
                if present
                else "No metric filter on AuditConfig changes found"
            ),
            nist_csf="DE.AE-3",
        )
    except Exception as e:
        return Finding(
            control_id="2.10",
            title="Log metric filter for audit-config changes",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


def check_2_13_cloud_asset_inventory(asset_client, project_id: str) -> Finding:
    """CIS 2.13 — Cloud Asset Inventory accessible (a successful list_assets call)."""
    try:
        page = asset_client.list_assets(request={"parent": f"projects/{project_id}"})
        # Materialise at most one entry — proves the API is enabled and reachable.
        iterator = iter(page)
        try:
            next(iterator)
        except StopIteration:
            pass
        return Finding(
            control_id="2.13",
            title="Cloud Asset Inventory enabled",
            section="logging",
            severity="LOW",
            status="PASS",
            detail="cloudasset.googleapis.com responded successfully",
            nist_csf="ID.AM-1",
        )
    except Exception as e:
        return Finding(
            control_id="2.13",
            title="Cloud Asset Inventory enabled",
            section="logging",
            severity="LOW",
            status="FAIL",
            detail=str(e),
            nist_csf="ID.AM-1",
        )


# ---------------------------------------------------------------------------
# Section 3 — Networking (additional)
# ---------------------------------------------------------------------------


def check_3_10_dns_logging(dns_client, project_id: str) -> Finding:
    """CIS 3.10 — Cloud DNS logging enabled on all VPC network policies."""
    try:
        policies = list(dns_client.list(project=project_id))
        unlogged: list[str] = []
        for policy in policies:
            name = getattr(policy, "name", None) or (
                policy.get("name") if isinstance(policy, dict) else ""
            )
            enable = getattr(policy, "enable_logging", None)
            if enable is None and isinstance(policy, dict):
                enable = policy.get("enable_logging")
            if not enable:
                unlogged.append(str(name))
        return Finding(
            control_id="3.10",
            title="Cloud DNS logging enabled",
            section="networking",
            severity="MEDIUM",
            status="FAIL" if unlogged else "PASS",
            detail=(
                f"{len(unlogged)} DNS policies without logging"
                if unlogged
                else "All Cloud DNS policies enable logging"
            ),
            nist_csf="DE.CM-1",
            resources=unlogged,
        )
    except Exception as e:
        return Finding(
            control_id="3.10",
            title="Cloud DNS logging enabled",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


# ---------------------------------------------------------------------------
# Section 4 — Compute (VM)
# ---------------------------------------------------------------------------


def _list_aggregated_instances(compute_client, project_id: str):
    """Yield (zone_label, instance) tuples from an aggregated_list response."""
    request = {"project": project_id}
    response = compute_client.aggregated_list(request=request)
    if hasattr(response, "items") and not callable(response.items):
        items = response.items
    else:
        items = response
    if isinstance(items, dict):
        iterable = items.items()
    else:
        iterable = items
    for entry in iterable:
        if isinstance(entry, tuple) and len(entry) == 2:
            zone, scoped = entry
            instances = getattr(scoped, "instances", None)
            if instances is None and isinstance(scoped, dict):
                instances = scoped.get("instances")
            for inst in instances or []:
                yield zone, inst
        else:
            instances = getattr(entry, "instances", None)
            if instances is None and isinstance(entry, dict):
                instances = entry.get("instances")
            for inst in instances or []:
                yield "", inst


def check_4_5_block_project_wide_ssh(compute_client, project_id: str) -> Finding:
    """CIS 4.5 — Compute instances block project-wide SSH keys."""
    try:
        offenders: list[str] = []
        for zone, inst in _list_aggregated_instances(compute_client, project_id):
            name = getattr(inst, "name", None) or (
                inst.get("name") if isinstance(inst, dict) else ""
            )
            metadata = getattr(inst, "metadata", None)
            if metadata is None and isinstance(inst, dict):
                metadata = inst.get("metadata")
            items = getattr(metadata, "items", None) if metadata else None
            if items is None and isinstance(metadata, dict):
                items = metadata.get("items")
            blocked = False
            for item in items or []:
                key = getattr(item, "key", None) or (
                    item.get("key") if isinstance(item, dict) else ""
                )
                value = getattr(item, "value", None) or (
                    item.get("value") if isinstance(item, dict) else ""
                )
                if key == "block-project-ssh-keys" and str(value).lower() == "true":
                    blocked = True
                    break
            if not blocked:
                offenders.append(f"{zone}/{name}".strip("/"))
        return Finding(
            control_id="4.5",
            title="Block project-wide SSH keys",
            section="compute",
            severity="MEDIUM",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} instances allow project-wide SSH keys"
                if offenders
                else "All instances block project-wide SSH keys"
            ),
            nist_csf="PR.AC-1",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="4.5",
            title="Block project-wide SSH keys",
            section="compute",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_4_6_confidential_vm(compute_client, project_id: str) -> Finding:
    """CIS 4.6 — Confidential VM enabled on all instances."""
    try:
        offenders: list[str] = []
        for zone, inst in _list_aggregated_instances(compute_client, project_id):
            name = getattr(inst, "name", None) or (
                inst.get("name") if isinstance(inst, dict) else ""
            )
            cc = getattr(inst, "confidential_instance_config", None)
            if cc is None and isinstance(inst, dict):
                cc = inst.get("confidential_instance_config")
            enabled = bool(getattr(cc, "enable_confidential_compute", False)) if cc else False
            if isinstance(cc, dict):
                enabled = bool(cc.get("enable_confidential_compute", False))
            if not enabled:
                offenders.append(f"{zone}/{name}".strip("/"))
        return Finding(
            control_id="4.6",
            title="Confidential VM enabled",
            section="compute",
            severity="LOW",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} instances without Confidential VM"
                if offenders
                else "All instances use Confidential VM"
            ),
            nist_csf="PR.DS-1",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="4.6",
            title="Confidential VM enabled",
            section="compute",
            severity="LOW",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


def check_4_7_shielded_vm(compute_client, project_id: str) -> Finding:
    """CIS 4.7 — Shielded VM (vTPM + integrity monitoring) on all instances."""
    try:
        offenders: list[str] = []
        for zone, inst in _list_aggregated_instances(compute_client, project_id):
            name = getattr(inst, "name", None) or (
                inst.get("name") if isinstance(inst, dict) else ""
            )
            cfg = getattr(inst, "shielded_instance_config", None)
            if cfg is None and isinstance(inst, dict):
                cfg = inst.get("shielded_instance_config")
            v_tpm = bool(getattr(cfg, "enable_vtpm", False)) if cfg else False
            integ = bool(getattr(cfg, "enable_integrity_monitoring", False)) if cfg else False
            if isinstance(cfg, dict):
                v_tpm = bool(cfg.get("enable_vtpm", False))
                integ = bool(cfg.get("enable_integrity_monitoring", False))
            if not (v_tpm and integ):
                offenders.append(f"{zone}/{name}".strip("/"))
        return Finding(
            control_id="4.7",
            title="Shielded VM enabled",
            section="compute",
            severity="MEDIUM",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} instances missing vTPM or integrity monitoring"
                if offenders
                else "All instances enable vTPM and integrity monitoring"
            ),
            nist_csf="PR.DS-1",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="4.7",
            title="Shielded VM enabled",
            section="compute",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


def check_4_8_disk_cmek(compute_client, project_id: str) -> Finding:
    """CIS 4.8 — Compute disks encrypted with CMEK (customer-managed)."""
    try:
        offenders: list[str] = []
        for zone, inst in _list_aggregated_instances(compute_client, project_id):
            name = getattr(inst, "name", None) or (
                inst.get("name") if isinstance(inst, dict) else ""
            )
            disks = getattr(inst, "disks", None)
            if disks is None and isinstance(inst, dict):
                disks = inst.get("disks")
            for disk in disks or []:
                disk_name = getattr(disk, "device_name", None) or (
                    disk.get("device_name") if isinstance(disk, dict) else ""
                )
                key = getattr(disk, "disk_encryption_key", None)
                if key is None and isinstance(disk, dict):
                    key = disk.get("disk_encryption_key")
                kms_name = getattr(key, "kms_key_name", None) if key else None
                if isinstance(key, dict):
                    kms_name = key.get("kms_key_name")
                if not kms_name:
                    offenders.append(f"{zone}/{name}/{disk_name}".strip("/"))
        return Finding(
            control_id="4.8",
            title="Compute disks encrypted with CMEK",
            section="compute",
            severity="MEDIUM",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} disks lack CMEK encryption"
                if offenders
                else "All compute disks use CMEK"
            ),
            nist_csf="PR.DS-1",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="4.8",
            title="Compute disks encrypted with CMEK",
            section="compute",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


# ---------------------------------------------------------------------------
# Section 6 — Cloud SQL
# ---------------------------------------------------------------------------


def _sql_instances(sql_client, project_id: str):
    response = sql_client.list(project=project_id)
    items = getattr(response, "items", None)
    if items is None and isinstance(response, dict):
        items = response.get("items")
    if items is None:
        items = response  # treat as iterable
    return list(items or [])


def check_6_1_cloudsql_no_public_ip(sql_client, project_id: str) -> Finding:
    """CIS 6.1 — Cloud SQL instances do not use a public IP."""
    try:
        offenders: list[str] = []
        for inst in _sql_instances(sql_client, project_id):
            name = getattr(inst, "name", None) or (
                inst.get("name") if isinstance(inst, dict) else ""
            )
            settings = getattr(inst, "settings", None)
            if settings is None and isinstance(inst, dict):
                settings = inst.get("settings")
            ip_cfg = getattr(settings, "ip_configuration", None) if settings else None
            if isinstance(settings, dict):
                ip_cfg = settings.get("ip_configuration")
            ipv4 = getattr(ip_cfg, "ipv4_enabled", None) if ip_cfg else None
            if isinstance(ip_cfg, dict):
                ipv4 = ip_cfg.get("ipv4_enabled")
            if ipv4 is True:
                offenders.append(str(name))
        return Finding(
            control_id="6.1",
            title="Cloud SQL not configured with public IP",
            section="cloudsql",
            severity="HIGH",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} Cloud SQL instances have public IPv4 enabled"
                if offenders
                else "No Cloud SQL instances expose a public IP"
            ),
            nist_csf="PR.AC-5",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="6.1",
            title="Cloud SQL not configured with public IP",
            section="cloudsql",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


def check_6_4_cloudsql_require_ssl(sql_client, project_id: str) -> Finding:
    """CIS 6.4 — Cloud SQL instances require SSL connections."""
    try:
        offenders: list[str] = []
        for inst in _sql_instances(sql_client, project_id):
            name = getattr(inst, "name", None) or (
                inst.get("name") if isinstance(inst, dict) else ""
            )
            settings = getattr(inst, "settings", None)
            if settings is None and isinstance(inst, dict):
                settings = inst.get("settings")
            ip_cfg = getattr(settings, "ip_configuration", None) if settings else None
            if isinstance(settings, dict):
                ip_cfg = settings.get("ip_configuration")
            require_ssl = getattr(ip_cfg, "require_ssl", None) if ip_cfg else None
            if isinstance(ip_cfg, dict):
                require_ssl = ip_cfg.get("require_ssl")
            if not require_ssl:
                offenders.append(str(name))
        return Finding(
            control_id="6.4",
            title="Cloud SQL require SSL",
            section="cloudsql",
            severity="HIGH",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} Cloud SQL instances do not require SSL"
                if offenders
                else "All Cloud SQL instances require SSL"
            ),
            nist_csf="PR.DS-2",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="6.4",
            title="Cloud SQL require SSL",
            section="cloudsql",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-2",
        )


# ---------------------------------------------------------------------------
# Section 7 — BigQuery
# ---------------------------------------------------------------------------


def check_7_1_bigquery_not_public(bq_client, project_id: str) -> Finding:
    """CIS 7.1 — BigQuery datasets not anonymously / publicly accessible."""
    try:
        public: list[str] = []
        datasets = list(bq_client.list_datasets(project=project_id))
        for ds_ref in datasets:
            dataset = bq_client.get_dataset(ds_ref)
            access_entries = getattr(dataset, "access_entries", None)
            if access_entries is None and isinstance(dataset, dict):
                access_entries = dataset.get("access_entries")
            for entry in access_entries or []:
                entity = (
                    getattr(entry, "entity_id", None)
                    or getattr(entry, "entity_type", None)
                    or (entry.get("entity_id") if isinstance(entry, dict) else None)
                )
                if entity in {"allUsers", "allAuthenticatedUsers"}:
                    ds_id = getattr(dataset, "dataset_id", None) or (
                        dataset.get("dataset_id") if isinstance(dataset, dict) else ""
                    )
                    public.append(str(ds_id))
                    break
        return Finding(
            control_id="7.1",
            title="BigQuery datasets not publicly accessible",
            section="bigquery",
            severity="CRITICAL",
            status="FAIL" if public else "PASS",
            detail=(
                f"{len(public)} BigQuery datasets exposed to allUsers/allAuthenticatedUsers"
                if public
                else "No public BigQuery datasets"
            ),
            nist_csf="PR.AC-3",
            resources=public,
        )
    except Exception as e:
        return Finding(
            control_id="7.1",
            title="BigQuery datasets not publicly accessible",
            section="bigquery",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


def check_7_2_bigquery_default_cmek(bq_client, project_id: str) -> Finding:
    """CIS 7.2 — BigQuery datasets configured with a default CMEK key."""
    try:
        offenders: list[str] = []
        datasets = list(bq_client.list_datasets(project=project_id))
        for ds_ref in datasets:
            dataset = bq_client.get_dataset(ds_ref)
            ds_id = getattr(dataset, "dataset_id", None) or (
                dataset.get("dataset_id") if isinstance(dataset, dict) else ""
            )
            enc = getattr(dataset, "default_encryption_configuration", None)
            if enc is None and isinstance(dataset, dict):
                enc = dataset.get("default_encryption_configuration")
            kms_name = getattr(enc, "kms_key_name", None) if enc else None
            if isinstance(enc, dict):
                kms_name = enc.get("kms_key_name")
            if not kms_name:
                offenders.append(str(ds_id))
        return Finding(
            control_id="7.2",
            title="BigQuery datasets use default CMEK",
            section="bigquery",
            severity="MEDIUM",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} BigQuery datasets without a default CMEK key"
                if offenders
                else "All BigQuery datasets have a default CMEK key"
            ),
            nist_csf="PR.DS-1",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="7.2",
            title="BigQuery datasets use default CMEK",
            section="bigquery",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _status_symbol(status: str) -> str:
    return {
        "PASS": "\033[92m✓\033[0m",
        "FAIL": "\033[91m✗\033[0m",
        "ERROR": "\033[90m?\033[0m",
    }.get(status, "?")


def _try_import(module_path: str, attr: str | None = None):
    """Best-effort import: returns the symbol or None when the SDK is missing."""
    try:
        mod = importlib.import_module(module_path)
    except ImportError:
        return None
    return getattr(mod, attr) if attr else mod


def run_assessment(project_id: str, section: str | None = None) -> list[Finding]:
    """Run all checks. Imports GCP SDKs at call time to fail gracefully."""
    try:
        from google.cloud import iam_admin_v1, resourcemanager_v3
        from google.cloud.compute_v1.services.firewalls import FirewallsClient
        from google.cloud.compute_v1.services.instances import InstancesClient
        from google.cloud.compute_v1.services.networks import NetworksClient
        from google.cloud.compute_v1.services.subnetworks import SubnetworksClient

        storage = importlib.import_module("google.cloud.storage")
    except ImportError:
        print(
            "ERROR: Install GCP SDKs: pip install google-cloud-iam google-cloud-storage google-cloud-resource-manager google-cloud-compute"
        )
        sys.exit(1)

    crm = resourcemanager_v3.ProjectsClient()
    iam = iam_admin_v1.IAMClient()
    gcs = storage.Client(project=project_id)
    fw = FirewallsClient()
    nw = NetworksClient()
    sn = SubnetworksClient()
    instances = InstancesClient()

    # Optional clients — when their SDK isn't installed, the corresponding
    # checks emit ERROR findings rather than blowing up the whole runner.
    OrgPolicyClient = _try_import("google.cloud.orgpolicy_v2", "OrgPolicyClient")
    KMSClient = _try_import("google.cloud.kms_v1", "KeyManagementServiceClient")
    APIKeysClient = _try_import("google.cloud.api_keys_v2", "ApiKeysClient")
    EssentialContactsClient = _try_import(
        "google.cloud.essential_contacts_v1", "EssentialContactsServiceClient"
    )
    LoggingClient = _try_import("google.cloud.logging_v2", "ConfigServiceV2Client")
    LogMetricsClient = _try_import("google.cloud.logging_v2", "MetricsServiceV2Client")
    AssetClient = _try_import("google.cloud.asset_v1", "AssetServiceClient")
    DNSPoliciesClient = _try_import("google.cloud.dns_v1.services.policies", "PoliciesClient")
    SQLClient = _try_import("googleapiclient.discovery", "build")
    BQClient = _try_import("google.cloud.bigquery", "Client")

    orgpol = OrgPolicyClient() if OrgPolicyClient else None
    kms = KMSClient() if KMSClient else None
    apikeys = APIKeysClient() if APIKeysClient else None
    contacts = EssentialContactsClient() if EssentialContactsClient else None
    log_cfg = LoggingClient() if LoggingClient else None
    log_metrics = LogMetricsClient() if LogMetricsClient else None
    asset = AssetClient() if AssetClient else None
    dns = DNSPoliciesClient() if DNSPoliciesClient else None
    sql = SQLClient("sqladmin", "v1beta4").instances() if SQLClient else None
    bq = BQClient(project=project_id) if BQClient else None

    # The logging-config client lists sinks; the metrics client lists log metrics.
    # The 2.4 / 2.7 / 2.10 helper expects a single object exposing both
    # `list_log_metrics` (metrics client) — we use the metrics client there.
    findings: list[Finding] = []

    checks = {
        "iam": [
            lambda: check_1_1_no_gmail_accounts(crm, project_id),
            lambda: check_1_3_no_sa_keys(iam, project_id),
            lambda: check_1_4_sa_key_rotation(iam, project_id),
            lambda: check_1_5_separation_sa_admin(crm, project_id),
            lambda: check_1_6_disable_sa_key_creation(orgpol, project_id),
            lambda: check_1_11_separation_kms(crm, project_id),
            lambda: check_1_12_kms_keys_not_public(kms, project_id),
            lambda: check_1_13_api_keys_restricted(apikeys, project_id),
            lambda: check_1_14_essential_contacts(contacts, project_id),
        ],
        "storage": [
            lambda: check_2_1_uniform_access(gcs, project_id),
            lambda: check_2_3_no_public_buckets(gcs, project_id),
        ],
        "logging": [
            lambda: check_3_1_audit_logging_all_services(crm, project_id),
            lambda: check_2_2_log_sink_configured(log_cfg, project_id),
            lambda: check_2_4_log_metric_project_ownership(log_metrics, project_id),
            lambda: check_2_7_log_metric_vpc_changes(log_metrics, project_id),
            lambda: check_2_10_log_metric_audit_config(log_metrics, project_id),
            lambda: check_2_13_cloud_asset_inventory(asset, project_id),
        ],
        "networking": [
            lambda: check_4_1_default_network_deleted(nw, project_id),
            lambda: check_4_2_no_unrestricted_ssh_rdp(fw, project_id),
            lambda: check_4_3_vpc_flow_logs(sn, project_id),
            lambda: check_4_4_private_google_access(sn, project_id),
            lambda: check_3_10_dns_logging(dns, project_id),
        ],
        "compute": [
            lambda: check_4_5_block_project_wide_ssh(instances, project_id),
            lambda: check_4_6_confidential_vm(instances, project_id),
            lambda: check_4_7_shielded_vm(instances, project_id),
            lambda: check_4_8_disk_cmek(instances, project_id),
        ],
        "cloudsql": [
            lambda: check_6_1_cloudsql_no_public_ip(sql, project_id),
            lambda: check_6_4_cloudsql_require_ssl(sql, project_id),
        ],
        "bigquery": [
            lambda: check_7_1_bigquery_not_public(bq, project_id),
            lambda: check_7_2_bigquery_default_cmek(bq, project_id),
        ],
    }

    sections_to_run = {section: checks[section]} if section and section in checks else checks
    for check_fns in sections_to_run.values():
        for fn in check_fns:
            findings.append(fn())

    return findings


def print_summary(findings: list[Finding]) -> None:
    passed = sum(1 for f in findings if f.status == "PASS")
    total = len(findings)

    print(f"\n{'=' * 60}")
    print("  CIS GCP Foundations v3.0 — Assessment Results")
    print(f"{'=' * 60}\n")

    current_section = ""
    for f in findings:
        if f.section != current_section:
            current_section = f.section
            print(f"\n  [{current_section.upper()}]")
        print(f"  {_status_symbol(f.status)} {f.control_id}  {f.title}")
        if f.status != "PASS":
            print(f"         {f.detail}")
            for r in f.resources[:5]:
                print(f"         - {r}")

    pct = (passed / total * 100) if total else 0
    print(f"\n{'─' * 60}")
    print(f"  Score: {passed}/{total} passed ({pct:.0f}%)")
    print(f"{'─' * 60}\n")


def main():
    parser = argparse.ArgumentParser(description="CIS GCP Foundations Benchmark v3.0 Assessment")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument(
        "--section",
        choices=["iam", "storage", "logging", "networking", "compute", "cloudsql", "bigquery"],
        help="Run specific section",
    )
    parser.add_argument("--output", choices=["console", "json"], default="console")
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args()

    findings = run_assessment(project_id=args.project, section=args.section)

    if args.output == "json":
        rendered = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=["CIS GCP Foundations v3.0", "NIST CSF 2.0"],
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        print(json.dumps(rendered, indent=2))
    else:
        print_summary(findings)

    critical_high_fails = [
        f for f in findings if f.status == "FAIL" and f.severity in ("CRITICAL", "HIGH")
    ]
    sys.exit(1 if critical_high_fails else 0)


if __name__ == "__main__":
    if "--worker" in sys.argv:
        from skills._shared.worker_harness import run_worker

        raise SystemExit(run_worker(main))
    main()
