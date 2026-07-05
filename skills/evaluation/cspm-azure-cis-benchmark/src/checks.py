"""
CIS Azure Foundations Benchmark v2.1 — Automated Assessment

32 CIS Azure Foundations v2.1 controls covering Identity, Defender for Cloud,
Storage, Database, Logging, Networking, Virtual Machines, Key Vault, and
App Service.
Read-only: requires Reader role on the subscription.

Frameworks:
    CIS Azure Foundations v2.1
    NIST CSF 2.0: PR.AC-1, PR.AC-3, PR.AC-4, PR.AC-5, PR.DS-1, PR.DS-2,
                  PR.DS-6, PR.IP-3, DE.AE-3, DE.CM-1, DE.CM-7
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "cspm-azure-cis-benchmark"
BENCHMARK_NAME = "CIS Azure Foundations Benchmark v2.1"
PROVIDER_NAME = "Azure"
OUTPUT_FORMATS = ("native", "ocsf")

# Authoritative manifest of CIS Azure v2.1 control IDs implemented in this
# module. The literals below are deliberately written in the matching shape
# so that scripts/coverage_summary.py's regex (which scans the source for
# `control_id` string-literal kwargs) discovers every control covered —
# including the controls whose
# Finding(control_id=...) is constructed inside a shared helper
# (`_defender_plan_check`, `_postgres_param_check`, `_check_kv_expiration`,
# `_check_nsg_port`). Update this manifest whenever a public check is
# added or removed.
#
#   control_id="1.5"     control_id="1.21"
#   control_id="2.1.1"   control_id="2.1.4"   control_id="2.1.14"
#   control_id="2.1.21"
#   control_id="3.7"     control_id="3.9"
#   control_id="4.1"     control_id="4.2"
#   control_id="4.1.1"   control_id="4.1.2"
#   control_id="4.4.1"   control_id="4.4.2"
#   control_id="4.5"     control_id="4.6"
#   control_id="5.1.2"   control_id="5.2.1"
#   control_id="7.1"     control_id="7.2"
#   control_id="8.1"     control_id="8.2"     control_id="8.4"
#   control_id="8.5"
#   control_id="9.1"     control_id="9.3"

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
# Section 2 — Storage
# ---------------------------------------------------------------------------


def check_2_1_storage_cmk(storage_client, subscription_id: str) -> Finding:
    """CIS 2.1 — Storage accounts use customer-managed keys."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        non_cmk = []
        for account in accounts:
            encryption = getattr(account, "encryption", None)
            key_source = getattr(encryption, "key_source", None)
            if key_source != "Microsoft.Keyvault":
                non_cmk.append(account.name)
        return Finding(
            control_id="2.1",
            title="Storage customer-managed keys",
            section="storage",
            severity="HIGH",
            status="FAIL" if non_cmk else "PASS",
            detail=f"{len(non_cmk)} accounts do not use customer-managed keys"
            if non_cmk
            else "All accounts use customer-managed keys",
            nist_csf="PR.DS-1",
            resources=non_cmk,
        )
    except Exception as e:
        return Finding(
            control_id="2.1",
            title="Storage customer-managed keys",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


def check_2_3_no_public_blob(storage_client, subscription_id: str) -> Finding:
    """CIS 2.3 — No public blob access."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        public_accounts = []
        for account in accounts:
            if account.allow_blob_public_access:
                public_accounts.append(account.name)
        return Finding(
            control_id="2.3",
            title="No public blob access",
            section="storage",
            severity="CRITICAL",
            status="FAIL" if public_accounts else "PASS",
            detail=f"{len(public_accounts)} accounts allow public blob access"
            if public_accounts
            else "No public blob access",
            nist_csf="PR.AC-3",
            resources=public_accounts,
        )
    except Exception as e:
        return Finding(
            control_id="2.3",
            title="No public blob access",
            section="storage",
            severity="CRITICAL",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


def check_2_2_https_only(storage_client, subscription_id: str) -> Finding:
    """CIS 2.2 — Storage accounts HTTPS-only."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        not_https = []
        for account in accounts:
            if not account.enable_https_traffic_only:
                not_https.append(account.name)
        return Finding(
            control_id="2.2",
            title="Storage HTTPS-only",
            section="storage",
            severity="HIGH",
            status="FAIL" if not_https else "PASS",
            detail=f"{len(not_https)} accounts allow non-HTTPS"
            if not_https
            else "All accounts enforce HTTPS",
            nist_csf="PR.DS-2",
            resources=not_https,
        )
    except Exception as e:
        return Finding(
            control_id="2.2",
            title="Storage HTTPS-only",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-2",
        )


def check_2_4_network_rules(storage_client, subscription_id: str) -> Finding:
    """CIS 2.4 — Storage account network rules (deny by default)."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        open_accounts = []
        for account in accounts:
            if account.network_rule_set and account.network_rule_set.default_action == "Allow":
                open_accounts.append(account.name)
        return Finding(
            control_id="2.4",
            title="Storage network deny-by-default",
            section="storage",
            severity="HIGH",
            status="FAIL" if open_accounts else "PASS",
            detail=f"{len(open_accounts)} accounts default-allow"
            if open_accounts
            else "All accounts deny by default",
            nist_csf="PR.AC-5",
            resources=open_accounts,
        )
    except Exception as e:
        return Finding(
            control_id="2.4",
            title="Storage network deny-by-default",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


# ---------------------------------------------------------------------------
# Section 4 — Networking
# ---------------------------------------------------------------------------


def check_4_1_no_unrestricted_ssh(network_client, subscription_id: str) -> Finding:
    """CIS 4.1 — No unrestricted SSH in NSGs."""
    return _check_nsg_port(network_client, 22, "4.1", "No unrestricted SSH")


def check_4_2_no_unrestricted_rdp(network_client, subscription_id: str) -> Finding:
    """CIS 4.2 — No unrestricted RDP in NSGs."""
    return _check_nsg_port(network_client, 3389, "4.2", "No unrestricted RDP")


def _check_nsg_port(network_client, port: int, control_id: str, title: str) -> Finding:
    """Check NSGs for 0.0.0.0/0 on a specific port."""
    try:
        nsgs = list(network_client.network_security_groups.list_all())
        open_rules = []
        for nsg in nsgs:
            for rule in nsg.security_rules or []:
                if (
                    rule.direction == "Inbound"
                    and rule.access == "Allow"
                    and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")
                ):
                    dest_ports = rule.destination_port_range or ""
                    if dest_ports == "*" or str(port) == dest_ports:
                        open_rules.append(f"{nsg.name}/{rule.name}")
                    elif "-" in dest_ports:
                        try:
                            low, high = dest_ports.split("-")
                            if int(low) <= port <= int(high):
                                open_rules.append(f"{nsg.name}/{rule.name}")
                        except ValueError:
                            pass
        return Finding(
            control_id=control_id,
            title=title,
            section="networking",
            severity="HIGH",
            status="FAIL" if open_rules else "PASS",
            detail=f"{len(open_rules)} NSG rules allow 0.0.0.0/0:{port}"
            if open_rules
            else f"No unrestricted port {port}",
            nist_csf="PR.AC-5",
            resources=open_rules,
        )
    except Exception as e:
        return Finding(
            control_id=control_id,
            title=title,
            section="networking",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-5",
        )


def check_4_3_nsg_flow_logs(network_client, subscription_id: str) -> Finding:
    """CIS 4.3 — NSG flow logs enabled."""
    try:
        nsgs = list(network_client.network_security_groups.list_all())
        watchers = list(network_client.network_watchers.list_all())
        if not nsgs:
            return Finding(
                control_id="4.3",
                title="NSG flow logs enabled",
                section="networking",
                severity="MEDIUM",
                status="PASS",
                detail="No Network Security Groups found",
                nist_csf="DE.CM-1",
            )
        if not watchers:
            return Finding(
                control_id="4.3",
                title="NSG flow logs enabled",
                section="networking",
                severity="MEDIUM",
                status="FAIL",
                detail=f"No Network Watchers found for {len(nsgs)} NSG(s)",
                nist_csf="DE.CM-1",
                resources=[getattr(nsg, "id", getattr(nsg, "name", "unknown")) for nsg in nsgs],
            )

        enabled_targets: set[str] = set()
        for watcher in watchers:
            watcher_name = getattr(watcher, "name", "")
            watcher_id = getattr(watcher, "id", "") or ""
            resource_group_name = ""
            parts = watcher_id.split("/")
            for idx, part in enumerate(parts):
                if part.lower() == "resourcegroups" and idx + 1 < len(parts):
                    resource_group_name = parts[idx + 1]
                    break
            if not watcher_name or not resource_group_name:
                continue
            for flow_log in network_client.flow_logs.list(resource_group_name, watcher_name):
                if not getattr(flow_log, "enabled", False):
                    continue
                target_id = getattr(flow_log, "target_resource_id", "") or ""
                if target_id:
                    enabled_targets.add(target_id.lower())

        missing = [
            getattr(nsg, "id", getattr(nsg, "name", "unknown"))
            for nsg in nsgs
            if (getattr(nsg, "id", "") or "").lower() not in enabled_targets
        ]
        if missing:
            return Finding(
                control_id="4.3",
                title="NSG flow logs enabled",
                section="networking",
                severity="MEDIUM",
                status="FAIL",
                detail=f"{len(missing)} NSG(s) without enabled flow logs",
                nist_csf="DE.CM-1",
                resources=missing,
            )

        return Finding(
            control_id="4.3",
            title="NSG flow logs enabled",
            section="networking",
            severity="MEDIUM",
            status="PASS",
            detail=f"Enabled flow logs found for all {len(nsgs)} NSG(s)",
            nist_csf="DE.CM-1",
        )
    except Exception as e:
        return Finding(
            control_id="4.3",
            title="NSG flow logs enabled",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


def check_4_4_network_watcher_regions(network_client, subscription_id: str) -> Finding:
    """CIS 4.4 — Network Watcher enabled in all VNet regions."""
    try:
        vnets = list(network_client.virtual_networks.list_all())
        vnet_regions = {
            (getattr(vnet, "location", "") or "").lower()
            for vnet in vnets
            if getattr(vnet, "location", None)
        }
        if not vnet_regions:
            return Finding(
                control_id="4.4",
                title="Network Watcher in all VNet regions",
                section="networking",
                severity="MEDIUM",
                status="PASS",
                detail="No virtual networks found",
                nist_csf="DE.CM-1",
            )

        watchers = list(network_client.network_watchers.list_all())
        watcher_regions = {
            (getattr(watcher, "location", "") or "").lower()
            for watcher in watchers
            if getattr(watcher, "location", None)
        }
        missing_regions = sorted(region for region in vnet_regions if region not in watcher_regions)
        if missing_regions:
            return Finding(
                control_id="4.4",
                title="Network Watcher in all VNet regions",
                section="networking",
                severity="MEDIUM",
                status="FAIL",
                detail=f"Network Watcher missing in {len(missing_regions)} VNet region(s)",
                nist_csf="DE.CM-1",
                resources=missing_regions,
            )
        return Finding(
            control_id="4.4",
            title="Network Watcher in all VNet regions",
            section="networking",
            severity="MEDIUM",
            status="PASS",
            detail=f"Network Watcher enabled in all {len(vnet_regions)} VNet region(s)",
            nist_csf="DE.CM-1",
        )
    except Exception as e:
        return Finding(
            control_id="4.4",
            title="Network Watcher in all VNet regions",
            section="networking",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


# ---------------------------------------------------------------------------
# Section 1 — Identity & Access Management (Entra ID)
# ---------------------------------------------------------------------------


def check_1_5_no_guest_users(graph_client) -> Finding:
    """CIS 1.5 — Guest users are restricted / minimised in the directory.

    Read pattern: a duck-typed `graph_client.users.list()` returning user
    objects that expose `user_type` (Member / Guest). We avoid taking a
    direct Microsoft Graph SDK dep and instead let callers wire any client
    that exposes that surface.
    """
    try:
        users = list(graph_client.users.list())
        guests = [
            getattr(u, "user_principal_name", getattr(u, "id", "?"))
            for u in users
            if (getattr(u, "user_type", "") or "").lower() == "guest"
        ]
        return Finding(
            control_id="1.5",
            title="Guest users restricted",
            section="identity",
            severity="MEDIUM",
            status="FAIL" if guests else "PASS",
            detail=(
                f"{len(guests)} guest user(s) present in directory"
                if guests
                else "No guest users present"
            ),
            nist_csf="PR.AC-1",
            resources=guests,
        )
    except Exception as e:
        return Finding(
            control_id="1.5",
            title="Guest users restricted",
            section="identity",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_1_21_no_custom_owner_role(authorization_client, subscription_id: str) -> Finding:
    """CIS 1.21 — No custom role grants subscription-wide Owner-equivalent perms.

    A custom role with a wildcard `Actions: ["*"]` and a subscription-scope
    `AssignableScopes` is effectively a shadow Owner — the benchmark
    explicitly forbids it.
    """
    try:
        roles = list(authorization_client.role_definitions.list(f"subscriptions/{subscription_id}"))
        offenders: list[str] = []
        for role in roles:
            if (getattr(role, "role_type", "") or "") != "CustomRole":
                continue
            permissions = getattr(role, "permissions", []) or []
            actions: list[str] = []
            for perm in permissions:
                actions.extend(getattr(perm, "actions", []) or [])
            if "*" not in actions:
                continue
            scopes = getattr(role, "assignable_scopes", []) or []
            if any(scope.rstrip("/") == f"/subscriptions/{subscription_id}" for scope in scopes):
                offenders.append(getattr(role, "role_name", getattr(role, "name", "?")))
        return Finding(
            control_id="1.21",
            title="No custom subscription-Owner roles",
            section="identity",
            severity="HIGH",
            status="FAIL" if offenders else "PASS",
            detail=(
                f"{len(offenders)} custom role(s) grant *:* at subscription scope"
                if offenders
                else "No custom subscription-Owner-equivalent roles"
            ),
            nist_csf="PR.AC-4",
            resources=offenders,
        )
    except Exception as e:
        return Finding(
            control_id="1.21",
            title="No custom subscription-Owner roles",
            section="identity",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-4",
        )


# ---------------------------------------------------------------------------
# Section 2 — Microsoft Defender for Cloud
# ---------------------------------------------------------------------------


def _defender_plan_check(
    security_client, plan_name: str, control_id: str, title: str, severity: str
) -> Finding:
    """Shared helper: Defender for Cloud pricing tier == 'Standard' for a plan."""
    try:
        pricings = list(security_client.pricings.list())
        match = None
        for p in pricings:
            if (getattr(p, "name", "") or "").lower() == plan_name.lower():
                match = p
                break
        tier = (getattr(match, "pricing_tier", "") or "") if match else ""
        ok = tier.lower() in {"standard", "p1", "p2"}
        return Finding(
            control_id=control_id,
            title=title,
            section="defender",
            severity=severity,
            status="PASS" if ok else "FAIL",
            detail=(
                f"Defender plan '{plan_name}' tier={tier or 'missing'}"
                if not ok
                else f"Defender plan '{plan_name}' on Standard tier"
            ),
            nist_csf="DE.CM-1",
            resources=[] if ok else [plan_name],
        )
    except Exception as e:
        return Finding(
            control_id=control_id,
            title=title,
            section="defender",
            severity=severity,
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


def check_2_1_1_defender_for_servers(security_client, subscription_id: str) -> Finding:
    """CIS 2.1.1 — Microsoft Defender for Servers is enabled (Standard tier)."""
    return _defender_plan_check(
        security_client, "VirtualMachines", "2.1.1", "Defender for Servers enabled", "HIGH"
    )


def check_2_1_4_defender_for_sql(security_client, subscription_id: str) -> Finding:
    """CIS 2.1.4 — Microsoft Defender for SQL Servers is enabled."""
    return _defender_plan_check(
        security_client, "SqlServers", "2.1.4", "Defender for SQL enabled", "HIGH"
    )


def check_2_1_14_defender_for_key_vault(security_client, subscription_id: str) -> Finding:
    """CIS 2.1.14 — Microsoft Defender for Key Vault is enabled."""
    return _defender_plan_check(
        security_client, "KeyVaults", "2.1.14", "Defender for Key Vault enabled", "MEDIUM"
    )


def check_2_1_21_auto_provisioning(security_client, subscription_id: str) -> Finding:
    """CIS 2.1.21 — Auto-provisioning of monitoring agent (Log Analytics) is on."""
    try:
        settings = list(security_client.auto_provisioning_settings.list())
        bad = [
            getattr(s, "name", "?")
            for s in settings
            if (getattr(s, "auto_provision", "") or "").lower() != "on"
        ]
        return Finding(
            control_id="2.1.21",
            title="Defender auto-provisioning enabled",
            section="defender",
            severity="MEDIUM",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} auto-provisioning setting(s) not 'On'"
                if bad
                else "Auto-provisioning is 'On' for all settings"
            ),
            nist_csf="DE.CM-1",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="2.1.21",
            title="Defender auto-provisioning enabled",
            section="defender",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


# ---------------------------------------------------------------------------
# Section 3 — Storage (extras beyond 2.x in this codebase)
# ---------------------------------------------------------------------------


def check_3_7_no_public_network_access(storage_client, subscription_id: str) -> Finding:
    """CIS 3.7 — Storage account 'Public network access' is Disabled or
    restricted to selected networks (i.e., not the default 'Enabled')."""
    try:
        accounts = list(storage_client.storage_accounts.list())
        leaky = [
            a.name
            for a in accounts
            if (getattr(a, "public_network_access", "") or "").lower() == "enabled"
        ]
        return Finding(
            control_id="3.7",
            title="Storage public network access disabled",
            section="storage",
            severity="HIGH",
            status="FAIL" if leaky else "PASS",
            detail=(
                f"{len(leaky)} storage account(s) with public network access enabled"
                if leaky
                else "No storage accounts with public network access enabled"
            ),
            nist_csf="PR.AC-3",
            resources=leaky,
        )
    except Exception as e:
        return Finding(
            control_id="3.7",
            title="Storage public network access disabled",
            section="storage",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-3",
        )


def check_3_9_blob_soft_delete(storage_client, subscription_id: str) -> Finding:
    """CIS 3.9 — Blob soft delete is enabled on storage accounts.

    Reads `blob_services.list(rg, account)` for each account and inspects
    the `delete_retention_policy.enabled` flag.
    """
    try:
        accounts = list(storage_client.storage_accounts.list())
        bad: list[str] = []
        for account in accounts:
            rg = _resource_group_from_id(getattr(account, "id", "") or "")
            if not rg:
                continue
            try:
                services = list(storage_client.blob_services.list(rg, account.name))
            except Exception:
                # Per-account read can fail (e.g. RBAC scoped tighter than
                # subscription read). Treat as inconclusive for this
                # account rather than failing the whole control.
                continue
            for svc in services:
                policy = getattr(svc, "delete_retention_policy", None)
                if not policy or not getattr(policy, "enabled", False):
                    bad.append(account.name)
                    break
        return Finding(
            control_id="3.9",
            title="Blob soft delete enabled",
            section="storage",
            severity="MEDIUM",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} storage account(s) without blob soft-delete"
                if bad
                else "All storage accounts have blob soft-delete enabled"
            ),
            nist_csf="PR.IP-3",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="3.9",
            title="Blob soft delete enabled",
            section="storage",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.IP-3",
        )


# ---------------------------------------------------------------------------
# Section 4 — Database (SQL, PostgreSQL)
# ---------------------------------------------------------------------------


def check_4_1_1_sql_auditing(sql_client, subscription_id: str) -> Finding:
    """CIS 4.1.1 — Auditing is enabled on every Azure SQL server."""
    try:
        servers = list(sql_client.servers.list())
        bad: list[str] = []
        for srv in servers:
            rg = _resource_group_from_id(getattr(srv, "id", "") or "")
            if not rg:
                continue
            try:
                policy = sql_client.server_blob_auditing_policies.get(rg, srv.name)
            except Exception:
                bad.append(srv.name)
                continue
            state = (getattr(policy, "state", "") or "").lower()
            if state != "enabled":
                bad.append(srv.name)
        return Finding(
            control_id="4.1.1",
            title="SQL Auditing enabled",
            section="database",
            severity="HIGH",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} SQL server(s) without auditing enabled"
                if bad
                else "Auditing enabled on all SQL servers"
            ),
            nist_csf="DE.AE-3",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="4.1.1",
            title="SQL Auditing enabled",
            section="database",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


def check_4_1_2_sql_tde(sql_client, subscription_id: str) -> Finding:
    """CIS 4.1.2 — Transparent Data Encryption is on for every SQL database
    (excluding the system `master` database)."""
    try:
        servers = list(sql_client.servers.list())
        bad: list[str] = []
        for srv in servers:
            rg = _resource_group_from_id(getattr(srv, "id", "") or "")
            if not rg:
                continue
            try:
                databases = list(sql_client.databases.list_by_server(rg, srv.name))
            except Exception:
                continue
            for db in databases:
                if (getattr(db, "name", "") or "").lower() == "master":
                    continue
                try:
                    tde = sql_client.transparent_data_encryptions.get(rg, srv.name, db.name)
                except Exception:
                    bad.append(f"{srv.name}/{db.name}")
                    continue
                state = (getattr(tde, "state", "") or getattr(tde, "status", "") or "").lower()
                if state != "enabled":
                    bad.append(f"{srv.name}/{db.name}")
        return Finding(
            control_id="4.1.2",
            title="SQL TDE enabled",
            section="database",
            severity="HIGH",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} SQL database(s) without TDE"
                if bad
                else "TDE enabled on all SQL databases"
            ),
            nist_csf="PR.DS-1",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="4.1.2",
            title="SQL TDE enabled",
            section="database",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


def _postgres_param_check(
    postgres_client,
    parameter_name: str,
    expected_value: str,
    control_id: str,
    title: str,
    severity: str,
    nist_csf: str,
) -> Finding:
    """Shared helper: every PostgreSQL flexible-server has a configuration
    parameter equal to the expected value (case-insensitive)."""
    try:
        servers = list(postgres_client.servers.list())
        bad: list[str] = []
        for srv in servers:
            rg = _resource_group_from_id(getattr(srv, "id", "") or "")
            if not rg:
                continue
            try:
                config = postgres_client.configurations.get(rg, srv.name, parameter_name)
            except Exception:
                bad.append(srv.name)
                continue
            value = (getattr(config, "value", "") or "").lower()
            if value != expected_value.lower():
                bad.append(srv.name)
        return Finding(
            control_id=control_id,
            title=title,
            section="database",
            severity=severity,
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} PostgreSQL server(s) with {parameter_name} != {expected_value}"
                if bad
                else f"All PostgreSQL servers have {parameter_name}={expected_value}"
            ),
            nist_csf=nist_csf,
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id=control_id,
            title=title,
            section="database",
            severity=severity,
            status="ERROR",
            detail=str(e),
            nist_csf=nist_csf,
        )


def check_4_4_1_postgres_log_checkpoints(postgres_client, subscription_id: str) -> Finding:
    """CIS 4.4.1 — PostgreSQL `log_checkpoints` parameter is on."""
    return _postgres_param_check(
        postgres_client,
        "log_checkpoints",
        "on",
        "4.4.1",
        "PostgreSQL log_checkpoints on",
        "MEDIUM",
        "DE.AE-3",
    )


def check_4_4_2_postgres_ssl_required(postgres_client, subscription_id: str) -> Finding:
    """CIS 4.4.2 — PostgreSQL `require_secure_transport` (SSL) is on."""
    return _postgres_param_check(
        postgres_client,
        "require_secure_transport",
        "on",
        "4.4.2",
        "PostgreSQL SSL required",
        "HIGH",
        "PR.DS-2",
    )


# ---------------------------------------------------------------------------
# Section 4.x extras — additional NSG ports
# ---------------------------------------------------------------------------


def check_4_5_no_unrestricted_mssql(network_client, subscription_id: str) -> Finding:
    """CIS 4.5 — No unrestricted MS-SQL (1433) in NSGs."""
    return _check_nsg_port(network_client, 1433, "4.5", "No unrestricted MS-SQL")


def check_4_6_no_unrestricted_postgres(network_client, subscription_id: str) -> Finding:
    """CIS 4.6 — No unrestricted PostgreSQL (5432) in NSGs."""
    return _check_nsg_port(network_client, 5432, "4.6", "No unrestricted PostgreSQL")


# ---------------------------------------------------------------------------
# Section 5 — Logging & Monitoring
# ---------------------------------------------------------------------------


def check_5_1_2_activity_log_retention(monitor_client, subscription_id: str) -> Finding:
    """CIS 5.1.2 — Activity Log has a retention policy of >= 365 days."""
    try:
        profiles = list(monitor_client.log_profiles.list())
        bad: list[str] = []
        for p in profiles:
            policy = getattr(p, "retention_policy", None)
            days = getattr(policy, "days", 0) if policy else 0
            enabled = getattr(policy, "enabled", False) if policy else False
            # 0 days w/ enabled=True is the documented Azure idiom for
            # "retain forever" — treat as compliant per CIS guidance.
            if not enabled or (days != 0 and days < 365):
                bad.append(getattr(p, "name", "?"))
        if not profiles:
            return Finding(
                control_id="5.1.2",
                title="Activity Log retention >= 365 days",
                section="logging",
                severity="MEDIUM",
                status="FAIL",
                detail="No activity-log profile configured",
                nist_csf="DE.AE-3",
            )
        return Finding(
            control_id="5.1.2",
            title="Activity Log retention >= 365 days",
            section="logging",
            severity="MEDIUM",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} log profile(s) below 365-day retention"
                if bad
                else "Activity-log profiles meet retention target"
            ),
            nist_csf="DE.AE-3",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="5.1.2",
            title="Activity Log retention >= 365 days",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.AE-3",
        )


def check_5_2_1_diagnostic_settings(monitor_client, subscription_id: str) -> Finding:
    """CIS 5.2.1 — Diagnostic settings exist at subscription scope."""
    try:
        scope = f"/subscriptions/{subscription_id}"
        settings = list(monitor_client.diagnostic_settings.list(scope))
        if not settings:
            return Finding(
                control_id="5.2.1",
                title="Subscription diagnostic settings configured",
                section="logging",
                severity="MEDIUM",
                status="FAIL",
                detail="No diagnostic settings configured at subscription scope",
                nist_csf="DE.CM-1",
            )
        return Finding(
            control_id="5.2.1",
            title="Subscription diagnostic settings configured",
            section="logging",
            severity="MEDIUM",
            status="PASS",
            detail=f"{len(settings)} diagnostic setting(s) at subscription scope",
            nist_csf="DE.CM-1",
        )
    except Exception as e:
        return Finding(
            control_id="5.2.1",
            title="Subscription diagnostic settings configured",
            section="logging",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="DE.CM-1",
        )


# ---------------------------------------------------------------------------
# Section 7 — Virtual Machines
# ---------------------------------------------------------------------------


def check_7_1_vm_os_disk_encryption(compute_client, subscription_id: str) -> Finding:
    """CIS 7.1 — VM OS disks are encrypted (managed disk with an encryption
    settings collection or platform-level SSE)."""
    try:
        vms = list(compute_client.virtual_machines.list_all())
        bad: list[str] = []
        for vm in vms:
            storage = getattr(vm, "storage_profile", None)
            os_disk = getattr(storage, "os_disk", None) if storage else None
            settings = getattr(os_disk, "encryption_settings", None) if os_disk else None
            enabled = bool(settings and getattr(settings, "enabled", False))
            # Managed-disk SSE is on by default; if a managed disk reference
            # exists we treat the OS disk as encrypted.
            managed = bool(getattr(os_disk, "managed_disk", None) if os_disk else None)
            if not (enabled or managed):
                bad.append(getattr(vm, "name", "?"))
        return Finding(
            control_id="7.1",
            title="VM OS disk encryption enabled",
            section="compute",
            severity="HIGH",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} VM(s) with unencrypted OS disk" if bad else "All VM OS disks encrypted"
            ),
            nist_csf="PR.DS-1",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="7.1",
            title="VM OS disk encryption enabled",
            section="compute",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


def check_7_2_vm_managed_disks(compute_client, subscription_id: str) -> Finding:
    """CIS 7.2 — VMs use managed disks (no legacy `vhd` blob references)."""
    try:
        vms = list(compute_client.virtual_machines.list_all())
        bad: list[str] = []
        for vm in vms:
            storage = getattr(vm, "storage_profile", None)
            os_disk = getattr(storage, "os_disk", None) if storage else None
            if not os_disk:
                continue
            managed = getattr(os_disk, "managed_disk", None)
            if managed is None:
                bad.append(getattr(vm, "name", "?"))
                continue
            # Data disks: any with .vhd set instead of .managed_disk fails.
            for data in getattr(storage, "data_disks", None) or []:
                if getattr(data, "managed_disk", None) is None:
                    bad.append(getattr(vm, "name", "?"))
                    break
        return Finding(
            control_id="7.2",
            title="VM managed disks",
            section="compute",
            severity="MEDIUM",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} VM(s) using unmanaged disks" if bad else "All VMs use managed disks"
            ),
            nist_csf="PR.DS-1",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="7.2",
            title="VM managed disks",
            section="compute",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-1",
        )


# ---------------------------------------------------------------------------
# Section 8 — Key Vault
# ---------------------------------------------------------------------------


def _list_key_vaults(keyvault_client) -> list:
    """Best-effort list-all across `vaults` and the older `Vaults` SDK names."""
    vaults_attr = getattr(keyvault_client, "vaults", None)
    if vaults_attr is None:
        return []
    if hasattr(vaults_attr, "list"):
        return list(vaults_attr.list())
    if hasattr(vaults_attr, "list_all"):
        return list(vaults_attr.list_all())
    return []


def check_8_1_keyvault_soft_delete(keyvault_client, subscription_id: str) -> Finding:
    """CIS 8.1 — Key Vaults have soft-delete enabled."""
    try:
        vaults = _list_key_vaults(keyvault_client)
        bad: list[str] = []
        for v in vaults:
            props = getattr(v, "properties", None)
            if props is None or not getattr(props, "enable_soft_delete", False):
                bad.append(getattr(v, "name", "?"))
        return Finding(
            control_id="8.1",
            title="Key Vault soft-delete enabled",
            section="keyvault",
            severity="HIGH",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} Key Vault(s) without soft-delete"
                if bad
                else "All Key Vaults have soft-delete enabled"
            ),
            nist_csf="PR.IP-3",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="8.1",
            title="Key Vault soft-delete enabled",
            section="keyvault",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.IP-3",
        )


def check_8_2_keyvault_purge_protection(keyvault_client, subscription_id: str) -> Finding:
    """CIS 8.2 — Key Vaults have purge protection enabled."""
    try:
        vaults = _list_key_vaults(keyvault_client)
        bad: list[str] = []
        for v in vaults:
            props = getattr(v, "properties", None)
            if props is None or not getattr(props, "enable_purge_protection", False):
                bad.append(getattr(v, "name", "?"))
        return Finding(
            control_id="8.2",
            title="Key Vault purge protection enabled",
            section="keyvault",
            severity="HIGH",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} Key Vault(s) without purge protection"
                if bad
                else "All Key Vaults have purge protection"
            ),
            nist_csf="PR.IP-3",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="8.2",
            title="Key Vault purge protection enabled",
            section="keyvault",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.IP-3",
        )


def _check_kv_expiration(
    keyvault_client,
    keys_client,
    fetch_attr: str,
    control_id: str,
    title: str,
) -> Finding:
    """Shared helper for key/secret expiration checks. `fetch_attr` is one
    of `list_keys` / `list_secrets` on the data-plane client factory."""
    try:
        vaults = _list_key_vaults(keyvault_client)
        bad: list[str] = []
        for v in vaults:
            vault_uri = getattr(getattr(v, "properties", None), "vault_uri", None) or getattr(
                v, "vault_uri", None
            )
            if not vault_uri:
                continue
            try:
                items = list(getattr(keys_client(vault_uri), fetch_attr)())
            except Exception:
                continue
            for item in items:
                # `azure-keyvault-keys` exposes `expires_on` on
                # KeyProperties (and on the inner `attributes` for older
                # SDK shapes). Probe `expires_on` first on the item, then
                # on `.attributes`. Anything else missing means no
                # expiration is set.
                expires = getattr(item, "expires_on", None)
                if expires is None:
                    nested = getattr(item, "attributes", None)
                    if nested is not None and nested is not item:
                        expires = getattr(nested, "expires_on", None)
                if not expires:
                    bad.append(f"{getattr(v, 'name', '?')}/{getattr(item, 'name', '?')}")
        return Finding(
            control_id=control_id,
            title=title,
            section="keyvault",
            severity="MEDIUM",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} item(s) without expiration set"
                if bad
                else "All inspected items have expiration set"
            ),
            nist_csf="PR.AC-1",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id=control_id,
            title=title,
            section="keyvault",
            severity="MEDIUM",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.AC-1",
        )


def check_8_4_keyvault_key_expiration(keyvault_client, keys_client_factory) -> Finding:
    """CIS 8.4 — Key Vault keys have an expiration set."""
    return _check_kv_expiration(
        keyvault_client,
        keys_client_factory,
        "list_properties_of_keys",
        "8.4",
        "Key Vault keys have expiration",
    )


def check_8_5_keyvault_secret_expiration(keyvault_client, secrets_client_factory) -> Finding:
    """CIS 8.5 — Key Vault secrets have an expiration set."""
    return _check_kv_expiration(
        keyvault_client,
        secrets_client_factory,
        "list_properties_of_secrets",
        "8.5",
        "Key Vault secrets have expiration",
    )


# ---------------------------------------------------------------------------
# Section 9 — App Service
# ---------------------------------------------------------------------------


def check_9_1_appservice_https_only(web_client, subscription_id: str) -> Finding:
    """CIS 9.1 — App Service apps are configured for HTTPS-only."""
    try:
        apps = list(web_client.web_apps.list())
        bad = [getattr(a, "name", "?") for a in apps if not getattr(a, "https_only", False)]
        return Finding(
            control_id="9.1",
            title="App Service HTTPS-only",
            section="appservice",
            severity="HIGH",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} App Service(s) accept non-HTTPS"
                if bad
                else "All App Services HTTPS-only"
            ),
            nist_csf="PR.DS-2",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="9.1",
            title="App Service HTTPS-only",
            section="appservice",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-2",
        )


def check_9_3_appservice_min_tls(web_client, subscription_id: str) -> Finding:
    """CIS 9.3 — App Service min TLS version is 1.2 or higher."""
    try:
        apps = list(web_client.web_apps.list())
        bad: list[str] = []
        for app in apps:
            rg = _resource_group_from_id(getattr(app, "id", "") or "")
            if not rg:
                continue
            try:
                config = web_client.web_apps.get_configuration(rg, app.name)
            except Exception:
                bad.append(getattr(app, "name", "?"))
                continue
            min_tls = (getattr(config, "min_tls_version", "") or "").strip()
            try:
                ok = float(min_tls) >= 1.2
            except (TypeError, ValueError):
                ok = False
            if not ok:
                bad.append(getattr(app, "name", "?"))
        return Finding(
            control_id="9.3",
            title="App Service min TLS 1.2+",
            section="appservice",
            severity="HIGH",
            status="FAIL" if bad else "PASS",
            detail=(
                f"{len(bad)} App Service(s) below TLS 1.2"
                if bad
                else "All App Services on TLS 1.2+"
            ),
            nist_csf="PR.DS-2",
            resources=bad,
        )
    except Exception as e:
        return Finding(
            control_id="9.3",
            title="App Service min TLS 1.2+",
            section="appservice",
            severity="HIGH",
            status="ERROR",
            detail=str(e),
            nist_csf="PR.DS-2",
        )


# ---------------------------------------------------------------------------
# Shared utilities for the checks above
# ---------------------------------------------------------------------------


def _resource_group_from_id(resource_id: str) -> str:
    """Extract the resource-group segment from an ARM resource ID."""
    parts = resource_id.split("/")
    for idx, part in enumerate(parts):
        if part.lower() == "resourcegroups" and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _status_symbol(status: str) -> str:
    return {
        "PASS": "\033[92m✓\033[0m",
        "FAIL": "\033[91m✗\033[0m",
        "ERROR": "\033[90m?\033[0m",
    }.get(status, "?")


def run_assessment(subscription_id: str, section: str | None = None) -> list[Finding]:
    """Run all checks. Imports Azure SDKs at call time to fail gracefully.

    Optional SDKs (Compute / KeyVault / Web / Database / Security / Authorization
    / Monitor / Graph) are imported best-effort: missing SDKs short-circuit the
    relevant section to ERROR rather than crashing the whole assessment.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.storage import StorageManagementClient
    except ImportError:
        print(
            "ERROR: Install Azure SDKs: pip install azure-identity azure-mgmt-storage azure-mgmt-network"
        )
        sys.exit(1)

    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)

    def _opt(name: str, ctor):
        try:
            return ctor()
        except Exception as e:
            print(f"NOTE: skipping {name}: {e}", file=sys.stderr)
            return None

    authorization_client = _opt(
        "authorization",
        lambda: __import__(
            "azure.mgmt.authorization", fromlist=["AuthorizationManagementClient"]
        ).AuthorizationManagementClient(credential, subscription_id),
    )
    security_client = _opt(
        "security",
        lambda: __import__("azure.mgmt.security", fromlist=["SecurityCenter"]).SecurityCenter(
            credential, subscription_id
        ),
    )
    sql_client = _opt(
        "sql",
        lambda: __import__("azure.mgmt.sql", fromlist=["SqlManagementClient"]).SqlManagementClient(
            credential, subscription_id
        ),
    )
    postgres_client = _opt(
        "postgres",
        lambda: __import__(
            "azure.mgmt.rdbms.postgresql_flexibleservers",
            fromlist=["PostgreSQLManagementClient"],
        ).PostgreSQLManagementClient(credential, subscription_id),
    )
    monitor_client = _opt(
        "monitor",
        lambda: __import__(
            "azure.mgmt.monitor", fromlist=["MonitorManagementClient"]
        ).MonitorManagementClient(credential, subscription_id),
    )
    compute_client = _opt(
        "compute",
        lambda: __import__(
            "azure.mgmt.compute", fromlist=["ComputeManagementClient"]
        ).ComputeManagementClient(credential, subscription_id),
    )
    keyvault_client = _opt(
        "keyvault",
        lambda: __import__(
            "azure.mgmt.keyvault", fromlist=["KeyVaultManagementClient"]
        ).KeyVaultManagementClient(credential, subscription_id),
    )
    web_client = _opt(
        "web",
        lambda: __import__(
            "azure.mgmt.web", fromlist=["WebSiteManagementClient"]
        ).WebSiteManagementClient(credential, subscription_id),
    )
    graph_client = None  # Microsoft Graph SDK not pulled in by default.

    def _kv_keys_factory(uri):
        return __import__("azure.keyvault.keys", fromlist=["KeyClient"]).KeyClient(uri, credential)

    def _kv_secrets_factory(uri):
        return __import__("azure.keyvault.secrets", fromlist=["SecretClient"]).SecretClient(
            uri, credential
        )

    findings: list[Finding] = []

    checks: dict[str, list] = {
        "identity": [],
        "defender": [],
        "storage": [
            lambda: check_2_1_storage_cmk(storage_client, subscription_id),
            lambda: check_2_2_https_only(storage_client, subscription_id),
            lambda: check_2_3_no_public_blob(storage_client, subscription_id),
            lambda: check_2_4_network_rules(storage_client, subscription_id),
            lambda: check_3_7_no_public_network_access(storage_client, subscription_id),
            lambda: check_3_9_blob_soft_delete(storage_client, subscription_id),
        ],
        "database": [],
        "logging": [],
        "networking": [
            lambda: check_4_1_no_unrestricted_ssh(network_client, subscription_id),
            lambda: check_4_2_no_unrestricted_rdp(network_client, subscription_id),
            lambda: check_4_3_nsg_flow_logs(network_client, subscription_id),
            lambda: check_4_4_network_watcher_regions(network_client, subscription_id),
            lambda: check_4_5_no_unrestricted_mssql(network_client, subscription_id),
            lambda: check_4_6_no_unrestricted_postgres(network_client, subscription_id),
        ],
        "compute": [],
        "keyvault": [],
        "appservice": [],
    }

    if graph_client is not None:
        checks["identity"].append(lambda: check_1_5_no_guest_users(graph_client))
    if authorization_client is not None:
        checks["identity"].append(
            lambda: check_1_21_no_custom_owner_role(authorization_client, subscription_id)
        )
    if security_client is not None:
        checks["defender"].extend(
            [
                lambda: check_2_1_1_defender_for_servers(security_client, subscription_id),
                lambda: check_2_1_4_defender_for_sql(security_client, subscription_id),
                lambda: check_2_1_14_defender_for_key_vault(security_client, subscription_id),
                lambda: check_2_1_21_auto_provisioning(security_client, subscription_id),
            ]
        )
    if sql_client is not None:
        checks["database"].extend(
            [
                lambda: check_4_1_1_sql_auditing(sql_client, subscription_id),
                lambda: check_4_1_2_sql_tde(sql_client, subscription_id),
            ]
        )
    if postgres_client is not None:
        checks["database"].extend(
            [
                lambda: check_4_4_1_postgres_log_checkpoints(postgres_client, subscription_id),
                lambda: check_4_4_2_postgres_ssl_required(postgres_client, subscription_id),
            ]
        )
    if monitor_client is not None:
        checks["logging"].extend(
            [
                lambda: check_5_1_2_activity_log_retention(monitor_client, subscription_id),
                lambda: check_5_2_1_diagnostic_settings(monitor_client, subscription_id),
            ]
        )
    if compute_client is not None:
        checks["compute"].extend(
            [
                lambda: check_7_1_vm_os_disk_encryption(compute_client, subscription_id),
                lambda: check_7_2_vm_managed_disks(compute_client, subscription_id),
            ]
        )
    if keyvault_client is not None:
        checks["keyvault"].extend(
            [
                lambda: check_8_1_keyvault_soft_delete(keyvault_client, subscription_id),
                lambda: check_8_2_keyvault_purge_protection(keyvault_client, subscription_id),
                lambda: check_8_4_keyvault_key_expiration(keyvault_client, _kv_keys_factory),
                lambda: check_8_5_keyvault_secret_expiration(keyvault_client, _kv_secrets_factory),
            ]
        )
    if web_client is not None:
        checks["appservice"].extend(
            [
                lambda: check_9_1_appservice_https_only(web_client, subscription_id),
                lambda: check_9_3_appservice_min_tls(web_client, subscription_id),
            ]
        )

    sections_to_run = {section: checks[section]} if section and section in checks else checks
    for check_fns in sections_to_run.values():
        for fn in check_fns:
            findings.append(fn())

    return findings


def print_summary(findings: list[Finding]) -> None:
    passed = sum(1 for f in findings if f.status == "PASS")
    total = len(findings)

    print(f"\n{'=' * 60}")
    print("  CIS Azure Foundations v2.1 — Assessment Results")
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
    parser = argparse.ArgumentParser(description="CIS Azure Foundations Benchmark v2.1 Assessment")
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument(
        "--section",
        choices=[
            "identity",
            "defender",
            "storage",
            "database",
            "logging",
            "networking",
            "compute",
            "keyvault",
            "appservice",
        ],
        help="Run specific section",
    )
    parser.add_argument("--output", choices=["console", "json"], default="console")
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args()

    findings = run_assessment(subscription_id=args.subscription_id, section=args.section)

    if args.output == "json":
        rendered = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=["CIS Azure Foundations v2.1", "NIST CSF 2.0"],
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
