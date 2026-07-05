"""Tests for CIS Azure Foundations Benchmark v2.1 checks.

Uses unittest.mock to simulate Azure SDK responses. Each test maps 1:1 to a
function that actually exists in src/checks.py — if a check is not implemented,
it does not appear here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_azure_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

check_2_2_https_only = _CHECKS.check_2_2_https_only
check_2_1_storage_cmk = _CHECKS.check_2_1_storage_cmk
check_2_3_no_public_blob = _CHECKS.check_2_3_no_public_blob
check_2_4_network_rules = _CHECKS.check_2_4_network_rules
check_4_1_no_unrestricted_ssh = _CHECKS.check_4_1_no_unrestricted_ssh
check_4_2_no_unrestricted_rdp = _CHECKS.check_4_2_no_unrestricted_rdp
check_4_3_nsg_flow_logs = _CHECKS.check_4_3_nsg_flow_logs
check_4_4_network_watcher_regions = _CHECKS.check_4_4_network_watcher_regions
check_1_5_no_guest_users = _CHECKS.check_1_5_no_guest_users
check_1_21_no_custom_owner_role = _CHECKS.check_1_21_no_custom_owner_role
check_2_1_1_defender_for_servers = _CHECKS.check_2_1_1_defender_for_servers
check_2_1_4_defender_for_sql = _CHECKS.check_2_1_4_defender_for_sql
check_2_1_14_defender_for_key_vault = _CHECKS.check_2_1_14_defender_for_key_vault
check_2_1_21_auto_provisioning = _CHECKS.check_2_1_21_auto_provisioning
check_3_7_no_public_network_access = _CHECKS.check_3_7_no_public_network_access
check_3_9_blob_soft_delete = _CHECKS.check_3_9_blob_soft_delete
check_4_1_1_sql_auditing = _CHECKS.check_4_1_1_sql_auditing
check_4_1_2_sql_tde = _CHECKS.check_4_1_2_sql_tde
check_4_4_1_postgres_log_checkpoints = _CHECKS.check_4_4_1_postgres_log_checkpoints
check_4_4_2_postgres_ssl_required = _CHECKS.check_4_4_2_postgres_ssl_required
check_4_5_no_unrestricted_mssql = _CHECKS.check_4_5_no_unrestricted_mssql
check_4_6_no_unrestricted_postgres = _CHECKS.check_4_6_no_unrestricted_postgres
check_5_1_2_activity_log_retention = _CHECKS.check_5_1_2_activity_log_retention
check_5_2_1_diagnostic_settings = _CHECKS.check_5_2_1_diagnostic_settings
check_7_1_vm_os_disk_encryption = _CHECKS.check_7_1_vm_os_disk_encryption
check_7_2_vm_managed_disks = _CHECKS.check_7_2_vm_managed_disks
check_8_1_keyvault_soft_delete = _CHECKS.check_8_1_keyvault_soft_delete
check_8_2_keyvault_purge_protection = _CHECKS.check_8_2_keyvault_purge_protection
check_8_4_keyvault_key_expiration = _CHECKS.check_8_4_keyvault_key_expiration
check_8_5_keyvault_secret_expiration = _CHECKS.check_8_5_keyvault_secret_expiration
check_9_1_appservice_https_only = _CHECKS.check_9_1_appservice_https_only
check_9_3_appservice_min_tls = _CHECKS.check_9_3_appservice_min_tls

SUB_ID = "00000000-0000-0000-0000-000000000000"


# ── Storage ───────────────────────────────────────────────────────


class TestStorageChecks:
    def _account(
        self,
        name,
        *,
        https=True,
        public_blob=False,
        default_action="Deny",
        key_source="Microsoft.Keyvault",
    ):
        a = MagicMock()
        a.name = name
        a.enable_https_traffic_only = https
        a.allow_blob_public_access = public_blob
        a.network_rule_set = MagicMock()
        a.network_rule_set.default_action = default_action
        a.encryption = MagicMock()
        a.encryption.key_source = key_source
        return a

    def test_2_1_storage_cmk_passes(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            self._account("ok", key_source="Microsoft.Keyvault")
        ]
        f = check_2_1_storage_cmk(client, SUB_ID)
        assert f.control_id == "2.1"
        assert f.status == "PASS"

    def test_2_1_storage_cmk_fails(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            self._account("bad", key_source="Microsoft.Storage")
        ]
        f = check_2_1_storage_cmk(client, SUB_ID)
        assert f.status == "FAIL"
        assert "bad" in f.resources

    def test_2_2_https_only_passes(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok", https=True)]
        f = check_2_2_https_only(client, SUB_ID)
        assert f.control_id == "2.2"
        assert f.status == "PASS"

    def test_2_2_https_only_fails(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("bad", https=False)]
        f = check_2_2_https_only(client, SUB_ID)
        assert f.status == "FAIL"
        assert "bad" in f.resources

    def test_2_3_public_blob_fails(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("leak", public_blob=True)]
        f = check_2_3_no_public_blob(client, SUB_ID)
        assert f.control_id == "2.3"
        assert f.status == "FAIL"
        assert "leak" in f.resources

    def test_2_3_no_public_blob_passes(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok", public_blob=False)]
        f = check_2_3_no_public_blob(client, SUB_ID)
        assert f.status == "PASS"

    def test_2_4_default_allow_fails(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("open", default_action="Allow")]
        f = check_2_4_network_rules(client, SUB_ID)
        assert f.control_id == "2.4"
        assert f.status == "FAIL"
        assert "open" in f.resources

    def test_2_4_deny_by_default_passes(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok", default_action="Deny")]
        f = check_2_4_network_rules(client, SUB_ID)
        assert f.status == "PASS"


# ── Networking ────────────────────────────────────────────────────


class TestNetworkChecks:
    def _nsg_with_rule(self, name, *, port="22", source="*", access="Allow", direction="Inbound"):
        nsg = MagicMock()
        nsg.name = name
        nsg.id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/rg-net/providers/"
            f"Microsoft.Network/networkSecurityGroups/{name}"
        )
        rule = MagicMock()
        rule.name = "rule0"
        rule.direction = direction
        rule.access = access
        rule.destination_port_range = port
        rule.source_address_prefix = source
        rule.protocol = "Tcp"
        nsg.security_rules = [rule]
        return nsg

    def test_4_1_open_ssh_fails(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            self._nsg_with_rule("open", port="22", source="*")
        ]
        f = check_4_1_no_unrestricted_ssh(client, SUB_ID)
        assert f.control_id == "4.1"
        assert f.status == "FAIL"

    def test_4_1_restricted_ssh_passes(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            self._nsg_with_rule("ok", port="22", source="10.0.0.0/8")
        ]
        f = check_4_1_no_unrestricted_ssh(client, SUB_ID)
        assert f.status == "PASS"

    def test_4_2_open_rdp_fails(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            self._nsg_with_rule("open", port="3389", source="*")
        ]
        f = check_4_2_no_unrestricted_rdp(client, SUB_ID)
        assert f.control_id == "4.2"
        assert f.status == "FAIL"

    def test_4_3_no_watchers_fails(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [self._nsg_with_rule("nsg-a")]
        client.network_watchers.list_all.return_value = []
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.control_id == "4.3"
        assert f.status == "FAIL"

    def test_4_3_with_enabled_logs_passes(self):
        client = MagicMock()
        watcher = MagicMock()
        watcher.name = "nw-eastus"
        watcher.id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/NetworkWatcherRG/providers/"
            "Microsoft.Network/networkWatchers/nw-eastus"
        )
        client.network_security_groups.list_all.return_value = [
            self._nsg_with_rule("nsg-a"),
            self._nsg_with_rule("nsg-b"),
        ]
        client.network_watchers.list_all.return_value = [watcher]
        flow_log_a = MagicMock(enabled=True)
        flow_log_a.target_resource_id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/rg-net/providers/"
            "Microsoft.Network/networkSecurityGroups/nsg-a"
        )
        flow_log_b = MagicMock(enabled=True)
        flow_log_b.target_resource_id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/rg-net/providers/"
            "Microsoft.Network/networkSecurityGroups/nsg-b"
        )
        client.flow_logs.list.return_value = [flow_log_a, flow_log_b]
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.status == "PASS"
        assert "all 2 NSG" in f.detail

    def test_4_3_missing_logs_fail(self):
        client = MagicMock()
        watcher = MagicMock()
        watcher.name = "nw-eastus"
        watcher.id = (
            f"/subscriptions/{SUB_ID}/resourceGroups/NetworkWatcherRG/providers/"
            "Microsoft.Network/networkWatchers/nw-eastus"
        )
        nsg_a = self._nsg_with_rule("nsg-a")
        nsg_b = self._nsg_with_rule("nsg-b")
        client.network_security_groups.list_all.return_value = [nsg_a, nsg_b]
        client.network_watchers.list_all.return_value = [watcher]
        flow_log = MagicMock(enabled=True)
        flow_log.target_resource_id = nsg_a.id
        client.flow_logs.list.return_value = [flow_log]
        f = check_4_3_nsg_flow_logs(client, SUB_ID)
        assert f.status == "FAIL"
        assert nsg_b.id in f.resources

    def test_4_4_network_watcher_regions_passes(self):
        client = MagicMock()
        vnet = MagicMock()
        vnet.location = "eastus"
        watcher = MagicMock()
        watcher.location = "eastus"
        client.virtual_networks.list_all.return_value = [vnet]
        client.network_watchers.list_all.return_value = [watcher]
        f = check_4_4_network_watcher_regions(client, SUB_ID)
        assert f.control_id == "4.4"
        assert f.status == "PASS"

    def test_4_4_network_watcher_regions_fails_for_missing_region(self):
        client = MagicMock()
        eastus = MagicMock()
        eastus.location = "eastus"
        westus = MagicMock()
        westus.location = "westus"
        watcher = MagicMock()
        watcher.location = "eastus"
        client.virtual_networks.list_all.return_value = [eastus, westus]
        client.network_watchers.list_all.return_value = [watcher]
        f = check_4_4_network_watcher_regions(client, SUB_ID)
        assert f.status == "FAIL"
        assert f.resources == ["westus"]


class TestFindingStructure:
    def test_finding_has_compliance(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = []
        f = check_2_3_no_public_blob(client, SUB_ID)
        assert f.nist_csf
        assert f.control_id == "2.3"


# ── Section 1 — Identity ─────────────────────────────────────────


def _arm_id(rg: str, kind: str, name: str) -> str:
    return f"/subscriptions/{SUB_ID}/resourceGroups/{rg}/providers/Microsoft.{kind}/{name}"


class TestIdentityChecks:
    def test_1_5_guest_users_fails(self):
        client = MagicMock()
        guest = MagicMock(user_principal_name="guest@example.com", user_type="Guest")
        member = MagicMock(user_principal_name="alice@example.com", user_type="Member")
        client.users.list.return_value = [guest, member]
        f = check_1_5_no_guest_users(client)
        assert f.control_id == "1.5"
        assert f.status == "FAIL"
        assert "guest@example.com" in f.resources

    def test_1_5_guest_users_passes(self):
        client = MagicMock()
        client.users.list.return_value = [
            MagicMock(user_principal_name="alice@example.com", user_type="Member")
        ]
        f = check_1_5_no_guest_users(client)
        assert f.status == "PASS"

    def _custom_owner_role(self, name="shadow-owner"):
        role = MagicMock()
        role.role_type = "CustomRole"
        role.role_name = name
        perm = MagicMock()
        perm.actions = ["*"]
        role.permissions = [perm]
        role.assignable_scopes = [f"/subscriptions/{SUB_ID}"]
        return role

    def test_1_21_custom_owner_fails(self):
        client = MagicMock()
        client.role_definitions.list.return_value = [self._custom_owner_role("shadow-owner")]
        f = check_1_21_no_custom_owner_role(client, SUB_ID)
        assert f.control_id == "1.21"
        assert f.status == "FAIL"
        assert "shadow-owner" in f.resources

    def test_1_21_builtin_passes(self):
        client = MagicMock()
        builtin = MagicMock()
        builtin.role_type = "BuiltInRole"
        builtin.role_name = "Owner"
        client.role_definitions.list.return_value = [builtin]
        f = check_1_21_no_custom_owner_role(client, SUB_ID)
        assert f.status == "PASS"


# ── Section 2 — Defender for Cloud ──────────────────────────────


def _pricing(name: str, tier: str = "Free"):
    p = MagicMock()
    p.name = name
    p.pricing_tier = tier
    return p


class TestDefenderChecks:
    def test_2_1_1_defender_for_servers_fail(self):
        client = MagicMock()
        client.pricings.list.return_value = [_pricing("VirtualMachines", "Free")]
        f = check_2_1_1_defender_for_servers(client, SUB_ID)
        assert f.control_id == "2.1.1"
        assert f.status == "FAIL"

    def test_2_1_1_defender_for_servers_pass(self):
        client = MagicMock()
        client.pricings.list.return_value = [_pricing("VirtualMachines", "Standard")]
        f = check_2_1_1_defender_for_servers(client, SUB_ID)
        assert f.status == "PASS"

    def test_2_1_4_defender_for_sql_fail(self):
        client = MagicMock()
        client.pricings.list.return_value = [_pricing("SqlServers", "Free")]
        f = check_2_1_4_defender_for_sql(client, SUB_ID)
        assert f.control_id == "2.1.4"
        assert f.status == "FAIL"

    def test_2_1_14_defender_for_key_vault_pass(self):
        client = MagicMock()
        client.pricings.list.return_value = [_pricing("KeyVaults", "Standard")]
        f = check_2_1_14_defender_for_key_vault(client, SUB_ID)
        assert f.control_id == "2.1.14"
        assert f.status == "PASS"

    def test_2_1_21_auto_provisioning_fail(self):
        client = MagicMock()
        s = MagicMock()
        s.name = "default"
        s.auto_provision = "Off"
        client.auto_provisioning_settings.list.return_value = [s]
        f = check_2_1_21_auto_provisioning(client, SUB_ID)
        assert f.control_id == "2.1.21"
        assert f.status == "FAIL"

    def test_2_1_21_auto_provisioning_pass(self):
        client = MagicMock()
        s = MagicMock()
        s.name = "default"
        s.auto_provision = "On"
        client.auto_provisioning_settings.list.return_value = [s]
        f = check_2_1_21_auto_provisioning(client, SUB_ID)
        assert f.status == "PASS"


# ── Section 3 — Storage extras ──────────────────────────────────


class TestStorageExtras:
    def _account(self, name, *, public_network="Disabled"):
        a = MagicMock()
        a.name = name
        a.id = _arm_id("rg-stor", "Storage/storageAccounts", name)
        a.public_network_access = public_network
        return a

    def test_3_7_public_network_fail(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [
            self._account("leak", public_network="Enabled")
        ]
        f = check_3_7_no_public_network_access(client, SUB_ID)
        assert f.control_id == "3.7"
        assert f.status == "FAIL"
        assert "leak" in f.resources

    def test_3_7_public_network_pass(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok", public_network="Disabled")]
        f = check_3_7_no_public_network_access(client, SUB_ID)
        assert f.status == "PASS"

    def test_3_9_soft_delete_fail(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("nodelete")]
        svc = MagicMock()
        svc.delete_retention_policy = MagicMock(enabled=False)
        client.blob_services.list.return_value = [svc]
        f = check_3_9_blob_soft_delete(client, SUB_ID)
        assert f.control_id == "3.9"
        assert f.status == "FAIL"
        assert "nodelete" in f.resources

    def test_3_9_soft_delete_pass(self):
        client = MagicMock()
        client.storage_accounts.list.return_value = [self._account("ok")]
        svc = MagicMock()
        svc.delete_retention_policy = MagicMock(enabled=True)
        client.blob_services.list.return_value = [svc]
        f = check_3_9_blob_soft_delete(client, SUB_ID)
        assert f.status == "PASS"


# ── Section 4 — Database ─────────────────────────────────────────


def _sql_server(name="srv-prod"):
    srv = MagicMock()
    srv.name = name
    srv.id = _arm_id("rg-sql", "Sql/servers", name)
    return srv


class TestDatabaseChecks:
    def test_4_1_1_auditing_fail(self):
        client = MagicMock()
        client.servers.list.return_value = [_sql_server()]
        client.server_blob_auditing_policies.get.return_value = MagicMock(state="Disabled")
        f = check_4_1_1_sql_auditing(client, SUB_ID)
        assert f.control_id == "4.1.1"
        assert f.status == "FAIL"

    def test_4_1_1_auditing_pass(self):
        client = MagicMock()
        client.servers.list.return_value = [_sql_server()]
        client.server_blob_auditing_policies.get.return_value = MagicMock(state="Enabled")
        f = check_4_1_1_sql_auditing(client, SUB_ID)
        assert f.status == "PASS"

    def test_4_1_2_tde_fail(self):
        client = MagicMock()
        client.servers.list.return_value = [_sql_server()]
        db = MagicMock()
        db.name = "appdb"
        client.databases.list_by_server.return_value = [db]
        client.transparent_data_encryptions.get.return_value = MagicMock(state="Disabled")
        f = check_4_1_2_sql_tde(client, SUB_ID)
        assert f.control_id == "4.1.2"
        assert f.status == "FAIL"
        assert "srv-prod/appdb" in f.resources

    def test_4_1_2_tde_pass_skips_master(self):
        client = MagicMock()
        client.servers.list.return_value = [_sql_server()]
        db = MagicMock()
        db.name = "master"
        client.databases.list_by_server.return_value = [db]
        f = check_4_1_2_sql_tde(client, SUB_ID)
        # No non-master DB to evaluate -> PASS by vacuity.
        assert f.status == "PASS"

    def _pg_server(self, name="pg-prod"):
        srv = MagicMock()
        srv.name = name
        srv.id = _arm_id("rg-pg", "DBforPostgreSQL/flexibleServers", name)
        return srv

    def test_4_4_1_log_checkpoints_fail(self):
        client = MagicMock()
        client.servers.list.return_value = [self._pg_server()]
        client.configurations.get.return_value = MagicMock(value="off")
        f = check_4_4_1_postgres_log_checkpoints(client, SUB_ID)
        assert f.control_id == "4.4.1"
        assert f.status == "FAIL"

    def test_4_4_1_log_checkpoints_pass(self):
        client = MagicMock()
        client.servers.list.return_value = [self._pg_server()]
        client.configurations.get.return_value = MagicMock(value="on")
        f = check_4_4_1_postgres_log_checkpoints(client, SUB_ID)
        assert f.status == "PASS"

    def test_4_4_2_ssl_required_fail(self):
        client = MagicMock()
        client.servers.list.return_value = [self._pg_server()]
        client.configurations.get.return_value = MagicMock(value="off")
        f = check_4_4_2_postgres_ssl_required(client, SUB_ID)
        assert f.control_id == "4.4.2"
        assert f.status == "FAIL"

    def test_4_4_2_ssl_required_pass(self):
        client = MagicMock()
        client.servers.list.return_value = [self._pg_server()]
        client.configurations.get.return_value = MagicMock(value="on")
        f = check_4_4_2_postgres_ssl_required(client, SUB_ID)
        assert f.status == "PASS"


# ── Section 4 — Extra NSG ports ─────────────────────────────────


def _nsg_with_rule_v2(name, *, port="22", source="*"):
    nsg = MagicMock()
    nsg.name = name
    nsg.id = _arm_id("rg-net", "Network/networkSecurityGroups", name)
    rule = MagicMock()
    rule.name = "rule0"
    rule.direction = "Inbound"
    rule.access = "Allow"
    rule.destination_port_range = port
    rule.source_address_prefix = source
    nsg.security_rules = [rule]
    return nsg


class TestNetworkExtras:
    def test_4_5_open_mssql_fails(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            _nsg_with_rule_v2("open", port="1433", source="*")
        ]
        f = check_4_5_no_unrestricted_mssql(client, SUB_ID)
        assert f.control_id == "4.5"
        assert f.status == "FAIL"

    def test_4_5_restricted_mssql_passes(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            _nsg_with_rule_v2("ok", port="1433", source="10.0.0.0/8")
        ]
        f = check_4_5_no_unrestricted_mssql(client, SUB_ID)
        assert f.status == "PASS"

    def test_4_6_open_postgres_fails(self):
        client = MagicMock()
        client.network_security_groups.list_all.return_value = [
            _nsg_with_rule_v2("open", port="5432", source="*")
        ]
        f = check_4_6_no_unrestricted_postgres(client, SUB_ID)
        assert f.control_id == "4.6"
        assert f.status == "FAIL"


# ── Section 5 — Logging ─────────────────────────────────────────


class TestLoggingChecks:
    def test_5_1_2_short_retention_fails(self):
        client = MagicMock()
        prof = MagicMock()
        prof.name = "default"
        prof.retention_policy = MagicMock(enabled=True, days=30)
        client.log_profiles.list.return_value = [prof]
        f = check_5_1_2_activity_log_retention(client, SUB_ID)
        assert f.control_id == "5.1.2"
        assert f.status == "FAIL"

    def test_5_1_2_long_retention_passes(self):
        client = MagicMock()
        prof = MagicMock()
        prof.name = "default"
        prof.retention_policy = MagicMock(enabled=True, days=365)
        client.log_profiles.list.return_value = [prof]
        f = check_5_1_2_activity_log_retention(client, SUB_ID)
        assert f.status == "PASS"

    def test_5_2_1_no_diagnostic_settings_fail(self):
        client = MagicMock()
        client.diagnostic_settings.list.return_value = []
        f = check_5_2_1_diagnostic_settings(client, SUB_ID)
        assert f.control_id == "5.2.1"
        assert f.status == "FAIL"

    def test_5_2_1_with_diagnostic_settings_pass(self):
        client = MagicMock()
        client.diagnostic_settings.list.return_value = [MagicMock(name="ds")]
        f = check_5_2_1_diagnostic_settings(client, SUB_ID)
        assert f.status == "PASS"


# ── Section 7 — Compute ─────────────────────────────────────────


class TestComputeChecks:
    def _vm(self, name, *, managed_os=True, encryption=False, data_managed=True):
        vm = MagicMock()
        vm.name = name
        os_disk = MagicMock()
        os_disk.managed_disk = MagicMock() if managed_os else None
        os_disk.encryption_settings = MagicMock(enabled=encryption)
        data_disk = MagicMock()
        data_disk.managed_disk = MagicMock() if data_managed else None
        vm.storage_profile = MagicMock(os_disk=os_disk, data_disks=[data_disk])
        return vm

    def test_7_1_unencrypted_unmanaged_fails(self):
        client = MagicMock()
        vm = self._vm("legacy", managed_os=False, encryption=False)
        client.virtual_machines.list_all.return_value = [vm]
        f = check_7_1_vm_os_disk_encryption(client, SUB_ID)
        assert f.control_id == "7.1"
        assert f.status == "FAIL"

    def test_7_1_managed_disk_passes(self):
        client = MagicMock()
        vm = self._vm("ok", managed_os=True)
        client.virtual_machines.list_all.return_value = [vm]
        f = check_7_1_vm_os_disk_encryption(client, SUB_ID)
        assert f.status == "PASS"

    def test_7_2_unmanaged_data_disk_fails(self):
        client = MagicMock()
        vm = self._vm("partial", managed_os=True, data_managed=False)
        client.virtual_machines.list_all.return_value = [vm]
        f = check_7_2_vm_managed_disks(client, SUB_ID)
        assert f.control_id == "7.2"
        assert f.status == "FAIL"

    def test_7_2_all_managed_passes(self):
        client = MagicMock()
        vm = self._vm("ok")
        client.virtual_machines.list_all.return_value = [vm]
        f = check_7_2_vm_managed_disks(client, SUB_ID)
        assert f.status == "PASS"


# ── Section 8 — Key Vault ──────────────────────────────────────


def _vault(name, *, soft_delete=True, purge=True, uri=None):
    v = MagicMock()
    v.name = name
    props = MagicMock()
    props.enable_soft_delete = soft_delete
    props.enable_purge_protection = purge
    props.vault_uri = uri or f"https://{name}.vault.azure.net/"
    v.properties = props
    return v


class TestKeyVaultChecks:
    def test_8_1_soft_delete_fail(self):
        client = MagicMock()
        client.vaults.list.return_value = [_vault("kv-bad", soft_delete=False)]
        f = check_8_1_keyvault_soft_delete(client, SUB_ID)
        assert f.control_id == "8.1"
        assert f.status == "FAIL"
        assert "kv-bad" in f.resources

    def test_8_1_soft_delete_pass(self):
        client = MagicMock()
        client.vaults.list.return_value = [_vault("kv-ok")]
        f = check_8_1_keyvault_soft_delete(client, SUB_ID)
        assert f.status == "PASS"

    def test_8_2_purge_protection_fail(self):
        client = MagicMock()
        client.vaults.list.return_value = [_vault("kv-bad", purge=False)]
        f = check_8_2_keyvault_purge_protection(client, SUB_ID)
        assert f.control_id == "8.2"
        assert f.status == "FAIL"

    def test_8_2_purge_protection_pass(self):
        client = MagicMock()
        client.vaults.list.return_value = [_vault("kv-ok")]
        f = check_8_2_keyvault_purge_protection(client, SUB_ID)
        assert f.status == "PASS"

    def _factory(self, items):
        data_client = MagicMock()
        data_client.list_properties_of_keys.return_value = items
        data_client.list_properties_of_secrets.return_value = items
        return lambda uri: data_client

    def _make_kv_item(self, name, *, expires_on=None):
        # Build a plain object (not MagicMock) so the absent `expires_on`
        # test mirrors real KeyProperties / SecretProperties without
        # MagicMock auto-attribute-generation polluting the probe.
        class _Item:
            pass

        item = _Item()
        item.name = name
        item.expires_on = expires_on
        return item

    def test_8_4_keys_no_expiration_fail(self):
        client = MagicMock()
        client.vaults.list.return_value = [_vault("kv-prod")]
        item = self._make_kv_item("rotated-key", expires_on=None)
        f = check_8_4_keyvault_key_expiration(client, self._factory([item]))
        assert f.control_id == "8.4"
        assert f.status == "FAIL"
        assert "kv-prod/rotated-key" in f.resources

    def test_8_4_keys_with_expiration_pass(self):
        client = MagicMock()
        client.vaults.list.return_value = [_vault("kv-prod")]
        item = self._make_kv_item("rotated-key", expires_on="2030-01-01T00:00:00Z")
        f = check_8_4_keyvault_key_expiration(client, self._factory([item]))
        assert f.status == "PASS"

    def test_8_5_secrets_no_expiration_fail(self):
        client = MagicMock()
        client.vaults.list.return_value = [_vault("kv-prod")]
        item = self._make_kv_item("db-password", expires_on=None)
        f = check_8_5_keyvault_secret_expiration(client, self._factory([item]))
        assert f.control_id == "8.5"
        assert f.status == "FAIL"


# ── Section 9 — App Service ─────────────────────────────────────


class TestAppServiceChecks:
    def _app(self, name="web-prod", https=True):
        app = MagicMock()
        app.name = name
        app.id = _arm_id("rg-web", "Web/sites", name)
        app.https_only = https
        return app

    def test_9_1_https_only_fail(self):
        client = MagicMock()
        client.web_apps.list.return_value = [self._app("leak", https=False)]
        f = check_9_1_appservice_https_only(client, SUB_ID)
        assert f.control_id == "9.1"
        assert f.status == "FAIL"
        assert "leak" in f.resources

    def test_9_1_https_only_pass(self):
        client = MagicMock()
        client.web_apps.list.return_value = [self._app("ok", https=True)]
        f = check_9_1_appservice_https_only(client, SUB_ID)
        assert f.status == "PASS"

    def test_9_3_min_tls_fail(self):
        client = MagicMock()
        client.web_apps.list.return_value = [self._app("legacy")]
        client.web_apps.get_configuration.return_value = MagicMock(min_tls_version="1.0")
        f = check_9_3_appservice_min_tls(client, SUB_ID)
        assert f.control_id == "9.3"
        assert f.status == "FAIL"

    def test_9_3_min_tls_pass(self):
        client = MagicMock()
        client.web_apps.list.return_value = [self._app("ok")]
        client.web_apps.get_configuration.return_value = MagicMock(min_tls_version="1.2")
        f = check_9_3_appservice_min_tls(client, SUB_ID)
        assert f.status == "PASS"
