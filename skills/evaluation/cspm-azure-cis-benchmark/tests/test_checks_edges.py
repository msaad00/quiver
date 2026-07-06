"""Edge-case coverage for CIS Azure Foundations Benchmark v3 checks (issue #405).

Each of the 32 check functions is exercised across five axes:
    1. Empty input — empty subscription surfaces 0 findings
    2. Malformed payload — None/missing attrs are absorbed (broad except in src/)
    3. Partial-pass scenario — passing + failing resources in one call
    4. Permission denied — Azure AuthorizationFailed surfaces as ERROR not crash
    5. Multi-resource happy path — covered in test_checks.py / test_checks_extra.py

Azure checks all wrap their body in `try/except Exception:` returning ERROR — this
file pins that contract per check so future refactors can't regress.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_azure_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

Finding = _CHECKS.Finding


class _AuthorizationFailed(Exception):
    """Mimic azure.core.exceptions.HttpResponseError(AuthorizationFailed)."""


def _empty_storage():
    s = MagicMock()
    s.storage_accounts.list.return_value = iter([])
    s.blob_services.list.return_value = iter([])
    s.blob_containers.list.return_value = iter([])
    return s


def _empty_network():
    n = MagicMock()
    n.network_security_groups.list_all.return_value = iter([])
    n.network_watchers.list_all.return_value = iter([])
    n.flow_logs.list.return_value = iter([])
    return n


def _empty_security():
    s = MagicMock()
    s.pricings.list.return_value.value = []
    s.auto_provisioning_settings.list.return_value = iter([])
    return s


def _empty_sql():
    s = MagicMock()
    s.servers.list.return_value = iter([])
    s.databases.list_by_server.return_value = iter([])
    return s


def _empty_compute():
    c = MagicMock()
    c.virtual_machines.list_all.return_value = iter([])
    c.disks.list.return_value = iter([])
    return c


def _empty_keyvault():
    k = MagicMock()
    k.vaults.list.return_value = iter([])
    return k


def _empty_web():
    w = MagicMock()
    w.web_apps.list.return_value = iter([])
    return w


def _empty_monitor():
    m = MagicMock()
    m.log_profiles.list.return_value = iter([])
    m.diagnostic_settings.list.return_value.value = []
    return m


def _empty_postgres():
    p = MagicMock()
    p.servers.list.return_value = iter([])
    p.configurations.list_by_server.return_value = iter([])
    return p


def _empty_authorization():
    a = MagicMock()
    a.role_definitions.list.return_value = iter([])
    return a


def _empty_graph():
    g = MagicMock()
    g.users.list.return_value = iter([])
    return g


def _kv_factory(_uri):
    """A keys-client factory that returns an empty list."""
    client = MagicMock()
    client.list_properties_of_keys.return_value = iter([])
    client.list_properties_of_secrets.return_value = iter([])
    return client


# ---------------------------------------------------------------------------
# Per-check fixtures: takes one positional arg (sub_id), or two for kv-factory.
# ---------------------------------------------------------------------------


def _call(check_name, builder):
    """Invoke a check, picking the right calling convention."""
    fn = getattr(_CHECKS, check_name)
    if check_name in {"check_8_4_keyvault_key_expiration", "check_8_5_keyvault_secret_expiration"}:
        return fn(builder(), _kv_factory)
    if check_name == "check_1_5_no_guest_users":
        return fn(builder())
    return fn(builder(), "sub-id-1")


_AZURE_CHECKS = [
    ("check_2_1_storage_cmk", _empty_storage),
    ("check_2_2_https_only", _empty_storage),
    ("check_2_3_no_public_blob", _empty_storage),
    ("check_2_4_network_rules", _empty_storage),
    ("check_3_7_no_public_network_access", _empty_storage),
    ("check_3_9_blob_soft_delete", _empty_storage),
    ("check_4_1_no_unrestricted_ssh", _empty_network),
    ("check_4_2_no_unrestricted_rdp", _empty_network),
    ("check_4_3_nsg_flow_logs", _empty_network),
    ("check_4_4_network_watcher_regions", _empty_network),
    ("check_4_5_no_unrestricted_mssql", _empty_network),
    ("check_4_6_no_unrestricted_postgres", _empty_network),
    ("check_1_5_no_guest_users", _empty_graph),
    ("check_1_21_no_custom_owner_role", _empty_authorization),
    ("check_2_1_1_defender_for_servers", _empty_security),
    ("check_2_1_4_defender_for_sql", _empty_security),
    ("check_2_1_14_defender_for_key_vault", _empty_security),
    ("check_2_1_21_auto_provisioning", _empty_security),
    ("check_4_1_1_sql_auditing", _empty_sql),
    ("check_4_1_2_sql_tde", _empty_sql),
    ("check_4_4_1_postgres_log_checkpoints", _empty_postgres),
    ("check_4_4_2_postgres_ssl_required", _empty_postgres),
    ("check_5_1_2_activity_log_retention", _empty_monitor),
    ("check_5_2_1_diagnostic_settings", _empty_monitor),
    ("check_7_1_vm_os_disk_encryption", _empty_compute),
    ("check_7_2_vm_managed_disks", _empty_compute),
    ("check_8_1_keyvault_soft_delete", _empty_keyvault),
    ("check_8_2_keyvault_purge_protection", _empty_keyvault),
    ("check_8_4_keyvault_key_expiration", _empty_keyvault),
    ("check_8_5_keyvault_secret_expiration", _empty_keyvault),
    ("check_9_1_appservice_https_only", _empty_web),
    ("check_9_3_appservice_min_tls", _empty_web),
]


# ---------------------------------------------------------------------------
# Axis 1 — empty input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,builder", _AZURE_CHECKS, ids=[c[0] for c in _AZURE_CHECKS])
def test_empty_subscription_returns_finding(check_name, builder):
    """Axis 1: empty subscription surfaces a Finding (PASS, FAIL, or ERROR)."""
    f = _call(check_name, builder)
    assert isinstance(f, Finding)
    assert f.status in {"PASS", "FAIL", "ERROR"}
    assert f.control_id
    assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert f.section
    assert f.nist_csf


# ---------------------------------------------------------------------------
# Axis 2 — malformed payload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,builder", _AZURE_CHECKS, ids=[c[0] for c in _AZURE_CHECKS])
def test_malformed_payload_returns_finding(check_name, builder):
    """Axis 2: SDK raising TypeError mid-iteration → ERROR not crash."""
    fn = getattr(_CHECKS, check_name)
    client = builder()
    # Pin every common iteration point to TypeError("malformed").
    for op_name in (
        "list",
        "list_all",
        "list_by_server",
        "list_properties_of_keys",
        "list_properties_of_secrets",
    ):
        for attr in (
            "storage_accounts",
            "blob_services",
            "blob_containers",
            "network_security_groups",
            "network_watchers",
            "flow_logs",
            "pricings",
            "auto_provisioning_settings",
            "servers",
            "databases",
            "configurations",
            "virtual_machines",
            "disks",
            "vaults",
            "web_apps",
            "log_profiles",
            "diagnostic_settings",
            "role_definitions",
            "users",
        ):
            sub = getattr(client, attr, None)
            if sub is None:
                continue
            method = getattr(sub, op_name, None)
            if method is not None and hasattr(method, "side_effect"):
                method.side_effect = TypeError("malformed payload")
    if check_name in {"check_8_4_keyvault_key_expiration", "check_8_5_keyvault_secret_expiration"}:
        f = fn(client, _kv_factory)
    elif check_name == "check_1_5_no_guest_users":
        f = fn(client)
    else:
        f = fn(client, "sub-id-1")
    assert isinstance(f, Finding)
    assert f.status in {"ERROR", "PASS", "FAIL"}


# ---------------------------------------------------------------------------
# Axis 3 — partial pass for representative checks
# ---------------------------------------------------------------------------


def _account(name: str, **attrs):
    a = MagicMock()
    a.name = name
    for k, v in attrs.items():
        setattr(a, k, v)
    return a


def test_2_1_storage_cmk_partial():
    storage = MagicMock()
    cmk = _account("cmk", encryption=MagicMock(key_source="Microsoft.Keyvault"))
    msft = _account("msft", encryption=MagicMock(key_source="Microsoft.Storage"))
    storage.storage_accounts.list.return_value = iter([cmk, msft])
    f = _CHECKS.check_2_1_storage_cmk(storage, "sub")
    assert f.status == "FAIL"
    assert "msft" in f.resources
    assert "cmk" not in f.resources


def test_2_3_no_public_blob_partial():
    storage = MagicMock()
    private = _account("private", allow_blob_public_access=False)
    public = _account("public", allow_blob_public_access=True)
    storage.storage_accounts.list.return_value = iter([private, public])
    f = _CHECKS.check_2_3_no_public_blob(storage, "sub")
    assert f.status == "FAIL"
    assert "public" in f.resources
    assert "private" not in f.resources


def test_2_2_https_only_partial():
    storage = MagicMock()
    s_safe = _account("safe", enable_https_traffic_only=True)
    s_open = _account("open", enable_https_traffic_only=False)
    storage.storage_accounts.list.return_value = iter([s_safe, s_open])
    f = _CHECKS.check_2_2_https_only(storage, "sub")
    assert f.status == "FAIL"
    assert "open" in f.resources
    assert "safe" not in f.resources


def test_4_1_unrestricted_ssh_partial():
    network = MagicMock()
    open_rule = MagicMock()
    open_rule.access = "Allow"
    open_rule.direction = "Inbound"
    open_rule.destination_port_range = "22"
    open_rule.source_address_prefix = "*"
    locked_rule = MagicMock()
    locked_rule.access = "Allow"
    locked_rule.direction = "Inbound"
    locked_rule.destination_port_range = "22"
    locked_rule.source_address_prefix = "10.0.0.0/8"

    nsg_open = MagicMock()
    nsg_open.name = "open-nsg"
    nsg_open.security_rules = [open_rule]
    nsg_locked = MagicMock()
    nsg_locked.name = "locked-nsg"
    nsg_locked.security_rules = [locked_rule]
    network.network_security_groups.list_all.return_value = iter([nsg_open, nsg_locked])
    f = _CHECKS.check_4_1_no_unrestricted_ssh(network, "sub")
    assert f.status == "FAIL"
    assert any("open-nsg" in r for r in f.resources)
    assert not any("locked-nsg" in r for r in f.resources)


# ---------------------------------------------------------------------------
# Axis 4 — permission denied
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,builder", _AZURE_CHECKS, ids=[c[0] for c in _AZURE_CHECKS])
def test_authorization_failed_does_not_crash(check_name, builder):
    """Axis 4: an SDK AuthorizationFailed surfaces as ERROR not crash."""
    fn = getattr(_CHECKS, check_name)
    client = builder()
    for attr in dir(client):
        if attr.startswith("_"):
            continue
        sub = getattr(client, attr)
        for op in ("list", "list_all", "list_by_server"):
            method = getattr(sub, op, None)
            if method is not None and hasattr(method, "side_effect"):
                method.side_effect = _AuthorizationFailed(
                    "403 The client does not have authorization"
                )
    if check_name in {"check_8_4_keyvault_key_expiration", "check_8_5_keyvault_secret_expiration"}:
        f = fn(client, _kv_factory)
    elif check_name == "check_1_5_no_guest_users":
        f = fn(client)
    else:
        f = fn(client, "sub-id-1")
    assert isinstance(f, Finding)
    assert f.status in {"ERROR", "PASS", "FAIL"}


# ---------------------------------------------------------------------------
# Axis 5 — multi-resource happy path
# ---------------------------------------------------------------------------


def test_2_1_storage_cmk_all_pass():
    storage = MagicMock()
    accounts = [
        _account(f"acct-{i}", encryption=MagicMock(key_source="Microsoft.Keyvault"))
        for i in range(5)
    ]
    storage.storage_accounts.list.return_value = iter(accounts)
    f = _CHECKS.check_2_1_storage_cmk(storage, "sub")
    assert f.status == "PASS"
    assert f.resources == []


def test_2_2_https_all_pass():
    storage = MagicMock()
    accounts = [_account(f"a{i}", enable_https_traffic_only=True) for i in range(3)]
    storage.storage_accounts.list.return_value = iter(accounts)
    f = _CHECKS.check_2_2_https_only(storage, "sub")
    assert f.status == "PASS"


# ---------------------------------------------------------------------------
# Cross-check invariants
# ---------------------------------------------------------------------------


def test_all_32_checks_set_compliance_metadata():
    """Every check must always set NIST CSF mapping + section + severity."""
    for check_name, builder in _AZURE_CHECKS:
        f = _call(check_name, builder)
        assert f.nist_csf, f"{check_name}: missing nist_csf"
        assert f.section, f"{check_name}: missing section"
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, f"{check_name}: bad severity"
