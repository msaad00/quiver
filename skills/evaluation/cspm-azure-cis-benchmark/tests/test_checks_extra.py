"""Additional coverage for CIS Azure Foundations v2.1 checks.

Targets uncovered paths:
    - error branches in every check
    - NSG port range parsing + malformed range
    - check_4_3_nsg_flow_logs: no NSGs, no watchers, enabled + disabled targets
    - run_assessment runner w/ patched SDK modules
    - print_summary + main CLI (console / JSON / OCSF)
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import types
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_azure_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)


def _account(**kwargs):
    a = MagicMock()
    for k, v in kwargs.items():
        setattr(a, k, v)
    return a


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_2_3_public_blob_fail():
    client = MagicMock()
    client.storage_accounts.list.return_value = [
        _account(name="open", allow_blob_public_access=True),
        _account(name="locked", allow_blob_public_access=False),
    ]
    f = _CHECKS.check_2_3_no_public_blob(client, "sub")
    assert f.status == "FAIL"
    assert f.resources == ["open"]


def test_2_1_storage_cmk_fail():
    client = MagicMock()
    account = _account(name="managed")
    account.encryption = MagicMock(key_source="Microsoft.Storage")
    client.storage_accounts.list.return_value = [account]
    f = _CHECKS.check_2_1_storage_cmk(client, "sub")
    assert f.status == "FAIL"
    assert f.resources == ["managed"]


def test_2_1_storage_cmk_error_branch():
    client = MagicMock()
    client.storage_accounts.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_1_storage_cmk(client, "sub").status == "ERROR"


def test_2_3_error_branch():
    client = MagicMock()
    client.storage_accounts.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_3_no_public_blob(client, "sub").status == "ERROR"


def test_2_2_https_only_flags_non_https_accounts():
    client = MagicMock()
    client.storage_accounts.list.return_value = [
        _account(name="http-ok", enable_https_traffic_only=False),
        _account(name="tls", enable_https_traffic_only=True),
    ]
    f = _CHECKS.check_2_2_https_only(client, "sub")
    assert f.status == "FAIL"
    assert f.resources == ["http-ok"]


def test_2_2_all_https_passes():
    client = MagicMock()
    client.storage_accounts.list.return_value = [
        _account(name="tls", enable_https_traffic_only=True)
    ]
    assert _CHECKS.check_2_2_https_only(client, "sub").status == "PASS"


def test_2_2_error_branch():
    client = MagicMock()
    client.storage_accounts.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_2_https_only(client, "sub").status == "ERROR"


def test_2_4_network_rules_default_allow_fails():
    nrs = MagicMock()
    nrs.default_action = "Allow"
    client = MagicMock()
    client.storage_accounts.list.return_value = [_account(name="open", network_rule_set=nrs)]
    f = _CHECKS.check_2_4_network_rules(client, "sub")
    assert f.status == "FAIL"
    assert f.resources == ["open"]


def test_2_4_network_rules_default_deny_passes():
    nrs = MagicMock()
    nrs.default_action = "Deny"
    client = MagicMock()
    client.storage_accounts.list.return_value = [_account(name="locked", network_rule_set=nrs)]
    assert _CHECKS.check_2_4_network_rules(client, "sub").status == "PASS"


def test_2_4_error_branch():
    client = MagicMock()
    client.storage_accounts.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_4_network_rules(client, "sub").status == "ERROR"


# ---------------------------------------------------------------------------
# Networking — SSH/RDP
# ---------------------------------------------------------------------------


def _rule(**kwargs):
    r = MagicMock()
    r.direction = kwargs.get("direction", "Inbound")
    r.access = kwargs.get("access", "Allow")
    r.source_address_prefix = kwargs.get("source_address_prefix", "*")
    r.destination_port_range = kwargs.get("destination_port_range", "22")
    r.name = kwargs.get("name", "r")
    return r


def _nsg(name, rules):
    n = MagicMock()
    n.name = name
    n.id = f"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}"
    n.security_rules = rules
    return n


def test_4_1_ssh_open_fails():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [
        _nsg("nsg-a", [_rule(name="ssh", destination_port_range="22")])
    ]
    f = _CHECKS.check_4_1_no_unrestricted_ssh(client, "sub")
    assert f.status == "FAIL"
    assert "nsg-a/ssh" in f.resources


def test_4_2_rdp_range_hits():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [
        _nsg("nsg-a", [_rule(name="wide", destination_port_range="3000-4000")])
    ]
    f = _CHECKS.check_4_2_no_unrestricted_rdp(client, "sub")
    assert f.status == "FAIL"


def test_4_1_wildcard_port_flagged():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [
        _nsg("nsg-a", [_rule(name="any", destination_port_range="*")])
    ]
    assert _CHECKS.check_4_1_no_unrestricted_ssh(client, "sub").status == "FAIL"


def test_4_1_outbound_or_deny_ignored():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [
        _nsg(
            "nsg-a",
            [
                _rule(name="outbound", direction="Outbound"),
                _rule(name="deny", access="Deny"),
                _rule(name="internal", source_address_prefix="10.0.0.0/8"),
            ],
        )
    ]
    assert _CHECKS.check_4_1_no_unrestricted_ssh(client, "sub").status == "PASS"


def test_4_1_malformed_port_range_is_ignored():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [
        _nsg("nsg-a", [_rule(name="bad", destination_port_range="abc-def")])
    ]
    assert _CHECKS.check_4_1_no_unrestricted_ssh(client, "sub").status == "PASS"


def test_4_1_error_branch():
    client = MagicMock()
    client.network_security_groups.list_all.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_1_no_unrestricted_ssh(client, "sub").status == "ERROR"


# ---------------------------------------------------------------------------
# NSG flow logs
# ---------------------------------------------------------------------------


def _watcher(name, rg):
    w = MagicMock()
    w.name = name
    w.id = (
        f"/subscriptions/sub/resourceGroups/{rg}/providers/Microsoft.Network/networkWatchers/{name}"
    )
    return w


def _flow_log(target_id, enabled=True):
    f = MagicMock()
    f.enabled = enabled
    f.target_resource_id = target_id
    return f


def test_4_3_no_nsgs_passes():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = []
    client.network_watchers.list_all.return_value = []
    f = _CHECKS.check_4_3_nsg_flow_logs(client, "sub")
    assert f.status == "PASS"


def test_4_3_nsg_but_no_watchers_fails():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [_nsg("nsg-a", [])]
    client.network_watchers.list_all.return_value = []
    f = _CHECKS.check_4_3_nsg_flow_logs(client, "sub")
    assert f.status == "FAIL"


def test_4_3_all_nsgs_have_enabled_flow_logs():
    nsg = _nsg("nsg-a", [])
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [nsg]
    client.network_watchers.list_all.return_value = [_watcher("w", "rg")]
    client.flow_logs.list.return_value = [_flow_log(nsg.id, enabled=True)]
    f = _CHECKS.check_4_3_nsg_flow_logs(client, "sub")
    assert f.status == "PASS"


def test_4_3_some_nsgs_missing_flow_logs_fails():
    a = _nsg("nsg-a", [])
    b = _nsg("nsg-b", [])
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [a, b]
    client.network_watchers.list_all.return_value = [_watcher("w", "rg")]
    # Only one enabled flow log, and one disabled for the second
    client.flow_logs.list.return_value = [
        _flow_log(a.id, enabled=True),
        _flow_log(b.id, enabled=False),
    ]
    f = _CHECKS.check_4_3_nsg_flow_logs(client, "sub")
    assert f.status == "FAIL"
    assert b.id in f.resources


def test_4_3_skips_watcher_with_no_resource_group():
    nsg = _nsg("nsg-a", [])
    bad_watcher = MagicMock()
    bad_watcher.name = ""
    bad_watcher.id = ""
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [nsg]
    client.network_watchers.list_all.return_value = [bad_watcher]
    client.flow_logs.list.return_value = []
    f = _CHECKS.check_4_3_nsg_flow_logs(client, "sub")
    assert f.status == "FAIL"  # can't verify any flow logs


def test_4_3_error_branch():
    client = MagicMock()
    client.network_security_groups.list_all.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_3_nsg_flow_logs(client, "sub").status == "ERROR"


def test_4_4_no_virtual_networks_passes():
    client = MagicMock()
    client.virtual_networks.list_all.return_value = []
    client.network_watchers.list_all.return_value = []
    f = _CHECKS.check_4_4_network_watcher_regions(client, "sub")
    assert f.status == "PASS"


def test_4_4_missing_watcher_region_fails():
    client = MagicMock()
    eastus = MagicMock(location="eastus")
    westus = MagicMock(location="westus2")
    watcher = MagicMock(location="eastus")
    client.virtual_networks.list_all.return_value = [eastus, westus]
    client.network_watchers.list_all.return_value = [watcher]
    f = _CHECKS.check_4_4_network_watcher_regions(client, "sub")
    assert f.status == "FAIL"
    assert f.resources == ["westus2"]


def test_4_4_error_branch():
    client = MagicMock()
    client.virtual_networks.list_all.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_4_network_watcher_regions(client, "sub").status == "ERROR"


# ---------------------------------------------------------------------------
# Runner + CLI
# ---------------------------------------------------------------------------


def _install_fake_azure(monkeypatch):
    azure = types.ModuleType("azure")
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = MagicMock()

    mgmt = types.ModuleType("azure.mgmt")
    storage = types.ModuleType("azure.mgmt.storage")
    storage.StorageManagementClient = MagicMock()
    network = types.ModuleType("azure.mgmt.network")
    network.NetworkManagementClient = MagicMock()

    monkeypatch.setitem(sys.modules, "azure", azure)
    monkeypatch.setitem(sys.modules, "azure.identity", identity)
    monkeypatch.setitem(sys.modules, "azure.mgmt", mgmt)
    monkeypatch.setitem(sys.modules, "azure.mgmt.storage", storage)
    monkeypatch.setitem(sys.modules, "azure.mgmt.network", network)


def test_run_assessment_and_section_filter(monkeypatch):
    _install_fake_azure(monkeypatch)
    findings = _CHECKS.run_assessment(subscription_id="sub")
    assert {f.section for f in findings} == {"storage", "networking"}
    filtered = _CHECKS.run_assessment(subscription_id="sub", section="storage")
    assert {f.section for f in filtered} == {"storage"}


def test_run_assessment_missing_sdk_exits(monkeypatch):
    import builtins

    for key in list(sys.modules):
        if key.startswith("azure"):
            monkeypatch.delitem(sys.modules, key, raising=False)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("azure"):
            raise ImportError("no sdk")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        _CHECKS.run_assessment(subscription_id="sub")
    except SystemExit as e:
        assert e.code == 1
    else:
        raise AssertionError("expected SystemExit")


def test_status_symbol_handles_unknown():
    assert _CHECKS._status_symbol("WEIRD") == "?"


def test_print_summary_renders():
    findings = [
        _CHECKS.Finding(
            control_id="2.3",
            title="t",
            section="storage",
            severity="CRITICAL",
            status="FAIL",
            detail="d",
            resources=["a"],
        ),
        _CHECKS.Finding(
            control_id="4.1", title="t", section="networking", severity="HIGH", status="PASS"
        ),
    ]
    buf = io.StringIO()
    with redirect_stdout(buf):
        _CHECKS.print_summary(findings)
    out = buf.getvalue()
    assert "STORAGE" in out and "NETWORKING" in out and "Score" in out


def test_main_console_exit_zero(monkeypatch):
    _install_fake_azure(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["checks.py", "--subscription-id", "sub", "--section", "storage"]
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit as e:
            assert e.code == 0


def test_main_json_ocsf(monkeypatch):
    _install_fake_azure(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "checks.py",
            "--subscription-id",
            "sub",
            "--section",
            "networking",
            "--output",
            "json",
            "--output-format",
            "ocsf",
        ],
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit:
            pass
    payload = json.loads(buf.getvalue())
    assert isinstance(payload, list)


def test_main_json_native(monkeypatch):
    _install_fake_azure(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["checks.py", "--subscription-id", "sub", "--section", "storage", "--output", "json"],
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit:
            pass
    payload = json.loads(buf.getvalue())
    assert isinstance(payload, list)
