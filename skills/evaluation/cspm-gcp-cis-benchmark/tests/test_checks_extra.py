"""Additional coverage for CIS GCP Foundations v3.0 checks.

Exercises uncovered paths:
    - check_1_4_sa_key_rotation (old vs fresh keys)
    - check_2_1_uniform_access (legacy ACL vs UBLA)
    - check_3_1_audit_logging_all_services (coverage + exemptions)
    - check_4_1_default_network_deleted (default VPC present/absent)
    - check_4_3_vpc_flow_logs (subnet w/ and w/o logs)
    - check_4_4_private_google_access (subnet w/ and w/o PGA)
    - error branches for every check
    - run_assessment + section filter via patched SDK modules
    - print_summary + main CLI (console and JSON outputs)
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import types
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_gcp_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)


# ---------------------------------------------------------------------------
# IAM checks
# ---------------------------------------------------------------------------


def test_1_1_error_branch():
    crm = MagicMock()
    crm.get_iam_policy.side_effect = RuntimeError("denied")
    f = _CHECKS.check_1_1_no_gmail_accounts(crm, "p")
    assert f.status == "ERROR"
    assert "denied" in f.detail


def test_1_3_error_branch():
    iam = MagicMock()
    iam.list_service_accounts.side_effect = RuntimeError("boom")
    f = _CHECKS.check_1_3_no_sa_keys(iam, "p")
    assert f.status == "ERROR"


def test_1_4_sa_key_rotation_flags_old_key_only():
    now = datetime.now(timezone.utc)
    old = MagicMock()
    old.valid_after_time = (now - timedelta(days=120)).replace(tzinfo=None)
    old.name = "projects/p/serviceAccounts/sa/keys/OLD"

    fresh = MagicMock()
    fresh.valid_after_time = (now - timedelta(days=5)).replace(tzinfo=None)
    fresh.name = "projects/p/serviceAccounts/sa/keys/FRESH"

    sa = MagicMock()
    sa.name = "projects/p/serviceAccounts/sa"
    sa.email = "sa@p.iam.gserviceaccount.com"

    iam = MagicMock()
    iam.list_service_accounts.return_value = [sa]
    iam.list_service_account_keys.return_value = [old, fresh]

    f = _CHECKS.check_1_4_sa_key_rotation(iam, "p")
    assert f.status == "FAIL"
    assert any("OLD" in r for r in f.resources)
    assert not any("FRESH" in r for r in f.resources)


def test_1_4_sa_key_rotation_all_fresh_passes():
    now = datetime.now(timezone.utc)
    fresh = MagicMock()
    fresh.valid_after_time = (now - timedelta(days=10)).replace(tzinfo=None)
    fresh.name = "projects/p/serviceAccounts/sa/keys/FRESH"

    sa = MagicMock()
    sa.name = "projects/p/serviceAccounts/sa"
    sa.email = "sa@p.iam.gserviceaccount.com"

    iam = MagicMock()
    iam.list_service_accounts.return_value = [sa]
    iam.list_service_account_keys.return_value = [fresh]

    f = _CHECKS.check_1_4_sa_key_rotation(iam, "p")
    assert f.status == "PASS"


def test_1_4_error_branch():
    iam = MagicMock()
    iam.list_service_accounts.side_effect = RuntimeError("x")
    f = _CHECKS.check_1_4_sa_key_rotation(iam, "p")
    assert f.status == "ERROR"


# ---------------------------------------------------------------------------
# Storage checks
# ---------------------------------------------------------------------------


def test_2_1_uniform_access_flags_legacy_acl_buckets():
    storage = MagicMock()
    b1 = MagicMock()
    b1.name = "legacy"
    b1.iam_configuration.uniform_bucket_level_access_enabled = False
    b2 = MagicMock()
    b2.name = "modern"
    b2.iam_configuration.uniform_bucket_level_access_enabled = True
    storage.list_buckets.return_value = [b1, b2]
    f = _CHECKS.check_2_1_uniform_access(storage, "p")
    assert f.status == "FAIL"
    assert f.resources == ["legacy"]


def test_2_1_uniform_access_all_passing():
    storage = MagicMock()
    b = MagicMock()
    b.name = "modern"
    b.iam_configuration.uniform_bucket_level_access_enabled = True
    storage.list_buckets.return_value = [b]
    assert _CHECKS.check_2_1_uniform_access(storage, "p").status == "PASS"


def test_2_1_error_branch():
    storage = MagicMock()
    storage.list_buckets.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_1_uniform_access(storage, "p").status == "ERROR"


def test_2_3_all_authenticated_users_also_flagged():
    storage = MagicMock()
    bucket = MagicMock()
    bucket.name = "auth-public"
    policy = MagicMock()
    policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}]
    bucket.get_iam_policy.return_value = policy
    storage.list_buckets.return_value = [bucket]
    f = _CHECKS.check_2_3_no_public_buckets(storage, "p")
    assert f.status == "FAIL"
    assert "auth-public" in f.resources[0]


def test_2_3_error_branch():
    storage = MagicMock()
    storage.list_buckets.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_3_no_public_buckets(storage, "p").status == "ERROR"


# ---------------------------------------------------------------------------
# Logging checks
# ---------------------------------------------------------------------------


def _audit_log_config(log_type: str, exempted_members: list[str] | None = None):
    config = MagicMock()
    config.log_type = log_type
    config.exempted_members = exempted_members or []
    return config


def _audit_config(service: str, *log_configs):
    config = MagicMock()
    config.service = service
    config.audit_log_configs = list(log_configs)
    return config


def test_3_1_audit_logging_all_services_passes():
    crm = MagicMock()
    policy = MagicMock()
    policy.audit_configs = [
        _audit_config(
            "allServices",
            _audit_log_config("ADMIN_READ"),
            _audit_log_config("DATA_READ"),
            _audit_log_config("DATA_WRITE"),
        )
    ]
    crm.get_iam_policy.return_value = policy
    f = _CHECKS.check_3_1_audit_logging_all_services(crm, "p")
    assert f.status == "PASS"


def test_3_1_audit_logging_missing_type_fails():
    crm = MagicMock()
    policy = MagicMock()
    policy.audit_configs = [
        _audit_config(
            "allServices",
            _audit_log_config("ADMIN_READ"),
            _audit_log_config("DATA_WRITE"),
        )
    ]
    crm.get_iam_policy.return_value = policy
    f = _CHECKS.check_3_1_audit_logging_all_services(crm, "p")
    assert f.status == "FAIL"
    assert "DATA_READ" in f.resources


def test_3_1_audit_logging_exemptions_fail():
    crm = MagicMock()
    policy = MagicMock()
    policy.audit_configs = [
        _audit_config(
            "allServices",
            _audit_log_config("ADMIN_READ"),
            _audit_log_config("DATA_READ", ["user:alice@example.com"]),
            _audit_log_config("DATA_WRITE"),
        )
    ]
    crm.get_iam_policy.return_value = policy
    f = _CHECKS.check_3_1_audit_logging_all_services(crm, "p")
    assert f.status == "FAIL"
    assert any("alice@example.com" in r for r in f.resources)


def test_3_1_error_branch():
    crm = MagicMock()
    crm.get_iam_policy.side_effect = RuntimeError("x")
    assert _CHECKS.check_3_1_audit_logging_all_services(crm, "p").status == "ERROR"


# ---------------------------------------------------------------------------
# Networking checks
# ---------------------------------------------------------------------------


def test_4_1_default_network_detected():
    networks = MagicMock()
    default = MagicMock()
    default.name = "default"
    custom = MagicMock()
    custom.name = "custom"
    networks.list.return_value = [default, custom]
    f = _CHECKS.check_4_1_default_network_deleted(networks, "p")
    assert f.status == "FAIL"
    assert f.resources == ["default"]


def test_4_1_no_default_network_passes():
    networks = MagicMock()
    custom = MagicMock()
    custom.name = "custom"
    networks.list.return_value = [custom]
    assert _CHECKS.check_4_1_default_network_deleted(networks, "p").status == "PASS"


def test_4_1_error_branch():
    networks = MagicMock()
    networks.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_1_default_network_deleted(networks, "p").status == "ERROR"


def test_4_2_rule_disabled_is_ignored():
    compute = MagicMock()
    rule = MagicMock()
    rule.name = "disabled-ssh"
    rule.direction = "INGRESS"
    rule.disabled = True
    allowed = MagicMock()
    allowed.ip_protocol = "tcp"
    allowed.ports = ["22"]
    rule.allowed = [allowed]
    rule.source_ranges = ["0.0.0.0/0"]
    compute.list.return_value = [rule]
    assert _CHECKS.check_4_2_no_unrestricted_ssh_rdp(compute, "p").status == "PASS"


def test_4_2_port_range_expansion_catches_rdp():
    compute = MagicMock()
    rule = MagicMock()
    rule.name = "wide-range"
    rule.direction = "INGRESS"
    rule.disabled = False
    allowed = MagicMock()
    allowed.ip_protocol = "tcp"
    allowed.ports = ["3000-4000"]
    rule.allowed = [allowed]
    rule.source_ranges = ["0.0.0.0/0"]
    compute.list.return_value = [rule]
    f = _CHECKS.check_4_2_no_unrestricted_ssh_rdp(compute, "p")
    assert f.status == "FAIL"


def test_4_2_egress_rule_ignored():
    compute = MagicMock()
    rule = MagicMock()
    rule.direction = "EGRESS"
    rule.disabled = False
    rule.allowed = []
    rule.source_ranges = []
    compute.list.return_value = [rule]
    assert _CHECKS.check_4_2_no_unrestricted_ssh_rdp(compute, "p").status == "PASS"


def test_4_2_error_branch():
    compute = MagicMock()
    compute.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_2_no_unrestricted_ssh_rdp(compute, "p").status == "ERROR"


def test_4_3_flow_logs_mixed_subnets():
    compute = MagicMock()
    enabled_subnet = MagicMock()
    enabled_subnet.name = "good"
    enabled_subnet.log_config.enable = True

    disabled_subnet = MagicMock()
    disabled_subnet.name = "bad"
    disabled_subnet.log_config.enable = False

    region_bundle = MagicMock()
    region_bundle.subnetworks = [enabled_subnet, disabled_subnet]
    compute.aggregated_list.return_value = [region_bundle]

    f = _CHECKS.check_4_3_vpc_flow_logs(compute, "p")
    assert f.status == "FAIL"
    assert f.resources == ["bad"]


def test_4_3_error_branch():
    compute = MagicMock()
    compute.aggregated_list.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_3_vpc_flow_logs(compute, "p").status == "ERROR"


def test_4_4_private_google_access_mixed_subnets():
    compute = MagicMock()
    good = MagicMock()
    good.name = "good"
    good.private_ip_google_access = True

    bad = MagicMock()
    bad.name = "bad"
    bad.private_ip_google_access = False

    region_bundle = MagicMock()
    region_bundle.subnetworks = [good, bad]
    compute.aggregated_list.return_value = [region_bundle]

    f = _CHECKS.check_4_4_private_google_access(compute, "p")
    assert f.status == "FAIL"
    assert f.resources == ["bad"]


def test_4_4_private_google_access_all_enabled():
    compute = MagicMock()
    good = MagicMock()
    good.name = "good"
    good.private_ip_google_access = True
    region_bundle = MagicMock()
    region_bundle.subnetworks = [good]
    compute.aggregated_list.return_value = [region_bundle]
    assert _CHECKS.check_4_4_private_google_access(compute, "p").status == "PASS"


def test_4_4_error_branch():
    compute = MagicMock()
    compute.aggregated_list.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_4_private_google_access(compute, "p").status == "ERROR"


# ---------------------------------------------------------------------------
# Runner, CLI, summary
# ---------------------------------------------------------------------------


def _install_fake_google_modules(monkeypatch):
    """Install tiny stand-ins for the google.cloud.* modules the runner imports."""
    google = types.ModuleType("google")
    cloud = types.ModuleType("google.cloud")

    iam_admin_v1 = types.ModuleType("google.cloud.iam_admin_v1")
    iam_admin_v1.IAMClient = MagicMock()

    rm = types.ModuleType("google.cloud.resourcemanager_v3")
    rm.ProjectsClient = MagicMock()

    storage_mod = types.ModuleType("google.cloud.storage")
    storage_mod.Client = MagicMock()

    compute_v1 = types.ModuleType("google.cloud.compute_v1")
    services = types.ModuleType("google.cloud.compute_v1.services")
    firewalls_mod = types.ModuleType("google.cloud.compute_v1.services.firewalls")
    firewalls_mod.FirewallsClient = MagicMock()
    networks_mod = types.ModuleType("google.cloud.compute_v1.services.networks")
    networks_mod.NetworksClient = MagicMock()
    subnetworks_mod = types.ModuleType("google.cloud.compute_v1.services.subnetworks")
    subnetworks_mod.SubnetworksClient = MagicMock()
    instances_mod = types.ModuleType("google.cloud.compute_v1.services.instances")
    instances_mod.InstancesClient = MagicMock()

    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.iam_admin_v1", iam_admin_v1)
    monkeypatch.setitem(sys.modules, "google.cloud.resourcemanager_v3", rm)
    monkeypatch.setitem(sys.modules, "google.cloud.storage", storage_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.compute_v1", compute_v1)
    monkeypatch.setitem(sys.modules, "google.cloud.compute_v1.services", services)
    monkeypatch.setitem(sys.modules, "google.cloud.compute_v1.services.firewalls", firewalls_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.compute_v1.services.networks", networks_mod)
    monkeypatch.setitem(
        sys.modules, "google.cloud.compute_v1.services.subnetworks", subnetworks_mod
    )
    monkeypatch.setitem(
        sys.modules, "google.cloud.compute_v1.services.instances", instances_mod
    )


def test_run_assessment_full_and_section_filter(monkeypatch):
    _install_fake_google_modules(monkeypatch)
    findings = _CHECKS.run_assessment(project_id="p")
    assert {f.section for f in findings} >= {
        "iam",
        "storage",
        "logging",
        "networking",
        "compute",
        "cloudsql",
        "bigquery",
    }
    # Section filter
    filtered = _CHECKS.run_assessment(project_id="p", section="iam")
    assert {f.section for f in filtered} == {"iam"}


def test_run_assessment_missing_sdk_exits(monkeypatch):
    # Remove the google.cloud namespace so the import fails.
    for key in list(sys.modules):
        if key.startswith("google"):
            monkeypatch.delitem(sys.modules, key, raising=False)
    # Block real imports
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("google.cloud"):
            raise ImportError("no sdk")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        _CHECKS.run_assessment(project_id="p")
    except SystemExit as e:
        assert e.code == 1
    else:
        raise AssertionError("expected SystemExit")


def test_status_symbol_handles_unknown():
    assert _CHECKS._status_symbol("WEIRD") == "?"
    for s in ("PASS", "FAIL", "ERROR"):
        assert _CHECKS._status_symbol(s)


def test_print_summary_renders_findings():
    findings = [
        _CHECKS.Finding(
            control_id="1.1", title="t", section="iam", severity="HIGH", status="PASS"
        ),
        _CHECKS.Finding(
            control_id="2.1",
            title="t",
            section="storage",
            severity="HIGH",
            status="FAIL",
            detail="d",
            resources=["a", "b"],
        ),
    ]
    buf = io.StringIO()
    with redirect_stdout(buf):
        _CHECKS.print_summary(findings)
    out = buf.getvalue()
    assert "IAM" in out and "STORAGE" in out and "Score" in out


def test_main_console_exit_zero(monkeypatch):
    _install_fake_google_modules(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["checks.py", "--project", "p", "--section", "iam"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit as e:
            assert e.code == 0


def test_main_json_ocsf(monkeypatch):
    _install_fake_google_modules(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "checks.py",
            "--project",
            "p",
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
    _install_fake_google_modules(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["checks.py", "--project", "p", "--section", "storage", "--output", "json"]
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit:
            pass
    payload = json.loads(buf.getvalue())
    assert isinstance(payload, list)
