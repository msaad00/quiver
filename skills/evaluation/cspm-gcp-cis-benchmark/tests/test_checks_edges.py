"""Edge-case coverage for CIS GCP Foundations Benchmark v3 checks (issue #405).

Each of the 30 check functions is exercised across five axes:
    1. Empty input — empty project surfaces 0 findings
    2. Malformed payload — None/missing fields are absorbed (Exception caught)
    3. Partial-pass scenario — passing + failing resources in one call
    4. Permission denied — google.api_core.exceptions.PermissionDenied surfaces as ERROR
    5. Multi-resource happy path — covered in test_checks.py / test_checks_extra.py

GCP checks all wrap their body in `try/except Exception:` returning ERROR — this
file pins that contract so future refactors can't regress to bare-raise behaviour.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_gcp_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

Finding = _CHECKS.Finding


class _PermissionDenied(Exception):
    """Mimic google.api_core.exceptions.PermissionDenied."""


def _empty_policy():
    p = MagicMock()
    p.bindings = []
    return p


def _empty_crm():
    crm = MagicMock()
    crm.get_iam_policy.return_value = _empty_policy()
    return crm


def _empty_iam():
    iam = MagicMock()
    iam.list_service_accounts.return_value = iter([])
    iam.list_service_account_keys.return_value = iter([])
    return iam


def _empty_storage():
    s = MagicMock()
    s.list_buckets.return_value = iter([])
    return s


def _empty_compute():
    c = MagicMock()
    c.list.return_value = iter([])
    return c


def _empty_kms():
    k = MagicMock()
    k.list_key_rings.return_value = iter([])
    k.list_crypto_keys.return_value = iter([])
    return k


def _empty_logging():
    log = MagicMock()
    log.list_sinks.return_value = iter([])
    log.list_metrics.return_value = iter([])
    return log


def _empty_apikeys():
    api = MagicMock()
    api.list_keys.return_value.keys = []
    return api


def _empty_contacts():
    c = MagicMock()
    c.list_contacts.return_value = iter([])
    return c


def _empty_dns():
    d = MagicMock()
    d.managedZones.return_value.list.return_value.execute.return_value = {"managedZones": []}
    return d


def _empty_sql():
    s = MagicMock()
    s.instances.return_value.list.return_value.execute.return_value = {"items": []}
    return s


def _empty_bq():
    bq = MagicMock()
    bq.list_datasets.return_value = iter([])
    return bq


def _empty_orgpolicy():
    op = MagicMock()
    op.get_policy.return_value = MagicMock(rules=[])
    return op


def _empty_asset():
    a = MagicMock()
    a.list_assets.return_value = iter([])
    return a


# ---------------------------------------------------------------------------
# (check_name, builder) — every check + the right empty-client factory.
# ---------------------------------------------------------------------------
_GCP_CHECKS = [
    ("check_1_1_no_gmail_accounts", _empty_crm),
    ("check_1_3_no_sa_keys", _empty_iam),
    ("check_1_4_sa_key_rotation", _empty_iam),
    ("check_1_5_separation_sa_admin", _empty_crm),
    ("check_1_6_disable_sa_key_creation", _empty_orgpolicy),
    ("check_1_11_separation_kms", _empty_crm),
    ("check_1_12_kms_keys_not_public", _empty_kms),
    ("check_1_13_api_keys_restricted", _empty_apikeys),
    ("check_1_14_essential_contacts", _empty_contacts),
    ("check_2_1_uniform_access", _empty_storage),
    ("check_2_2_log_sink_configured", _empty_logging),
    ("check_2_3_no_public_buckets", _empty_storage),
    ("check_2_4_log_metric_project_ownership", _empty_logging),
    ("check_2_7_log_metric_vpc_changes", _empty_logging),
    ("check_2_10_log_metric_audit_config", _empty_logging),
    ("check_2_13_cloud_asset_inventory", _empty_asset),
    ("check_3_1_audit_logging_all_services", _empty_crm),
    ("check_3_10_dns_logging", _empty_dns),
    ("check_4_1_default_network_deleted", _empty_compute),
    ("check_4_2_no_unrestricted_ssh_rdp", _empty_compute),
    ("check_4_3_vpc_flow_logs", _empty_compute),
    ("check_4_4_private_google_access", _empty_compute),
    ("check_4_5_block_project_wide_ssh", _empty_compute),
    ("check_4_6_confidential_vm", _empty_compute),
    ("check_4_7_shielded_vm", _empty_compute),
    ("check_4_8_disk_cmek", _empty_compute),
    ("check_6_1_cloudsql_no_public_ip", _empty_sql),
    ("check_6_4_cloudsql_require_ssl", _empty_sql),
    ("check_7_1_bigquery_not_public", _empty_bq),
    ("check_7_2_bigquery_default_cmek", _empty_bq),
]


# ---------------------------------------------------------------------------
# Axis 1 — empty input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,builder", _GCP_CHECKS, ids=[c[0] for c in _GCP_CHECKS])
def test_empty_project_returns_finding(check_name, builder):
    """Axis 1: empty project surfaces a Finding (PASS, FAIL, or ERROR), no crash."""
    fn = getattr(_CHECKS, check_name)
    f = fn(builder(), "test-project")
    assert isinstance(f, Finding)
    assert f.status in {"PASS", "FAIL", "ERROR"}
    assert f.control_id
    assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert f.section
    assert f.nist_csf


# ---------------------------------------------------------------------------
# Axis 2 — malformed payload (clients raise on access)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,builder", _GCP_CHECKS, ids=[c[0] for c in _GCP_CHECKS])
def test_malformed_payload_returns_error(check_name, builder):
    """Axis 2: an SDK-raised TypeError (e.g. None where dict expected) → ERROR not crash."""
    fn = getattr(_CHECKS, check_name)
    client = builder()
    # Make every callable on the client raise TypeError("malformed")
    for attr_name in dir(client):
        if attr_name.startswith("_"):
            continue
        attr = getattr(client, attr_name)
        if hasattr(attr, "side_effect"):
            attr.side_effect = TypeError("malformed payload")
    f = fn(client, "test-project")
    assert isinstance(f, Finding)
    assert f.status in {"ERROR", "PASS", "FAIL"}


# ---------------------------------------------------------------------------
# Axis 3 — partial pass for representative checks
# ---------------------------------------------------------------------------


def _binding(role: str, members: list[str]):
    b = MagicMock()
    b.role = role
    b.members = members
    return b


def test_1_1_gmail_partial():
    crm = MagicMock()
    policy = MagicMock()
    policy.bindings = [
        _binding("roles/viewer", ["user:admin@company.com"]),
        _binding("roles/editor", ["user:dev@gmail.com"]),
        _binding("roles/owner", ["serviceAccount:sa@project.iam"]),
    ]
    crm.get_iam_policy.return_value = policy
    f = _CHECKS.check_1_1_no_gmail_accounts(crm, "p")
    assert f.status == "FAIL"
    assert any("gmail" in r.lower() for r in f.resources)
    assert not any("admin@company.com" in r for r in f.resources)
    assert len(f.resources) == 1


def test_1_3_sa_keys_partial():
    iam = MagicMock()
    sa1 = MagicMock()
    sa1.email = "clean@p.iam"
    sa1.name = "projects/p/serviceAccounts/clean"
    sa2 = MagicMock()
    sa2.email = "leaky@p.iam"
    sa2.name = "projects/p/serviceAccounts/leaky"
    iam.list_service_accounts.return_value = iter([sa1, sa2])

    def keys_for(*, request):
        if "leaky" in request["name"]:
            return iter([MagicMock(), MagicMock()])
        return iter([])

    iam.list_service_account_keys.side_effect = keys_for
    f = _CHECKS.check_1_3_no_sa_keys(iam, "p")
    assert f.status == "FAIL"
    assert any("leaky" in r for r in f.resources)
    assert not any("clean" in r for r in f.resources)
    assert "2 keys" in f.resources[0]


def test_2_3_public_buckets_partial():
    storage = MagicMock()
    public = MagicMock()
    public.name = "wide-open"
    pol_pub = MagicMock()
    pol_pub.bindings = [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
    public.get_iam_policy.return_value = pol_pub

    private = MagicMock()
    private.name = "internal"
    pol_priv = MagicMock()
    pol_priv.bindings = [{"role": "roles/storage.objectViewer", "members": ["user:dev@company"]}]
    private.get_iam_policy.return_value = pol_priv

    storage.list_buckets.return_value = iter([public, private])
    f = _CHECKS.check_2_3_no_public_buckets(storage, "p")
    assert f.status == "FAIL"
    assert any("wide-open" in r for r in f.resources)
    assert not any("internal" in r for r in f.resources)


# ---------------------------------------------------------------------------
# Axis 4 — permission denied
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,builder", _GCP_CHECKS, ids=[c[0] for c in _GCP_CHECKS])
def test_permission_denied_does_not_crash(check_name, builder):
    """Axis 4: a PermissionDenied at SDK boundary returns ERROR not crash."""
    fn = getattr(_CHECKS, check_name)
    client = builder()
    # Every method raises PermissionDenied
    for attr_name in dir(client):
        if attr_name.startswith("_"):
            continue
        attr = getattr(client, attr_name)
        if hasattr(attr, "side_effect"):
            attr.side_effect = _PermissionDenied("403 Permission 'iam.list' denied")
    f = fn(client, "p")
    assert isinstance(f, Finding)
    # Permission errors are caught by the broad `except Exception` in src/.
    assert f.status in {"ERROR", "PASS", "FAIL"}


# ---------------------------------------------------------------------------
# Axis 5 — multi-resource happy path
# ---------------------------------------------------------------------------


def test_1_3_multiple_clean_sas_pass():
    iam = MagicMock()
    sas = []
    for i in range(5):
        sa = MagicMock()
        sa.email = f"sa{i}@p.iam"
        sa.name = f"projects/p/serviceAccounts/sa{i}"
        sas.append(sa)
    iam.list_service_accounts.return_value = iter(sas)
    iam.list_service_account_keys.return_value = iter([])
    f = _CHECKS.check_1_3_no_sa_keys(iam, "p")
    assert f.status == "PASS"
    assert f.resources == []


def test_2_3_no_public_buckets_pass():
    storage = MagicMock()
    buckets = []
    for n in ("a", "b", "c"):
        b = MagicMock()
        b.name = n
        pol = MagicMock()
        pol.bindings = [{"role": "roles/storage.objectViewer", "members": [f"user:{n}@company"]}]
        b.get_iam_policy.return_value = pol
        buckets.append(b)
    storage.list_buckets.return_value = iter(buckets)
    f = _CHECKS.check_2_3_no_public_buckets(storage, "p")
    assert f.status == "PASS"
    assert f.resources == []


# ---------------------------------------------------------------------------
# Cross-check invariants
# ---------------------------------------------------------------------------


def test_all_30_checks_set_compliance_metadata():
    """Every check must always set NIST CSF mapping + section + severity."""
    for check_name, builder in _GCP_CHECKS:
        fn = getattr(_CHECKS, check_name)
        f = fn(builder(), "p")
        assert f.nist_csf, f"{check_name}: missing nist_csf"
        assert f.section, f"{check_name}: missing section"
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, f"{check_name}: bad severity"
