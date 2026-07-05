"""Tests for CIS GCP Foundations Benchmark v3.0 checks.

Uses unittest.mock to simulate GCP SDK responses.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_gcp_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

check_1_1_no_gmail_accounts = _CHECKS.check_1_1_no_gmail_accounts
check_1_3_no_sa_keys = _CHECKS.check_1_3_no_sa_keys
check_2_3_no_public_buckets = _CHECKS.check_2_3_no_public_buckets
check_4_2_no_unrestricted_ssh_rdp = _CHECKS.check_4_2_no_unrestricted_ssh_rdp


class TestIAMChecks:
    def test_1_1_gmail_found_fails(self):
        mock_crm = MagicMock()
        binding = MagicMock()
        binding.role = "roles/editor"
        binding.members = ["user:someone@gmail.com"]
        policy = MagicMock()
        policy.bindings = [binding]
        mock_crm.get_iam_policy.return_value = policy

        f = check_1_1_no_gmail_accounts(mock_crm, "test-project")
        assert f.status == "FAIL"
        assert f.severity == "HIGH"
        assert len(f.resources) == 1

    def test_1_1_no_gmail_passes(self):
        mock_crm = MagicMock()
        binding = MagicMock()
        binding.role = "roles/viewer"
        binding.members = ["user:admin@company.com"]
        policy = MagicMock()
        policy.bindings = [binding]
        mock_crm.get_iam_policy.return_value = policy

        f = check_1_1_no_gmail_accounts(mock_crm, "test-project")
        assert f.status == "PASS"

    def test_1_3_sa_keys_found_fails(self):
        mock_iam = MagicMock()
        sa = MagicMock()
        sa.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com"
        sa.email = "sa@test.iam.gserviceaccount.com"
        mock_iam.list_service_accounts.return_value = [sa]
        key = MagicMock()
        mock_iam.list_service_account_keys.return_value = [key]

        f = check_1_3_no_sa_keys(mock_iam, "test-project")
        assert f.status == "FAIL"

    def test_1_3_no_sa_keys_passes(self):
        mock_iam = MagicMock()
        sa = MagicMock()
        sa.name = "projects/test/serviceAccounts/sa@test.iam.gserviceaccount.com"
        sa.email = "sa@test.iam.gserviceaccount.com"
        mock_iam.list_service_accounts.return_value = [sa]
        mock_iam.list_service_account_keys.return_value = []

        f = check_1_3_no_sa_keys(mock_iam, "test-project")
        assert f.status == "PASS"


class TestStorageChecks:
    def test_2_3_public_bucket_fails(self):
        mock_storage = MagicMock()
        bucket = MagicMock()
        bucket.name = "public-bucket"
        policy = MagicMock()
        policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
        bucket.get_iam_policy.return_value = policy
        mock_storage.list_buckets.return_value = [bucket]

        f = check_2_3_no_public_buckets(mock_storage, "test-project")
        assert f.status == "FAIL"
        assert "public-bucket" in f.resources[0]

    def test_2_3_private_bucket_passes(self):
        mock_storage = MagicMock()
        bucket = MagicMock()
        bucket.name = "private-bucket"
        policy = MagicMock()
        policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["user:admin@company.com"]}
        ]
        bucket.get_iam_policy.return_value = policy
        mock_storage.list_buckets.return_value = [bucket]

        f = check_2_3_no_public_buckets(mock_storage, "test-project")
        assert f.status == "PASS"


class TestNetworkingChecks:
    def test_4_2_open_ssh_rule_fails(self):
        mock_compute = MagicMock()
        rule = MagicMock()
        rule.name = "allow-ssh"
        rule.direction = "INGRESS"
        rule.disabled = False
        allowed = MagicMock()
        allowed.ip_protocol = "tcp"
        allowed.ports = ["22"]
        rule.allowed = [allowed]
        rule.source_ranges = ["0.0.0.0/0"]
        mock_compute.list.return_value = [rule]

        f = check_4_2_no_unrestricted_ssh_rdp(mock_compute, "test-project")
        assert f.status == "FAIL"
        assert "allow-ssh: tcp/22" in f.resources


class TestFindingStructure:
    def test_finding_has_compliance_fields(self):
        mock_crm = MagicMock()
        policy = MagicMock()
        policy.bindings = []
        mock_crm.get_iam_policy.return_value = policy

        f = check_1_1_no_gmail_accounts(mock_crm, "test-project")
        assert f.nist_csf == "PR.AC-1"
        assert f.control_id == "1.1"


# ---------------------------------------------------------------------------
# New IAM checks (1.5, 1.6, 1.11, 1.12, 1.13, 1.14)
# ---------------------------------------------------------------------------


def _binding(role, members):
    b = MagicMock()
    b.role = role
    b.members = list(members)
    return b


class TestIAMSeparationAndKMS:
    def test_1_5_dual_role_holder_fails(self):
        crm = MagicMock()
        policy = MagicMock()
        policy.bindings = [
            _binding("roles/iam.serviceAccountAdmin", ["user:dev@x.com"]),
            _binding("roles/iam.serviceAccountUser", ["user:dev@x.com"]),
        ]
        crm.get_iam_policy.return_value = policy
        f = _CHECKS.check_1_5_separation_sa_admin(crm, "p")
        assert f.status == "FAIL"
        assert f.resources == ["user:dev@x.com"]

    def test_1_5_distinct_holders_pass(self):
        crm = MagicMock()
        policy = MagicMock()
        policy.bindings = [
            _binding("roles/iam.serviceAccountAdmin", ["user:a@x.com"]),
            _binding("roles/iam.serviceAccountUser", ["user:b@x.com"]),
        ]
        crm.get_iam_policy.return_value = policy
        assert _CHECKS.check_1_5_separation_sa_admin(crm, "p").status == "PASS"

    def test_1_6_org_policy_enforced_passes(self):
        client = MagicMock()
        policy = MagicMock()
        policy.boolean_policy.enforced = True
        client.get_org_policy.return_value = policy
        assert _CHECKS.check_1_6_disable_sa_key_creation(client, "p").status == "PASS"

    def test_1_6_org_policy_not_enforced_fails(self):
        client = MagicMock()
        policy = MagicMock()
        policy.boolean_policy.enforced = False
        client.get_org_policy.return_value = policy
        assert _CHECKS.check_1_6_disable_sa_key_creation(client, "p").status == "FAIL"

    def test_1_11_kms_admin_plus_crypto_role_fails(self):
        crm = MagicMock()
        policy = MagicMock()
        policy.bindings = [
            _binding("roles/cloudkms.admin", ["user:bob@x.com"]),
            _binding("roles/cloudkms.cryptoKeyEncrypterDecrypter", ["user:bob@x.com"]),
        ]
        crm.get_iam_policy.return_value = policy
        f = _CHECKS.check_1_11_separation_kms(crm, "p")
        assert f.status == "FAIL"
        assert any("bob" in r for r in f.resources)

    def test_1_11_admin_only_passes(self):
        crm = MagicMock()
        policy = MagicMock()
        policy.bindings = [
            _binding("roles/cloudkms.admin", ["user:bob@x.com"]),
        ]
        crm.get_iam_policy.return_value = policy
        assert _CHECKS.check_1_11_separation_kms(crm, "p").status == "PASS"

    def test_1_12_public_kms_key_fails(self):
        kms = MagicMock()
        ring = MagicMock()
        ring.name = "projects/p/locations/us/keyRings/r"
        kms.list_key_rings.return_value = [ring]
        key = MagicMock()
        key.name = "projects/p/locations/us/keyRings/r/cryptoKeys/k1"
        kms.list_crypto_keys.return_value = [key]
        binding = MagicMock()
        binding.members = ["allUsers"]
        policy = MagicMock()
        policy.bindings = [binding]
        kms.get_iam_policy.return_value = policy
        f = _CHECKS.check_1_12_kms_keys_not_public(kms, "p")
        assert f.status == "FAIL"
        assert "k1" in f.resources[0]

    def test_1_12_private_kms_key_passes(self):
        kms = MagicMock()
        ring = MagicMock()
        ring.name = "projects/p/locations/us/keyRings/r"
        kms.list_key_rings.return_value = [ring]
        key = MagicMock()
        key.name = "projects/p/locations/us/keyRings/r/cryptoKeys/k1"
        kms.list_crypto_keys.return_value = [key]
        binding = MagicMock()
        binding.members = ["user:owner@x.com"]
        policy = MagicMock()
        policy.bindings = [binding]
        kms.get_iam_policy.return_value = policy
        assert _CHECKS.check_1_12_kms_keys_not_public(kms, "p").status == "PASS"

    def test_1_13_unrestricted_api_key_fails(self):
        client = MagicMock()
        key = MagicMock()
        key.name = "projects/p/locations/global/keys/abc"
        key.display_name = "abc"
        key.restrictions = None
        client.list_keys.return_value = [key]
        f = _CHECKS.check_1_13_api_keys_restricted(client, "p")
        assert f.status == "FAIL"
        assert "abc" in f.resources

    def test_1_13_restricted_api_key_passes(self):
        client = MagicMock()
        key = MagicMock()
        key.name = "projects/p/locations/global/keys/abc"
        key.display_name = "abc"
        restrictions = MagicMock()
        restrictions.api_targets = [MagicMock()]
        restrictions.browser_key_restrictions = MagicMock()
        restrictions.server_key_restrictions = None
        restrictions.android_key_restrictions = None
        restrictions.ios_key_restrictions = None
        key.restrictions = restrictions
        client.list_keys.return_value = [key]
        assert _CHECKS.check_1_13_api_keys_restricted(client, "p").status == "PASS"

    def test_1_14_missing_categories_fails(self):
        client = MagicMock()
        contact = MagicMock()
        contact.notification_category_subscriptions = ["SECURITY"]
        client.list_contacts.return_value = [contact]
        f = _CHECKS.check_1_14_essential_contacts(client, "p")
        assert f.status == "FAIL"
        assert {"TECHNICAL", "LEGAL", "SUSPENSION"}.issubset(set(f.resources))

    def test_1_14_all_categories_present_passes(self):
        client = MagicMock()
        contact = MagicMock()
        contact.notification_category_subscriptions = [
            "SECURITY",
            "TECHNICAL",
            "LEGAL",
            "SUSPENSION",
        ]
        client.list_contacts.return_value = [contact]
        assert _CHECKS.check_1_14_essential_contacts(client, "p").status == "PASS"


# ---------------------------------------------------------------------------
# New Logging checks (2.2, 2.4, 2.7, 2.10, 2.13)
# ---------------------------------------------------------------------------


class TestLoggingMonitoring:
    def test_2_2_catch_all_sink_passes(self):
        client = MagicMock()
        sink = MagicMock()
        sink.filter = ""
        sink.destination = "storage.googleapis.com/bkt"
        client.list_sinks.return_value = [sink]
        f = _CHECKS.check_2_2_log_sink_configured(client, "p")
        assert f.status == "PASS"
        assert "bkt" in f.resources[0]

    def test_2_2_only_filtered_sinks_fails(self):
        client = MagicMock()
        sink = MagicMock()
        sink.filter = "severity>=ERROR"
        sink.destination = "storage.googleapis.com/bkt"
        client.list_sinks.return_value = [sink]
        assert _CHECKS.check_2_2_log_sink_configured(client, "p").status == "FAIL"

    def test_2_4_metric_present_passes(self):
        client = MagicMock()
        m = MagicMock()
        m.filter = 'protoPayload.methodName="SetIamPolicy"'
        client.list_log_metrics.return_value = [m]
        assert _CHECKS.check_2_4_log_metric_project_ownership(client, "p").status == "PASS"

    def test_2_4_metric_missing_fails(self):
        client = MagicMock()
        client.list_log_metrics.return_value = []
        assert _CHECKS.check_2_4_log_metric_project_ownership(client, "p").status == "FAIL"

    def test_2_7_vpc_metric_present_passes(self):
        client = MagicMock()
        m = MagicMock()
        m.filter = 'resource.type="compute.networks"'
        client.list_log_metrics.return_value = [m]
        assert _CHECKS.check_2_7_log_metric_vpc_changes(client, "p").status == "PASS"

    def test_2_7_vpc_metric_missing_fails(self):
        client = MagicMock()
        client.list_log_metrics.return_value = []
        assert _CHECKS.check_2_7_log_metric_vpc_changes(client, "p").status == "FAIL"

    def test_2_10_audit_metric_present_passes(self):
        client = MagicMock()
        m = MagicMock()
        m.filter = "protoPayload.serviceData.policyDelta.auditConfigDeltas.AuditConfig"
        client.list_log_metrics.return_value = [m]
        assert _CHECKS.check_2_10_log_metric_audit_config(client, "p").status == "PASS"

    def test_2_10_audit_metric_missing_fails(self):
        client = MagicMock()
        client.list_log_metrics.return_value = []
        assert _CHECKS.check_2_10_log_metric_audit_config(client, "p").status == "FAIL"

    def test_2_13_asset_inventory_reachable_passes(self):
        client = MagicMock()
        client.list_assets.return_value = iter([])
        assert _CHECKS.check_2_13_cloud_asset_inventory(client, "p").status == "PASS"

    def test_2_13_asset_inventory_error_fails(self):
        client = MagicMock()
        client.list_assets.side_effect = RuntimeError("Permission denied")
        f = _CHECKS.check_2_13_cloud_asset_inventory(client, "p")
        assert f.status == "FAIL"
        assert "Permission denied" in f.detail


# ---------------------------------------------------------------------------
# New Networking checks (3.10)
# ---------------------------------------------------------------------------


class TestDNSLogging:
    def test_3_10_unlogged_policy_fails(self):
        dns = MagicMock()
        p = MagicMock()
        p.name = "policy-1"
        p.enable_logging = False
        dns.list.return_value = [p]
        f = _CHECKS.check_3_10_dns_logging(dns, "p")
        assert f.status == "FAIL"
        assert f.resources == ["policy-1"]

    def test_3_10_logged_policy_passes(self):
        dns = MagicMock()
        p = MagicMock()
        p.name = "policy-1"
        p.enable_logging = True
        dns.list.return_value = [p]
        assert _CHECKS.check_3_10_dns_logging(dns, "p").status == "PASS"


# ---------------------------------------------------------------------------
# New Compute checks (4.5, 4.6, 4.7, 4.8)
# ---------------------------------------------------------------------------


def _instance(name, **attrs):
    inst = MagicMock()
    inst.name = name
    for k, v in attrs.items():
        setattr(inst, k, v)
    return inst


def _aggregated(zone, instances):
    scoped = MagicMock()
    scoped.instances = instances
    return [(zone, scoped)]


class TestComputeChecks:
    def test_4_5_unblocked_ssh_fails(self):
        compute = MagicMock()
        item = MagicMock()
        item.key = "block-project-ssh-keys"
        item.value = "false"
        meta = MagicMock()
        meta.items = [item]
        inst = _instance("vm-1", metadata=meta)
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        f = _CHECKS.check_4_5_block_project_wide_ssh(compute, "p")
        assert f.status == "FAIL"
        assert "vm-1" in f.resources[0]

    def test_4_5_blocked_ssh_passes(self):
        compute = MagicMock()
        item = MagicMock()
        item.key = "block-project-ssh-keys"
        item.value = "true"
        meta = MagicMock()
        meta.items = [item]
        inst = _instance("vm-1", metadata=meta)
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        assert _CHECKS.check_4_5_block_project_wide_ssh(compute, "p").status == "PASS"

    def test_4_6_no_confidential_compute_fails(self):
        compute = MagicMock()
        cc = MagicMock()
        cc.enable_confidential_compute = False
        inst = _instance("vm-1", confidential_instance_config=cc)
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        assert _CHECKS.check_4_6_confidential_vm(compute, "p").status == "FAIL"

    def test_4_6_confidential_compute_passes(self):
        compute = MagicMock()
        cc = MagicMock()
        cc.enable_confidential_compute = True
        inst = _instance("vm-1", confidential_instance_config=cc)
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        assert _CHECKS.check_4_6_confidential_vm(compute, "p").status == "PASS"

    def test_4_7_missing_vtpm_fails(self):
        compute = MagicMock()
        cfg = MagicMock()
        cfg.enable_vtpm = False
        cfg.enable_integrity_monitoring = True
        inst = _instance("vm-1", shielded_instance_config=cfg)
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        assert _CHECKS.check_4_7_shielded_vm(compute, "p").status == "FAIL"

    def test_4_7_full_shielded_vm_passes(self):
        compute = MagicMock()
        cfg = MagicMock()
        cfg.enable_vtpm = True
        cfg.enable_integrity_monitoring = True
        inst = _instance("vm-1", shielded_instance_config=cfg)
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        assert _CHECKS.check_4_7_shielded_vm(compute, "p").status == "PASS"

    def test_4_8_disk_without_cmek_fails(self):
        compute = MagicMock()
        disk = MagicMock()
        disk.device_name = "boot"
        disk.disk_encryption_key = None
        inst = _instance("vm-1", disks=[disk])
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        assert _CHECKS.check_4_8_disk_cmek(compute, "p").status == "FAIL"

    def test_4_8_disk_with_cmek_passes(self):
        compute = MagicMock()
        key = MagicMock()
        key.kms_key_name = "projects/p/locations/us/keyRings/r/cryptoKeys/k"
        disk = MagicMock()
        disk.device_name = "boot"
        disk.disk_encryption_key = key
        inst = _instance("vm-1", disks=[disk])
        compute.aggregated_list.return_value = _aggregated("zones/us-c1", [inst])
        assert _CHECKS.check_4_8_disk_cmek(compute, "p").status == "PASS"


# ---------------------------------------------------------------------------
# New Cloud SQL checks (6.1, 6.4)
# ---------------------------------------------------------------------------


def _sql_instance(name, ipv4_enabled=False, require_ssl=False):
    inst = MagicMock()
    inst.name = name
    settings = MagicMock()
    ip_cfg = MagicMock()
    ip_cfg.ipv4_enabled = ipv4_enabled
    ip_cfg.require_ssl = require_ssl
    settings.ip_configuration = ip_cfg
    inst.settings = settings
    return inst


class TestCloudSQLChecks:
    def test_6_1_public_ip_fails(self):
        sql = MagicMock()
        sql.list.return_value = [_sql_instance("db-1", ipv4_enabled=True)]
        f = _CHECKS.check_6_1_cloudsql_no_public_ip(sql, "p")
        assert f.status == "FAIL"
        assert "db-1" in f.resources

    def test_6_1_private_ip_passes(self):
        sql = MagicMock()
        sql.list.return_value = [_sql_instance("db-1", ipv4_enabled=False)]
        assert _CHECKS.check_6_1_cloudsql_no_public_ip(sql, "p").status == "PASS"

    def test_6_4_no_ssl_fails(self):
        sql = MagicMock()
        sql.list.return_value = [_sql_instance("db-1", require_ssl=False)]
        assert _CHECKS.check_6_4_cloudsql_require_ssl(sql, "p").status == "FAIL"

    def test_6_4_ssl_required_passes(self):
        sql = MagicMock()
        sql.list.return_value = [_sql_instance("db-1", require_ssl=True)]
        assert _CHECKS.check_6_4_cloudsql_require_ssl(sql, "p").status == "PASS"


# ---------------------------------------------------------------------------
# New BigQuery checks (7.1, 7.2)
# ---------------------------------------------------------------------------


class TestBigQueryChecks:
    def _bq_with_dataset(self, dataset):
        bq = MagicMock()
        bq.list_datasets.return_value = ["ds-ref"]
        bq.get_dataset.return_value = dataset
        return bq

    def test_7_1_public_dataset_fails(self):
        ds = MagicMock()
        ds.dataset_id = "public_ds"
        entry = MagicMock()
        entry.entity_id = "allUsers"
        ds.access_entries = [entry]
        bq = self._bq_with_dataset(ds)
        f = _CHECKS.check_7_1_bigquery_not_public(bq, "p")
        assert f.status == "FAIL"
        assert "public_ds" in f.resources

    def test_7_1_private_dataset_passes(self):
        ds = MagicMock()
        ds.dataset_id = "private_ds"
        entry = MagicMock()
        entry.entity_id = "user:owner@x.com"
        ds.access_entries = [entry]
        bq = self._bq_with_dataset(ds)
        assert _CHECKS.check_7_1_bigquery_not_public(bq, "p").status == "PASS"

    def test_7_2_no_default_cmek_fails(self):
        ds = MagicMock()
        ds.dataset_id = "ds_a"
        ds.default_encryption_configuration = None
        bq = self._bq_with_dataset(ds)
        assert _CHECKS.check_7_2_bigquery_default_cmek(bq, "p").status == "FAIL"

    def test_7_2_default_cmek_passes(self):
        ds = MagicMock()
        ds.dataset_id = "ds_a"
        enc = MagicMock()
        enc.kms_key_name = "projects/p/locations/us/keyRings/r/cryptoKeys/k"
        ds.default_encryption_configuration = enc
        bq = self._bq_with_dataset(ds)
        assert _CHECKS.check_7_2_bigquery_default_cmek(bq, "p").status == "PASS"


# ---------------------------------------------------------------------------
# Error-branch coverage for new checks
# ---------------------------------------------------------------------------


def test_new_checks_error_branches():
    crm = MagicMock()
    crm.get_iam_policy.side_effect = RuntimeError("boom")
    assert _CHECKS.check_1_5_separation_sa_admin(crm, "p").status == "ERROR"
    assert _CHECKS.check_1_11_separation_kms(crm, "p").status == "ERROR"

    op = MagicMock()
    op.get_org_policy.side_effect = RuntimeError("x")
    assert _CHECKS.check_1_6_disable_sa_key_creation(op, "p").status == "ERROR"

    kms = MagicMock()
    kms.list_key_rings.side_effect = RuntimeError("x")
    assert _CHECKS.check_1_12_kms_keys_not_public(kms, "p").status == "ERROR"

    api = MagicMock()
    api.list_keys.side_effect = RuntimeError("x")
    assert _CHECKS.check_1_13_api_keys_restricted(api, "p").status == "ERROR"

    contacts = MagicMock()
    contacts.list_contacts.side_effect = RuntimeError("x")
    assert _CHECKS.check_1_14_essential_contacts(contacts, "p").status == "ERROR"

    log = MagicMock()
    log.list_sinks.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_2_log_sink_configured(log, "p").status == "ERROR"
    log.list_log_metrics.side_effect = RuntimeError("x")
    assert _CHECKS.check_2_4_log_metric_project_ownership(log, "p").status == "ERROR"
    assert _CHECKS.check_2_7_log_metric_vpc_changes(log, "p").status == "ERROR"
    assert _CHECKS.check_2_10_log_metric_audit_config(log, "p").status == "ERROR"

    dns = MagicMock()
    dns.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_3_10_dns_logging(dns, "p").status == "ERROR"

    compute = MagicMock()
    compute.aggregated_list.side_effect = RuntimeError("x")
    assert _CHECKS.check_4_5_block_project_wide_ssh(compute, "p").status == "ERROR"
    assert _CHECKS.check_4_6_confidential_vm(compute, "p").status == "ERROR"
    assert _CHECKS.check_4_7_shielded_vm(compute, "p").status == "ERROR"
    assert _CHECKS.check_4_8_disk_cmek(compute, "p").status == "ERROR"

    sql = MagicMock()
    sql.list.side_effect = RuntimeError("x")
    assert _CHECKS.check_6_1_cloudsql_no_public_ip(sql, "p").status == "ERROR"
    assert _CHECKS.check_6_4_cloudsql_require_ssl(sql, "p").status == "ERROR"

    bq = MagicMock()
    bq.list_datasets.side_effect = RuntimeError("x")
    assert _CHECKS.check_7_1_bigquery_not_public(bq, "p").status == "ERROR"
    assert _CHECKS.check_7_2_bigquery_default_cmek(bq, "p").status == "ERROR"
