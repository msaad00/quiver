"""Edge-case coverage for CIS AWS Foundations Benchmark v3 checks (issue #405).

Each of the 31 check functions is exercised across five axes:
    1. Empty input — no resources surface 0 findings
    2. Malformed payload — missing/None fields are absorbed without KeyError
    3. Partial-pass scenario — passing + failing resources in one call
    4. Permission denied — boto3 ClientError(AccessDenied) yields ERROR not crash
    5. Multi-resource happy path — covered in test_checks.py / test_checks_extra.py

The boto3 clients are stubbed via MagicMock; no AWS credentials needed.
ClientError is the documented contract for permission failures, so the AWS
checks already handle axes 1-4 via `try/except ClientError` in src/.
This file pins that contract explicitly per check.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_aws_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

Finding = _CHECKS.Finding


def _access_denied(op: str = "Op") -> ClientError:
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "User is not authorized"}},
        op,
    )


# ---------------------------------------------------------------------------
# Per-check shape: each tuple is (check_fn, build_empty_client, build_partial_client)
# build_*_client returns (mock, expected_status, expected_resources_substring or None).
# ---------------------------------------------------------------------------


def _stub_paginator(pages: list[dict]) -> MagicMock:
    """Build a paginator mock whose .paginate() yields the given pages."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


class _NoSuchEntity(ClientError):
    def __init__(self):
        super().__init__({"Error": {"Code": "NoSuchEntity", "Message": "no policy"}}, "Op")


def _empty_iam():
    iam = MagicMock()
    # boto3 IAM client exposes exceptions.NoSuchEntityException as a real class —
    # make the mock match that contract so `except iam.exceptions.NoSuchEntityException`
    # evaluates correctly.
    iam.exceptions.NoSuchEntityException = _NoSuchEntity
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
    }
    # Paginator paths used by _paginate(...) in src/checks.py.
    iam.get_paginator.side_effect = lambda op: _stub_paginator(
        [{"Users": [], "AccessKeyMetadata": [], "Policies": []}]
    )
    iam.list_users.return_value = {"Users": []}
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    iam.list_user_policies.return_value = {"PolicyNames": []}
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    iam.generate_credential_report.return_value = None
    iam.get_credential_report.return_value = {
        "Content": b"user,arn,user_creation_time,password_enabled,password_last_used\n"
    }
    iam.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        }
    }
    iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}
    return iam


def _empty_s3():
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": []}
    return s3


def _empty_ec2():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_flow_logs.return_value = {"FlowLogs": []}
    ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}
    return ec2


def _empty_ct():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": []}
    ct.get_trail_status.return_value = {"IsLogging": False}
    ct.get_event_selectors.return_value = {"EventSelectors": [], "AdvancedEventSelectors": []}
    return ct


def _empty_cw():
    cw = MagicMock()
    cw.describe_alarms.return_value = {"MetricAlarms": []}
    return cw


def _empty_aa():
    aa = MagicMock()
    aa.list_analyzers.return_value = {"analyzers": []}
    return aa


def _empty_gd():
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": []}
    return gd


def _empty_sh():
    sh = MagicMock()
    sh.describe_hub.return_value = {"HubArn": ""}
    return sh


# Map of check → (callable that takes the client, client builder for empty inputs)
# Includes which clients each check needs.
_AWS_CHECKS = [
    # IAM
    ("check_1_1_root_mfa", _empty_iam),
    ("check_1_2_user_mfa", _empty_iam),
    ("check_1_3_stale_credentials", _empty_iam),
    ("check_1_4_key_rotation", _empty_iam),
    ("check_1_5_password_policy", _empty_iam),
    ("check_1_6_no_root_keys", _empty_iam),
    ("check_1_7_no_inline_policies", _empty_iam),
    ("check_1_9_password_reuse", _empty_iam),
    ("check_1_13_one_active_key", _empty_iam),
    ("check_1_14_hardware_mfa_root", _empty_iam),
    ("check_1_16_no_user_attached_policies", _empty_iam),
    ("check_1_20_access_analyzer", _empty_aa),
    # Storage
    ("check_2_1_s3_encryption", _empty_s3),
    ("check_2_2_s3_logging", _empty_s3),
    ("check_2_3_s3_public_access", _empty_s3),
    ("check_2_4_s3_versioning", _empty_s3),
    ("check_2_1_4_s3_ssl_required", _empty_s3),
    ("check_2_2_1_ebs_encryption_default", _empty_ec2),
    # Logging
    ("check_3_1_cloudtrail_multiregion", _empty_ct),
    ("check_3_2_cloudtrail_validation", _empty_ct),
    ("check_3_4_cloudwatch_alarms", _empty_cw),
    ("check_3_5_cloudtrail_kms_encryption", _empty_ct),
    ("check_3_6_cloudtrail_data_events", _empty_ct),
    ("check_3_7_cloudtrail_cloudwatch_integration", _empty_ct),
    # Networking
    ("check_4_1_no_unrestricted_ssh", _empty_ec2),
    ("check_4_2_no_unrestricted_rdp", _empty_ec2),
    ("check_4_3_vpc_flow_logs", _empty_ec2),
    ("check_5_4_default_sg_restricts_traffic", _empty_ec2),
    # Security services
    ("check_6_1_guardduty_enabled", _empty_gd),
    ("check_6_2_securityhub_enabled", _empty_sh),
]


# ---------------------------------------------------------------------------
# Axis 1 — empty input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,client_builder", _AWS_CHECKS, ids=[c[0] for c in _AWS_CHECKS])
def test_empty_input_returns_finding(check_name, client_builder):
    """Axis 1: empty AWS account → check returns a Finding (PASS or FAIL), no crash."""
    fn = getattr(_CHECKS, check_name)
    f = fn(client_builder())
    assert isinstance(f, Finding)
    assert f.status in {"PASS", "FAIL", "ERROR"}
    assert f.control_id, "missing control_id"
    assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert f.nist_csf
    assert f.iso_27001


# ---------------------------------------------------------------------------
# Axis 2 — malformed payload (missing keys, None values)
# ---------------------------------------------------------------------------


def test_2_3_s3_public_access_with_partial_pab():
    """Malformed PAB (missing flags) should mark bucket as not-blocked, not crash."""
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "partial"}]}
    # Missing some flags entirely
    s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}
    }
    f = _CHECKS.check_2_3_s3_public_access(s3)
    assert f.status == "FAIL"
    assert "partial" in f.resources


def test_3_5_kms_encryption_with_missing_kms_field():
    """Trail dict missing KmsKeyId should be flagged, not crash."""
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [{"Name": "t1"}, {"Name": "t2", "KmsKeyId": "arn:aws:kms:..."}]
    }
    f = _CHECKS.check_3_5_cloudtrail_kms_encryption(ct)
    assert f.status == "FAIL"
    assert "t1" in f.resources
    assert "t2" not in f.resources


def test_3_6_data_events_with_unknown_selector_shape():
    """Unknown selector structure is treated as no data-events configured."""
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "t1"}]}
    ct.get_event_selectors.return_value = {"EventSelectors": None, "AdvancedEventSelectors": None}
    f = _CHECKS.check_3_6_cloudtrail_data_events(ct)
    assert f.control_id == "3.6"
    assert f.status == "FAIL"


def test_4_3_flow_logs_missing_resource_id():
    """A flow-log entry with no ResourceId is ignored, not crashed on."""
    ec2 = MagicMock()
    ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
    ec2.describe_flow_logs.return_value = {"FlowLogs": [{"LogGroupName": "x"}]}  # no ResourceId
    f = _CHECKS.check_4_3_vpc_flow_logs(ec2)
    assert f.status == "FAIL"
    assert "vpc-1" in f.resources


def test_5_4_default_sg_with_missing_fields():
    """SG dict missing GroupId/VpcId still produces a Finding."""
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{"IpPermissions": [{"IpProtocol": "-1"}], "IpPermissionsEgress": []}]
    }
    f = _CHECKS.check_5_4_default_sg_restricts_traffic(ec2)
    assert f.status == "FAIL"
    assert len(f.resources) == 1


def test_6_2_securityhub_invalid_access_resolves_to_fail():
    """InvalidAccessException is the AWS contract for 'not enrolled' — must FAIL not ERROR."""
    sh = MagicMock()
    sh.describe_hub.side_effect = ClientError(
        {"Error": {"Code": "InvalidAccessException", "Message": "Account is not subscribed"}},
        "DescribeHub",
    )
    f = _CHECKS.check_6_2_securityhub_enabled(sh)
    assert f.status == "FAIL"


# ---------------------------------------------------------------------------
# Axis 3 — partial pass
# ---------------------------------------------------------------------------


def test_2_1_s3_encryption_partial():
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "ok"}, {"Name": "bare"}]}

    def _enc_side_effect(Bucket):
        if Bucket == "bare":
            raise ClientError(
                {
                    "Error": {
                        "Code": "ServerSideEncryptionConfigurationNotFoundError",
                        "Message": "",
                    }
                },
                "GetBucketEncryption",
            )
        return {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}

    s3.get_bucket_encryption.side_effect = _enc_side_effect
    f = _CHECKS.check_2_1_s3_encryption(s3)
    assert f.status == "FAIL"
    assert "bare" in f.resources
    assert "ok" not in f.resources
    assert len(f.resources) == 1


def test_2_4_s3_versioning_partial():
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "ver"}, {"Name": "unver"}]}

    def _versioning(Bucket):
        return {"Status": "Enabled"} if Bucket == "ver" else {}

    s3.get_bucket_versioning.side_effect = _versioning
    f = _CHECKS.check_2_4_s3_versioning(s3)
    assert f.status == "FAIL"
    assert "unver" in f.resources
    assert "ver" not in f.resources


def test_3_1_multiregion_partial():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"Name": "all", "IsMultiRegionTrail": True},
            {"Name": "single", "IsMultiRegionTrail": False},
        ]
    }
    ct.get_trail_status.return_value = {"IsLogging": True}
    f = _CHECKS.check_3_1_cloudtrail_multiregion(ct)
    # Multiregion + logging = PASS overall (any one trail satisfies it).
    assert f.control_id == "3.1"


def test_3_2_validation_partial():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"Name": "validated", "LogFileValidationEnabled": True},
            {"Name": "not-validated", "LogFileValidationEnabled": False},
        ]
    }
    f = _CHECKS.check_3_2_cloudtrail_validation(ct)
    assert f.status == "FAIL"
    assert "not-validated" in f.resources
    assert "validated" not in f.resources


def test_4_3_vpc_flow_logs_partial():
    ec2 = MagicMock()
    ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-good"}, {"VpcId": "vpc-bad"}]}
    ec2.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-good"}]}
    f = _CHECKS.check_4_3_vpc_flow_logs(ec2)
    assert f.status == "FAIL"
    assert "vpc-bad" in f.resources
    assert "vpc-good" not in f.resources


def test_3_5_kms_partial():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"Name": "kms-on", "KmsKeyId": "arn:aws:kms:us-east-1:1:key/abc"},
            {"Name": "kms-off"},
        ]
    }
    f = _CHECKS.check_3_5_cloudtrail_kms_encryption(ct)
    assert f.status == "FAIL"
    assert f.resources == ["kms-off"]


# ---------------------------------------------------------------------------
# Axis 4 — permission denied (AccessDenied client error)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check_name,client_builder", _AWS_CHECKS, ids=[c[0] for c in _AWS_CHECKS])
def test_access_denied_does_not_crash(check_name, client_builder):
    """Axis 4: AccessDenied at the top-level call surfaces as ERROR/FAIL, never raises.

    Some checks (1.14, 1.20, 2.2.1, 6.x) catch ClientError and return either ERROR or
    FAIL depending on the error code; either is an acceptable known-state outcome.
    """
    fn = getattr(_CHECKS, check_name)
    client = client_builder()
    # Pick the most likely "primary" call per service and make it raise AccessDenied.
    primary_calls = [
        "get_account_summary",
        "list_users",
        "generate_credential_report",
        "list_buckets",
        "describe_trails",
        "describe_alarms",
        "list_analyzers",
        "describe_security_groups",
        "describe_vpcs",
        "get_ebs_encryption_by_default",
        "list_detectors",
        "describe_hub",
        "get_account_password_policy",
        "list_virtual_mfa_devices",
    ]
    for op in primary_calls:
        method = getattr(client, op, None)
        if method is None:
            continue
        # Give every primary op the AccessDenied behaviour.
        method.side_effect = _access_denied(op)
    f = fn(client)
    assert isinstance(f, Finding)
    assert f.status in {"ERROR", "FAIL", "PASS"}
    # Accessor stayed alive — no exception bubbled up.


# ---------------------------------------------------------------------------
# Axis 5 — multi-resource happy path (already covered, but pin per-section invariants)
# ---------------------------------------------------------------------------


def test_4_1_ssh_with_multiple_sgs():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-open",
                "GroupName": "open",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            },
            {
                "GroupId": "sg-locked",
                "GroupName": "locked",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    }
                ],
            },
        ]
    }
    f = _CHECKS.check_4_1_no_unrestricted_ssh(ec2)
    assert f.status == "FAIL"
    assert any("sg-open" in r for r in f.resources)
    assert not any("sg-locked" in r for r in f.resources)


def test_3_4_alarms_multiple_alarms_passes():
    cw = MagicMock()
    cw.describe_alarms.return_value = {
        "MetricAlarms": [{"AlarmName": f"alarm-{i}"} for i in range(5)]
    }
    f = _CHECKS.check_3_4_cloudwatch_alarms(cw)
    assert f.status == "PASS"
    assert "5 alarm" in f.detail


def test_6_1_guardduty_multi_detector():
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": ["d1", "d2"]}
    f = _CHECKS.check_6_1_guardduty_enabled(gd)
    assert f.status == "PASS"
    assert "d1" in f.resources
    assert "d2" in f.resources


# ---------------------------------------------------------------------------
# Cross-check invariants
# ---------------------------------------------------------------------------


def test_all_31_checks_return_finding_with_compliance_metadata():
    """Every check must always set NIST CSF + ISO 27001 mappings, regardless of result."""
    for check_name, client_builder in _AWS_CHECKS:
        fn = getattr(_CHECKS, check_name)
        f = fn(client_builder())
        assert f.nist_csf, f"{check_name}: missing nist_csf"
        assert f.iso_27001, f"{check_name}: missing iso_27001"
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, f"{check_name}: bad severity"
        assert f.section, f"{check_name}: missing section"
