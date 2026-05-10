"""Additional coverage for CIS AWS Foundations v3.0 checks.

Targets the uncovered paths in src/checks.py:
    - check_1_3_stale_credentials (credential report parsing, stale+fresh)
    - check_1_4_key_rotation (old active key vs fresh key)
    - check_2_2_s3_logging (logging enabled vs disabled)
    - check_3_1_cloudtrail_multiregion (trail logging vs not)
    - check_3_2_cloudtrail_validation (log file validation)
    - check_3_3_cloudtrail_s3_not_public (trail bucket public-access block)
    - check_3_4_cloudwatch_alarms (empty / populated)
    - check_3_5_cloudtrail_kms_encryption
    - check_3_6_cloudtrail_data_events
    - check_6_1_guardduty_enabled
    - check_6_2_securityhub_enabled
    - _check_unrestricted_port (IPv6 path, cross-port range)
    - check_4_3_vpc_flow_logs (VPC w/ and w/o flow logs)
    - run_assessment (section filter + full run routing)
    - print_summary / _severity_color / _status_symbol / main CLI
    - ClientError branches via stubbed clients

Uses moto where supported; falls back to small stub clients for
services where moto coverage is thin (access key age, credential
report dates, cloudtrail bucket policy).
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_aws_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)
Finding = _CHECKS.Finding
RemediationTarget = _CHECKS.RemediationTarget


class _FakeIamExceptions:
    class NoSuchEntityException(ClientError):
        def __init__(self):
            super().__init__(
                {"Error": {"Code": "NoSuchEntity", "Message": "no"}}, "GetAccountPasswordPolicy"
            )


def _client_error(code: str, op: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, op)


# ---------------------------------------------------------------------------
# Section 1 — IAM — stale credentials + key rotation
# ---------------------------------------------------------------------------


def test_1_3_stale_credentials_parses_report_and_flags_old_users():
    now = datetime.now(UTC)
    stale_ts = (now - timedelta(days=120)).isoformat().replace("+00:00", "Z")
    fresh_ts = (now - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    report = (
        "user,arn,user_creation_time,password_enabled,password_last_used\n"
        f"stale-user,arn,2020-01-01T00:00:00+00:00,true,{stale_ts}\n"
        f"fresh-user,arn,2020-01-01T00:00:00+00:00,true,{fresh_ts}\n"
        "never,arn,2020-01-01T00:00:00+00:00,false,N/A\n"
    ).encode()

    iam = MagicMock()
    iam.generate_credential_report.return_value = None
    iam.get_credential_report.return_value = {"Content": report}

    f = _CHECKS.check_1_3_stale_credentials(iam)
    assert f.control_id == "1.3"
    assert f.status == "FAIL"
    assert "stale-user" in f.resources
    assert "fresh-user" not in f.resources
    assert "never" not in f.resources


def test_1_3_stale_credentials_all_fresh_passes():
    iam = MagicMock()
    iam.generate_credential_report.return_value = None
    iam.get_credential_report.return_value = {
        "Content": b"user,arn,user_creation_time,password_enabled,password_last_used\n"
        b"never,arn,2020-01-01T00:00:00+00:00,false,N/A\n"
    }
    f = _CHECKS.check_1_3_stale_credentials(iam)
    assert f.status == "PASS"


def test_1_3_stale_credentials_client_error_yields_error_finding():
    iam = MagicMock()
    iam.generate_credential_report.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_1_3_stale_credentials(iam)
    assert f.status == "ERROR"
    assert f.control_id == "1.3"


def test_1_4_key_rotation_flags_old_active_keys_only():
    now = datetime.now(UTC)
    iam = MagicMock()

    class _Paginator:
        def __init__(self, pages):
            self._pages = pages

        def paginate(self, **_):
            return iter(self._pages)

    def _get_paginator(op):
        if op == "list_users":
            return _Paginator([{"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}])
        if op == "list_access_keys":
            return _Paginator(
                [
                    {
                        "AccessKeyMetadata": [
                            {
                                "AccessKeyId": "AKIAOLD",
                                "Status": "Active",
                                "CreateDate": now - timedelta(days=120),
                            },
                            {
                                "AccessKeyId": "AKIAFRESH",
                                "Status": "Active",
                                "CreateDate": now - timedelta(days=10),
                            },
                            {
                                "AccessKeyId": "AKIAINACTIVE",
                                "Status": "Inactive",
                                "CreateDate": now - timedelta(days=400),
                            },
                        ]
                    }
                ]
            )
        raise AssertionError(op)

    iam.get_paginator.side_effect = _get_paginator
    f = _CHECKS.check_1_4_key_rotation(iam)
    assert f.status == "FAIL"
    assert any("AKIAOLD" in r for r in f.resources)
    assert not any("AKIAFRESH" in r for r in f.resources)
    assert not any("AKIAINACTIVE" in r for r in f.resources)


def test_1_4_key_rotation_client_error():
    iam = MagicMock()

    class _ErrPaginator:
        def paginate(self, **_):
            raise _client_error("AccessDenied")

    iam.get_paginator.return_value = _ErrPaginator()
    f = _CHECKS.check_1_4_key_rotation(iam)
    assert f.status == "ERROR"


def test_1_5_password_policy_missing_policy_fails():
    iam = MagicMock()
    iam.exceptions = _FakeIamExceptions()
    iam.get_account_password_policy.side_effect = iam.exceptions.NoSuchEntityException()
    f = _CHECKS.check_1_5_password_policy(iam)
    assert f.status == "FAIL"
    assert "No password policy" in f.detail


def test_1_5_password_policy_weak_policy_reports_issues():
    iam = MagicMock()
    iam.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 8,
            "RequireSymbols": False,
            "RequireNumbers": False,
            "RequireUppercaseCharacters": False,
            "RequireLowercaseCharacters": False,
        }
    }
    f = _CHECKS.check_1_5_password_policy(iam)
    assert f.status == "FAIL"
    assert "MinLength=8" in f.detail
    assert "RequireSymbols=false" in f.detail


def test_1_6_no_root_keys_fails_when_present():
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 1}}
    f = _CHECKS.check_1_6_no_root_keys(iam)
    assert f.status == "FAIL"
    assert "Root has 1" in f.detail


# ---------------------------------------------------------------------------
# Section 2 — Storage extras
# ---------------------------------------------------------------------------


@mock_aws
def test_2_1_s3_encryption_unencrypted_bucket_flagged():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="unenc")
    f = _CHECKS.check_2_1_s3_encryption(s3)
    # moto default: no encryption configured → ServerSideEncryptionConfigurationNotFoundError
    assert f.control_id == "2.1"
    assert "unenc" in f.resources or f.status == "PASS"


@mock_aws
def test_2_2_s3_logging_missing_flagged():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-logging")
    f = _CHECKS.check_2_2_s3_logging(s3)
    assert f.control_id == "2.2"
    assert f.status == "FAIL"
    assert "no-logging" in f.resources


def test_2_2_s3_logging_client_error():
    s3 = MagicMock()
    s3.list_buckets.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_2_2_s3_logging(s3)
    assert f.status == "ERROR"


@mock_aws
def test_2_3_s3_public_access_no_pab_flagged():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="nopab")
    f = _CHECKS.check_2_3_s3_public_access(s3)
    assert f.status == "FAIL"
    assert "nopab" in f.resources


@mock_aws
def test_2_4_s3_versioning_disabled_flagged():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="nov")
    f = _CHECKS.check_2_4_s3_versioning(s3)
    assert f.status == "FAIL"
    assert "nov" in f.resources


# ---------------------------------------------------------------------------
# Section 3 — Logging
# ---------------------------------------------------------------------------


def test_3_1_cloudtrail_multiregion_detects_active_trail():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"Name": "mr", "IsMultiRegionTrail": True},
            {"Name": "sr", "IsMultiRegionTrail": False},
        ]
    }
    ct.get_trail_status.return_value = {"IsLogging": True}
    f = _CHECKS.check_3_1_cloudtrail_multiregion(ct)
    assert f.status == "PASS"
    assert f.resources == ["mr"]


def test_3_1_cloudtrail_multiregion_no_trail_fails():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": []}
    f = _CHECKS.check_3_1_cloudtrail_multiregion(ct)
    assert f.status == "FAIL"


def test_3_1_cloudtrail_multiregion_client_error():
    ct = MagicMock()
    ct.describe_trails.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_3_1_cloudtrail_multiregion(ct)
    assert f.status == "ERROR"


def test_3_2_cloudtrail_validation_detects_missing_validation():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"Name": "bad", "LogFileValidationEnabled": False},
            {"Name": "good", "LogFileValidationEnabled": True},
        ]
    }
    f = _CHECKS.check_3_2_cloudtrail_validation(ct)
    assert f.status == "FAIL"
    assert f.resources == ["bad"]


def test_3_2_cloudtrail_validation_client_error():
    ct = MagicMock()
    ct.describe_trails.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_3_2_cloudtrail_validation(ct)
    assert f.status == "ERROR"


def test_3_3_cloudtrail_s3_not_public_with_pab_passes():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{"S3BucketName": "trailbkt"}]}
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    f = _CHECKS.check_3_3_cloudtrail_s3_not_public(ct, s3)
    assert f.status == "PASS"


def test_3_3_cloudtrail_s3_not_public_without_pab_fails():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{"S3BucketName": "trailbkt"}]}
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
    f = _CHECKS.check_3_3_cloudtrail_s3_not_public(ct, s3)
    assert f.status == "FAIL"
    assert "trailbkt" in f.resources


def test_3_3_cloudtrail_s3_ignores_trails_without_bucket():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "org-only"}]}
    s3 = MagicMock()
    f = _CHECKS.check_3_3_cloudtrail_s3_not_public(ct, s3)
    assert f.status == "PASS"
    s3.get_public_access_block.assert_not_called()


def test_3_3_cloudtrail_s3_outer_client_error():
    ct = MagicMock()
    ct.describe_trails.side_effect = _client_error("AccessDenied")
    s3 = MagicMock()
    f = _CHECKS.check_3_3_cloudtrail_s3_not_public(ct, s3)
    assert f.status == "ERROR"


def test_3_4_cloudwatch_alarms_empty_fails():
    cw = MagicMock()
    cw.describe_alarms.return_value = {"MetricAlarms": []}
    f = _CHECKS.check_3_4_cloudwatch_alarms(cw)
    assert f.status == "FAIL"


def test_3_4_cloudwatch_alarms_client_error():
    cw = MagicMock()
    cw.describe_alarms.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_3_4_cloudwatch_alarms(cw)
    assert f.status == "ERROR"


def test_3_5_cloudtrail_kms_encryption_detects_missing_kms():
    ct = MagicMock()
    ct.describe_trails.return_value = {
        "trailList": [
            {"Name": "bad"},
            {"Name": "good", "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc"},
        ]
    }
    f = _CHECKS.check_3_5_cloudtrail_kms_encryption(ct)
    assert f.status == "FAIL"
    assert f.resources == ["bad"]


def test_3_5_cloudtrail_kms_encryption_client_error():
    ct = MagicMock()
    ct.describe_trails.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_3_5_cloudtrail_kms_encryption(ct)
    assert f.status == "ERROR"


def test_3_6_cloudtrail_data_events_detects_missing_selectors():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "trail-a"}, {"Name": "trail-b"}]}
    ct.get_event_selectors.side_effect = [
        {"EventSelectors": [{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]}]}]},
        {"EventSelectors": []},
    ]
    f = _CHECKS.check_3_6_cloudtrail_data_events(ct)
    assert f.status == "FAIL"
    assert f.resources == ["trail-b"]


def test_3_6_cloudtrail_data_events_accepts_advanced_event_selectors():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "trail-a"}]}
    ct.get_event_selectors.return_value = {
        "AdvancedEventSelectors": [
            {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}]}
        ]
    }
    f = _CHECKS.check_3_6_cloudtrail_data_events(ct)
    assert f.status == "PASS"


def test_3_6_cloudtrail_data_events_client_error():
    ct = MagicMock()
    ct.describe_trails.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_3_6_cloudtrail_data_events(ct)
    assert f.status == "ERROR"


# ---------------------------------------------------------------------------
# Section 4 — Networking
# ---------------------------------------------------------------------------


def test_4_1_unrestricted_port_detects_ipv6_open_range():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1",
                "GroupName": "wideopen",
                "IpPermissions": [
                    {
                        "FromPort": 0,
                        "ToPort": 65535,
                        "IpProtocol": "tcp",
                        "IpRanges": [],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }
                ],
            }
        ]
    }
    f = _CHECKS.check_4_1_no_unrestricted_ssh(ec2)
    assert f.status == "FAIL"
    assert any("sg-1" in r for r in f.resources)


def test_4_1_unrestricted_port_client_error():
    ec2 = MagicMock()
    ec2.describe_security_groups.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_4_1_no_unrestricted_ssh(ec2)
    assert f.status == "ERROR"


def test_4_2_rdp_open_detected():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-rdp",
                "GroupName": "rdp",
                "IpPermissions": [
                    {
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
    }
    f = _CHECKS.check_4_2_no_unrestricted_rdp(ec2)
    assert f.status == "FAIL"


def test_4_3_vpc_flow_logs_missing_flagged():
    ec2 = MagicMock()
    ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-a"}, {"VpcId": "vpc-b"}]}
    ec2.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-a"}]}
    f = _CHECKS.check_4_3_vpc_flow_logs(ec2)
    assert f.status == "FAIL"
    assert f.resources == ["vpc-b"]


def test_4_3_vpc_flow_logs_all_covered_passes():
    ec2 = MagicMock()
    ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-a"}]}
    ec2.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-a"}]}
    f = _CHECKS.check_4_3_vpc_flow_logs(ec2)
    assert f.status == "PASS"


def test_4_3_vpc_flow_logs_client_error():
    ec2 = MagicMock()
    ec2.describe_vpcs.side_effect = _client_error("AccessDenied")
    f = _CHECKS.check_4_3_vpc_flow_logs(ec2)
    assert f.status == "ERROR"


# ---------------------------------------------------------------------------
# Section 6 — Security Services
# ---------------------------------------------------------------------------


def test_6_1_guardduty_enabled_passes_when_detector_present():
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": ["12abc34d567e8fa901bc2d34e56789f0"]}
    f = _CHECKS.check_6_1_guardduty_enabled(gd)
    assert f.status == "PASS"


def test_6_1_guardduty_enabled_fails_when_missing():
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": []}
    f = _CHECKS.check_6_1_guardduty_enabled(gd)
    assert f.status == "FAIL"


def test_6_2_securityhub_enabled_handles_missing_hub_as_fail():
    sh = MagicMock()
    sh.describe_hub.side_effect = _client_error("InvalidAccessException")
    f = _CHECKS.check_6_2_securityhub_enabled(sh)
    assert f.status == "FAIL"


def test_6_2_securityhub_enabled_passes_when_hub_exists():
    sh = MagicMock()
    sh.describe_hub.return_value = {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"}
    f = _CHECKS.check_6_2_securityhub_enabled(sh)
    assert f.status == "PASS"


# ---------------------------------------------------------------------------
# Runner / CLI / helpers
# ---------------------------------------------------------------------------


def _stub_clients() -> dict:
    iam = MagicMock()
    iam.exceptions = _FakeIamExceptions()
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
    }
    iam.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 16,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
        }
    }
    iam.generate_credential_report.return_value = None
    iam.get_credential_report.return_value = {"Content": b"user\n"}

    class _EmptyPaginator:
        def paginate(self, **_):
            return iter([{"Users": [], "PolicyNames": [], "AccessKeyMetadata": []}])

    iam.get_paginator.return_value = _EmptyPaginator()

    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": []}

    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": []}

    cw = MagicMock()
    cw.describe_alarms.return_value = {"MetricAlarms": [{"AlarmName": "a"}]}

    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {"SecurityGroups": []}
    ec2.describe_vpcs.return_value = {"Vpcs": []}
    ec2.describe_flow_logs.return_value = {"FlowLogs": []}
    gd = MagicMock()
    gd.list_detectors.return_value = {"DetectorIds": ["det-1"]}
    sh = MagicMock()
    sh.describe_hub.return_value = {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"}
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    aa = MagicMock()
    aa.list_analyzers.return_value = {"analyzers": []}

    # ec2 helpers used by added v3 checks (2.2.1, 5.4)
    ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}

    return {
        "iam": iam,
        "s3": s3,
        "ct": ct,
        "cw": cw,
        "ec2": ec2,
        "gd": gd,
        "sh": sh,
        "sts": sts,
        "aa": aa,
    }


def test_run_assessment_runs_all_sections_with_stubbed_clients(monkeypatch):
    monkeypatch.setattr(_CHECKS, "_get_clients", lambda region: _stub_clients())
    findings = _CHECKS.run_assessment(region="us-east-1")
    # 22 checks defined across 5 sections
    assert len(findings) == sum(len(v) for v in _CHECKS.SECTIONS.values())
    assert {f.section for f in findings} == {"iam", "storage", "logging", "networking", "security-services"}


def test_run_assessment_section_filter(monkeypatch):
    monkeypatch.setattr(_CHECKS, "_get_clients", lambda region: _stub_clients())
    findings = _CHECKS.run_assessment(section="networking")
    assert {f.section for f in findings} == {"networking"}


def test_get_clients_builds_boto3_session():
    with patch.object(_CHECKS.boto3, "Session") as session:
        clients = _CHECKS._get_clients("us-west-2")
    assert set(clients.keys()) == {"iam", "s3", "ct", "cw", "ec2", "gd", "sh", "sts", "aa"}
    session.assert_called_once_with(region_name="us-west-2")


def test_run_check_routes_by_function_name():
    clients = _stub_clients()
    # cloudtrail_s3 → two-arg
    clients["ct"].describe_trails.return_value = {"trailList": []}
    f = _CHECKS._run_check(_CHECKS.check_3_3_cloudtrail_s3_not_public, clients)
    assert f.control_id == "3.3"
    # iam check routing
    f = _CHECKS._run_check(_CHECKS.check_1_1_root_mfa, clients)
    assert f.control_id == "1.1"
    # s3 routing
    f = _CHECKS._run_check(_CHECKS.check_2_2_s3_logging, clients)
    assert f.control_id == "2.2"
    # ec2 routing
    f = _CHECKS._run_check(_CHECKS.check_4_3_vpc_flow_logs, clients)
    assert f.control_id == "4.3"
    # guardduty routing
    f = _CHECKS._run_check(_CHECKS.check_6_1_guardduty_enabled, clients)
    assert f.control_id == "6.1"
    # securityhub routing
    f = _CHECKS._run_check(_CHECKS.check_6_2_securityhub_enabled, clients)
    assert f.control_id == "6.2"


def test_severity_color_and_status_symbol_cover_all_keys():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        assert isinstance(_CHECKS._severity_color(sev), str)
    for status in ("PASS", "FAIL", "ERROR", "???"):
        assert isinstance(_CHECKS._status_symbol(status), str)


def test_print_summary_renders_all_sections():
    findings = [
        _CHECKS.Finding(
            control_id="1.1", title="t", section="iam", severity="CRITICAL", status="PASS"
        ),
        _CHECKS.Finding(
            control_id="2.1",
            title="t",
            section="storage",
            severity="HIGH",
            status="FAIL",
            detail="d",
            resources=[f"bucket-{i}" for i in range(10)],
        ),
        _CHECKS.Finding(
            control_id="3.4", title="t", section="logging", severity="MEDIUM", status="ERROR"
        ),
    ]
    buf = io.StringIO()
    with redirect_stdout(buf):
        _CHECKS.print_summary(findings)
    out = buf.getvalue()
    assert "IAM" in out and "STORAGE" in out and "LOGGING" in out
    assert "... and 5 more" in out
    assert "Score" in out


def test_main_json_ocsf_output_exits_zero_when_no_high_fails(monkeypatch):
    monkeypatch.setattr(_CHECKS, "_get_clients", lambda region: _stub_clients())
    monkeypatch.setattr(
        sys,
        "argv",
        ["checks.py", "--section", "networking", "--output", "json", "--output-format", "ocsf"],
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit as e:
            assert e.code == 0
    payload = json.loads(buf.getvalue())
    assert isinstance(payload, list)
    assert all(item.get("class_uid") == 2003 for item in payload)


def test_main_console_output_exits_one_on_critical_fail(monkeypatch):
    clients = _stub_clients()
    clients["iam"].get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
    }
    monkeypatch.setattr(_CHECKS, "_get_clients", lambda region: clients)
    monkeypatch.setattr(sys, "argv", ["checks.py", "--section", "iam"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit as e:
            assert e.code == 1


def test_main_native_json_output(monkeypatch):
    monkeypatch.setattr(_CHECKS, "_get_clients", lambda region: _stub_clients())
    monkeypatch.setattr(
        sys, "argv", ["checks.py", "--section", "storage", "--output", "json"]
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit:
            pass
    payload = json.loads(buf.getvalue())
    assert isinstance(payload, list)


def test_paginate_fallback_when_paginator_unavailable():
    client = MagicMock()
    client.get_paginator.side_effect = Exception("no paginator")
    client.list_users = MagicMock(return_value={"Users": [{"UserName": "x"}]})
    items = _CHECKS._paginate(client, "list_users", "Users")
    assert items == [{"UserName": "x"}]


def test_build_remediation_targets_for_supported_storage_control():
    s3 = MagicMock()
    s3.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
    clients = {"s3": s3, "ec2": MagicMock(), "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}

    findings = [
        Finding(
            control_id="2.3",
            title="S3 public access blocked",
            section="storage",
            severity="CRITICAL",
            status="FAIL",
            resources=["public-bucket"],
        )
    ]

    targets = _CHECKS.build_remediation_targets(findings, clients=clients, region="us-east-1")
    assert len(targets) == 1
    target, protected_reason = targets[0]
    assert protected_reason is None
    assert target.action == "put_public_access_block"
    assert target.resource_id == "public-bucket"
    assert target.account_id == "123456789012"


def test_build_remediation_targets_marks_protected_bucket(monkeypatch):
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_PROTECTED_BUCKETS", "protected-bucket")
    s3 = MagicMock()
    s3.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
    clients = {"s3": s3, "ec2": MagicMock(), "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}

    findings = [
        Finding(
            control_id="2.4",
            title="S3 versioning enabled",
            section="storage",
            severity="MEDIUM",
            status="FAIL",
            resources=["protected-bucket"],
        )
    ]

    targets = _CHECKS.build_remediation_targets(findings, clients=clients, region="us-east-1")
    assert len(targets) == 1
    _, protected_reason = targets[0]
    assert "PROTECTED_BUCKETS" in protected_reason


def test_build_remediation_targets_for_open_ssh_rule():
    ec2 = MagicMock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1234",
                "GroupName": "open-ssh",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
    }
    clients = {"s3": MagicMock(), "ec2": ec2, "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}

    findings = [
        Finding(
            control_id="4.1",
            title="No unrestricted SSH",
            section="networking",
            severity="HIGH",
            status="FAIL",
            resources=["sg-1234 (open-ssh)"],
        )
    ]

    targets = _CHECKS.build_remediation_targets(findings, clients=clients, region="us-east-1")
    assert len(targets) == 1
    target, protected_reason = targets[0]
    assert protected_reason is None
    assert target.action == "revoke_security_group_ingress"
    assert target.parameters["cidrs"] == ["0.0.0.0/0"]


def test_build_remediation_records_dry_run_plans_supported_controls():
    s3 = MagicMock()
    s3.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
    clients = {"s3": s3, "ec2": MagicMock(), "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    findings = [
        Finding(
            control_id="2.1",
            title="S3 default encryption",
            section="storage",
            severity="HIGH",
            status="FAIL",
            resources=["unencrypted-bucket"],
        ),
        Finding(
            control_id="3.1",
            title="CloudTrail multi-region",
            section="logging",
            severity="CRITICAL",
            status="FAIL",
            resources=["trail-a"],
        ),
    ]

    records = _CHECKS.build_remediation_records(
        findings,
        clients=clients,
        region="us-east-1",
        apply=False,
    )
    assert len(records) == 1
    assert records[0]["record_type"] == "remediation_plan"
    assert records[0]["control_id"] == "2.1"
    assert records[0]["status"] == "planned"


def test_build_remediation_records_apply_requires_hitl_envs():
    clients = {"s3": MagicMock(), "ec2": MagicMock(), "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    findings = [
        Finding(
            control_id="2.3",
            title="S3 public access blocked",
            section="storage",
            severity="CRITICAL",
            status="FAIL",
            resources=["public-bucket"],
        )
    ]
    try:
        _CHECKS.build_remediation_records(findings, clients=clients, region="us-east-1", apply=True)
    except ValueError as exc:
        assert "INCIDENT_ID" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_build_remediation_records_apply_executes_and_audits(monkeypatch):
    class _FakeAudit:
        def __init__(self, *args, **kwargs):
            self.writes = []

        def record(self, *, target, status, detail, incident_id, approver):
            self.writes.append((target.resource_id, status, incident_id, approver))
            return {"row_uid": "row-1", "s3_evidence_uri": "s3://bucket/evidence.json"}

    s3 = MagicMock()
    s3.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
    clients = {"s3": s3, "ec2": MagicMock(), "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_APPROVER", "alice@security")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_ALLOWED_ACCOUNT_IDS", "123456789012")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_AUDIT_DYNAMODB_TABLE", "audit-table")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_AUDIT_BUCKET", "audit-bucket")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_AUDIT_KMS_KEY_ARN", "arn:aws:kms:::key/123")
    monkeypatch.setattr(_CHECKS, "DualAuditWriter", _FakeAudit)

    findings = [
        Finding(
            control_id="2.4",
            title="S3 versioning enabled",
            section="storage",
            severity="MEDIUM",
            status="FAIL",
            resources=["bucket-a"],
        )
    ]

    records = _CHECKS.build_remediation_records(
        findings,
        clients=clients,
        region="us-east-1",
        apply=True,
        confirm=_CHECKS.CONFIRM_APPLY_PHRASE,
    )
    assert records[0]["record_type"] == "remediation_action"
    assert records[0]["status"] == "success"
    assert records[0]["incident_id"] == "INC-1"
    assert records[0]["approver"] == "alice@security"
    clients["s3"].put_bucket_versioning.assert_called_once()


def test_build_remediation_records_apply_requires_explicit_account_allowlist(monkeypatch):
    clients = {"s3": MagicMock(), "ec2": MagicMock(), "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_APPROVER", "alice@security")

    findings = [
        Finding(
            control_id="2.3",
            title="S3 public access blocked",
            section="storage",
            severity="CRITICAL",
            status="FAIL",
            resources=["public-bucket"],
        )
    ]

    try:
        _CHECKS.build_remediation_records(
            findings,
            clients=clients,
            region="us-east-1",
            apply=True,
            confirm=_CHECKS.CONFIRM_APPLY_PHRASE,
        )
    except ValueError as exc:
        assert "ALLOWED_ACCOUNT_IDS" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_build_remediation_records_apply_rejects_wrong_account_allowlist(monkeypatch):
    clients = {"s3": MagicMock(), "ec2": MagicMock(), "sts": MagicMock()}
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_APPROVER", "alice@security")
    monkeypatch.setenv("CSPM_AWS_AUTOREMEDIATE_ALLOWED_ACCOUNT_IDS", "210987654321")

    findings = [
        Finding(
            control_id="2.3",
            title="S3 public access blocked",
            section="storage",
            severity="CRITICAL",
            status="FAIL",
            resources=["public-bucket"],
        )
    ]

    try:
        _CHECKS.build_remediation_records(
            findings,
            clients=clients,
            region="us-east-1",
            apply=True,
            confirm=_CHECKS.CONFIRM_APPLY_PHRASE,
        )
    except ValueError as exc:
        assert "123456789012" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_main_auto_remediate_json_wraps_findings_and_remediation(monkeypatch):
    clients = _stub_clients()
    clients["s3"].list_buckets.return_value = {"Buckets": [{"Name": "public-bucket"}]}
    clients["s3"].get_bucket_encryption.side_effect = _client_error(
        "ServerSideEncryptionConfigurationNotFoundError"
    )
    clients["s3"].get_bucket_logging.return_value = {}
    clients["s3"].get_public_access_block.side_effect = _client_error("NoSuchPublicAccessBlockConfiguration")
    clients["s3"].get_bucket_versioning.return_value = {}
    clients["s3"].get_bucket_tagging = MagicMock(side_effect=_client_error("NoSuchTagSet"))
    monkeypatch.setattr(_CHECKS, "_get_clients", lambda region: clients)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "checks.py",
            "--section",
            "storage",
            "--output",
            "json",
            "--auto-remediate",
        ],
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            _CHECKS.main()
        except SystemExit:
            pass
    payload = json.loads(buf.getvalue())
    assert "findings" in payload
    assert "remediation" in payload
    assert payload["remediation"]
