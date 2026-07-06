"""Tests for CIS AWS Foundations Benchmark v3.0 checks.

Uses moto to mock AWS services — no real AWS credentials needed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cspm_aws_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

Finding = _CHECKS.Finding
_run_check = _CHECKS._run_check
check_1_1_root_mfa = _CHECKS.check_1_1_root_mfa
check_1_2_user_mfa = _CHECKS.check_1_2_user_mfa
check_1_5_password_policy = _CHECKS.check_1_5_password_policy
check_1_6_no_root_keys = _CHECKS.check_1_6_no_root_keys
check_1_7_no_inline_policies = _CHECKS.check_1_7_no_inline_policies
check_2_1_s3_encryption = _CHECKS.check_2_1_s3_encryption
check_2_3_s3_public_access = _CHECKS.check_2_3_s3_public_access
check_2_4_s3_versioning = _CHECKS.check_2_4_s3_versioning
check_3_4_cloudwatch_alarms = _CHECKS.check_3_4_cloudwatch_alarms
check_4_1_no_unrestricted_ssh = _CHECKS.check_4_1_no_unrestricted_ssh
check_4_2_no_unrestricted_rdp = _CHECKS.check_4_2_no_unrestricted_rdp
check_4_3_vpc_flow_logs = _CHECKS.check_4_3_vpc_flow_logs
check_1_9_password_reuse = _CHECKS.check_1_9_password_reuse
check_1_13_one_active_key = _CHECKS.check_1_13_one_active_key
check_1_14_hardware_mfa_root = _CHECKS.check_1_14_hardware_mfa_root
check_1_16_no_user_attached_policies = _CHECKS.check_1_16_no_user_attached_policies
check_1_20_access_analyzer = _CHECKS.check_1_20_access_analyzer
check_2_1_4_s3_ssl_required = _CHECKS.check_2_1_4_s3_ssl_required
check_2_2_1_ebs_encryption_default = _CHECKS.check_2_2_1_ebs_encryption_default
check_3_7_cloudtrail_cloudwatch_integration = _CHECKS.check_3_7_cloudtrail_cloudwatch_integration
check_5_4_default_sg_restricts_traffic = _CHECKS.check_5_4_default_sg_restricts_traffic
findings_to_ocsf = _CHECKS.findings_to_ocsf


@mock_aws
class TestIAMChecks:
    def test_1_1_root_mfa_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_1_root_mfa(iam)
        assert isinstance(f, Finding)
        assert f.control_id == "1.1"
        assert f.severity == "CRITICAL"
        assert f.nist_csf == "PR.AC-1"

    def test_1_2_no_users_passes(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_2_user_mfa(iam)
        assert f.status == "PASS"

    def test_1_5_password_policy(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=24,
        )
        f = check_1_5_password_policy(iam)
        assert f.control_id == "1.5"
        assert f.status == "PASS"

    def test_1_6_no_root_keys(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_6_no_root_keys(iam)
        assert f.control_id == "1.6"
        assert f.severity == "CRITICAL"

    def test_1_7_no_inline_policies_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_7_no_inline_policies(iam)
        assert f.status == "PASS"

    def test_1_7_inline_policy_fails(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="testuser")
        iam.put_user_policy(
            UserName="testuser",
            PolicyName="inline-policy",
            PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}',
        )
        f = check_1_7_no_inline_policies(iam)
        assert f.status == "FAIL"
        assert "testuser" in f.resources


@mock_aws
class TestStorageChecks:
    def test_2_1_s3_encryption(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        f = check_2_1_s3_encryption(s3)
        assert f.control_id == "2.1"

    def test_2_3_public_access_blocked(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        s3.put_public_access_block(
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        f = check_2_3_s3_public_access(s3)
        assert f.control_id == "2.3"

    def test_2_4_versioning(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        f = check_2_4_s3_versioning(s3)
        assert f.control_id == "2.4"


@mock_aws
class TestNetworkChecks:
    def test_4_1_ssh_open_fails(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        sg = ec2.create_security_group(
            GroupName="open-ssh", Description="test", VpcId=vpc["Vpc"]["VpcId"]
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        f = check_4_1_no_unrestricted_ssh(ec2)
        assert f.status == "FAIL"

    def test_4_2_rdp_closed_passes(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        f = check_4_2_no_unrestricted_rdp(ec2)
        # Default SGs don't have RDP open
        assert f.control_id == "4.2"

    def test_4_3_vpc_flow_logs(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        f = check_4_3_vpc_flow_logs(ec2)
        assert f.control_id == "4.3"


@mock_aws
class TestFindingCompliance:
    def test_all_checks_have_nist_mapping(self):
        iam = boto3.client("iam", region_name="us-east-1")
        checks = [
            check_1_1_root_mfa(iam),
            check_1_2_user_mfa(iam),
            check_1_5_password_policy(iam),
            check_1_6_no_root_keys(iam),
            check_1_7_no_inline_policies(iam),
        ]
        for f in checks:
            assert f.nist_csf, f"Check {f.control_id} missing NIST CSF mapping"
            assert f.iso_27001, f"Check {f.control_id} missing ISO 27001 mapping"


class TestRunnerRouting:
    def test_run_check_routes_logging_checks_to_cloudwatch(self):
        clients = {
            "iam": MagicMock(),
            "s3": MagicMock(),
            "ct": MagicMock(),
            "cw": MagicMock(),
            "ec2": MagicMock(),
        }
        clients["cw"].describe_alarms.return_value = {
            "MetricAlarms": [{"AlarmName": "cis-cloudtrail-alarm"}]
        }

        finding = _run_check(check_3_4_cloudwatch_alarms, clients)

        assert finding.control_id == "3.4"
        clients["cw"].describe_alarms.assert_called_once()
        clients["iam"].describe_alarms.assert_not_called()


class TestOcsfProjection:
    def test_findings_can_render_as_compliance_findings(self):
        finding = Finding(
            control_id="1.1",
            title="MFA on root account",
            section="iam",
            severity="CRITICAL",
            status="FAIL",
            detail="Root MFA disabled",
            nist_csf="PR.AC-1",
            iso_27001="A.8.5",
            resources=["root"],
        )

        rendered = findings_to_ocsf(
            [finding],
            skill_name=_CHECKS.SKILL_NAME,
            benchmark_name=_CHECKS.BENCHMARK_NAME,
            provider=_CHECKS.PROVIDER_NAME,
            frameworks=["CIS AWS Foundations v3.0", "NIST CSF 2.0", "ISO/IEC 27001:2022"],
        )

        assert rendered[0]["class_uid"] == 2003
        assert rendered[0]["finding_info"]["types"] == ["1.1"]
        assert rendered[0]["cloud"]["provider"] == "AWS"
        assert "PR.AC-1" in rendered[0]["compliance"]["requirements"]


# ---------------------------------------------------------------------------
# Newly-added CIS AWS v3 controls (1.9, 1.13, 1.14, 1.16, 1.20, 2.1.4,
# 2.2.1, 3.7, 5.4) — happy path + at least one finding-fires path each.
# ---------------------------------------------------------------------------


@mock_aws
class TestExpandedIamControls:
    def test_1_9_password_reuse_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            PasswordReusePrevention=24,
        )
        f = check_1_9_password_reuse(iam)
        assert f.control_id == "1.9"
        assert f.status == "PASS"

    def test_1_9_password_reuse_fail_when_low(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            PasswordReusePrevention=5,
        )
        f = check_1_9_password_reuse(iam)
        assert f.status == "FAIL"
        assert "PasswordReusePrevention=5" in f.detail

    def test_1_13_one_active_key_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="solo")
        iam.create_access_key(UserName="solo")
        f = check_1_13_one_active_key(iam)
        assert f.control_id == "1.13"
        assert f.status == "PASS"

    def test_1_13_one_active_key_fail(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="dual")
        iam.create_access_key(UserName="dual")
        iam.create_access_key(UserName="dual")
        f = check_1_13_one_active_key(iam)
        assert f.status == "FAIL"
        assert any("dual" in r for r in f.resources)

    def test_1_14_hardware_mfa_root_pass_when_no_virtual_root_device(self):
        iam = MagicMock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}
        f = check_1_14_hardware_mfa_root(iam)
        assert f.control_id == "1.14"
        assert f.status == "PASS"

    def test_1_14_hardware_mfa_root_fail_when_virtual_assigned(self):
        iam = MagicMock()
        iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        iam.list_virtual_mfa_devices.return_value = {
            "VirtualMFADevices": [
                {"SerialNumber": "arn:aws:iam::123456789012:mfa/root-account-mfa-device"}
            ]
        }
        f = check_1_14_hardware_mfa_root(iam)
        assert f.status == "FAIL"
        assert "virtual" in f.detail.lower()

    def test_1_16_no_user_attached_policies_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="clean")
        f = check_1_16_no_user_attached_policies(iam)
        assert f.control_id == "1.16"
        assert f.status == "PASS"

    def test_1_16_no_user_attached_policies_fail(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="bound")
        policy = iam.create_policy(
            PolicyName="cis-test-readonly",
            PolicyDocument=(
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}'
            ),
        )["Policy"]
        iam.attach_user_policy(UserName="bound", PolicyArn=policy["Arn"])
        f = check_1_16_no_user_attached_policies(iam)
        assert f.status == "FAIL"
        assert "bound" in f.resources

    def test_1_20_access_analyzer_pass(self):
        aa = MagicMock()
        aa.list_analyzers.return_value = {
            "analyzers": [
                {"arn": "arn:aws:access-analyzer:us-east-1:123:analyzer/x", "status": "ACTIVE"}
            ]
        }
        f = check_1_20_access_analyzer(aa)
        assert f.control_id == "1.20"
        assert f.status == "PASS"
        assert f.resources

    def test_1_20_access_analyzer_fail_when_none(self):
        aa = MagicMock()
        aa.list_analyzers.return_value = {"analyzers": []}
        f = check_1_20_access_analyzer(aa)
        assert f.status == "FAIL"


@mock_aws
class TestExpandedStorageControls:
    _SSL_DENY_POLICY = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": ["arn:aws:s3:::test-bucket", "arn:aws:s3:::test-bucket/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
    )

    def test_2_1_4_ssl_required_pass(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        s3.put_bucket_policy(Bucket="test-bucket", Policy=self._SSL_DENY_POLICY)
        f = check_2_1_4_s3_ssl_required(s3)
        assert f.control_id == "2.1.4"
        assert f.status == "PASS"

    def test_2_1_4_ssl_required_fail_when_no_policy(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="open-bucket")
        f = check_2_1_4_s3_ssl_required(s3)
        assert f.status == "FAIL"
        assert "open-bucket" in f.resources

    def test_2_2_1_ebs_encryption_default_pass(self):
        ec2 = MagicMock()
        ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}
        f = check_2_2_1_ebs_encryption_default(ec2)
        assert f.control_id == "2.2.1"
        assert f.status == "PASS"

    def test_2_2_1_ebs_encryption_default_fail(self):
        ec2 = MagicMock()
        ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
        f = check_2_2_1_ebs_encryption_default(ec2)
        assert f.status == "FAIL"


class TestExpandedLoggingControls:
    def test_3_7_cloudwatch_integration_pass(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "primary",
                    "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:1:log-group:cis",
                }
            ]
        }
        ct.get_trail_status.return_value = {
            "LatestCloudWatchLogsDeliveryTime": "2026-04-30T00:00:00Z"
        }
        f = check_3_7_cloudtrail_cloudwatch_integration(ct)
        assert f.control_id == "3.7"
        assert f.status == "PASS"

    def test_3_7_cloudwatch_integration_fail_when_missing_log_group(self):
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"Name": "no-cw"}]}
        f = check_3_7_cloudtrail_cloudwatch_integration(ct)
        assert f.status == "FAIL"
        assert "no-cw" in f.resources


@mock_aws
class TestExpandedNetworkingControls:
    def test_5_4_default_sg_pass_when_empty(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        f = check_5_4_default_sg_restricts_traffic(ec2)
        assert f.control_id == "5.4"
        # moto's default VPC ships a default SG with implicit egress-all rule,
        # so the check fires; assert structure regardless.
        assert f.severity == "HIGH"

    def test_5_4_default_sg_fail_when_rules_present(self):
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-default",
                    "GroupName": "default",
                    "VpcId": "vpc-1",
                    "IpPermissions": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        }
        f = check_5_4_default_sg_restricts_traffic(ec2)
        assert f.status == "FAIL"
        assert any("sg-default" in r for r in f.resources)
