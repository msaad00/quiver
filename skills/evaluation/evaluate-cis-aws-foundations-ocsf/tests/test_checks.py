"""Tests for evaluate-cis-aws-foundations-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src" / "checks.py"
_SPEC = importlib.util.spec_from_file_location("cis_aws_ocsf_checks", _SRC)
assert _SPEC and _SPEC.loader
_CHECKS = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECKS
_SPEC.loader.exec_module(_CHECKS)

BENCHMARK_NAME = _CHECKS.BENCHMARK_NAME
CONTROLS = _CHECKS.CONTROLS
DOCUMENTED_NOT_IMPLEMENTED = _CHECKS.DOCUMENTED_NOT_IMPLEMENTED
FRAMEWORKS = _CHECKS.FRAMEWORKS
PROVIDER_NAME = _CHECKS.PROVIDER_NAME
SKILL_NAME = _CHECKS.SKILL_NAME
STATUS_FAIL = _CHECKS.STATUS_FAIL
STATUS_NA = _CHECKS.STATUS_NA
STATUS_PASS = _CHECKS.STATUS_PASS
benchmark_metadata = _CHECKS.benchmark_metadata
findings_to_ocsf = _CHECKS.findings_to_ocsf
load_records = _CHECKS.load_records
main = _CHECKS.main
parse_records = _CHECKS.parse_records
run_benchmark = _CHECKS.run_benchmark


def _item(
    resource_type: str, resource_id: str, config: dict[str, object], *, region: str = "us-east-1"
) -> dict[str, object]:
    return {
        "class_uid": 6003,
        "time": 1776572400000,
        "metadata": {"uid": f"ci-{resource_id}"},
        "cloud": {"provider": "AWS", "account": {"uid": "111122223333"}, "region": region},
        "resources": [
            {"uid": resource_id, "name": resource_id, "type": resource_type, "region": region}
        ],
        "unmapped": {
            "aws_config": {
                "configuration": config,
                "tags": {},
                "relationships": [],
            }
        },
    }


def _passing_records() -> list[dict[str, object]]:
    return [
        _item(
            "AWS::S3::Bucket",
            "prod-logs",
            {
                "bucketEncryption": {
                    "serverSideEncryptionConfiguration": [{"rule": {"sse": "AES256"}}]
                },
                "loggingConfiguration": {"destinationBucketName": "central-logs"},
                "publicAccessBlockConfiguration": {
                    "blockPublicAcls": True,
                    "ignorePublicAcls": True,
                    "blockPublicPolicy": True,
                    "restrictPublicBuckets": True,
                },
                "versioningConfiguration": {"status": "Enabled"},
            },
        ),
        _item(
            "AWS::CloudTrail::Trail",
            "org-trail",
            {"isMultiRegionTrail": True, "logFileValidationEnabled": True, "kmsKeyId": "arn:kms"},
        ),
        _item(
            "AWS::EC2::SecurityGroup",
            "sg-private",
            {
                "ipPermissions": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": [{"cidrIp": "10.0.0.0/8"}],
                    }
                ]
            },
        ),
        _item("AWS::EC2::VPC", "vpc-1", {}),
        _item("AWS::EC2::FlowLog", "fl-1", {"resourceId": "vpc-1"}),
        _item("AWS::GuardDuty::Detector", "gd-1", {"status": "ENABLED"}),
        _item("AWS::SecurityHub::Hub", "hub-1", {"subscribedAt": "2026-06-05T00:00:00Z"}),
    ]


class TestInputParsing:
    def test_parse_json_array_and_jsonl(self):
        records = _passing_records()[:2]
        assert parse_records(json.dumps(records)) == records
        jsonl = "\n".join(json.dumps(record) for record in records)
        assert parse_records(jsonl) == records

    def test_parse_rejects_non_object_jsonl(self):
        with pytest.raises(ValueError):
            parse_records("[1]\n")

    def test_load_records_reads_stream(self):
        records = load_records(None, stream=[json.dumps(_passing_records()[0])])
        assert len(records) == 1


class TestEvaluation:
    def test_passing_config_evidence_passes_implemented_controls(self):
        findings = run_benchmark(_passing_records())
        assert len(findings) == len(CONTROLS)
        assert {finding.status for finding in findings} == {STATUS_PASS}

    def test_s3_and_security_group_failures_are_detected(self):
        records = [
            _item(
                "AWS::S3::Bucket",
                "bad-bucket",
                {
                    "publicAccessBlockConfiguration": {
                        "blockPublicAcls": False,
                        "ignorePublicAcls": True,
                        "blockPublicPolicy": True,
                        "restrictPublicBuckets": False,
                    },
                    "versioningConfiguration": {"status": "Suspended"},
                },
            ),
            _item(
                "AWS::EC2::SecurityGroup",
                "sg-open",
                {
                    "ipPermissions": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 3389,
                            "ipRanges": [{"cidrIp": "0.0.0.0/0"}],
                        }
                    ]
                },
            ),
        ]
        findings = {finding.control_id: finding for finding in run_benchmark(records)}
        assert findings["2.1"].status == STATUS_FAIL
        assert findings["2.3"].status == STATUS_FAIL
        assert findings["2.4"].status == STATUS_FAIL
        assert findings["4.1"].status == STATUS_FAIL
        assert findings["4.2"].status == STATUS_FAIL
        assert "bad-bucket" in findings["2.1"].detail
        assert "sg-open" in findings["4.1"].detail

    def test_empty_input_is_not_applicable_except_required_services(self):
        findings = {finding.control_id: finding for finding in run_benchmark([])}
        assert findings["2.1"].status == STATUS_NA
        assert findings["4.3"].status == STATUS_NA
        assert findings["6.1"].status == STATUS_FAIL
        assert findings["6.2"].status == STATUS_FAIL

    def test_aws_config_rule_evidence_can_fail_without_config_item(self):
        records = [
            {
                "class_uid": 2003,
                "time": 1776572760000,
                "cloud": {
                    "provider": "AWS",
                    "account": {"uid": "111122223333"},
                    "region": "us-east-1",
                },
                "resources": [
                    {
                        "uid": "prod-logs",
                        "name": "prod-logs",
                        "type": "AWS::S3::Bucket",
                        "region": "us-east-1",
                    }
                ],
                "finding_info": {"desc": "Bucket encryption missing."},
                "compliance": {
                    "status": "FAIL",
                    "control": "s3-bucket-server-side-encryption-enabled",
                    "frameworks": ["AWS Config"],
                },
                "evidence": {
                    "source": "AWS Config",
                    "rule_name": "s3-bucket-server-side-encryption-enabled",
                },
            }
        ]
        findings = {finding.control_id: finding for finding in run_benchmark(records)}
        assert findings["2.1"].status == STATUS_FAIL
        assert "AWS Config rule failure evidence" in findings["2.1"].detail

    def test_control_filter_returns_one_finding(self):
        findings = run_benchmark(_passing_records(), control_id="2.1")
        assert len(findings) == 1
        assert findings[0].control_id == "2.1"


class TestOcsfProjection:
    def test_findings_render_as_ocsf_compliance_findings(self):
        findings = run_benchmark(_passing_records())
        rendered = findings_to_ocsf(
            findings,
            skill_name=SKILL_NAME,
            benchmark_name=BENCHMARK_NAME,
            provider=PROVIDER_NAME,
            frameworks=list(FRAMEWORKS),
        )
        assert len(rendered) == len(CONTROLS)
        assert all(record["class_uid"] == 2003 for record in rendered)
        assert rendered[0]["cloud"]["provider"] == "AWS"
        assert "CIS AWS Foundations v3.0 2.1" in rendered[0]["compliance"]["requirements"]


class TestCli:
    def test_main_json_output_success(self, tmp_path: Path, capsys):
        path = tmp_path / "records.json"
        path.write_text(json.dumps(_passing_records()), encoding="utf-8")
        assert main([str(path), "--output", "json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert len(out) == len(CONTROLS)

    def test_main_returns_2_for_bad_input(self, tmp_path: Path, capsys):
        path = tmp_path / "bad.jsonl"
        path.write_text("{bad", encoding="utf-8")
        assert main([str(path)]) == 2
        assert "JSON parse failed" in capsys.readouterr().err


class TestHonestyContract:
    def test_metadata_declares_partial_coverage(self):
        metadata = benchmark_metadata()
        assert metadata["implemented_count"] == 12
        assert metadata["source_skill"] == "ingest-aws-config-ocsf"
        assert set(metadata["implemented_controls"]).isdisjoint(DOCUMENTED_NOT_IMPLEMENTED)

    def test_documented_not_implemented_is_non_empty(self):
        assert DOCUMENTED_NOT_IMPLEMENTED
