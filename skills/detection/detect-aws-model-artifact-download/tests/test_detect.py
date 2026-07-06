"""Tests for detect-aws-model-artifact-download."""

from __future__ import annotations

import importlib.util
from pathlib import Path

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location("detect_aws_model_artifact_download_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _event(
    *,
    producer: str = "ingest-cloudtrail-ocsf",
    operation: str = "GetObject",
    service: str = "s3.amazonaws.com",
    status_id: int = 1,
    actor_name: str = "alice",
    actor_type: str = "IAMUser",
    actor_account_uid: str = "111122223333",
    target_account_uid: str = "111122223333",
    bucket_name: str = "model-artifacts-prod",
    key: str = "bedrock/checkpoints/fraud-model/model.safetensors",
    src_ip: str = "198.51.100.24",
) -> dict:
    return {
        "class_uid": 6003,
        "status_id": status_id,
        "time": 1775797200000,
        "metadata": {
            "uid": "evt-1",
            "product": {"feature": {"name": producer}},
        },
        "api": {
            "operation": operation,
            "service": {"name": service},
        },
        "actor": {
            "user": {
                "name": actor_name,
                "type": actor_type,
                "account": {"uid": actor_account_uid},
            }
        },
        "cloud": {
            "provider": "AWS",
            "account": {"uid": target_account_uid},
            "region": "us-east-1",
        },
        "src_endpoint": {"ip": src_ip},
        "resources": [
            {"name": bucket_name, "type": "bucketName"},
            {"name": key, "type": "key"},
        ],
    }


def test_fires_on_model_safetensors_get_object():
    findings = list(MODULE.detect([_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_info"]["title"] == "AWS model artifact downloaded from S3"
    attacks = finding["finding_info"]["attacks"]
    assert any(item["technique_uid"] == "T1530" for item in attacks)
    assert any(item["technique_uid"] == "AML.T0035" for item in attacks)
    assert any(
        obs["name"] == "object.key" and obs["value"].endswith("model.safetensors")
        for obs in finding["observables"]
    )


def test_native_output_includes_bucket_key_and_match():
    findings = list(
        MODULE.detect([_event(key="training/run-42/pytorch_model.bin")], output_format="native")
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule"] == "aws-model-artifact-download"
    assert finding["bucket_name"] == "model-artifacts-prod"
    assert finding["object_key"] == "training/run-42/pytorch_model.bin"
    assert finding["artifact_match"] == "pytorch_model.bin"


def test_non_model_object_is_ignored():
    findings = list(MODULE.detect([_event(key="reports/2026-04-24/quarterly.csv")]))
    assert findings == []


def test_non_get_object_is_ignored():
    findings = list(MODULE.detect([_event(operation="HeadObject")]))
    assert findings == []


def test_failed_event_is_ignored():
    findings = list(MODULE.detect([_event(status_id=2)]))
    assert findings == []


def test_aws_service_reads_are_ignored():
    findings = list(MODULE.detect([_event(actor_name="s3.amazonaws.com", actor_type="AWSService")]))
    assert findings == []


def test_wrong_source_is_ignored():
    findings = list(MODULE.detect([_event(producer="ingest-azure-activity-ocsf")]))
    assert findings == []


def test_missing_bucket_or_key_is_skipped(capsys):
    event = _event()
    event["resources"] = [{"name": "model-artifacts-prod", "type": "bucketName"}]
    findings = list(MODULE.detect([event]))
    assert findings == []
    assert "missing bucket or key context" in capsys.readouterr().err
