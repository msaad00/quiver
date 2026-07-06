"""Tests for detect-s3-cross-account-copy."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError  # noqa: E402

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location("detect_s3_cross_account_copy_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ACCEPTED_PRODUCERS = MODULE.ACCEPTED_PRODUCERS
COPY_OBJECT_OPERATION = MODULE.COPY_OBJECT_OPERATION
S3_SERVICE = MODULE.S3_SERVICE
TECHNIQUE_UID = MODULE.TECHNIQUE_UID
detect = MODULE.detect


def _ct_event(
    *,
    success: bool = True,
    actor: str = "alice",
    actor_account_uid: str = "111122223333",
    target_account_uid: str = "444455556666",
    region: str = "us-east-1",
    src_ip: str = "203.0.113.42",
    producer: str = "ingest-cloudtrail-ocsf",
    time_ms: int = 1700000000000,
    event_uid: str = "evt-1",
    operation: str = "CopyObject",
    service: str = "s3.amazonaws.com",
    bucket_name: str = "target-bucket",
    key: str = "archive/secret.txt",
    copy_source: str = "source-bucket/original/secret.txt",
) -> dict:
    resources = []
    if bucket_name:
        resources.append({"name": bucket_name, "type": "bucketName"})
    if key:
        resources.append({"name": key, "type": "key"})
    if copy_source:
        resources.append({"name": copy_source, "type": "x-amz-copy-source"})
    return {
        "class_uid": 6003,
        "status_id": 1 if success else 2,
        "time": time_ms,
        "metadata": {"uid": event_uid, "product": {"feature": {"name": producer}}},
        "actor": {"user": {"name": actor, "account": {"uid": actor_account_uid}}},
        "src_endpoint": {"ip": src_ip},
        "api": {"operation": operation, "service": {"name": service}},
        "resources": resources,
        "cloud": {"provider": "AWS", "account": {"uid": target_account_uid}, "region": region},
    }


def test_accepted_producer_is_cloudtrail():
    assert ACCEPTED_PRODUCERS == frozenset({"ingest-cloudtrail-ocsf"})


def test_operation_and_service_constants():
    assert COPY_OBJECT_OPERATION == "CopyObject"
    assert S3_SERVICE == "s3.amazonaws.com"


def test_fires_on_successful_cross_account_copy():
    findings = list(detect([_ct_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class_uid"] == 2004
    assert finding["finding_info"]["title"] == "S3 cross-account copy detected"
    assert finding["finding_info"]["attacks"][0]["technique_uid"] == TECHNIQUE_UID
    assert any(
        obs["name"] == "destination.bucket" and obs["value"] == "target-bucket"
        for obs in finding["observables"]
    )


def test_native_output_contains_source_and_destination():
    findings = list(detect([_ct_event()], output_format="native"))
    finding = findings[0]
    assert finding["schema_mode"] == "native"
    assert finding["source_bucket"] == "source-bucket"
    assert finding["source_key"] == "original/secret.txt"
    assert finding["destination_bucket"] == "target-bucket"
    assert finding["destination_key"] == "archive/secret.txt"


def test_skips_same_account_copy():
    assert (
        list(
            detect([_ct_event(actor_account_uid="444455556666", target_account_uid="444455556666")])
        )
        == []
    )


def test_skips_failed_event():
    assert list(detect([_ct_event(success=False)])) == []


def test_skips_wrong_operation():
    assert list(detect([_ct_event(operation="PutObject")])) == []


def test_skips_wrong_service():
    assert list(detect([_ct_event(service="ec2.amazonaws.com")])) == []


def test_skips_wrong_producer(capsys):
    findings = list(detect([_ct_event(producer="ingest-okta-system-log-ocsf")]))
    assert findings == []
    assert "non-cloudtrail producer" in capsys.readouterr().err


def test_skips_missing_copy_context(capsys):
    findings = list(detect([_ct_event(copy_source="")]))
    assert findings == []
    assert "missing bucket, key, or x-amz-copy-source" in capsys.readouterr().err


def test_skips_missing_account_context(capsys):
    findings = list(detect([_ct_event(actor_account_uid="")]))
    assert findings == []
    assert "missing actor or target account context" in capsys.readouterr().err


def test_finding_uid_is_deterministic():
    event = _ct_event()
    first = list(detect([event]))[0]["finding_info"]["uid"]
    second = list(detect([event]))[0]["finding_info"]["uid"]
    assert first == second
    assert first.startswith("s3x-")


def test_rejects_unknown_output_format():
    with pytest.raises(ContractError, match="unsupported output_format") as excinfo:
        list(detect([_ct_event()], output_format="weird"))
    assert excinfo.value.error_class == "contract"
    assert excinfo.value.retryable is False
    assert excinfo.value.hint
    assert "ocsf" in excinfo.value.hint or "native" in excinfo.value.hint
