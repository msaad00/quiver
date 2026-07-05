"""Tests for detect-gcp-model-artifact-download."""

from __future__ import annotations

import importlib.util
from pathlib import Path

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location("detect_gcp_model_artifact_download_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _event(
    *,
    producer: str = "ingest-gcp-audit-ocsf",
    operation: str = "storage.objects.get",
    service: str = "storage.googleapis.com",
    status_id: int = 1,
    actor_name: str = "alice@example.com",
    actor_type: str = "",
    project_uid: str = "prod-ml-project",
    resource_name: str = "projects/_/buckets/model-artifacts-prod/objects/vertex/checkpoints/model.safetensors",
    src_ip: str = "198.51.100.25",
) -> dict:
    actor_user = {"name": actor_name}
    if actor_type:
        actor_user["type"] = actor_type
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
        "actor": {"user": actor_user},
        "cloud": {
            "provider": "GCP",
            "account": {"uid": project_uid},
            "region": "us-central1",
        },
        "src_endpoint": {"ip": src_ip},
        "resources": [
            {"name": resource_name, "type": "gcs_bucket"},
        ],
    }


def test_fires_on_model_safetensors_get_object():
    findings = list(MODULE.detect([_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_info"]["title"] == "GCP model artifact downloaded from Cloud Storage"
    attacks = finding["finding_info"]["attacks"]
    assert any(item["technique"]["uid"] == "T1530" for item in attacks)
    assert any(item["technique"]["uid"] == "AML.T0035" for item in attacks)
    assert any(
        obs["name"] == "object.key" and obs["value"].endswith("model.safetensors")
        for obs in finding["observables"]
    )


def test_native_output_includes_bucket_key_and_match():
    findings = list(
        MODULE.detect(
            [
                _event(
                    resource_name="projects/_/buckets/model-artifacts-prod/objects/training%2Frun-42%2Fpytorch_model.bin"
                )
            ],
            output_format="native",
        )
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule"] == "gcp-model-artifact-download"
    assert finding["bucket_name"] == "model-artifacts-prod"
    assert finding["object_key"] == "training/run-42/pytorch_model.bin"
    assert finding["artifact_match"] == "pytorch_model.bin"


def test_non_model_object_is_ignored():
    findings = list(
        MODULE.detect(
            [
                _event(
                    resource_name="projects/_/buckets/model-artifacts-prod/objects/reports/quarterly.csv"
                )
            ]
        )
    )
    assert findings == []


def test_wrong_operation_is_ignored():
    findings = list(MODULE.detect([_event(operation="storage.objects.list")]))
    assert findings == []


def test_failed_event_is_ignored():
    findings = list(MODULE.detect([_event(status_id=2)]))
    assert findings == []


def test_wrong_source_is_ignored():
    findings = list(MODULE.detect([_event(producer="ingest-cloudtrail-ocsf")]))
    assert findings == []


def test_missing_bucket_or_key_is_skipped(capsys):
    findings = list(
        MODULE.detect([_event(resource_name="projects/_/buckets/model-artifacts-prod")])
    )
    assert findings == []
    assert "missing bucket or object context" in capsys.readouterr().err
