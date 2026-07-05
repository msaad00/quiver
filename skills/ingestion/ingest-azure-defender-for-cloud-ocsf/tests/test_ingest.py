"""Tests for ingest-azure-defender-for-cloud-ocsf."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_azure_defender", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_INGEST)

CATEGORY_UID = _INGEST.CATEGORY_UID
CLASS_UID = _INGEST.CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
SEVERITY_CRITICAL = _INGEST.SEVERITY_CRITICAL
SEVERITY_HIGH = _INGEST.SEVERITY_HIGH
SEVERITY_INFORMATIONAL = _INGEST.SEVERITY_INFORMATIONAL
SEVERITY_LOW = _INGEST.SEVERITY_LOW
SEVERITY_MEDIUM = _INGEST.SEVERITY_MEDIUM
SKILL_NAME = _INGEST.SKILL_NAME
TYPE_UID = _INGEST.TYPE_UID
convert_alert = _INGEST.convert_alert
convert_alert_native = _INGEST.convert_alert_native
ingest = _INGEST.ingest
iter_raw_alerts = _INGEST.iter_raw_alerts
severity_to_id = _INGEST.severity_to_id
validate_alert = _INGEST.validate_alert

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "azure_defender_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "azure_defender_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _alert(**property_overrides) -> dict:
    props = {
        "alertDisplayName": "Suspicious process launched in container",
        "description": "Defender observed a suspicious process execution inside a Kubernetes workload.",
        "severity": "High",
        "compromisedEntity": "aks-nodepool-1",
        "timeGeneratedUtc": "2026-04-10T05:00:00.000000Z",
        "resourceIdentifiers": [
            {
                "azureResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/prod-aks"
            }
        ],
        "resourceDetails": {"location": "eastus"},
        "remediationSteps": ["Review running containers", "Rotate affected credentials"],
        "alertType": "KubernetesSuspiciousProcess",
        "status": "Active",
    }
    props.update(property_overrides)
    return {
        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/alerts/alert-1",
        "name": "alert-1",
        "properties": props,
    }


class TestSeverity:
    def test_mapping(self):
        assert severity_to_id("Critical") == SEVERITY_CRITICAL
        assert severity_to_id("High") == SEVERITY_HIGH
        assert severity_to_id("Medium") == SEVERITY_MEDIUM
        assert severity_to_id("Low") == SEVERITY_LOW
        assert severity_to_id(None) == SEVERITY_INFORMATIONAL


class TestValidation:
    def test_valid(self):
        ok, reason = validate_alert(_alert())
        assert ok, reason

    def test_missing_properties(self):
        ok, reason = validate_alert({})
        assert not ok
        assert "properties" in reason

    def test_missing_title(self):
        ok, reason = validate_alert(_alert(alertDisplayName="", displayName=""))
        assert not ok
        assert "title" in reason


class TestConvert:
    def test_pinned_fields(self):
        event = convert_alert(_alert())
        assert event["class_uid"] == CLASS_UID == 2004
        assert event["category_uid"] == CATEGORY_UID == 2
        assert event["type_uid"] == TYPE_UID
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert event["cloud"]["provider"] == "Azure"
        assert event["cloud"]["region"] == "eastus"
        assert event["cloud"]["account"]["uid"] == "00000000-0000-0000-0000-000000000000"

    def test_native_output_has_no_ocsf_envelope(self):
        native = convert_alert_native(_alert())
        assert native["schema_mode"] == "native"
        assert native["record_type"] == "detection_finding"
        assert native["provider"] == "Azure"
        assert native["title"] == "Suspicious process launched in container"
        assert "class_uid" not in native
        assert "category_uid" not in native
        assert "metadata" not in native

    def test_native_and_ocsf_share_same_uid_basis(self):
        raw = _alert()
        native = convert_alert_native(raw)
        ocsf = convert_alert(raw)
        assert native["event_uid"] == ocsf["metadata"]["uid"] == raw["id"]
        assert native["finding_uid"] == ocsf["finding_info"]["uid"]

    def test_compliance_lifted_to_observables(self):
        alert = _alert(compliance={"status": "Failed", "securityControlId": "LT-1"})
        event = convert_alert(alert)
        observables = {o["name"]: o["value"] for o in event["observables"]}
        assert observables["defender.compliance_status"] == "Failed"
        assert observables["defender.compliance_control"] == "LT-1"


class TestStream:
    def test_value_wrapper(self):
        wrapped = {"value": [_alert()]}
        assert list(iter_raw_alerts([json.dumps(wrapped)]))[0]["name"] == "alert-1"

    def test_golden_fixture(self):
        produced = list(ingest([RAW_FIXTURE.read_text()]))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected

    def test_native_output_mode(self):
        wrapped = {"value": [_alert()]}
        out = list(ingest([json.dumps(wrapped)], output_format="native"))
        assert len(out) == 1
        assert out[0]["schema_mode"] == "native"
        assert "metadata" not in out[0]
