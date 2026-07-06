"""Tests for ingest-entra-directory-audit-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_entra_directory_audit", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

ACTIVITY_CREATE = _INGEST.ACTIVITY_CREATE
ACTIVITY_OTHER = _INGEST.ACTIVITY_OTHER
CANONICAL_VERSION = _INGEST.CANONICAL_VERSION
CLASS_UID = _INGEST.CLASS_UID
OCSF_VERSION = _INGEST.OCSF_VERSION
OUTPUT_FORMATS = _INGEST.OUTPUT_FORMATS
SKILL_NAME = _INGEST.SKILL_NAME
STATUS_FAILURE = _INGEST.STATUS_FAILURE
STATUS_SUCCESS = _INGEST.STATUS_SUCCESS
STATUS_UNKNOWN = _INGEST.STATUS_UNKNOWN
SUPPORTED_ACTIVITIES = _INGEST.SUPPORTED_ACTIVITIES
_metadata_uid = _INGEST._metadata_uid
convert_event = _INGEST.convert_event
infer_activity_id = _INGEST.infer_activity_id
ingest = _INGEST.ingest
iter_raw_events = _INGEST.iter_raw_events
parse_ts_ms = _INGEST.parse_ts_ms
validate_event = _INGEST.validate_event

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "entra_directory_audit_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "entra_directory_audit_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _entry(**overrides) -> dict:
    event = {
        "id": "audit-evt-1",
        "activityDateTime": "2026-04-13T04:00:00.000Z",
        "activityDisplayName": "Add service principal credentials",
        "category": "ApplicationManagement",
        "correlationId": "corr-entra-1",
        "loggedByService": "Core Directory",
        "operationType": "Add",
        "result": "success",
        "resultReason": None,
        "initiatedBy": {
            "app": {
                "displayName": "Terraform Runner",
                "servicePrincipalId": "spn-111",
                "appId": "app-111",
            },
            "user": None,
        },
        "targetResources": [
            {
                "id": "spn-target-1",
                "displayName": "payments-api",
                "type": "ServicePrincipal",
                "userPrincipalName": None,
                "modifiedProperties": [],
            }
        ],
        "additionalDetails": [{"key": "KeyId", "value": "cred-123"}],
    }
    event.update(overrides)
    return event


class TestParseTs:
    def test_iso_z(self):
        assert parse_ts_ms("2026-04-13T04:00:00.000Z") == 1776052800000

    def test_missing_falls_to_now(self):
        ms = parse_ts_ms(None)
        assert isinstance(ms, int) and ms > 1_700_000_000_000


class TestActivityInference:
    def test_supported_activity_names_are_narrow(self):
        assert "Add service principal credentials" in SUPPORTED_ACTIVITIES
        assert "Create federated identity credential" in SUPPORTED_ACTIVITIES

    def test_add_maps_to_create(self):
        assert infer_activity_id("Add service principal credentials", "Add") == ACTIVITY_CREATE

    def test_unknown_falls_to_other(self):
        assert infer_activity_id("Rotate something custom", None) == ACTIVITY_OTHER


class TestValidation:
    def test_valid_event(self):
        ok, reason = validate_event(_entry())
        assert ok, reason

    def test_missing_required_field(self):
        ok, reason = validate_event(_entry(activityDateTime=None))
        assert not ok
        assert "missing required field" in reason

    def test_unsupported_activity(self):
        ok, reason = validate_event(_entry(activityDisplayName="Delete user"))
        assert not ok
        assert "unsupported activityDisplayName" in reason


class TestConvert:
    def test_class_pinning(self):
        event = convert_event(_entry())
        assert event["class_uid"] == CLASS_UID == 6003
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_actor_from_app(self):
        event = convert_event(_entry())
        assert event["actor"]["user"]["name"] == "Terraform Runner"
        assert event["actor"]["user"]["uid"] == "spn-111"
        assert event["actor"]["user"]["type"] == "ServicePrincipal"

    def test_actor_from_user(self):
        event = convert_event(
            _entry(
                initiatedBy={
                    "user": {
                        "id": "user-123",
                        "displayName": "Alice Admin",
                        "userPrincipalName": "alice@example.com",
                        "ipAddress": "203.0.113.20",
                    },
                    "app": None,
                }
            )
        )
        assert event["actor"]["user"]["name"] == "alice@example.com"
        assert event["actor"]["user"]["uid"] == "user-123"
        assert event["actor"]["user"]["email_addr"] == "alice@example.com"
        assert event["src_endpoint"]["ip"] == "203.0.113.20"

    def test_api_and_resources(self):
        event = convert_event(_entry())
        assert event["api"]["operation"] == "Add service principal credentials"
        assert event["api"]["service"]["name"] == "Core Directory"
        assert event["api"]["request"]["uid"] == "corr-entra-1"
        assert event["resources"] == [
            {"name": "payments-api", "type": "ServicePrincipal", "uid": "spn-target-1"}
        ]

    def test_failure_status_detail(self):
        event = convert_event(_entry(result="failure", resultReason="Authorization_RequestDenied"))
        assert event["status_id"] == STATUS_FAILURE
        assert event["status_detail"] == "Authorization_RequestDenied"

    def test_unknown_status(self):
        event = convert_event(_entry(result="unknownFutureValue", resultReason=None))
        assert event["status_id"] == STATUS_UNKNOWN

    def test_metadata_uid_prefers_id(self):
        assert _metadata_uid(_entry()) == "audit-evt-1"

    def test_metadata_uid_uses_hash_fallback(self):
        uid = _metadata_uid(_entry(id=None, correlationId=None))
        assert len(uid) == 64

    def test_native_projection_strips_ocsf_envelope(self):
        event = convert_event(_entry(), output_format="native")
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert event["schema_mode"] == "native"
        assert event["canonical_schema_version"] == CANONICAL_VERSION
        assert event["record_type"] == "api_activity"
        assert event["event_uid"] == "audit-evt-1"
        assert event["provider"] == "Azure"
        assert event["operation"] == "Add service principal credentials"
        assert "class_uid" not in event
        assert "metadata" not in event

    def test_native_and_ocsf_keep_same_uid(self):
        ocsf = convert_event(_entry(), output_format="ocsf")
        native = convert_event(_entry(), output_format="native")
        assert ocsf["metadata"]["uid"] == native["event_uid"]
        assert ocsf["api"]["operation"] == native["operation"]


class TestIterRawEvents:
    def test_value_wrapper(self):
        wrapped = {"value": [_entry(id="audit-a"), _entry(id="audit-b")]}
        events = list(iter_raw_events([json.dumps(wrapped)]))
        assert [event["id"] for event in events] == ["audit-a", "audit-b"]

    def test_array(self):
        events = list(iter_raw_events([json.dumps([_entry(id="audit-a"), _entry(id="audit-b")])]))
        assert [event["id"] for event in events] == ["audit-a", "audit-b"]

    def test_ndjson_and_bad_line(self, capsys):
        lines = [
            json.dumps(_entry(id="ok-1")),
            '{"broken"',
        ]
        events = list(iter_raw_events(lines))
        assert len(events) == 1
        assert events[0]["id"] == "ok-1"
        assert "skipping line" in capsys.readouterr().err


class TestGoldenFixture:
    def test_golden_fixture(self):
        produced = list(ingest([RAW_FIXTURE.read_text()]))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected

    def test_native_fixture_projection(self):
        produced = list(ingest([RAW_FIXTURE.read_text()], output_format="native"))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert len(produced) == len(expected)
        assert produced[0]["schema_mode"] == "native"
        assert produced[0]["event_uid"] == expected[0]["metadata"]["uid"]
        assert "class_uid" not in produced[0]
