"""Tests for ingest-gcp-audit-ocsf."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ingest import (  # type: ignore[import-not-found]
    ACTIVITY_CREATE,
    ACTIVITY_DELETE,
    ACTIVITY_OTHER,
    ACTIVITY_READ,
    ACTIVITY_UPDATE,
    AUDIT_LOG_TYPE,
    CATEGORY_UID,
    CLASS_UID,
    OCSF_VERSION,
    SKILL_NAME,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    _status_id_and_detail,
    convert_event,
    convert_event_native,
    infer_activity_id,
    ingest,
    parse_ts_ms,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "gcp_audit_raw_sample.jsonl"
OCSF_FIXTURE = GOLDEN / "gcp_audit_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ── Verb → activity_id ────────────────────────────────────────────────


class TestInferActivity:
    def test_dotted_method_creates(self):
        for n in (
            "google.iam.admin.v1.CreateServiceAccountKey",
            "google.cloud.compute.v1.Instances.Insert",
            "google.cloud.kms.v1.GenerateRandomBytes",
        ):
            assert infer_activity_id(n) == ACTIVITY_CREATE

    def test_dotted_method_reads(self):
        for n in (
            "google.cloud.compute.v1.Instances.List",
            "storage.buckets.list",
            "google.iam.admin.v1.GetServiceAccount",
            "google.cloud.bigquery.v2.JobsService.GetQueryResults",
        ):
            assert infer_activity_id(n) == ACTIVITY_READ

    def test_dotted_method_updates(self):
        for n in (
            "google.iam.admin.v1.SetIamPolicy",
            "google.cloud.compute.v1.Instances.Patch",
            "google.cloud.storage.v1.SetIamPermissions",
        ):
            assert infer_activity_id(n) == ACTIVITY_UPDATE

    def test_dotted_method_deletes(self):
        for n in (
            "v1.compute.instances.delete",
            "google.cloud.storage.v1.DeleteBucket",
            "google.iam.admin.v1.DeleteServiceAccountKey",
        ):
            assert infer_activity_id(n) == ACTIVITY_DELETE

    def test_unknown_falls_to_other(self):
        for n in ("google.cloud.unknown.v1.Doodle", "google.cloud.foo.bar"):
            assert infer_activity_id(n) == ACTIVITY_OTHER

    def test_empty_string(self):
        assert infer_activity_id("") == ACTIVITY_OTHER

    def test_no_dots(self):
        assert infer_activity_id("ConsoleLogin") == ACTIVITY_OTHER


# ── Status decoder ────────────────────────────────────────────────────


class TestStatus:
    def test_empty_status_is_success(self):
        sid, detail = _status_id_and_detail({})
        assert sid == STATUS_SUCCESS
        assert detail is None

    def test_missing_status_is_success(self):
        sid, detail = _status_id_and_detail(None)
        assert sid == STATUS_SUCCESS

    def test_code_zero_is_success(self):
        sid, detail = _status_id_and_detail({"code": 0})
        assert sid == STATUS_SUCCESS

    def test_permission_denied(self):
        sid, detail = _status_id_and_detail({"code": 7, "message": "denied"})
        assert sid == STATUS_FAILURE
        assert "PERMISSION_DENIED" in detail
        assert "denied" in detail

    def test_unknown_code_uses_numeric_name(self):
        sid, detail = _status_id_and_detail({"code": 99, "message": "x"})
        assert sid == STATUS_FAILURE
        assert "CODE_99" in detail


# ── Timestamp ─────────────────────────────────────────────────────────


class TestParseTs:
    def test_iso_z(self):
        assert parse_ts_ms("2026-04-10T05:00:00Z") == 1775797200000

    def test_iso_microseconds(self):
        assert parse_ts_ms("2026-04-10T05:00:00.000000Z") == 1775797200000

    def test_iso_nanoseconds_truncated(self):
        # GCP can emit 9-digit fractional seconds; we truncate to 6
        assert parse_ts_ms("2026-04-10T05:00:00.123456789Z") == 1775797200123

    def test_garbage_falls_to_now(self):
        assert parse_ts_ms("not-a-date") > 1_700_000_000_000


# ── convert_event ─────────────────────────────────────────────────────


class TestConvertEvent:
    def _entry(self, **proto_overrides):
        proto = {
            "@type": AUDIT_LOG_TYPE,
            "authenticationInfo": {"principalEmail": "alice@x.com"},
            "requestMetadata": {"callerIp": "1.2.3.4", "callerSuppliedUserAgent": "gcloud"},
            "serviceName": "iam.googleapis.com",
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "resourceName": "projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com",
            "status": {},
        }
        proto.update(proto_overrides)
        return {
            "protoPayload": proto,
            "insertId": "e1",
            "resource": {
                "type": "service_account",
                "labels": {"project_id": "my-project", "location": "us-central1"},
            },
            "timestamp": "2026-04-10T05:00:00Z",
        }

    def test_class_pinning(self):
        e = convert_event(self._entry())
        assert e["class_uid"] == CLASS_UID == 6003
        assert e["category_uid"] == CATEGORY_UID == 6
        assert e["type_uid"] == CLASS_UID * 100 + ACTIVITY_CREATE
        assert e["metadata"]["version"] == OCSF_VERSION
        assert e["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_actor_basic(self):
        e = convert_event(self._entry())
        assert e["actor"]["user"]["name"] == "alice@x.com"
        assert e["actor"]["user"]["uid"] == "alice@x.com"

    def test_service_account_actor_has_type(self):
        e = convert_event(
            self._entry(
                authenticationInfo={
                    "principalEmail": "sa@p.iam.gserviceaccount.com",
                    "principalSubject": "serviceAccount:sa@p.iam.gserviceaccount.com",
                    "serviceAccountKeyName": "projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/abc",
                }
            )
        )
        assert e["actor"]["user"]["type"] == "ServiceAccount"
        assert e["actor"]["user"]["uid"] == "serviceAccount:sa@p.iam.gserviceaccount.com"

    def test_src_endpoint(self):
        e = convert_event(self._entry())
        assert e["src_endpoint"]["ip"] == "1.2.3.4"
        assert e["src_endpoint"]["svc_name"] == "gcloud"

    def test_api(self):
        e = convert_event(self._entry())
        assert e["api"]["operation"] == "google.iam.admin.v1.CreateServiceAccountKey"
        assert e["api"]["service"]["name"] == "iam.googleapis.com"
        assert e["api"]["request"]["uid"] == "e1"

    def test_cloud(self):
        e = convert_event(self._entry())
        assert e["cloud"]["provider"] == "GCP"
        assert e["cloud"]["account"]["uid"] == "my-project"
        assert e["cloud"]["region"] == "us-central1"

    def test_resources(self):
        e = convert_event(self._entry())
        assert len(e["resources"]) == 1
        assert (
            e["resources"][0]["name"] == "projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com"
        )
        assert e["resources"][0]["type"] == "service_account"

    def test_resources_include_sanitized_created_service_account_key_name(self):
        e = convert_event(
            self._entry(
                response={
                    "name": "projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/key-123",
                    "privateKeyData": "base64-secret-material",
                }
            )
        )
        assert e["resources"] == [
            {
                "name": "projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com",
                "type": "service_account",
            },
            {
                "name": "projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/key-123",
                "type": "service_account_key",
            },
        ]
        assert "privateKeyData" not in e

    def test_failure_status(self):
        e = convert_event(self._entry(status={"code": 7, "message": "denied"}))
        assert e["status_id"] == STATUS_FAILURE
        assert "PERMISSION_DENIED" in e["status_detail"]

    def test_skips_non_audit_log(self):
        e = {
            "protoPayload": {
                "@type": "type.googleapis.com/something.else.LogEntry",
                "methodName": "x",
            }
        }
        assert convert_event(e) is None

    def test_native_output_keeps_canonical_fields_without_ocsf_envelope(self):
        e = convert_event_native(self._entry())
        assert e["schema_mode"] == "native"
        assert e["record_type"] == "api_activity"
        assert e["provider"] == "GCP"
        assert e["operation"] == "google.iam.admin.v1.CreateServiceAccountKey"
        assert e["event_uid"] == "e1"
        assert "class_uid" not in e
        assert "metadata" not in e


# ── ingest stream ──────────────────────────────────────────────────────


class TestIngestStream:
    def test_ndjson(self):
        e1 = json.dumps(
            {
                "protoPayload": {"@type": AUDIT_LOG_TYPE, "methodName": "x.y.GetThing"},
                "timestamp": "2026-04-10T05:00:00Z",
            }
        )
        e2 = json.dumps(
            {
                "protoPayload": {"@type": AUDIT_LOG_TYPE, "methodName": "x.y.DeleteThing"},
                "timestamp": "2026-04-10T05:01:00Z",
            }
        )
        out = list(ingest([e1, e2]))
        assert len(out) == 2
        assert out[0]["activity_id"] == ACTIVITY_READ
        assert out[1]["activity_id"] == ACTIVITY_DELETE

    def test_skips_non_audit(self, capsys):
        good = json.dumps(
            {
                "protoPayload": {"@type": AUDIT_LOG_TYPE, "methodName": "x.y.GetThing"},
                "timestamp": "2026-04-10T05:00:00Z",
            }
        )
        bad = json.dumps(
            {"protoPayload": {"@type": "type.googleapis.com/other.LogEntry", "methodName": "x"}}
        )
        out = list(ingest([bad, good]))
        assert len(out) == 1
        assert "not a google.cloud.audit.AuditLog" in capsys.readouterr().err

    def test_native_output_mode(self):
        payload = json.dumps(
            {
                "protoPayload": {"@type": AUDIT_LOG_TYPE, "methodName": "x.y.GetThing"},
                "insertId": "n1",
                "timestamp": "2026-04-10T05:00:00Z",
            }
        )
        out = list(ingest([payload], output_format="native"))
        assert len(out) == 1
        first = out[0]
        assert first["schema_mode"] == "native"
        assert first["record_type"] == "api_activity"
        assert "class_uid" not in first

    def test_mixed_malformed_batch_keeps_valid_entries(self, capsys):
        read_event = json.dumps(
            {
                "protoPayload": {"@type": AUDIT_LOG_TYPE, "methodName": "x.y.GetThing"},
                "insertId": "good-read",
                "timestamp": "2026-04-10T05:00:00Z",
            }
        )
        delete_event = json.dumps(
            {
                "protoPayload": {"@type": AUDIT_LOG_TYPE, "methodName": "x.y.DeleteThing"},
                "insertId": "good-delete",
                "timestamp": "2026-04-10T05:01:00Z",
            }
        )
        out = list(ingest([read_event, '{"bad"', "[]", delete_event]))
        assert len(out) == 2
        assert [event["activity_id"] for event in out] == [ACTIVITY_READ, ACTIVITY_DELETE]
        stderr = capsys.readouterr().err
        assert "skipping line 2: json parse failed" in stderr
        assert "skipping line 3: not a JSON object" in stderr


# ── Golden fixture parity ──────────────────────────────────────────────


class TestGoldenFixture:
    def test_event_count(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines()))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert len(produced) == len(expected) == 4

    def test_deep_equality(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines()))
        expected = _load_jsonl(OCSF_FIXTURE)
        for p, e in zip(produced, expected):
            assert p == e, (
                f"event mismatch:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )

    def test_fixture_exercises_all_activities(self):
        events = _load_jsonl(OCSF_FIXTURE)
        activities = {e["activity_id"] for e in events}
        assert activities == {ACTIVITY_CREATE, ACTIVITY_READ, ACTIVITY_UPDATE, ACTIVITY_DELETE}

    def test_fixture_has_one_failure(self):
        events = _load_jsonl(OCSF_FIXTURE)
        failures = [e for e in events if e["status_id"] == STATUS_FAILURE]
        assert len(failures) == 1
        assert "SetIamPolicy" in failures[0]["api"]["operation"]
        assert "PERMISSION_DENIED" in failures[0]["status_detail"]
