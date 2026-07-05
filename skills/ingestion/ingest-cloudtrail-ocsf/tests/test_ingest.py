"""Tests for ingest-cloudtrail-ocsf.

Runs the ingester against the frozen golden CloudTrail fixture and asserts
the output matches the frozen OCSF fixture exactly. Plus unit tests for
verb→activity_id mapping, status_id derivation, Records-wrapper auto-detect,
and resource projection.
"""

from __future__ import annotations

import json
import os
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ingest import (  # type: ignore[import-not-found]
    ACTIVITY_CREATE,
    ACTIVITY_DELETE,
    ACTIVITY_OTHER,
    ACTIVITY_READ,
    ACTIVITY_UPDATE,
    CATEGORY_UID,
    CLASS_UID,
    OCSF_VERSION,
    SKILL_NAME,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    convert_event,
    convert_event_native,
    infer_activity_id,
    ingest,
    iter_raw_events,
    parse_ts_ms,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "cloudtrail_raw_sample.jsonl"
OCSF_FIXTURE = GOLDEN / "cloudtrail_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ── Verb → activity_id ─────────────────────────────────────────────────


class TestInferActivity:
    def test_create_prefix(self):
        for n in (
            "CreateUser",
            "CreateAccessKey",
            "RunInstances",
            "StartLogging",
            "IssueCertificate",
        ):
            assert infer_activity_id(n) == ACTIVITY_CREATE

    def test_read_prefix(self):
        for n in ("GetObject", "ListBuckets", "DescribeInstances", "LookupEvents", "HeadBucket"):
            assert infer_activity_id(n) == ACTIVITY_READ

    def test_update_prefix(self):
        for n in (
            "UpdateRole",
            "PutBucketPolicy",
            "ModifyDBInstance",
            "AttachUserPolicy",
            "EnableMFA",
        ):
            assert infer_activity_id(n) == ACTIVITY_UPDATE

    def test_delete_prefix(self):
        for n in (
            "DeleteUser",
            "TerminateInstances",
            "RemoveTagsFromResource",
            "DetachRolePolicy",
            "RevokeSecurityGroupIngress",
        ):
            assert infer_activity_id(n) == ACTIVITY_DELETE

    def test_unknown_falls_to_other(self):
        for n in ("ConsoleLogin", "AssumeRole", "CheckMfa"):
            assert infer_activity_id(n) == ACTIVITY_OTHER

    def test_empty_falls_to_other(self):
        assert infer_activity_id("") == ACTIVITY_OTHER


# ── Timestamp ──────────────────────────────────────────────────────────


class TestParseTs:
    def test_iso_z(self):
        # 2026-04-10T05:00:00Z == 1775797200000 ms
        assert parse_ts_ms("2026-04-10T05:00:00Z") == 1775797200000

    def test_missing_falls_to_now(self):
        ms = parse_ts_ms(None)
        assert isinstance(ms, int) and ms > 1_700_000_000_000

    def test_garbage_falls_to_now(self):
        ms = parse_ts_ms("not-a-date")
        assert isinstance(ms, int) and ms > 1_700_000_000_000


# ── convert_event ──────────────────────────────────────────────────────


class TestConvertEvent:
    def _base_event(self, **overrides):
        e = {
            "eventTime": "2026-04-10T05:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "1.2.3.4",
            "userAgent": "aws-cli/2",
            "userIdentity": {"type": "IAMUser", "userName": "alice", "accountId": "111122223333"},
            "recipientAccountId": "111122223333",
            "eventID": "abc-123",
        }
        e.update(overrides)
        return e

    def test_class_and_category_pinned(self):
        e = convert_event(self._base_event())
        assert e["class_uid"] == CLASS_UID == 6003
        assert e["category_uid"] == CATEGORY_UID == 6
        assert e["class_name"] == "API Activity"
        assert e["type_uid"] == CLASS_UID * 100 + ACTIVITY_CREATE

    def test_metadata_feature_name(self):
        e = convert_event(self._base_event())
        assert e["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert e["metadata"]["version"] == OCSF_VERSION
        assert e["metadata"]["uid"] == "abc-123"
        assert "cloudtrail" in e["metadata"]["labels"]

    def test_metadata_uid_falls_back_to_deterministic_hash(self):
        base = self._base_event()
        base.pop("eventID")
        a = convert_event(base)["metadata"]["uid"]
        b = convert_event(base)["metadata"]["uid"]
        assert a == b
        assert len(a) == 64

    def test_status_success_when_no_error(self):
        e = convert_event(self._base_event())
        assert e["status_id"] == STATUS_SUCCESS
        assert "status_detail" not in e

    def test_status_failure_when_error_code(self):
        e = convert_event(self._base_event(errorCode="AccessDenied", errorMessage="boom"))
        assert e["status_id"] == STATUS_FAILURE
        assert "AccessDenied" in e["status_detail"]
        assert "boom" in e["status_detail"]

    def test_actor_user_basic(self):
        e = convert_event(self._base_event())
        assert e["actor"]["user"]["name"] == "alice"
        assert e["actor"]["user"]["type"] == "IAMUser"
        assert e["actor"]["user"]["account"]["uid"] == "111122223333"

    def test_actor_session_with_mfa(self):
        e = convert_event(
            self._base_event(
                userIdentity={
                    "type": "AssumedRole",
                    "principalId": "AROA:alice",
                    "accessKeyId": "ASIA1",
                    "sessionContext": {
                        "attributes": {
                            "creationDate": "2026-04-10T04:00:00Z",
                            "mfaAuthenticated": "true",
                        }
                    },
                }
            )
        )
        s = e["actor"]["session"]
        assert s["uid"] == "ASIA1"
        assert s["mfa"] is True
        assert s["created_time"] == 1775793600000

    def test_src_endpoint(self):
        e = convert_event(self._base_event())
        assert e["src_endpoint"]["ip"] == "1.2.3.4"
        assert e["src_endpoint"]["svc_name"] == "aws-cli/2"

    def test_api(self):
        e = convert_event(self._base_event())
        assert e["api"]["operation"] == "CreateAccessKey"
        assert e["api"]["service"]["name"] == "iam.amazonaws.com"
        assert e["api"]["request"]["uid"] == "abc-123"

    def test_cloud(self):
        e = convert_event(self._base_event())
        assert e["cloud"]["provider"] == "AWS"
        assert e["cloud"]["account"]["uid"] == "111122223333"
        assert e["cloud"]["region"] == "us-east-1"

    def test_resources_projection(self):
        e = convert_event(
            self._base_event(
                requestParameters={
                    "userName": "bob",
                    "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                }
            )
        )
        names = {r["name"] for r in e["resources"]}
        assert "bob" in names
        assert "arn:aws:iam::aws:policy/ReadOnlyAccess" in names

    def test_resources_skips_complex_values(self):
        e = convert_event(
            self._base_event(requestParameters={"userName": "bob", "tags": [{"key": "env"}]})
        )
        # Only the scalar userName should make it into resources[]
        assert len(e["resources"]) == 1
        assert e["resources"][0]["name"] == "bob"

    def test_native_output_keeps_canonical_fields_without_ocsf_envelope(self):
        e = convert_event_native(self._base_event())
        assert e["schema_mode"] == "native"
        assert e["record_type"] == "api_activity"
        assert e["provider"] == "AWS"
        assert e["operation"] == "CreateAccessKey"
        assert e["event_uid"] == "abc-123"
        assert "class_uid" not in e
        assert "metadata" not in e


# ── iter_raw_events: format auto-detect ─────────────────────────────────


class TestIterRawEvents:
    def test_records_wrapper_unwrapped(self):
        records = {"Records": [{"eventName": "A"}, {"eventName": "B"}]}
        out = list(iter_raw_events([json.dumps(records)]))
        assert [e["eventName"] for e in out] == ["A", "B"]

    def test_single_object(self):
        out = list(iter_raw_events([json.dumps({"eventName": "ConsoleLogin"})]))
        assert len(out) == 1
        assert out[0]["eventName"] == "ConsoleLogin"

    def test_array_at_root(self):
        out = list(iter_raw_events([json.dumps([{"eventName": "X"}, {"eventName": "Y"}])]))
        assert [e["eventName"] for e in out] == ["X", "Y"]

    def test_ndjson_one_per_line(self):
        lines = [json.dumps({"eventName": "A"}), json.dumps({"eventName": "B"})]
        # Combined into a single multi-line buffer
        out = list(iter_raw_events(lines))
        assert len(out) == 2

    def test_skips_blank_lines(self):
        out = list(iter_raw_events(["", "  ", "\n"]))
        assert out == []

    def test_skips_malformed_without_crash(self, capsys):
        # NDJSON with one bad line followed by one good line
        out = list(iter_raw_events(['{"not": "json"', '{"eventName": "Good"}']))
        assert len(out) == 1
        assert out[0]["eventName"] == "Good"
        assert "skipping line" in capsys.readouterr().err

    def test_skips_malformed_with_json_stderr(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        out = list(iter_raw_events(['{"not": "json"', '{"eventName": "Good"}']))
        assert len(out) == 1
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1

    def test_mixed_random_garbage_keeps_valid_events(self, capsys):
        rng = random.Random(7)
        alphabet = string.ascii_letters + string.digits + "[]{}:,"
        malformed = ["".join(rng.choice(alphabet) for _ in range(25)) for _ in range(20)]
        lines = malformed + [json.dumps({"eventName": "StillGood"})]

        out = list(iter_raw_events(lines))

        assert out == [{"eventName": "StillGood"}]
        stderr = capsys.readouterr().err
        assert "skipping line" in stderr


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

    def test_fixture_has_all_four_activity_types(self):
        events = _load_jsonl(OCSF_FIXTURE)
        activities = {e["activity_id"] for e in events}
        # Fixture is designed to exercise Create, Read, Delete, Update
        assert activities == {ACTIVITY_CREATE, ACTIVITY_READ, ACTIVITY_DELETE, ACTIVITY_UPDATE}

    def test_fixture_has_one_failure(self):
        events = _load_jsonl(OCSF_FIXTURE)
        failures = [e for e in events if e["status_id"] == STATUS_FAILURE]
        assert len(failures) == 1
        assert failures[0]["api"]["operation"] == "DeleteUser"
        assert "AccessDenied" in failures[0]["status_detail"]

    def test_fixture_actor_names_present(self):
        events = _load_jsonl(OCSF_FIXTURE)
        names = {e["actor"]["user"]["name"] for e in events}
        # principalId becomes the name when userName is missing (assumed-role events)
        assert "AROAEXAMPLEID:alice" in names or "alice" in names
        assert "bob" in names

    def test_native_output_mode_emits_enriched_events(self):
        produced = list(ingest(RAW_FIXTURE.read_text().splitlines(), output_format="native"))
        assert len(produced) == 4
        first = produced[0]
        assert first["schema_mode"] == "native"
        assert first["record_type"] == "api_activity"
        assert first["provider"] == "AWS"
        assert "class_uid" not in first
        assert "metadata" not in first
