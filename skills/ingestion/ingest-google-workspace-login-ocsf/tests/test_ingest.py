"""Tests for ingest-google-workspace-login-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_google_workspace_login", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

ACCOUNT_CHANGE_CLASS_UID = _INGEST.ACCOUNT_CHANGE_CLASS_UID
ACCOUNT_CHANGE_MFA_DISABLE = _INGEST.ACCOUNT_CHANGE_MFA_DISABLE
ACCOUNT_CHANGE_MFA_ENABLE = _INGEST.ACCOUNT_CHANGE_MFA_ENABLE
AUTH_ACTIVITY_LOGOFF = _INGEST.AUTH_ACTIVITY_LOGOFF
AUTH_ACTIVITY_LOGON = _INGEST.AUTH_ACTIVITY_LOGON
AUTH_CLASS_UID = _INGEST.AUTH_CLASS_UID
CANONICAL_VERSION = _INGEST.CANONICAL_VERSION
OCSF_VERSION = _INGEST.OCSF_VERSION
OUTPUT_FORMATS = _INGEST.OUTPUT_FORMATS
SKILL_NAME = _INGEST.SKILL_NAME
STATUS_FAILURE = _INGEST.STATUS_FAILURE
STATUS_SUCCESS = _INGEST.STATUS_SUCCESS
SUPPORTED_EVENT_NAMES = _INGEST.SUPPORTED_EVENT_NAMES
_classify = _INGEST._classify
convert_activity_event = _INGEST.convert_activity_event
ingest = _INGEST.ingest
iter_raw_activities = _INGEST.iter_raw_activities
parse_ts_ms = _INGEST.parse_ts_ms
validate_activity = _INGEST.validate_activity

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
RAW_FIXTURE = GOLDEN / "google_workspace_login_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "google_workspace_login_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _activity(**overrides) -> dict:
    activity = {
        "kind": "audit#activity",
        "id": {
            "time": "2026-04-13T06:00:00.000Z",
            "uniqueQualifier": "workspace-evt-1",
            "applicationName": "login",
            "customerId": "C03az79cb",
        },
        "actor": {
            "callerType": "USER",
            "email": "alice@example.com",
            "profileId": "117200475532672775229",
        },
        "ownerDomain": "example.com",
        "ipAddress": "198.51.100.21",
        "events": [
            {
                "type": "login",
                "name": "login_success",
                "parameters": [
                    {"name": "login_type", "value": "google_password"},
                    {"name": "is_suspicious", "boolValue": True},
                    {"name": "login_challenge_method", "value": "backup_code"},
                ],
            }
        ],
    }
    activity.update(overrides)
    return activity


class TestParseTs:
    def test_iso_z(self):
        assert parse_ts_ms("2026-04-13T06:00:00.000Z") == 1776060000000

    def test_missing_falls_to_now(self):
        ms = parse_ts_ms(None)
        assert isinstance(ms, int) and ms > 1_700_000_000_000


class TestClassification:
    def test_supported_events_are_narrow(self):
        assert SUPPORTED_EVENT_NAMES == {
            "login_success",
            "login_failure",
            "logout",
            "2sv_enroll",
            "2sv_disable",
        }

    def test_authentication_routes(self):
        assert _classify("login_success") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGON)
        assert _classify("logout") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGOFF)

    def test_account_change_routes(self):
        assert _classify("2sv_enroll") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_MFA_ENABLE,
        )
        assert _classify("2sv_disable") == (
            ACCOUNT_CHANGE_CLASS_UID,
            "Account Change",
            ACCOUNT_CHANGE_MFA_DISABLE,
        )


class TestValidation:
    def test_valid_activity(self):
        ok, reason = validate_activity(_activity())
        assert ok, reason

    def test_missing_id_time(self):
        ok, reason = validate_activity(_activity(id={"applicationName": "login"}))
        assert not ok
        assert "id.time" in reason

    def test_missing_events(self):
        ok, reason = validate_activity(_activity(events=[]))
        assert not ok
        assert "events" in reason


class TestConvert:
    def test_login_success(self):
        activity = _activity()
        event = convert_activity_event(activity, activity["events"][0])
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_LOGON
        assert event["status_id"] == STATUS_SUCCESS
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert event["actor"]["user"]["email_addr"] == "alice@example.com"
        assert event["user"]["email_addr"] == "alice@example.com"
        assert event["src_endpoint"]["ip"] == "198.51.100.21"
        assert event["session"]["uid"] == "workspace-evt-1"
        assert (
            event["unmapped"]["google_workspace_login"]["parameters"]["login_type"]
            == "google_password"
        )

    def test_login_failure(self):
        activity = _activity(
            events=[
                {
                    "type": "login",
                    "name": "login_failure",
                    "parameters": [
                        {"name": "login_failure_type", "value": "login_failure_invalid_password"},
                        {"name": "login_type", "value": "google_password"},
                    ],
                }
            ]
        )
        event = convert_activity_event(activity, activity["events"][0])
        assert event["status_id"] == STATUS_FAILURE
        assert event["status_detail"] == "login_failure_invalid_password"

    def test_2sv_disable(self):
        activity = _activity(
            events=[
                {
                    "type": "2sv_change",
                    "name": "2sv_disable",
                    "parameters": [],
                }
            ]
        )
        event = convert_activity_event(activity, activity["events"][0])
        assert event["class_uid"] == ACCOUNT_CHANGE_CLASS_UID
        assert event["activity_id"] == ACCOUNT_CHANGE_MFA_DISABLE

    def test_native_output_has_no_ocsf_envelope(self):
        activity = _activity()
        event = convert_activity_event(activity, activity["events"][0], output_format="native")
        assert event["schema_mode"] == "native"
        assert event["canonical_schema_version"] == CANONICAL_VERSION
        assert event["record_type"] == "authentication"
        assert event["provider"] == "Google Workspace"
        assert event["event_name"] == "login_success"
        assert event["event_uid"]
        assert "class_uid" not in event
        assert "metadata" not in event


class TestIterRawActivities:
    def test_items_wrapper(self):
        wrapped = {
            "items": [
                _activity(),
                _activity(id={**_activity()["id"], "uniqueQualifier": "workspace-evt-2"}),
            ]
        }
        events = list(iter_raw_activities([json.dumps(wrapped)]))
        assert len(events) == 2

    def test_array(self):
        events = list(
            iter_raw_activities(
                [
                    json.dumps(
                        [
                            _activity(),
                            _activity(
                                id={**_activity()["id"], "uniqueQualifier": "workspace-evt-2"}
                            ),
                        ]
                    )
                ]
            )
        )
        assert len(events) == 2

    def test_ndjson_and_bad_line(self, capsys):
        lines = [json.dumps(_activity()), '{"broken"']
        events = list(iter_raw_activities(lines))
        assert len(events) == 1
        assert "skipping line" in capsys.readouterr().err

    def test_json_stderr_telemetry_for_bad_line(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        list(iter_raw_activities(['{"broken"']))
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1


class TestGoldenFixture:
    def test_golden_fixture(self):
        produced = list(ingest([RAW_FIXTURE.read_text()]))
        expected = _load_jsonl(OCSF_FIXTURE)
        assert produced == expected

    def test_native_projection_preserves_event_uid(self):
        native = list(ingest([RAW_FIXTURE.read_text()], output_format="native"))
        ocsf = list(ingest([RAW_FIXTURE.read_text()], output_format="ocsf"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(native) == len(ocsf)
        assert native[0]["event_uid"] == ocsf[0]["metadata"]["uid"]
        assert native[0]["schema_mode"] == "native"
        assert "class_uid" not in native[0]
