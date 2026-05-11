"""Tests for ingest-slack-audit-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_slack_audit", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

API_ACTIVITY_CLASS_UID = _INGEST.API_ACTIVITY_CLASS_UID
AUTH_ACTIVITY_LOGOFF = _INGEST.AUTH_ACTIVITY_LOGOFF
AUTH_ACTIVITY_LOGON = _INGEST.AUTH_ACTIVITY_LOGON
AUTH_CLASS_UID = _INGEST.AUTH_CLASS_UID
CANONICAL_VERSION = _INGEST.CANONICAL_VERSION
OCSF_VERSION = _INGEST.OCSF_VERSION
OUTPUT_FORMATS = _INGEST.OUTPUT_FORMATS
SKILL_NAME = _INGEST.SKILL_NAME
USER_ACCESS_ASSIGN = _INGEST.USER_ACCESS_ASSIGN
USER_ACCESS_CLASS_UID = _INGEST.USER_ACCESS_CLASS_UID
USER_ACCESS_REVOKE = _INGEST.USER_ACCESS_REVOKE
_classify_action = _INGEST._classify_action
convert_event = _INGEST.convert_event
ingest = _INGEST.ingest
iter_raw_events = _INGEST.iter_raw_events
parse_ts_ms = _INGEST.parse_ts_ms
validate_event = _INGEST.validate_event

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
RAW_FIXTURE = GOLDEN / "slack_audit_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "slack_audit_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _entry(**overrides) -> dict:
    entry = {
        "id": "slack-evt-1",
        "date_create": 1718323200,
        "action": "user_login",
        "actor": {
            "type": "user",
            "user": {
                "id": "U01234ABC",
                "name": "alice",
                "email": "alice@example.com",
                "team": "T01234XYZ",
            },
        },
        "entity": {
            "type": "user",
            "user": {"id": "U01234ABC", "name": "alice", "email": "alice@example.com"},
        },
        "context": {
            "location": {"type": "workspace", "id": "T01234XYZ", "name": "Example Corp"},
            "ua": "Mozilla/5.0",
            "ip_address": "203.0.113.10",
            "session_id": "sess-1",
        },
    }
    entry.update(overrides)
    return entry


class TestParseTs:
    def test_unix_seconds(self):
        assert parse_ts_ms(1718323200) == 1718323200000

    def test_float_seconds(self):
        assert parse_ts_ms(1718323200.5) == 1718323200500

    def test_missing(self):
        ms = parse_ts_ms(None)
        assert isinstance(ms, int) and ms > 1_700_000_000_000


class TestClassification:
    def test_authentication_routes(self):
        assert _classify_action("user_login") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGON)
        assert _classify_action("user_logout") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGOFF)
        assert _classify_action("signout_all_sessions") == (AUTH_CLASS_UID, "Authentication", AUTH_ACTIVITY_LOGOFF)

    def test_user_access_routes(self):
        assert _classify_action("private_channel_member_added") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_ASSIGN,
        )
        assert _classify_action("workspace_user_removed_from_workspace") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_REVOKE,
        )
        assert _classify_action("role_change_to_admin") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_ASSIGN,
        )
        assert _classify_action("role_change_to_owner") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_ASSIGN,
        )

    def test_api_activity_routes(self):
        out = _classify_action("app_installed")
        assert out is not None and out[0] == API_ACTIVITY_CLASS_UID
        out = _classify_action("file_downloaded")
        assert out is not None and out[0] == API_ACTIVITY_CLASS_UID


class TestValidation:
    def test_valid_event(self):
        ok, _ = validate_event(_entry())
        assert ok

    def test_unsupported_action(self):
        ok, reason = validate_event(_entry(action="totally_unknown"))
        assert not ok
        assert "unsupported action" in reason

    def test_missing_date(self):
        bad = _entry()
        del bad["date_create"]
        ok, reason = validate_event(bad)
        assert not ok and "date_create" in reason


class TestConvert:
    def test_login_authentication_event(self):
        event = convert_event(_entry())
        assert event["class_uid"] == AUTH_CLASS_UID
        assert event["activity_id"] == AUTH_ACTIVITY_LOGON
        assert event["metadata"]["uid"] == "slack-evt-1"
        assert event["metadata"]["version"] == OCSF_VERSION
        assert event["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert event["actor"]["user"]["email_addr"] == "alice@example.com"
        assert event["src_endpoint"]["ip"] == "203.0.113.10"
        assert event["unmapped"]["slack"]["workspace"]["id"] == "T01234XYZ"

    def test_external_private_channel_add(self):
        event = convert_event(
            _entry(
                id="slack-evt-ext-1",
                action="private_channel_member_added",
                entity={
                    "type": "user",
                    "user": {"id": "UEXT", "name": "eve", "email": "eve@partner.com", "team": "TEXT"},
                },
                details={
                    "channel": {"id": "C01234SEC", "name": "security-private", "privacy": "private"},
                    "workspace_type": "external",
                    "is_external": True,
                },
            )
        )
        assert event["class_uid"] == USER_ACCESS_CLASS_UID
        assert event["activity_id"] == USER_ACCESS_ASSIGN
        slack = event["unmapped"]["slack"]
        assert slack["workspace_type"] == "external"
        assert slack["channel"]["name"] == "security-private"
        assert event["user"]["uid"] == "UEXT"

    def test_role_change_to_admin(self):
        event = convert_event(
            _entry(
                id="slack-evt-role-1",
                action="role_change_to_admin",
                entity={"type": "user", "user": {"id": "U02", "name": "bob"}},
                details={"new_role": "admin", "previous_role": "user"},
            )
        )
        assert event["class_uid"] == USER_ACCESS_CLASS_UID
        assert event["unmapped"]["slack"]["new_role"] == "admin"
        assert event["unmapped"]["slack"]["previous_role"] == "user"

    def test_app_install_api_activity(self):
        event = convert_event(
            _entry(
                id="slack-evt-app-1",
                action="app_installed",
                details={
                    "app": {"id": "A0123", "name": "Notes Bot", "is_distributed": True},
                    "scopes": ["chat:write", "files:read", "channels:read"],
                },
            )
        )
        assert event["class_uid"] == API_ACTIVITY_CLASS_UID
        assert event["api"]["operation"] == "app_installed"
        slack = event["unmapped"]["slack"]
        assert slack["app"]["id"] == "A0123"
        assert slack["scopes"] == ["chat:write", "files:read", "channels:read"]

    def test_native_projection_strips_ocsf_envelope(self):
        event = convert_event(_entry(), output_format="native")
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert event["schema_mode"] == "native"
        assert event["canonical_schema_version"] == CANONICAL_VERSION
        assert event["record_type"] == "authentication"
        assert event["provider"] == "Slack"
        assert "class_uid" not in event

    def test_metadata_uid_fallback_when_id_missing(self):
        raw = _entry()
        del raw["id"]
        event = convert_event(raw)
        assert event["metadata"]["uid"] and len(event["metadata"]["uid"]) == 64


class TestIterRawEvents:
    def test_audit_logs_response_wrapper(self):
        wrapped = {"entries": [_entry(id="a"), _entry(id="b")]}
        events = list(iter_raw_events([json.dumps(wrapped)]))
        assert [event["id"] for event in events] == ["a", "b"]

    def test_single_entry(self):
        events = list(iter_raw_events([json.dumps(_entry(id="solo"))]))
        assert [event["id"] for event in events] == ["solo"]

    def test_ndjson_with_bad_line(self, capsys):
        events = list(iter_raw_events([json.dumps(_entry(id="ok")), '{"bad"']))
        assert [event["id"] for event in events] == ["ok"]
        assert "skipping line" in capsys.readouterr().err

    def test_json_stderr_telemetry_for_bad_line(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        list(iter_raw_events(['{"bad"']))
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["event"] == "json_parse_failed"


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


class TestUnmappedEventCounter:
    """Audit honesty: every unmapped Slack action is counted, not silently dropped."""

    def _wrap(self, action: str) -> str:
        return json.dumps(
            {"id": f"u-{action}", "date_create": 1718323200, "action": action}
        )

    def test_unmapped_counts_populated_with_repeats(self):
        unmapped: dict[str, int] = {}
        events = [
            self._wrap("totally.fake.action"),
            self._wrap("totally.fake.action"),
            self._wrap("another.fake.action"),
        ]
        produced = list(ingest(events, unmapped_counts=unmapped))
        assert produced == []
        assert unmapped == {"totally.fake.action": 2, "another.fake.action": 1}

    def test_unmapped_counts_optional(self):
        # No regression: omitting the kwarg still works.
        list(ingest([self._wrap("totally.fake.action")]))
