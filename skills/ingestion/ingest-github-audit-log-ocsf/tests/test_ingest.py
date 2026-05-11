"""Tests for ingest-github-audit-log-ocsf."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ingest.py"
_SPEC = importlib.util.spec_from_file_location("ingest_github_audit_log", _SRC)
assert _SPEC and _SPEC.loader
_INGEST = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _INGEST
_SPEC.loader.exec_module(_INGEST)

API_ACTIVITY_CLASS_UID = _INGEST.API_ACTIVITY_CLASS_UID
AUTH_CLASS_UID = _INGEST.AUTH_CLASS_UID
USER_ACCESS_CLASS_UID = _INGEST.USER_ACCESS_CLASS_UID
USER_ACCESS_ASSIGN = _INGEST.USER_ACCESS_ASSIGN
USER_ACCESS_REVOKE = _INGEST.USER_ACCESS_REVOKE
AUTH_ACTIVITY_LOGON = _INGEST.AUTH_ACTIVITY_LOGON
API_ACTIVITY_CREATE = _INGEST.API_ACTIVITY_CREATE
API_ACTIVITY_UPDATE = _INGEST.API_ACTIVITY_UPDATE
OCSF_VERSION = _INGEST.OCSF_VERSION
OUTPUT_FORMATS = _INGEST.OUTPUT_FORMATS
SKILL_NAME = _INGEST.SKILL_NAME
STATUS_SUCCESS = _INGEST.STATUS_SUCCESS
STATUS_FAILURE = _INGEST.STATUS_FAILURE
_classify_event = _INGEST._classify_event
convert_event = _INGEST.convert_event
ingest = _INGEST.ingest
iter_raw_events = _INGEST.iter_raw_events
parse_ts_ms = _INGEST.parse_ts_ms
validate_event = _INGEST.validate_event

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
RAW_FIXTURE = GOLDEN / "github_audit_log_raw_sample.json"
OCSF_FIXTURE = GOLDEN / "github_audit_log_sample.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(**overrides) -> dict:
    event = {
        "_document_id": "doc-1",
        "@timestamp": 1735689600000,
        "action": "personal_access_token.access_granted",
        "actor": "alice",
        "actor_id": 1001,
        "actor_ip": "203.0.113.10",
        "user_agent": "GitHub CLI/2.40.0",
        "actor_location": {"country_code": "US"},
        "org": "acme",
        "org_id": 42,
        "request_id": "req-abc",
        "programmatic_access_type": "fine_grained_personal_access_token",
        "token_id": 9001,
        "hashed_token": "deadbeef",
    }
    event.update(overrides)
    return event


class TestParseTs:
    def test_iso_z(self):
        assert parse_ts_ms("2025-01-01T00:00:00Z") == 1735689600000

    def test_millis_int(self):
        assert parse_ts_ms(1735689600000) == 1735689600000

    def test_seconds_int_promotes_to_ms(self):
        assert parse_ts_ms(1735689600) == 1735689600000

    def test_none_falls_to_now(self):
        ms = parse_ts_ms(None)
        assert isinstance(ms, int) and ms > 1_700_000_000_000


class TestClassification:
    def test_user_access_routes(self):
        assert _classify_event("org.add_member") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_ASSIGN,
        )
        assert _classify_event("org.remove_member") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_REVOKE,
        )
        assert _classify_event("team.add_member") == (
            USER_ACCESS_CLASS_UID,
            "User Access Management",
            USER_ACCESS_ASSIGN,
        )

    def test_auth_routes(self):
        assert _classify_event("account.login") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_LOGON,
        )
        assert _classify_event("account.failed_login") == (
            AUTH_CLASS_UID,
            "Authentication",
            AUTH_ACTIVITY_LOGON,
        )

    def test_api_activity_routes(self):
        result = _classify_event("personal_access_token.access_granted")
        assert result is not None
        assert result[0] == API_ACTIVITY_CLASS_UID
        assert result[2] == API_ACTIVITY_CREATE

    def test_unknown_returns_none(self):
        assert _classify_event("totally.fake.action") is None


class TestValidation:
    def test_valid_event(self):
        ok, reason = validate_event(_event())
        assert ok, reason

    def test_missing_action(self):
        evt = _event()
        evt.pop("action")
        ok, reason = validate_event(evt)
        assert not ok
        assert "action" in reason

    def test_missing_timestamp(self):
        evt = _event()
        evt.pop("@timestamp")
        ok, reason = validate_event(evt)
        assert not ok
        assert "@timestamp" in reason

    def test_unsupported_action(self):
        ok, reason = validate_event(_event(action="totally.fake.action"))
        assert not ok
        assert "unsupported action" in reason


class TestConvert:
    def test_pat_create_routes_to_api_activity(self):
        out = convert_event(_event())
        assert out["class_uid"] == API_ACTIVITY_CLASS_UID
        assert out["activity_id"] == API_ACTIVITY_CREATE
        assert out["api"]["operation"] == "personal_access_token.access_granted"
        assert out["metadata"]["uid"] == "doc-1"
        assert out["metadata"]["version"] == OCSF_VERSION
        assert out["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert out["actor"]["user"]["name"] == "alice"
        assert out["src_endpoint"]["ip"] == "203.0.113.10"
        assert out["unmapped"]["github"]["programmatic_access_type"] == "fine_grained_personal_access_token"
        assert out["unmapped"]["github"]["hashed_token"] == "deadbeef"

    def test_org_add_member_routes_to_user_access(self):
        out = convert_event(_event(action="org.add_member", permission="admin"))
        assert out["class_uid"] == USER_ACCESS_CLASS_UID
        assert out["activity_id"] == USER_ACCESS_ASSIGN
        assert out["privileges"] == ["admin"]

    def test_account_failed_login_routes_to_authentication(self):
        out = convert_event(_event(action="account.failed_login"))
        assert out["class_uid"] == AUTH_CLASS_UID
        assert out["status_id"] == STATUS_FAILURE

    def test_account_login_success(self):
        out = convert_event(_event(action="account.login"))
        assert out["class_uid"] == AUTH_CLASS_UID
        assert out["status_id"] == STATUS_SUCCESS

    def test_native_projection_strips_ocsf_envelope(self):
        out = convert_event(_event(), output_format="native")
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert out["schema_mode"] == "native"
        assert out["record_type"] == "api_activity"
        assert out["event_uid"] == "doc-1"
        assert out["provider"] == "GitHub"
        assert "class_uid" not in out
        assert "metadata" not in out

    def test_visibility_delta_preserved_under_unmapped(self):
        out = convert_event(
            _event(
                action="actions.org_secret_update",
                secret_name="DEPLOY_KEY",
                visibility="all",
                before_visibility="selected",
                selected_repositories=[],
                before_selected_repositories=[101, 202, 303],
            )
        )
        gh = out["unmapped"]["github"]
        assert gh["visibility"] == "all"
        assert gh["before_visibility"] == "selected"
        assert gh["before_selected_repositories"] == [101, 202, 303]


class TestIterRawEvents:
    def test_array(self):
        events = list(
            iter_raw_events(
                [json.dumps([_event(_document_id="a"), _event(_document_id="b")])]
            )
        )
        assert [e["_document_id"] for e in events] == ["a", "b"]

    def test_wrapper(self):
        wrapped = {"audit_log": [_event(_document_id="w-1"), _event(_document_id="w-2")]}
        events = list(iter_raw_events([json.dumps(wrapped)]))
        assert [e["_document_id"] for e in events] == ["w-1", "w-2"]

    def test_ndjson_with_bad_line(self, capsys):
        events = list(
            iter_raw_events(
                [
                    json.dumps(_event(_document_id="ok")),
                    '{"bad"',
                ]
            )
        )
        assert len(events) == 1
        assert events[0]["_document_id"] == "ok"
        assert "skipping line" in capsys.readouterr().err

    def test_mixed_batch_keeps_valid_events(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        out = list(
            ingest(
                [
                    json.dumps(_event(_document_id="g-1")),
                    '{"bad"',
                    "[]",
                    json.dumps(_event(_document_id="g-2")),
                ]
            )
        )
        assert [event["metadata"]["uid"] for event in out] == ["g-1", "g-2"]
        stderr_lines = [
            json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()
        ]
        assert [payload["event"] for payload in stderr_lines] == [
            "json_parse_failed",
            "invalid_json_shape",
        ]


class TestUnmappedEventCounter:
    """Audit honesty: every unmapped GitHub action is counted, not silently dropped."""

    def _wrap(self, action: str) -> str:
        return json.dumps(
            {
                "_document_id": f"doc-{action}",
                "@timestamp": "2025-01-01T00:00:00Z",
                "action": action,
            }
        )

    def test_unmapped_counts_populated_with_repeats(self):
        unmapped: dict[str, int] = {}
        events = [
            self._wrap("totally.fake.event.one"),
            self._wrap("totally.fake.event.one"),
            self._wrap("totally.fake.event.two"),
        ]
        produced = list(ingest(events, unmapped_counts=unmapped))
        assert produced == []
        assert unmapped == {
            "totally.fake.event.one": 2,
            "totally.fake.event.two": 1,
        }

    def test_unmapped_counts_unaffected_by_invalid_payloads(self):
        unmapped: dict[str, int] = {}
        events = [
            json.dumps(
                {"_document_id": "missing-ts", "action": "personal_access_token.create"}
            ),
            self._wrap("totally.fake.event"),
        ]
        list(ingest(events, unmapped_counts=unmapped))
        assert unmapped == {"totally.fake.event": 1}


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
