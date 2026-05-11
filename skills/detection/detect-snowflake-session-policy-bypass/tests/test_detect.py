"""Tests for detect-snowflake-session-policy-bypass."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    API_ACTIVITY_CLASS_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MAX_IDLE_MINS_DEFAULT,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    REPO_VENDOR,
    SESSION_POLICY_OPERATIONS,
    SEVERITY_HIGH,
    SKILL_NAME,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "snowflake_session_policy_bypass_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_session_policy_bypass_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "ACCOUNTADMIN",
    actor_name: str = "alice@example.com",
    api_operation: str = "ALTER_SESSION_POLICY",
    policy_name: str = "SESSION_POLICY_PROD",
    session_idle_timeout_mins: int = 240,
    session_ui_idle_timeout_mins: int = 30,
    producer: str = "ingest-snowflake-query-history-ocsf",
    status_id: int = 1,
) -> dict:
    return {
        "activity_id": 1,
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "type_uid": API_ACTIVITY_CLASS_UID * 100 + 1,
        "severity_id": 1,
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": producer},
            },
        },
        "actor": {"user": {"uid": actor_uid, "name": actor_name, "type": "User"}},
        "api": {"operation": api_operation, "service": {"name": "snowflake.warehouse"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {
            "snowflake": {
                "policy_name": policy_name,
                "session_idle_timeout_mins": session_idle_timeout_mins,
                "session_ui_idle_timeout_mins": session_ui_idle_timeout_mins,
                "query_id": uid,
            }
        },
    }


class TestDetection:
    def test_idle_timeout_raised_fires(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, session_idle_timeout_mins=240)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["session_idle_timeout_mins"] == 240
        assert finding["evidence"]["threshold_mins"] == MAX_IDLE_MINS_DEFAULT

    def test_ui_idle_timeout_raised_fires_when_idle_unchanged(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                session_idle_timeout_mins=15,
                session_ui_idle_timeout_mins=60,
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["session_ui_idle_timeout_mins"] == 60

    def test_at_threshold_does_not_fire(self) -> None:
        # Equal to threshold = compliant.
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                session_idle_timeout_mins=MAX_IDLE_MINS_DEFAULT,
                session_ui_idle_timeout_mins=MAX_IDLE_MINS_DEFAULT,
            )
        ]
        assert list(detect(events)) == []

    def test_below_threshold_does_not_fire(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                session_idle_timeout_mins=15,
                session_ui_idle_timeout_mins=15,
            )
        ]
        assert list(detect(events)) == []

    def test_non_session_policy_operation_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, api_operation="SELECT")]
        assert list(detect(events)) == []

    def test_failed_status_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, producer="ingest-cloudtrail-ocsf")]
        assert list(detect(events)) == []

    def test_missing_policy_name_is_ignored(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000, policy_name="")]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [
            _event(uid="q-1", time_ms=1_000),
            _event(uid="q-1", time_ms=1_000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_create_session_policy_with_high_idle_fires(self) -> None:
        events = [
            _event(
                uid="q-1",
                time_ms=1_000,
                api_operation="CREATE_SESSION_POLICY",
                session_idle_timeout_mins=120,
            )
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["operation"] == "CREATE_SESSION_POLICY"

    def test_native_output_format(self) -> None:
        events = [_event(uid="q-1", time_ms=1_000)]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Snowflake"
        assert "class_uid" not in finding

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
            assert exc.error_class == "contract"
            assert exc.retryable is False
        else:
            raise AssertionError("expected unsupported output_format to raise")

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestThresholdOverrides:
    def test_threshold_env_override_raises_bar(self, monkeypatch) -> None:
        events = [_event(uid="q-1", time_ms=1_000, session_idle_timeout_mins=60)]
        assert len(list(detect(events))) == 1

        monkeypatch.setenv("SNOWFLAKE_SESSION_POLICY_MAX_IDLE_MINS", "120")
        assert list(detect(events)) == []


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert metadata["thresholds"]["max_idle_mins"] == MAX_IDLE_MINS_DEFAULT
        assert "ALTER_SESSION_POLICY" in SESSION_POLICY_OPERATIONS
        assert "ingest-snowflake-query-history-ocsf" in ACCEPTED_PRODUCERS


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
