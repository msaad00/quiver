"""Tests for detect-snowflake-failed-mfa-burst."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    AUTH_CLASS_UID,
    FAIL_THRESHOLD_DEFAULT,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_SECONDARY_TECHNIQUE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    OWASP_FINDING_TYPE,
    REPO_NAME,
    REPO_VENDOR,
    SEVERITY_HIGH,
    SKILL_NAME,
    WINDOW_MIN_DEFAULT,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "snowflake_failed_mfa_burst_input.ocsf.jsonl"
EXPECTED = GOLDEN / "snowflake_failed_mfa_burst_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "MARK",
    actor_name: str = "mark@example.com",
    authentication_method: str = "MFA",
    error_code: str = "390127",
    is_success: bool = False,
    src_ip: str = "203.0.113.10",
    producer: str = "ingest-snowflake-login-history-ocsf",
    class_uid: int = AUTH_CLASS_UID,
) -> dict:
    return {
        "activity_id": 2 if not is_success else 1,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": class_uid,
        "class_name": "Authentication",
        "type_uid": class_uid * 100 + 1,
        "severity_id": 3,
        "status_id": 1 if is_success else 2,
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
        "src_endpoint": {"ip": src_ip},
        "unmapped": {
            "snowflake": {
                "authentication_method": authentication_method,
                "error_code": error_code,
                "is_success": is_success,
                "event_id": uid,
            }
        },
    }


def _burst(*, count: int, actor_uid: str = "MARK", time_start: int = 1_000) -> list[dict]:
    return [
        _event(
            uid=f"q-{actor_uid}-{i}",
            time_ms=time_start + i * 1_000,
            actor_uid=actor_uid,
        )
        for i in range(count)
    ]


class TestDetection:
    def test_eight_failed_mfa_events_fire_once(self) -> None:
        events = _burst(count=8)
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        technique_uids = {
            attack["technique"]["uid"] for attack in finding["finding_info"]["attacks"]
        }
        assert MITRE_TECHNIQUE_UID in technique_uids
        assert MITRE_SECONDARY_TECHNIQUE_UID in technique_uids
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["failed_event_count"] == 8

    def test_threshold_minus_one_does_not_fire(self) -> None:
        # 7 failed-MFA events — one short of the default threshold.
        events = _burst(count=FAIL_THRESHOLD_DEFAULT - 1)
        assert list(detect(events)) == []

    def test_successful_mfa_events_do_not_fire(self) -> None:
        events = [
            _event(uid=f"s-{i}", time_ms=1_000 + i * 1_000, is_success=True)
            for i in range(FAIL_THRESHOLD_DEFAULT)
        ]
        assert list(detect(events)) == []

    def test_non_mfa_failed_logins_are_ignored(self) -> None:
        events = [
            _event(uid=f"p-{i}", time_ms=1_000 + i * 1_000, authentication_method="PASSWORD")
            for i in range(FAIL_THRESHOLD_DEFAULT)
        ]
        assert list(detect(events)) == []

    def test_non_snowflake_producer_is_ignored(self) -> None:
        events = [
            _event(uid=f"o-{i}", time_ms=1_000 + i * 1_000, producer="ingest-okta-system-log-ocsf")
            for i in range(FAIL_THRESHOLD_DEFAULT)
        ]
        assert list(detect(events)) == []

    def test_wrong_class_uid_is_ignored(self) -> None:
        events = [
            _event(uid=f"c-{i}", time_ms=1_000 + i * 1_000, class_uid=6003)
            for i in range(FAIL_THRESHOLD_DEFAULT)
        ]
        assert list(detect(events)) == []

    def test_out_of_order_events_still_fire_once(self) -> None:
        events = list(reversed(_burst(count=FAIL_THRESHOLD_DEFAULT)))
        assert len(list(detect(events))) == 1

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = _burst(count=FAIL_THRESHOLD_DEFAULT - 1)
        events.append(events[-1])  # dup the last event_uid
        assert list(detect(events)) == []

    def test_two_principals_each_fire_separately(self) -> None:
        events = _burst(count=FAIL_THRESHOLD_DEFAULT, actor_uid="ALICE") + _burst(
            count=FAIL_THRESHOLD_DEFAULT, actor_uid="BOB", time_start=100_000
        )
        findings = list(detect(events))
        assert len(findings) == 2
        principals = {finding["observables"][0]["value"] for finding in findings}
        assert principals == {"ALICE", "BOB"}

    def test_events_outside_window_do_not_aggregate(self) -> None:
        # Spread 8 events across 2 hours; only events inside the 10-minute
        # window contribute, so the threshold is never reached.
        events = [
            _event(uid=f"f-{i}", time_ms=1_000 + i * 15 * 60_000)
            for i in range(FAIL_THRESHOLD_DEFAULT)
        ]
        assert list(detect(events)) == []

    def test_native_output_format(self) -> None:
        findings = list(detect(_burst(count=FAIL_THRESHOLD_DEFAULT), output_format="native"))
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
        events = _burst(count=FAIL_THRESHOLD_DEFAULT)
        assert len(list(detect(events))) == 1

        monkeypatch.setenv("SNOWFLAKE_MFA_FAIL_THRESHOLD", "20")
        assert list(detect(events)) == []

    def test_window_env_override_widens_aggregation(self, monkeypatch) -> None:
        # Spread events across 30 minutes — default 10-minute window misses.
        events = [
            _event(uid=f"w-{i}", time_ms=1_000 + i * 4 * 60_000)
            for i in range(FAIL_THRESHOLD_DEFAULT)
        ]
        assert list(detect(events)) == []

        monkeypatch.setenv("SNOWFLAKE_MFA_FAIL_WINDOW_MIN", "120")
        assert len(list(detect(events))) == 1


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("snowflake",)
        assert metadata["thresholds"]["window_minutes"] == WINDOW_MIN_DEFAULT
        assert metadata["thresholds"]["fail_threshold"] == FAIL_THRESHOLD_DEFAULT
        assert "ingest-snowflake-login-history-ocsf" in ACCEPTED_PRODUCERS


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 3002}']))
        assert out == [{"class_uid": 3002}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_emits_json_stderr_telemetry_when_enabled(self, capsys, monkeypatch) -> None:
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        list(load_jsonl(['{"bad": ']))
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1
