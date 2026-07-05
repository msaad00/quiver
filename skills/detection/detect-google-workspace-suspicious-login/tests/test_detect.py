"""Tests for detect-google-workspace-suspicious-login."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detect import (  # type: ignore[import-not-found]  # noqa: E402
    AUTH_CLASS_UID,
    BRUTE_FORCE_UID,
    CANONICAL_VERSION,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MIN_FAILURES,
    OUTPUT_FORMATS,
    REPO_NAME,
    REPO_VENDOR,
    SKILL_NAME,
    VALID_ACCOUNTS_UID,
    WINDOW_MS,
    coverage_metadata,
    detect,
    load_jsonl,
)

from skills._shared.errors import ContractError  # noqa: E402

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT = GOLDEN / "google_workspace_suspicious_login_input.ocsf.jsonl"
EXPECTED = GOLDEN / "google_workspace_suspicious_login_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    event_name: str,
    time_ms: int,
    user_uid: str = "workspace-user-1",
    user_name: str = "alice@example.com",
    ip: str = "198.51.100.21",
    session_uid: str = "workspace-login-1",
    suspicious: bool = False,
    status_id: int = 1,
    status_detail: str | None = None,
) -> dict:
    params: dict[str, object] = {"login_type": "google_password"}
    if suspicious:
        params["is_suspicious"] = True
    event = {
        "activity_id": 1,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": AUTH_CLASS_UID,
        "class_name": "Authentication",
        "type_uid": 300201,
        "severity_id": 2,
        "status_id": status_id,
        "time": time_ms,
        "message": event_name,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": "ingest-google-workspace-login-ocsf"},
            },
        },
        "src_endpoint": {"ip": ip},
        "user": {"uid": user_uid, "name": user_name, "email_addr": user_name},
        "session": {"uid": session_uid},
        "unmapped": {
            "google_workspace_login": {
                "event_name": event_name,
                "event_type": "login",
                "parameters": params,
            }
        },
    }
    if status_detail:
        event["status_detail"] = status_detail
    return event


def _native_event(
    *,
    uid: str,
    event_name: str,
    time_ms: int,
    user_uid: str = "workspace-user-1",
    user_name: str = "alice@example.com",
    ip: str = "198.51.100.21",
    session_uid: str = "workspace-login-1",
    suspicious: bool = False,
    status_id: int = 1,
    status_detail: str | None = None,
) -> dict:
    params: dict[str, object] = {"login_type": "google_password"}
    if suspicious:
        params["is_suspicious"] = True
    event = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "authentication",
        "source_skill": "ingest-google-workspace-login-ocsf",
        "event_uid": uid,
        "provider": "Google Workspace",
        "time_ms": time_ms,
        "status_id": status_id,
        "user": {"uid": user_uid, "name": user_name, "email_addr": user_name},
        "src_endpoint": {"ip": ip},
        "session": {"uid": session_uid},
        "event_name": event_name,
        "parameters": params,
    }
    if status_detail:
        event["status_detail"] = status_detail
    return event


class TestDetection:
    def test_suspicious_flag_fires(self):
        events = [_event(uid="evt-1", event_name="login_success", time_ms=1000, suspicious=True)]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["metadata"]["product"]["name"] == REPO_NAME
        assert finding["metadata"]["product"]["vendor_name"] == REPO_VENDOR
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        attacks = {item["technique"]["uid"] for item in finding["finding_info"]["attacks"]}
        assert attacks == {BRUTE_FORCE_UID, VALID_ACCOUNTS_UID}
        assert finding["evidence"]["suspicious_flag_events"] == 1

    def test_failure_burst_followed_by_success_fires(self):
        events = [
            _event(
                uid="evt-1",
                event_name="login_failure",
                time_ms=1000,
                status_id=2,
                status_detail="login_failure_invalid_password",
            ),
            _event(
                uid="evt-2",
                event_name="login_failure",
                time_ms=2000,
                status_id=2,
                status_detail="login_failure_invalid_password",
            ),
            _event(
                uid="evt-3",
                event_name="login_failure",
                time_ms=3000,
                status_id=2,
                status_detail="login_failure_invalid_password",
            ),
            _event(uid="evt-4", event_name="login_success", time_ms=4000),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        assert findings[0]["evidence"]["failure_count"] == MIN_FAILURES
        assert findings[0]["evidence"]["success_count"] == 1

    def test_out_of_order_input_is_sorted(self):
        events = [
            _event(uid="evt-4", event_name="login_success", time_ms=4000),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2),
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-3", event_name="login_failure", time_ms=3000, status_id=2),
        ]
        assert len(list(detect(events))) == 1

    def test_exact_boundary_is_included(self):
        events = [
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2),
            _event(uid="evt-3", event_name="login_failure", time_ms=3000, status_id=2),
            _event(uid="evt-4", event_name="login_success", time_ms=1000 + WINDOW_MS),
        ]
        assert len(list(detect(events))) == 1

    def test_duplicate_event_uid_does_not_double_count(self):
        events = [
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-1", event_name="login_failure", time_ms=1000, status_id=2),
            _event(uid="evt-2", event_name="login_failure", time_ms=2000, status_id=2),
            _event(uid="evt-3", event_name="login_success", time_ms=3000),
        ]
        assert list(detect(events)) == []

    def test_different_ip_does_not_join_same_user(self):
        events = [
            _event(
                uid="evt-1",
                event_name="login_failure",
                time_ms=1000,
                status_id=2,
                ip="198.51.100.21",
            ),
            _event(
                uid="evt-2",
                event_name="login_failure",
                time_ms=2000,
                status_id=2,
                ip="198.51.100.21",
            ),
            _event(
                uid="evt-3", event_name="login_failure", time_ms=3000, status_id=2, ip="203.0.113.9"
            ),
            _event(uid="evt-4", event_name="login_success", time_ms=4000, ip="203.0.113.9"),
        ]
        assert list(detect(events)) == []

    def test_golden_fixture_matches(self):
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)

    def test_native_input_can_emit_native_finding(self):
        events = [
            _native_event(uid="evt-1", event_name="login_success", time_ms=1000, suspicious=True)
        ]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Google Workspace"
        assert "class_uid" not in finding

    def test_native_input_can_emit_ocsf_finding(self):
        events = [
            _native_event(uid="evt-1", event_name="login_success", time_ms=1000, suspicious=True)
        ]
        findings = list(detect(events, output_format="ocsf"))
        assert len(findings) == 1
        assert findings[0]["class_uid"] == FINDING_CLASS_UID

    def test_rejects_unsupported_output_format(self):
        try:
            list(detect([], output_format="bridge"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
            assert exc.error_class == "contract"
            assert exc.retryable is False
            assert exc.hint
            assert "ocsf" in exc.hint or "native" in exc.hint
        else:
            raise AssertionError("expected unsupported output_format to raise")


class TestMetadata:
    def test_coverage_metadata(self):
        metadata = coverage_metadata()
        assert metadata["providers"] == ("google-workspace",)
        assert metadata["thresholds"]["min_failures"] == MIN_FAILURES
        assert set(metadata["attack_coverage"]["google-workspace"]["techniques"]) == {
            BRUTE_FORCE_UID,
            VALID_ACCOUNTS_UID,
        }


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 3002}']))
        assert out == [{"class_uid": 3002}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_emits_json_stderr_telemetry_when_enabled(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        list(load_jsonl(['{"bad": ']))
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1
