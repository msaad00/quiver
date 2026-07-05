"""Tests for detect-credential-stuffing-okta."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    AUTH_CLASS_UID,
    CANONICAL_VERSION,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MIN_FAILURES,
    MIN_UNIQUE_IPS,
    MITRE_SUBTECHNIQUE_UID,
    MITRE_TECHNIQUE_UID,
    OKTA_INGEST_SKILL,
    OUTPUT_FORMATS,
    REPO_NAME,
    REPO_VENDOR,
    SEVERITY_HIGH,
    SKILL_NAME,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    WINDOW_MS,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT = GOLDEN / "okta_credential_stuffing_input.ocsf.jsonl"
EXPECTED = GOLDEN / "okta_credential_stuffing_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    event_type: str = "user.session.start",
    user_uid: str = "00u-alice",
    user_name: str = "alice@example.com",
    status_id: int = STATUS_FAILURE,
    status_detail: str | None = "INVALID_CREDENTIALS",
    ip: str = "198.51.100.10",
    session_uid: str = "sess-1",
) -> dict:
    event = {
        "activity_id": 1,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": AUTH_CLASS_UID,
        "class_name": "Authentication",
        "type_uid": 300201,
        "severity_id": 2 if status_id == STATUS_FAILURE else 1,
        "status_id": status_id,
        "time": time_ms,
        "message": event_type,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": OKTA_INGEST_SKILL},
            },
        },
        "src_endpoint": {"ip": ip},
        "user": {"uid": user_uid, "name": user_name, "email_addr": user_name},
        "session": {"uid": session_uid},
        "unmapped": {"okta": {"event_type": event_type}},
    }
    if status_detail:
        event["status_detail"] = status_detail
    return event


def _native_event(
    *,
    uid: str,
    time_ms: int,
    event_type: str = "user.session.start",
    user_uid: str = "00u-alice",
    user_name: str = "alice@example.com",
    status_id: int = STATUS_FAILURE,
    status_detail: str | None = "INVALID_CREDENTIALS",
    ip: str = "198.51.100.10",
    session_uid: str = "sess-1",
) -> dict:
    event = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "authentication",
        "source_skill": OKTA_INGEST_SKILL,
        "event_uid": uid,
        "provider": "Okta",
        "time_ms": time_ms,
        "status_id": status_id,
        "user": {"uid": user_uid, "name": user_name, "email_addr": user_name},
        "src_endpoint": {"ip": ip},
        "session": {"uid": session_uid},
        "event_type": event_type,
    }
    if status_detail:
        event["status_detail"] = status_detail
    return event


def _stuffing_burst(start_ms: int = 1000, user_uid: str = "00u-alice") -> list[dict]:
    """Five failures from five distinct IPs, then a success. Textbook fire case."""
    failures = [
        _event(
            uid=f"evt-f{i}",
            time_ms=start_ms + i * 1000,
            status_id=STATUS_FAILURE,
            ip=f"203.0.113.{i + 1}",
            user_uid=user_uid,
        )
        for i in range(MIN_FAILURES)
    ]
    success = _event(
        uid="evt-s",
        time_ms=start_ms + (MIN_FAILURES + 1) * 1000,
        status_id=STATUS_SUCCESS,
        status_detail=None,
        ip="198.51.100.99",
        user_uid=user_uid,
    )
    return failures + [success]


class TestDetection:
    def test_failures_then_success_fires(self):
        findings = list(detect(_stuffing_burst()))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        attacks = finding["finding_info"]["attacks"]
        assert attacks[0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert attacks[0]["sub_technique"]["uid"] == MITRE_SUBTECHNIQUE_UID
        assert finding["evidence"]["failure_events"] == MIN_FAILURES
        assert len(finding["evidence"]["source_ips"]) == MIN_FAILURES
        assert finding["evidence"]["success_ip"] == "198.51.100.99"

    def test_failures_without_success_do_not_fire(self):
        failures = [
            _event(
                uid=f"evt-f{i}",
                time_ms=1000 + i * 1000,
                status_id=STATUS_FAILURE,
                ip=f"203.0.113.{i + 1}",
            )
            for i in range(MIN_FAILURES)
        ]
        assert list(detect(failures)) == []

    def test_not_enough_failures_does_not_fire(self):
        events = [
            _event(uid=f"evt-f{i}", time_ms=1000 + i * 1000, ip=f"203.0.113.{i + 1}")
            for i in range(MIN_FAILURES - 1)
        ]
        events.append(
            _event(uid="evt-s", time_ms=9000, status_id=STATUS_SUCCESS, status_detail=None)
        )
        assert list(detect(events)) == []

    def test_single_ip_below_unique_threshold_does_not_fire(self):
        """With default MIN_UNIQUE_IPS=2, all-same-IP failures do NOT fire."""
        events = [
            _event(uid=f"evt-f{i}", time_ms=1000 + i * 1000, ip="203.0.113.1")
            for i in range(MIN_FAILURES)
        ]
        events.append(
            _event(uid="evt-s", time_ms=9000, status_id=STATUS_SUCCESS, status_detail=None)
        )
        assert list(detect(events)) == []

    def test_single_ip_fires_when_threshold_lowered(self, monkeypatch):
        monkeypatch.setenv("DETECT_OKTA_STUFFING_MIN_UNIQUE_IPS", "1")
        events = [
            _event(uid=f"evt-f{i}", time_ms=1000 + i * 1000, ip="203.0.113.1")
            for i in range(MIN_FAILURES)
        ]
        events.append(
            _event(uid="evt-s", time_ms=9000, status_id=STATUS_SUCCESS, status_detail=None)
        )
        assert len(list(detect(events))) == 1

    def test_success_outside_window_does_not_fire(self):
        failures = [
            _event(
                uid=f"evt-f{i}",
                time_ms=1000 + i * 1000,
                ip=f"203.0.113.{i + 1}",
            )
            for i in range(MIN_FAILURES)
        ]
        # success happens after the window closes
        failures.append(
            _event(
                uid="evt-s",
                time_ms=1000 + WINDOW_MS + 10_000,
                status_id=STATUS_SUCCESS,
                status_detail=None,
            )
        )
        assert list(detect(failures)) == []

    def test_duplicate_event_uid_does_not_inflate_counts(self):
        """Two failures sharing the same metadata.uid count once."""
        events = [_event(uid="evt-f1", time_ms=1000, ip="203.0.113.1")]
        # Same uid repeated — should be deduped
        events.extend(_event(uid="evt-f1", time_ms=1000, ip="203.0.113.1") for _ in range(4))
        events.append(
            _event(uid="evt-s", time_ms=9000, status_id=STATUS_SUCCESS, status_detail=None)
        )
        assert list(detect(events)) == []

    def test_out_of_order_events_are_sorted(self):
        burst = _stuffing_burst()
        shuffled = [burst[-1], burst[2], burst[0], burst[4], burst[1], burst[3], burst[5]]
        findings = list(detect(shuffled))
        assert len(findings) == 1

    def test_isolated_users_dont_interfere(self):
        bob = _stuffing_burst(start_ms=1000, user_uid="00u-bob")
        # alice has only a handful of failures, not enough to fire
        alice = [
            _event(
                uid="evt-a1",
                time_ms=2000,
                user_uid="00u-alice",
                user_name="alice@example.com",
                ip="203.0.113.50",
            )
        ]
        findings = list(detect(alice + bob))
        assert len(findings) == 1
        assert findings[0]["evidence"]["failure_events"] == MIN_FAILURES
        # Finding belongs to bob, not alice
        user_observable = next(o for o in findings[0]["observables"] if o["name"] == "user.uid")
        assert user_observable["value"] == "00u-bob"

    def test_non_okta_source_skill_is_ignored(self):
        events = _stuffing_burst()
        for event in events:
            event["metadata"]["product"]["feature"]["name"] = "ingest-google-workspace-login-ocsf"
        assert list(detect(events)) == []

    def test_non_auth_class_is_ignored(self):
        events = _stuffing_burst()
        for event in events:
            event["class_uid"] = 3001  # Account Change, not Authentication
        assert list(detect(events)) == []

    def test_native_input_emits_ocsf_by_default(self):
        failures = [
            _native_event(
                uid=f"evt-f{i}",
                time_ms=1000 + i * 1000,
                ip=f"203.0.113.{i + 1}",
            )
            for i in range(MIN_FAILURES)
        ]
        failures.append(
            _native_event(
                uid="evt-s",
                time_ms=1000 + (MIN_FAILURES + 1) * 1000,
                status_id=STATUS_SUCCESS,
                status_detail=None,
                ip="198.51.100.99",
            )
        )
        findings = list(detect(failures))
        assert len(findings) == 1
        assert findings[0]["class_uid"] == FINDING_CLASS_UID

    def test_native_input_can_emit_native_finding(self):
        failures = [
            _native_event(
                uid=f"evt-f{i}",
                time_ms=1000 + i * 1000,
                ip=f"203.0.113.{i + 1}",
            )
            for i in range(MIN_FAILURES)
        ]
        failures.append(
            _native_event(
                uid="evt-s",
                time_ms=1000 + (MIN_FAILURES + 1) * 1000,
                status_id=STATUS_SUCCESS,
                status_detail=None,
                ip="198.51.100.99",
            )
        )
        findings = list(detect(failures, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Okta"
        assert "class_uid" not in finding

    def test_fires_once_per_user_burst(self):
        """One finding even if multiple successes arrive within the same window."""
        burst = _stuffing_burst()
        # Tack on a second success right after the first
        burst.append(
            _event(
                uid="evt-s2",
                time_ms=burst[-1]["time"] + 1000,
                status_id=STATUS_SUCCESS,
                status_detail=None,
                ip="198.51.100.100",
            )
        )
        findings = list(detect(burst))
        assert len(findings) == 1

    def test_golden_fixture_matches(self):
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)

    def test_load_jsonl_skips_invalid_lines(self):
        lines = [
            '{"class_uid": 3002}',
            "not-json",
            "",
            '["wrong-shape"]',
            '{"class_uid": 3001}',
        ]
        parsed = list(load_jsonl(iter(lines)))
        assert len(parsed) == 2


class TestCoverageMetadata:
    def test_contains_mitre_and_okta(self):
        meta = coverage_metadata()
        assert "MITRE ATT&CK v14" in meta["frameworks"]
        assert meta["providers"] == ("okta",)
        assert MITRE_TECHNIQUE_UID in meta["attack_coverage"]["okta"]["techniques"]
        assert MITRE_SUBTECHNIQUE_UID in meta["attack_coverage"]["okta"]["techniques"]
        assert meta["thresholds"]["min_failures"] == MIN_FAILURES
        assert meta["thresholds"]["min_unique_ips"] == MIN_UNIQUE_IPS
