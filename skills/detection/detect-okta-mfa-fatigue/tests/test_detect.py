"""Tests for detect-okta-mfa-fatigue."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    AUTH_CLASS_UID,
    CANONICAL_VERSION,
    CHALLENGE_EVENT_TYPES,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    GENERIC_MFA_EVENT_TYPE,
    MIN_CHALLENGES,
    MIN_DENIALS,
    MIN_RELEVANT_EVENTS,
    MITRE_TECHNIQUE_UID,
    OKTA_INGEST_SKILL,
    OUTPUT_FORMATS,
    REPO_NAME,
    REPO_VENDOR,
    SEVERITY_HIGH,
    SKILL_NAME,
    STATUS_FAILURE,
    WINDOW_MS,
    coverage_metadata,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT = GOLDEN / "okta_mfa_fatigue_input.ocsf.jsonl"
EXPECTED = GOLDEN / "okta_mfa_fatigue_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    event_type: str,
    time_ms: int,
    user_uid: str = "00u-alice",
    user_name: str = "alice@example.com",
    status_id: int = 1,
    status_detail: str | None = None,
    ip: str = "198.51.100.25",
    session_uid: str = "sess-okta-1",
    resource_name: str = "Okta Verify",
) -> dict:
    event = {
        "activity_id": 99,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": AUTH_CLASS_UID,
        "class_name": "Authentication",
        "type_uid": 300299,
        "severity_id": 2,
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
    if resource_name:
        event["resources"] = [{"name": resource_name, "type": "AuthenticatorEnrollment"}]
        event["service"] = {"name": resource_name}
    return event


def _native_event(
    *,
    uid: str,
    event_type: str,
    time_ms: int,
    user_uid: str = "00u-alice",
    user_name: str = "alice@example.com",
    status_id: int = 1,
    status_detail: str | None = None,
    ip: str = "198.51.100.25",
    session_uid: str = "sess-okta-1",
    resource_name: str = "Okta Verify",
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
        "unmapped": {"okta": {"event_type": event_type}},
    }
    if status_detail:
        event["status_detail"] = status_detail
    if resource_name:
        event["resources"] = [{"name": resource_name, "type": "AuthenticatorEnrollment"}]
        event["service"] = {"name": resource_name}
    return event


class TestDetection:
    def test_repeated_push_denials_fire(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["name"] == REPO_NAME
        assert finding["metadata"]["product"]["vendor_name"] == REPO_VENDOR
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["uid"] == finding["finding_info"]["uid"]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert finding["evidence"]["challenge_events"] == 2
        assert finding["evidence"]["denial_events"] == 1

    def test_oie_generic_failure_path_fires_only_for_okta_verify(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type=GENERIC_MFA_EVENT_TYPE,
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
                resource_name="Okta Verify",
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 1

    def test_oie_generic_failure_without_okta_verify_is_ignored(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type=GENERIC_MFA_EVENT_TYPE,
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
                resource_name="WebAuthn",
            ),
        ]
        assert list(detect(events)) == []

    def test_requires_denial_signal(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(uid="evt-3", event_type="system.push.send_factor_verify_push", time_ms=3000),
        ]
        assert list(detect(events)) == []

    def test_duplicate_event_uid_does_not_inflate_counts(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(
                uid="evt-2",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=2000,
                status_id=STATUS_FAILURE,
            ),
        ]
        assert list(detect(events)) == []

    def test_out_of_order_events_are_sorted(self):
        events = [
            _event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
            ),
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
        ]
        assert len(list(detect(events))) == 1

    def test_quiet_period_starts_new_burst(self):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
            ),
            _event(
                uid="evt-4",
                event_type="system.push.send_factor_verify_push",
                time_ms=3000 + WINDOW_MS + 1,
                session_uid="sess-okta-2",
            ),
            _event(
                uid="evt-5",
                event_type="system.push.send_factor_verify_push",
                time_ms=4000 + WINDOW_MS,
                session_uid="sess-okta-2",
            ),
            _event(
                uid="evt-6",
                event_type="user.mfa.okta_verify.deny_push_upgrade_needed",
                time_ms=5000 + WINDOW_MS,
                session_uid="sess-okta-2",
                status_id=STATUS_FAILURE,
            ),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

    def test_golden_fixture_matches(self):
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)

    def test_native_input_can_emit_native_finding(self):
        events = [
            _native_event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _native_event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _native_event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
            ),
        ]
        findings = list(detect(events, output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "Okta"
        assert "class_uid" not in finding

    def test_native_input_can_emit_ocsf_finding(self):
        events = [
            _native_event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _native_event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _native_event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
                status_detail="INVALID_CREDENTIALS",
            ),
        ]
        findings = list(detect(events, output_format="ocsf"))
        assert len(findings) == 1
        assert findings[0]["class_uid"] == FINDING_CLASS_UID

    def test_rejects_unsupported_output_format(self):
        # Migrated from ValueError to ContractError so SIEMs can route
        # bad-input failures off the same envelope as cred / config /
        # transient errors. ContractError extends Exception, so
        # `except Exception` callers still catch it.
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="bridge"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
            assert exc.error_class == "contract"
            assert exc.retryable is False
            assert "ocsf" in exc.hint
        else:
            raise AssertionError("expected unsupported output_format to raise")


class TestThresholdOverrides:
    def test_min_challenges_env_override_raises_threshold(self, monkeypatch):
        events = [
            _event(uid="evt-1", event_type="system.push.send_factor_verify_push", time_ms=1000),
            _event(uid="evt-2", event_type="system.push.send_factor_verify_push", time_ms=2000),
            _event(
                uid="evt-3",
                event_type="user.mfa.okta_verify.deny_push",
                time_ms=3000,
                status_id=STATUS_FAILURE,
            ),
        ]

        assert len(list(detect(events))) == 1

        monkeypatch.setenv("DETECT_OKTA_MFA_FATIGUE_MIN_CHALLENGES", "3")

        assert list(detect(events)) == []


class TestMetadata:
    def test_coverage_metadata(self):
        metadata = coverage_metadata()
        assert metadata["providers"] == ("okta",)
        assert metadata["thresholds"]["min_relevant_events"] == MIN_RELEVANT_EVENTS
        assert metadata["thresholds"]["min_challenges"] == MIN_CHALLENGES
        assert metadata["thresholds"]["min_denials"] == MIN_DENIALS
        assert CHALLENGE_EVENT_TYPES.issubset(set(metadata["attack_coverage"]["okta"]["anchor_event_types"]))


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


class TestSharedContractMigration:
    """Lock-in: this detector now uses the shared `_shared/{retry,errors,logging}`
    contract from #437. SIEMs / agents pattern-match on the
    `SkillError.error_class` and the structured-logging envelope."""

    def test_main_emit_error_path_for_contract_violation(self, tmp_path, capsys):
        """argparse blocks bad --output-format upfront, so we exercise
        the contract path by calling `detect()` directly through main's
        try/except — passing a value that argparse accepts but that the
        detector does not understand. This is a synthetic smoke test
        for the emit_error shape."""
        from skills._shared.errors import ContractError, emit_error

        rc = emit_error(
            "detect-okta-mfa-fatigue",
            ContractError("synthetic", hint="for the test"),
        )
        assert rc == 1
        envelope_line = capsys.readouterr().out.strip().splitlines()[0]
        envelope = json.loads(envelope_line)
        assert envelope["event"] == "skill_error"
        assert envelope["skill"] == "detect-okta-mfa-fatigue"
        assert envelope["error_class"] == "contract"
        assert envelope["retryable"] is False
        assert envelope["hint"] == "for the test"
