"""Tests for skills/_shared/remediation_verifier.py.

Contract tests for the shared re-verification helpers. Proves the emitted
records:
- carry deterministic UIDs (same input → same UID across invocations)
- have the right OCSF envelope for DRIFT findings
- include the load-bearing evidence fields
- refuse to emit a drift finding for non-DRIFT status
- compute the SLA deadline correctly
- validate against the OCSF schema validator we just shipped
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_REV_MODULE = ROOT / "skills" / "_shared" / "remediation_verifier.py"
_spec = importlib.util.spec_from_file_location(
    "cloud_security_remediation_verifier_test", _REV_MODULE
)
assert _spec and _spec.loader
REV = importlib.util.module_from_spec(_spec)
sys.modules["cloud_security_remediation_verifier_test"] = REV
_spec.loader.exec_module(REV)

_OCSF_MODULE = ROOT / "skills" / "_shared" / "ocsf_validator.py"
_ocsf_spec = importlib.util.spec_from_file_location(
    "cloud_security_ocsf_validator_rev_test", _OCSF_MODULE
)
assert _ocsf_spec and _ocsf_spec.loader
OCSF = importlib.util.module_from_spec(_ocsf_spec)
sys.modules["cloud_security_ocsf_validator_rev_test"] = OCSF
_ocsf_spec.loader.exec_module(OCSF)


def _ref(**overrides) -> "REV.RemediationReference":  # type: ignore[name-defined]
    defaults = dict(
        remediation_skill="remediate-okta-session-kill",
        remediation_action_uid="rok-abc123",
        target_provider="Okta",
        target_identifier="00u-target-1",
        original_finding_uid="det-stuff-xyz",
        remediated_at_ms=1776046500000,
    )
    defaults.update(overrides)
    return REV.RemediationReference(**defaults)


def _result(status: "REV.VerificationStatus", **overrides) -> "REV.VerificationResult":  # type: ignore[name-defined]
    defaults = dict(
        status=status,
        checked_at_ms=1776046600000,
        sla_deadline_ms=1776047400000,  # 15 min after remediated_at_ms
        expected_state="user has zero active sessions",
        actual_state="user has zero active sessions",
        detail=None,
    )
    defaults.update(overrides)
    return REV.VerificationResult(**defaults)


class TestVerificationRecord:
    def test_verified_record_shape(self):
        record = REV.build_verification_record(
            reference=_ref(),
            result=_result(REV.VerificationStatus.VERIFIED),
            verifier_skill="verify-okta-session-kill",
        )
        assert record["schema_mode"] == "native"
        assert record["record_type"] == "remediation_verification"
        assert record["status"] == "verified"
        assert record["within_sla"] is True
        assert record["reference"]["remediation_skill"] == "remediate-okta-session-kill"
        assert record["reference"]["target_identifier"] == "00u-target-1"
        assert record["record_uid"].startswith("rev-")

    def test_drift_record_shape(self):
        record = REV.build_verification_record(
            reference=_ref(),
            result=_result(
                REV.VerificationStatus.DRIFT,
                actual_state="user has 1 session from 203.0.113.10",
                detail="session re-established post-remediation",
            ),
            verifier_skill="verify-okta-session-kill",
        )
        assert record["status"] == "drift"
        assert record["actual_state"] == "user has 1 session from 203.0.113.10"
        assert record["detail"] == "session re-established post-remediation"

    def test_unreachable_record_shape(self):
        record = REV.build_verification_record(
            reference=_ref(),
            result=_result(
                REV.VerificationStatus.UNREACHABLE,
                detail="Okta API throttled: 429",
            ),
            verifier_skill="verify-okta-session-kill",
        )
        assert record["status"] == "unreachable"
        assert record["detail"] == "Okta API throttled: 429"

    def test_late_verification_flags_within_sla_false(self):
        late_result = _result(
            REV.VerificationStatus.VERIFIED,
            checked_at_ms=1776048000000,  # past the 15-min deadline
        )
        record = REV.build_verification_record(
            reference=_ref(),
            result=late_result,
            verifier_skill="verify-okta-session-kill",
        )
        assert record["within_sla"] is False

    def test_deterministic_uid_across_invocations(self):
        a = REV.build_verification_record(
            reference=_ref(),
            result=_result(REV.VerificationStatus.VERIFIED),
            verifier_skill="verify-okta-session-kill",
        )
        b = REV.build_verification_record(
            reference=_ref(),
            result=_result(REV.VerificationStatus.VERIFIED),
            verifier_skill="verify-okta-session-kill",
        )
        assert a["record_uid"] == b["record_uid"]

    def test_different_targets_yield_different_uids(self):
        a = REV.build_verification_record(
            reference=_ref(target_identifier="00u-A"),
            result=_result(REV.VerificationStatus.VERIFIED),
            verifier_skill="verify-okta-session-kill",
        )
        b = REV.build_verification_record(
            reference=_ref(target_identifier="00u-B"),
            result=_result(REV.VerificationStatus.VERIFIED),
            verifier_skill="verify-okta-session-kill",
        )
        assert a["record_uid"] != b["record_uid"]


class TestDriftFinding:
    def test_drift_finding_is_ocsf_2004(self):
        finding = REV.build_drift_finding(
            reference=_ref(),
            result=_result(
                REV.VerificationStatus.DRIFT,
                actual_state="user still has session",
            ),
            verifier_skill="verify-okta-session-kill",
        )
        assert finding["class_uid"] == 2004
        assert finding["category_uid"] == 2
        assert finding["type_uid"] == 200401
        assert finding["severity_id"] == 4
        assert finding["finding_info"]["types"] == ["remediation-drift"]

    def test_drift_finding_carries_remediation_reference_as_observables(self):
        finding = REV.build_drift_finding(
            reference=_ref(),
            result=_result(REV.VerificationStatus.DRIFT, actual_state="x"),
            verifier_skill="verify-okta-session-kill",
        )
        observable_names = [o["name"] for o in finding["observables"]]
        assert "remediation.skill" in observable_names
        assert "remediation.action_uid" in observable_names
        assert "target.provider" in observable_names
        assert "target.identifier" in observable_names
        assert "original.finding_uid" in observable_names

    def test_drift_finding_validates_against_ocsf_validator(self):
        """The emitted drift finding must pass the OCSF 1.8 validator."""
        finding = REV.build_drift_finding(
            reference=_ref(),
            result=_result(REV.VerificationStatus.DRIFT, actual_state="x"),
            verifier_skill="verify-okta-session-kill",
        )
        errors = OCSF.validate_event(finding)
        assert errors == [], f"drift finding failed OCSF validation: {errors}"

    def test_drift_finding_raises_for_non_drift_status(self):
        import pytest

        for status in (REV.VerificationStatus.VERIFIED, REV.VerificationStatus.UNREACHABLE):
            with pytest.raises(ValueError):
                REV.build_drift_finding(
                    reference=_ref(),
                    result=_result(status),
                    verifier_skill="verify-okta-session-kill",
                )

    def test_drift_finding_uid_deterministic_per_action(self):
        a = REV.build_drift_finding(
            reference=_ref(),
            result=_result(REV.VerificationStatus.DRIFT, actual_state="x"),
            verifier_skill="verify-okta-session-kill",
        )
        b = REV.build_drift_finding(
            reference=_ref(),
            result=_result(
                REV.VerificationStatus.DRIFT,
                actual_state="different description",  # detail varies
                checked_at_ms=1776049000000,  # later retry
            ),
            verifier_skill="verify-okta-session-kill",
        )
        # Same remediation action → same finding UID (dedupe in SIEM).
        assert a["metadata"]["uid"] == b["metadata"]["uid"]


class TestSLADeadline:
    def test_deadline_is_remediated_plus_sla(self):
        assert (
            REV.sla_deadline(1776046500000, REV.DEFAULT_VERIFICATION_SLA_MS)
            == 1776046500000 + 15 * 60 * 1000
        )

    def test_default_sla_is_15_minutes(self):
        assert REV.DEFAULT_VERIFICATION_SLA_MS == 15 * 60 * 1000
