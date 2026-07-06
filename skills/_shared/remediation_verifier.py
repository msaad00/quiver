"""Generalized remediation re-verification contract.

The iam-departures-aws skill already implements this loop end-to-end (the
"ingest-back" pattern — after deletion, the next reconciler run reads the
HR warehouse + IAM state and confirms the user is closed across all
systems). This module extracts the pattern into a shared contract so that
every `remediate-*` skill can emit a uniform verification record without
each author reinventing the schema.

Three outcomes. Every re-verification lands in exactly one:

  VERIFIED     — post-remediation state matches what the action promised
                 to produce. Closed loop.
  DRIFT        — state does NOT match. Either the action did not land,
                 OR it landed and then got reverted within the SLA. Both
                 are treated as a fresh finding so the SIEM/ticketing
                 picks it up again.
  UNREACHABLE  — the verifier could not reach the target (network,
                 permissions, quota). NEVER silently downgrade this to
                 VERIFIED; the operator must see the gap.

Emission contract:

  - `build_verification_record()` — native record, for audit trails
  - `build_drift_finding()`       — OCSF 1.8 Detection Finding (class 2004)
                                    with `finding_types: ["remediation-drift"]`
                                    so it flows through the same detection
                                    pipeline every other finding does

Integration pattern (for each `remediate-*` skill):

  1. After `apply_actions()` writes the audit row, the skill's operator
     records the SLA clock start (e.g. DynamoDB TTL, EventBridge timer).
  2. When the SLA timer fires (or on next scheduled re-scan), the skill's
     paired verifier re-reads the target state.
  3. Verifier calls `build_verification_record()` with the outcome.
  4. On DRIFT, verifier ALSO calls `build_drift_finding()` and emits the
     OCSF Detection Finding through the same pipeline the original
     detector used.

This module ships the shape. Per-skill adoption (wiring each
`remediate-*` skill's verifier) is a follow-up per-skill change.

Contract: docs/REMEDIATION_VERIFICATION.md
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
REPO_VENDOR = "msaad00/cloud-ai-security-skills"

# Detection Finding envelope (OCSF 1.8)
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1


class VerificationStatus(str, enum.Enum):
    """Every re-verification lands in exactly one of these."""

    VERIFIED = "verified"
    DRIFT = "drift"
    UNREACHABLE = "unreachable"


@dataclasses.dataclass(frozen=True)
class RemediationReference:
    """Identifies the original remediation action being re-verified.

    These fields are populated from the remediation skill's audit row — the
    verifier reads them from the audit table and passes them back here.
    """

    remediation_skill: str  # e.g. "remediate-okta-session-kill"
    remediation_action_uid: str  # deterministic id of the action
    target_provider: str  # "Okta" / "AWS" / "GCP" / "Azure" / "Kubernetes"
    target_identifier: str  # e.g. Okta user uid, IAM username, k8s binding
    original_finding_uid: str  # the finding that triggered remediation
    remediated_at_ms: int  # when the action wrote its post-audit row


@dataclasses.dataclass
class VerificationResult:
    """Outcome of one re-verification run."""

    status: VerificationStatus
    checked_at_ms: int
    sla_deadline_ms: int  # by when this verification had to land
    expected_state: str  # one-line description of what we expected
    actual_state: str  # what the verifier actually found
    detail: str | None = None  # free-form context (error msg, query, etc.)


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"rev-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def build_verification_record(
    *,
    reference: RemediationReference,
    result: VerificationResult,
    verifier_skill: str,
) -> dict[str, Any]:
    """Return a native `remediation_verification` record.

    Every verification — VERIFIED, DRIFT, or UNREACHABLE — emits one of
    these. The record is the ground truth for the audit trail; a DRIFT
    outcome additionally emits an OCSF Detection Finding via
    `build_drift_finding()` so downstream SIEM/SOAR picks it up.
    """
    record_uid = _deterministic_uid(
        reference.remediation_skill,
        reference.remediation_action_uid,
        reference.target_identifier,
        str(result.checked_at_ms),
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "remediation_verification",
        "source_skill": verifier_skill,
        "record_uid": record_uid,
        "reference": {
            "remediation_skill": reference.remediation_skill,
            "remediation_action_uid": reference.remediation_action_uid,
            "target_provider": reference.target_provider,
            "target_identifier": reference.target_identifier,
            "original_finding_uid": reference.original_finding_uid,
            "remediated_at_ms": reference.remediated_at_ms,
        },
        "status": result.status.value,
        "checked_at_ms": result.checked_at_ms,
        "sla_deadline_ms": result.sla_deadline_ms,
        "within_sla": result.checked_at_ms <= result.sla_deadline_ms,
        "expected_state": result.expected_state,
        "actual_state": result.actual_state,
        "detail": result.detail,
    }


def build_drift_finding(
    *,
    reference: RemediationReference,
    result: VerificationResult,
    verifier_skill: str,
) -> dict[str, Any]:
    """Return an OCSF 1.8 Detection Finding (2004) marking a remediation
    that did NOT land or got reverted.

    Emitted ONLY when `result.status == VerificationStatus.DRIFT`. For
    VERIFIED or UNREACHABLE, use `build_verification_record()` alone.
    """
    if result.status != VerificationStatus.DRIFT:
        raise ValueError(
            f"build_drift_finding must only be called with status=DRIFT; got {result.status}"
        )

    finding_uid = _deterministic_uid(
        "drift",
        reference.remediation_skill,
        reference.remediation_action_uid,
        reference.target_identifier,
    )
    title = (
        f"Remediation drift: {reference.target_provider} "
        f"{reference.target_identifier} state does not match "
        f"{reference.remediation_skill} post-remediation expectation"
    )
    description = (
        f"{reference.remediation_skill} completed at "
        f"{reference.remediated_at_ms} with action {reference.remediation_action_uid}. "
        f"Re-verification at {result.checked_at_ms} found actual state "
        f'"{result.actual_state}" but expected "{result.expected_state}". '
        "Either the remediation did not land, it landed and was reverted, or "
        "the target state was modified out of band."
    )

    observables = [
        {"name": "remediation.skill", "type": "Other", "value": reference.remediation_skill},
        {
            "name": "remediation.action_uid",
            "type": "Other",
            "value": reference.remediation_action_uid,
        },
        {"name": "target.provider", "type": "Other", "value": reference.target_provider},
        {"name": "target.identifier", "type": "Other", "value": reference.target_identifier},
        {"name": "original.finding_uid", "type": "Other", "value": reference.original_finding_uid},
    ]

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": STATUS_SUCCESS,
        "time": result.checked_at_ms,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": finding_uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": verifier_skill},
            },
            "labels": ["remediation", "drift", "verification"],
        },
        "finding_info": {
            "uid": finding_uid,
            "title": title,
            "desc": description,
            "types": ["remediation-drift"],
            "first_seen_time": reference.remediated_at_ms,
            "last_seen_time": result.checked_at_ms,
        },
        "observables": observables,
        "evidence": {
            "expected_state": result.expected_state,
            "actual_state": result.actual_state,
            "within_sla": result.checked_at_ms <= result.sla_deadline_ms,
            "sla_deadline_ms": result.sla_deadline_ms,
            "detail": result.detail,
        },
    }


def sla_deadline(remediated_at_ms: int, sla_ms: int) -> int:
    """Given a remediation timestamp and an SLA window, return the deadline
    by which re-verification MUST land. Sentinel used by verifier callers
    that need to decide whether to escalate on late verification."""
    return remediated_at_ms + sla_ms


DEFAULT_VERIFICATION_SLA_MS = 15 * 60 * 1000  # 15 minutes
