"""Contain a Google Workspace suspicious-login finding by killing all active sessions.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-google-workspace-suspicious-login (T1110 Brute Force / T1078 Valid
Accounts). Plans (dry-run default), applies (--apply), or re-verifies
(--reverify) two containment steps via the Admin SDK Directory API:

1. **Sign out**: POST /admin/directory/v1/users/{userKey}/signOut
   Invalidates web/mobile session tokens immediately. Returns 204 on
   success, 404 if the user is gone (no work to do).
2. **Force password change**: PATCH /admin/directory/v1/users/{userKey}
   with {"changePasswordAtNextLogin": true}. Forces re-auth on next sign-in.

Why sign-out + force-password-change rather than user.suspend
-------------------------------------------------------------
Suspending the user breaks legitimate work for the legitimate owner.
Sign-out + force-password-change is the standard Workspace
account-takeover containment: it kills the attacker's existing tokens
AND requires the legitimate user to re-authenticate before regaining
access. The legitimate user can recover by completing a password reset
(via their recovery phone/email or admin assist).

Wires `_shared/remediation_verifier.py` from day one. Re-verify reads the
Admin SDK Reports API for any successful login by the user since the
remediated_at timestamp; emits VERIFIED if no successful login, DRIFT
(+ paired OCSF Detection Finding) if the attacker came back in,
UNREACHABLE if the Reports API throws.

Guardrails enforced in code:
- ACCEPTED_PRODUCERS limited to detect-google-workspace-suspicious-login
- protected-principal deny-list mirrors remediate-okta-session-kill:
  *@google.com, *admin*, service-account*, break-glass-*, emergency-*,
  root, plus an extensible WORKSPACE_SESSION_KILL_DENY_LIST_FILE
- --apply requires WORKSPACE_SESSION_KILL_INCIDENT_ID +
  WORKSPACE_SESSION_KILL_APPROVER
- --apply requires explicit target-domain allow-listing via
  WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS
- dual audit BEFORE and AFTER each Admin SDK call
- failure paths still write the failure audit row

Required Workspace permissions:
- Admin SDK Directory scope: https://www.googleapis.com/auth/admin.directory.user.security
- Admin SDK Reports scope (reverify): https://www.googleapis.com/auth/admin.reports.audit.readonly
- Service account with domain-wide delegation, OR an admin user impersonation
- Entra ID role: User Management
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.remediation_verifier import (  # noqa: E402
    DEFAULT_VERIFICATION_SLA_MS,
    RemediationReference,
    VerificationResult,
    VerificationStatus,
    build_drift_finding,
    build_verification_record,
    sla_deadline,
)
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "remediate-workspace-session-kill"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset({"detect-google-workspace-suspicious-login"})

# Same protected-principal philosophy as remediate-okta-session-kill.
DEFAULT_DENY_PATTERNS = (
    "@google.com",
    "admin",
    "administrator",
    "service-account",
    "svc-",
    "break-glass",
    "emergency",
    "root",
)

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_SIGN_OUT = "sign_out_user"
STEP_FORCE_PASSWORD_CHANGE = "force_password_change"
CONTAINMENT_STEPS = (STEP_SIGN_OUT, STEP_FORCE_PASSWORD_CHANGE)

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_DENY_LIST = "skipped_deny_list"
STATUS_WOULD_VIOLATE_DENY_LIST = "would-violate-deny-list"
STATUS_SKIPPED_NO_USER = "skipped_no_user_pointer"
STATUS_SKIPPED_DOMAIN_BOUNDARY = "skipped_domain_boundary"


@dataclasses.dataclass(frozen=True)
class Target:
    user_uid: str
    user_name: str
    source_ips: tuple[str, ...]
    session_uids: tuple[str, ...]
    producer_skill: str
    finding_uid: str


class WorkspaceClient(Protocol):
    """Minimal Admin SDK surface this skill needs. Tests inject a stub."""

    def sign_out(self, user_key: str) -> None: ...
    def force_password_change(self, user_key: str) -> None: ...
    def list_recent_successful_logins(
        self, user_key: str, *, since_ms: int
    ) -> list[dict[str, Any]]: ...


class AuditWriter(Protocol):
    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
    ) -> dict[str, str]: ...


@dataclasses.dataclass
class GoogleAdminSDKClient:
    """Real Admin SDK client. Built lazily so tests don't require google-api-python-client."""

    delegated_admin_email: str
    service_account_key_json: str  # JSON-encoded SA key, fetched from Secrets Manager

    def _client(self, scope: str) -> Any:
        # Lazy import — tests inject a stub Protocol implementation.
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        info = json.loads(self.service_account_key_json)
        creds = service_account.Credentials.from_service_account_info(
            info, scopes=[scope]
        ).with_subject(self.delegated_admin_email)
        # `directory_v1` covers signOut + user PATCH; `reports_v1` covers reverify.
        if "reports.audit" in scope:
            return build("admin", "reports_v1", credentials=creds, cache_discovery=False)
        return build("admin", "directory_v1", credentials=creds, cache_discovery=False)

    def sign_out(self, user_key: str) -> None:
        client = self._client("https://www.googleapis.com/auth/admin.directory.user.security")
        client.users().signOut(userKey=user_key).execute()

    def force_password_change(self, user_key: str) -> None:
        client = self._client("https://www.googleapis.com/auth/admin.directory.user.security")
        client.users().patch(userKey=user_key, body={"changePasswordAtNextLogin": True}).execute()

    def list_recent_successful_logins(
        self, user_key: str, *, since_ms: int
    ) -> list[dict[str, Any]]:
        client = self._client("https://www.googleapis.com/auth/admin.reports.audit.readonly")
        start = datetime.fromtimestamp(since_ms / 1000, tz=timezone.utc).isoformat()
        response = (
            client.activities()
            .list(
                userKey=user_key,
                applicationName="login",
                startTime=start,
                eventName="login_success",
            )
            .execute()
        )
        items = response.get("items") or []
        return [item for item in items if isinstance(item, dict)]


@dataclasses.dataclass
class DualAuditWriter:
    dynamodb_table: str
    s3_bucket: str
    kms_key_arn: str

    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
    ) -> dict[str, str]:
        import boto3

        action_at = datetime.now(timezone.utc).isoformat()
        row_uid = _deterministic_uid(target.user_uid, step, action_at)
        evidence_key = (
            "workspace-session-kill/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(target.user_uid)}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "user_uid": target.user_uid,
            "user_name": target.user_name,
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
            "step": step,
            "status": status,
            "status_detail": detail,
            "incident_id": incident_id,
            "approver": approver,
            "action_at": action_at,
        }
        body = json.dumps(envelope, separators=(",", ":"))

        boto3.client("s3").put_object(
            Bucket=self.s3_bucket,
            Key=evidence_key,
            Body=body.encode("utf-8"),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_arn,
            ContentType="application/json",
        )
        boto3.client("dynamodb").put_item(
            TableName=self.dynamodb_table,
            Item={
                "user_uid": {"S": target.user_uid},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "user_name": {"S": target.user_name},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"wssk-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _safe_path_component(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_.@" else "_" for ch in (value or "_"))
    return safe[:120] or "_"


def _finding_product(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _finding_uid(event: dict[str, Any]) -> str:
    return str(
        (event.get("finding_info") or {}).get("uid")
        or (event.get("metadata") or {}).get("uid")
        or ""
    )


def _observable_value(event: dict[str, Any], name: str) -> str:
    for obs in event.get("observables") or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("name") == name:
            value = obs.get("value")
            if value:
                return str(value)
    return ""


def _observable_values(event: dict[str, Any], name: str) -> tuple[str, ...]:
    values: list[str] = []
    for obs in event.get("observables") or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("name") == name and obs.get("value"):
            values.append(str(obs["value"]))
    return tuple(values)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_reference_time_ms(event: dict[str, Any]) -> int | None:
    candidates = (
        event.get("remediated_at_ms"),
        event.get("time_ms"),
        event.get("time"),
        ((event.get("finding_info") or {}).get("last_seen_time")),
        ((event.get("finding_info") or {}).get("first_seen_time")),
    )
    for value in candidates:
        parsed = _safe_int(value)
        if parsed is not None and parsed > 0:
            return parsed
    return None


def _target_from_event(event: dict[str, Any]) -> Target | None:
    producer = _finding_product(event)
    if producer not in ACCEPTED_PRODUCERS:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="wrong_source_skill",
            message=f"skipping finding from unaccepted producer `{producer or '<missing>'}`",
        )
        return None

    user_uid = _observable_value(event, "user.uid")
    user_name = _observable_value(event, "user.name") or user_uid
    if not user_uid:
        return Target(
            user_uid="",
            user_name=user_name,
            source_ips=(),
            session_uids=(),
            producer_skill=producer,
            finding_uid=_finding_uid(event),
        )

    return Target(
        user_uid=user_uid,
        user_name=user_name,
        source_ips=_observable_values(event, "src.ip"),
        session_uids=_observable_values(event, "session.uid"),
        producer_skill=producer,
        finding_uid=_finding_uid(event),
    )


def parse_targets(
    events: Iterable[dict[str, Any]],
) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_deny_patterns() -> tuple[str, ...]:
    extras: list[str] = []
    file_path = os.getenv("WORKSPACE_SESSION_KILL_DENY_LIST_FILE", "").strip()
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                extras = [str(item) for item in data if item]
        except (OSError, json.JSONDecodeError) as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="deny_list_file_unreadable",
                message=f"could not load extra deny patterns from {file_path}: {exc}",
            )
    return tuple(DEFAULT_DENY_PATTERNS) + tuple(extras)


def is_protected(target: Target, deny_patterns: tuple[str, ...]) -> tuple[bool, str | None]:
    haystack = (target.user_uid + " " + target.user_name).lower()
    for pattern in deny_patterns:
        if pattern.lower() in haystack:
            return True, pattern
    return False, None


def _email_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "@" not in candidate:
        return ""
    return candidate.rsplit("@", 1)[1]


def load_allowed_domains() -> tuple[str, ...]:
    raw = os.getenv("WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS", "").strip()
    if not raw:
        return ()
    return tuple(domain for domain in (part.strip().lower() for part in raw.split(",")) if domain)


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("WORKSPACE_SESSION_KILL_INCIDENT_ID", "").strip()
    approver = os.getenv("WORKSPACE_SESSION_KILL_APPROVER", "").strip()
    delegated_admin = os.getenv("WORKSPACE_DELEGATED_ADMIN_EMAIL", "").strip()
    delegated_admin_domain = _email_domain(delegated_admin)
    allowed_domains = load_allowed_domains()
    if not incident_id:
        return False, "WORKSPACE_SESSION_KILL_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "WORKSPACE_SESSION_KILL_APPROVER is required for --apply"
    if not allowed_domains:
        return False, "WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS is required for --apply"
    if delegated_admin and delegated_admin_domain not in allowed_domains:
        return (
            False,
            "WORKSPACE_DELEGATED_ADMIN_EMAIL must belong to WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS",
        )
    return True, ""


def _step_endpoint(step: str, user_uid: str) -> str:
    if step == STEP_SIGN_OUT:
        return f"POST /admin/directory/v1/users/{user_uid}/signOut"
    if step == STEP_FORCE_PASSWORD_CHANGE:
        return f"PATCH /admin/directory/v1/users/{user_uid} {{changePasswordAtNextLogin: true}}"
    return f"<unknown step {step}> {user_uid}"


def _plan_record(
    target: Target, *, status: str, detail: str | None, dry_run: bool
) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "GoogleWorkspace",
            "user_uid": target.user_uid,
            "user_name": target.user_name,
            "source_ips": list(target.source_ips),
            "session_uids": list(target.session_uids),
        },
        "actions": [
            {
                "step": step,
                "endpoint": _step_endpoint(step, target.user_uid),
                "status": status,
                "detail": detail,
            }
            for step in CONTAINMENT_STEPS
        ],
        "status": status,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def _skip_record(target: Target, *, status: str, detail: str, dry_run: bool) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "GoogleWorkspace",
            "user_uid": target.user_uid,
            "user_name": target.user_name,
        },
        "actions": [],
        "status": status,
        "status_detail": detail,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def apply_actions(
    target: Target,
    *,
    workspace_client: WorkspaceClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
) -> dict[str, Any]:
    """Sign out + force password change, dual-audited per step. Returns a single
    remediation_action record summarising both steps."""
    action_results: list[dict[str, Any]] = []
    overall_status = STATUS_SUCCESS
    last_audit_ref: dict[str, str] = {}

    for step in CONTAINMENT_STEPS:
        audit.record(
            target=target,
            step=step,
            status=STATUS_IN_PROGRESS,
            detail=f"about to {step}",
            incident_id=incident_id,
            approver=approver,
        )
        try:
            if step == STEP_SIGN_OUT:
                workspace_client.sign_out(target.user_uid)
            elif step == STEP_FORCE_PASSWORD_CHANGE:
                workspace_client.force_password_change(target.user_uid)
        except Exception as exc:
            audit.record(
                target=target,
                step=step,
                status=STATUS_FAILURE,
                detail=str(exc),
                incident_id=incident_id,
                approver=approver,
            )
            action_results.append(
                {
                    "step": step,
                    "endpoint": _step_endpoint(step, target.user_uid),
                    "status": STATUS_FAILURE,
                    "detail": str(exc),
                }
            )
            overall_status = STATUS_FAILURE
            continue

        last_audit_ref = audit.record(
            target=target,
            step=step,
            status=STATUS_SUCCESS,
            detail=f"completed {step}",
            incident_id=incident_id,
            approver=approver,
        )
        action_results.append(
            {
                "step": step,
                "endpoint": _step_endpoint(step, target.user_uid),
                "status": STATUS_SUCCESS,
                "detail": None,
            }
        )

    record = _plan_record(target, status=overall_status, detail=None, dry_run=False)
    record["actions"] = action_results
    record["audit"] = last_audit_ref
    record["incident_id"] = incident_id
    record["approver"] = approver
    return record


def reverify_target(
    target: Target,
    *,
    workspace_client: WorkspaceClient,
    remediated_at_ms: int | None = None,
    now_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Re-verify by reading Admin SDK Reports for any login_success activity by
    this user since the remediated_at timestamp. Emits one verification record;
    on DRIFT also emits an OCSF Detection Finding via the shared contract."""
    checked_at_ms = (
        now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    remediated_at_ms_resolved = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=_deterministic_uid("session-kill", target.user_uid),
        target_provider="GoogleWorkspace",
        target_identifier=target.user_uid,
        original_finding_uid=target.finding_uid,
        remediated_at_ms=remediated_at_ms_resolved,
    )
    expected = f"no successful Workspace login by `{target.user_uid}` after remediation"

    try:
        recent_logins = workspace_client.list_recent_successful_logins(
            target.user_uid, since_ms=remediated_at_ms_resolved
        )
    except Exception as exc:
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="admin sdk reports api unreadable; cannot determine state",
            detail=str(exc),
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = {
            "provider": "GoogleWorkspace",
            "user_uid": target.user_uid,
            "user_name": target.user_name,
        }
        return [record]

    if recent_logins:
        result = VerificationResult(
            status=VerificationStatus.DRIFT,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state=f"{len(recent_logins)} successful login(s) since remediation",
            detail="user authenticated again after session-kill",
        )
    else:
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="0 successful logins since remediation",
            detail="session-kill confirmed",
        )

    record = build_verification_record(
        reference=reference, result=result, verifier_skill=SKILL_NAME
    )
    record["target"] = {
        "provider": "GoogleWorkspace",
        "user_uid": target.user_uid,
        "user_name": target.user_name,
    }
    outputs: list[dict[str, Any]] = [record]
    if result.status == VerificationStatus.DRIFT:
        outputs.append(
            build_drift_finding(reference=reference, result=result, verifier_skill=SKILL_NAME)
        )
    return outputs


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}",
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object",
                line=lineno,
            )


def run(
    events: Iterable[dict[str, Any]],
    *,
    workspace_client: WorkspaceClient | None,
    apply: bool = False,
    reverify: bool = False,
    audit: AuditWriter | None = None,
    deny_patterns: tuple[str, ...] | None = None,
    incident_id: str = "",
    approver: str = "",
    allowed_domains: tuple[str, ...] | None = None,
    now_ms: int | None = None,
) -> Iterator[dict[str, Any]]:
    deny_patterns = deny_patterns if deny_patterns is not None else load_deny_patterns()
    resolved_allowed_domains = (
        allowed_domains if allowed_domains is not None else load_allowed_domains()
    )
    for target, event in parse_targets(events):
        if target is None:
            continue

        dry_run = not apply and not reverify

        if not target.user_uid:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_NO_USER,
                detail="finding did not carry a user.uid observable; cannot identify target",
                dry_run=dry_run,
            )
            continue

        protected, matched = is_protected(target, deny_patterns)
        if protected:
            status = STATUS_SKIPPED_DENY_LIST if apply else STATUS_WOULD_VIOLATE_DENY_LIST
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="target_denied",
                message=f"refusing to remediate protected principal `{target.user_name}` (matched `{matched}`)",
                user_uid=target.user_uid,
                matched_pattern=matched,
            )
            yield _skip_record(
                target,
                status=status,
                detail=f"matched deny pattern `{matched}`",
                dry_run=dry_run,
            )
            continue

        if reverify:
            if workspace_client is None:
                raise RuntimeError("reverify=True requires workspace_client to be provided")
            yield from reverify_target(
                target,
                workspace_client=workspace_client,
                now_ms=now_ms,
                remediated_at_ms=_event_reference_time_ms(event),
            )
            continue

        if not apply:
            yield _plan_record(
                target,
                status=STATUS_PLANNED,
                detail=f"dry-run: would sign out `{target.user_uid}` and force password change",
                dry_run=True,
            )
            continue

        if workspace_client is None or audit is None:
            raise RuntimeError("apply=True requires both workspace_client and audit to be provided")
        if not resolved_allowed_domains:
            raise RuntimeError("apply=True requires allowed_domains to be provided")
        user_domain = _email_domain(target.user_uid)
        if not user_domain or user_domain not in resolved_allowed_domains:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_DOMAIN_BOUNDARY,
                detail=("target user domain is outside WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS"),
                dry_run=False,
            )
            continue
        yield apply_actions(
            target,
            workspace_client=workspace_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify Google Workspace session-kill containment."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Sign out + force password change on the target user after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm no successful login since remediation.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    workspace_client: WorkspaceClient | None = None
    audit: AuditWriter | None = None
    incident_id = ""
    approver = ""

    try:
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.environ["WORKSPACE_SESSION_KILL_INCIDENT_ID"].strip()
            approver = os.environ["WORKSPACE_SESSION_KILL_APPROVER"].strip()
            workspace_client = GoogleAdminSDKClient(
                delegated_admin_email=os.environ["WORKSPACE_DELEGATED_ADMIN_EMAIL"],
                service_account_key_json=os.environ["WORKSPACE_SA_KEY_JSON"],
            )
            audit = DualAuditWriter(
                dynamodb_table=os.environ["WORKSPACE_SESSION_KILL_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["WORKSPACE_SESSION_KILL_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )
        elif args.reverify:
            workspace_client = GoogleAdminSDKClient(
                delegated_admin_email=os.environ["WORKSPACE_DELEGATED_ADMIN_EMAIL"],
                service_account_key_json=os.environ["WORKSPACE_SA_KEY_JSON"],
            )

        for record in run(
            load_jsonl(in_stream),
            workspace_client=workspace_client,
            apply=args.apply,
            reverify=args.reverify,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
            allowed_domains=load_allowed_domains(),
        ):
            out_stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
