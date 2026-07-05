"""Contain an Okta account takeover by revoking sessions + OAuth tokens.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-okta-mfa-fatigue or detect-credential-stuffing-okta. Plans (dry-run
default) or executes (--apply) the Okta API calls that log out the
target user and invalidate their refresh tokens.

Guardrails enforced in code:
- source-skill check rejects findings from any non-Okta producer
- deny-list of protected principals (admin / service-account / break-glass)
- --apply requires OKTA_SESSION_KILL_INCIDENT_ID + OKTA_SESSION_KILL_APPROVER
- --apply requires OKTA_ORG_URL to be explicitly allow-listed for this run
- dual-audit write (DynamoDB + S3) BEFORE and AFTER each Okta API call
- Okta API token pulled from AWS Secrets Manager at invocation time

Closes the Okta detect → act → audit → re-verify loop (see #240, #30).
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

SKILL_NAME = "remediate-okta-session-kill"
CANONICAL_VERSION = "2026-04"

# Detection skills whose findings this skill will accept as input. Any other
# producer is refused at the source-skill gate before any network egress.
ACCEPTED_PRODUCERS = frozenset(
    {
        "detect-okta-mfa-fatigue",
        "detect-credential-stuffing-okta",
    }
)

# Hard-coded deny-list of target principal patterns the skill will refuse
# even under --apply. Extensible via OKTA_SESSION_KILL_DENY_LIST_FILE but
# never shrinkable: the union of the hard-coded list and the file is applied.
DEFAULT_DENY_PATTERNS = (
    "@okta.com",
    "admin",
    "administrator",
    "service-account",
    "svc-",
    "break-glass",
    "emergency",
    "root",
)

# Okta containment steps, in execution order.
STEP_REVOKE_SESSIONS = "revoke_sessions"
STEP_REVOKE_OAUTH_TOKENS = "revoke_oauth_tokens"
STEP_EXPIRE_PASSWORD = "expire_password"
CONTAINMENT_STEPS = (STEP_REVOKE_SESSIONS, STEP_REVOKE_OAUTH_TOKENS)

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_SKIPPED_DENY_LIST = "skipped_deny_list"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_ORG_BOUNDARY = "skipped_org_boundary"


# -- Data classes ------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Target:
    user_uid: str
    user_name: str
    source_ips: tuple[str, ...]
    session_uids: tuple[str, ...]
    producer_skill: str
    finding_uid: str


@dataclasses.dataclass
class ActionResult:
    step: str
    endpoint: str
    status: str
    detail: str | None = None


# -- Okta client protocol (injectable for tests) -----------------------------


class OktaClient(Protocol):
    """Minimal Okta API surface. Real impl uses httpx; tests use a stub."""

    def revoke_sessions(self, user_id: str) -> None: ...
    def revoke_oauth_tokens(self, user_id: str) -> None: ...
    def list_active_sessions(self, user_id: str) -> list[dict[str, Any]]: ...
    def list_active_oauth_tokens(self, user_id: str) -> list[dict[str, Any]]: ...


@dataclasses.dataclass
class HttpxOktaClient:
    """Real client. Built lazily so tests don't require the httpx install."""

    org_url: str
    api_token: str

    def _client(self) -> Any:
        import httpx  # local import: tests that never call apply don't need it

        return httpx.Client(
            base_url=self.org_url,
            headers={
                "Authorization": f"SSWS {self.api_token}",
                "Accept": "application/json",
            },
            timeout=10.0,
        )

    def revoke_sessions(self, user_id: str) -> None:
        with self._client() as c:
            response = c.delete(f"/api/v1/users/{user_id}/sessions")
            if response.status_code not in (204, 200):
                raise RuntimeError(
                    f"Okta revoke_sessions returned {response.status_code}: {response.text[:200]}"
                )

    def revoke_oauth_tokens(self, user_id: str) -> None:
        with self._client() as c:
            response = c.delete(f"/api/v1/users/{user_id}/oauth/tokens")
            if response.status_code not in (204, 200, 404):
                raise RuntimeError(
                    f"Okta revoke_oauth_tokens returned {response.status_code}: {response.text[:200]}"
                )

    def list_active_sessions(self, user_id: str) -> list[dict[str, Any]]:
        # Okta provides GET /api/v1/users/{id}/sessions per
        # https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUserSessions
        # The endpoint returns 200 with a list (possibly empty) when the user
        # exists; 404 if the user is gone (we treat as no sessions).
        with self._client() as c:
            response = c.get(f"/api/v1/users/{user_id}/sessions")
            if response.status_code == 404:
                return []
            if response.status_code != 200:
                raise RuntimeError(
                    f"Okta list_active_sessions returned {response.status_code}: {response.text[:200]}"
                )
            data = response.json()
            return list(data) if isinstance(data, list) else []

    def list_active_oauth_tokens(self, user_id: str) -> list[dict[str, Any]]:
        # Okta GET /api/v1/users/{id}/oauth/tokens (refresh tokens for
        # OAuth/OIDC apps) per
        # https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listRefreshTokensForUser
        with self._client() as c:
            response = c.get(f"/api/v1/users/{user_id}/oauth/tokens")
            if response.status_code == 404:
                return []
            if response.status_code != 200:
                raise RuntimeError(
                    f"Okta list_active_oauth_tokens returned {response.status_code}: {response.text[:200]}"
                )
            data = response.json()
            return list(data) if isinstance(data, list) else []


# -- Audit writer protocol (injectable for tests) ----------------------------


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
class DualAuditWriter:
    """Dual-writes every action: DynamoDB row + S3 evidence object."""

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
        import boto3  # local import — tests inject a stub writer

        action_at = datetime.now(timezone.utc).isoformat()
        row_uid = _deterministic_uid(target.user_uid, step, action_at)
        evidence_key = (
            "okta-session-kill/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{target.user_uid}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "okta_user_uid": target.user_uid,
            "okta_user_name": target.user_name,
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
                "okta_user_uid": {"S": target.user_uid},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"rok-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


# -- OCSF finding parsing ----------------------------------------------------


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
            return str(obs.get("value") or "")
    return ""


def _observable_values(event: dict[str, Any], name: str) -> tuple[str, ...]:
    out: list[str] = []
    for obs in event.get("observables") or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("name") == name:
            value = str(obs.get("value") or "")
            if value:
                out.append(value)
    return tuple(out)


def parse_targets(events: Iterable[dict[str, Any]]) -> Iterator[tuple[Target | None, str]]:
    """Yield (Target, reason) pairs. Target is None when the finding is skipped."""
    for event in events:
        producer = _finding_product(event)
        if producer not in ACCEPTED_PRODUCERS:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="source_skill_mismatch",
                message=f"skipping finding from unaccepted producer `{producer}`",
                producer=producer,
            )
            yield None, STATUS_SKIPPED_SOURCE
            continue

        user_uid = _observable_value(event, "user.uid")
        if not user_uid:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_user_uid",
                message="skipping finding with no user.uid observable",
            )
            yield None, STATUS_SKIPPED_SOURCE
            continue

        user_name = _observable_value(event, "user.name") or user_uid
        source_ips = _observable_values(event, "src.ip") or _observable_values(event, "failure.ip")
        session_uids = _observable_values(event, "session.uid")

        target = Target(
            user_uid=user_uid,
            user_name=user_name,
            source_ips=source_ips,
            session_uids=session_uids,
            producer_skill=producer,
            finding_uid=_finding_uid(event),
        )
        yield target, ""


# -- Guardrails --------------------------------------------------------------


def load_deny_patterns() -> tuple[str, ...]:
    patterns: list[str] = list(DEFAULT_DENY_PATTERNS)
    extra_file = os.environ.get("OKTA_SESSION_KILL_DENY_LIST_FILE")
    if extra_file:
        try:
            with open(extra_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and item:
                        patterns.append(item)
        except (OSError, json.JSONDecodeError) as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="deny_list_file_unreadable",
                message=f"could not load {extra_file}: {exc}",
            )
    return tuple(patterns)


def is_protected(target: Target, deny_patterns: tuple[str, ...]) -> tuple[bool, str | None]:
    haystack = (target.user_uid + " " + target.user_name).lower()
    for pattern in deny_patterns:
        if pattern.lower() in haystack:
            return True, pattern
    return False, None


def _normalize_org_url(raw: str) -> str:
    value = raw.strip().rstrip("/")
    return value.lower()


def load_allowed_org_urls() -> tuple[str, ...]:
    raw = os.environ.get("OKTA_SESSION_KILL_ALLOWED_ORG_URLS", "").strip()
    if not raw:
        return ()
    return tuple(
        normalized
        for normalized in (_normalize_org_url(part) for part in raw.split(","))
        if normalized
    )


def check_apply_gate() -> tuple[bool, str]:
    """Return (ok, reason). Both env vars must be set before any Okta write."""
    incident_id = os.environ.get("OKTA_SESSION_KILL_INCIDENT_ID", "").strip()
    approver = os.environ.get("OKTA_SESSION_KILL_APPROVER", "").strip()
    org_url = _normalize_org_url(os.environ.get("OKTA_ORG_URL", ""))
    allowed_org_urls = load_allowed_org_urls()
    if not incident_id:
        return False, "OKTA_SESSION_KILL_INCIDENT_ID must be set before --apply"
    if not approver:
        return False, "OKTA_SESSION_KILL_APPROVER must be set before --apply"
    if not org_url:
        return False, "OKTA_ORG_URL must be set before --apply"
    if not allowed_org_urls:
        return False, "OKTA_SESSION_KILL_ALLOWED_ORG_URLS must be set before --apply"
    if org_url not in allowed_org_urls:
        return (
            False,
            "OKTA_ORG_URL must be included in OKTA_SESSION_KILL_ALLOWED_ORG_URLS before --apply",
        )
    return True, ""


# -- Core action -------------------------------------------------------------


def _step_endpoint(step: str, user_uid: str) -> str:
    if step == STEP_REVOKE_SESSIONS:
        return f"DELETE /api/v1/users/{user_uid}/sessions"
    if step == STEP_REVOKE_OAUTH_TOKENS:
        return f"DELETE /api/v1/users/{user_uid}/oauth/tokens"
    if step == STEP_EXPIRE_PASSWORD:
        return f"POST /api/v1/users/{user_uid}/lifecycle/expire_password"
    return step


def plan_actions(target: Target) -> list[ActionResult]:
    return [
        ActionResult(
            step=step, endpoint=_step_endpoint(step, target.user_uid), status=STATUS_PLANNED
        )
        for step in CONTAINMENT_STEPS
    ]


def apply_actions(
    target: Target,
    *,
    okta_client: OktaClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
) -> tuple[list[ActionResult], dict[str, str]]:
    audit_refs: dict[str, str] = {}
    results: list[ActionResult] = []

    for step in CONTAINMENT_STEPS:
        endpoint = _step_endpoint(step, target.user_uid)

        # 1) Audit-before — prove intent to act is recorded
        pre = audit.record(
            target=target,
            step=step,
            status=STATUS_IN_PROGRESS,
            detail=None,
            incident_id=incident_id,
            approver=approver,
        )
        audit_refs.setdefault(f"{step}_before_row_uid", pre["row_uid"])
        audit_refs.setdefault(f"{step}_before_s3_evidence_uri", pre["s3_evidence_uri"])

        # 2) API call
        try:
            if step == STEP_REVOKE_SESSIONS:
                okta_client.revoke_sessions(target.user_uid)
            elif step == STEP_REVOKE_OAUTH_TOKENS:
                okta_client.revoke_oauth_tokens(target.user_uid)
            final_status = STATUS_SUCCESS
            detail: str | None = None
        except Exception as exc:
            final_status = STATUS_FAILURE
            detail = str(exc)

        # 3) Audit-after — prove the outcome is recorded, even on failure
        post = audit.record(
            target=target,
            step=step,
            status=final_status,
            detail=detail,
            incident_id=incident_id,
            approver=approver,
        )
        audit_refs[f"{step}_after_row_uid"] = post["row_uid"]
        audit_refs[f"{step}_after_s3_evidence_uri"] = post["s3_evidence_uri"]

        results.append(
            ActionResult(step=step, endpoint=endpoint, status=final_status, detail=detail)
        )
        if final_status == STATUS_FAILURE:
            # Stop on failure. Later steps won't run without fresh operator intent.
            break

    return results, audit_refs


# -- Top-level entry ---------------------------------------------------------


def reverify_target(
    target: Target,
    *,
    okta_client: OktaClient,
    remediated_at_ms: int | None = None,
    now_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Re-verify that the user has no active sessions or OAuth refresh tokens
    after a previous session-kill remediation. Emits one verification record
    per call; on DRIFT also emits an OCSF Detection Finding so downstream
    SIEM/SOAR picks it up via the same pipeline.

    `remediated_at_ms` may be None when the verifier doesn't have access to
    the audit row; we use the verification time as the proxy and note
    within_sla=True. A future PR can wire DynamoDB lookup to populate this.
    """
    checked_at_ms = (
        now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    remediated_at_ms_resolved = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=_deterministic_uid("session-kill", target.user_uid),
        target_provider="Okta",
        target_identifier=target.user_uid,
        original_finding_uid=target.finding_uid,
        remediated_at_ms=remediated_at_ms_resolved,
    )

    expected = "no active sessions and no active OAuth refresh tokens for the user"

    try:
        sessions = okta_client.list_active_sessions(target.user_uid)
        tokens = okta_client.list_active_oauth_tokens(target.user_uid)
    except Exception as exc:
        # NEVER silently downgrade unreachable to verified — operator must see it
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="okta API call raised; cannot determine state",
            detail=str(exc),
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = {
            "provider": "Okta",
            "user_uid": target.user_uid,
            "user_name": target.user_name,
        }
        return [record]

    drift = bool(sessions) or bool(tokens)
    if drift:
        actual = f"sessions={len(sessions)} oauth_tokens={len(tokens)} (expected 0/0)"
        result = VerificationResult(
            status=VerificationStatus.DRIFT,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state=actual,
            detail="user has active sessions or OAuth refresh tokens after session-kill",
        )
    else:
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="0 sessions, 0 oauth tokens",
            detail="session-kill confirmed",
        )

    record = build_verification_record(
        reference=reference, result=result, verifier_skill=SKILL_NAME
    )
    record["target"] = {
        "provider": "Okta",
        "user_uid": target.user_uid,
        "user_name": target.user_name,
    }
    outputs = [record]
    if result.status == VerificationStatus.DRIFT:
        outputs.append(
            build_drift_finding(reference=reference, result=result, verifier_skill=SKILL_NAME)
        )
    return outputs


def run(
    events: Iterable[dict[str, Any]],
    *,
    apply: bool,
    okta_client: OktaClient | None,
    audit: AuditWriter | None,
    deny_patterns: tuple[str, ...] | None = None,
    incident_id: str = "",
    approver: str = "",
    org_url: str = "",
    allowed_org_urls: tuple[str, ...] | None = None,
    now_ms: int | None = None,
    reverify: bool = False,
) -> Iterator[dict[str, Any]]:
    deny_patterns = deny_patterns if deny_patterns is not None else load_deny_patterns()
    normalized_org_url = _normalize_org_url(org_url)
    resolved_allowed_org_urls = (
        allowed_org_urls if allowed_org_urls is not None else load_allowed_org_urls()
    )
    for target, skip_reason in parse_targets(events):
        if target is None:
            continue

        protected, matched = is_protected(target, deny_patterns)
        if protected:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="target_denied",
                message=f"refusing to remediate protected principal `{target.user_name}` (matched `{matched}`)",
                user_uid=target.user_uid,
                matched_pattern=matched,
            )
            yield _render_record(
                target=target,
                actions=[],
                audit_refs={},
                status=STATUS_SKIPPED_DENY_LIST,
                dry_run=not apply and not reverify,
                incident_id=incident_id,
                approver=approver,
                now_ms=now_ms,
                status_detail=f"matched deny pattern `{matched}`",
            )
            continue

        if reverify:
            if okta_client is None:
                raise RuntimeError("reverify=True requires okta_client to be provided")
            yield from reverify_target(target, okta_client=okta_client, now_ms=now_ms)
            continue

        if not apply:
            yield _render_record(
                target=target,
                actions=plan_actions(target),
                audit_refs={},
                status=STATUS_PLANNED,
                dry_run=True,
                incident_id=incident_id,
                approver=approver,
                now_ms=now_ms,
            )
            continue

        # --apply branch
        if okta_client is None or audit is None:
            raise RuntimeError("apply=True requires both okta_client and audit to be provided")
        if not normalized_org_url:
            raise RuntimeError("apply=True requires org_url to be provided")
        if not resolved_allowed_org_urls:
            raise RuntimeError("apply=True requires allowed_org_urls to be provided")
        if normalized_org_url not in resolved_allowed_org_urls:
            raise RuntimeError(
                "OKTA_ORG_URL is outside OKTA_SESSION_KILL_ALLOWED_ORG_URLS; refusing apply"
            )
        results, audit_refs = apply_actions(
            target,
            okta_client=okta_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
        )
        overall_status = (
            STATUS_SUCCESS if all(r.status == STATUS_SUCCESS for r in results) else STATUS_FAILURE
        )
        yield _render_record(
            target=target,
            actions=results,
            audit_refs=audit_refs,
            status=overall_status,
            dry_run=False,
            incident_id=incident_id,
            approver=approver,
            now_ms=now_ms,
        )


def _render_record(
    *,
    target: Target,
    actions: list[ActionResult],
    audit_refs: dict[str, str],
    status: str,
    dry_run: bool,
    incident_id: str,
    approver: str,
    now_ms: int | None,
    status_detail: str | None = None,
) -> dict[str, Any]:
    time_ms = now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "remediation_plan" if dry_run else "remediation_action",
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Okta",
            "user_uid": target.user_uid,
            "user_name": target.user_name,
        },
        "source_finding": {
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
            "source_ips": list(target.source_ips),
            "session_uids": list(target.session_uids),
        },
        "incident_id": incident_id,
        "approver": approver,
        "actions": [
            {
                "step": action.step,
                "endpoint": action.endpoint,
                "status": action.status,
                **({"detail": action.detail} if action.detail else {}),
            }
            for action in actions
        ],
        "audit": audit_refs,
        "status": status,
        "status_detail": status_detail,
        "dry_run": dry_run,
        "time_ms": time_ms,
    }


# -- CLI ---------------------------------------------------------------------


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
                message=f"skipping line {lineno}: {exc}",
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj


def _build_production_clients() -> tuple[OktaClient, AuditWriter]:
    """Wire up real Okta + AWS clients from environment. Called only under --apply."""
    org_url = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
    if not org_url:
        raise RuntimeError("OKTA_ORG_URL must be set under --apply")
    secret_arn = os.environ.get("OKTA_API_TOKEN_SECRETSMANAGER_ARN", "")
    if not secret_arn:
        raise RuntimeError("OKTA_API_TOKEN_SECRETSMANAGER_ARN must be set under --apply")

    import boto3  # local import

    secrets = boto3.client("secretsmanager")
    value = secrets.get_secret_value(SecretId=secret_arn)
    api_token = value.get("SecretString") or ""
    if not api_token:
        raise RuntimeError("Okta API token secret has empty SecretString")

    dynamodb_table = os.environ.get("IAM_AUDIT_DYNAMODB_TABLE", "")
    s3_bucket = os.environ.get("IAM_REMEDIATION_BUCKET", "")
    kms_key_arn = os.environ.get("KMS_KEY_ARN", "")
    for name, value in (
        ("IAM_AUDIT_DYNAMODB_TABLE", dynamodb_table),
        ("IAM_REMEDIATION_BUCKET", s3_bucket),
        ("KMS_KEY_ARN", kms_key_arn),
    ):
        if not value:
            raise RuntimeError(f"{name} must be set under --apply")

    return (
        HttpxOktaClient(org_url=org_url, api_token=api_token),
        DualAuditWriter(
            dynamodb_table=dynamodb_table, s3_bucket=s3_bucket, kms_key_arn=kms_key_arn
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Contain an Okta account takeover by revoking sessions and OAuth tokens. "
            "Dry-run by default; --apply requires a declared incident window."
        )
    )
    parser.add_argument("input", nargs="?", help="OCSF finding JSONL input (default: stdin)")
    parser.add_argument("--output", "-o", help="Record JSONL output (default: stdout)")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually call the Okta API. Requires OKTA_SESSION_KILL_INCIDENT_ID and OKTA_SESSION_KILL_APPROVER.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help=(
            "Read-only verification: confirm the user has no active sessions or "
            "OAuth refresh tokens after a previous session-kill remediation. "
            "Emits a verification record always, plus an OCSF Detection Finding "
            "on DRIFT so SIEM/SOAR picks it up."
        ),
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    incident_id = ""
    approver = ""
    okta_client: OktaClient | None = None
    audit: AuditWriter | None = None

    try:
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                emit_stderr_event(
                    SKILL_NAME,
                    level="error",
                    event="apply_gate_blocked",
                    message=reason,
                )
                return 2
            incident_id = os.environ["OKTA_SESSION_KILL_INCIDENT_ID"].strip()
            approver = os.environ["OKTA_SESSION_KILL_APPROVER"].strip()
            okta_client, audit = _build_production_clients()
        elif args.reverify:
            # Reverify needs Okta read access but no audit writer (read-only path)
            okta_client, _ = _build_production_clients()

        events = list(load_jsonl(in_stream))
        for record in run(
            events,
            apply=args.apply,
            reverify=args.reverify,
            okta_client=okta_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
            org_url=os.environ.get("OKTA_ORG_URL", ""),
            allowed_org_urls=load_allowed_org_urls(),
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
