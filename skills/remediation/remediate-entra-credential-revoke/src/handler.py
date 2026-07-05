"""Contain a Microsoft Entra credential-addition or role-grant-escalation finding.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by either:

- detect-entra-credential-addition (T1098.001 — Additional Cloud Credentials)
- detect-entra-role-grant-escalation (T1098.003 — Additional Cloud Roles)

Plans (dry-run default), applies (--apply), or re-verifies (--reverify) a
two-stage containment on the target service principal:

1. **Disable**: set `accountEnabled = false` on the service principal.
   Immediately stops new auth + token issuance. Cleanly reversible.
2. **Triage**: list the SP's current `keyCredentials`, `passwordCredentials`,
   `appRoleAssignments`, and `oauth2PermissionGrants`. Emit them in the
   action record so the operator can selectively revoke (the detector
   knows an event happened but does not know which specific credential id
   or assignment id is the offending one — manual triage by an operator
   with the audit context is the safe path).

Why disable + triage rather than auto-revoke
--------------------------------------------
Both Entra detectors fire on a CloudTrail-equivalent event log entry.
They know:
- WHICH service principal was modified (`target.uid`)
- WHEN (`time`)
- WHAT operation (`api.operation`, e.g. `Update application -- Certificates and secrets management`)

They do NOT know:
- The specific `keyCredentials[].keyId` of the new credential
- The specific `appRoleAssignments[].id` of the new assignment

Auto-revoke without that pointer would either over-block (revoke ALL
credentials, breaking legitimate ones) or guess. Disable-then-triage gives
the operator immediate containment AND the full state needed to make a
correct revocation choice — preserving forensic context.

Guardrails enforced in code:
- ACCEPTED_PRODUCERS limits input to the two Entra detectors
- protected-target deny-list: tenant-bootstrap and break-glass SPs by
  display-name prefix, plus any `target.uid` listed in
  ENTRA_PROTECTED_OBJECT_IDS env var
- --apply requires ENTRA_REVOKE_INCIDENT_ID + ENTRA_REVOKE_APPROVER
- dual audit BEFORE and AFTER the disable call
- --reverify confirms the SP is still disabled (DRIFT if re-enabled)

Required Microsoft Graph (Application) permissions:
- Application.ReadWrite.All  (disable + read credentials/assignments)
- Directory.Read.All         (resolve target.uid → object metadata)

Required Entra ID role: Application Administrator (or Privileged Role
Administrator if any target SPs have privileged roles assigned).
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import http.client
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol
from urllib import parse as urllib_parse

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

SKILL_NAME = "remediate-entra-credential-revoke"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset(
    {
        "detect-entra-credential-addition",
        "detect-entra-role-grant-escalation",
    }
)

# Display-name prefixes that mark a service principal as tenant-bootstrap or
# break-glass — refuse to disable these even with --apply. Operators must
# triage these by hand.
DEFAULT_PROTECTED_NAME_PREFIXES = (
    "break-glass",
    "emergency",
    "tenant-",
    "directory-",
    "ms-",
    "microsoft-",
)

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_DISABLE_SP = "disable_service_principal"
STEP_TRIAGE_LIST = "list_credentials_and_assignments"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_PROTECTED = "skipped_protected_target"
STATUS_WOULD_VIOLATE_PROTECTED = "would-violate-protected-target"
STATUS_SKIPPED_NO_TARGET = "skipped_no_target_pointer"
STATUS_SKIPPED_UNSUPPORTED_TYPE = "skipped_unsupported_target_type"

SUPPORTED_TARGET_TYPES = frozenset({"ServicePrincipal", "Application"})


@dataclasses.dataclass(frozen=True)
class Target:
    object_id: str  # target.uid — the SP/Application objectId
    display_name: str  # target.name
    target_type: str  # target.type ("ServicePrincipal" | "Application")
    actor: str  # actor.name (audit context)
    api_operation: str  # api.operation (audit context)
    rule: str  # which detector rule fired
    producer_skill: str
    finding_uid: str


@dataclasses.dataclass(frozen=True)
class ResolvedServicePrincipal:
    object_id: str
    display_name: str
    app_id: str
    source_target_type: str
    source_object_id: str


class GraphClient(Protocol):
    """Microsoft Graph API surface this skill needs. Tests inject a stub."""

    def resolve_service_principal(self, target: Target) -> ResolvedServicePrincipal | None: ...
    def get_service_principal(self, object_id: str) -> dict[str, Any] | None: ...
    def disable_service_principal(self, object_id: str) -> None: ...
    def list_key_credentials(self, object_id: str) -> list[dict[str, Any]]: ...
    def list_password_credentials(self, object_id: str) -> list[dict[str, Any]]: ...
    def list_app_role_assignments(self, object_id: str) -> list[dict[str, Any]]: ...
    def list_oauth2_permission_grants(self, object_id: str) -> list[dict[str, Any]]: ...


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
class MsGraphClient:
    """Real Microsoft Graph REST client. Built lazily so tests don't require Azure SDKs."""

    tenant_id: str
    client_id: str
    client_secret: str

    def _credential(self) -> Any:
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

    def _token(self) -> str:
        return self._credential().get_token("https://graph.microsoft.com/.default").token

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        body: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> Any | None:
        parsed = urllib_parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com":
            raise RuntimeError(f"refusing non-Microsoft Graph URL `{url}`")
        body_bytes = None
        headers = {"Authorization": f"Bearer {self._token()}"}
        if body is not None:
            body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        connection = http.client.HTTPSConnection(parsed.netloc)
        try:
            connection.request(method.upper(), path, body=body_bytes, headers=headers)
            response = connection.getresponse()
            payload = response.read()
        except OSError as exc:
            raise RuntimeError(f"Microsoft Graph connection failed: {exc}") from exc
        finally:
            connection.close()
        if response.status >= 400:
            if response.status == 404 and allow_not_found:
                return None
            detail = payload.decode("utf-8", errors="replace")
            raise RuntimeError(f"Microsoft Graph {response.status}: {detail or response.reason}")
        if not payload:
            return None
        return json.loads(payload)

    def _collection(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        while next_url:
            payload = self._request_json("GET", next_url)
            if not isinstance(payload, dict):
                break
            value = payload.get("value")
            if isinstance(value, list):
                items.extend(item for item in value if isinstance(item, dict))
            raw_next = payload.get("@odata.nextLink")
            next_url = str(raw_next) if raw_next else None
        return items

    def _service_principal_base_url(self, object_id: str) -> str:
        object_id_q = urllib_parse.quote(object_id, safe="")
        return f"https://graph.microsoft.com/v1.0/servicePrincipals/{object_id_q}"

    def _service_principal_url(self, object_id: str, *, select: str) -> str:
        return f"{self._service_principal_base_url(object_id)}?$select={select}"

    def _application_url(self, object_id: str, *, select: str) -> str:
        object_id_q = urllib_parse.quote(object_id, safe="")
        return f"https://graph.microsoft.com/v1.0/applications/{object_id_q}?$select={select}"

    def _service_principals_by_app_id_url(self, app_id: str, *, select: str) -> str:
        escaped = app_id.replace("'", "''")
        filter_expr = urllib_parse.quote(f"appId eq '{escaped}'", safe="'")
        return (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"?$filter={filter_expr}&$select={select}"
        )

    def resolve_service_principal(self, target: Target) -> ResolvedServicePrincipal | None:
        if target.target_type == "Application":
            app = self._request_json(
                "GET",
                self._application_url(target.object_id, select="id,appId,displayName"),
                allow_not_found=True,
            )
            if app is None:
                return None
            if not isinstance(app, dict):
                raise RuntimeError("Microsoft Graph returned a non-object application response")
            app_id = str(app.get("appId") or "")
            if not app_id:
                raise RuntimeError(f"application `{target.object_id}` is missing appId")
            matches = self._collection(
                self._service_principals_by_app_id_url(
                    app_id,
                    select="id,appId,displayName,accountEnabled",
                )
            )
            if not matches:
                return None
            if len(matches) > 1:
                raise RuntimeError(
                    f"application `{target.object_id}` resolved to multiple service principals for appId `{app_id}`"
                )
            match = matches[0]
            return ResolvedServicePrincipal(
                object_id=str(match.get("id") or ""),
                display_name=str(
                    match.get("displayName") or target.display_name or target.object_id
                ),
                app_id=str(match.get("appId") or app_id),
                source_target_type=target.target_type,
                source_object_id=target.object_id,
            )
        sp = self.get_service_principal(target.object_id)
        if sp is None:
            return None
        return ResolvedServicePrincipal(
            object_id=str(sp.get("id") or target.object_id),
            display_name=str(sp.get("displayName") or target.display_name or target.object_id),
            app_id=str(sp.get("appId") or ""),
            source_target_type=target.target_type or "ServicePrincipal",
            source_object_id=target.object_id,
        )

    def get_service_principal(self, object_id: str) -> dict[str, Any] | None:
        payload = self._request_json(
            "GET",
            self._service_principal_url(
                object_id,
                select="id,appId,displayName,accountEnabled,keyCredentials,passwordCredentials",
            ),
            allow_not_found=True,
        )
        if payload is None:
            return None
        if not isinstance(payload, dict):
            raise RuntimeError("Microsoft Graph returned a non-object servicePrincipal response")
        return payload

    def disable_service_principal(self, object_id: str) -> None:
        self._request_json(
            "PATCH",
            self._service_principal_base_url(object_id),
            body={"accountEnabled": False},
        )

    def list_key_credentials(self, object_id: str) -> list[dict[str, Any]]:
        sp = self.get_service_principal(object_id) or {}
        values = sp.get("keyCredentials") or []
        return [item for item in values if isinstance(item, dict)]

    def list_password_credentials(self, object_id: str) -> list[dict[str, Any]]:
        sp = self.get_service_principal(object_id) or {}
        values = sp.get("passwordCredentials") or []
        return [item for item in values if isinstance(item, dict)]

    def list_app_role_assignments(self, object_id: str) -> list[dict[str, Any]]:
        return self._collection(f"{self._service_principal_base_url(object_id)}/appRoleAssignments")

    def list_oauth2_permission_grants(self, object_id: str) -> list[dict[str, Any]]:
        escaped = object_id.replace("'", "''")
        filter_expr = urllib_parse.quote(f"clientId eq '{escaped}'", safe="'")
        return self._collection(
            "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
            f"?$filter={filter_expr}&$select=id,clientId,resourceId,scope,consentType"
        )


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
        row_uid = _deterministic_uid(target.object_id, step, action_at)
        evidence_key = (
            "entra-credential-revoke/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(target.object_id)}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "object_id": target.object_id,
            "display_name": target.display_name,
            "target_type": target.target_type,
            "actor": target.actor,
            "api_operation": target.api_operation,
            "rule": target.rule,
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
                "object_id": {"S": target.object_id},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "display_name": {"S": target.display_name},
                "target_type": {"S": target.target_type},
                "actor": {"S": target.actor},
                "api_operation": {"S": target.api_operation},
                "rule": {"S": target.rule},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"entra-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _safe_path_component(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (value or "_"))
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

    return Target(
        object_id=_observable_value(event, "target.uid"),
        display_name=_observable_value(event, "target.name"),
        target_type=_observable_value(event, "target.type"),
        actor=_observable_value(event, "actor.name"),
        api_operation=_observable_value(event, "api.operation"),
        rule=_observable_value(event, "rule"),
        producer_skill=producer,
        finding_uid=_finding_uid(event),
    )


def parse_targets(
    events: Iterable[dict[str, Any]],
) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_protected_name_prefixes() -> tuple[str, ...]:
    return DEFAULT_PROTECTED_NAME_PREFIXES


def load_protected_object_ids() -> tuple[str, ...]:
    raw = os.getenv("ENTRA_PROTECTED_OBJECT_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def is_protected_target(
    target: Target, *, name_prefixes: Iterable[str], object_ids: Iterable[str]
) -> tuple[bool, str]:
    name_lc = (target.display_name or "").strip().lower()
    if name_lc:
        for prefix in name_prefixes:
            needle = prefix.lower()
            if name_lc.startswith(needle):
                return True, f"name-prefix `{prefix}`"
    if target.object_id and target.object_id in set(object_ids):
        return True, f"object-id allowlist match `{target.object_id}`"
    return False, ""


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("ENTRA_REVOKE_INCIDENT_ID", "").strip()
    approver = os.getenv("ENTRA_REVOKE_APPROVER", "").strip()
    tenant_id = os.getenv("AZURE_TENANT_ID", "").strip()
    if not incident_id:
        return False, "ENTRA_REVOKE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "ENTRA_REVOKE_APPROVER is required for --apply"
    if not tenant_id:
        return False, "AZURE_TENANT_ID is required for --apply"
    allowed_tenants = load_allowed_tenant_ids()
    if not allowed_tenants:
        return False, "ENTRA_REVOKE_ALLOWED_TENANT_IDS is required for --apply"
    if tenant_id not in allowed_tenants:
        return (
            False,
            f"AZURE_TENANT_ID `{tenant_id}` is not listed in ENTRA_REVOKE_ALLOWED_TENANT_IDS",
        )
    return True, ""


def load_allowed_tenant_ids() -> tuple[str, ...]:
    raw = os.getenv("ENTRA_REVOKE_ALLOWED_TENANT_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _disable_endpoint(resolved: ResolvedServicePrincipal) -> str:
    # Microsoft Graph: PATCH /servicePrincipals/{id} with {"accountEnabled": false}
    return f"PATCH /v1.0/servicePrincipals/{resolved.object_id}"


def _triage_endpoint(resolved: ResolvedServicePrincipal) -> str:
    return (
        f"GET /v1.0/servicePrincipals/{resolved.object_id} "
        "(keyCredentials, passwordCredentials, appRoleAssignments, oauth2PermissionGrants)"
    )


def _resolved_target(target: Target, resolved: ResolvedServicePrincipal) -> Target:
    return Target(
        object_id=resolved.object_id,
        display_name=resolved.display_name or target.display_name,
        target_type="ServicePrincipal",
        actor=target.actor,
        api_operation=target.api_operation,
        rule=target.rule,
        producer_skill=target.producer_skill,
        finding_uid=target.finding_uid,
    )


def _build_triage_payload(
    resolved: ResolvedServicePrincipal, *, graph_client: GraphClient
) -> dict[str, Any]:
    """Read the SP's current credentials + assignments; bundle for operator triage."""
    return {
        "key_credentials": graph_client.list_key_credentials(resolved.object_id),
        "password_credentials": graph_client.list_password_credentials(resolved.object_id),
        "app_role_assignments": graph_client.list_app_role_assignments(resolved.object_id),
        "oauth2_permission_grants": graph_client.list_oauth2_permission_grants(resolved.object_id),
    }


def _plan_record(
    target: Target,
    *,
    status: str,
    detail: str | None,
    dry_run: bool,
    triage: dict[str, Any] | None = None,
    resolved: ResolvedServicePrincipal | None = None,
) -> dict[str, Any]:
    resolved_section = None
    if resolved is not None:
        resolved_section = {
            "object_id": resolved.object_id,
            "display_name": resolved.display_name,
            "app_id": resolved.app_id,
            "source_target_type": resolved.source_target_type,
            "source_object_id": resolved.source_object_id,
        }
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Entra",
            "object_id": target.object_id,
            "display_name": target.display_name,
            "target_type": target.target_type,
            "actor": target.actor,
            "rule": target.rule,
        },
        "actions": [
            {
                "step": STEP_DISABLE_SP,
                "endpoint": _disable_endpoint(resolved)
                if resolved is not None
                else "PATCH /v1.0/servicePrincipals/<resolved-target>",
                "status": status,
                "detail": detail,
            },
            {
                "step": STEP_TRIAGE_LIST,
                "endpoint": _triage_endpoint(resolved)
                if resolved is not None
                else "GET /v1.0/servicePrincipals/<resolved-target> (...)",
                "status": status,
                "detail": "list current credentials + assignments for operator triage",
            },
        ],
        "resolved_service_principal": resolved_section,
        "triage": triage,
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
            "provider": "Entra",
            "object_id": target.object_id,
            "display_name": target.display_name,
            "target_type": target.target_type,
            "actor": target.actor,
            "rule": target.rule,
        },
        "actions": [],
        "status": status,
        "status_detail": detail,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def disable_and_triage(
    target: Target,
    *,
    graph_client: GraphClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
) -> dict[str, Any]:
    resolved = graph_client.resolve_service_principal(target)
    if resolved is None:
        return _plan_record(
            target,
            status=STATUS_FAILURE,
            detail=(
                "could not resolve a backing service principal for "
                f"{target.target_type or 'target'} `{target.object_id}`"
            ),
            dry_run=False,
        )
    audit_target = _resolved_target(target, resolved)
    first_audit = audit.record(
        target=audit_target,
        step=STEP_DISABLE_SP,
        status=STATUS_IN_PROGRESS,
        detail=f"about to disable service principal `{resolved.object_id}`",
        incident_id=incident_id,
        approver=approver,
    )
    try:
        graph_client.disable_service_principal(resolved.object_id)
    except Exception as exc:
        audit.record(
            target=audit_target,
            step=STEP_DISABLE_SP,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
        )
        record = _plan_record(
            target,
            status=STATUS_FAILURE,
            detail=str(exc),
            dry_run=False,
            resolved=resolved,
        )
        record["audit"] = first_audit
        return record

    audit.record(
        target=audit_target,
        step=STEP_DISABLE_SP,
        status=STATUS_SUCCESS,
        detail=f"disabled `{resolved.object_id}` (accountEnabled=false)",
        incident_id=incident_id,
        approver=approver,
    )

    # Best-effort triage gather. If this fails we still return SUCCESS for the
    # disable step — the SP is contained either way and the operator can rerun
    # triage manually.
    try:
        triage = _build_triage_payload(resolved, graph_client=graph_client)
        triage_detail = (
            f"listed {len(triage['key_credentials'])} keys, "
            f"{len(triage['password_credentials'])} passwords, "
            f"{len(triage['app_role_assignments'])} role assignments, "
            f"{len(triage['oauth2_permission_grants'])} OAuth2 grants"
        )
        triage_audit = audit.record(
            target=audit_target,
            step=STEP_TRIAGE_LIST,
            status=STATUS_SUCCESS,
            detail=triage_detail,
            incident_id=incident_id,
            approver=approver,
        )
    except Exception as exc:
        triage = None
        triage_detail = f"triage list failed: {exc}"
        triage_audit = audit.record(
            target=audit_target,
            step=STEP_TRIAGE_LIST,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
        )

    record = _plan_record(
        target,
        status=STATUS_SUCCESS,
        detail="disabled service principal; triage payload attached",
        dry_run=False,
        triage=triage,
        resolved=resolved,
    )
    # Mark the second action with the actual triage outcome
    record["actions"][1]["status"] = "success" if triage is not None else "failure"
    record["actions"][1]["detail"] = triage_detail
    record["audit"] = triage_audit
    record["incident_id"] = incident_id
    record["approver"] = approver
    return record


def reverify_target(
    target: Target,
    *,
    graph_client: GraphClient,
    now_ms: int | None = None,
    remediated_at_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Re-verify the SP is still disabled. Emits one verification record;
    on DRIFT also emits an OCSF Detection Finding via the shared contract."""
    checked_at_ms = (
        now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    remediated_at_ms_resolved = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=_deterministic_uid("disable", target.object_id),
        target_provider="Entra",
        target_identifier=target.object_id,
        original_finding_uid=target.finding_uid,
        remediated_at_ms=remediated_at_ms_resolved,
    )
    expected = f"service principal `{target.object_id}` has accountEnabled=false"

    try:
        resolved = graph_client.resolve_service_principal(target)
    except Exception as exc:
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="microsoft graph resolution raised; cannot determine state",
            detail=str(exc),
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = {
            "provider": "Entra",
            "object_id": target.object_id,
            "display_name": target.display_name,
        }
        return [record]

    if resolved is None:
        # SP is gone entirely. That's a STRONGER state than disabled — counts as
        # verified containment. Operator may also want to know it was deleted.
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="backing service principal not found (deleted or never existed) — stronger than disabled",
            detail="containment confirmed via absence",
        )
    else:
        try:
            sp = graph_client.get_service_principal(resolved.object_id)
        except Exception as exc:
            result = VerificationResult(
                status=VerificationStatus.UNREACHABLE,
                checked_at_ms=checked_at_ms,
                sla_deadline_ms=sla_deadline(
                    remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                ),
                expected_state=expected,
                actual_state="microsoft graph call raised; cannot determine state",
                detail=str(exc),
            )
        else:
            if sp is None:
                result = VerificationResult(
                    status=VerificationStatus.VERIFIED,
                    checked_at_ms=checked_at_ms,
                    sla_deadline_ms=sla_deadline(
                        remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                    ),
                    expected_state=expected,
                    actual_state="service principal not found (deleted) — stronger than disabled",
                    detail="containment confirmed via absence",
                )
            elif sp.get("accountEnabled") is False:
                result = VerificationResult(
                    status=VerificationStatus.VERIFIED,
                    checked_at_ms=checked_at_ms,
                    sla_deadline_ms=sla_deadline(
                        remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                    ),
                    expected_state=expected,
                    actual_state="accountEnabled=false",
                    detail="service principal still disabled",
                )
            else:
                result = VerificationResult(
                    status=VerificationStatus.DRIFT,
                    checked_at_ms=checked_at_ms,
                    sla_deadline_ms=sla_deadline(
                        remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                    ),
                    expected_state=expected,
                    actual_state=f"accountEnabled={sp.get('accountEnabled')!r}",
                    detail="service principal was re-enabled after remediation",
                )

    record = build_verification_record(
        reference=reference, result=result, verifier_skill=SKILL_NAME
    )
    record["target"] = {
        "provider": "Entra",
        "object_id": target.object_id,
        "display_name": target.display_name,
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
    graph_client: GraphClient,
    apply: bool = False,
    reverify: bool = False,
    audit: AuditWriter | None = None,
    name_prefixes: Iterable[str] = DEFAULT_PROTECTED_NAME_PREFIXES,
    object_ids: Iterable[str] = (),
    incident_id: str = "",
    approver: str = "",
    tenant_id: str = "",
    allowed_tenant_ids: Iterable[str] = (),
) -> Iterator[dict[str, Any]]:
    name_prefixes = tuple(name_prefixes)
    object_ids = tuple(object_ids)
    allowed_tenant_ids = tuple(allowed_tenant_ids)

    if apply:
        if not tenant_id:
            raise ValueError("tenant_id is required under --apply")
        if tenant_id not in allowed_tenant_ids:
            raise ValueError(
                f"tenant_id `{tenant_id}` is not listed in ENTRA_REVOKE_ALLOWED_TENANT_IDS"
            )

    for target, event in parse_targets(events):
        if target is None:
            continue

        dry_run = not apply and not reverify

        if not target.object_id:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_NO_TARGET,
                detail="finding did not carry a target.uid observable; cannot identify SP",
                dry_run=dry_run,
            )
            continue

        if target.target_type and target.target_type not in SUPPORTED_TARGET_TYPES:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_UNSUPPORTED_TYPE,
                detail=(
                    f"target.type=`{target.target_type}` is not in supported set "
                    f"({sorted(SUPPORTED_TARGET_TYPES)})"
                ),
                dry_run=dry_run,
            )
            continue

        protected, why = is_protected_target(
            target, name_prefixes=name_prefixes, object_ids=object_ids
        )
        if protected:
            status = STATUS_SKIPPED_PROTECTED if apply else STATUS_WOULD_VIOLATE_PROTECTED
            yield _skip_record(
                target,
                status=status,
                detail=f"target is protected: {why}",
                dry_run=dry_run,
            )
            continue

        if reverify:
            yield from reverify_target(
                target,
                graph_client=graph_client,
                remediated_at_ms=_event_reference_time_ms(event),
            )
            continue

        if not apply:
            yield _plan_record(
                target,
                status=STATUS_PLANNED,
                detail=f"dry-run: would disable `{target.object_id}` and emit triage payload",
                dry_run=True,
            )
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        yield disable_and_triage(
            target,
            graph_client=graph_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify Entra service-principal credential containment."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Disable the offending service principal after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm the service principal is still disabled.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        graph_client: GraphClient = MsGraphClient(
            tenant_id=os.environ.get("AZURE_TENANT_ID", ""),
            client_id=os.environ.get("AZURE_CLIENT_ID", ""),
            client_secret=os.environ.get("AZURE_CLIENT_SECRET", ""),
        )
        audit: AuditWriter | None = None
        incident_id = ""
        approver = ""
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.environ["ENTRA_REVOKE_INCIDENT_ID"].strip()
            approver = os.environ["ENTRA_REVOKE_APPROVER"].strip()
            audit = DualAuditWriter(
                dynamodb_table=os.environ["ENTRA_REVOKE_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["ENTRA_REVOKE_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )

        for record in run(
            load_jsonl(in_stream),
            graph_client=graph_client,
            apply=args.apply,
            reverify=args.reverify,
            audit=audit,
            object_ids=load_protected_object_ids(),
            incident_id=incident_id,
            approver=approver,
            tenant_id=os.environ.get("AZURE_TENANT_ID", "").strip(),
            allowed_tenant_ids=load_allowed_tenant_ids(),
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
