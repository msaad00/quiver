"""Function 2: Worker — execute the 11-step Entra IAM teardown for one user.

Receives validated entries from the parser Function via the Logic App map
step. For each Entra user we run the eleven steps defined in :mod:`steps`,
with dual audit (Cosmos DB + CMK-encrypted Blob Storage) BEFORE and AFTER
each step so the audit trail captures both the intent and the outcome
(including failures).

This is the Azure Entra counterpart to
`skills/remediation/iam-departures-aws/src/lambda_worker/handler.py`.
Same shape, same semantics, different cloud surface.

HITL enforcement: --apply requires both
    IAM_DEPARTURES_AZURE_INCIDENT_ID
    IAM_DEPARTURES_AZURE_APPROVER
set out-of-band. Without both, --apply is rejected with exit code 2.

MITRE ATT&CK coverage:
    T1531     Account Access Removal — revoking departed-employee Entra access
    T1098.001 Account Manipulation: Additional Cloud Credentials — sessions/grants/keys cleared
    T1078.004 Valid Accounts: Cloud Accounts — eliminating persistence vector

NIST CSF 2.0:
    PR.AC-1   Identities and credentials are issued, managed, verified, revoked
    PR.AC-4   Access permissions and authorizations are managed
    RS.MI-2   Incidents are mitigated

CIS Controls v8:
    5.3   Disable Dormant Accounts
    6.2   Establish an Access Revoking Process
    6.5   Require MFA (clean up MFA-bound sessions via revokeSignInSessions)

SOC 2 (Trust Services Criteria):
    CC6.1   Logical and Physical Access Controls — access revocation
    CC6.2   Prior to Issuing System Credentials — lifecycle management
    CC6.3   Registration and Authorization — deprovisioning
"""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterable

# Steps live in a sibling module so they can be unit-tested without the
# rest of the orchestrator. Both relative- and direct-import paths must
# work because the `tests/conftest.py` shim points sys.path at `src/` so
# `import function_worker.handler` works in production, and `from steps
# import ...` works in the test harness (where `function_worker` is on
# the path twice through different roots).
try:
    from .steps import STEP_NAMES, remediation_steps
except ImportError:  # pragma: no cover — exercised via test conftest
    from steps import STEP_NAMES, remediation_steps  # type: ignore[no-redef]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ── Configuration ──────────────────────────────────────────────────────────

SKILL_NAME = "iam-departures-azure-entra"
CANONICAL_VERSION = "2026-04"

# Protected principals — defense-in-depth deny list, mirrored from the IaC
# `infra/iam_policies/cross_subscription_role.json` `DenyProtectedUsers`
# condition. These are the UPNs / display-name patterns we refuse to touch
# locally even before Microsoft Graph is called.
DEFAULT_PROTECTED_UPN_PATTERNS: tuple[str, ...] = (
    "admin@*",
    "breakglass-*",
    "emergency-*",
    "sync_*",
)

ENTRA_OBJECT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ProtectedPrincipalError(ValueError):
    """Raised when a remediation target matches the protected-principal deny list."""


def is_protected_user(
    *, upn: str, object_id: str, extra_object_ids: Iterable[str] = ()
) -> tuple[bool, str]:
    """True (with reason) if this UPN/objectId is on the deny list."""
    upn_lc = (upn or "").strip().lower()
    if upn_lc:
        for pattern in DEFAULT_PROTECTED_UPN_PATTERNS:
            if fnmatch.fnmatchcase(upn_lc, pattern.lower()):
                return True, f"upn-pattern `{pattern}`"
    if object_id and object_id in set(extra_object_ids):
        return True, f"object-id allowlist match `{object_id}`"
    return False, ""


def load_extra_protected_object_ids() -> tuple[str, ...]:
    raw = os.getenv("IAM_DEPARTURES_AZURE_PROTECTED_OBJECT_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


# ── HITL gate ──────────────────────────────────────────────────────────────


def check_apply_gate() -> tuple[bool, str]:
    """Both env vars MUST be set for --apply to fire."""
    incident = os.getenv("IAM_DEPARTURES_AZURE_INCIDENT_ID", "").strip()
    approver = os.getenv("IAM_DEPARTURES_AZURE_APPROVER", "").strip()
    if not incident:
        return False, "IAM_DEPARTURES_AZURE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "IAM_DEPARTURES_AZURE_APPROVER is required for --apply"
    return True, ""


# ── Audit writer ───────────────────────────────────────────────────────────


@dataclasses.dataclass
class DualAuditWriter:
    """Dual-write to Cosmos DB + CMK-encrypted Blob Storage.

    The handler always writes BEFORE the step (status=in_progress) and
    AFTER (status=success or failure). Cosmos failures do not block the
    Blob write and vice versa; both errors are logged.
    """

    cosmos_account: str
    cosmos_database: str
    cosmos_container: str
    blob_account: str
    blob_container: str
    key_vault_key_id: str

    def record(
        self,
        *,
        upn: str,
        object_id: str,
        tenant_id: str,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
        actions_so_far: list[dict[str, Any]] | None = None,
    ) -> dict[str, str]:
        action_at = _now()
        row_uid = _deterministic_uid(object_id, step, action_at)
        evidence_key = (
            f"departures/audit/{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(object_id)}/{action_at}-{step}.json"
        )
        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "object_id": object_id,
            "upn": upn,
            "tenant_id": tenant_id,
            "step": step,
            "status": status,
            "status_detail": detail,
            "incident_id": incident_id,
            "approver": approver,
            "action_at": action_at,
            "actions_so_far": actions_so_far or [],
        }
        body = json.dumps(envelope, separators=(",", ":"))

        self._write_blob(blob_name=evidence_key, body=body)
        self._write_cosmos(envelope=envelope, evidence_key=evidence_key)
        return {"row_uid": row_uid, "blob_evidence_key": evidence_key}

    def _write_blob(self, *, blob_name: str, body: str) -> None:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient
        except Exception:
            logger.exception("Cannot import azure.storage.blob; skipping blob audit write")
            return
        try:
            credential = DefaultAzureCredential()
            service = BlobServiceClient(
                account_url=f"https://{self.blob_account}.blob.core.windows.net",
                credential=credential,
            )
            blob_client = service.get_blob_client(container=self.blob_container, blob=blob_name)
            blob_client.upload_blob(
                body.encode("utf-8"),
                overwrite=False,
                content_type="application/json",
                # CMK is enforced on the storage account by Key Vault binding;
                # we pin the key id in the audit envelope so the audit row is
                # self-describing even if the CMK is rotated later.
                metadata={"key_vault_key_id": self.key_vault_key_id},
            )
        except Exception:
            logger.exception("Failed to write blob audit record `%s`", blob_name)

    def _write_cosmos(self, *, envelope: dict[str, Any], evidence_key: str) -> None:
        try:
            from azure.cosmos import CosmosClient
            from azure.identity import DefaultAzureCredential
        except Exception:
            logger.exception("Cannot import azure.cosmos; skipping cosmos audit write")
            return
        try:
            credential = DefaultAzureCredential()
            client = CosmosClient(
                url=f"https://{self.cosmos_account}.documents.azure.com:443/",
                credential=credential,
            )
            container = client.get_database_client(self.cosmos_database).get_container_client(
                self.cosmos_container
            )
            container.upsert_item(
                {
                    "id": envelope["row_uid"],
                    "pk": f"AUDIT#{envelope['object_id']}",
                    "blob_evidence_key": evidence_key,
                    **envelope,
                }
            )
        except Exception:
            logger.exception("Failed to write Cosmos DB audit row")


# ── Microsoft Graph + Azure RBAC client ────────────────────────────────────


@dataclasses.dataclass
class EntraRemediationClient:
    """Lazy Microsoft Graph + Azure RBAC client.

    Implementations of the per-step methods live here so :mod:`steps` can
    consume a typed surface in tests without dragging the SDK in. All Azure
    SDK imports happen inside the methods so dry-run + test runs do not
    require the SDK to be installed.
    """

    tenant_id: str
    client_id: str
    client_secret: str
    management_group_id: str = ""

    # ── Microsoft Graph: user state ───────────────────────────────────────
    def disable_user(self, *, object_id: str) -> None:
        self._graph_request("PATCH", f"/v1.0/users/{object_id}", body={"accountEnabled": False})

    def revoke_signin_sessions(self, *, object_id: str) -> None:
        self._graph_request("POST", f"/v1.0/users/{object_id}/revokeSignInSessions")

    def hard_delete_user(self, *, object_id: str) -> None:
        self._graph_request("DELETE", f"/v1.0/users/{object_id}")

    def tag_user(self, *, object_id: str, tags: dict[str, Any]) -> None:
        self._graph_request("PATCH", f"/v1.0/users/{object_id}", body=tags)

    # ── Microsoft Graph: groups + roles + grants ──────────────────────────
    def list_oauth2_permission_grants(self, *, principal_id: str) -> list[dict[str, Any]]:
        return self._graph_collection(
            f"/v1.0/oauth2PermissionGrants?$filter=clientId eq '{principal_id}'"
        )

    def delete_oauth2_permission_grant(self, *, grant_id: str) -> None:
        self._graph_request("DELETE", f"/v1.0/oauth2PermissionGrants/{grant_id}")

    def list_user_groups(self, *, object_id: str) -> list[dict[str, Any]]:
        return self._graph_collection(f"/v1.0/users/{object_id}/memberOf")

    def remove_group_member(self, *, group_id: str, user_id: str) -> None:
        self._graph_request("DELETE", f"/v1.0/groups/{group_id}/members/{user_id}/$ref")

    def list_user_directory_roles(self, *, object_id: str) -> list[dict[str, Any]]:
        # Directory roles are returned by the same memberOf collection but
        # carry @odata.type=#microsoft.graph.directoryRole. The simplest
        # robust path is to list the user's transitive directory-role
        # memberships explicitly.
        return self._graph_collection(
            f"/v1.0/users/{object_id}/transitiveMemberOf/microsoft.graph.directoryRole"
        )

    def remove_directory_role_member(self, *, role_id: str, user_id: str) -> None:
        self._graph_request("DELETE", f"/v1.0/directoryRoles/{role_id}/members/{user_id}/$ref")

    def list_user_app_role_assignments(self, *, object_id: str) -> list[dict[str, Any]]:
        return self._graph_collection(f"/v1.0/users/{object_id}/appRoleAssignments")

    def delete_user_app_role_assignment(self, *, user_id: str, assignment_id: str) -> None:
        self._graph_request("DELETE", f"/v1.0/users/{user_id}/appRoleAssignments/{assignment_id}")

    def list_user_licenses(self, *, object_id: str) -> list[dict[str, Any]]:
        return self._graph_collection(f"/v1.0/users/{object_id}/licenseDetails")

    def remove_licenses(self, *, object_id: str, sku_ids: list[str]) -> None:
        self._graph_request(
            "POST",
            f"/v1.0/users/{object_id}/assignLicense",
            body={"addLicenses": [], "removeLicenses": sku_ids},
        )

    # ── Azure RBAC: role assignments ──────────────────────────────────────
    def list_role_assignments(self, *, scope_type: str, principal_id: str) -> list[dict[str, Any]]:
        # scope_type is one of: subscription, management_group, resource_group
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.authorization import AuthorizationManagementClient

        credential = DefaultAzureCredential()
        # The SDK requires a per-call subscription_id; for management-group
        # scope we still need one but the API list-by-scope works against any
        # subscription the principal has access to. The runner is expected
        # to set IAM_DEPARTURES_AZURE_DEFAULT_SUBSCRIPTION_ID for this case.
        subscription_id = os.environ.get("IAM_DEPARTURES_AZURE_DEFAULT_SUBSCRIPTION_ID", "")
        scope = self._scope_for(scope_type=scope_type, subscription_id=subscription_id)
        client = AuthorizationManagementClient(credential, subscription_id)
        out: list[dict[str, Any]] = []
        for assignment in client.role_assignments.list_for_scope(
            scope=scope, filter=f"principalId eq '{principal_id}'"
        ):
            out.append({"id": assignment.id, "scope": assignment.scope})
        return out

    def delete_role_assignment(self, *, assignment_id: str) -> None:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.authorization import AuthorizationManagementClient

        credential = DefaultAzureCredential()
        subscription_id = os.environ.get("IAM_DEPARTURES_AZURE_DEFAULT_SUBSCRIPTION_ID", "")
        client = AuthorizationManagementClient(credential, subscription_id)
        client.role_assignments.delete_by_id(role_assignment_id=assignment_id)

    def _scope_for(self, *, scope_type: str, subscription_id: str) -> str:
        if scope_type == "subscription":
            return f"/subscriptions/{subscription_id}"
        if scope_type == "management_group":
            return f"/providers/Microsoft.Management/managementGroups/{self.management_group_id}"
        if scope_type == "resource_group":
            # The runner enumerates resource groups in scope and re-calls;
            # for the SDK list call we use the subscription scope and filter
            # by principalId. The scope on each returned assignment carries
            # the resource-group path.
            return f"/subscriptions/{subscription_id}"
        raise ValueError(f"Unknown scope_type `{scope_type}`")

    # ── Microsoft Graph plumbing ──────────────────────────────────────────
    def _graph_request(self, method: str, path: str, *, body: dict[str, Any] | None = None) -> None:
        import http.client
        from urllib import parse as urllib_parse

        from azure.identity import ClientSecretCredential

        credential = ClientSecretCredential(
            tenant_id=self.tenant_id, client_id=self.client_id, client_secret=self.client_secret
        )
        token = credential.get_token("https://graph.microsoft.com/.default").token
        url = f"https://graph.microsoft.com{path}"
        parsed = urllib_parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com":
            raise RuntimeError(f"refusing non-Microsoft Graph URL `{url}`")
        headers = {"Authorization": f"Bearer {token}"}
        body_bytes = None
        if body is not None:
            body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request_path = parsed.path or "/"
        if parsed.query:
            request_path = f"{request_path}?{parsed.query}"
        connection = http.client.HTTPSConnection(parsed.netloc)
        try:
            connection.request(method.upper(), request_path, body=body_bytes, headers=headers)
            response = connection.getresponse()
            payload = response.read()
        finally:
            connection.close()
        if response.status >= 400 and response.status != 404:
            raise RuntimeError(
                f"Microsoft Graph {response.status}: {payload.decode('utf-8', errors='replace') or response.reason}"
            )

    def _graph_collection(self, path: str) -> list[dict[str, Any]]:
        import http.client
        from urllib import parse as urllib_parse

        from azure.identity import ClientSecretCredential

        credential = ClientSecretCredential(
            tenant_id=self.tenant_id, client_id=self.client_id, client_secret=self.client_secret
        )
        token = credential.get_token("https://graph.microsoft.com/.default").token
        url = f"https://graph.microsoft.com{path}"
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        while next_url:
            parsed = urllib_parse.urlsplit(next_url)
            request_path = parsed.path or "/"
            if parsed.query:
                request_path = f"{request_path}?{parsed.query}"
            connection = http.client.HTTPSConnection(parsed.netloc)
            try:
                connection.request(
                    "GET", request_path, headers={"Authorization": f"Bearer {token}"}
                )
                response = connection.getresponse()
                payload = response.read()
            finally:
                connection.close()
            if response.status >= 400:
                raise RuntimeError(
                    f"Microsoft Graph {response.status}: {payload.decode('utf-8', errors='replace') or response.reason}"
                )
            data = json.loads(payload) if payload else {}
            value = data.get("value", []) if isinstance(data, dict) else []
            items.extend(item for item in value if isinstance(item, dict))
            raw_next = data.get("@odata.nextLink") if isinstance(data, dict) else None
            next_url = str(raw_next) if raw_next else None
        return items


# ── Orchestrator ───────────────────────────────────────────────────────────


@dataclasses.dataclass
class WorkerConfig:
    apply: bool = False
    reverify: bool = False
    hard_delete: bool = False
    dry_run: bool = True

    @classmethod
    def from_args(cls, *, apply: bool, reverify: bool, hard_delete: bool) -> "WorkerConfig":
        return cls(
            apply=apply, reverify=reverify, hard_delete=hard_delete, dry_run=not (apply or reverify)
        )


def remediate_one(
    entry: dict[str, Any],
    *,
    config: WorkerConfig,
    client: Any,
    audit: DualAuditWriter | None,
    incident_id: str,
    approver: str,
    extra_protected_object_ids: Iterable[str] = (),
    tenant_id: str = "",
) -> dict[str, Any]:
    """Run the eleven-step pipeline for a single validated entry.

    Returns a result envelope describing the outcome (status + actions
    taken). Failures are caught here; the next entry in the batch still
    runs.
    """
    upn = str(entry.get("upn") or "")
    object_id = str(entry.get("object_id") or "")
    tenant_id = tenant_id or str(entry.get("tenant_id") or "")
    actions: list[dict[str, Any]] = []

    # Validate the shape one more time as a defense-in-depth gate; the
    # parser is the primary check.
    if not upn or not object_id or not ENTRA_OBJECT_ID_RE.fullmatch(object_id):
        return _error_result(
            entry, status="error", error="Invalid entry: upn / object_id missing or malformed"
        )

    protected, why = is_protected_user(
        upn=upn, object_id=object_id, extra_object_ids=extra_protected_object_ids
    )
    if protected:
        msg = f"refusing protected principal `{upn}` ({object_id}): {why}"
        logger.warning(msg)
        return _error_result(entry, status="refused", error=msg, actions=actions)

    if config.dry_run:
        planned = [name for name, _ in remediation_steps(hard_delete=config.hard_delete)]
        return {
            "upn": upn,
            "object_id": object_id,
            "status": "planned",
            "would_take_steps": planned,
            "hard_delete": config.hard_delete,
            "dry_run": True,
        }

    if config.reverify:
        return _reverify_one(entry, client=client)

    if audit is None:
        return _error_result(entry, status="error", error="audit writer required for --apply")

    # ── --apply path ──────────────────────────────────────────────────────
    completed: list[str] = []
    for step_name, step_fn in remediation_steps(hard_delete=config.hard_delete):
        # BEFORE write
        audit.record(
            upn=upn,
            object_id=object_id,
            tenant_id=tenant_id,
            step=step_name,
            status="in_progress",
            detail=f"about to run step `{step_name}`",
            incident_id=incident_id,
            approver=approver,
            actions_so_far=actions,
        )
        try:
            step_fn(client, object_id, entry, actions)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Step %s failed for %s", step_name, object_id)
            audit.record(
                upn=upn,
                object_id=object_id,
                tenant_id=tenant_id,
                step=step_name,
                status="failure",
                detail=str(exc),
                incident_id=incident_id,
                approver=approver,
                actions_so_far=actions,
            )
            return {
                "upn": upn,
                "object_id": object_id,
                "tenant_id": tenant_id,
                "status": "error",
                "error": str(exc),
                "completed_steps": completed,
                "actions_taken": actions,
                "dry_run": False,
            }
        completed.append(step_name)
        audit.record(
            upn=upn,
            object_id=object_id,
            tenant_id=tenant_id,
            step=step_name,
            status="success",
            detail=f"completed step `{step_name}`",
            incident_id=incident_id,
            approver=approver,
            actions_so_far=actions,
        )

    return {
        "upn": upn,
        "object_id": object_id,
        "tenant_id": tenant_id,
        "status": "remediated",
        "completed_steps": completed,
        "expected_steps": list(STEP_NAMES),
        "actions_taken": actions,
        "remediated_at": _now(),
        "hard_delete": config.hard_delete,
        "dry_run": False,
    }


def _reverify_one(entry: dict[str, Any], *, client: Any) -> dict[str, Any]:
    upn = str(entry.get("upn") or "")
    object_id = str(entry.get("object_id") or "")
    try:
        # Two acceptable terminal states: user gone (hard-deleted) OR user disabled.
        present = (
            client.user_exists(object_id=object_id) if hasattr(client, "user_exists") else None
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "upn": upn,
            "object_id": object_id,
            "status": "unreachable",
            "expected_state": "accountEnabled=false (or user absent)",
            "actual_state": f"microsoft graph raised: {exc}",
        }
    if present is False:
        return {
            "upn": upn,
            "object_id": object_id,
            "status": "verified",
            "expected_state": "accountEnabled=false (or user absent)",
            "actual_state": "user not found (hard-deleted) — stronger than disabled",
        }
    try:
        state = client.get_user_state(object_id=object_id)
    except Exception as exc:  # noqa: BLE001
        return {
            "upn": upn,
            "object_id": object_id,
            "status": "unreachable",
            "expected_state": "accountEnabled=false (or user absent)",
            "actual_state": f"microsoft graph raised: {exc}",
        }
    if state.get("accountEnabled") is False:
        return {
            "upn": upn,
            "object_id": object_id,
            "status": "verified",
            "expected_state": "accountEnabled=false (or user absent)",
            "actual_state": "accountEnabled=false",
        }
    return {
        "upn": upn,
        "object_id": object_id,
        "status": "drift",
        "expected_state": "accountEnabled=false (or user absent)",
        "actual_state": f"accountEnabled={state.get('accountEnabled')!r} — user re-enabled after remediation",
    }


def _error_result(
    entry: dict[str, Any],
    *,
    status: str,
    error: str,
    actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "upn": entry.get("upn", ""),
        "object_id": entry.get("object_id", ""),
        "status": status,
        "error": error,
        "actions_taken": actions or [],
        "dry_run": True,
    }


# ── Helpers ────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"entradep-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _safe_path_component(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (value or "_"))
    return safe[:120] or "_"


# ── Logic App task entrypoint ──────────────────────────────────────────────


def handler(event: dict[str, Any], context: Any | None = None) -> dict[str, Any]:
    """Logic App map-step task: remediate a single Entra user."""
    entry = event.get("entry", event) if isinstance(event, dict) else {}
    if not isinstance(entry, dict):
        entry = {}

    apply_flag = bool(event.get("apply", True)) if isinstance(event, dict) else True
    reverify_flag = bool(event.get("reverify", False)) if isinstance(event, dict) else False
    hard_delete_flag = bool(event.get("hard_delete", False)) if isinstance(event, dict) else False

    config = WorkerConfig.from_args(
        apply=apply_flag, reverify=reverify_flag, hard_delete=hard_delete_flag
    )
    incident_id = os.environ.get("IAM_DEPARTURES_AZURE_INCIDENT_ID", "").strip()
    approver = os.environ.get("IAM_DEPARTURES_AZURE_APPROVER", "").strip()
    if config.apply:
        ok, reason = check_apply_gate()
        if not ok:
            return _error_result(entry, status="error", error=reason)

    client = _build_runtime_client()
    audit = _build_runtime_audit() if config.apply else None
    return remediate_one(
        entry,
        config=config,
        client=client,
        audit=audit,
        incident_id=incident_id,
        approver=approver,
        extra_protected_object_ids=load_extra_protected_object_ids(),
    )


def _build_runtime_client() -> Any:
    return EntraRemediationClient(
        tenant_id=os.environ.get("AZURE_TENANT_ID", ""),
        client_id=os.environ.get("AZURE_CLIENT_ID", ""),
        client_secret=os.environ.get("AZURE_CLIENT_SECRET", ""),
        management_group_id=os.environ.get("IAM_DEPARTURES_AZURE_MANAGEMENT_GROUP_ID", ""),
    )


def _build_runtime_audit() -> DualAuditWriter:
    return DualAuditWriter(
        cosmos_account=os.environ["IAM_DEPARTURES_AZURE_AUDIT_COSMOS_ACCOUNT"],
        cosmos_database=os.environ["IAM_DEPARTURES_AZURE_AUDIT_COSMOS_DATABASE"],
        cosmos_container=os.environ["IAM_DEPARTURES_AZURE_AUDIT_COSMOS_CONTAINER"],
        blob_account=os.environ["IAM_DEPARTURES_AZURE_AUDIT_BLOB_ACCOUNT"],
        blob_container=os.environ["IAM_DEPARTURES_AZURE_AUDIT_BLOB_CONTAINER"],
        key_vault_key_id=os.environ["IAM_DEPARTURES_AZURE_KEY_VAULT_KEY_ID"],
    )


# ── CLI ────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: dry-run / --apply / --reverify against a local manifest.

    The CLI iterates over the manifest's `entries[]` (no parser pre-filter
    here — that's the parser Function's job; the CLI is a quick way for
    operators and CI to exercise the worker). For --apply, both HITL env
    vars must be set or the CLI returns 2 without firing anything.
    """
    parser = argparse.ArgumentParser(
        description="Run the Entra IAM departures worker against a manifest file."
    )
    parser.add_argument(
        "manifest", help="Path to a manifest JSON file (see examples/manifest.json)."
    )
    parser.add_argument(
        "--apply", action="store_true", help="Run the destructive teardown after HITL gates pass."
    )
    parser.add_argument(
        "--reverify", action="store_true", help="Read-only verification (no writes)."
    )
    parser.add_argument(
        "--hard-delete",
        action="store_true",
        help="With --apply, replace soft-delete with DELETE /users/{id}. Opt-in only.",
    )
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2
    if args.hard_delete and not args.apply:
        print("--hard-delete is only valid with --apply", file=sys.stderr)
        return 2

    config = WorkerConfig.from_args(
        apply=args.apply, reverify=args.reverify, hard_delete=args.hard_delete
    )
    incident_id = ""
    approver = ""
    audit: DualAuditWriter | None = None
    client: Any = _CliDryRunClient()

    if config.apply:
        ok, reason = check_apply_gate()
        if not ok:
            print(reason, file=sys.stderr)
            return 2
        incident_id = os.environ["IAM_DEPARTURES_AZURE_INCIDENT_ID"].strip()
        approver = os.environ["IAM_DEPARTURES_AZURE_APPROVER"].strip()
        audit = _build_runtime_audit()
        client = _build_runtime_client()
    elif config.reverify:
        client = _build_runtime_client()

    with open(args.manifest, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    entries = manifest.get("entries", [])

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        for entry in entries:
            result = remediate_one(
                entry,
                config=config,
                client=client,
                audit=audit,
                incident_id=incident_id,
                approver=approver,
                extra_protected_object_ids=load_extra_protected_object_ids(),
                tenant_id=str(manifest.get("tenant_id") or entry.get("tenant_id") or ""),
            )
            out.write(json.dumps(result, separators=(",", ":")) + "\n")
    finally:
        if args.output:
            out.close()
    return 0


class _CliDryRunClient:
    """Stub Microsoft Graph client used in dry-run CLI mode.

    Returns deterministic empty answers so the CLI can run without Azure
    credentials. Operators get a reliable plan view without any side
    effects, which is exactly what dry-run is for.
    """

    def user_exists(self, *, object_id: str) -> bool:  # noqa: ARG002
        return True

    def get_user_state(self, *, object_id: str) -> dict[str, Any]:  # noqa: ARG002
        return {"accountEnabled": False}


if __name__ == "__main__":
    raise SystemExit(main())
