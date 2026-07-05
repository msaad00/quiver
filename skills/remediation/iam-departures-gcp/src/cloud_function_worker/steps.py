"""GCP IAM teardown — the 11 step functions executed in strict order.

Each step takes a `GcpClients` bundle, the entry payload, and an `actions`
list it appends a structured action record to. Steps are idempotent: if the
target binding / token / key has already been removed, the step exits clean
and records a no-op. The Worker handler's checkpoint loop skips any step
already marked complete on a previous Workflow attempt.

Steps are deliberately small and individually unit-testable. The real Cloud
SDK calls go through `googleapiclient.discovery.build`, lazy-imported from
`GcpClients` so tests can substitute a mocked module via
`unittest.mock.patch.dict(sys.modules, ...)`.

Order matters — a Workspace user cannot be deleted while the SSH key
metadata or IAM bindings still reference them. The 11-step ordering matches
SKILL.md's "GCP IAM teardown order" table.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Mirrored from infra/iam_policies/cross_project_role.yaml — keep in sync.
PROTECTED_USER_PATTERNS: tuple[str, ...] = (
    "super-admin*",
    "break-glass-*",
    "emergency-*",
)
PROTECTED_SA_PATTERNS: tuple[str, ...] = (
    "terraform-*",
    "cd-*",
    "org-admin-*",
)


class ProtectedPrincipalError(ValueError):
    """Raised when a remediation target matches the protected-principal deny list."""


def is_protected_principal(principal_type: str, principal_id: str) -> bool:
    """True if the principal matches the protected deny list.

    Matches the local part of the email (Workspace user) or the SA name
    (`<name>@<project>.iam.gserviceaccount.com`).
    """
    local_part = principal_id.split("@", 1)[0].lower()
    patterns: tuple[str, ...]
    if principal_type == "service_account":
        patterns = PROTECTED_SA_PATTERNS
    else:
        patterns = PROTECTED_USER_PATTERNS
    return any(fnmatch.fnmatchcase(local_part, pattern.lower()) for pattern in patterns)


def assert_not_protected(principal_type: str, principal_id: str) -> None:
    if is_protected_principal(principal_type, principal_id):
        raise ProtectedPrincipalError(
            f"refusing to remediate protected principal `{principal_id}` "
            f"(type={principal_type}) — matches one of "
            f"{PROTECTED_USER_PATTERNS + PROTECTED_SA_PATTERNS}. "
            "This list is mirrored from infra/iam_policies/cross_project_role.yaml."
        )


@dataclasses.dataclass
class GcpClients:
    """Lazy holder for googleapiclient.discovery.build clients.

    Cached per worker invocation. Each property triggers a single
    `discovery.build` call the first time it's accessed.
    """

    _admin_directory: Any | None = None
    _cloud_identity: Any | None = None
    _crm: Any | None = None
    _iam: Any | None = None
    _compute: Any | None = None
    _bigquery: Any | None = None
    _storage: Any | None = None
    _logging: Any | None = None

    def _build(self, api: str, version: str) -> Any:
        from googleapiclient.discovery import build  # noqa: PLC0415

        return build(api, version, cache_discovery=False)

    @property
    def admin_directory(self) -> Any:
        if self._admin_directory is None:
            self._admin_directory = self._build("admin", "directory_v1")
        return self._admin_directory

    @property
    def cloud_identity(self) -> Any:
        if self._cloud_identity is None:
            self._cloud_identity = self._build("cloudidentity", "v1")
        return self._cloud_identity

    @property
    def crm(self) -> Any:
        if self._crm is None:
            self._crm = self._build("cloudresourcemanager", "v3")
        return self._crm

    @property
    def iam(self) -> Any:
        if self._iam is None:
            self._iam = self._build("iam", "v1")
        return self._iam

    @property
    def compute(self) -> Any:
        if self._compute is None:
            self._compute = self._build("compute", "v1")
        return self._compute

    @property
    def bigquery(self) -> Any:
        if self._bigquery is None:
            self._bigquery = self._build("bigquery", "v2")
        return self._bigquery

    @property
    def storage(self) -> Any:
        if self._storage is None:
            self._storage = self._build("storage", "v1")
        return self._storage

    @property
    def logging(self) -> Any:
        if self._logging is None:
            self._logging = self._build("logging", "v2")
        return self._logging


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _principal_member(principal_type: str, principal_id: str) -> str:
    """Return the IAM `member:` string used in policy bindings."""
    if principal_type == "service_account":
        return f"serviceAccount:{principal_id}"
    return f"user:{principal_id}"


# ── Step 1: pre-disable the principal ───────────────────────────────


def step_pre_disable(clients: GcpClients, entry: dict, actions: list) -> None:
    """Workspace user → set `suspended: true`. SA → call `serviceAccounts.disable`."""
    principal_id = entry["principal_id"]
    principal_type = entry["principal_type"]
    if principal_type == "workspace_user":
        clients.admin_directory.users().update(
            userKey=principal_id, body={"suspended": True}
        ).execute()
        actions.append(
            {"action": "suspend_workspace_user", "target": principal_id, "timestamp": _now()}
        )
        return

    project_id = entry.get("project_ids", [None])[0] or principal_id.split("@")[1].split(".")[0]
    name = f"projects/{project_id}/serviceAccounts/{principal_id}"
    clients.iam.projects().serviceAccounts().disable(name=name).execute()
    actions.append(
        {"action": "disable_service_account", "target": principal_id, "timestamp": _now()}
    )


# ── Step 2: revoke OAuth refresh tokens ─────────────────────────────


def step_revoke_oauth_tokens(clients: GcpClients, entry: dict, actions: list) -> None:
    if entry["principal_type"] != "workspace_user":
        actions.append(
            {
                "action": "revoke_oauth_tokens",
                "target": entry["principal_id"],
                "timestamp": _now(),
                "skipped": "n/a-for-service-account",
            }
        )
        return

    user = entry["principal_id"]
    response = clients.admin_directory.tokens().list(userKey=user).execute() or {}
    tokens = response.get("items", []) or []
    revoked = 0
    for token in tokens:
        client_id = token.get("clientId")
        if not client_id:
            continue
        clients.admin_directory.tokens().delete(userKey=user, clientId=client_id).execute()
        revoked += 1
    actions.append(
        {"action": "revoke_oauth_tokens", "target": user, "count": revoked, "timestamp": _now()}
    )


# ── Step 3: delete SSH keys (project + per-instance metadata) ───────


def step_delete_ssh_keys(clients: GcpClients, entry: dict, actions: list) -> None:
    user = entry["principal_id"]
    user_local = user.split("@", 1)[0].lower()
    removed_total = 0
    for project_id in entry.get("project_ids", []) or []:
        project = clients.compute.projects().get(project=project_id).execute() or {}
        common = (project.get("commonInstanceMetadata") or {}).get("items") or []
        new_items = []
        changed = False
        for item in common:
            if item.get("key") != "ssh-keys":
                new_items.append(item)
                continue
            keep_lines: list[str] = []
            for line in (item.get("value") or "").splitlines():
                # Format: `<google-username>:ssh-rsa AAAA... <comment>`
                if ":" not in line:
                    keep_lines.append(line)
                    continue
                gu = line.split(":", 1)[0].strip().lower()
                if gu == user_local:
                    removed_total += 1
                    changed = True
                    continue
                keep_lines.append(line)
            new_items.append({"key": "ssh-keys", "value": "\n".join(keep_lines)})
        if changed:
            clients.compute.projects().setCommonInstanceMetadata(
                project=project_id,
                body={
                    "fingerprint": (project.get("commonInstanceMetadata") or {}).get("fingerprint"),
                    "items": new_items,
                },
            ).execute()
    actions.append(
        {"action": "delete_ssh_keys", "target": user, "count": removed_total, "timestamp": _now()}
    )


# ── Step 4: remove user from Cloud Identity / Workspace groups ──────


def step_remove_from_groups(clients: GcpClients, entry: dict, actions: list) -> None:
    if entry["principal_type"] != "workspace_user":
        actions.append(
            {
                "action": "remove_from_groups",
                "target": entry["principal_id"],
                "timestamp": _now(),
                "skipped": "n/a-for-service-account",
            }
        )
        return

    user = entry["principal_id"]
    parent_query = f"member_key_id == '{user}' && 'cloudidentity.googleapis.com/groups.discussion_forum' in labels"
    response = (
        clients.cloud_identity.groups()
        .memberships()
        .searchTransitiveMemberships(parent="groups/-", query=parent_query)
        .execute()
        if hasattr(clients.cloud_identity.groups().memberships(), "searchTransitiveMemberships")
        else {}
    )
    memberships = response.get("memberships", []) or []
    removed = 0
    for member in memberships:
        member_name = member.get("relationType") and member.get("memberKey", {}).get("id")
        # The membership resource name comes back as `groups/{group_id}/memberships/{membership_id}`.
        name = member.get("name")
        if not name:
            continue
        clients.cloud_identity.groups().memberships().delete(name=name).execute()
        removed += 1
        _ = member_name  # kept for log readability
    actions.append(
        {"action": "remove_from_groups", "target": user, "count": removed, "timestamp": _now()}
    )


# ── Step 5: detach project-level IAM bindings ───────────────────────


def _strip_member_from_policy(policy: dict, member: str) -> tuple[dict, int]:
    bindings = policy.get("bindings", []) or []
    removed = 0
    new_bindings = []
    for binding in bindings:
        members = list(binding.get("members") or [])
        if member in members:
            members.remove(member)
            removed += 1
        if members:
            new_bindings.append({**binding, "members": members})
    return {**policy, "bindings": new_bindings}, removed


def step_detach_project_iam(clients: GcpClients, entry: dict, actions: list) -> None:
    member = _principal_member(entry["principal_type"], entry["principal_id"])
    total = 0
    for project_id in entry.get("project_ids", []) or []:
        resource = f"projects/{project_id}"
        policy = clients.crm.projects().getIamPolicy(resource=resource, body={}).execute() or {}
        new_policy, removed = _strip_member_from_policy(policy, member)
        if removed:
            clients.crm.projects().setIamPolicy(
                resource=resource, body={"policy": new_policy}
            ).execute()
            total += removed
    actions.append(
        {"action": "detach_project_iam", "target": member, "count": total, "timestamp": _now()}
    )


# ── Step 6: detach folder-level IAM bindings ────────────────────────


def step_detach_folder_iam(clients: GcpClients, entry: dict, actions: list) -> None:
    member = _principal_member(entry["principal_type"], entry["principal_id"])
    total = 0
    for folder_id in entry.get("folder_ids", []) or []:
        resource = folder_id if folder_id.startswith("folders/") else f"folders/{folder_id}"
        policy = clients.crm.folders().getIamPolicy(resource=resource, body={}).execute() or {}
        new_policy, removed = _strip_member_from_policy(policy, member)
        if removed:
            clients.crm.folders().setIamPolicy(
                resource=resource, body={"policy": new_policy}
            ).execute()
            total += removed
    actions.append(
        {"action": "detach_folder_iam", "target": member, "count": total, "timestamp": _now()}
    )


# ── Step 7: detach org-level IAM bindings ───────────────────────────


def step_detach_org_iam(clients: GcpClients, entry: dict, actions: list) -> None:
    member = _principal_member(entry["principal_type"], entry["principal_id"])
    org_id = entry["gcp_org_id"]
    resource = f"organizations/{org_id}"
    policy = clients.crm.organizations().getIamPolicy(resource=resource, body={}).execute() or {}
    new_policy, removed = _strip_member_from_policy(policy, member)
    if removed:
        clients.crm.organizations().setIamPolicy(
            resource=resource, body={"policy": new_policy}
        ).execute()
    actions.append(
        {"action": "detach_org_iam", "target": member, "count": removed, "timestamp": _now()}
    )


# ── Step 8: detach BigQuery dataset-level IAM ───────────────────────


def step_detach_bigquery_iam(clients: GcpClients, entry: dict, actions: list) -> None:
    member = _principal_member(entry["principal_type"], entry["principal_id"])
    member_local = entry["principal_id"]
    total_datasets = 0
    total_grants = 0
    for project_id in entry.get("project_ids", []) or []:
        datasets_resp = clients.bigquery.datasets().list(projectId=project_id).execute() or {}
        for ds in datasets_resp.get("datasets", []) or []:
            dataset_id = ds.get("datasetReference", {}).get("datasetId")
            if not dataset_id:
                continue
            full = (
                clients.bigquery.datasets()
                .get(projectId=project_id, datasetId=dataset_id)
                .execute()
                or {}
            )
            access = full.get("access", []) or []
            new_access = []
            removed_here = 0
            for entry_acl in access:
                # BigQuery dataset access uses userByEmail / groupByEmail / iamMember
                if (
                    entry_acl.get("userByEmail") == member_local
                    or entry_acl.get("groupByEmail") == member_local
                    or entry_acl.get("iamMember") == member
                ):
                    removed_here += 1
                    continue
                new_access.append(entry_acl)
            if removed_here:
                clients.bigquery.datasets().patch(
                    projectId=project_id,
                    datasetId=dataset_id,
                    body={"access": new_access},
                ).execute()
                total_datasets += 1
                total_grants += removed_here
    actions.append(
        {
            "action": "detach_bigquery_iam",
            "target": member_local,
            "datasets": total_datasets,
            "grants": total_grants,
            "timestamp": _now(),
        }
    )


# ── Step 9: revoke Cloud Storage bucket-level IAM ───────────────────


def step_revoke_storage_iam(clients: GcpClients, entry: dict, actions: list) -> None:
    member = _principal_member(entry["principal_type"], entry["principal_id"])
    total_buckets = 0
    total_grants = 0
    for project_id in entry.get("project_ids", []) or []:
        listing = clients.storage.buckets().list(project=project_id).execute() or {}
        for bucket in listing.get("items", []) or []:
            name = bucket.get("name")
            if not name:
                continue
            policy = clients.storage.buckets().getIamPolicy(bucket=name).execute() or {}
            new_policy, removed = _strip_member_from_policy(policy, member)
            if removed:
                clients.storage.buckets().setIamPolicy(bucket=name, body=new_policy).execute()
                total_buckets += 1
                total_grants += removed
    actions.append(
        {
            "action": "revoke_storage_iam",
            "target": member,
            "buckets": total_buckets,
            "grants": total_grants,
            "timestamp": _now(),
        }
    )


# ── Step 10: tag the action via Cloud Audit Logs entry ──────────────


def step_emit_audit_log(clients: GcpClients, entry: dict, actions: list) -> None:
    """Write a structured Cloud Logging entry so the action is preserved
    after the principal is deleted. The entry land in the operator's
    `iam-departures-gcp-audit` log name."""
    log_name = f"projects/{entry.get('project_ids', ['unknown'])[0]}/logs/iam-departures-gcp-audit"
    body = {
        "entries": [
            {
                "logName": log_name,
                "resource": {"type": "global"},
                "severity": "NOTICE",
                "jsonPayload": {
                    "action": "iam-departures-gcp/remediation",
                    "principal_id": entry["principal_id"],
                    "principal_type": entry["principal_type"],
                    "gcp_org_id": entry["gcp_org_id"],
                    "terminated_at": entry.get("terminated_at"),
                    "termination_source": entry.get("termination_source"),
                    "timestamp": _now(),
                },
            }
        ]
    }
    clients.logging.entries().write(body=body).execute()
    actions.append(
        {"action": "emit_audit_log", "target": entry["principal_id"], "timestamp": _now()}
    )


# ── Step 11: final disable / delete ─────────────────────────────────


def step_final_disable_or_delete(clients: GcpClients, entry: dict, actions: list) -> None:
    principal_id = entry["principal_id"]
    if entry["principal_type"] == "workspace_user":
        # 20-day soft delete window
        clients.admin_directory.users().delete(userKey=principal_id).execute()
        actions.append(
            {"action": "delete_workspace_user", "target": principal_id, "timestamp": _now()}
        )
        return

    project_id = entry.get("project_ids", [None])[0] or principal_id.split("@")[1].split(".")[0]
    name = f"projects/{project_id}/serviceAccounts/{principal_id}"
    # Delete user-managed keys first — system-managed cannot be deleted
    response = clients.iam.projects().serviceAccounts().keys().list(name=name).execute() or {}
    for key in response.get("keys", []) or []:
        if key.get("keyType") == "SYSTEM_MANAGED":
            continue
        clients.iam.projects().serviceAccounts().keys().delete(name=key["name"]).execute()
    # 30-day soft delete window
    clients.iam.projects().serviceAccounts().delete(name=name).execute()
    actions.append(
        {"action": "delete_service_account", "target": principal_id, "timestamp": _now()}
    )


# ── Public step registry ────────────────────────────────────────────


STEP_REGISTRY: tuple[tuple[str, Any], ...] = (
    ("pre_disable", step_pre_disable),
    ("revoke_oauth_tokens", step_revoke_oauth_tokens),
    ("delete_ssh_keys", step_delete_ssh_keys),
    ("remove_from_groups", step_remove_from_groups),
    ("detach_project_iam", step_detach_project_iam),
    ("detach_folder_iam", step_detach_folder_iam),
    ("detach_org_iam", step_detach_org_iam),
    ("detach_bigquery_iam", step_detach_bigquery_iam),
    ("revoke_storage_iam", step_revoke_storage_iam),
    ("emit_audit_log", step_emit_audit_log),
    ("final_disable_or_delete", step_final_disable_or_delete),
)


def remediation_steps() -> tuple[tuple[str, Any], ...]:
    """Return the immutable 11-step ordering. Mirrored in SKILL.md."""
    return STEP_REGISTRY
