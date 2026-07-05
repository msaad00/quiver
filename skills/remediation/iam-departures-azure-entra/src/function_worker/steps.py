"""The eleven Entra IAM teardown steps.

Kept in a separate module from `handler.py` so each step can be unit-tested
in isolation against a stubbed Microsoft Graph + Azure RBAC client. Every
step has the same signature:

    step(graph_or_rbac_client, object_id, entry, actions) -> None

It must:
- only call read + delete + patch APIs documented in REFERENCES.md
- append one or more {"action": ..., "target": ..., "timestamp": ...}
  records to `actions` for the audit row
- raise on hard failure; the orchestrator catches and writes the failure audit

Step list (mirror of the AWS sibling's 11 worker functions):

    1. disable_user                    PATCH /users/{id} accountEnabled=false
    2. revoke_signin_sessions          POST /users/{id}/revokeSignInSessions
    3. delete_oauth2_grants            DELETE /oauth2PermissionGrants/{id} per grant
    4. remove_from_groups              DELETE /groups/{id}/members/{userId}/$ref
    5. remove_directory_role_memberships
    6. delete_app_role_assignments     DELETE /users/{id}/appRoleAssignments/{id}
    7. detach_subscription_role_assignments
    8. detach_managementgroup_and_resourcegroup_role_assignments
    9. detach_assigned_licenses        POST /users/{id}/assignLicense removeLicenses
    10. tag_user_for_audit             PATCH /users/{id} extension property
    11. final_delete_user              soft-delete (default) or hard-delete (opt-in)

The function `remediation_steps()` returns the ordered tuple the orchestrator
loops over.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

# Public so handler.py can also reference for the audit "completed_steps" list.
STEP_NAMES: tuple[str, ...] = (
    "disable_user",
    "revoke_signin_sessions",
    "delete_oauth2_grants",
    "remove_from_groups",
    "remove_directory_role_memberships",
    "delete_app_role_assignments",
    "detach_subscription_role_assignments",
    "detach_managementgroup_and_resourcegroup_role_assignments",
    "detach_assigned_licenses",
    "tag_user_for_audit",
    "final_delete_user",
)


StepFn = Callable[[Any, str, dict[str, Any], list[dict[str, Any]]], None]


def remediation_steps(*, hard_delete: bool) -> tuple[tuple[str, StepFn], ...]:
    """Return the ordered (name, callable) tuple. `hard_delete` rewires step 11."""
    final_step: StepFn = _final_delete_user_hard if hard_delete else _final_delete_user_soft
    return (
        ("disable_user", _disable_user),
        ("revoke_signin_sessions", _revoke_signin_sessions),
        ("delete_oauth2_grants", _delete_oauth2_grants),
        ("remove_from_groups", _remove_from_groups),
        ("remove_directory_role_memberships", _remove_directory_role_memberships),
        ("delete_app_role_assignments", _delete_app_role_assignments),
        ("detach_subscription_role_assignments", _detach_subscription_role_assignments),
        (
            "detach_managementgroup_and_resourcegroup_role_assignments",
            _detach_managementgroup_and_resourcegroup_role_assignments,
        ),
        ("detach_assigned_licenses", _detach_assigned_licenses),
        ("tag_user_for_audit", _tag_user_for_audit),
        ("final_delete_user", final_step),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record(actions: list[dict[str, Any]], *, action: str, target: str, **extra: Any) -> None:
    actions.append({"action": action, "target": target, "timestamp": _now(), **extra})


# ── Step 1 ─────────────────────────────────────────────────────────────────


def _disable_user(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """PATCH /users/{id} {"accountEnabled": false}."""
    client.disable_user(object_id=object_id)
    _record(actions, action="disable_user", target=object_id)


# ── Step 2 ─────────────────────────────────────────────────────────────────


def _revoke_signin_sessions(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """POST /users/{id}/revokeSignInSessions."""
    client.revoke_signin_sessions(object_id=object_id)
    _record(actions, action="revoke_signin_sessions", target=object_id)


# ── Step 3 ─────────────────────────────────────────────────────────────────


def _delete_oauth2_grants(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """DELETE /oauth2PermissionGrants/{id} for each grant whose principalId == userId."""
    for grant in client.list_oauth2_permission_grants(principal_id=object_id):
        grant_id = str(grant.get("id") or "")
        if not grant_id:
            continue
        client.delete_oauth2_permission_grant(grant_id=grant_id)
        _record(actions, action="delete_oauth2_permission_grant", target=grant_id)


# ── Step 4 ─────────────────────────────────────────────────────────────────


def _remove_from_groups(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """DELETE /groups/{id}/members/{userId}/$ref for every group the user is in."""
    for group in client.list_user_groups(object_id=object_id):
        group_id = str(group.get("id") or "")
        if not group_id:
            continue
        client.remove_group_member(group_id=group_id, user_id=object_id)
        _record(actions, action="remove_from_group", target=group_id)


# ── Step 5 ─────────────────────────────────────────────────────────────────


def _remove_directory_role_memberships(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """DELETE /directoryRoles/{id}/members/{userId}/$ref."""
    for role in client.list_user_directory_roles(object_id=object_id):
        role_id = str(role.get("id") or "")
        if not role_id:
            continue
        client.remove_directory_role_member(role_id=role_id, user_id=object_id)
        _record(actions, action="remove_directory_role_member", target=role_id)


# ── Step 6 ─────────────────────────────────────────────────────────────────


def _delete_app_role_assignments(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """DELETE /users/{id}/appRoleAssignments/{id}."""
    for assignment in client.list_user_app_role_assignments(object_id=object_id):
        assignment_id = str(assignment.get("id") or "")
        if not assignment_id:
            continue
        client.delete_user_app_role_assignment(user_id=object_id, assignment_id=assignment_id)
        _record(actions, action="delete_app_role_assignment", target=assignment_id)


# ── Step 7 ─────────────────────────────────────────────────────────────────


def _detach_subscription_role_assignments(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """DELETE /providers/Microsoft.Authorization/roleAssignments/{id} at subscription scope."""
    for assignment in client.list_role_assignments(
        scope_type="subscription", principal_id=object_id
    ):
        assignment_id = str(assignment.get("id") or "")
        scope = str(assignment.get("scope") or "")
        if not assignment_id:
            continue
        client.delete_role_assignment(assignment_id=assignment_id)
        _record(
            actions,
            action="detach_subscription_role_assignment",
            target=assignment_id,
            scope=scope,
        )


# ── Step 8 ─────────────────────────────────────────────────────────────────


def _detach_managementgroup_and_resourcegroup_role_assignments(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """Same API as step 7 but at management-group + resource-group scopes."""
    for scope_type in ("management_group", "resource_group"):
        for assignment in client.list_role_assignments(
            scope_type=scope_type, principal_id=object_id
        ):
            assignment_id = str(assignment.get("id") or "")
            scope = str(assignment.get("scope") or "")
            if not assignment_id:
                continue
            client.delete_role_assignment(assignment_id=assignment_id)
            _record(
                actions,
                action=f"detach_{scope_type}_role_assignment",
                target=assignment_id,
                scope=scope,
            )


# ── Step 9 ─────────────────────────────────────────────────────────────────


def _detach_assigned_licenses(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """POST /users/{id}/assignLicense with removeLicenses=[<sku-ids>]."""
    sku_ids = [
        str(lic.get("skuId") or "") for lic in client.list_user_licenses(object_id=object_id)
    ]
    sku_ids = [s for s in sku_ids if s]
    if not sku_ids:
        return
    client.remove_licenses(object_id=object_id, sku_ids=sku_ids)
    _record(actions, action="remove_licenses", target=object_id, sku_ids=sku_ids)


# ── Step 10 ────────────────────────────────────────────────────────────────


def _tag_user_for_audit(
    client: Any, object_id: str, entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """PATCH /users/{id} setting `extension_audit_remediated_at` and supporting tags."""
    tags = {
        "extension_audit_remediated_at": _now(),
        "extension_audit_employee_upn": (entry.get("upn") or "")[:256],
        "extension_audit_terminated_at": (entry.get("terminated_at") or "")[:256],
        "extension_audit_termination_source": (entry.get("termination_source") or "")[:256],
    }
    client.tag_user(object_id=object_id, tags=tags)
    _record(actions, action="tag_user", target=object_id, tags=tags)


# ── Step 11 (two flavours) ─────────────────────────────────────────────────


def _final_delete_user_soft(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """Soft-delete: leave the user object so the next reconciler run can audit it.

    Step 1 already set accountEnabled=false; step 10 added the audit tag.
    The user is now soft-deleted in the operational sense (no auth, no
    sessions, no group/role memberships, no licenses). The hard
    DELETE /users/{id} call is opt-in via --hard-delete.
    """
    _record(actions, action="soft_delete_user", target=object_id, mode="soft")


def _final_delete_user_hard(
    client: Any, object_id: str, _entry: dict[str, Any], actions: list[dict[str, Any]]
) -> None:
    """Hard delete: DELETE /users/{id}. Opt-in only."""
    client.hard_delete_user(object_id=object_id)
    _record(actions, action="hard_delete_user", target=object_id, mode="hard")
