"""Azure Entra ID (Azure AD) identity remediation.

SDK: msgraph-sdk + azure-identity
API: Microsoft Graph v1.0

Deletion order (6 steps):
    1. Revoke all sign-in sessions (invalidates refresh tokens)
    2. Remove from all group memberships
    3. Remove app role assignments
    4. Revoke OAuth2 delegated permission grants
    5. Disable user (accountEnabled = false)
    6. Delete user (soft-deletes to recycle bin for 30 days)

Required Microsoft Graph API permissions (Application):
    - User.ReadWrite.All
    - GroupMember.ReadWrite.All
    - AppRoleAssignment.ReadWrite.All
    - DelegatedPermissionGrant.ReadWrite.All
    - Directory.Read.All

Required Entra ID role: User Administrator

GOTCHAS:
    - Soft delete: 30-day recycle bin. Use DELETE /directory/deletedItems/{id}
      for permanent deletion.
    - /$ref is CRITICAL: When removing group members, you MUST append /$ref to
      the URL. Without it, the entire user object gets deleted from Entra.
    - Privileged users: User.ReadWrite.All alone cannot delete users with
      privileged admin roles. The app must have a higher-privileged role.
    - Dynamic groups: Members of dynamic groups cannot be removed manually —
      they are governed by membership rules.
    - External/guest users: revokeSignInSessions does NOT work for guests
      (they sign in through their home tenant).
    - Token lag: After revokeSignInSessions, there may be a delay of a few
      minutes before tokens are actually invalid.

Env vars:
    AZURE_TENANT_ID
    AZURE_CLIENT_ID
    AZURE_CLIENT_SECRET
"""

from __future__ import annotations

import logging
import os

from . import CloudProvider, RemediationResult, RemediationStatus, RemediationStep

logger = logging.getLogger(__name__)


def get_required_permissions() -> list[str]:
    """Return the minimum Microsoft Graph API permissions needed."""
    return [
        "User.ReadWrite.All",
        "GroupMember.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "DelegatedPermissionGrant.ReadWrite.All",
        "Directory.Read.All",
    ]


def _get_graph_client():
    """Create an authenticated Microsoft Graph client.

    Uses ClientSecretCredential with AZURE_TENANT_ID, AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET from environment.
    """
    from azure.identity import ClientSecretCredential
    from msgraph import GraphServiceClient

    credential = ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )
    return GraphServiceClient(credential, scopes=["https://graph.microsoft.com/.default"])


async def remediate_user(
    user_id: str,
    tenant_id: str,
    *,
    dry_run: bool = False,
) -> RemediationResult:
    """Remediate an Azure Entra ID user (6-step process).

    Args:
        user_id: Entra ID user object ID or UPN (user@domain.com).
        tenant_id: Azure tenant ID.
        dry_run: If True, log actions without executing them.

    Returns:
        RemediationResult with per-step status.
    """
    result = RemediationResult(
        cloud=CloudProvider.AZURE,
        identity_id=user_id,
        identity_type="entra_user",
        account_id=tenant_id,
    )

    if dry_run:
        result.status = RemediationStatus.DRY_RUN
        for i, action in enumerate(_STEP_NAMES, 1):
            result.steps.append(
                RemediationStep(
                    step_number=i, action=action, target=user_id, status=RemediationStatus.DRY_RUN
                )
            )
        result.complete()
        return result

    try:
        client = _get_graph_client()
    except Exception as e:
        result.status = RemediationStatus.FAILED
        result.error = f"Failed to create Graph client: {e}"
        result.complete()
        return result

    # Step 1: Revoke sign-in sessions
    result.steps.append(await _revoke_sessions(client, user_id, step=1))

    # Step 2: Remove group memberships
    result.steps.append(await _remove_group_memberships(client, user_id, step=2))

    # Step 3: Remove app role assignments
    result.steps.append(await _remove_app_role_assignments(client, user_id, step=3))

    # Step 4: Revoke OAuth2 permission grants
    result.steps.append(await _revoke_oauth2_grants(client, user_id, step=4))

    # Step 5: Disable user
    result.steps.append(await _disable_user(client, user_id, step=5))

    # Step 6: Delete user
    result.steps.append(await _delete_user(client, user_id, step=6))

    result.complete()
    return result


_STEP_NAMES = [
    "revoke_sign_in_sessions",
    "remove_group_memberships",
    "remove_app_role_assignments",
    "revoke_oauth2_grants",
    "disable_user",
    "delete_user",
]


async def _revoke_sessions(client, user_id: str, step: int) -> RemediationStep:
    """POST /users/{id}/revokeSignInSessions — invalidates all refresh tokens."""
    try:
        await client.users.by_user_id(user_id).revoke_sign_in_sessions.post()
        return RemediationStep(
            step_number=step,
            action="revoke_sign_in_sessions",
            target=user_id,
            detail="All sessions revoked",
        )
    except Exception as e:
        logger.warning("Failed to revoke sessions for %s: %s", user_id, e)
        return RemediationStep(
            step_number=step,
            action="revoke_sign_in_sessions",
            target=user_id,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


async def _remove_group_memberships(client, user_id: str, step: int) -> RemediationStep:
    """GET /users/{id}/memberOf then DELETE /groups/{gid}/members/{uid}/$ref.

    CRITICAL: Must use /$ref endpoint. Without it, the entire user gets deleted.
    Dynamic group memberships are skipped (managed by rules, not direct removal).
    """
    try:
        memberships = await client.users.by_user_id(user_id).member_of.get()
        removed = 0
        skipped = 0
        for member in memberships.value or []:
            if member.odata_type == "#microsoft.graph.group":
                try:
                    # /$ref is critical — without it you delete the user, not the membership
                    await (
                        client.groups.by_group_id(member.id)
                        .members.by_directory_object_id(user_id)
                        .ref.delete()
                    )
                    removed += 1
                except Exception:
                    # Dynamic groups can't be manually modified
                    skipped += 1
        return RemediationStep(
            step_number=step,
            action="remove_group_memberships",
            target=user_id,
            detail=f"Removed from {removed} groups, skipped {skipped} (dynamic/protected)",
        )
    except Exception as e:
        logger.warning("Failed to remove group memberships for %s: %s", user_id, e)
        return RemediationStep(
            step_number=step,
            action="remove_group_memberships",
            target=user_id,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


async def _remove_app_role_assignments(client, user_id: str, step: int) -> RemediationStep:
    """DELETE /users/{id}/appRoleAssignments/{assignment_id}."""
    try:
        assignments = await client.users.by_user_id(user_id).app_role_assignments.get()
        removed = 0
        for assignment in assignments.value or []:
            await (
                client.users.by_user_id(user_id)
                .app_role_assignments.by_app_role_assignment_id(assignment.id)
                .delete()
            )
            removed += 1
        return RemediationStep(
            step_number=step,
            action="remove_app_role_assignments",
            target=user_id,
            detail=f"Removed {removed} app role assignments",
        )
    except Exception as e:
        logger.warning("Failed to remove app role assignments for %s: %s", user_id, e)
        return RemediationStep(
            step_number=step,
            action="remove_app_role_assignments",
            target=user_id,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


async def _revoke_oauth2_grants(client, user_id: str, step: int) -> RemediationStep:
    """DELETE /oauth2PermissionGrants/{id} for each grant to this user."""
    try:
        grants = await client.users.by_user_id(user_id).oauth2_permission_grants.get()
        revoked = 0
        for grant in grants.value or []:
            await client.oauth2_permission_grants.by_o_auth2_permission_grant_id(grant.id).delete()
            revoked += 1
        return RemediationStep(
            step_number=step,
            action="revoke_oauth2_grants",
            target=user_id,
            detail=f"Revoked {revoked} OAuth2 delegated permission grants",
        )
    except Exception as e:
        logger.warning("Failed to revoke OAuth2 grants for %s: %s", user_id, e)
        return RemediationStep(
            step_number=step,
            action="revoke_oauth2_grants",
            target=user_id,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


async def _disable_user(client, user_id: str, step: int) -> RemediationStep:
    """PATCH /users/{id} with accountEnabled=false."""
    try:
        from msgraph.generated.models.user import User

        body = User()
        body.account_enabled = False
        await client.users.by_user_id(user_id).patch(body)
        return RemediationStep(
            step_number=step,
            action="disable_user",
            target=user_id,
            detail="accountEnabled set to false",
        )
    except Exception as e:
        logger.warning("Failed to disable user %s: %s", user_id, e)
        return RemediationStep(
            step_number=step,
            action="disable_user",
            target=user_id,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


async def _delete_user(client, user_id: str, step: int) -> RemediationStep:
    """DELETE /users/{id} — soft-deletes to recycle bin (30-day retention)."""
    try:
        await client.users.by_user_id(user_id).delete()
        return RemediationStep(
            step_number=step,
            action="delete_user",
            target=user_id,
            detail="User soft-deleted (30-day recycle bin)",
        )
    except Exception as e:
        logger.warning("Failed to delete user %s: %s", user_id, e)
        return RemediationStep(
            step_number=step,
            action="delete_user",
            target=user_id,
            status=RemediationStatus.FAILED,
            error=str(e),
        )
