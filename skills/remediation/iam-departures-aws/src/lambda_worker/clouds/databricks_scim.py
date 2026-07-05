"""Databricks identity remediation via SCIM API.

SDK: databricks-sdk
API: SCIM v2 (workspace), SCIM v2 (account-level)

Deletion order (4 steps):
    1. Revoke all Personal Access Tokens (PATs)
    2. Deactivate user at workspace level (active=false via SCIM PATCH)
    3. Deactivate user at account level (removes from all workspaces)
    4. Delete user (account-level deletion cascades to all workspaces)

Required permissions:
    - Workspace admin (for PAT management + workspace-level SCIM)
    - Account admin (for account-level SCIM operations)

GOTCHAS:
    - Deactivation vs Deletion: Deactivation preserves user objects, permissions,
      and config. Deletion removes them. PATs issued to a deactivated user can't
      authenticate, but they still exist in the system.
    - Account-level deletion cascades to ALL workspaces under that account.
    - SCIM provisioning conflicts: If an IdP (Okta, Entra ID) provisions via
      SCIM, deleting a user via API may conflict. The user could be
      re-provisioned on the next sync cycle. Deprovision from the IdP first.
    - Two API versions: workspace-level uses /api/2.0/preview/scim/v2/,
      account-level uses /api/2.1/accounts/{account_id}/scim/v2/.
      The 'preview' in the workspace path is stable despite the name.
    - Token ownership: token_management.list() filters by created_by_username
      (email string) or created_by_id (numeric).
    - Service principals: Same SCIM pattern but use service_principals client
      instead of users client.
    - PAT auto-revocation: Databricks auto-revokes PATs unused for 90+ days,
      but don't rely on this for security remediation.

Env vars:
    DATABRICKS_HOST (workspace URL, e.g., https://your-workspace.cloud.databricks.com)
    DATABRICKS_TOKEN (workspace admin PAT or OAuth token)
    DATABRICKS_ACCOUNT_HOST (account console, e.g., https://accounts.cloud.databricks.com)
    DATABRICKS_ACCOUNT_ID
    DATABRICKS_ACCOUNT_TOKEN (account admin token)
"""

from __future__ import annotations

import logging
import os

from . import CloudProvider, RemediationResult, RemediationStatus, RemediationStep

logger = logging.getLogger(__name__)


def get_required_permissions() -> list[str]:
    """Return minimum Databricks permissions needed."""
    return [
        "Workspace admin (PAT management + workspace SCIM)",
        "Account admin (account-level SCIM)",
    ]


def _get_workspace_client():
    """Create Databricks workspace client."""
    from databricks.sdk import WorkspaceClient

    return WorkspaceClient(
        host=os.environ["DATABRICKS_HOST"],
        token=os.environ["DATABRICKS_TOKEN"],
    )


def _get_account_client():
    """Create Databricks account client for multi-workspace operations."""
    from databricks.sdk import AccountClient

    return AccountClient(
        host=os.environ.get("DATABRICKS_ACCOUNT_HOST", "https://accounts.cloud.databricks.com"),
        account_id=os.environ["DATABRICKS_ACCOUNT_ID"],
        token=os.environ["DATABRICKS_ACCOUNT_TOKEN"],
    )


async def remediate_user(
    username: str,
    *,
    workspace_only: bool = False,
    dry_run: bool = False,
) -> RemediationResult:
    """Remediate a Databricks user (4-step process).

    Args:
        username: User's email address (SCIM userName).
        workspace_only: If True, only remediate at workspace level.
        dry_run: If True, log actions without executing.

    Returns:
        RemediationResult with per-step status.
    """
    result = RemediationResult(
        cloud=CloudProvider.DATABRICKS,
        identity_id=username,
        identity_type="databricks_user",
        account_id=os.environ.get("DATABRICKS_ACCOUNT_ID", "workspace"),
    )

    if dry_run:
        result.status = RemediationStatus.DRY_RUN
        for i, action in enumerate(_STEP_NAMES, 1):
            result.steps.append(
                RemediationStep(
                    step_number=i, action=action, target=username, status=RemediationStatus.DRY_RUN
                )
            )
        result.complete()
        return result

    # Step 1: Revoke all PATs (workspace-level)
    result.steps.append(_revoke_pats(username, step=1))

    # Step 2: Deactivate at workspace level
    result.steps.append(_deactivate_workspace_user(username, step=2))

    if not workspace_only:
        # Step 3: Deactivate at account level
        result.steps.append(_deactivate_account_user(username, step=3))

        # Step 4: Delete at account level (cascades to all workspaces)
        result.steps.append(_delete_account_user(username, step=4))
    else:
        result.steps.append(
            RemediationStep(
                step_number=3,
                action="deactivate_account_user",
                target=username,
                detail="Skipped (workspace_only mode)",
            )
        )
        result.steps.append(
            RemediationStep(
                step_number=4,
                action="delete_account_user",
                target=username,
                detail="Skipped (workspace_only mode)",
            )
        )

    result.complete()
    return result


_STEP_NAMES = [
    "revoke_pats",
    "deactivate_workspace_user",
    "deactivate_account_user",
    "delete_account_user",
]


def _revoke_pats(username: str, step: int) -> RemediationStep:
    """List and delete all PATs created by the user.

    Uses token_management API: DELETE /api/2.0/token-management/tokens/{token_id}
    """
    try:
        ws = _get_workspace_client()
        tokens = list(ws.token_management.list(created_by_username=username))
        revoked = 0
        for token_info in tokens:
            ws.token_management.delete(token_id=token_info.token_id)
            revoked += 1
        return RemediationStep(
            step_number=step,
            action="revoke_pats",
            target=username,
            detail=f"Revoked {revoked} personal access tokens",
        )
    except Exception as e:
        logger.warning("Failed to revoke PATs for %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="revoke_pats",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _deactivate_workspace_user(username: str, step: int) -> RemediationStep:
    """PATCH /api/2.0/preview/scim/v2/Users/{id} with active=false.

    Prevents authentication but preserves user objects and permissions.
    """
    try:
        from databricks.sdk.service import iam

        ws = _get_workspace_client()
        # Find user by email
        user = _find_workspace_user(ws, username)
        if user is None:
            return RemediationStep(
                step_number=step,
                action="deactivate_workspace_user",
                target=username,
                detail="User not found in workspace, skipped",
            )

        ws.users.patch(
            id=user.id,
            operations=[
                iam.Patch(
                    op=iam.PatchOp.REPLACE,
                    path="active",
                    value="false",
                )
            ],
            schemas=[iam.PatchSchema.URN_IETF_PARAMS_SCIM_API_MESSAGES_2_0_PATCH_OP],
        )
        return RemediationStep(
            step_number=step,
            action="deactivate_workspace_user",
            target=username,
            detail=f"User {user.id} deactivated in workspace",
        )
    except Exception as e:
        logger.warning("Failed to deactivate workspace user %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="deactivate_workspace_user",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _deactivate_account_user(username: str, step: int) -> RemediationStep:
    """PATCH /api/2.1/accounts/{id}/scim/v2/Users/{id} with active=false.

    Account-level deactivation removes the user from all workspaces.
    """
    try:
        from databricks.sdk.service import iam

        ac = _get_account_client()
        user = _find_account_user(ac, username)
        if user is None:
            return RemediationStep(
                step_number=step,
                action="deactivate_account_user",
                target=username,
                detail="User not found at account level, skipped",
            )

        ac.users.patch(
            id=user.id,
            operations=[
                iam.Patch(
                    op=iam.PatchOp.REPLACE,
                    path="active",
                    value="false",
                )
            ],
            schemas=[iam.PatchSchema.URN_IETF_PARAMS_SCIM_API_MESSAGES_2_0_PATCH_OP],
        )
        return RemediationStep(
            step_number=step,
            action="deactivate_account_user",
            target=username,
            detail=f"User {user.id} deactivated at account level",
        )
    except Exception as e:
        logger.warning("Failed to deactivate account user %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="deactivate_account_user",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _delete_account_user(username: str, step: int) -> RemediationStep:
    """DELETE /api/2.1/accounts/{id}/scim/v2/Users/{id}.

    Account-level deletion cascades — removes user from ALL workspaces.
    WARNING: If user was provisioned via IdP SCIM, they may be re-created
    on next sync cycle. Deprovision from IdP first.
    """
    try:
        ac = _get_account_client()
        user = _find_account_user(ac, username)
        if user is None:
            return RemediationStep(
                step_number=step,
                action="delete_account_user",
                target=username,
                detail="User not found at account level, skipped",
            )

        ac.users.delete(id=user.id)
        return RemediationStep(
            step_number=step,
            action="delete_account_user",
            target=username,
            detail=f"User {user.id} deleted at account level (cascades to all workspaces)",
        )
    except Exception as e:
        logger.warning("Failed to delete account user %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="delete_account_user",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _find_workspace_user(ws, username: str):
    """Find a user in the workspace by email using SCIM filter."""
    users = list(ws.users.list(filter=f'userName eq "{username}"'))
    return users[0] if users else None


def _find_account_user(ac, username: str):
    """Find a user at account level by email using SCIM filter."""
    users = list(ac.users.list(filter=f'userName eq "{username}"'))
    return users[0] if users else None
