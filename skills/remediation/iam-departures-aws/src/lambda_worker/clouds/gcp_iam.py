"""GCP IAM identity remediation.

SDK: google-cloud-iam (Service Accounts), google-api-python-client (Workspace users)
API: iam.googleapis.com, admin.googleapis.com

Two identity types for departed employees:
    1. Service Accounts — machine identities created by/for the employee
    2. Cloud Identity / Workspace users — the employee's human identity

Service Account deletion order (4 steps):
    1. Disable the service account
    2. Delete all user-managed keys (SYSTEM_MANAGED keys are GCP-internal)
    3. Remove IAM policy bindings from all projects
    4. Delete the service account (30-day soft delete)

Workspace user deletion:
    1. Remove IAM policy bindings from all GCP projects
    2. Delete the user via Admin SDK (20-day soft delete)

Required GCP IAM roles:
    - roles/iam.serviceAccountAdmin (disable + delete SA)
    - roles/iam.serviceAccountKeyAdmin (delete SA keys)
    - roles/resourcemanager.projectIamAdmin (modify IAM policies)

Required Workspace admin role:
    - Super Admin or User Management Admin

GOTCHAS:
    - Deleting SA keys does NOT revoke already-issued short-lived tokens.
      They expire naturally (default 1 hour).
    - IAM policy read-modify-write has race conditions. Always use the etag
      from get_iam_policy in your set_iam_policy to prevent overwrites.
    - Multi-project scope: IAM bindings can exist on projects, folders, org.
      Scan all of them. Direct resource-level bindings (buckets, datasets)
      require separate enumeration.
    - Principal format: 'user:email@domain.com' for humans,
      'serviceAccount:sa@project.iam.gserviceaccount.com' for SAs.
    - Service account soft delete is 30 days, Workspace user is 20 days.
    - System-managed keys CANNOT be deleted — skip them.

Env vars:
    GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_CLOUD_PROJECT
    GCP_ORG_ID (optional, for org-wide IAM scanning)
"""

from __future__ import annotations

import logging
import os

from . import CloudProvider, RemediationResult, RemediationStatus, RemediationStep

logger = logging.getLogger(__name__)


def get_required_permissions() -> list[str]:
    """Return minimum GCP IAM roles needed."""
    return [
        "roles/iam.serviceAccountAdmin",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/resourcemanager.projectIamAdmin",
    ]


def _get_iam_client():
    """Create GCP IAM admin client."""
    from google.cloud import iam_admin_v1

    return iam_admin_v1.IAMClient()


def _get_resource_manager_client():
    """Create GCP Resource Manager client for IAM policy operations."""
    from google.cloud import resourcemanager_v3

    return resourcemanager_v3.ProjectsClient()


async def remediate_service_account(
    email: str,
    project_id: str,
    *,
    projects_to_scan: list[str] | None = None,
    dry_run: bool = False,
) -> RemediationResult:
    """Remediate a GCP service account (4-step process).

    Args:
        email: Service account email (sa@project.iam.gserviceaccount.com).
        project_id: GCP project where the SA lives.
        projects_to_scan: Additional projects to scan for IAM bindings.
        dry_run: If True, log actions without executing.

    Returns:
        RemediationResult with per-step status.
    """
    result = RemediationResult(
        cloud=CloudProvider.GCP,
        identity_id=email,
        identity_type="service_account",
        account_id=project_id,
    )

    if dry_run:
        result.status = RemediationStatus.DRY_RUN
        for i, action in enumerate(["disable_service_account", "delete_sa_keys", "remove_iam_bindings", "delete_service_account"], 1):
            result.steps.append(RemediationStep(step_number=i, action=action, target=email, status=RemediationStatus.DRY_RUN))
        result.complete()
        return result

    sa_name = f"projects/{project_id}/serviceAccounts/{email}"
    all_projects = [project_id] + (projects_to_scan or [])

    try:
        iam_client = _get_iam_client()
    except Exception as e:
        result.status = RemediationStatus.FAILED
        result.error = f"Failed to create IAM client: {e}"
        result.complete()
        return result

    # Step 1: Disable service account
    result.steps.append(_disable_service_account(iam_client, sa_name, step=1))

    # Step 2: Delete all user-managed keys
    result.steps.append(_delete_sa_keys(iam_client, sa_name, step=2))

    # Step 3: Remove IAM policy bindings across projects
    result.steps.append(_remove_iam_bindings(f"serviceAccount:{email}", all_projects, step=3))

    # Step 4: Delete service account (30-day soft delete)
    result.steps.append(_delete_service_account(iam_client, sa_name, step=4))

    result.complete()
    return result


def _disable_service_account(client, sa_name: str, step: int) -> RemediationStep:
    """POST /v1/{name}:disable — prevents the SA from authenticating."""
    try:
        from google.cloud.iam_admin_v1 import types

        request = types.DisableServiceAccountRequest(name=sa_name)
        client.disable_service_account(request=request)
        return RemediationStep(step_number=step, action="disable_service_account", target=sa_name, detail="Service account disabled")
    except Exception as e:
        logger.warning("Failed to disable SA %s: %s", sa_name, e)
        return RemediationStep(
            step_number=step, action="disable_service_account", target=sa_name, status=RemediationStatus.FAILED, error=str(e)
        )


def _delete_sa_keys(client, sa_name: str, step: int) -> RemediationStep:
    """Delete all USER_MANAGED keys. SYSTEM_MANAGED keys cannot be deleted."""
    try:
        from google.cloud.iam_admin_v1 import types

        list_request = types.ListServiceAccountKeysRequest(name=sa_name)
        response = client.list_service_account_keys(request=list_request)

        deleted = 0
        skipped = 0
        for key in response.keys:
            if key.key_type == types.ListServiceAccountKeysRequest.KeyType.USER_MANAGED:
                del_request = types.DeleteServiceAccountKeyRequest(name=key.name)
                client.delete_service_account_key(request=del_request)
                deleted += 1
            else:
                skipped += 1  # SYSTEM_MANAGED — cannot delete

        return RemediationStep(
            step_number=step,
            action="delete_sa_keys",
            target=sa_name,
            detail=f"Deleted {deleted} user-managed keys, skipped {skipped} system-managed",
        )
    except Exception as e:
        logger.warning("Failed to delete SA keys for %s: %s", sa_name, e)
        return RemediationStep(step_number=step, action="delete_sa_keys", target=sa_name, status=RemediationStatus.FAILED, error=str(e))


def _remove_iam_bindings(principal: str, project_ids: list[str], step: int) -> RemediationStep:
    """Remove principal from all IAM role bindings across given projects.

    Uses read-modify-write with etag to prevent concurrent overwrites.
    """
    try:
        rm_client = _get_resource_manager_client()
        total_removed = 0

        for project_id in project_ids:
            resource = f"projects/{project_id}"
            policy = rm_client.get_iam_policy(resource=resource)

            modified = False
            for binding in policy.bindings:
                if principal in binding.members:
                    binding.members.remove(principal)
                    modified = True
                    total_removed += 1

            if modified:
                from google.cloud import resourcemanager_v3

                request = resourcemanager_v3.SetIamPolicyRequest(
                    resource=resource,
                    policy=policy,
                )
                rm_client.set_iam_policy(request=request)

        return RemediationStep(
            step_number=step,
            action="remove_iam_bindings",
            target=principal,
            detail=f"Removed {total_removed} bindings across {len(project_ids)} projects",
        )
    except Exception as e:
        logger.warning("Failed to remove IAM bindings for %s: %s", principal, e)
        return RemediationStep(
            step_number=step, action="remove_iam_bindings", target=principal, status=RemediationStatus.FAILED, error=str(e)
        )


def _delete_service_account(client, sa_name: str, step: int) -> RemediationStep:
    """DELETE /v1/{name} — 30-day soft delete with undelete option."""
    try:
        from google.cloud.iam_admin_v1 import types

        request = types.DeleteServiceAccountRequest(name=sa_name)
        client.delete_service_account(request=request)
        return RemediationStep(
            step_number=step,
            action="delete_service_account",
            target=sa_name,
            detail="Service account deleted (30-day undelete window)",
        )
    except Exception as e:
        logger.warning("Failed to delete SA %s: %s", sa_name, e)
        return RemediationStep(
            step_number=step, action="delete_service_account", target=sa_name, status=RemediationStatus.FAILED, error=str(e)
        )


async def remediate_workspace_user(
    email: str,
    *,
    project_ids: list[str] | None = None,
    dry_run: bool = False,
) -> RemediationResult:
    """Remediate a Google Workspace / Cloud Identity user (2 steps).

    Args:
        email: User's email address.
        project_ids: GCP projects to remove IAM bindings from.
        dry_run: If True, log without executing.
    """
    result = RemediationResult(
        cloud=CloudProvider.GCP,
        identity_id=email,
        identity_type="workspace_user",
        account_id=os.environ.get("GCP_ORG_ID", "unknown"),
    )

    if dry_run:
        result.status = RemediationStatus.DRY_RUN
        for i, action in enumerate(["remove_iam_bindings", "delete_workspace_user"], 1):
            result.steps.append(RemediationStep(step_number=i, action=action, target=email, status=RemediationStatus.DRY_RUN))
        result.complete()
        return result

    # Step 1: Remove IAM bindings
    if project_ids:
        result.steps.append(_remove_iam_bindings(f"user:{email}", project_ids, step=1))
    else:
        result.steps.append(
            RemediationStep(step_number=1, action="remove_iam_bindings", target=email, detail="No projects specified, skipped")
        )

    # Step 2: Delete via Admin SDK (20-day soft delete)
    result.steps.append(_delete_workspace_user(email, step=2))

    result.complete()
    return result


def _delete_workspace_user(email: str, step: int) -> RemediationStep:
    """DELETE /admin/directory/v1/users/{userKey} — 20-day recovery window."""
    try:
        from googleapiclient.discovery import build

        service = build("admin", "directory_v1")
        service.users().delete(userKey=email).execute()
        return RemediationStep(
            step_number=step,
            action="delete_workspace_user",
            target=email,
            detail="Workspace user deleted (20-day recovery window)",
        )
    except Exception as e:
        logger.warning("Failed to delete Workspace user %s: %s", email, e)
        return RemediationStep(
            step_number=step, action="delete_workspace_user", target=email, status=RemediationStatus.FAILED, error=str(e)
        )
