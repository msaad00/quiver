"""Lambda 2: Worker — execute IAM remediation for each validated user.

Receives validated entries from the parser Lambda via Step Function
Map state. For each IAM user:

    1. Deactivate all access keys
    2. Delete login profile (console access)
    3. Remove from all groups
    4. Detach all managed policies
    5. Delete all inline policies
    6. Delete MFA devices
    7. Delete signing certificates
    8. Tag user with audit metadata
    9. DELETE the IAM user (after all dependencies removed)
    10. Write audit record

AWS IAM deletion requires ALL dependencies to be removed first.
The order matters — you cannot delete a user with active keys, policies,
group memberships, MFA devices, or signing certificates.

MITRE ATT&CK coverage:
    T1531     Account Access Removal — revoking departed-employee access
    T1098.001 Account Manipulation: Additional Cloud Credentials — removing orphaned keys
    T1078.004 Valid Accounts: Cloud Accounts — eliminating persistence vector

NIST CSF:
    PR.AC-1   Identities and credentials are issued, managed, verified, revoked
    PR.AC-4   Access permissions and authorizations are managed
    RS.MI-2   Incidents are mitigated

CIS Controls v8:
    5.3   Disable Dormant Accounts
    6.2   Establish an Access Revoking Process
    6.5   Require MFA for Administrative Access (clean up MFA devices)

SOC 2 (Trust Services Criteria):
    CC6.1   Logical and Physical Access Controls — access revocation
    CC6.2   Prior to Issuing System Credentials — lifecycle management
    CC6.3   Registration and Authorization — deprovisioning
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import boto3

from .protected_principals import ProtectedPrincipalError, assert_not_protected

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CROSS_ACCOUNT_ROLE = os.environ.get("IAM_CROSS_ACCOUNT_ROLE", "iam-remediation-role")
AUDIT_TABLE = os.environ.get("IAM_AUDIT_DYNAMODB_TABLE", "iam-remediation-audit")
AUDIT_BUCKET = os.environ.get("IAM_REMEDIATION_BUCKET", "")
ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
CHECKPOINT_SK = "CURRENT"


class AuditWriteError(RuntimeError):
    """All configured audit stores failed.

    Raised by ``_write_audit`` when every configured audit sink (DynamoDB
    and/or S3) fails. The worker treats this as distinct from a remediation
    failure: the IAM mutation already landed, but there is no durable
    record of it. The Step Function must route these to DLQ/alerting so
    operators manually reconcile.
    """


def handler(event: dict, context: Any) -> dict:
    """Step Function Map task: remediate a single IAM user.

    Input (from Step Function Map over validated_entries):
        {
            "entry": {
                "email": "jane.doe@company.com",
                "recipient_account_id": "123456789012",
                "iam_username": "jane.doe",
                "terminated_at": "2026-02-15T00:00:00+00:00",
                ...
            },
            "source_bucket": "my-bucket",
            "source_key": "departures/2026-03-01.json"
        }

    Output:
        {
            "email": "...",
            "iam_username": "...",
            "account_id": "...",
            "status": "remediated"|"error",
            "actions_taken": [...],
            "error": "..." (if status == "error")
        }
    """
    entry = event.get("entry", event)
    if not isinstance(entry, dict):
        entry = {}

    try:
        account_id = _require_non_empty_str(entry, "recipient_account_id")
        iam_username = _require_non_empty_str(entry, "iam_username")
        email = _require_non_empty_str(entry, "email")
        if not ACCOUNT_ID_RE.fullmatch(account_id):
            raise ValueError("recipient_account_id must be a 12-digit AWS account ID")
        # Defense-in-depth: refuse protected principals before any IAM call.
        # The IaC deny policy is the authoritative guard; this is a local
        # second layer in case that policy is ever missing from a deploy.
        assert_not_protected(iam_username)
    except ProtectedPrincipalError as exc:
        logger.error("Refusing protected principal: %s", exc)
        audit_record = _build_audit_record(entry, [], "refused", error=str(exc), context=context)
        _write_audit(audit_record)
        return {
            "email": entry.get("email", ""),
            "iam_username": entry.get("iam_username", ""),
            "account_id": entry.get("recipient_account_id", ""),
            "status": "refused",
            "actions_taken": [],
            "error": str(exc),
        }
    except ValueError as exc:
        logger.warning("Invalid remediation payload: %s", exc)
        audit_record = _build_audit_record(
            entry, [], "error", error="Invalid remediation payload", context=context
        )
        _write_audit(audit_record)
        return {
            "email": entry.get("email", ""),
            "iam_username": entry.get("iam_username", ""),
            "account_id": entry.get("recipient_account_id", ""),
            "status": "error",
            "actions_taken": [],
            "error": "Invalid remediation payload",
        }

    logger.info(
        "Remediating IAM user: %s in account %s (employee: %s)",
        iam_username,
        account_id,
        email,
    )

    checkpoint = _load_checkpoint(entry)
    actions_taken: list[dict[str, Any]] = list(checkpoint["actions_taken"])
    completed_steps: list[str] = list(checkpoint["completed_steps"])
    completed_step_set = set(completed_steps)

    if checkpoint["status"] == "remediated":
        logger.info(
            "Replay-safe short circuit for already remediated user %s in %s",
            iam_username,
            account_id,
        )
        return {
            "email": email,
            "iam_username": iam_username,
            "account_id": account_id,
            "status": "remediated",
            "actions_taken": actions_taken,
            "remediated_at": checkpoint["updated_at"],
            "checkpoint_reused": True,
        }

    try:
        iam = _get_iam_client(account_id, request_id=getattr(context, "aws_request_id", None))

        for step_name, step_fn in _remediation_steps():
            if step_name in completed_step_set:
                continue
            step_fn(iam, iam_username, entry, actions_taken)
            completed_steps.append(step_name)
            completed_step_set.add(step_name)
            _save_checkpoint(
                entry,
                actions_taken,
                completed_steps,
                status="in_progress",
            )

        logger.info("Successfully deleted IAM user: %s", iam_username)

        # Step 12: Write audit record.
        # The IAM mutation has already landed. If every audit store fails,
        # return a distinct status so Step Function routes this invocation
        # to DLQ/alerts for manual reconciliation — do NOT hide the gap by
        # returning "remediated".
        audit_record = _build_audit_record(entry, actions_taken, "remediated", context=context)
        try:
            _write_audit(audit_record)
            final_status = "remediated"
            audit_error: str | None = None
        except AuditWriteError as audit_exc:
            logger.error(
                "IAM user %s in %s deleted but all audit stores failed: %s",
                iam_username,
                account_id,
                audit_exc,
            )
            final_status = "remediated_audit_failed"
            audit_error = str(audit_exc)

        _save_checkpoint(
            entry,
            actions_taken,
            completed_steps,
            status=final_status,
            audit_timestamp=audit_record["audit_timestamp"],
        )

        response: dict[str, Any] = {
            "email": email,
            "iam_username": iam_username,
            "account_id": account_id,
            "status": final_status,
            "actions_taken": actions_taken,
            "remediated_at": _now(),
        }
        if audit_error is not None:
            response["audit_error"] = audit_error
        return response

    except Exception as exc:
        logger.exception("Remediation failed for %s in %s", iam_username, account_id)
        _save_checkpoint(
            entry,
            actions_taken,
            completed_steps,
            status="error",
            error=str(exc),
        )

        # Still write audit — record the failure
        audit_record = _build_audit_record(
            entry, actions_taken, "error", error=str(exc), context=context
        )
        _write_audit(audit_record)

        return {
            "email": email,
            "iam_username": iam_username,
            "account_id": account_id,
            "status": "error",
            "actions_taken": actions_taken,
            "error": str(exc),
        }


# ── IAM Remediation Steps ──────────────────────────────────────────


def _remediation_steps() -> tuple[tuple[str, Any], ...]:
    """11 worker functions that collectively perform 13 distinct IAM API operations.

    Why the two numbers differ: `_deactivate_access_keys` below issues BOTH
    `iam:UpdateAccessKey(Inactive)` and `iam:DeleteAccessKey` per key, and
    `_delete_mfa_devices` issues BOTH `iam:DeactivateMFADevice` and
    `iam:DeleteVirtualMFADevice` per device. The SVG + SKILL.md "13-step
    deletion order" counts distinct IAM API calls (what shows up in
    CloudTrail); this tuple counts function-level steps for the checkpoint
    loop. Both views are truthful; the numbers describe different things.

    Keep in sync with `SKILL.md § Deletion order` and
    `docs/images/iam-departures-aws.svg` DELETION ORDER card.
    """
    return (
        (
            "deactivate_access_keys",
            lambda iam, username, _entry, actions: _deactivate_access_keys(iam, username, actions),
        ),
        (
            "delete_login_profile",
            lambda iam, username, _entry, actions: _delete_login_profile(iam, username, actions),
        ),
        (
            "remove_from_groups",
            lambda iam, username, _entry, actions: _remove_from_groups(iam, username, actions),
        ),
        (
            "detach_managed_policies",
            lambda iam, username, _entry, actions: _detach_managed_policies(iam, username, actions),
        ),
        (
            "delete_inline_policies",
            lambda iam, username, _entry, actions: _delete_inline_policies(iam, username, actions),
        ),
        (
            "delete_mfa_devices",
            lambda iam, username, _entry, actions: _delete_mfa_devices(iam, username, actions),
        ),
        (
            "delete_signing_certificates",
            lambda iam, username, _entry, actions: _delete_signing_certificates(
                iam, username, actions
            ),
        ),
        (
            "delete_ssh_keys",
            lambda iam, username, _entry, actions: _delete_ssh_keys(iam, username, actions),
        ),
        (
            "delete_service_credentials",
            lambda iam, username, _entry, actions: _delete_service_credentials(
                iam, username, actions
            ),
        ),
        (
            "tag_user_for_audit",
            lambda iam, username, entry, actions: _tag_user_for_audit(
                iam, username, entry, actions
            ),
        ),
        (
            "delete_user",
            lambda iam, username, _entry, actions: _delete_user(iam, username, actions),
        ),
    )


def _deactivate_access_keys(iam: Any, username: str, actions: list) -> None:
    """Deactivate and delete all access keys for the user."""
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=username):
        for key_meta in page["AccessKeyMetadata"]:
            key_id = key_meta["AccessKeyId"]

            # Deactivate first (safer — reversible)
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key_id,
                Status="Inactive",
            )
            actions.append(
                {
                    "action": "deactivate_access_key",
                    "target": key_id,
                    "timestamp": _now(),
                }
            )

            # Then delete (required before user deletion)
            iam.delete_access_key(
                UserName=username,
                AccessKeyId=key_id,
            )
            actions.append(
                {
                    "action": "delete_access_key",
                    "target": key_id,
                    "timestamp": _now(),
                }
            )


def _delete_login_profile(iam: Any, username: str, actions: list) -> None:
    """Delete console login profile (password)."""
    try:
        iam.delete_login_profile(UserName=username)
        actions.append(
            {
                "action": "delete_login_profile",
                "target": username,
                "timestamp": _now(),
            }
        )
    except iam.exceptions.NoSuchEntityException:
        pass  # No login profile — console access was never enabled


def _remove_from_groups(iam: Any, username: str, actions: list) -> None:
    """Remove user from all IAM groups."""
    paginator = iam.get_paginator("list_groups_for_user")
    for page in paginator.paginate(UserName=username):
        for group in page["Groups"]:
            group_name = group["GroupName"]
            iam.remove_user_from_group(
                GroupName=group_name,
                UserName=username,
            )
            actions.append(
                {
                    "action": "remove_from_group",
                    "target": group_name,
                    "timestamp": _now(),
                }
            )


def _detach_managed_policies(iam: Any, username: str, actions: list) -> None:
    """Detach all managed policies from the user."""
    paginator = iam.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy in page["AttachedPolicies"]:
            iam.detach_user_policy(
                UserName=username,
                PolicyArn=policy["PolicyArn"],
            )
            actions.append(
                {
                    "action": "detach_managed_policy",
                    "target": policy["PolicyArn"],
                    "timestamp": _now(),
                }
            )


def _delete_inline_policies(iam: Any, username: str, actions: list) -> None:
    """Delete all inline policies from the user."""
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=username):
        for policy_name in page["PolicyNames"]:
            iam.delete_user_policy(
                UserName=username,
                PolicyName=policy_name,
            )
            actions.append(
                {
                    "action": "delete_inline_policy",
                    "target": policy_name,
                    "timestamp": _now(),
                }
            )


def _delete_mfa_devices(iam: Any, username: str, actions: list) -> None:
    """Deactivate and delete all MFA devices."""
    paginator = iam.get_paginator("list_mfa_devices")
    for page in paginator.paginate(UserName=username):
        for device in page["MFADevices"]:
            serial = device["SerialNumber"]
            iam.deactivate_mfa_device(
                UserName=username,
                SerialNumber=serial,
            )
            # Virtual MFA devices need explicit deletion
            if ":mfa/" in serial:
                try:
                    iam.delete_virtual_mfa_device(SerialNumber=serial)
                except iam.exceptions.NoSuchEntityException:
                    pass
            actions.append(
                {
                    "action": "delete_mfa_device",
                    "target": serial,
                    "timestamp": _now(),
                }
            )


def _delete_signing_certificates(iam: Any, username: str, actions: list) -> None:
    """Delete all signing certificates."""
    paginator = iam.get_paginator("list_signing_certificates")
    for page in paginator.paginate(UserName=username):
        for cert in page["Certificates"]:
            iam.delete_signing_certificate(
                UserName=username,
                CertificateId=cert["CertificateId"],
            )
            actions.append(
                {
                    "action": "delete_signing_certificate",
                    "target": cert["CertificateId"],
                    "timestamp": _now(),
                }
            )


def _delete_ssh_keys(iam: Any, username: str, actions: list) -> None:
    """Delete all SSH public keys."""
    paginator = iam.get_paginator("list_ssh_public_keys")
    for page in paginator.paginate(UserName=username):
        for key in page["SSHPublicKeys"]:
            iam.delete_ssh_public_key(
                UserName=username,
                SSHPublicKeyId=key["SSHPublicKeyId"],
            )
            actions.append(
                {
                    "action": "delete_ssh_key",
                    "target": key["SSHPublicKeyId"],
                    "timestamp": _now(),
                }
            )


def _delete_service_credentials(iam: Any, username: str, actions: list) -> None:
    """Delete service-specific credentials (CodeCommit, etc.)."""
    try:
        response = iam.list_service_specific_credentials(UserName=username)
        for cred in response.get("ServiceSpecificCredentials", []):
            iam.delete_service_specific_credential(
                UserName=username,
                ServiceSpecificCredentialId=cred["ServiceSpecificCredentialId"],
            )
            actions.append(
                {
                    "action": "delete_service_credential",
                    "target": cred["ServiceSpecificCredentialId"],
                    "timestamp": _now(),
                }
            )
    except Exception:
        pass  # Some accounts may not support this API


def _tag_user_for_audit(iam: Any, username: str, entry: dict, actions: list) -> None:
    """Tag IAM user with audit metadata before deletion.

    Tags persist briefly before deletion but are captured in CloudTrail.
    """
    tags = [
        {"Key": "remediation-action", "Value": "departed-employee-cleanup"},
        {"Key": "remediation-timestamp", "Value": _now()},
        {"Key": "employee-email", "Value": entry.get("email", "")[:256]},
        {"Key": "terminated-at", "Value": entry.get("terminated_at", "")[:256]},
        {"Key": "termination-source", "Value": entry.get("termination_source", "")[:256]},
    ]
    try:
        iam.tag_user(UserName=username, Tags=tags)
        actions.append(
            {
                "action": "tag_user",
                "target": username,
                "tags": {t["Key"]: t["Value"] for t in tags},
                "timestamp": _now(),
            }
        )
    except Exception:
        logger.warning("Failed to tag user %s before deletion", username)


def _delete_user(iam: Any, username: str, actions: list[dict[str, Any]]) -> None:
    iam.delete_user(UserName=username)
    actions.append(
        {
            "action": "delete_user",
            "target": username,
            "timestamp": _now(),
        }
    )


# ── Audit ───────────────────────────────────────────────────────────


def _build_audit_record(
    entry: dict,
    actions: list[dict],
    status: str,
    error: str = "",
    context: Any | None = None,
) -> dict:
    """Build a complete audit record for compliance logging."""
    return {
        "audit_timestamp": _now(),
        "email": entry.get("email", ""),
        "iam_username": entry.get("iam_username", ""),
        "account_id": entry.get("recipient_account_id", ""),
        "terminated_at": entry.get("terminated_at", ""),
        "termination_source": entry.get("termination_source", ""),
        "is_rehire": entry.get("is_rehire", False),
        "rehire_date": entry.get("rehire_date"),
        "status": status,
        "error": error,
        "actions_taken": actions,
        "actions_count": len(actions),
        "lambda_function": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown"),
        "lambda_request_id": getattr(context, "aws_request_id", ""),
        "invoked_by": os.environ.get("SKILL_CALLER_ID", ""),
        "invoked_by_email": os.environ.get("SKILL_CALLER_EMAIL", ""),
        "agent_session_id": os.environ.get("SKILL_SESSION_ID", ""),
        "caller_roles": os.environ.get("SKILL_CALLER_ROLES", ""),
        "approved_by": os.environ.get("SKILL_APPROVER_ID", ""),
        "approved_by_email": os.environ.get("SKILL_APPROVER_EMAIL", ""),
        "approval_ticket": os.environ.get("SKILL_APPROVAL_TICKET", ""),
        "approval_timestamp": os.environ.get("SKILL_APPROVAL_TIMESTAMP", ""),
    }


def _write_audit(record: dict) -> None:
    """Write audit record to DynamoDB and S3.

    Dual-write ensures audit durability:
    - DynamoDB: fast queries for operational dashboards
    - S3: immutable long-term storage for compliance

    The audit record is then ingested back to the source data warehouse
    (Snowflake/Databricks/ClickHouse) via a separate ETL process to
    update the remediation_status column and close the loop.
    """
    stores_configured = 0
    stores_written = 0
    failures: list[str] = []

    # DynamoDB audit
    if AUDIT_TABLE:
        stores_configured += 1
        try:
            dynamodb = boto3.resource("dynamodb")
            table = dynamodb.Table(AUDIT_TABLE)
            table.put_item(
                Item={
                    "pk": f"AUDIT#{record['account_id']}#{record['iam_username']}",
                    "sk": record["audit_timestamp"],
                    **{k: v for k, v in record.items() if v is not None and v != ""},
                    "actions_taken": json.dumps(record.get("actions_taken", [])),
                }
            )
            stores_written += 1
        except Exception as exc:
            logger.exception("Failed to write DynamoDB audit record")
            failures.append(f"dynamodb={type(exc).__name__}")

    # S3 audit (append to daily log)
    if AUDIT_BUCKET:
        stores_configured += 1
        try:
            s3 = boto3.client("s3")
            date_str = record["audit_timestamp"][:10]
            key = f"departures/audit/{date_str}/{record['iam_username']}.json"
            s3.put_object(
                Bucket=AUDIT_BUCKET,
                Key=key,
                Body=json.dumps(record, indent=2, default=str).encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="aws:kms",
            )
            stores_written += 1
        except Exception as exc:
            logger.exception("Failed to write S3 audit record")
            failures.append(f"s3={type(exc).__name__}")

    if stores_configured > 0 and stores_written == 0:
        raise AuditWriteError(
            f"all {stores_configured} audit stores failed for "
            f"account={record.get('account_id')} user={record.get('iam_username')}: "
            f"{', '.join(failures)}"
        )


def _load_checkpoint(entry: dict[str, Any]) -> dict[str, Any]:
    checkpoint: dict[str, Any] = {
        "status": "new",
        "actions_taken": [],
        "completed_steps": [],
        "updated_at": "",
    }
    if not AUDIT_TABLE:
        return checkpoint
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(AUDIT_TABLE)
        response = table.get_item(
            Key={
                "pk": _checkpoint_pk(entry),
                "sk": CHECKPOINT_SK,
            }
        )
    except Exception:
        logger.exception("Failed to read DynamoDB checkpoint")
        return checkpoint

    item = response.get("Item") or {}
    actions_taken = item.get("actions_taken")
    parsed_actions: list[dict[str, Any]] = []
    if isinstance(actions_taken, str):
        try:
            decoded = json.loads(actions_taken)
            if isinstance(decoded, list):
                parsed_actions = [action for action in decoded if isinstance(action, dict)]
        except json.JSONDecodeError:
            parsed_actions = []

    completed_steps = item.get("completed_steps")
    if not isinstance(completed_steps, list):
        completed_steps = []

    checkpoint["status"] = str(item.get("status") or "new")
    checkpoint["actions_taken"] = parsed_actions
    checkpoint["completed_steps"] = [step for step in completed_steps if isinstance(step, str)]
    checkpoint["updated_at"] = str(item.get("updated_at") or "")
    return checkpoint


def _save_checkpoint(
    entry: dict[str, Any],
    actions_taken: list[dict[str, Any]],
    completed_steps: list[str],
    *,
    status: str,
    error: str = "",
    audit_timestamp: str = "",
) -> None:
    if not AUDIT_TABLE:
        return
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(AUDIT_TABLE)
        table.put_item(
            Item={
                "pk": _checkpoint_pk(entry),
                "sk": CHECKPOINT_SK,
                "record_type": "remediation_checkpoint",
                "status": status,
                "email": entry.get("email", ""),
                "iam_username": entry.get("iam_username", ""),
                "account_id": entry.get("recipient_account_id", ""),
                "completed_steps": completed_steps,
                "updated_at": _now(),
                "actions_taken": json.dumps(actions_taken),
                "error": error,
                "audit_timestamp": audit_timestamp,
            }
        )
    except Exception:
        logger.exception("Failed to write DynamoDB checkpoint")


# ── Helpers ─────────────────────────────────────────────────────────


def _get_iam_client(account_id: str, request_id: str | None = None) -> Any:
    """Assume cross-account role for IAM operations.

    The session name embeds the Lambda invocation's aws_request_id when
    available, so CloudTrail AssumeRole events, DynamoDB audit rows, and
    S3 audit objects can be cross-referenced during incident response.
    Session names are capped at 64 chars by IAM.
    """
    if not ACCOUNT_ID_RE.fullmatch(account_id):
        raise ValueError("Invalid AWS account ID")

    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE}"

    session_name = "iam-departures-worker"
    if request_id:
        # Keep the first 8 chars of the UUID-style request id; ample for
        # correlation and stays well under the 64-char IAM limit.
        session_name = f"iam-departures-worker-{request_id[:8]}"

    credentials = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=3600,  # 1 hour for full remediation
    )["Credentials"]

    return boto3.client(
        "iam",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_non_empty_str(entry: dict[str, Any], field: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing required field: {field}")
    return value.strip()


def _checkpoint_pk(entry: dict[str, Any]) -> str:
    account_id = str(entry.get("recipient_account_id") or "")
    iam_username = str(entry.get("iam_username") or "")
    return f"CHECKPOINT#{account_id}#{iam_username}"
