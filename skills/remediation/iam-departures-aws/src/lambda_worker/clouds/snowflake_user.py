"""Snowflake user identity remediation.

SDK: snowflake-connector-python
API: Snowflake SQL commands (DDL)

Deletion order (6 steps):
    1. Abort all active queries/sessions
    2. Disable the user (ALTER USER SET DISABLED=TRUE)
    3. List and revoke all granted roles
    4. Transfer ownership of objects to a target role
    5. Drop the user (DROP USER IF EXISTS)
    6. Verify user no longer exists

Required Snowflake privileges:
    - USERADMIN or SECURITYADMIN role (for ALTER USER, DROP USER)
    - OWNERSHIP on the user, or SECURITYADMIN
    - SECURITYADMIN for REVOKE ROLE
    - Current owner role for GRANT OWNERSHIP transfer

GOTCHAS:
    - PUBLIC role CANNOT be revoked — it is implicitly granted to all users.
      Skip it in the revocation loop.
    - Disabling a user (DISABLED=TRUE) prevents new logins but does NOT kill
      existing sessions. You must ABORT ALL QUERIES first.
    - DROP USER succeeds even with owned objects, but those objects become
      orphaned and inaccessible. ALWAYS transfer ownership first.
    - Ownership transfer is per-object-type: tables, views, schemas, stages,
      pipes, etc. each need separate GRANT OWNERSHIP statements.
    - Snowsight worksheets/dashboards/folders owned by the user become
      permanently inaccessible after DROP USER unless Edit permissions were
      shared with other users beforehand.
    - COPY CURRENT GRANTS must be specified in GRANT OWNERSHIP to preserve
      existing privilege grants on transferred objects.
    - The snowflake-connector-python can log passwords in ALTER USER statements.
      Disable verbose logging in production.

Env vars:
    SNOWFLAKE_REMEDIATION_ACCOUNT
    SNOWFLAKE_REMEDIATION_USER
    SNOWFLAKE_REMEDIATION_PASSWORD
    SNOWFLAKE_REMEDIATION_ROLE (default: SECURITYADMIN)
    SNOWFLAKE_OWNERSHIP_TARGET_ROLE (default: SYSADMIN)
"""

from __future__ import annotations

import logging
import os
import re

from . import CloudProvider, RemediationResult, RemediationStatus, RemediationStep

logger = logging.getLogger(__name__)

# Roles that cannot be revoked from any user
_IMPLICIT_ROLES = frozenset({"PUBLIC"})

# Object types that need ownership transfer before DROP USER
_OWNERSHIP_OBJECT_TYPES = [
    "TABLES",
    "VIEWS",
    "SCHEMAS",
    "STAGES",
    "PIPES",
    "STREAMS",
    "TASKS",
    "PROCEDURES",
    "FUNCTIONS",
    "FILE FORMATS",
    "SEQUENCES",
]
_IDENTIFIER_RE = re.compile(r"^[^\x00\r\n]+$")


def _configure_snowflake_logging() -> None:
    """Suppress verbose connector logging before credentials are used."""
    logging.getLogger("snowflake.connector").setLevel(logging.WARNING)


def get_required_permissions() -> list[str]:
    """Return minimum Snowflake privileges needed."""
    return [
        "USERADMIN or SECURITYADMIN role",
        "OWNERSHIP on target user",
        "SECURITYADMIN for REVOKE ROLE",
    ]


def _get_connection():
    """Create authenticated Snowflake connection."""
    import snowflake.connector

    _configure_snowflake_logging()
    return snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_REMEDIATION_ACCOUNT"],
        user=os.environ["SNOWFLAKE_REMEDIATION_USER"],
        password=os.environ["SNOWFLAKE_REMEDIATION_PASSWORD"],
        role=os.environ.get("SNOWFLAKE_REMEDIATION_ROLE", "SECURITYADMIN"),
    )


async def remediate_user(
    username: str,
    account: str,
    *,
    ownership_target_role: str | None = None,
    dry_run: bool = False,
) -> RemediationResult:
    """Remediate a Snowflake user (6-step process).

    Args:
        username: Snowflake username to remediate.
        account: Snowflake account identifier.
        ownership_target_role: Role to receive ownership of user's objects.
        dry_run: If True, log actions without executing.

    Returns:
        RemediationResult with per-step status.
    """
    target_role = ownership_target_role or os.environ.get(
        "SNOWFLAKE_OWNERSHIP_TARGET_ROLE", "SYSADMIN"
    )

    result = RemediationResult(
        cloud=CloudProvider.SNOWFLAKE,
        identity_id=username,
        identity_type="snowflake_user",
        account_id=account,
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

    try:
        conn = _get_connection()
        cursor = conn.cursor()
    except Exception as e:
        result.status = RemediationStatus.FAILED
        result.error = f"Failed to connect to Snowflake: {e}"
        result.complete()
        return result

    try:
        # Step 1: Abort all active queries/sessions
        result.steps.append(_abort_queries(cursor, username, step=1))

        # Step 2: Disable user
        result.steps.append(_disable_user(cursor, username, step=2))

        # Step 3: Revoke all roles
        result.steps.append(_revoke_roles(cursor, username, step=3))

        # Step 4: Transfer ownership
        result.steps.append(_transfer_ownership(cursor, username, target_role, step=4))

        # Step 5: Drop user
        result.steps.append(_drop_user(cursor, username, step=5))

        # Step 6: Verify
        result.steps.append(_verify_dropped(cursor, username, step=6))
    finally:
        cursor.close()
        conn.close()

    result.complete()
    return result


_STEP_NAMES = [
    "abort_active_queries",
    "disable_user",
    "revoke_roles",
    "transfer_ownership",
    "drop_user",
    "verify_dropped",
]


def _abort_queries(cursor, username: str, step: int) -> RemediationStep:
    """ALTER USER {name} ABORT ALL QUERIES — kills active sessions."""
    try:
        cursor.execute(f"ALTER USER {_quote_identifier(username)} ABORT ALL QUERIES")
        return RemediationStep(
            step_number=step,
            action="abort_active_queries",
            target=username,
            detail="All active queries aborted",
        )
    except Exception as e:
        logger.warning("Failed to abort queries for %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="abort_active_queries",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _disable_user(cursor, username: str, step: int) -> RemediationStep:
    """ALTER USER SET DISABLED=TRUE — prevents new logins."""
    try:
        cursor.execute(f"ALTER USER {_quote_identifier(username)} SET DISABLED = TRUE")
        return RemediationStep(
            step_number=step,
            action="disable_user",
            target=username,
            detail="User disabled (no new logins)",
        )
    except Exception as e:
        logger.warning("Failed to disable user %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="disable_user",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _revoke_roles(cursor, username: str, step: int) -> RemediationStep:
    """SHOW GRANTS TO USER then REVOKE ROLE for each (except PUBLIC)."""
    try:
        quoted_username = _quote_identifier(username)
        cursor.execute(f"SHOW GRANTS TO USER {quoted_username}")
        grants = cursor.fetchall()

        revoked = 0
        skipped = 0
        for row in grants:
            role_name = row[1]  # role name is second column
            if role_name.upper() in _IMPLICIT_ROLES:
                skipped += 1
                continue
            try:
                cursor.execute(
                    f"REVOKE ROLE {_quote_identifier(role_name)} FROM USER {quoted_username}"
                )
                revoked += 1
            except Exception:
                skipped += 1

        return RemediationStep(
            step_number=step,
            action="revoke_roles",
            target=username,
            detail=f"Revoked {revoked} roles, skipped {skipped} (implicit/protected)",
        )
    except Exception as e:
        logger.warning("Failed to revoke roles for %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="revoke_roles",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _transfer_ownership(cursor, username: str, target_role: str, step: int) -> RemediationStep:
    """Transfer ownership of all objects to target role.

    COPY CURRENT GRANTS preserves existing privilege grants on the objects.
    Each object type requires a separate GRANT OWNERSHIP statement.
    """
    try:
        _quote_identifier(username)
        quoted_target_role = _quote_identifier(target_role)
        transferred = 0
        errors = 0

        # Get databases where user might own objects
        cursor.execute("SHOW DATABASES")
        databases = [row[1] for row in cursor.fetchall()]

        for db in databases:
            try:
                quoted_db = _quote_identifier(db)
                cursor.execute(f"SHOW SCHEMAS IN DATABASE {quoted_db}")
                schemas = [row[1] for row in cursor.fetchall()]
            except Exception:
                continue

            for schema in schemas:
                if schema in ("INFORMATION_SCHEMA",):
                    continue
                for obj_type in _OWNERSHIP_OBJECT_TYPES:
                    try:
                        cursor.execute(
                            f"GRANT OWNERSHIP ON ALL {obj_type} IN SCHEMA {quoted_db}.{_quote_identifier(schema)} TO ROLE {quoted_target_role} COPY CURRENT GRANTS"
                        )
                        transferred += 1
                    except Exception:
                        errors += 1

        return RemediationStep(
            step_number=step,
            action="transfer_ownership",
            target=username,
            detail=f"Transferred ownership in {transferred} schema/type combos, {errors} errors",
        )
    except Exception as e:
        logger.warning("Failed to transfer ownership for %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="transfer_ownership",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _drop_user(cursor, username: str, step: int) -> RemediationStep:
    """DROP USER IF EXISTS — permanent deletion (no soft delete in Snowflake)."""
    try:
        cursor.execute(f"DROP USER IF EXISTS {_quote_identifier(username)}")
        return RemediationStep(
            step_number=step,
            action="drop_user",
            target=username,
            detail="User dropped (permanent, no soft delete)",
        )
    except Exception as e:
        logger.warning("Failed to drop user %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="drop_user",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _verify_dropped(cursor, username: str, step: int) -> RemediationStep:
    """Verify the user no longer exists in Snowflake."""
    try:
        cursor.execute(f"SHOW USERS LIKE {_quote_string_literal(username)}")
        rows = cursor.fetchall()
        if rows:
            return RemediationStep(
                step_number=step,
                action="verify_dropped",
                target=username,
                status=RemediationStatus.FAILED,
                error="User still exists after DROP",
            )
        return RemediationStep(
            step_number=step,
            action="verify_dropped",
            target=username,
            detail="Confirmed: user no longer exists",
        )
    except Exception as e:
        logger.warning("Failed to verify user drop for %s: %s", username, e)
        return RemediationStep(
            step_number=step,
            action="verify_dropped",
            target=username,
            status=RemediationStatus.FAILED,
            error=str(e),
        )


def _quote_identifier(value: str) -> str:
    """Quote a Snowflake identifier safely for DDL statements."""
    if not isinstance(value, str) or not value.strip() or not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError("Invalid Snowflake identifier")
    escaped = value.replace('"', '""')
    return f'"{escaped}"'


def _quote_string_literal(value: str) -> str:
    """Quote a Snowflake string literal safely."""
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError("Invalid Snowflake string literal")
    escaped = value.replace("'", "''")
    return f"'{escaped}'"
