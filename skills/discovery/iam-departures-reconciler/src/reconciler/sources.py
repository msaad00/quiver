"""Multi-source HR data ingestion for departed-employee reconciliation.

Each source normalizes termination records into a unified DepartureRecord
schema for downstream reconciliation and remediation.

Supported sources:
    - Snowflake  (Workday tables replicated via ETL)
    - Databricks (Workday tables in Unity Catalog)
    - ClickHouse (Workday tables replicated via CDC)
    - Workday    (direct RaaS API)

MITRE ATT&CK context:
    T1078.004 — Valid Accounts: Cloud Accounts
    We query HR termination data to identify cloud accounts that should
    no longer exist, preventing persistence via departed-employee credentials.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

SOURCE_FETCH_ATTEMPTS = int(os.environ.get("HR_SOURCE_FETCH_ATTEMPTS", "3"))
SOURCE_FETCH_BASE_DELAY = float(os.environ.get("HR_SOURCE_FETCH_BASE_DELAY", "1.5"))


def _with_retry(fn: Callable[[], _T], what: str) -> _T:
    """Retry a transient-failure-prone read-only callable with exponential backoff.

    Used for HR source `fetch_departures` bodies so that a single transient
    network/availability hiccup does not drop a whole reconciler run. The
    callable must be idempotent — we only use it for reads against
    Snowflake / Databricks / ClickHouse / Workday.

    Delay doubles per attempt starting from ``SOURCE_FETCH_BASE_DELAY``.
    Default is 3 attempts over roughly 4.5 seconds. Override via env vars
    ``HR_SOURCE_FETCH_ATTEMPTS`` and ``HR_SOURCE_FETCH_BASE_DELAY``.
    """
    attempts = max(1, SOURCE_FETCH_ATTEMPTS)
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:
            if attempt == attempts:
                raise
            delay = SOURCE_FETCH_BASE_DELAY * (2 ** (attempt - 1))
            logger.warning(
                "%s failed on attempt %d/%d (%s); retrying in %.1fs",
                what,
                attempt,
                attempts,
                type(exc).__name__,
                delay,
            )
            time.sleep(delay)
    # Unreachable: the final attempt either returns or raises above.
    raise RuntimeError(f"{what}: retry loop exhausted without result")


SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _configure_snowflake_logging() -> None:
    """Suppress verbose connector logging before credentials are used."""
    logging.getLogger("snowflake.connector").setLevel(logging.WARNING)


class RemediationStatus(Enum):
    """Lifecycle state of a departure record."""

    PENDING = "pending"
    VALIDATED = "validated"
    REMEDIATED = "remediated"
    SKIPPED = "skipped"
    ERROR = "error"


class TerminationSource(Enum):
    """Origin system for the termination data."""

    SNOWFLAKE = "snowflake"
    DATABRICKS = "databricks"
    CLICKHOUSE = "clickhouse"
    WORKDAY = "workday"


@dataclass
class DepartureRecord:
    """Unified schema for a departed employee's IAM footprint.

    This is the canonical record used throughout the pipeline — from
    HR ingestion through change detection, S3 export, and Lambda processing.
    """

    email: str
    recipient_account_id: str
    iam_username: str
    iam_created_at: datetime | None = None
    terminated_at: datetime | None = None
    termination_source: TerminationSource = TerminationSource.SNOWFLAKE
    is_rehire: bool = False
    rehire_date: datetime | None = None
    iam_deleted: bool = False
    iam_deleted_at: datetime | None = None
    iam_last_used_at: datetime | None = None
    last_checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    remediation_status: RemediationStatus = RemediationStatus.PENDING
    record_hash: str = ""

    def __post_init__(self) -> None:
        self.email = self.email.strip().lower()
        self.iam_username = self.iam_username.strip()
        self.record_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Deterministic hash for change detection."""
        parts = [
            self.email,
            self.recipient_account_id,
            self.iam_username,
            str(self.terminated_at),
            str(self.is_rehire),
            str(self.rehire_date),
            str(self.iam_deleted),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def should_remediate(self) -> bool:
        """Determine if this IAM user should be remediated.

        Rehire logic (caveats):
        1. Rehired + same IAM still in use → SKIP (active employee)
        2. Rehired + different IAM created after rehire → REMEDIATE old IAM
        3. Rehired + old IAM not used after rehire_date → REMEDIATE old IAM
        4. IAM already deleted → SKIP
        5. Within grace period → SKIP (HR correction window)

        Returns:
            True if remediation should proceed for this record.
        """
        # Already handled
        if self.iam_deleted:
            return False

        # Already remediated or errored
        if self.remediation_status in (RemediationStatus.REMEDIATED, RemediationStatus.ERROR):
            return False

        # No termination date = still employed
        if self.terminated_at is None:
            return False

        # Rehire handling — the critical caveats
        if self.is_rehire and self.rehire_date:
            # If IAM was used AFTER rehire date, the employee is using this
            # same IAM in their new role → do NOT remediate
            if self.iam_last_used_at and self.iam_last_used_at > self.rehire_date:
                return False

            # If IAM was created AFTER rehire date, this is a new IAM for the
            # rehired employee → do NOT remediate (it's their current IAM)
            if self.iam_created_at and self.iam_created_at > self.rehire_date:
                return False

            # If IAM was NOT used after rehire, the employee got a new IAM
            # and this old one is orphaned → REMEDIATE
            return True

        # Standard case: terminated, not rehired → remediate
        return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON export."""
        return {
            "email": self.email,
            "recipient_account_id": self.recipient_account_id,
            "iam_username": self.iam_username,
            "iam_created_at": self.iam_created_at.isoformat() if self.iam_created_at else None,
            "terminated_at": self.terminated_at.isoformat() if self.terminated_at else None,
            "termination_source": self.termination_source.value,
            "is_rehire": self.is_rehire,
            "rehire_date": self.rehire_date.isoformat() if self.rehire_date else None,
            "iam_deleted": self.iam_deleted,
            "iam_deleted_at": self.iam_deleted_at.isoformat() if self.iam_deleted_at else None,
            "iam_last_used_at": self.iam_last_used_at.isoformat()
            if self.iam_last_used_at
            else None,
            "last_checked_at": self.last_checked_at.isoformat(),
            "remediation_status": self.remediation_status.value,
            "record_hash": self.record_hash,
        }


class HRSource(ABC):
    """Abstract base for HR data sources."""

    @abstractmethod
    def fetch_departures(self) -> list[DepartureRecord]:
        """Fetch terminated employees with IAM mappings."""

    @abstractmethod
    def health_check(self) -> bool:
        """Verify connectivity to the HR data source."""


class SnowflakeSource(HRSource):
    """Ingest Workday termination data from Snowflake.

    Expects tables:
        {hr_database}.{hr_schema}.employees    — Workday employee records
        {iam_database}.{iam_schema}.iam_users  — IAM user inventory

    Env vars:
        SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_PASSWORD
        SNOWFLAKE_HR_DATABASE (default: hr_db)
        SNOWFLAKE_HR_SCHEMA (default: workday)
        SNOWFLAKE_IAM_DATABASE (default: security_db)
        SNOWFLAKE_IAM_SCHEMA (default: iam)
    """

    QUERY = """
    SELECT
        w.email_address         AS email,
        i.account_id            AS recipient_account_id,
        i.iam_username,
        i.created_at            AS iam_created_at,
        w.termination_date      AS terminated_at,
        w.rehire_date,
        i.last_used_at          AS iam_last_used_at,
        i.is_deleted            AS iam_deleted,
        i.deleted_at            AS iam_deleted_at
    FROM {hr_database}.{hr_schema}.employees w
    JOIN {iam_database}.{iam_schema}.iam_users i
        ON LOWER(w.email_address) = LOWER(i.email)
    WHERE w.termination_date IS NOT NULL
      AND w.termination_date <= CURRENT_DATE()
    ORDER BY w.termination_date DESC
    """

    def __init__(self) -> None:
        self.account = os.environ["SNOWFLAKE_ACCOUNT"]
        self.user = os.environ["SNOWFLAKE_USER"]
        self.password = os.environ["SNOWFLAKE_PASSWORD"]
        self.hr_database = _validate_sql_identifier(
            os.environ.get("SNOWFLAKE_HR_DATABASE", "hr_db"), "SNOWFLAKE_HR_DATABASE"
        )
        self.hr_schema = _validate_sql_identifier(
            os.environ.get("SNOWFLAKE_HR_SCHEMA", "workday"), "SNOWFLAKE_HR_SCHEMA"
        )
        self.iam_database = _validate_sql_identifier(
            os.environ.get("SNOWFLAKE_IAM_DATABASE", "security_db"), "SNOWFLAKE_IAM_DATABASE"
        )
        self.iam_schema = _validate_sql_identifier(
            os.environ.get("SNOWFLAKE_IAM_SCHEMA", "iam"), "SNOWFLAKE_IAM_SCHEMA"
        )

    def _get_connection(self) -> Any:
        import snowflake.connector

        _configure_snowflake_logging()
        return snowflake.connector.connect(
            account=self.account,
            user=self.user,
            password=self.password,
            database=self.hr_database,
            schema=self.hr_schema,
        )

    def fetch_departures(self) -> list[DepartureRecord]:
        return _with_retry(self._fetch_departures_once, "Snowflake.fetch_departures")

    def _fetch_departures_once(self) -> list[DepartureRecord]:
        query = self.QUERY.format(
            hr_database=self.hr_database,
            hr_schema=self.hr_schema,
            iam_database=self.iam_database,
            iam_schema=self.iam_schema,
        )
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            columns = [desc[0].lower() for desc in cursor.description]
            return [self._row_to_record(dict(zip(columns, row, strict=False))) for row in rows]
        finally:
            conn.close()

    def _row_to_record(self, row: dict) -> DepartureRecord:
        rehire_date = row.get("rehire_date")
        terminated_at = row.get("terminated_at")
        is_rehire = bool(rehire_date and terminated_at and rehire_date > terminated_at)

        return DepartureRecord(
            email=row["email"],
            recipient_account_id=str(row["recipient_account_id"]),
            iam_username=row["iam_username"],
            iam_created_at=row.get("iam_created_at"),
            terminated_at=terminated_at,
            termination_source=TerminationSource.SNOWFLAKE,
            is_rehire=is_rehire,
            rehire_date=rehire_date,
            iam_deleted=bool(row.get("iam_deleted")),
            iam_deleted_at=row.get("iam_deleted_at"),
            iam_last_used_at=row.get("iam_last_used_at"),
        )

    def health_check(self) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            return True
        except Exception:
            logger.exception("Snowflake health check failed")
            return False


class DatabricksSource(HRSource):
    """Ingest Workday termination data from Databricks Unity Catalog.

    Expects tables:
        {hr_catalog}.{hr_schema}.employees    — Workday employee records
        {iam_catalog}.{iam_schema}.iam_users  — IAM user inventory

    Env vars:
        DATABRICKS_HOST, DATABRICKS_TOKEN
        DATABRICKS_HR_CATALOG (default: hr_catalog)
        DATABRICKS_HR_SCHEMA (default: workday)
        DATABRICKS_IAM_CATALOG (default: security_catalog)
        DATABRICKS_IAM_SCHEMA (default: iam)
    """

    QUERY = """
    SELECT
        w.email_address         AS email,
        i.account_id            AS recipient_account_id,
        i.iam_username,
        i.created_at            AS iam_created_at,
        w.termination_date      AS terminated_at,
        w.rehire_date,
        i.last_used_at          AS iam_last_used_at,
        i.is_deleted            AS iam_deleted,
        i.deleted_at            AS iam_deleted_at
    FROM {hr_catalog}.{hr_schema}.employees w
    JOIN {iam_catalog}.{iam_schema}.iam_users i
        ON LOWER(w.email_address) = LOWER(i.email)
    WHERE w.termination_date IS NOT NULL
      AND w.termination_date <= current_date()
    ORDER BY w.termination_date DESC
    """

    def __init__(self) -> None:
        self.host = os.environ["DATABRICKS_HOST"]
        self.token = os.environ["DATABRICKS_TOKEN"]
        self.hr_catalog = _validate_sql_identifier(
            os.environ.get("DATABRICKS_HR_CATALOG", "hr_catalog"), "DATABRICKS_HR_CATALOG"
        )
        self.hr_schema = _validate_sql_identifier(
            os.environ.get("DATABRICKS_HR_SCHEMA", "workday"), "DATABRICKS_HR_SCHEMA"
        )
        self.iam_catalog = _validate_sql_identifier(
            os.environ.get("DATABRICKS_IAM_CATALOG", "security_catalog"), "DATABRICKS_IAM_CATALOG"
        )
        self.iam_schema = _validate_sql_identifier(
            os.environ.get("DATABRICKS_IAM_SCHEMA", "iam"), "DATABRICKS_IAM_SCHEMA"
        )

    def _get_connection(self) -> Any:
        from databricks import sql as dbsql

        return dbsql.connect(
            server_hostname=self.host,
            http_path=os.environ.get("DATABRICKS_HTTP_PATH", "/sql/1.0/warehouses/default"),
            access_token=self.token,
        )

    def fetch_departures(self) -> list[DepartureRecord]:
        return _with_retry(self._fetch_departures_once, "Databricks.fetch_departures")

    def _fetch_departures_once(self) -> list[DepartureRecord]:
        query = self.QUERY.format(
            hr_catalog=self.hr_catalog,
            hr_schema=self.hr_schema,
            iam_catalog=self.iam_catalog,
            iam_schema=self.iam_schema,
        )
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            columns = [desc[0].lower() for desc in cursor.description]
            return [self._row_to_record(dict(zip(columns, row, strict=False))) for row in rows]
        finally:
            conn.close()

    def _row_to_record(self, row: dict) -> DepartureRecord:
        rehire_date = row.get("rehire_date")
        terminated_at = row.get("terminated_at")
        is_rehire = bool(rehire_date and terminated_at and rehire_date > terminated_at)

        return DepartureRecord(
            email=row["email"],
            recipient_account_id=str(row["recipient_account_id"]),
            iam_username=row["iam_username"],
            iam_created_at=row.get("iam_created_at"),
            terminated_at=terminated_at,
            termination_source=TerminationSource.DATABRICKS,
            is_rehire=is_rehire,
            rehire_date=rehire_date,
            iam_deleted=bool(row.get("iam_deleted")),
            iam_deleted_at=row.get("iam_deleted_at"),
            iam_last_used_at=row.get("iam_last_used_at"),
        )

    def health_check(self) -> bool:
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            conn.close()
            return True
        except Exception:
            logger.exception("Databricks health check failed")
            return False


class ClickHouseSource(HRSource):
    """Ingest Workday termination data from ClickHouse.

    Expects tables:
        {hr_database}.workday_employees  — Workday employee records
        {iam_database}.iam_users         — IAM user inventory

    Env vars:
        CLICKHOUSE_HOST, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
        CLICKHOUSE_HR_DATABASE (default: hr)
        CLICKHOUSE_IAM_DATABASE (default: security)
    """

    QUERY = """
    SELECT
        w.email_address         AS email,
        i.account_id            AS recipient_account_id,
        i.iam_username,
        i.created_at            AS iam_created_at,
        w.termination_date      AS terminated_at,
        w.rehire_date,
        i.last_used_at          AS iam_last_used_at,
        i.is_deleted            AS iam_deleted,
        i.deleted_at            AS iam_deleted_at
    FROM {hr_database}.workday_employees w
    JOIN {iam_database}.iam_users i
        ON lower(w.email_address) = lower(i.email)
    WHERE w.termination_date IS NOT NULL
      AND w.termination_date <= today()
    ORDER BY w.termination_date DESC
    """

    def __init__(self) -> None:
        self.host = os.environ["CLICKHOUSE_HOST"]
        self.user = os.environ.get("CLICKHOUSE_USER", "default")
        self.password = os.environ.get("CLICKHOUSE_PASSWORD", "")
        self.hr_database = _validate_sql_identifier(
            os.environ.get("CLICKHOUSE_HR_DATABASE", "hr"), "CLICKHOUSE_HR_DATABASE"
        )
        self.iam_database = _validate_sql_identifier(
            os.environ.get("CLICKHOUSE_IAM_DATABASE", "security"), "CLICKHOUSE_IAM_DATABASE"
        )

    def _get_client(self) -> Any:
        import clickhouse_connect

        return clickhouse_connect.get_client(
            host=self.host,
            username=self.user,
            password=self.password,
        )

    def fetch_departures(self) -> list[DepartureRecord]:
        return _with_retry(self._fetch_departures_once, "ClickHouse.fetch_departures")

    def _fetch_departures_once(self) -> list[DepartureRecord]:
        query = self.QUERY.format(
            hr_database=self.hr_database,
            iam_database=self.iam_database,
        )
        client = self._get_client()
        result = client.query(query)
        columns = [col.lower() for col in result.column_names]
        return [
            self._row_to_record(dict(zip(columns, row, strict=False))) for row in result.result_rows
        ]

    def _row_to_record(self, row: dict) -> DepartureRecord:
        rehire_date = row.get("rehire_date")
        terminated_at = row.get("terminated_at")
        is_rehire = bool(rehire_date and terminated_at and rehire_date > terminated_at)

        return DepartureRecord(
            email=row["email"],
            recipient_account_id=str(row["recipient_account_id"]),
            iam_username=row["iam_username"],
            iam_created_at=row.get("iam_created_at"),
            terminated_at=terminated_at,
            termination_source=TerminationSource.CLICKHOUSE,
            is_rehire=is_rehire,
            rehire_date=rehire_date,
            iam_deleted=bool(row.get("iam_deleted")),
            iam_deleted_at=row.get("iam_deleted_at"),
            iam_last_used_at=row.get("iam_last_used_at"),
        )

    def health_check(self) -> bool:
        try:
            client = self._get_client()
            client.query("SELECT 1")
            return True
        except Exception:
            logger.exception("ClickHouse health check failed")
            return False


class WorkdayAPISource(HRSource):
    """Ingest termination data directly from Workday RaaS API.

    Requires a custom Workday report (RaaS) exposing terminated workers
    with their email, termination date, and rehire date fields.

    Env vars:
        WORKDAY_API_URL      — RaaS report endpoint
        WORKDAY_CLIENT_ID    — OAuth client ID
        WORKDAY_CLIENT_SECRET — OAuth client secret
        WORKDAY_TOKEN_URL    — OAuth token endpoint (default: {tenant}/oauth2/token)
    """

    def __init__(self) -> None:
        self.api_url = os.environ["WORKDAY_API_URL"]
        self.client_id = os.environ["WORKDAY_CLIENT_ID"]
        self.client_secret = os.environ["WORKDAY_CLIENT_SECRET"]
        self.token_url = os.environ.get("WORKDAY_TOKEN_URL", "")

    def _get_token(self) -> str:
        """Fetch an OAuth access token.

        On failure, raises a sanitized ``RuntimeError`` carrying only the
        HTTP status (or ``network-error`` when no response was received).
        The raw ``httpx.Response`` body is never logged or re-raised — it
        can contain tenant metadata or echoed credentials and downstream
        log sinks would not have the context to redact it.
        """
        import httpx

        try:
            resp = httpx.post(
                self.token_url,
                data={"grant_type": "client_credentials"},
                auth=(self.client_id, self.client_secret),
                timeout=30,
            )
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Workday token endpoint unreachable ({type(exc).__name__})"
            ) from None
        if resp.status_code >= 400:
            # Do NOT include response text — potentially sensitive.
            raise RuntimeError(f"Workday token endpoint returned HTTP {resp.status_code}")
        return resp.json()["access_token"]

    def fetch_departures(self) -> list[DepartureRecord]:
        return _with_retry(self._fetch_departures_once, "Workday.fetch_departures")

    def _fetch_departures_once(self) -> list[DepartureRecord]:
        import httpx

        token = self._get_token()
        resp = httpx.get(
            self.api_url,
            headers={"Authorization": f"Bearer {token}"},
            params={"format": "json"},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()

        records = []
        for entry in data.get("Report_Entry", []):
            rehire_date = _parse_date(entry.get("rehire_date"))
            terminated_at = _parse_date(entry.get("termination_date"))
            is_rehire = bool(rehire_date and terminated_at and rehire_date > terminated_at)

            records.append(
                DepartureRecord(
                    email=entry["email_address"],
                    recipient_account_id=entry.get("aws_account_id", ""),
                    iam_username=entry.get("iam_username", ""),
                    terminated_at=terminated_at,
                    termination_source=TerminationSource.WORKDAY,
                    is_rehire=is_rehire,
                    rehire_date=rehire_date,
                )
            )
        return records

    def health_check(self) -> bool:
        try:
            self._get_token()
            return True
        except Exception as exc:
            # _get_token raises sanitized RuntimeError; other exceptions are
            # type-only logged so auth responses never reach log sinks.
            logger.warning("Workday API health check failed: %s", type(exc).__name__)
            return False


def _parse_date(value: str | None) -> datetime | None:
    """Parse ISO date string to datetime."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _validate_sql_identifier(value: str, field: str) -> str:
    if not SQL_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"Invalid SQL identifier for {field}")
    return value


def get_source(name: str) -> HRSource:
    """Factory: instantiate an HR source by name.

    Args:
        name: One of 'snowflake', 'databricks', 'clickhouse', 'workday'

    Returns:
        Configured HRSource instance.

    Raises:
        ValueError: Unknown source name.
    """
    sources: dict[str, type[HRSource]] = {
        "snowflake": SnowflakeSource,
        "databricks": DatabricksSource,
        "clickhouse": ClickHouseSource,
        "workday": WorkdayAPISource,
    }
    if name not in sources:
        raise ValueError(f"Unknown HR source: {name!r}. Must be one of {sorted(sources)}")
    return sources[name]()
