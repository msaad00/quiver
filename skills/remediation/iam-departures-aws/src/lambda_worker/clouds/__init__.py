"""Cross-cloud identity remediation workers.

Each cloud module implements:
    remediate_user(record, credentials, dry_run=False) -> RemediationResult
    get_required_permissions() -> list[str]

Cloud-specific deletion order matters — each cloud has different
dependencies that must be removed before the identity can be deleted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    SNOWFLAKE = "snowflake"
    DATABRICKS = "databricks"


class RemediationStatus(Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"


@dataclass
class RemediationStep:
    """Single step in the remediation process."""

    step_number: int
    action: str
    target: str
    status: RemediationStatus = RemediationStatus.SUCCESS
    detail: str = ""
    error: str = ""


@dataclass
class RemediationResult:
    """Outcome of remediating a single identity."""

    cloud: CloudProvider
    identity_id: str
    identity_type: str  # "iam_user", "entra_user", "service_account", etc.
    account_id: str  # AWS account, Azure tenant, GCP project, etc.
    status: RemediationStatus = RemediationStatus.SUCCESS
    steps: list[RemediationStep] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    error: str = ""

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()

    def complete(self) -> None:
        self.completed_at = datetime.now(timezone.utc).isoformat()
        failed = [s for s in self.steps if s.status == RemediationStatus.FAILED]
        if failed:
            self.status = (
                RemediationStatus.PARTIAL
                if len(failed) < len(self.steps)
                else RemediationStatus.FAILED
            )

    @property
    def steps_completed(self) -> int:
        return sum(1 for s in self.steps if s.status == RemediationStatus.SUCCESS)

    @property
    def steps_failed(self) -> int:
        return sum(1 for s in self.steps if s.status == RemediationStatus.FAILED)

    def to_dict(self) -> dict:
        return {
            "cloud": self.cloud.value,
            "identity_id": self.identity_id,
            "identity_type": self.identity_type,
            "account_id": self.account_id,
            "status": self.status.value,
            "steps_completed": self.steps_completed,
            "steps_failed": self.steps_failed,
            "steps": [
                {
                    "step": s.step_number,
                    "action": s.action,
                    "target": s.target,
                    "status": s.status.value,
                    "detail": s.detail,
                    "error": s.error,
                }
                for s in self.steps
            ],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }
