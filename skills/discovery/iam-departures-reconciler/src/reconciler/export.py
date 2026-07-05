"""Manifest builder for the shared read-only IAM departures planner.

Builds the canonical manifest body that the cloud-specific write paths persist
to their native object stores. This module does not write to S3 itself.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reconciler.sources import DepartureRecord


class ManifestBuilder:
    """Build the canonical manifest body without persisting it."""

    def build_manifest(
        self,
        records: list[DepartureRecord],
        source: str,
        content_hash: str,
        *,
        exported_at: datetime | None = None,
    ) -> dict[str, Any]:
        exported_at = exported_at or datetime.now(timezone.utc)
        actionable = [r for r in records if r.should_remediate()]
        skipped = [r for r in records if not r.should_remediate()]
        return {
            "export_timestamp": exported_at.isoformat(),
            "source": source,
            "hash": content_hash,
            "total_records": len(records),
            "actionable_count": len(actionable),
            "skipped_count": len(skipped),
            "skip_reasons": self._summarize_skips(skipped),
            "entries": [r.to_dict() for r in actionable],
        }

    @staticmethod
    def _summarize_skips(skipped: list[DepartureRecord]) -> dict[str, int]:
        """Categorize why records were skipped."""
        reasons: dict[str, int] = {
            "iam_already_deleted": 0,
            "rehire_same_iam": 0,
            "already_remediated": 0,
            "no_termination_date": 0,
        }
        for r in skipped:
            if r.iam_deleted:
                reasons["iam_already_deleted"] += 1
            elif (
                r.is_rehire
                and r.iam_last_used_at
                and r.rehire_date
                and r.iam_last_used_at > r.rehire_date
            ):
                reasons["rehire_same_iam"] += 1
            elif r.remediation_status.value == "remediated":
                reasons["already_remediated"] += 1
            else:
                reasons["no_termination_date"] += 1
        return {k: v for k, v in reasons.items() if v > 0}
