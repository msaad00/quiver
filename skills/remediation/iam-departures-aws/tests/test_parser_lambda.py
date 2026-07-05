"""Tests for Lambda 1 (Parser) — manifest validation and filtering."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lambda_parser.handler import _validate_entry, handler


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _days_ago_iso(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def _make_entry(
    email: str = "jane@co.com",
    account_id: str = "123456789012",
    iam_username: str = "jane",
    terminated_at: str | None = None,
    is_rehire: bool = False,
    rehire_date: str | None = None,
    iam_deleted: bool = False,
    iam_last_used_at: str | None = None,
    iam_created_at: str | None = None,
) -> dict:
    return {
        "email": email,
        "recipient_account_id": account_id,
        "iam_username": iam_username,
        "terminated_at": terminated_at or _days_ago_iso(30),
        "is_rehire": is_rehire,
        "rehire_date": rehire_date,
        "iam_deleted": iam_deleted,
        "iam_last_used_at": iam_last_used_at,
        "iam_created_at": iam_created_at or _days_ago_iso(365),
        "remediation_status": "pending",
    }


class TestValidateEntry:
    """Test individual entry validation logic."""

    @patch("lambda_parser.handler._get_iam_client")
    def test_valid_entry_passes(self, mock_iam):
        """Standard terminated employee passes validation."""
        mock_client = MagicMock()
        mock_iam.return_value = mock_client

        entry = _make_entry(terminated_at=_days_ago_iso(30))
        result = _validate_entry(entry)
        assert result["action"] == "remediate"

    def test_missing_email_skipped(self):
        entry = _make_entry(email="")
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "Missing required field" in result["reason"]

    def test_missing_account_id_skipped(self):
        entry = _make_entry(account_id="")
        result = _validate_entry(entry)
        assert result["action"] == "skip"

    def test_already_deleted_skipped(self):
        entry = _make_entry(iam_deleted=True)
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "already deleted" in result["reason"]

    def test_already_remediated_skipped(self):
        entry = _make_entry()
        entry["remediation_status"] = "remediated"
        result = _validate_entry(entry)
        assert result["action"] == "skip"

    @patch("lambda_parser.handler.GRACE_PERIOD_DAYS", 7)
    def test_within_grace_period_skipped(self):
        """Recently terminated (within grace) → skip for HR corrections."""
        entry = _make_entry(terminated_at=_days_ago_iso(3))
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "grace period" in result["reason"]

    @patch("lambda_parser.handler._get_iam_client")
    def test_rehire_same_iam_in_use_skipped(self, mock_iam):
        """Rehired employee using same IAM → skip."""
        mock_iam.return_value = MagicMock()
        entry = _make_entry(
            terminated_at=_days_ago_iso(60),
            is_rehire=True,
            rehire_date=_days_ago_iso(30),
            iam_last_used_at=_days_ago_iso(5),
        )
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "rehire" in result["reason"].lower()

    @patch("lambda_parser.handler._get_iam_client")
    def test_rehire_old_iam_orphaned_remediates(self, mock_iam):
        """Rehired but old IAM not used after rehire → remediate."""
        mock_iam.return_value = MagicMock()
        entry = _make_entry(
            terminated_at=_days_ago_iso(60),
            is_rehire=True,
            rehire_date=_days_ago_iso(30),
            iam_last_used_at=_days_ago_iso(45),
            iam_created_at=_days_ago_iso(365),
        )
        result = _validate_entry(entry)
        assert result["action"] == "remediate"

    @patch("lambda_parser.handler._get_iam_client")
    def test_iam_not_found_skipped(self, mock_iam):
        """IAM user doesn't exist in target account → skip."""
        mock_client = MagicMock()
        no_such = type("NoSuchEntityException", (Exception,), {})
        mock_client.exceptions.NoSuchEntityException = no_such
        mock_client.get_user.side_effect = no_such()
        mock_iam.return_value = mock_client

        entry = _make_entry(terminated_at=_days_ago_iso(30))
        result = _validate_entry(entry)
        assert result["action"] == "skip"
        assert "not found" in result["reason"]


class TestParserHandler:
    """Test the full Lambda handler."""

    @patch("lambda_parser.handler._get_iam_client")
    @patch("lambda_parser.handler.boto3")
    def test_handler_processes_manifest(self, mock_boto3, mock_iam):
        """Handler reads S3 manifest and returns validated entries."""
        mock_iam.return_value = MagicMock()

        manifest = {
            "entries": [
                _make_entry(email="valid@co.com", terminated_at=_days_ago_iso(30)),
                _make_entry(email="deleted@co.com", iam_deleted=True),
            ]
        }

        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=MagicMock(return_value=json.dumps(manifest).encode()))
        }
        mock_boto3.client.return_value = mock_s3

        result = handler(
            {"bucket": "test-bucket", "key": "departures/2026-03-01.json"},
            None,
        )

        assert "validated_entries" in result
        assert "validation_summary" in result
        assert result["validation_summary"]["total_entries"] == 2
        # 1 actionable (valid), 1 skipped (deleted)
        assert result["validation_summary"]["skipped_count"] >= 1

    @patch("lambda_parser.handler.boto3")
    def test_handler_rejects_invalid_event_payload(self, mock_boto3):
        result = handler({"bucket": "", "key": ""}, None)

        assert result["validated_entries"] == []
        assert result["validation_summary"]["error_count"] == 1
        assert "Invalid event payload" in result["validation_summary"]["errors"][0]["error"]
        mock_boto3.client.assert_not_called()
