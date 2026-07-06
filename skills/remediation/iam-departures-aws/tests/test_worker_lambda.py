"""Tests for Lambda 2 (Worker) — IAM user remediation."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lambda_worker.handler import (
    AuditWriteError,
    _build_audit_record,
    _checkpoint_pk,
    _deactivate_access_keys,
    _delete_inline_policies,
    _delete_login_profile,
    _delete_mfa_devices,
    _detach_managed_policies,
    _remove_from_groups,
    _write_audit,
    handler,
)


def _make_event(
    email: str = "jane@co.com",
    account_id: str = "123456789012",
    iam_username: str = "jane",
) -> dict:
    return {
        "entry": {
            "email": email,
            "recipient_account_id": account_id,
            "iam_username": iam_username,
            "terminated_at": "2026-02-15T00:00:00+00:00",
            "termination_source": "snowflake",
            "is_rehire": False,
        },
        "source_bucket": "test-bucket",
        "source_key": "departures/2026-03-01.json",
    }


class TestRemediationSteps:
    """Test individual IAM remediation steps."""

    def test_deactivate_access_keys(self):
        """Should deactivate then delete all access keys."""
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "AccessKeyMetadata": [
                    {"AccessKeyId": "AKIA111", "Status": "Active"},
                    {"AccessKeyId": "AKIA222", "Status": "Active"},
                ]
            }
        ]
        actions = []
        _deactivate_access_keys(iam, "jane", actions)

        assert iam.update_access_key.call_count == 2
        assert iam.delete_access_key.call_count == 2
        assert len(actions) == 4  # 2 deactivate + 2 delete

        # Verify deactivation happens before deletion
        deactivate_calls = [a for a in actions if a["action"] == "deactivate_access_key"]
        delete_calls = [a for a in actions if a["action"] == "delete_access_key"]
        assert len(deactivate_calls) == 2
        assert len(delete_calls) == 2

    def test_delete_login_profile(self):
        iam = MagicMock()
        actions = []
        _delete_login_profile(iam, "jane", actions)

        iam.delete_login_profile.assert_called_once_with(UserName="jane")
        assert len(actions) == 1

    def test_delete_login_profile_not_found(self):
        """No login profile → no error, no action logged."""
        iam = MagicMock()
        iam.exceptions.NoSuchEntityException = type("E", (Exception,), {})
        iam.delete_login_profile.side_effect = iam.exceptions.NoSuchEntityException()

        actions = []
        _delete_login_profile(iam, "jane", actions)
        assert len(actions) == 0

    def test_remove_from_groups(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "Groups": [
                    {"GroupName": "developers"},
                    {"GroupName": "admin"},
                ]
            }
        ]
        actions = []
        _remove_from_groups(iam, "jane", actions)

        assert iam.remove_user_from_group.call_count == 2
        assert len(actions) == 2

    def test_detach_managed_policies(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "AttachedPolicies": [
                    {
                        "PolicyName": "ReadOnly",
                        "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    },
                ]
            }
        ]
        actions = []
        _detach_managed_policies(iam, "jane", actions)

        iam.detach_user_policy.assert_called_once()
        assert len(actions) == 1

    def test_delete_inline_policies(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {"PolicyNames": ["custom-policy-1", "custom-policy-2"]}
        ]
        actions = []
        _delete_inline_policies(iam, "jane", actions)

        assert iam.delete_user_policy.call_count == 2
        assert len(actions) == 2

    def test_delete_mfa_devices(self):
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [
            {
                "MFADevices": [
                    {"SerialNumber": "arn:aws:iam::123:mfa/jane"},
                ]
            }
        ]
        actions = []
        _delete_mfa_devices(iam, "jane", actions)

        iam.deactivate_mfa_device.assert_called_once()
        iam.delete_virtual_mfa_device.assert_called_once()
        assert len(actions) == 1


class TestWorkerHandler:
    """Test the full worker Lambda handler."""

    @patch("lambda_worker.handler._save_checkpoint")
    @patch(
        "lambda_worker.handler._load_checkpoint",
        return_value={
            "status": "new",
            "actions_taken": [],
            "completed_steps": [],
            "updated_at": "",
        },
    )
    @patch("lambda_worker.handler._write_audit")
    @patch("lambda_worker.handler._get_iam_client")
    def test_successful_remediation(
        self, mock_iam, mock_audit, _mock_load_checkpoint, mock_save_checkpoint
    ):
        """Full remediation flow for a standard terminated employee."""
        iam = MagicMock()
        mock_iam.return_value = iam

        # Mock all pagination as empty (no keys, groups, policies, etc.)
        iam.get_paginator.return_value.paginate.return_value = [
            {"AccessKeyMetadata": []},
        ]
        iam.get_paginator.return_value.paginate.return_value = [{}]

        # Simplify — mock each paginator to return empty
        def mock_paginate(*args, **kwargs):
            paginator = MagicMock()
            paginator.paginate.return_value = iter(
                [
                    {
                        "AccessKeyMetadata": [],
                        "Groups": [],
                        "AttachedPolicies": [],
                        "PolicyNames": [],
                        "MFADevices": [],
                        "Certificates": [],
                        "SSHPublicKeys": [],
                    }
                ]
            )
            return paginator

        iam.get_paginator.side_effect = mock_paginate
        iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
        iam.exceptions.NoSuchEntityException = type("E", (Exception,), {})
        iam.delete_login_profile.side_effect = iam.exceptions.NoSuchEntityException()

        result = handler(_make_event(), None)

        assert result["status"] == "remediated"
        assert result["iam_username"] == "jane"
        assert result["account_id"] == "123456789012"
        iam.delete_user.assert_called_once_with(UserName="jane")
        mock_audit.assert_called_once()
        assert mock_save_checkpoint.call_count >= 2

    @patch("lambda_worker.handler._save_checkpoint")
    @patch(
        "lambda_worker.handler._load_checkpoint",
        return_value={
            "status": "new",
            "actions_taken": [],
            "completed_steps": [],
            "updated_at": "",
        },
    )
    @patch("lambda_worker.handler._write_audit")
    @patch("lambda_worker.handler._get_iam_client")
    def test_remediation_failure_logged(
        self, mock_iam, mock_audit, _mock_load_checkpoint, mock_save_checkpoint
    ):
        """If remediation fails, error is captured and audit still written."""
        mock_iam.side_effect = Exception("AssumeRole denied")

        result = handler(_make_event(), None)

        assert result["status"] == "error"
        assert "AssumeRole denied" in result["error"]
        mock_audit.assert_called_once()  # Audit still written on failure
        mock_save_checkpoint.assert_called()

    @patch("lambda_worker.handler._save_checkpoint")
    @patch("lambda_worker.handler._write_audit")
    def test_invalid_payload_rejected_before_remediation(self, mock_audit, mock_save_checkpoint):
        result = handler(_make_event(account_id="not-an-account"), None)

        assert result["status"] == "error"
        assert result["error"] == "Invalid remediation payload"
        mock_audit.assert_called_once()
        mock_save_checkpoint.assert_not_called()

    def test_audit_record_captures_caller_and_approval_context(self, monkeypatch):
        class _Context:
            aws_request_id = "req-123"

        monkeypatch.setenv("SKILL_CALLER_ID", "u-123")
        monkeypatch.setenv("SKILL_CALLER_EMAIL", "user@example.com")
        monkeypatch.setenv("SKILL_SESSION_ID", "sess-1")
        monkeypatch.setenv("SKILL_CALLER_ROLES", "security_engineer")
        monkeypatch.setenv("SKILL_APPROVER_ID", "a-456")
        monkeypatch.setenv("SKILL_APPROVER_EMAIL", "approver@example.com")
        monkeypatch.setenv("SKILL_APPROVAL_TICKET", "SEC-123")
        monkeypatch.setenv("SKILL_APPROVAL_TIMESTAMP", "2026-04-14T12:00:00Z")

        record = _build_audit_record(_make_event()["entry"], [], "remediated", context=_Context())

        assert record["invoked_by"] == "u-123"
        assert record["invoked_by_email"] == "user@example.com"
        assert record["agent_session_id"] == "sess-1"
        assert record["caller_roles"] == "security_engineer"
        assert record["approved_by"] == "a-456"
        assert record["approved_by_email"] == "approver@example.com"
        assert record["approval_ticket"] == "SEC-123"
        assert record["approval_timestamp"] == "2026-04-14T12:00:00Z"
        assert record["lambda_request_id"] == "req-123"

    @patch("lambda_worker.handler._save_checkpoint")
    @patch(
        "lambda_worker.handler._load_checkpoint",
        return_value={
            "status": "in_progress",
            "actions_taken": [
                {
                    "action": "delete_user",
                    "target": "jane",
                    "timestamp": "2026-04-17T00:00:00+00:00",
                }
            ],
            "completed_steps": [
                "deactivate_access_keys",
                "delete_login_profile",
                "remove_from_groups",
                "detach_managed_policies",
                "delete_inline_policies",
                "delete_mfa_devices",
                "delete_signing_certificates",
                "delete_ssh_keys",
                "delete_service_credentials",
                "tag_user_for_audit",
                "delete_user",
            ],
            "updated_at": "2026-04-17T00:00:00+00:00",
        },
    )
    @patch("lambda_worker.handler._write_audit")
    @patch("lambda_worker.handler._get_iam_client")
    def test_replay_after_delete_user_skips_delete_step(
        self,
        mock_iam,
        mock_audit,
        _mock_load_checkpoint,
        mock_save_checkpoint,
    ):
        iam = MagicMock()
        mock_iam.return_value = iam

        result = handler(_make_event(), None)

        assert result["status"] == "remediated"
        iam.delete_user.assert_not_called()
        mock_audit.assert_called_once()
        mock_save_checkpoint.assert_called()

    @patch("lambda_worker.handler._write_audit")
    @patch("lambda_worker.handler._get_iam_client")
    @patch(
        "lambda_worker.handler._load_checkpoint",
        return_value={
            "status": "remediated",
            "actions_taken": [
                {
                    "action": "delete_user",
                    "target": "jane",
                    "timestamp": "2026-04-17T00:00:00+00:00",
                }
            ],
            "completed_steps": ["delete_user"],
            "updated_at": "2026-04-17T00:00:00+00:00",
        },
    )
    def test_remediated_checkpoint_short_circuits(self, mock_load_checkpoint, mock_iam, mock_audit):
        result = handler(_make_event(), None)

        assert result["status"] == "remediated"
        assert result["checkpoint_reused"] is True
        mock_iam.assert_not_called()
        mock_audit.assert_not_called()


class TestCheckpoints:
    def test_checkpoint_pk_uses_account_and_username(self):
        assert _checkpoint_pk(_make_event()["entry"]) == "CHECKPOINT#123456789012#jane"


class TestSnowflakeIdentifierSafety:
    def test_embedded_quotes_are_escaped(self):
        from lambda_worker.clouds.snowflake_user import _quote_identifier

        assert _quote_identifier('jane"ops') == '"jane""ops"'

    def test_newlines_are_rejected(self):
        from lambda_worker.clouds.snowflake_user import _quote_identifier

        with pytest.raises(ValueError, match="Invalid Snowflake identifier"):
            _quote_identifier("bad\nuser")


class TestAuditWriteFailure:
    """Audit writes must not be silently swallowed after a successful IAM delete."""

    def _audit_record(self) -> dict:
        return {
            "account_id": "123456789012",
            "iam_username": "jane",
            "audit_timestamp": "2026-04-21T00:00:00+00:00",
            "email": "jane@co.com",
            "actions_taken": [],
        }

    @patch("lambda_worker.handler.boto3")
    def test_write_audit_raises_when_all_stores_fail(self, mock_boto3):
        mock_boto3.resource.return_value.Table.return_value.put_item.side_effect = RuntimeError(
            "ddb down"
        )
        mock_boto3.client.return_value.put_object.side_effect = RuntimeError("s3 down")

        with (
            patch("lambda_worker.handler.AUDIT_TABLE", "t"),
            patch("lambda_worker.handler.AUDIT_BUCKET", "b"),
        ):
            with pytest.raises(AuditWriteError) as excinfo:
                _write_audit(self._audit_record())

        msg = str(excinfo.value)
        assert "dynamodb=" in msg and "s3=" in msg
        assert "jane" in msg and "123456789012" in msg

    @patch("lambda_worker.handler.boto3")
    def test_write_audit_tolerates_one_store_failure(self, mock_boto3):
        """Dual-write redundancy: one store succeeding is still acceptable."""
        mock_boto3.resource.return_value.Table.return_value.put_item.side_effect = RuntimeError(
            "ddb down"
        )
        mock_boto3.client.return_value.put_object.return_value = {}

        with (
            patch("lambda_worker.handler.AUDIT_TABLE", "t"),
            patch("lambda_worker.handler.AUDIT_BUCKET", "b"),
        ):
            # Should not raise — S3 succeeded, so we have durable record.
            _write_audit(self._audit_record())

    @patch("lambda_worker.handler._save_checkpoint")
    @patch(
        "lambda_worker.handler._load_checkpoint",
        return_value={
            "status": "new",
            "actions_taken": [],
            "completed_steps": [],
            "updated_at": "",
        },
    )
    @patch("lambda_worker.handler._remediation_steps", return_value=[])
    @patch("lambda_worker.handler._get_iam_client")
    @patch("lambda_worker.handler._write_audit", side_effect=AuditWriteError("all stores failed"))
    def test_handler_returns_audit_failed_status_when_audit_raises(
        self,
        _mock_audit,
        _mock_iam,
        _mock_steps,
        _mock_load,
        _mock_save,
    ):
        """After IAM deletion, an AuditWriteError must surface in the response
        as a distinct status — not be hidden behind a generic 'error' status
        (which would imply IAM was NOT changed) or silently ignored."""
        result = handler(_make_event(), None)

        assert result["status"] == "remediated_audit_failed"
        assert "audit_error" in result
        assert "all stores failed" in result["audit_error"]

    @patch("lambda_worker.handler._save_checkpoint")
    @patch(
        "lambda_worker.handler._load_checkpoint",
        return_value={
            "status": "new",
            "actions_taken": [],
            "completed_steps": [],
            "updated_at": "",
        },
    )
    @patch("lambda_worker.handler._remediation_steps", return_value=[])
    @patch("lambda_worker.handler.boto3")
    @patch("lambda_worker.handler._get_iam_client")
    def test_get_iam_client_embeds_request_id_in_session_name(
        self,
        mock_get_iam,
        _mock_boto3,
        _mock_steps,
        _mock_load,
        _mock_save,
    ):
        """STS RoleSessionName must include the Lambda request id for audit correlation."""
        ctx = MagicMock()
        ctx.aws_request_id = "abcd1234-ef56-7890-abcd-1234567890ab"
        handler(_make_event(), ctx)
        # The handler calls _get_iam_client(account_id, request_id=...)
        mock_get_iam.assert_called_once()
        _args, kwargs = mock_get_iam.call_args
        assert kwargs.get("request_id") == "abcd1234-ef56-7890-abcd-1234567890ab"
