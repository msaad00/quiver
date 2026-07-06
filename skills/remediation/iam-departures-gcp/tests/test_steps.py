"""Tests for the 11 GCP teardown step functions."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

# Mock googleapiclient before steps imports run.
sys.modules.setdefault("googleapiclient", types.ModuleType("googleapiclient"))
sys.modules.setdefault("googleapiclient.discovery", types.SimpleNamespace(build=MagicMock()))
sys.modules.setdefault(
    "googleapiclient.http", types.SimpleNamespace(MediaInMemoryUpload=MagicMock())
)

from cloud_function_worker import steps  # noqa: E402


def _entry(**overrides):
    base = {
        "email": "jane@acme.example",
        "principal_type": "workspace_user",
        "principal_id": "jane@acme.example",
        "gcp_org_id": "111122223333",
        "project_ids": ["acme-prod"],
        "folder_ids": [],
        "terminated_at": "2026-04-01T17:00:00+00:00",
        "termination_source": "bigquery",
    }
    base.update(overrides)
    return base


class TestProtectedPrincipals:
    def test_super_admin_user_protected(self):
        assert steps.is_protected_principal("workspace_user", "super-admin@acme.example") is True

    def test_break_glass_user_protected(self):
        assert steps.is_protected_principal("workspace_user", "break-glass-1@acme.example") is True

    def test_emergency_user_protected(self):
        assert steps.is_protected_principal("workspace_user", "emergency-bob@acme.example") is True

    def test_terraform_sa_protected(self):
        assert (
            steps.is_protected_principal(
                "service_account", "terraform-cd@acme-prod.iam.gserviceaccount.com"
            )
            is True
        )

    def test_normal_user_not_protected(self):
        assert steps.is_protected_principal("workspace_user", "jane@acme.example") is False

    def test_assert_raises_for_protected(self):
        with pytest.raises(steps.ProtectedPrincipalError, match="protected principal"):
            steps.assert_not_protected("workspace_user", "break-glass-1@acme.example")

    def test_assert_no_error_for_normal(self):
        # No exception
        steps.assert_not_protected("workspace_user", "jane@acme.example")


class TestStepsBranching:
    def test_pre_disable_workspace_user_calls_users_update(self):
        clients = MagicMock()
        actions: list = []
        steps.step_pre_disable(clients, _entry(), actions)
        clients.admin_directory.users.return_value.update.assert_called_once()
        assert actions[0]["action"] == "suspend_workspace_user"

    def test_pre_disable_service_account_calls_disable(self):
        clients = MagicMock()
        actions: list = []
        steps.step_pre_disable(
            clients,
            _entry(
                principal_type="service_account",
                principal_id="ci@acme-prod.iam.gserviceaccount.com",
            ),
            actions,
        )
        clients.iam.projects.return_value.serviceAccounts.return_value.disable.assert_called_once()
        assert actions[0]["action"] == "disable_service_account"

    def test_revoke_oauth_skipped_for_sa(self):
        clients = MagicMock()
        actions: list = []
        steps.step_revoke_oauth_tokens(
            clients,
            _entry(
                principal_type="service_account",
                principal_id="ci@acme-prod.iam.gserviceaccount.com",
            ),
            actions,
        )
        assert actions[0]["skipped"] == "n/a-for-service-account"

    def test_revoke_oauth_lists_and_deletes_tokens(self):
        clients = MagicMock()
        clients.admin_directory.tokens.return_value.list.return_value.execute.return_value = {
            "items": [{"clientId": "cid-1"}, {"clientId": "cid-2"}]
        }
        actions: list = []
        steps.step_revoke_oauth_tokens(clients, _entry(), actions)
        # Two delete calls
        assert clients.admin_directory.tokens.return_value.delete.call_count == 2
        assert actions[0]["count"] == 2

    def test_detach_project_iam_strips_member(self):
        clients = MagicMock()
        clients.crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:jane@acme.example", "user:bob@acme.example"],
                },
                {"role": "roles/editor", "members": ["user:bob@acme.example"]},
            ]
        }
        actions: list = []
        steps.step_detach_project_iam(clients, _entry(), actions)
        # setIamPolicy was called once with member removed
        set_call = clients.crm.projects.return_value.setIamPolicy.call_args
        new_policy = set_call.kwargs["body"]["policy"]
        viewer_binding = next(b for b in new_policy["bindings"] if b["role"] == "roles/viewer")
        assert "user:jane@acme.example" not in viewer_binding["members"]
        assert actions[0]["count"] == 1

    def test_detach_org_iam_no_op_when_member_absent(self):
        clients = MagicMock()
        clients.crm.organizations.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [{"role": "roles/viewer", "members": ["user:bob@acme.example"]}]
        }
        actions: list = []
        steps.step_detach_org_iam(clients, _entry(), actions)
        clients.crm.organizations.return_value.setIamPolicy.assert_not_called()
        assert actions[0]["count"] == 0

    def test_delete_ssh_keys_filters_metadata(self):
        clients = MagicMock()
        clients.compute.projects.return_value.get.return_value.execute.return_value = {
            "commonInstanceMetadata": {
                "fingerprint": "abc",
                "items": [
                    {
                        "key": "ssh-keys",
                        "value": "jane:ssh-rsa AAA jane@host\nbob:ssh-rsa BBB bob@host",
                    }
                ],
            }
        }
        actions: list = []
        steps.step_delete_ssh_keys(clients, _entry(), actions)
        assert clients.compute.projects.return_value.setCommonInstanceMetadata.called
        assert actions[0]["count"] == 1

    def test_revoke_storage_iam_skips_buckets_without_member(self):
        clients = MagicMock()
        clients.storage.buckets.return_value.list.return_value.execute.return_value = {
            "items": [{"name": "bucket-a"}, {"name": "bucket-b"}]
        }
        clients.storage.buckets.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["user:jane@acme.example"]}
            ]
        }
        actions: list = []
        steps.step_revoke_storage_iam(clients, _entry(), actions)
        # Two buckets, both had jane → setIamPolicy called twice
        assert clients.storage.buckets.return_value.setIamPolicy.call_count == 2
        assert actions[0]["buckets"] == 2

    def test_emit_audit_log_writes_entry(self):
        clients = MagicMock()
        actions: list = []
        steps.step_emit_audit_log(clients, _entry(), actions)
        clients.logging.entries.return_value.write.assert_called_once()
        body = clients.logging.entries.return_value.write.call_args.kwargs["body"]
        assert body["entries"][0]["jsonPayload"]["principal_id"] == "jane@acme.example"

    def test_final_disable_or_delete_workspace_user(self):
        clients = MagicMock()
        actions: list = []
        steps.step_final_disable_or_delete(clients, _entry(), actions)
        clients.admin_directory.users.return_value.delete.assert_called_once_with(
            userKey="jane@acme.example"
        )
        assert actions[0]["action"] == "delete_workspace_user"

    def test_final_disable_or_delete_service_account_drops_keys_first(self):
        clients = MagicMock()
        clients.iam.projects.return_value.serviceAccounts.return_value.keys.return_value.list.return_value.execute.return_value = {
            "keys": [
                {"name": "k-user-1", "keyType": "USER_MANAGED"},
                {"name": "k-system-1", "keyType": "SYSTEM_MANAGED"},  # cannot delete
            ]
        }
        actions: list = []
        steps.step_final_disable_or_delete(
            clients,
            _entry(
                principal_type="service_account",
                principal_id="ci@acme-prod.iam.gserviceaccount.com",
            ),
            actions,
        )
        # Only the USER_MANAGED key was deleted, then the SA itself.
        clients.iam.projects.return_value.serviceAccounts.return_value.keys.return_value.delete.assert_called_once_with(
            name="k-user-1"
        )
        clients.iam.projects.return_value.serviceAccounts.return_value.delete.assert_called_once()
        assert actions[0]["action"] == "delete_service_account"

    def test_strip_member_from_policy_drops_empty_bindings(self):
        policy = {
            "bindings": [
                {"role": "roles/viewer", "members": ["user:jane@acme.example"]},
                {
                    "role": "roles/editor",
                    "members": ["user:bob@acme.example", "user:jane@acme.example"],
                },
            ]
        }
        new_policy, removed = steps._strip_member_from_policy(policy, "user:jane@acme.example")
        assert removed == 2
        assert len(new_policy["bindings"]) == 1
        assert new_policy["bindings"][0]["role"] == "roles/editor"


class TestStepRegistry:
    def test_eleven_steps_in_order(self):
        names = [name for name, _ in steps.remediation_steps()]
        expected = [
            "pre_disable",
            "revoke_oauth_tokens",
            "delete_ssh_keys",
            "remove_from_groups",
            "detach_project_iam",
            "detach_folder_iam",
            "detach_org_iam",
            "detach_bigquery_iam",
            "revoke_storage_iam",
            "emit_audit_log",
            "final_disable_or_delete",
        ]
        assert names == expected
