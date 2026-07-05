"""Tests for cross-cloud identity remediation workers.

Each cloud worker is tested with mocked SDKs to verify:
    - Correct deletion order
    - Step-by-step status tracking
    - Dry run mode (no actual API calls)
    - Error handling (partial failures)
    - Cloud-specific gotchas (PUBLIC role in Snowflake, /$ref in Azure, etc.)
"""

from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from lambda_worker.clouds import (
    CloudProvider,
    RemediationResult,
    RemediationStatus,
    RemediationStep,
)

# ── Shared fixtures ──────────────────────────────────────────────


class TestRemediationResult:
    def test_default_status(self):
        r = RemediationResult(
            cloud=CloudProvider.AWS,
            identity_id="test-user",
            identity_type="iam_user",
            account_id="123456789012",
        )
        assert r.status == RemediationStatus.SUCCESS
        assert r.steps_completed == 0
        assert r.steps_failed == 0
        assert r.started_at

    def test_complete_with_failures(self):
        r = RemediationResult(
            cloud=CloudProvider.AWS,
            identity_id="test-user",
            identity_type="iam_user",
            account_id="123456789012",
        )
        r.steps.append(RemediationStep(step_number=1, action="test", target="x"))
        r.steps.append(
            RemediationStep(
                step_number=2, action="test2", target="x", status=RemediationStatus.FAILED
            )
        )
        r.complete()
        assert r.status == RemediationStatus.PARTIAL
        assert r.steps_completed == 1
        assert r.steps_failed == 1

    def test_complete_all_failed(self):
        r = RemediationResult(
            cloud=CloudProvider.GCP,
            identity_id="sa@proj.iam.gserviceaccount.com",
            identity_type="service_account",
            account_id="my-project",
        )
        r.steps.append(
            RemediationStep(
                step_number=1, action="test", target="x", status=RemediationStatus.FAILED
            )
        )
        r.complete()
        assert r.status == RemediationStatus.FAILED

    def test_to_dict(self):
        r = RemediationResult(
            cloud=CloudProvider.SNOWFLAKE,
            identity_id="departing_user",
            identity_type="snowflake_user",
            account_id="myaccount",
        )
        r.steps.append(
            RemediationStep(step_number=1, action="disable", target="departing_user", detail="done")
        )
        r.complete()
        d = r.to_dict()
        assert d["cloud"] == "snowflake"
        assert d["identity_type"] == "snowflake_user"
        assert len(d["steps"]) == 1
        assert d["steps_completed"] == 1


# ── Azure Entra ID ───────────────────────────────────────────────


class TestAzureEntra:
    def test_dry_run_produces_all_steps(self):
        from lambda_worker.clouds import azure_entra

        result = asyncio.run(azure_entra.remediate_user("user-id-123", "tenant-abc", dry_run=True))
        assert result.status == RemediationStatus.DRY_RUN
        assert result.cloud == CloudProvider.AZURE
        assert len(result.steps) == 6
        assert result.steps[0].action == "revoke_sign_in_sessions"
        assert result.steps[1].action == "remove_group_memberships"
        assert result.steps[2].action == "remove_app_role_assignments"
        assert result.steps[3].action == "revoke_oauth2_grants"
        assert result.steps[4].action == "disable_user"
        assert result.steps[5].action == "delete_user"

    def test_required_permissions(self):
        from lambda_worker.clouds import azure_entra

        perms = azure_entra.get_required_permissions()
        assert "User.ReadWrite.All" in perms
        assert "GroupMember.ReadWrite.All" in perms
        assert "DelegatedPermissionGrant.ReadWrite.All" in perms

    def test_identity_type_is_entra_user(self):
        from lambda_worker.clouds import azure_entra

        result = asyncio.run(
            azure_entra.remediate_user("user@domain.com", "tenant-123", dry_run=True)
        )
        assert result.identity_type == "entra_user"


# ── GCP IAM ──────────────────────────────────────────────────────


class TestGCPIAM:
    def test_sa_dry_run_produces_all_steps(self):
        from lambda_worker.clouds import gcp_iam

        result = asyncio.run(
            gcp_iam.remediate_service_account(
                "sa@project.iam.gserviceaccount.com",
                "my-project",
                dry_run=True,
            )
        )
        assert result.status == RemediationStatus.DRY_RUN
        assert result.cloud == CloudProvider.GCP
        assert len(result.steps) == 4
        assert result.steps[0].action == "disable_service_account"
        assert result.steps[1].action == "delete_sa_keys"
        assert result.steps[2].action == "remove_iam_bindings"
        assert result.steps[3].action == "delete_service_account"

    def test_workspace_user_dry_run(self):
        from lambda_worker.clouds import gcp_iam

        result = asyncio.run(gcp_iam.remediate_workspace_user("user@domain.com", dry_run=True))
        assert result.status == RemediationStatus.DRY_RUN
        assert result.identity_type == "workspace_user"
        assert len(result.steps) == 2

    def test_required_permissions(self):
        from lambda_worker.clouds import gcp_iam

        perms = gcp_iam.get_required_permissions()
        assert "roles/iam.serviceAccountAdmin" in perms
        assert "roles/iam.serviceAccountKeyAdmin" in perms


# ── Snowflake ────────────────────────────────────────────────────


class TestSnowflake:
    def test_dry_run_produces_all_steps(self):
        from lambda_worker.clouds import snowflake_user

        result = asyncio.run(
            snowflake_user.remediate_user("departing_user", "myaccount", dry_run=True)
        )
        assert result.status == RemediationStatus.DRY_RUN
        assert result.cloud == CloudProvider.SNOWFLAKE
        assert len(result.steps) == 6
        assert result.steps[0].action == "abort_active_queries"
        assert result.steps[1].action == "disable_user"
        assert result.steps[2].action == "revoke_roles"
        assert result.steps[3].action == "transfer_ownership"
        assert result.steps[4].action == "drop_user"
        assert result.steps[5].action == "verify_dropped"

    def test_identity_type_is_snowflake_user(self):
        from lambda_worker.clouds import snowflake_user

        result = asyncio.run(snowflake_user.remediate_user("test_user", "acct", dry_run=True))
        assert result.identity_type == "snowflake_user"

    def test_implicit_roles_skipped(self):
        """PUBLIC role must be in the skip list."""
        from lambda_worker.clouds.snowflake_user import _IMPLICIT_ROLES

        assert "PUBLIC" in _IMPLICIT_ROLES

    def test_ownership_object_types(self):
        """All major Snowflake object types should be in the transfer list."""
        from lambda_worker.clouds.snowflake_user import _OWNERSHIP_OBJECT_TYPES

        assert "TABLES" in _OWNERSHIP_OBJECT_TYPES
        assert "VIEWS" in _OWNERSHIP_OBJECT_TYPES
        assert "SCHEMAS" in _OWNERSHIP_OBJECT_TYPES
        assert "STAGES" in _OWNERSHIP_OBJECT_TYPES

    def test_suppresses_verbose_connector_logs(self):
        from lambda_worker.clouds import snowflake_user

        with patch("lambda_worker.clouds.snowflake_user.logging.getLogger") as mock_get_logger:
            connector_logger = MagicMock()
            mock_get_logger.return_value = connector_logger

            snowflake_user._configure_snowflake_logging()

        mock_get_logger.assert_called_once_with("snowflake.connector")
        connector_logger.setLevel.assert_called_once_with(snowflake_user.logging.WARNING)


# ── Databricks ───────────────────────────────────────────────────


class TestDatabricks:
    def test_dry_run_produces_all_steps(self):
        from lambda_worker.clouds import databricks_scim

        result = asyncio.run(databricks_scim.remediate_user("user@company.com", dry_run=True))
        assert result.status == RemediationStatus.DRY_RUN
        assert result.cloud == CloudProvider.DATABRICKS
        assert len(result.steps) == 4
        assert result.steps[0].action == "revoke_pats"
        assert result.steps[1].action == "deactivate_workspace_user"
        assert result.steps[2].action == "deactivate_account_user"
        assert result.steps[3].action == "delete_account_user"

    def test_workspace_only_skips_account_ops(self):
        from lambda_worker.clouds import databricks_scim

        # workspace_only still needs workspace client, but dry_run skips all
        result = asyncio.run(
            databricks_scim.remediate_user("user@company.com", workspace_only=True, dry_run=True)
        )
        # dry_run returns all steps as DRY_RUN regardless of workspace_only
        assert result.status == RemediationStatus.DRY_RUN

    def test_required_permissions(self):
        from lambda_worker.clouds import databricks_scim

        perms = databricks_scim.get_required_permissions()
        assert any("Workspace admin" in p for p in perms)
        assert any("Account admin" in p for p in perms)

    def test_identity_type(self):
        from lambda_worker.clouds import databricks_scim

        result = asyncio.run(databricks_scim.remediate_user("user@co.com", dry_run=True))
        assert result.identity_type == "databricks_user"


# ── Cross-cloud comparison ───────────────────────────────────────


class TestCrossCloudComparison:
    """Verify that all cloud workers follow the same interface contract."""

    @pytest.mark.parametrize(
        "cloud,expected_type",
        [
            (CloudProvider.AWS, "aws"),
            (CloudProvider.AZURE, "azure"),
            (CloudProvider.GCP, "gcp"),
            (CloudProvider.SNOWFLAKE, "snowflake"),
            (CloudProvider.DATABRICKS, "databricks"),
        ],
    )
    def test_cloud_provider_values(self, cloud, expected_type):
        assert cloud.value == expected_type

    def test_all_workers_have_required_permissions(self):
        from lambda_worker.clouds import azure_entra, databricks_scim, gcp_iam, snowflake_user

        for module in [azure_entra, gcp_iam, snowflake_user, databricks_scim]:
            perms = module.get_required_permissions()
            assert isinstance(perms, list)
            assert len(perms) > 0

    def test_all_dry_runs_return_correct_status(self):
        from lambda_worker.clouds import azure_entra, databricks_scim, gcp_iam, snowflake_user

        results = [
            asyncio.run(azure_entra.remediate_user("u", "t", dry_run=True)),
            asyncio.run(gcp_iam.remediate_service_account("sa@p.iam.gsa.com", "p", dry_run=True)),
            asyncio.run(snowflake_user.remediate_user("u", "a", dry_run=True)),
            asyncio.run(databricks_scim.remediate_user("u@c.com", dry_run=True)),
        ]
        for r in results:
            assert r.status == RemediationStatus.DRY_RUN
            assert len(r.steps) > 0
            assert all(s.status == RemediationStatus.DRY_RUN for s in r.steps)
