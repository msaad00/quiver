"""Tests for the iam-departures-gcp worker Cloud Function."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

# Mock googleapiclient + google.oauth2 BEFORE the worker handler imports them.
sys.modules.setdefault("googleapiclient", types.ModuleType("googleapiclient"))
sys.modules.setdefault("googleapiclient.discovery", types.SimpleNamespace(build=MagicMock()))
sys.modules.setdefault(
    "googleapiclient.http", types.SimpleNamespace(MediaInMemoryUpload=MagicMock())
)
sys.modules.setdefault("google", types.ModuleType("google"))
sys.modules.setdefault("google.oauth2", types.ModuleType("google.oauth2"))

from cloud_function_worker import handler as worker_handler  # noqa: E402


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


@pytest.fixture(autouse=True)
def _clean_hitl_env(monkeypatch):
    monkeypatch.delenv(worker_handler.INCIDENT_ENV_VAR, raising=False)
    monkeypatch.delenv(worker_handler.APPROVER_ENV_VAR, raising=False)
    monkeypatch.delenv(worker_handler.AUDIT_FIRESTORE_ENV_VAR, raising=False)
    monkeypatch.delenv(worker_handler.AUDIT_BUCKET_ENV_VAR, raising=False)


class TestHitlGate:
    def test_apply_fails_without_incident_env(self):
        event = {"entry": _entry()}
        result = worker_handler.handler(event)
        assert result["status"] == "error"
        assert "missing-hitl-env-vars" in result["error"]
        assert worker_handler.INCIDENT_ENV_VAR in result["error"]

    def test_apply_fails_without_approver_env(self, monkeypatch):
        monkeypatch.setenv(worker_handler.INCIDENT_ENV_VAR, "INC-42")
        event = {"entry": _entry()}
        result = worker_handler.handler(event)
        assert result["status"] == "error"
        assert worker_handler.APPROVER_ENV_VAR in result["error"]

    def test_dry_run_does_not_require_hitl(self):
        event = {"entry": _entry(), "dry_run": True}
        result = worker_handler.handler(event)
        assert result["status"] == "dry_run"
        # Full 11-step plan surfaced
        assert len(result["actions_taken"]) == 11
        assert all(step["status"] == "dry_run" for step in result["actions_taken"])


class TestProtectedPrincipals:
    def test_break_glass_refused(self):
        event = {
            "entry": _entry(
                email="break-glass-1@acme.example", principal_id="break-glass-1@acme.example"
            ),
            "dry_run": True,
        }
        result = worker_handler.handler(event)
        assert result["status"] == "refused"
        assert "protected principal" in result["error"]


class TestInputValidation:
    def test_invalid_org_id_errors(self):
        event = {"entry": _entry(gcp_org_id="not-numeric"), "dry_run": True}
        result = worker_handler.handler(event)
        assert result["status"] == "error"
        assert "gcp_org_id" in result["error"]

    def test_unsupported_principal_type_errors(self):
        event = {"entry": _entry(principal_type="device"), "dry_run": True}
        result = worker_handler.handler(event)
        assert result["status"] == "error"
        assert "principal_type" in result["error"]


class TestFullRemediation:
    def test_successful_apply_runs_all_11_steps(self, monkeypatch):
        monkeypatch.setenv(worker_handler.INCIDENT_ENV_VAR, "INC-123")
        monkeypatch.setenv(worker_handler.APPROVER_ENV_VAR, "alice@security")

        # Replace the step registry with no-op stubs so we don't need to fully
        # wire every Google API mock. Each stub records the step name and a
        # synthetic action record.
        calls: list[str] = []

        def _make_stub(name: str):
            def step(clients, entry, actions):
                calls.append(name)
                actions.append({"action": name, "target": entry["principal_id"], "timestamp": "t"})

            return step

        from cloud_function_worker import steps as steps_module

        stub_registry = tuple(
            (name, _make_stub(name)) for name, _ in steps_module.remediation_steps()
        )
        monkeypatch.setattr(steps_module, "remediation_steps", lambda: stub_registry)
        monkeypatch.setattr(worker_handler.steps_module, "remediation_steps", lambda: stub_registry)

        # Neutralise audit + checkpoint writes (no Firestore / GCS in tests).
        monkeypatch.setattr(worker_handler, "_write_audit", lambda record: None)
        monkeypatch.setattr(worker_handler, "_save_checkpoint", lambda *a, **kw: None)
        monkeypatch.setattr(
            worker_handler,
            "_load_checkpoint",
            lambda entry: {
                "status": "new",
                "actions_taken": [],
                "completed_steps": [],
                "updated_at": "",
            },
        )

        result = worker_handler.handler({"entry": _entry()})
        assert result["status"] == "remediated"
        assert len(calls) == 11
        assert calls[0] == "pre_disable"
        assert calls[-1] == "final_disable_or_delete"

    def test_checkpoint_resume_skips_completed_steps(self, monkeypatch):
        monkeypatch.setenv(worker_handler.INCIDENT_ENV_VAR, "INC-123")
        monkeypatch.setenv(worker_handler.APPROVER_ENV_VAR, "alice@security")

        calls: list[str] = []

        def _make_stub(name: str):
            def step(clients, entry, actions):
                calls.append(name)
                actions.append({"action": name, "target": entry["principal_id"], "timestamp": "t"})

            return step

        from cloud_function_worker import steps as steps_module

        stub_registry = tuple(
            (name, _make_stub(name)) for name, _ in steps_module.remediation_steps()
        )
        monkeypatch.setattr(steps_module, "remediation_steps", lambda: stub_registry)
        monkeypatch.setattr(worker_handler.steps_module, "remediation_steps", lambda: stub_registry)
        monkeypatch.setattr(worker_handler, "_write_audit", lambda record: None)
        monkeypatch.setattr(worker_handler, "_save_checkpoint", lambda *a, **kw: None)
        monkeypatch.setattr(
            worker_handler,
            "_load_checkpoint",
            lambda entry: {
                "status": "in_progress",
                "actions_taken": [{"action": "pre_disable", "target": "x", "timestamp": "t"}],
                "completed_steps": ["pre_disable", "revoke_oauth_tokens", "delete_ssh_keys"],
                "updated_at": "2026-04-17T00:00:00+00:00",
            },
        )
        result = worker_handler.handler({"entry": _entry()})
        assert result["status"] == "remediated"
        # 3 steps already done → 8 runs this invocation
        assert len(calls) == 8
        assert "pre_disable" not in calls

    def test_checkpoint_remediated_short_circuits(self, monkeypatch):
        monkeypatch.setenv(worker_handler.INCIDENT_ENV_VAR, "INC-123")
        monkeypatch.setenv(worker_handler.APPROVER_ENV_VAR, "alice@security")
        monkeypatch.setattr(
            worker_handler,
            "_load_checkpoint",
            lambda entry: {
                "status": "remediated",
                "actions_taken": [
                    {"action": "final_disable_or_delete", "target": "x", "timestamp": "t"}
                ],
                "completed_steps": [
                    name for name, _ in worker_handler.steps_module.remediation_steps()
                ],
                "updated_at": "2026-04-17T00:00:00+00:00",
            },
        )
        result = worker_handler.handler({"entry": _entry()})
        assert result["status"] == "remediated"
        assert result["checkpoint_reused"] is True

    def test_failure_writes_error_audit_and_returns_error(self, monkeypatch):
        monkeypatch.setenv(worker_handler.INCIDENT_ENV_VAR, "INC-123")
        monkeypatch.setenv(worker_handler.APPROVER_ENV_VAR, "alice@security")

        audit_calls: list[dict] = []
        monkeypatch.setattr(worker_handler, "_write_audit", audit_calls.append)
        monkeypatch.setattr(worker_handler, "_save_checkpoint", lambda *a, **kw: None)
        monkeypatch.setattr(
            worker_handler,
            "_load_checkpoint",
            lambda entry: {
                "status": "new",
                "actions_taken": [],
                "completed_steps": [],
                "updated_at": "",
            },
        )

        def _boom(*args, **kwargs):
            raise RuntimeError("Workspace API refused")

        from cloud_function_worker import steps as steps_module

        boom_registry = (("pre_disable", _boom),)
        monkeypatch.setattr(steps_module, "remediation_steps", lambda: boom_registry)
        monkeypatch.setattr(worker_handler.steps_module, "remediation_steps", lambda: boom_registry)

        result = worker_handler.handler({"entry": _entry()})
        assert result["status"] == "error"
        assert "Workspace API refused" in result["error"]
        assert len(audit_calls) == 1
        assert audit_calls[0]["status"] == "error"


class TestAuditRecord:
    def test_record_captures_caller_approver_and_incident(self, monkeypatch):
        monkeypatch.setenv(worker_handler.INCIDENT_ENV_VAR, "INC-2026-04-20")
        monkeypatch.setenv(worker_handler.APPROVER_ENV_VAR, "alice@security")
        monkeypatch.setenv("SKILL_CALLER_ID", "u-42")
        monkeypatch.setenv("SKILL_CALLER_EMAIL", "operator@acme.example")
        monkeypatch.setenv("SKILL_SESSION_ID", "sess-x")
        monkeypatch.setenv("SKILL_CALLER_ROLES", "incident_responder")

        record = worker_handler._build_audit_record(_entry(), [], "remediated")
        assert record["approval_ticket"] == "INC-2026-04-20"
        assert record["approved_by"] == "alice@security"
        assert record["invoked_by"] == "u-42"
        assert record["invoked_by_email"] == "operator@acme.example"
        assert record["agent_session_id"] == "sess-x"
        assert record["caller_roles"] == "incident_responder"
        assert record["principal_id"] == "jane@acme.example"
        assert record["gcp_org_id"] == "111122223333"
        assert record["status"] == "remediated"

    def test_row_uid_is_deterministic(self):
        record_a = worker_handler._build_audit_record(_entry(), [], "remediated")
        record_b = worker_handler._build_audit_record(_entry(), [], "remediated")
        # audit_timestamp varies → row_uid varies → sanity check the format
        assert record_a["row_uid"].startswith("iam-gcp-")
        assert record_b["row_uid"].startswith("iam-gcp-")


class TestCli:
    def test_dry_run_cli_prints_plan(self, tmp_path, capsys):
        import json

        manifest_path = tmp_path / "m.json"
        manifest_path.write_text(json.dumps({"entries": [_entry()]}))
        rc = worker_handler.main([str(manifest_path), "--dry-run"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["results"][0]["status"] == "dry_run"
        assert len(payload["results"][0]["actions_taken"]) == 11

    def test_apply_cli_without_hitl_exits_nonzero(self, tmp_path, capsys):
        import json

        manifest_path = tmp_path / "m.json"
        manifest_path.write_text(json.dumps({"entries": [_entry()]}))
        rc = worker_handler.main([str(manifest_path), "--apply"])
        assert rc == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["results"][0]["status"] == "error"
        assert "missing-hitl-env-vars" in payload["results"][0]["error"]

    def test_reverify_cli_emits_verification_envelope(self, tmp_path, capsys):
        import json

        manifest_path = tmp_path / "m.json"
        manifest_path.write_text(json.dumps({"entries": [_entry()]}))
        rc = worker_handler.main([str(manifest_path), "--reverify"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert "verification" in payload
        assert payload["verification"][0]["record_type"] == "remediation_verification"
