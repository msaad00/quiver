"""Tests for the Entra IAM departures worker handler (orchestrator)."""

from __future__ import annotations

import json
import sys

# Stub Azure SDKs the worker handler lazy-imports.
sys.modules.setdefault("azure", type(sys)("azure"))
for _mod in (
    "azure.identity",
    "azure.mgmt",
    "azure.mgmt.authorization",
    "azure.cosmos",
    "azure.storage",
    "azure.storage.blob",
    "msgraph",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = type(sys)(_mod)

from function_worker import handler as worker_handler  # type: ignore[import-not-found]  # noqa: E402,I001

OBJECT_ID = "aaaaaaaa-1111-1111-1111-111111111111"


class _StubClient:
    """Stub Microsoft Graph + RBAC client for the orchestrator path."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.fail_step: str | None = None

    def _maybe_fail(self, step: str):
        if self.fail_step == step:
            raise RuntimeError(f"step {step} failed")

    def disable_user(self, *, object_id):
        self._maybe_fail("disable_user")
        self.calls.append(("disable_user", {"object_id": object_id}))

    def revoke_signin_sessions(self, *, object_id):
        self._maybe_fail("revoke_signin_sessions")
        self.calls.append(("revoke_signin_sessions", {"object_id": object_id}))

    def list_oauth2_permission_grants(self, *, principal_id):
        return []

    def list_user_groups(self, *, object_id):
        return []

    def list_user_directory_roles(self, *, object_id):
        return []

    def list_user_app_role_assignments(self, *, object_id):
        return []

    def list_role_assignments(self, *, scope_type, principal_id):
        return []

    def list_user_licenses(self, *, object_id):
        return []

    def tag_user(self, *, object_id, tags):
        self._maybe_fail("tag_user")
        self.calls.append(("tag_user", {"object_id": object_id, "tags": tags}))

    def hard_delete_user(self, *, object_id):
        self.calls.append(("hard_delete_user", {"object_id": object_id}))

    def user_exists(self, *, object_id):
        return True

    def get_user_state(self, *, object_id):
        return {"accountEnabled": False}


class _StubAudit:
    def __init__(self):
        self.rows: list[dict] = []

    def record(self, **kwargs):
        self.rows.append(kwargs)
        return {"row_uid": f"row-{len(self.rows)}", "blob_evidence_key": f"k-{len(self.rows)}"}


def _entry(**overrides):
    base = {
        "upn": "alice@acme.example",
        "object_id": OBJECT_ID,
        "terminated_at": "2025-01-01T00:00:00Z",
        "termination_source": "snowflake",
    }
    base.update(overrides)
    return base


def test_dry_run_lists_steps_and_does_not_call_client():
    client = _StubClient()
    config = worker_handler.WorkerConfig(
        apply=False, reverify=False, dry_run=True, hard_delete=False
    )
    out = worker_handler.remediate_one(
        _entry(),
        config=config,
        client=client,
        audit=None,
        incident_id="",
        approver="",
    )
    assert out["status"] == "planned"
    assert "would_take_steps" in out
    assert "disable_user" in out["would_take_steps"]
    assert "final_delete_user" in out["would_take_steps"]
    assert client.calls == []


def test_apply_runs_all_steps_and_writes_dual_audit():
    client = _StubClient()
    audit = _StubAudit()
    config = worker_handler.WorkerConfig(
        apply=True, reverify=False, dry_run=False, hard_delete=False
    )
    out = worker_handler.remediate_one(
        _entry(),
        config=config,
        client=client,
        audit=audit,
        incident_id="INC-1",
        approver="alice@security",
    )
    assert out["status"] == "remediated"
    assert out["completed_steps"] == list(worker_handler.STEP_NAMES)
    # BEFORE + AFTER per step = 22 audit rows total for 11 steps.
    assert len(audit.rows) == 22
    statuses = [r["status"] for r in audit.rows]
    assert statuses.count("in_progress") == 11
    assert statuses.count("success") == 11


def test_apply_failure_writes_failure_audit_and_stops():
    client = _StubClient()
    client.fail_step = "tag_user"
    audit = _StubAudit()
    config = worker_handler.WorkerConfig(
        apply=True, reverify=False, dry_run=False, hard_delete=False
    )
    out = worker_handler.remediate_one(
        _entry(),
        config=config,
        client=client,
        audit=audit,
        incident_id="INC-1",
        approver="alice@security",
    )
    assert out["status"] == "error"
    assert "tag_user" in out["error"] or "tag_user failed" in out["error"]
    # Steps before tag_user (index 9) should be in completed_steps.
    assert "disable_user" in out["completed_steps"]
    assert "tag_user_for_audit" not in out["completed_steps"]
    # The failure path still wrote a failure-audit row.
    assert any(r["status"] == "failure" and r["step"] == "tag_user_for_audit" for r in audit.rows)


def test_protected_principal_refused():
    client = _StubClient()
    out = worker_handler.remediate_one(
        _entry(upn="breakglass-alice@acme.example"),
        config=worker_handler.WorkerConfig(apply=True, dry_run=False),
        client=client,
        audit=_StubAudit(),
        incident_id="INC-1",
        approver="alice@security",
    )
    assert out["status"] == "refused"
    assert "protected" in out["error"].lower()
    assert client.calls == []


def test_extra_protected_object_ids_refused():
    client = _StubClient()
    out = worker_handler.remediate_one(
        _entry(),
        config=worker_handler.WorkerConfig(apply=True, dry_run=False),
        client=client,
        audit=_StubAudit(),
        incident_id="INC-1",
        approver="alice@security",
        extra_protected_object_ids=[OBJECT_ID],
    )
    assert out["status"] == "refused"
    assert client.calls == []


def test_invalid_object_id_errors():
    out = worker_handler.remediate_one(
        _entry(object_id="not-a-guid"),
        config=worker_handler.WorkerConfig(apply=True, dry_run=False),
        client=_StubClient(),
        audit=_StubAudit(),
        incident_id="INC-1",
        approver="a",
    )
    assert out["status"] == "error"


def test_apply_requires_audit_writer():
    out = worker_handler.remediate_one(
        _entry(),
        config=worker_handler.WorkerConfig(apply=True, dry_run=False),
        client=_StubClient(),
        audit=None,
        incident_id="INC-1",
        approver="alice@security",
    )
    assert out["status"] == "error"
    assert "audit writer required" in out["error"]


def test_check_apply_gate_blocks_when_env_unset(monkeypatch):
    monkeypatch.delenv("IAM_DEPARTURES_AZURE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("IAM_DEPARTURES_AZURE_APPROVER", raising=False)
    ok, reason = worker_handler.check_apply_gate()
    assert not ok
    assert "INCIDENT_ID" in reason


def test_check_apply_gate_passes_when_env_set(monkeypatch):
    monkeypatch.setenv("IAM_DEPARTURES_AZURE_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("IAM_DEPARTURES_AZURE_APPROVER", "alice@security")
    ok, reason = worker_handler.check_apply_gate()
    assert ok and reason == ""


def test_reverify_returns_verified_when_user_disabled():
    client = _StubClient()
    out = worker_handler.remediate_one(
        _entry(),
        config=worker_handler.WorkerConfig(reverify=True, dry_run=False),
        client=client,
        audit=None,
        incident_id="",
        approver="",
    )
    assert out["status"] == "verified"


def test_reverify_returns_drift_when_user_enabled():
    client = _StubClient()
    client.get_user_state = lambda *, object_id: {"accountEnabled": True}
    out = worker_handler.remediate_one(
        _entry(),
        config=worker_handler.WorkerConfig(reverify=True, dry_run=False),
        client=client,
        audit=None,
        incident_id="",
        approver="",
    )
    assert out["status"] == "drift"


def test_reverify_returns_unreachable_on_exception():
    client = _StubClient()

    def raiser(**_kwargs):
        raise RuntimeError("graph down")

    client.get_user_state = raiser
    out = worker_handler.remediate_one(
        _entry(),
        config=worker_handler.WorkerConfig(reverify=True, dry_run=False),
        client=client,
        audit=None,
        incident_id="",
        approver="",
    )
    assert out["status"] == "unreachable"


def test_hard_delete_swaps_step_11(tmp_path):
    client = _StubClient()
    audit = _StubAudit()
    out = worker_handler.remediate_one(
        _entry(),
        config=worker_handler.WorkerConfig(apply=True, hard_delete=True, dry_run=False),
        client=client,
        audit=audit,
        incident_id="INC-1",
        approver="alice@security",
    )
    assert out["status"] == "remediated"
    assert any(c[0] == "hard_delete_user" for c in client.calls)


def test_cli_main_rejects_apply_without_env(tmp_path, monkeypatch, capsys):
    manifest = tmp_path / "m.json"
    manifest.write_text('{"entries":[]}', encoding="utf-8")
    monkeypatch.delenv("IAM_DEPARTURES_AZURE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("IAM_DEPARTURES_AZURE_APPROVER", raising=False)
    rc = worker_handler.main([str(manifest), "--apply"])
    assert rc == 2


def test_cli_main_rejects_hard_delete_without_apply(tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text('{"entries":[]}', encoding="utf-8")
    rc = worker_handler.main([str(manifest), "--hard-delete"])
    assert rc == 2


def test_cli_dry_run_emits_planned_for_each_entry(tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text(
        json.dumps(
            {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "entries": [_entry()],
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "out.jsonl"
    rc = worker_handler.main([str(manifest), "-o", str(out_path)])
    assert rc == 0
    lines = [line for line in out_path.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["status"] == "planned"


def test_is_protected_user_matches_default_patterns():
    is_p, why = worker_handler.is_protected_user(upn="admin@example.com", object_id=OBJECT_ID)
    assert is_p and "admin@*" in why
    is_p, _ = worker_handler.is_protected_user(upn="emergency-alice@x", object_id=OBJECT_ID)
    assert is_p
    is_p, _ = worker_handler.is_protected_user(upn="alice@example.com", object_id=OBJECT_ID)
    assert not is_p


def test_load_extra_protected_object_ids(monkeypatch):
    monkeypatch.setenv("IAM_DEPARTURES_AZURE_PROTECTED_OBJECT_IDS", " a , b ,c, ")
    assert worker_handler.load_extra_protected_object_ids() == ("a", "b", "c")
