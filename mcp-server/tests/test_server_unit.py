from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
SPEC = importlib.util.spec_from_file_location("cloud_security_server_test", SERVER_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
RUNTIME_TELEMETRY_PATH = REPO_ROOT / "skills" / "_shared" / "runtime_telemetry.py"
RUNTIME_TELEMETRY_SPEC = importlib.util.spec_from_file_location(
    "cloud_security_runtime_telemetry_test",
    RUNTIME_TELEMETRY_PATH,
)
assert RUNTIME_TELEMETRY_SPEC and RUNTIME_TELEMETRY_SPEC.loader
RUNTIME_TELEMETRY = importlib.util.module_from_spec(RUNTIME_TELEMETRY_SPEC)
sys.modules[RUNTIME_TELEMETRY_SPEC.name] = RUNTIME_TELEMETRY
RUNTIME_TELEMETRY_SPEC.loader.exec_module(RUNTIME_TELEMETRY)


class _FakeCompleted:
    def __init__(self) -> None:
        self.stdout = "ok\n"
        self.stderr = ""
        self.returncode = 0


class _FakeSkill:
    def __init__(
        self,
        read_only: bool = True,
        approver_roles: tuple[str, ...] = (),
        min_approvers: int | None = None,
        mcp_timeout_seconds: int | None = None,
        category: str = "detection",
        entrypoint_name: str | None = None,
    ) -> None:
        self.name = "fake-skill"
        self.category = category
        self.capability = "read-only" if read_only else "write-remediation"
        self.description = "fake skill"
        self.approval_model = "none" if read_only else "human_required"
        self.execution_modes = ("local",)
        self.side_effects = ("none",) if read_only else ("writes-cloud",)
        self.network_egress = ()
        self.caller_roles = ()
        self.read_only = read_only
        self.approver_roles = approver_roles
        self.min_approvers = min_approvers
        self.mcp_timeout_seconds = mcp_timeout_seconds
        self.entrypoint = None if entrypoint_name is None else Path(entrypoint_name)
        self.output_formats = ()


def test_call_tool_injects_caller_and_approval_context(monkeypatch):
    captured: dict[str, object] = {}
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill(read_only=True)})
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        captured["shell"] = kwargs.get("shell", False)
        captured["cwd"] = kwargs["cwd"]
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)

    result = MODULE._call_tool(
        "fake-skill",
        {
            "args": [],
            "_caller_context": {
                "user_id": "u-123",
                "email": "user@example.com",
                "session_id": "sess-1",
                "roles": ["security_engineer"],
            },
            "_approval_context": {
                "approver_id": "a-456",
                "approver_email": "approver@example.com",
                "ticket_id": "SEC-123",
                "approval_timestamp": "2026-04-14T12:00:00Z",
            },
        },
    )

    env = captured["env"]
    assert env["SKILL_CALLER_ID"] == "u-123"
    assert env["SKILL_CALLER_EMAIL"] == "user@example.com"
    assert env["SKILL_SESSION_ID"] == "sess-1"
    assert env["SKILL_CALLER_ROLES"] == "security_engineer"
    assert isinstance(env["SKILL_CORRELATION_ID"], str) and env["SKILL_CORRELATION_ID"]
    assert env["SKILL_APPROVER_ID"] == "a-456"
    assert env["SKILL_APPROVER_EMAIL"] == "approver@example.com"
    assert env["SKILL_APPROVAL_TICKET"] == "SEC-123"
    assert env["SKILL_APPROVAL_TIMESTAMP"] == "2026-04-14T12:00:00Z"
    assert captured["shell"] is False
    assert captured["cwd"] == MODULE.repo_root()
    assert result["structuredContent"]["caller_context_provided"] is True
    assert result["structuredContent"]["approval_context_provided"] is True
    assert result["structuredContent"]["correlation_id"] == env["SKILL_CORRELATION_ID"]
    assert audit_events[0]["tool"] == "fake-skill"
    assert audit_events[0]["result"] == "success"
    assert audit_events[0]["correlation_id"] == env["SKILL_CORRELATION_ID"]
    assert audit_events[0]["caller_id"] == "u-123"
    assert audit_events[0]["approval_ticket"] == "SEC-123"
    assert audit_events[0]["args_count"] == 0
    assert audit_events[0]["input_length"] == 0


def test_call_tool_scrubs_ambient_secret_env(monkeypatch):
    captured: dict[str, object] = {}

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "top-secret")
    monkeypatch.setenv("UNRELATED_SECRET", "should-not-pass")
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill(read_only=True)})
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: None)

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)

    MODULE._call_tool("fake-skill", {"args": []})

    env = captured["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "UNRELATED_SECRET" not in env
    assert env["PATH"] == "/usr/bin"
    assert env["LANG"] == "en_US.UTF-8"
    assert env["PYTHONUNBUFFERED"] == "1"


def test_call_tool_preserves_cloud_security_control_env(monkeypatch):
    captured: dict[str, object] = {}

    monkeypatch.setenv("CLOUD_SECURITY_CONFORMANCE_MOTO_FIXTURE", "aws-cis-storage")
    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill(read_only=True)})
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: None)

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)

    MODULE._call_tool("fake-skill", {"args": []})

    env = captured["env"]
    assert env["CLOUD_SECURITY_CONFORMANCE_MOTO_FIXTURE"] == "aws-cis-storage"


def test_call_tool_requires_approval_context_for_write_skill(monkeypatch):
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {"fake-skill": _FakeSkill(read_only=False, approver_roles=("security_lead",))},
    )
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    try:
        MODULE._call_tool("fake-skill", {"args": ["--dry-run"]})
    except ValueError as exc:
        assert "require `_approval_context`" in str(exc)
    else:
        raise AssertionError("expected ValueError")
    assert audit_events[0]["tool"] == "fake-skill"
    assert audit_events[0]["result"] == "error"
    assert audit_events[0]["error_type"] == "ValueError"
    assert audit_events[0]["args_hash"] == MODULE._stable_hash(["--dry-run"])
    assert audit_events[0]["approval_context_provided"] is False


def test_safe_write_invocation_allows_handler_remediation_without_apply():
    skill = _FakeSkill(
        read_only=False,
        category="remediation",
        entrypoint_name="handler.py",
    )
    assert MODULE._is_safe_write_invocation(skill, []) is True


def test_safe_write_invocation_rejects_apply_for_handler_remediation():
    skill = _FakeSkill(
        read_only=False,
        category="remediation",
        entrypoint_name="handler.py",
    )
    assert MODULE._is_safe_write_invocation(skill, ["--apply"]) is False


def test_safe_write_invocation_still_requires_dry_run_for_non_handler_writes():
    skill = _FakeSkill(
        read_only=False,
        category="sinks",
        entrypoint_name="sink.py",
    )
    assert MODULE._is_safe_write_invocation(skill, []) is False
    assert MODULE._is_safe_write_invocation(skill, ["--dry-run"]) is True


def test_call_tool_requires_minimum_approver_count(monkeypatch):
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {
            "fake-skill": _FakeSkill(
                read_only=False,
                approver_roles=("security_lead", "incident_commander"),
                min_approvers=2,
            )
        },
    )
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    try:
        MODULE._call_tool(
            "fake-skill",
            {
                "args": ["--dry-run"],
                "_approval_context": {
                    "approver_id": "a-456",
                    "ticket_id": "SEC-123",
                },
            },
        )
    except ValueError as exc:
        assert "requires at least 2 approver" in str(exc)
    else:
        raise AssertionError("expected ValueError")
    assert audit_events[0]["approval_context_provided"] is True
    assert audit_events[0]["approval_count"] == 1


def test_call_tool_accepts_multi_approver_context(monkeypatch):
    captured: dict[str, object] = {}
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {
            "fake-skill": _FakeSkill(
                read_only=False,
                approver_roles=("security_lead", "incident_commander"),
                min_approvers=2,
            )
        },
    )
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)

    result = MODULE._call_tool(
        "fake-skill",
        {
            "args": ["--dry-run"],
            "_approval_context": {
                "approver_ids": ["a-456", "b-789"],
                "approver_emails": ["a@example.com", "b@example.com"],
                "ticket_id": "SEC-123",
            },
        },
    )

    env = captured["env"]
    assert env["SKILL_APPROVER_IDS"] == "a-456,b-789"
    assert env["SKILL_APPROVER_EMAILS"] == "a@example.com,b@example.com"
    assert result["isError"] is False
    assert audit_events[0]["approval_count"] == 2


def test_call_tool_rejects_duplicate_multi_approver_context(monkeypatch):
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {
            "fake-skill": _FakeSkill(
                read_only=False,
                approver_roles=("security_lead", "incident_commander"),
                min_approvers=2,
            )
        },
    )
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    try:
        MODULE._call_tool(
            "fake-skill",
            {
                "args": ["--dry-run"],
                "_approval_context": {
                    "approver_ids": ["a-456", "a-456"],
                    "ticket_id": "SEC-123",
                },
            },
        )
    except ValueError as exc:
        assert "requires at least 2 approver" in str(exc)
    else:
        raise AssertionError("expected ValueError")
    assert audit_events[0]["approval_count"] == 1


def test_safe_write_invocation_allows_checks_evaluation_without_apply():
    skill = _FakeSkill(
        read_only=False,
        category="evaluation",
        entrypoint_name="checks.py",
    )
    assert MODULE._is_safe_write_invocation(skill, ["--auto-remediate"]) is True
    assert MODULE._is_safe_write_invocation(skill, ["--auto-remediate", "--apply"]) is False


def test_safe_write_invocation_still_requires_dry_run_for_other_write_surfaces():
    skill = _FakeSkill(
        read_only=False,
        category="output",
        entrypoint_name="sink.py",
    )
    assert MODULE._is_safe_write_invocation(skill, []) is False
    assert MODULE._is_safe_write_invocation(skill, ["--dry-run"]) is True


def test_checks_evaluation_dry_run_does_not_require_approval_context(monkeypatch):
    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {
            "fake-skill": _FakeSkill(
                read_only=False,
                approver_roles=("security_lead",),
                category="evaluation",
                entrypoint_name="checks.py",
            )
        },
    )
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *args, **kwargs: _FakeCompleted())
    result = MODULE._call_tool("fake-skill", {"args": []})
    assert result["isError"] is False


def test_resolve_timeout_prefers_env_override():
    skill = _FakeSkill(mcp_timeout_seconds=45)
    env = {"CLOUD_SECURITY_MCP_TIMEOUT_SECONDS": "300"}
    assert MODULE._resolve_timeout(skill, env) == 300


def test_resolve_timeout_uses_skill_value_when_no_env_override():
    skill = _FakeSkill(mcp_timeout_seconds=120)
    env: dict[str, str] = {}
    assert MODULE._resolve_timeout(skill, env) == 120


def test_resolve_timeout_falls_back_to_default_when_neither_set():
    skill = _FakeSkill(mcp_timeout_seconds=None)
    env: dict[str, str] = {}
    assert MODULE._resolve_timeout(skill, env) == MODULE.DEFAULT_TIMEOUT_SECONDS


def test_resolve_timeout_ignores_blank_env_override():
    skill = _FakeSkill(mcp_timeout_seconds=90)
    env = {"CLOUD_SECURITY_MCP_TIMEOUT_SECONDS": "   "}
    assert MODULE._resolve_timeout(skill, env) == 90


def test_call_tool_audit_records_resolved_timeout(monkeypatch):
    audit_events: list[dict[str, object]] = []
    monkeypatch.setattr(
        MODULE,
        "tool_map",
        lambda: {"fake-skill": _FakeSkill(mcp_timeout_seconds=150)},
    )
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    def _fake_run(*args, **kwargs):
        assert kwargs["timeout"] == 150
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)
    monkeypatch.delenv("CLOUD_SECURITY_MCP_TIMEOUT_SECONDS", raising=False)
    MODULE._call_tool("fake-skill", {"args": []})
    assert audit_events[0]["timeout_seconds"] == 150


def test_allowed_skills_filter_unset_returns_none(monkeypatch):
    monkeypatch.delenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", raising=False)
    assert MODULE._allowed_skills_filter() is None


def test_allowed_skills_filter_blank_returns_none(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", "   ")
    assert MODULE._allowed_skills_filter() is None


def test_allowed_skills_filter_parses_csv_and_trims(monkeypatch):
    monkeypatch.setenv(
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS",
        " cspm-aws-cis-benchmark , detect-lateral-movement ,, ",
    )
    assert MODULE._allowed_skills_filter() == {
        "cspm-aws-cis-benchmark",
        "detect-lateral-movement",
    }


def test_filtered_tool_map_restricts_to_allowlist(monkeypatch):
    fake_tools = {
        "cspm-aws-cis-benchmark": _FakeSkill(),
        "iam-departures-aws": _FakeSkill(),
        "detect-lateral-movement": _FakeSkill(),
    }
    monkeypatch.setattr(MODULE, "tool_map", lambda: fake_tools)
    monkeypatch.setenv(
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS",
        "cspm-aws-cis-benchmark,detect-lateral-movement",
    )
    filtered = MODULE._filtered_tool_map()
    assert set(filtered) == {"cspm-aws-cis-benchmark", "detect-lateral-movement"}
    assert "iam-departures-aws" not in filtered


def test_filtered_tool_map_unset_exposes_all(monkeypatch):
    fake_tools = {"a": _FakeSkill(), "b": _FakeSkill()}
    monkeypatch.setattr(MODULE, "tool_map", lambda: fake_tools)
    monkeypatch.delenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", raising=False)
    assert set(MODULE._filtered_tool_map()) == {"a", "b"}


def test_scoped_tool_map_intersects_operator_and_caller_allowlists(monkeypatch):
    fake_tools = {
        "allowed-by-both": _FakeSkill(),
        "operator-only": _FakeSkill(),
        "caller-only": _FakeSkill(),
    }
    monkeypatch.setattr(MODULE, "tool_map", lambda: fake_tools)
    monkeypatch.setenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", "allowed-by-both,operator-only")

    scoped = MODULE._scoped_tool_map({"allowed_skills": ["allowed-by-both", "caller-only"]})

    assert set(scoped) == {"allowed-by-both"}


def test_scoped_tool_map_requires_caller_allowlist_when_enabled(monkeypatch):
    fake_tools = {"a": _FakeSkill(), "b": _FakeSkill()}
    monkeypatch.setattr(MODULE, "tool_map", lambda: fake_tools)
    monkeypatch.delenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", raising=False)
    monkeypatch.setenv("CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS", "true")

    assert MODULE._scoped_tool_map(None) == {}
    assert set(MODULE._scoped_tool_map({"allowed_skills": ["b"]})) == {"b"}


def test_call_tool_rejects_skill_outside_caller_scope(monkeypatch):
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(MODULE, "tool_map", lambda: {"blocked-skill": _FakeSkill()})
    monkeypatch.delenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", raising=False)
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    try:
        MODULE._call_tool(
            "blocked-skill",
            {
                "args": [],
                "_caller_context": {"user_id": "u-123", "allowed_skills": ["other-skill"]},
            },
        )
    except KeyError as exc:
        assert "unknown tool" in str(exc)
    else:
        raise AssertionError("expected KeyError for caller-scope-blocked tool")

    assert audit_events[0]["tool"] == "blocked-skill"
    assert audit_events[0]["result"] == "error"
    assert audit_events[0]["caller_skill_scope_provided"] is True
    assert audit_events[0]["caller_skill_scope_count"] == 1
    assert audit_events[0]["caller_skill_scope_hash"] == MODULE._stable_hash(["other-skill"])


def test_call_tool_forwards_caller_allowed_skill_scope(monkeypatch):
    captured: dict[str, object] = {}
    audit_events: list[dict[str, object]] = []

    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill(read_only=True)})
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: audit_events.append(event))

    def _fake_run(*args, **kwargs):
        captured["env"] = kwargs["env"]
        return _FakeCompleted()

    monkeypatch.setattr(MODULE.subprocess, "run", _fake_run)

    MODULE._call_tool(
        "fake-skill",
        {"args": [], "_caller_context": {"allowed_skills": ["fake-skill", "fake-skill", ""]}},
    )

    env = captured["env"]
    assert env["SKILL_CALLER_ALLOWED_SKILLS"] == "fake-skill"
    assert audit_events[0]["caller_skill_scope_provided"] is True
    assert audit_events[0]["caller_skill_scope_count"] == 1


def test_handle_tools_list_applies_caller_scope(monkeypatch):
    fake_tools = {"a": _FakeSkill(), "b": _FakeSkill()}
    fake_tools["a"].name = "a"
    fake_tools["b"].name = "b"
    monkeypatch.setattr(MODULE, "tool_map", lambda: fake_tools)
    monkeypatch.delenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", raising=False)

    response = MODULE._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_caller_context": {"allowed_skills": ["b"]}},
        }
    )

    tools = response["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["b"]


def test_call_tool_rejects_skill_outside_allowlist(monkeypatch):
    monkeypatch.setattr(MODULE, "tool_map", lambda: {"blocked-skill": _FakeSkill()})
    monkeypatch.setenv("CLOUD_SECURITY_MCP_ALLOWED_SKILLS", "other-skill")
    try:
        MODULE._call_tool("blocked-skill", {"args": []})
    except KeyError as exc:
        assert "unknown tool" in str(exc)
    else:
        raise AssertionError("expected KeyError for allowlist-blocked tool")


def test_handle_request_returns_distinct_timeout_error_code(monkeypatch):
    """Timeouts must use ERROR_TOOL_TIMEOUT (-32001) so clients can distinguish
    a slow skill from any other server-side error.
    """
    monkeypatch.setattr(MODULE, "tool_map", lambda: {"fake-skill": _FakeSkill(read_only=True)})
    monkeypatch.setattr(MODULE, "build_command", lambda skill, args, output_format=None: ["python", "fake.py"])
    monkeypatch.setattr(MODULE, "_emit_audit_event", lambda event: None)

    def _raise_timeout(*args, **kwargs):
        raise MODULE.subprocess.TimeoutExpired(cmd=["python", "fake.py"], timeout=42)

    monkeypatch.setattr(MODULE.subprocess, "run", _raise_timeout)

    response = MODULE._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "fake-skill", "arguments": {"args": []}},
        }
    )

    assert response["error"]["code"] == MODULE.ERROR_TOOL_TIMEOUT
    assert response["error"]["code"] == -32001
    assert "timed out" in response["error"]["message"]


def test_runtime_telemetry_includes_env_correlation_id(monkeypatch, capsys):
    monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
    monkeypatch.setenv("SKILL_CORRELATION_ID", "corr-123")

    RUNTIME_TELEMETRY.emit_stderr_event(
        "fake-skill",
        level="warning",
        event="skipped_record",
        message="record skipped",
        line=7,
    )

    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["correlation_id"] == "corr-123"
    assert payload["line"] == 7
