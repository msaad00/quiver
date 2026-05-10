"""End-to-end tests for `skills/_shared/library.py`."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_PATH = REPO_ROOT / "skills" / "_shared" / "library.py"
spec = importlib.util.spec_from_file_location("cs_library_test", LIB_PATH)
assert spec and spec.loader
LIB = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = LIB
spec.loader.exec_module(LIB)


def test_constructor_rejects_unknown_skill_in_allowlist():
    with pytest.raises(LIB.SkillNotAllowed):
        LIB.SkillsClient(allowed_skills=("ingest-cloudtrail-ocsf", "this-does-not-exist"))


def test_constructor_accepts_known_skills():
    client = LIB.SkillsClient(allowed_skills=("ingest-cloudtrail-ocsf",))
    assert "ingest-cloudtrail-ocsf" in client.list_skills()


def test_list_skills_with_no_allowlist_returns_full_set():
    client = LIB.SkillsClient()
    assert "ingest-cloudtrail-ocsf" in client.list_skills()
    assert "detect-okta-mfa-fatigue" in client.list_skills()
    # Read-only should be at least as big as the allowlist case.
    assert len(client.list_skills()) >= 70


def test_invoke_unknown_skill_raises():
    client = LIB.SkillsClient(allowed_skills=("ingest-cloudtrail-ocsf",))
    with pytest.raises(LIB.SkillNotAllowed):
        client.invoke("nonexistent")


def test_invoke_skill_outside_allowlist_raises():
    client = LIB.SkillsClient(allowed_skills=("ingest-cloudtrail-ocsf",))
    with pytest.raises(LIB.SkillNotAllowed):
        client.invoke("detect-okta-mfa-fatigue")


def test_invoke_remediation_without_dry_run_is_refused():
    """The library shim refuses write-capable invocations the same way
    the MCP wrapper does — `--apply` on a remediation handler.py is
    blocked unless we're on a runner that owns its own gate."""
    client = LIB.SkillsClient(allowed_skills=("remediate-mcp-tool-quarantine",))
    with pytest.raises(LIB.SkillCallRefused):
        client.invoke("remediate-mcp-tool-quarantine", args=["--apply"])


def test_invoke_remediation_dry_run_default_requires_approval_context():
    """The shipped MCP wrapper's bar: ANY non-read-only call with
    declared approver_roles needs an approval_context — even when
    `--apply` is absent and the skill is dry-run-default. This locks
    in MCP-parity for the library shim."""
    client = LIB.SkillsClient(allowed_skills=("remediate-mcp-tool-quarantine",))
    # No approval_context → refused even though no --apply.
    with pytest.raises(LIB.SkillCallRefused, match="approval_context"):
        client.invoke("remediate-mcp-tool-quarantine", stdin=b"{}")


def test_invoke_remediation_dry_run_with_approval_context_runs():
    """Same skill, same dry-run path, but with an approval_context that
    meets `min_approvers` — the gate accepts and the subprocess runs."""
    client = LIB.SkillsClient(allowed_skills=("remediate-mcp-tool-quarantine",))
    result = client.invoke(
        "remediate-mcp-tool-quarantine",
        stdin=b"{}",
        approval_context={
            "approver_emails": ["lead@example.com", "commander@example.com"],
            "ticket_id": "SEC-1",
        },
    )
    assert isinstance(result, LIB.SkillResult)
    assert result.correlation_id


def test_invoke_apply_without_approval_context_refused():
    """remediate-okta-session-kill is generic write-capable; --apply
    requires _approval_context."""
    client = LIB.SkillsClient(allowed_skills=("remediate-okta-session-kill",))
    with pytest.raises(LIB.SkillCallRefused):
        client.invoke("remediate-okta-session-kill", args=["--apply"])


def test_invoke_dry_run_with_approval_context_is_allowed():
    """--dry-run + a valid approval_context is the planning shape an
    agent uses to preview a remediation. Gate accepts."""
    client = LIB.SkillsClient(allowed_skills=("remediate-okta-session-kill",))
    result = client.invoke(
        "remediate-okta-session-kill",
        args=["--dry-run"],
        stdin=b"{}",
        approval_context={
            "approver_email": "approver@example.com",
            "ticket_id": "SEC-2",
        },
    )
    assert isinstance(result, LIB.SkillResult)


def test_invoke_read_only_skill_returns_skill_result():
    """End-to-end happy path for a read-only skill — runs the actual
    subprocess so we verify the SafeChildEnv / RLIMIT path."""
    client = LIB.SkillsClient(allowed_skills=("ingest-cloudtrail-ocsf",))
    raw = (
        REPO_ROOT
        / "skills"
        / "detection-engineering"
        / "golden"
        / "cloudtrail_raw_sample.jsonl"
    ).read_bytes()
    result = client.invoke("ingest-cloudtrail-ocsf", stdin=raw)
    assert result.exit_code == 0, result.stderr
    assert result.stdout
    # Ingester emits one OCSF JSONL record per CloudTrail event.
    assert b"\n" in result.stdout or len(result.stdout) > 0


def test_audit_writer_receives_one_record_per_call():
    """Audit writers must see one structured record per invocation. The
    record shape matches the MCP wrapper's so downstream tooling
    works."""
    seen: list[dict] = []
    client = LIB.SkillsClient(
        allowed_skills=("ingest-cloudtrail-ocsf",),
        audit_writer=lambda rec: seen.append(rec),
    )
    raw = (
        REPO_ROOT
        / "skills"
        / "detection-engineering"
        / "golden"
        / "cloudtrail_raw_sample.jsonl"
    ).read_bytes()
    client.invoke("ingest-cloudtrail-ocsf", stdin=raw)
    assert len(seen) == 1
    record = seen[0]
    assert record["event"] == "skills_library_call"
    assert record["skill"] == "ingest-cloudtrail-ocsf"
    assert record["category"] == "ingestion"
    assert record["result"] == "success"
    assert record["exit_code"] == 0
    assert record["correlation_id"]


def test_audit_writer_exception_does_not_break_call():
    """An exception in the operator's audit writer must not crash the
    call — the audit channel is best-effort."""
    def _broken_writer(rec):
        raise RuntimeError("operator's sink is down")

    client = LIB.SkillsClient(
        allowed_skills=("ingest-cloudtrail-ocsf",),
        audit_writer=_broken_writer,
    )
    raw = (
        REPO_ROOT
        / "skills"
        / "detection-engineering"
        / "golden"
        / "cloudtrail_raw_sample.jsonl"
    ).read_bytes()
    result = client.invoke("ingest-cloudtrail-ocsf", stdin=raw)
    assert result.exit_code == 0


def test_approval_count_helper_handles_empty():
    assert LIB._approval_count(None) == 0
    assert LIB._approval_count({}) == 0


def test_approval_count_helper_dedupes():
    assert LIB._approval_count(
        {"approver_emails": ["a@x.com", "b@x.com", "a@x.com"]}
    ) == 2


def test_approval_count_helper_falls_back_to_singular():
    assert LIB._approval_count({"approver_email": "a@x.com"}) == 1
    assert LIB._approval_count({"approver_id": "a-1"}) == 1
