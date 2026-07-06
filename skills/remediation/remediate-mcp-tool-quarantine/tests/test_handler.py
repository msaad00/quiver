"""Tests for remediate-mcp-tool-quarantine."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    DEFAULT_PROTECTED_TOOL_PREFIXES,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_TOOL,
    STATUS_SKIPPED_PROTECTED,
    STATUS_SUCCESS,
    STATUS_WOULD_VIOLATE_PROTECTED,
    JSONLQuarantineFile,
    check_apply_gate,
    is_protected_tool,
    parse_targets,
    run,
)


def _finding(
    *,
    producer: str = "detect-mcp-tool-drift",
    tool_name: str = "rogue-search",
    session_uid: str = "sess-1",
    fingerprint: str = "sha256:abcd",
    finding_uid: str = "find-1",
    omit_tool: bool = False,
    fp_observable: str = "tool.after_fingerprint",
) -> dict:
    observables = [
        {"name": "session.uid", "type": "Other", "value": session_uid},
    ]
    if not omit_tool:
        observables.append({"name": "tool.name", "type": "Other", "value": tool_name})
    observables.append({"name": fp_observable, "type": "Fingerprint", "value": fingerprint})
    return {
        "class_uid": 2004,
        "metadata": {
            "uid": finding_uid,
            "product": {"feature": {"name": producer}},
        },
        "finding_info": {"uid": finding_uid},
        "observables": observables,
    }


@dataclass
class _FakeAudit:
    writes: list[dict] = field(default_factory=list)

    def record(self, *, target, step, status, detail, incident_id, approvers):
        entry = {
            "tool_name": target.tool_name,
            "step": step,
            "status": status,
            "detail": detail,
            "incident_id": incident_id,
            "approver": approvers[0] if approvers else "",
            "approvers": list(approvers),
        }
        self.writes.append(entry)
        return {
            "row_uid": f"row-{len(self.writes)}",
            "s3_evidence_uri": f"s3://bucket/{target.tool_name}-{len(self.writes)}.json",
        }


@dataclass
class _FakeStore:
    tools: list[str] = field(default_factory=list)
    appended: list[dict] = field(default_factory=list)
    raise_on_append: bool = False
    raise_on_list: bool = False

    def list_tools(self):
        if self.raise_on_list:
            raise IOError("simulated unreadable quarantine file")
        return list(self.tools)

    def append(self, entry):
        if self.raise_on_append:
            raise IOError("simulated disk full")
        self.appended.append(entry)
        if entry.get("tool_name"):
            self.tools.append(entry["tool_name"])


# ----------------- helpers -----------------


def test_accepted_producers_set():
    assert ACCEPTED_PRODUCERS == frozenset(
        {"detect-mcp-tool-drift", "detect-prompt-injection-mcp-proxy"}
    )


def test_default_protected_prefixes_cover_infra_tools():
    assert "mcp_" in DEFAULT_PROTECTED_TOOL_PREFIXES
    assert "system_" in DEFAULT_PROTECTED_TOOL_PREFIXES
    assert "internal_" in DEFAULT_PROTECTED_TOOL_PREFIXES


def test_is_protected_tool_matches_prefix():
    assert is_protected_tool("mcp_audit", DEFAULT_PROTECTED_TOOL_PREFIXES) == (True, "mcp_")
    assert is_protected_tool("System_Probe", DEFAULT_PROTECTED_TOOL_PREFIXES) == (True, "system_")
    assert is_protected_tool("rogue-search", DEFAULT_PROTECTED_TOOL_PREFIXES) == (False, "")
    assert is_protected_tool("", DEFAULT_PROTECTED_TOOL_PREFIXES) == (False, "")


def test_check_apply_gate_requires_two_distinct_approvers(monkeypatch):
    monkeypatch.delenv("MCP_QUARANTINE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("MCP_QUARANTINE_APPROVER_EMAILS", raising=False)
    monkeypatch.delenv("MCP_QUARANTINE_APPROVER_IDS", raising=False)
    monkeypatch.delenv("MCP_QUARANTINE_APPROVER", raising=False)
    monkeypatch.delenv("MCP_QUARANTINE_SECOND_APPROVER", raising=False)
    ok, reason = check_apply_gate()
    assert ok is False
    assert "INCIDENT_ID" in reason

    monkeypatch.setenv("MCP_QUARANTINE_INCIDENT_ID", "INC-1")
    ok, reason = check_apply_gate()
    assert ok is False
    assert "two distinct approvers" in reason

    monkeypatch.setenv("MCP_QUARANTINE_APPROVER_EMAILS", "alice@security,bob@security")
    ok, reason = check_apply_gate()
    assert ok is True


def test_check_apply_gate_rejects_duplicate_approvers(monkeypatch):
    monkeypatch.setenv("MCP_QUARANTINE_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("MCP_QUARANTINE_APPROVER_EMAILS", "alice@security,alice@security")
    ok, reason = check_apply_gate()
    assert ok is False
    assert "two distinct approvers" in reason


def test_check_apply_gate_accepts_legacy_two_approver_envs(monkeypatch):
    monkeypatch.setenv("MCP_QUARANTINE_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("MCP_QUARANTINE_APPROVER", "alice@security")
    monkeypatch.setenv("MCP_QUARANTINE_SECOND_APPROVER", "bob@security")
    ok, reason = check_apply_gate()
    assert ok is True


# ----------------- parse_targets -----------------


def test_parse_targets_accepts_both_producers():
    drift = next(parse_targets([_finding(producer="detect-mcp-tool-drift")]))[0]
    inj = next(
        parse_targets(
            [
                _finding(
                    producer="detect-prompt-injection-mcp-proxy",
                    fp_observable="tool.description_sha256",
                )
            ]
        )
    )[0]
    assert drift is not None and drift.producer_skill == "detect-mcp-tool-drift"
    assert inj is not None and inj.producer_skill == "detect-prompt-injection-mcp-proxy"


def test_parse_targets_rejects_wrong_producer(capsys):
    target, _ = next(parse_targets([_finding(producer="detect-okta-mfa-fatigue")]))
    assert target is None
    assert "unaccepted producer" in capsys.readouterr().err


def test_parse_targets_extracts_observables():
    target, _ = next(parse_targets([_finding()]))
    assert target.tool_name == "rogue-search"
    assert target.session_uid == "sess-1"
    assert target.fingerprint == "sha256:abcd"


# ----------------- run: dry-run path -----------------


def test_run_dry_run_emits_plan_with_quarantine_entry():
    records = list(run([_finding()], store=_FakeStore()))
    assert len(records) == 1
    rec = records[0]
    assert rec["record_type"] == "remediation_plan"
    assert rec["status"] == STATUS_PLANNED
    assert rec["dry_run"] is True
    assert rec["quarantine_entry"]["tool_name"] == "rogue-search"
    assert rec["quarantine_entry"]["record_type"] == "mcp_tool_quarantine_entry"


def test_run_dry_run_does_not_touch_store():
    store = _FakeStore()
    list(run([_finding()], store=store))
    assert store.appended == []
    assert store.tools == []


# ----------------- run: skip paths -----------------


def test_run_skips_finding_without_tool_name():
    records = list(run([_finding(omit_tool=True)], store=_FakeStore()))
    rec = records[0]
    assert rec["status"] == STATUS_SKIPPED_NO_TOOL
    assert rec["actions"] == []


def test_run_skips_protected_tool_in_dry_run():
    records = list(run([_finding(tool_name="mcp_audit_proxy")], store=_FakeStore()))
    rec = records[0]
    assert rec["status"] == STATUS_WOULD_VIOLATE_PROTECTED
    assert "mcp_" in rec["status_detail"]


def test_run_skips_protected_tool_in_apply():
    audit = _FakeAudit()
    store = _FakeStore()
    records = list(
        run(
            [_finding(tool_name="system_probe")],
            store=store,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approvers=("alice", "bob"),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SKIPPED_PROTECTED
    assert audit.writes == []
    assert store.appended == []


# ----------------- run: apply path -----------------


def test_run_apply_quarantines_tool_with_dual_audit():
    audit = _FakeAudit()
    store = _FakeStore()
    records = list(
        run(
            [_finding()],
            store=store,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approvers=("alice@security", "bob@security"),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["dry_run"] is False
    assert rec["incident_id"] == "INC-1"
    assert store.appended[0]["tool_name"] == "rogue-search"
    assert "rogue-search" in store.tools

    # Dual audit: pre-action + post-action
    assert len(audit.writes) == 2
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[1]["status"] == STATUS_SUCCESS
    assert rec["approver_count"] == 2
    assert rec["approvers"] == ["alice@security", "bob@security"]


def test_run_apply_writes_failure_audit_when_store_throws():
    audit = _FakeAudit()
    store = _FakeStore(raise_on_append=True)
    records = list(
        run(
            [_finding()],
            store=store,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approvers=("alice", "bob"),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_FAILURE
    assert "disk full" in rec["actions"][0]["detail"]
    assert len(audit.writes) == 2
    assert audit.writes[1]["status"] == STATUS_FAILURE
    assert store.appended == []  # the throwing append did not persist


def test_run_apply_requires_audit_writer():
    import pytest

    with pytest.raises(ValueError, match="audit writer is required"):
        list(run([_finding()], store=_FakeStore(), apply=True, audit=None))


# ----------------- run: re-verify path -----------------


def test_run_reverify_verified_when_tool_present():
    store = _FakeStore(tools=["rogue-search"])
    records = list(run([_finding()], store=store, reverify=True))
    assert len(records) == 1
    rec = records[0]
    assert rec["record_type"] == "remediation_verification"
    assert rec["status"] == "verified"
    assert rec["reference"]["target_provider"] == "MCP"


def test_run_reverify_drift_emits_ocsf_finding_alongside_verification():
    """DRIFT outcome must yield BOTH a remediation_verification record AND
    an OCSF Detection Finding (class_uid 2004) so the drift flows through
    the same SIEM/SOAR pipeline as every other finding."""
    store = _FakeStore(tools=[])  # tool was removed from quarantine
    records = list(run([_finding()], store=store, reverify=True))
    assert len(records) == 2
    verification, finding = records
    assert verification["status"] == "drift"
    assert finding["class_uid"] == 2004
    assert finding["category_uid"] == 2
    assert finding["severity_id"] == 4  # SEVERITY_HIGH
    assert finding["finding_info"]["types"] == ["remediation-drift"]
    assert any(
        obs["name"] == "remediation.skill" and obs["value"] == "remediate-mcp-tool-quarantine"
        for obs in finding["observables"]
    )


def test_run_reverify_unreachable_never_silently_downgrades():
    store = _FakeStore(raise_on_list=True)
    records = list(run([_finding()], store=store, reverify=True))
    assert len(records) == 1  # no drift finding on UNREACHABLE
    assert records[0]["status"] == "unreachable"


def test_run_reverify_skips_protected_tool():
    store = _FakeStore()
    records = list(run([_finding(tool_name="mcp_internal")], store=store, reverify=True))
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED


# ----------------- JSONLQuarantineFile -----------------


def test_quarantine_file_round_trips_tool_names(tmp_path):
    path = tmp_path / "q.jsonl"
    store = JSONLQuarantineFile(path=path)
    assert store.list_tools() == []  # missing file → empty list

    store.append({"tool_name": "alpha", "incident_id": "INC-1"})
    store.append({"tool_name": "beta", "incident_id": "INC-2"})
    assert store.list_tools() == ["alpha", "beta"]


def test_quarantine_file_skips_malformed_lines(tmp_path):
    path = tmp_path / "q.jsonl"
    path.write_text(
        "\n".join(
            [
                '{"tool_name": "good"}',
                "this-is-not-json",
                "",
                '{"missing_tool_name": true}',
                '{"tool_name": "also-good"}',
            ]
        ),
        encoding="utf-8",
    )
    store = JSONLQuarantineFile(path=path)
    assert store.list_tools() == ["good", "also-good"]


def test_quarantine_file_creates_parent_dirs(tmp_path):
    path = tmp_path / "nested" / "deeper" / "q.jsonl"
    store = JSONLQuarantineFile(path=path)
    store.append({"tool_name": "alpha"})
    assert path.exists()
    # Re-read to confirm appended payload
    line = path.read_text(encoding="utf-8").strip()
    assert json.loads(line)["tool_name"] == "alpha"
