"""Tests for remediate-workspace-session-kill."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    CONTAINMENT_STEPS,
    DEFAULT_DENY_PATTERNS,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_DENY_LIST,
    STATUS_SKIPPED_DOMAIN_BOUNDARY,
    STATUS_SKIPPED_NO_USER,
    STATUS_SUCCESS,
    STATUS_WOULD_VIOLATE_DENY_LIST,
    STEP_FORCE_PASSWORD_CHANGE,
    STEP_SIGN_OUT,
    Target,
    check_apply_gate,
    is_protected,
    load_deny_patterns,
    parse_targets,
    run,
)


def _finding(
    *,
    producer: str = "detect-google-workspace-suspicious-login",
    user_uid: str = "alice@example.com",
    user_name: str = "Alice Example",
    finding_uid: str = "find-1",
    ips: list[str] | None = None,
    sessions: list[str] | None = None,
    omit_user_uid: bool = False,
) -> dict:
    obs: list[dict] = [{"name": "user.name", "type": "User Name", "value": user_name}]
    if not omit_user_uid:
        obs.insert(0, {"name": "user.uid", "type": "User Name", "value": user_uid})
    for ip in ips or []:
        obs.append({"name": "src.ip", "type": "IP Address", "value": ip})
    for s in sessions or []:
        obs.append({"name": "session.uid", "type": "Other", "value": s})
    return {
        "class_uid": 2004,
        "metadata": {"uid": finding_uid, "product": {"feature": {"name": producer}}},
        "finding_info": {"uid": finding_uid},
        "observables": obs,
    }


@dataclass
class _FakeAudit:
    writes: list[dict] = field(default_factory=list)

    def record(self, *, target, step, status, detail, incident_id, approver):
        entry = {
            "user_uid": target.user_uid,
            "step": step,
            "status": status,
            "detail": detail,
            "incident_id": incident_id,
            "approver": approver,
        }
        self.writes.append(entry)
        return {
            "row_uid": f"row-{len(self.writes)}",
            "s3_evidence_uri": f"s3://bucket/{target.user_uid}-{len(self.writes)}.json",
        }


@dataclass
class _FakeWorkspace:
    fail_on: str | None = None
    calls: list[tuple[str, str, int | None]] = field(default_factory=list)
    recent_logins_by_user: dict[str, list[dict]] = field(default_factory=dict)

    def sign_out(self, user_key):
        self.calls.append(("sign_out", user_key, None))
        if self.fail_on == "sign_out":
            raise RuntimeError("simulated workspace 500")

    def force_password_change(self, user_key):
        self.calls.append(("force_password_change", user_key, None))
        if self.fail_on == "force_password_change":
            raise RuntimeError("simulated workspace 403")

    def list_recent_successful_logins(self, user_key, *, since_ms):
        self.calls.append(("list_recent_successful_logins", user_key, since_ms))
        if self.fail_on == "list_recent_successful_logins":
            raise RuntimeError("simulated workspace 502")
        return list(self.recent_logins_by_user.get(user_key, []))


# ---------- contracts ----------


def test_accepted_producers_set_is_just_workspace():
    assert ACCEPTED_PRODUCERS == frozenset({"detect-google-workspace-suspicious-login"})


def test_containment_steps_in_safe_order():
    # Sign-out first invalidates current sessions; password-change forces the
    # legitimate user to re-auth before any new login. Order matters.
    assert CONTAINMENT_STEPS == (STEP_SIGN_OUT, STEP_FORCE_PASSWORD_CHANGE)


def test_default_deny_patterns_cover_protected_principal_classes():
    as_text = " ".join(DEFAULT_DENY_PATTERNS).lower()
    for required in ("admin", "service-account", "break-glass", "emergency", "root", "@google.com"):
        assert required in as_text


def test_check_apply_gate_requires_both_envs(monkeypatch):
    monkeypatch.delenv("WORKSPACE_SESSION_KILL_INCIDENT_ID", raising=False)
    monkeypatch.delenv("WORKSPACE_SESSION_KILL_APPROVER", raising=False)
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS", "example.com")
    ok, reason = check_apply_gate()
    assert ok is False and "INCIDENT_ID" in reason
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_INCIDENT_ID", "INC-1")
    ok, reason = check_apply_gate()
    assert ok is False and "APPROVER" in reason
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_APPROVER", "alice")
    ok, _ = check_apply_gate()
    assert ok is True


def test_check_apply_gate_requires_allowed_domains(monkeypatch):
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_APPROVER", "alice")
    monkeypatch.delenv("WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS", raising=False)
    ok, reason = check_apply_gate()
    assert ok is False
    assert "ALLOWED_DOMAINS" in reason


def test_check_apply_gate_rejects_admin_email_outside_allowed_domains(monkeypatch):
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_INCIDENT_ID", "INC-1")
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_APPROVER", "alice")
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_ALLOWED_DOMAINS", "example.com")
    monkeypatch.setenv("WORKSPACE_DELEGATED_ADMIN_EMAIL", "admin@other.com")
    ok, reason = check_apply_gate()
    assert ok is False
    assert "DELEGATED_ADMIN_EMAIL" in reason


# ---------- deny-list ----------


def _t(**overrides) -> Target:
    base = dict(
        user_uid="u-1",
        user_name="alice@example.com",
        source_ips=(),
        session_uids=(),
        producer_skill="detect-google-workspace-suspicious-login",
        finding_uid="f-1",
    )
    base.update(overrides)
    return Target(**base)


def test_admin_email_is_denied():
    denied, matched = is_protected(_t(user_name="admin@example.com"), DEFAULT_DENY_PATTERNS)
    assert denied is True and matched == "admin"


def test_break_glass_is_denied():
    assert (
        is_protected(_t(user_name="break-glass-oncall@example.com"), DEFAULT_DENY_PATTERNS)[0]
        is True
    )


def test_google_employee_is_denied():
    assert is_protected(_t(user_name="someone@google.com"), DEFAULT_DENY_PATTERNS)[0] is True


def test_regular_user_passes():
    assert is_protected(_t(user_name="alice@example.com"), DEFAULT_DENY_PATTERNS)[0] is False


def test_extensible_via_env_file(tmp_path, monkeypatch):
    extra = tmp_path / "extra.json"
    extra.write_text('["@contractor.example.com", "intern-"]')
    monkeypatch.setenv("WORKSPACE_SESSION_KILL_DENY_LIST_FILE", str(extra))
    patterns = load_deny_patterns()
    assert "@contractor.example.com" in patterns
    assert "intern-" in patterns
    # Default patterns still present
    assert "@google.com" in patterns


# ---------- parse_targets ----------


def test_parse_targets_extracts_user_and_forensics():
    target, _ = next(
        parse_targets([_finding(ips=["198.51.100.5", "198.51.100.6"], sessions=["s1"])])
    )
    assert target.user_uid == "alice@example.com"
    assert target.user_name == "Alice Example"
    assert target.source_ips == ("198.51.100.5", "198.51.100.6")
    assert target.session_uids == ("s1",)


def test_parse_targets_rejects_wrong_producer(capsys):
    target, _ = next(parse_targets([_finding(producer="detect-okta-mfa-fatigue")]))
    assert target is None
    assert "unaccepted producer" in capsys.readouterr().err


def test_parse_targets_handles_missing_user_uid():
    target, _ = next(parse_targets([_finding(omit_user_uid=True)]))
    assert target is not None
    assert target.user_uid == ""


# ---------- run: dry-run ----------


def test_run_dry_run_emits_plan_with_two_actions():
    records = list(run([_finding()], workspace_client=_FakeWorkspace()))
    rec = records[0]
    assert rec["record_type"] == "remediation_plan"
    assert rec["status"] == STATUS_PLANNED
    assert rec["dry_run"] is True
    assert [a["step"] for a in rec["actions"]] == list(CONTAINMENT_STEPS)


def test_run_dry_run_does_not_touch_workspace():
    ws = _FakeWorkspace()
    list(run([_finding()], workspace_client=ws))
    assert ws.calls == []


# ---------- run: skip paths ----------


def test_run_skips_finding_without_user_uid():
    records = list(run([_finding(omit_user_uid=True)], workspace_client=_FakeWorkspace()))
    assert records[0]["status"] == STATUS_SKIPPED_NO_USER


def test_run_skips_protected_principal_dry_run():
    records = list(
        run([_finding(user_name="admin@example.com")], workspace_client=_FakeWorkspace())
    )
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_DENY_LIST


def test_run_skips_protected_principal_apply():
    audit = _FakeAudit()
    ws = _FakeWorkspace()
    records = list(
        run(
            [_finding(user_name="break-glass-oncall@example.com")],
            workspace_client=ws,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_domains=("example.com",),
        )
    )
    assert records[0]["status"] == STATUS_SKIPPED_DENY_LIST
    assert ws.calls == []
    assert audit.writes == []


# ---------- run: apply ----------


def test_run_apply_runs_both_steps_with_dual_audit():
    audit = _FakeAudit()
    ws = _FakeWorkspace()
    records = list(
        run(
            [_finding()],
            workspace_client=ws,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            allowed_domains=("example.com",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["dry_run"] is False
    assert rec["incident_id"] == "INC-1"

    # Both Workspace API calls fired in order
    assert [c[0] for c in ws.calls] == ["sign_out", "force_password_change"]

    # Dual audit per step: 2 steps × 2 writes = 4 audit rows
    assert len(audit.writes) == 4
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[0]["step"] == STEP_SIGN_OUT
    assert audit.writes[1]["status"] == STATUS_SUCCESS
    assert audit.writes[1]["step"] == STEP_SIGN_OUT
    assert audit.writes[2]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[2]["step"] == STEP_FORCE_PASSWORD_CHANGE
    assert audit.writes[3]["status"] == STATUS_SUCCESS
    assert audit.writes[3]["step"] == STEP_FORCE_PASSWORD_CHANGE


def test_run_apply_marks_failure_when_step_throws():
    """If sign_out fails, force_password_change still runs (best-effort
    containment). Overall status reflects the failure."""
    audit = _FakeAudit()
    ws = _FakeWorkspace(fail_on="sign_out")
    records = list(
        run(
            [_finding()],
            workspace_client=ws,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_domains=("example.com",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_FAILURE
    # sign_out marked failure, force_password_change still attempted
    assert rec["actions"][0]["status"] == STATUS_FAILURE
    assert rec["actions"][1]["status"] == STATUS_SUCCESS
    # Audit captured the failure row
    assert any(w["status"] == STATUS_FAILURE for w in audit.writes)


def test_run_apply_requires_both_clients():
    import pytest

    with pytest.raises(RuntimeError, match="apply=True requires"):
        list(
            run(
                [_finding()],
                workspace_client=_FakeWorkspace(),
                apply=True,
                audit=None,
                allowed_domains=("example.com",),
            )
        )
    with pytest.raises(RuntimeError, match="apply=True requires"):
        list(
            run(
                [_finding()],
                workspace_client=None,
                apply=True,
                audit=_FakeAudit(),
                allowed_domains=("example.com",),
            )
        )


def test_run_apply_skips_wrong_domain_boundary():
    audit = _FakeAudit()
    ws = _FakeWorkspace()
    records = list(
        run(
            [_finding(user_uid="alice@other.com")],
            workspace_client=ws,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_domains=("example.com",),
        )
    )
    assert records[0]["status"] == STATUS_SKIPPED_DOMAIN_BOUNDARY
    assert ws.calls == []
    assert audit.writes == []


# ---------- run: re-verify ----------


def test_run_reverify_verified_when_no_recent_login():
    ws = _FakeWorkspace()  # no recent logins
    records = list(run([_finding()], workspace_client=ws, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"


def test_run_reverify_drift_emits_ocsf_finding_alongside_verification():
    """DRIFT (attacker came back in) must yield BOTH a verification record AND
    an OCSF Detection Finding (class_uid 2004) so the gap flows through the
    same SIEM/SOAR pipeline as every other finding."""
    ws = _FakeWorkspace(recent_logins_by_user={"alice@example.com": [{"id": "act-1"}]})
    records = list(run([_finding()], workspace_client=ws, reverify=True))
    assert len(records) == 2
    verification, finding = records
    assert verification["status"] == "drift"
    assert finding["class_uid"] == 2004
    assert finding["category_uid"] == 2
    assert finding["severity_id"] == 4
    assert finding["finding_info"]["types"] == ["remediation-drift"]
    assert any(
        obs["name"] == "remediation.skill" and obs["value"] == "remediate-workspace-session-kill"
        for obs in finding["observables"]
    )


def test_run_reverify_unreachable_never_silently_downgrades():
    ws = _FakeWorkspace(fail_on="list_recent_successful_logins")
    records = list(run([_finding()], workspace_client=ws, reverify=True))
    assert len(records) == 1  # no drift finding on UNREACHABLE
    assert records[0]["status"] == "unreachable"


def test_run_reverify_uses_finding_time_as_remediation_reference():
    ws = _FakeWorkspace()
    event = _finding()
    event["time"] = 1700000000456
    records = list(run([event], workspace_client=ws, reverify=True))
    assert records[0]["reference"]["remediated_at_ms"] == 1700000000456
    assert ws.calls[-1] == ("list_recent_successful_logins", "alice@example.com", 1700000000456)


def test_run_reverify_requires_workspace_client():
    import pytest

    with pytest.raises(RuntimeError, match="reverify=True requires"):
        list(run([_finding()], workspace_client=None, reverify=True))


def test_run_reverify_skips_protected_principal_without_api_call():
    """Protected principal must NOT trigger a Reports API read either."""
    ws = _FakeWorkspace()
    records = list(
        run([_finding(user_name="admin@example.com")], workspace_client=ws, reverify=True)
    )
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_DENY_LIST
    assert ws.calls == []
