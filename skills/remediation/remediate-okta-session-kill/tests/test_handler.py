"""Tests for remediate-okta-session-kill.

Covers the zero-trust / HITL / dual-audit / dry-run-by-default guardrails
declared in SKILL.md.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    CONTAINMENT_STEPS,
    DEFAULT_DENY_PATTERNS,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_DENY_LIST,
    STATUS_SUCCESS,
    STEP_REVOKE_OAUTH_TOKENS,
    STEP_REVOKE_SESSIONS,
    Target,
    apply_actions,
    check_apply_gate,
    is_protected,
    load_deny_patterns,
    main,
    parse_targets,
    run,
)

# -- helpers -----------------------------------------------------------------


def _finding(
    *,
    producer: str = "detect-okta-mfa-fatigue",
    user_uid: str = "00u-alice",
    user_name: str = "alice@example.com",
    finding_uid: str = "find-1",
    ips: list[str] | None = None,
    sessions: list[str] | None = None,
) -> dict:
    obs: list[dict] = [
        {"name": "user.uid", "type": "User Name", "value": user_uid},
        {"name": "user.name", "type": "User Name", "value": user_name},
    ]
    for ip in ips or []:
        obs.append({"name": "src.ip", "type": "IP Address", "value": ip})
    for s in sessions or []:
        obs.append({"name": "session.uid", "type": "Other", "value": s})
    return {
        "class_uid": 2004,
        "metadata": {
            "uid": finding_uid,
            "product": {"feature": {"name": producer}},
        },
        "finding_info": {"uid": finding_uid},
        "observables": obs,
    }


@dataclass
class _FakeOkta:
    """In-memory Okta client for tests. Records every call made."""

    fail_on: str | None = None
    calls: list[tuple[str, str]] = field(default_factory=list)
    # For reverify tests
    sessions_by_user: dict[str, list[dict]] = field(default_factory=dict)
    tokens_by_user: dict[str, list[dict]] = field(default_factory=dict)

    def revoke_sessions(self, user_id: str) -> None:
        self.calls.append(("revoke_sessions", user_id))
        if self.fail_on == "revoke_sessions":
            raise RuntimeError("simulated Okta 500")

    def revoke_oauth_tokens(self, user_id: str) -> None:
        self.calls.append(("revoke_oauth_tokens", user_id))
        if self.fail_on == "revoke_oauth_tokens":
            raise RuntimeError("simulated Okta 500")

    def list_active_sessions(self, user_id: str) -> list[dict]:
        self.calls.append(("list_active_sessions", user_id))
        if self.fail_on == "list_active_sessions":
            raise RuntimeError("simulated Okta 500")
        return list(self.sessions_by_user.get(user_id, []))

    def list_active_oauth_tokens(self, user_id: str) -> list[dict]:
        self.calls.append(("list_active_oauth_tokens", user_id))
        if self.fail_on == "list_active_oauth_tokens":
            raise RuntimeError("simulated Okta 500")
        return list(self.tokens_by_user.get(user_id, []))


@dataclass
class _FakeAudit:
    """In-memory audit writer. Records every audit write in order."""

    writes: list[dict] = field(default_factory=list)

    def record(self, *, target, step, status, detail, incident_id, approver):
        row_uid = f"audit-{len(self.writes):03d}"
        entry = {
            "row_uid": row_uid,
            "s3_evidence_uri": f"s3://bucket/key-{row_uid}",
            "target_uid": target.user_uid,
            "step": step,
            "status": status,
            "detail": detail,
            "incident_id": incident_id,
            "approver": approver,
        }
        self.writes.append(entry)
        return {"row_uid": entry["row_uid"], "s3_evidence_uri": entry["s3_evidence_uri"]}


# -- frontmatter / constant invariants --------------------------------------


class TestContract:
    def test_accepted_producers_are_the_two_okta_detectors(self):
        assert ACCEPTED_PRODUCERS == frozenset(
            {"detect-okta-mfa-fatigue", "detect-credential-stuffing-okta"}
        )

    def test_containment_steps_in_safe_order(self):
        assert CONTAINMENT_STEPS == (STEP_REVOKE_SESSIONS, STEP_REVOKE_OAUTH_TOKENS)

    def test_default_deny_patterns_cover_protected_principal_classes(self):
        as_text = " ".join(DEFAULT_DENY_PATTERNS).lower()
        for required in (
            "admin",
            "service-account",
            "break-glass",
            "emergency",
            "root",
            "@okta.com",
        ):
            assert required in as_text


# -- parse_targets -----------------------------------------------------------


class TestParseTargets:
    def test_accepts_mfa_fatigue_finding(self):
        results = list(parse_targets([_finding(producer="detect-okta-mfa-fatigue")]))
        assert len(results) == 1
        target, _ = results[0]
        assert target is not None
        assert target.user_uid == "00u-alice"
        assert target.user_name == "alice@example.com"
        assert target.producer_skill == "detect-okta-mfa-fatigue"

    def test_accepts_credential_stuffing_finding(self):
        results = list(parse_targets([_finding(producer="detect-credential-stuffing-okta")]))
        target, _ = results[0]
        assert target is not None
        assert target.producer_skill == "detect-credential-stuffing-okta"

    def test_refuses_non_okta_producer(self, capsys):
        results = list(parse_targets([_finding(producer="detect-entra-role-grant-escalation")]))
        assert len(results) == 1
        target, _ = results[0]
        assert target is None
        # stderr warning fired — emit_stderr_event plain mode prints the message
        captured = capsys.readouterr().err
        assert "unaccepted producer" in captured

    def test_skips_finding_without_user_uid(self, capsys):
        event = _finding()
        event["observables"] = [o for o in event["observables"] if o["name"] != "user.uid"]
        results = list(parse_targets([event]))
        assert results[0][0] is None

    def test_preserves_source_ips_and_sessions_for_forensic_audit(self):
        event = _finding(
            ips=["198.51.100.25", "198.51.100.26"],
            sessions=["sess-1", "sess-2"],
        )
        target, _ = next(parse_targets([event]))
        assert target is not None
        assert target.source_ips == ("198.51.100.25", "198.51.100.26")
        assert target.session_uids == ("sess-1", "sess-2")


# -- deny-list guardrail -----------------------------------------------------


class TestDenyList:
    def test_admin_email_is_denied(self):
        t = Target(
            user_uid="00u-1",
            user_name="admin@example.com",
            source_ips=(),
            session_uids=(),
            producer_skill="x",
            finding_uid="f",
        )
        denied, matched = is_protected(t, DEFAULT_DENY_PATTERNS)
        assert denied is True
        assert matched == "admin"

    def test_service_account_is_denied(self):
        t = Target(
            user_uid="00u-2",
            user_name="service-account-ci@example.com",
            source_ips=(),
            session_uids=(),
            producer_skill="x",
            finding_uid="f",
        )
        assert is_protected(t, DEFAULT_DENY_PATTERNS)[0] is True

    def test_break_glass_is_denied(self):
        t = Target(
            user_uid="00u-3",
            user_name="break-glass-oncall@example.com",
            source_ips=(),
            session_uids=(),
            producer_skill="x",
            finding_uid="f",
        )
        assert is_protected(t, DEFAULT_DENY_PATTERNS)[0] is True

    def test_okta_employee_is_denied(self):
        t = Target(
            user_uid="00u-4",
            user_name="someone@okta.com",
            source_ips=(),
            session_uids=(),
            producer_skill="x",
            finding_uid="f",
        )
        assert is_protected(t, DEFAULT_DENY_PATTERNS)[0] is True

    def test_regular_user_passes(self):
        t = Target(
            user_uid="00u-5",
            user_name="alice@example.com",
            source_ips=(),
            session_uids=(),
            producer_skill="x",
            finding_uid="f",
        )
        assert is_protected(t, DEFAULT_DENY_PATTERNS)[0] is False

    def test_additional_patterns_from_env_file(self, tmp_path, monkeypatch):
        extra = tmp_path / "extra.json"
        extra.write_text('["@contractor.example.com", "intern-"]')
        monkeypatch.setenv("OKTA_SESSION_KILL_DENY_LIST_FILE", str(extra))
        patterns = load_deny_patterns()
        assert "@contractor.example.com" in patterns
        assert "intern-" in patterns
        # Hard-coded ones still present
        assert "break-glass" in patterns

    def test_extra_file_cannot_remove_built_ins(self, tmp_path, monkeypatch):
        extra = tmp_path / "extra.json"
        extra.write_text("[]")
        monkeypatch.setenv("OKTA_SESSION_KILL_DENY_LIST_FILE", str(extra))
        patterns = load_deny_patterns()
        assert set(DEFAULT_DENY_PATTERNS).issubset(set(patterns))

    def test_malformed_deny_file_keeps_built_ins(self, tmp_path, monkeypatch, capsys):
        extra = tmp_path / "broken.json"
        extra.write_text("not json")
        monkeypatch.setenv("OKTA_SESSION_KILL_DENY_LIST_FILE", str(extra))
        patterns = load_deny_patterns()
        assert set(DEFAULT_DENY_PATTERNS).issubset(set(patterns))
        captured = capsys.readouterr().err
        assert "could not load" in captured

    def test_deny_list_blocks_run_even_under_apply(self):
        """An --apply invocation against a protected principal must NEVER hit Okta."""
        fake_okta = _FakeOkta()
        fake_audit = _FakeAudit()
        records = list(
            run(
                [_finding(user_name="admin@example.com")],
                apply=True,
                okta_client=fake_okta,
                audit=fake_audit,
                deny_patterns=DEFAULT_DENY_PATTERNS,
                incident_id="inc-1",
                approver="alice",
            )
        )
        assert len(records) == 1
        assert records[0]["status"] == STATUS_SKIPPED_DENY_LIST
        assert fake_okta.calls == []
        assert fake_audit.writes == []


# -- dry-run default ---------------------------------------------------------


class TestDryRunDefault:
    def test_default_emits_plan_not_action(self):
        records = list(
            run(
                [_finding()],
                apply=False,
                okta_client=None,
                audit=None,
            )
        )
        assert len(records) == 1
        assert records[0]["record_type"] == "remediation_plan"
        assert records[0]["dry_run"] is True
        assert records[0]["status"] == STATUS_PLANNED
        steps = [a["step"] for a in records[0]["actions"]]
        assert steps == list(CONTAINMENT_STEPS)
        assert all(a["status"] == STATUS_PLANNED for a in records[0]["actions"])

    def test_dry_run_does_not_require_okta_client_or_audit(self):
        # Plain run without clients must not crash.
        list(run([_finding()], apply=False, okta_client=None, audit=None))

    def test_plan_endpoints_match_okta_api_shape(self):
        records = list(run([_finding(user_uid="00u-x")], apply=False, okta_client=None, audit=None))
        endpoints = {a["endpoint"] for a in records[0]["actions"]}
        assert "DELETE /api/v1/users/00u-x/sessions" in endpoints
        assert "DELETE /api/v1/users/00u-x/oauth/tokens" in endpoints


# -- apply gate --------------------------------------------------------------


class TestApplyGate:
    def test_missing_incident_id_fails_closed(self, monkeypatch):
        monkeypatch.delenv("OKTA_SESSION_KILL_INCIDENT_ID", raising=False)
        monkeypatch.setenv("OKTA_SESSION_KILL_APPROVER", "alice")
        monkeypatch.setenv("OKTA_ORG_URL", "https://example.okta.com")
        monkeypatch.setenv("OKTA_SESSION_KILL_ALLOWED_ORG_URLS", "https://example.okta.com")
        ok, reason = check_apply_gate()
        assert ok is False
        assert "INCIDENT_ID" in reason

    def test_missing_approver_fails_closed(self, monkeypatch):
        monkeypatch.setenv("OKTA_SESSION_KILL_INCIDENT_ID", "inc-1")
        monkeypatch.delenv("OKTA_SESSION_KILL_APPROVER", raising=False)
        monkeypatch.setenv("OKTA_ORG_URL", "https://example.okta.com")
        monkeypatch.setenv("OKTA_SESSION_KILL_ALLOWED_ORG_URLS", "https://example.okta.com")
        ok, reason = check_apply_gate()
        assert ok is False
        assert "APPROVER" in reason

    def test_missing_allowed_org_urls_fails_closed(self, monkeypatch):
        monkeypatch.setenv("OKTA_SESSION_KILL_INCIDENT_ID", "inc-1")
        monkeypatch.setenv("OKTA_SESSION_KILL_APPROVER", "alice@example.com")
        monkeypatch.setenv("OKTA_ORG_URL", "https://example.okta.com")
        monkeypatch.delenv("OKTA_SESSION_KILL_ALLOWED_ORG_URLS", raising=False)
        ok, reason = check_apply_gate()
        assert ok is False
        assert "ALLOWED_ORG_URLS" in reason

    def test_org_url_outside_allow_list_fails_closed(self, monkeypatch):
        monkeypatch.setenv("OKTA_SESSION_KILL_INCIDENT_ID", "inc-1")
        monkeypatch.setenv("OKTA_SESSION_KILL_APPROVER", "alice@example.com")
        monkeypatch.setenv("OKTA_ORG_URL", "https://prod.okta.com")
        monkeypatch.setenv("OKTA_SESSION_KILL_ALLOWED_ORG_URLS", "https://sandbox.okta.com")
        ok, reason = check_apply_gate()
        assert ok is False
        assert "ALLOWED_ORG_URLS" in reason

    def test_both_set_passes(self, monkeypatch):
        monkeypatch.setenv("OKTA_SESSION_KILL_INCIDENT_ID", "inc-1")
        monkeypatch.setenv("OKTA_SESSION_KILL_APPROVER", "alice@example.com")
        monkeypatch.setenv("OKTA_ORG_URL", "https://example.okta.com")
        monkeypatch.setenv("OKTA_SESSION_KILL_ALLOWED_ORG_URLS", "https://example.okta.com")
        ok, reason = check_apply_gate()
        assert ok is True
        assert reason == ""

    def test_main_returns_2_when_apply_gate_blocks(self, monkeypatch, tmp_path, capsys):
        monkeypatch.delenv("OKTA_SESSION_KILL_INCIDENT_ID", raising=False)
        monkeypatch.delenv("OKTA_SESSION_KILL_APPROVER", raising=False)
        monkeypatch.setenv("OKTA_ORG_URL", "https://example.okta.com")
        monkeypatch.setenv("OKTA_SESSION_KILL_ALLOWED_ORG_URLS", "https://example.okta.com")
        finding_path = tmp_path / "f.jsonl"
        finding_path.write_text("{}\n")
        rc = main([str(finding_path), "--apply"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "OKTA_SESSION_KILL_INCIDENT_ID" in err


# -- apply_actions: audit-before-write invariant ----------------------------


class TestApplyActions:
    def test_audit_write_precedes_okta_call(self):
        """Invariant: audit row exists BEFORE the Okta API call for every step."""
        target = Target(
            user_uid="00u-1",
            user_name="alice@example.com",
            source_ips=(),
            session_uids=(),
            producer_skill="detect-okta-mfa-fatigue",
            finding_uid="f",
        )

        # Ordered log of operations so we can prove the sequence.
        order: list[str] = []

        @dataclass
        class OrderedAudit:
            writes: list[dict] = field(default_factory=list)

            def record(self, *, target, step, status, detail, incident_id, approver):
                order.append(f"audit:{step}:{status}")
                self.writes.append({"step": step, "status": status})
                return {
                    "row_uid": f"r{len(self.writes)}",
                    "s3_evidence_uri": f"s3://b/k{len(self.writes)}",
                }

        class OrderedOkta:
            def revoke_sessions(self, user_id):
                order.append(f"okta:revoke_sessions:{user_id}")

            def revoke_oauth_tokens(self, user_id):
                order.append(f"okta:revoke_oauth_tokens:{user_id}")

        audit = OrderedAudit()
        okta = OrderedOkta()

        results, refs = apply_actions(
            target,
            okta_client=okta,
            audit=audit,
            incident_id="inc-1",
            approver="alice",
        )

        # Each step follows: audit:in_progress → okta:call → audit:success/failure
        assert order == [
            "audit:revoke_sessions:in_progress",
            "okta:revoke_sessions:00u-1",
            "audit:revoke_sessions:success",
            "audit:revoke_oauth_tokens:in_progress",
            "okta:revoke_oauth_tokens:00u-1",
            "audit:revoke_oauth_tokens:success",
        ]
        assert [r.status for r in results] == [STATUS_SUCCESS, STATUS_SUCCESS]

    def test_okta_failure_still_writes_audit(self):
        """Even when the Okta call raises, we record status=failure + detail."""
        target = Target(
            user_uid="00u-1",
            user_name="alice@example.com",
            source_ips=(),
            session_uids=(),
            producer_skill="detect-okta-mfa-fatigue",
            finding_uid="f",
        )
        fake_okta = _FakeOkta(fail_on="revoke_sessions")
        fake_audit = _FakeAudit()
        results, refs = apply_actions(
            target,
            okta_client=fake_okta,
            audit=fake_audit,
            incident_id="inc-1",
            approver="alice",
        )
        # Stopped after the failing step
        assert len(results) == 1
        assert results[0].step == STEP_REVOKE_SESSIONS
        assert results[0].status == STATUS_FAILURE
        assert results[0].detail == "simulated Okta 500"
        # Both pre-write and post-write audit rows land for the failing step
        steps_and_statuses = [(w["step"], w["status"]) for w in fake_audit.writes]
        assert (STEP_REVOKE_SESSIONS, STATUS_IN_PROGRESS) in steps_and_statuses
        assert (STEP_REVOKE_SESSIONS, STATUS_FAILURE) in steps_and_statuses
        # OAuth-token step never attempted because earlier step failed
        assert (STEP_REVOKE_OAUTH_TOKENS, STATUS_IN_PROGRESS) not in steps_and_statuses


# -- end-to-end apply --------------------------------------------------------


class TestApplyEndToEnd:
    def test_happy_path_emits_action_record_with_audit_refs(self):
        fake_okta = _FakeOkta()
        fake_audit = _FakeAudit()
        records = list(
            run(
                [_finding(ips=["203.0.113.10"], sessions=["sess-1"])],
                apply=True,
                okta_client=fake_okta,
                audit=fake_audit,
                incident_id="inc-2026-04-18-001",
                approver="alice@example.com",
                org_url="https://example.okta.com",
                allowed_org_urls=("https://example.okta.com",),
                now_ms=1776046500000,
            )
        )
        assert len(records) == 1
        rec = records[0]
        assert rec["record_type"] == "remediation_action"
        assert rec["dry_run"] is False
        assert rec["status"] == STATUS_SUCCESS
        assert rec["incident_id"] == "inc-2026-04-18-001"
        assert rec["approver"] == "alice@example.com"
        assert [a["step"] for a in rec["actions"]] == list(CONTAINMENT_STEPS)
        assert all(a["status"] == STATUS_SUCCESS for a in rec["actions"])
        # audit refs populated for both before and after of each step
        assert "revoke_sessions_before_row_uid" in rec["audit"]
        assert "revoke_sessions_after_row_uid" in rec["audit"]
        assert "revoke_oauth_tokens_before_row_uid" in rec["audit"]
        assert "revoke_oauth_tokens_after_row_uid" in rec["audit"]
        # Okta received the expected calls in order
        assert fake_okta.calls == [
            ("revoke_sessions", "00u-alice"),
            ("revoke_oauth_tokens", "00u-alice"),
        ]

    def test_apply_without_client_raises(self):
        """Programming error — caller passed apply=True without providing clients."""
        with pytest.raises(RuntimeError):
            list(
                run(
                    [_finding()],
                    apply=True,
                    okta_client=None,
                    audit=None,
                    incident_id="inc-1",
                    approver="alice",
                    org_url="https://example.okta.com",
                    allowed_org_urls=("https://example.okta.com",),
                )
            )

    def test_apply_rejects_wrong_org_boundary(self):
        with pytest.raises(RuntimeError, match="ALLOWED_ORG_URLS"):
            list(
                run(
                    [_finding()],
                    apply=True,
                    okta_client=_FakeOkta(),
                    audit=_FakeAudit(),
                    incident_id="inc-1",
                    approver="alice",
                    org_url="https://prod.okta.com",
                    allowed_org_urls=("https://sandbox.okta.com",),
                )
            )

    def test_multiple_findings_produce_multiple_records(self):
        fake_okta = _FakeOkta()
        fake_audit = _FakeAudit()
        events = [
            _finding(user_uid="00u-a", user_name="alice@example.com", finding_uid="f1"),
            _finding(user_uid="00u-b", user_name="bob@example.com", finding_uid="f2"),
        ]
        records = list(
            run(
                events,
                apply=True,
                okta_client=fake_okta,
                audit=fake_audit,
                incident_id="inc-1",
                approver="alice",
                org_url="https://example.okta.com",
                allowed_org_urls=("https://example.okta.com",),
            )
        )
        assert len(records) == 2
        assert {r["target"]["user_uid"] for r in records} == {"00u-a", "00u-b"}
        # 2 steps × 2 writes each × 2 users = 8 audit rows
        assert len(fake_audit.writes) == 8


class TestReverify:
    """Re-verification path: confirm session-kill landed and didn't drift."""

    def test_reverify_verified_when_no_sessions_or_tokens(self):
        fake_okta = _FakeOkta()  # no sessions, no tokens
        records = list(
            run([_finding()], apply=False, reverify=True, okta_client=fake_okta, audit=None)
        )
        assert len(records) == 1
        rec = records[0]
        assert rec["record_type"] == "remediation_verification"
        assert rec["status"] == "verified"
        assert rec["reference"]["remediation_skill"] == "remediate-okta-session-kill"
        assert rec["reference"]["target_provider"] == "Okta"

    def test_reverify_drift_emits_verification_record_plus_ocsf_finding(self):
        """DRIFT must yield BOTH a remediation_verification record AND an OCSF
        Detection Finding (class_uid 2004) so the drift flows through the
        same SIEM/SOAR pipeline as every other finding."""
        fake_okta = _FakeOkta(
            sessions_by_user={"00u-a": [{"id": "sess-1"}]},
        )
        records = list(
            run(
                [_finding(user_uid="00u-a")],
                apply=False,
                reverify=True,
                okta_client=fake_okta,
                audit=None,
            )
        )
        assert len(records) == 2
        verification, finding = records
        assert verification["record_type"] == "remediation_verification"
        assert verification["status"] == "drift"
        assert finding["class_uid"] == 2004
        assert finding["category_uid"] == 2
        assert finding["severity_id"] == 4
        assert finding["finding_info"]["types"] == ["remediation-drift"]
        assert any(
            obs["name"] == "remediation.skill" and obs["value"] == "remediate-okta-session-kill"
            for obs in finding["observables"]
        )

    def test_reverify_drift_when_oauth_tokens_remain(self):
        fake_okta = _FakeOkta(
            tokens_by_user={"00u-a": [{"id": "tok-1"}]},
        )
        records = list(
            run(
                [_finding(user_uid="00u-a")],
                apply=False,
                reverify=True,
                okta_client=fake_okta,
                audit=None,
            )
        )
        assert len(records) == 2
        assert records[0]["status"] == "drift"

    def test_reverify_unreachable_never_silently_downgrades_to_verified(self):
        """If Okta API throws, the verifier must surface UNREACHABLE — never
        silently report VERIFIED. Operator must see the gap."""
        fake_okta = _FakeOkta(fail_on="list_active_sessions")
        records = list(
            run([_finding()], apply=False, reverify=True, okta_client=fake_okta, audit=None)
        )
        assert len(records) == 1
        rec = records[0]
        assert rec["status"] == "unreachable"
        # No drift finding emitted on UNREACHABLE — only on DRIFT
        assert rec["record_type"] == "remediation_verification"

    def test_reverify_requires_okta_client(self):
        import pytest

        with pytest.raises(RuntimeError, match="reverify=True requires okta_client"):
            list(run([_finding()], apply=False, reverify=True, okta_client=None, audit=None))

    def test_reverify_skips_protected_principal(self):
        """Protected principals are skipped before any reverify call —
        the deny-list is enforced regardless of mode."""
        fake_okta = _FakeOkta()
        records = list(
            run(
                [_finding(user_name="root@example.com")],
                apply=False,
                reverify=True,
                okta_client=fake_okta,
                audit=None,
                deny_patterns=("root",),
            )
        )
        # No Okta API call should have been made
        assert fake_okta.calls == []
        assert len(records) == 1
        assert records[0]["status"] == STATUS_SKIPPED_DENY_LIST
