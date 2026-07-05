"""Tests for remediate-entra-credential-revoke."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    DEFAULT_PROTECTED_NAME_PREFIXES,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_TARGET,
    STATUS_SKIPPED_PROTECTED,
    STATUS_SKIPPED_UNSUPPORTED_TYPE,
    STATUS_SUCCESS,
    STATUS_WOULD_VIOLATE_PROTECTED,
    ResolvedServicePrincipal,
    Target,
    check_apply_gate,
    is_protected_target,
    parse_targets,
    run,
)


def _finding(
    *,
    producer: str = "detect-entra-credential-addition",
    object_id: str = "11111111-1111-1111-1111-111111111111",
    display_name: str = "rogue-app",
    target_type: str = "ServicePrincipal",
    actor: str = "attacker@example.com",
    api_operation: str = "Update application -- Certificates and secrets management",
    rule: str = "entra-credential-addition",
    finding_uid: str = "find-1",
    omit_target_uid: bool = False,
) -> dict:
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "Azure"},
        {"name": "actor.name", "type": "Other", "value": actor},
        {"name": "api.operation", "type": "Other", "value": api_operation},
        {"name": "rule", "type": "Other", "value": rule},
        {"name": "target.name", "type": "Other", "value": display_name},
        {"name": "target.type", "type": "Other", "value": target_type},
    ]
    if not omit_target_uid:
        observables.append({"name": "target.uid", "type": "Other", "value": object_id})
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

    def record(self, *, target, step, status, detail, incident_id, approver):
        entry = {
            "object_id": target.object_id,
            "step": step,
            "status": status,
            "detail": detail,
            "incident_id": incident_id,
            "approver": approver,
        }
        self.writes.append(entry)
        return {
            "row_uid": f"row-{len(self.writes)}",
            "s3_evidence_uri": f"s3://bucket/{target.object_id}-{len(self.writes)}.json",
        }


@dataclass
class _FakeGraph:
    sps: dict[str, dict] = field(default_factory=dict)  # object_id → {accountEnabled: bool}
    applications: dict[str, dict] = field(
        default_factory=dict
    )  # object_id → {appId: str, displayName: str}
    service_principals_by_app_id: dict[str, list[dict]] = field(default_factory=dict)
    keys: dict[str, list[dict]] = field(default_factory=dict)
    passwords: dict[str, list[dict]] = field(default_factory=dict)
    role_assignments: dict[str, list[dict]] = field(default_factory=dict)
    oauth_grants: dict[str, list[dict]] = field(default_factory=dict)
    raise_on_disable: bool = False
    raise_on_get: bool = False
    raise_on_triage: bool = False
    disabled: list[str] = field(default_factory=list)

    def resolve_service_principal(self, target):
        if target.target_type == "Application":
            app = self.applications.get(target.object_id)
            if app is None:
                return None
            app_id = str(app.get("appId") or "")
            matches = list(self.service_principals_by_app_id.get(app_id, []))
            if not matches:
                return None
            if len(matches) > 1:
                raise RuntimeError("application resolved to multiple service principals")
            match = matches[0]
            return ResolvedServicePrincipal(
                object_id=str(match.get("id") or ""),
                display_name=str(match.get("displayName") or target.display_name),
                app_id=str(match.get("appId") or app_id),
                source_target_type=target.target_type,
                source_object_id=target.object_id,
            )
        sp = self.sps.get(target.object_id, {})
        return ResolvedServicePrincipal(
            object_id=target.object_id,
            display_name=str(sp.get("displayName") or target.display_name),
            app_id=str(sp.get("appId") or ""),
            source_target_type=target.target_type,
            source_object_id=target.object_id,
        )

    def get_service_principal(self, object_id):
        if self.raise_on_get:
            raise RuntimeError("simulated graph 502")
        return self.sps.get(object_id)

    def disable_service_principal(self, object_id):
        if self.raise_on_disable:
            raise RuntimeError("simulated graph 403 forbidden")
        self.disabled.append(object_id)
        existing = self.sps.setdefault(object_id, {})
        existing["accountEnabled"] = False

    def list_key_credentials(self, object_id):
        if self.raise_on_triage:
            raise RuntimeError("simulated graph 502 on triage")
        return list(self.keys.get(object_id, []))

    def list_password_credentials(self, object_id):
        return list(self.passwords.get(object_id, []))

    def list_app_role_assignments(self, object_id):
        return list(self.role_assignments.get(object_id, []))

    def list_oauth2_permission_grants(self, object_id):
        return list(self.oauth_grants.get(object_id, []))


# ----------------- helpers -----------------


def test_accepted_producers_set_is_just_entra():
    assert ACCEPTED_PRODUCERS == frozenset(
        {"detect-entra-credential-addition", "detect-entra-role-grant-escalation"}
    )


def test_default_protected_name_prefixes_cover_critical_classes():
    as_text = " ".join(DEFAULT_PROTECTED_NAME_PREFIXES).lower()
    for required in ("break-glass", "emergency", "tenant-", "ms-", "microsoft-"):
        assert required in as_text


def _t(**overrides) -> Target:
    base = dict(
        object_id="oid-1",
        display_name="rogue",
        target_type="ServicePrincipal",
        actor="x",
        api_operation="y",
        rule="z",
        producer_skill="detect-entra-credential-addition",
        finding_uid="f-1",
    )
    base.update(overrides)
    return Target(**base)


def test_is_protected_matches_name_prefix():
    protected, why = is_protected_target(
        _t(display_name="break-glass-prod"),
        name_prefixes=DEFAULT_PROTECTED_NAME_PREFIXES,
        object_ids=(),
    )
    assert protected is True
    assert "break-glass" in why


def test_is_protected_matches_object_id_allowlist():
    protected, why = is_protected_target(
        _t(object_id="bootstrap-id"),
        name_prefixes=(),
        object_ids=("bootstrap-id",),
    )
    assert protected is True
    assert "bootstrap-id" in why


def test_regular_target_passes_protected_check():
    protected, _ = is_protected_target(
        _t(display_name="my-prod-app"),
        name_prefixes=DEFAULT_PROTECTED_NAME_PREFIXES,
        object_ids=(),
    )
    assert protected is False


def test_check_apply_gate_requires_both_envs(monkeypatch):
    monkeypatch.delenv("ENTRA_REVOKE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("ENTRA_REVOKE_APPROVER", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("ENTRA_REVOKE_ALLOWED_TENANT_IDS", raising=False)
    ok, reason = check_apply_gate()
    assert ok is False and "INCIDENT_ID" in reason
    monkeypatch.setenv("ENTRA_REVOKE_INCIDENT_ID", "INC-1")
    ok, reason = check_apply_gate()
    assert ok is False and "APPROVER" in reason
    monkeypatch.setenv("ENTRA_REVOKE_APPROVER", "alice")
    ok, reason = check_apply_gate()
    assert ok is False and "AZURE_TENANT_ID" in reason
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-a")
    ok, reason = check_apply_gate()
    assert ok is False and "ALLOWED_TENANT_IDS" in reason
    monkeypatch.setenv("ENTRA_REVOKE_ALLOWED_TENANT_IDS", "tenant-a")
    ok, _ = check_apply_gate()
    assert ok is True


# ----------------- parse_targets -----------------


def test_parse_targets_accepts_both_entra_producers():
    add = next(parse_targets([_finding(producer="detect-entra-credential-addition")]))[0]
    grant = next(
        parse_targets(
            [
                _finding(
                    producer="detect-entra-role-grant-escalation",
                    rule="entra-role-grant-escalation",
                )
            ]
        )
    )[0]
    assert add is not None and add.producer_skill == "detect-entra-credential-addition"
    assert grant is not None and grant.producer_skill == "detect-entra-role-grant-escalation"


def test_parse_targets_rejects_wrong_producer(capsys):
    target, _ = next(parse_targets([_finding(producer="detect-okta-mfa-fatigue")]))
    assert target is None
    assert "unaccepted producer" in capsys.readouterr().err


def test_parse_targets_extracts_observables():
    target, _ = next(parse_targets([_finding()]))
    assert target.object_id == "11111111-1111-1111-1111-111111111111"
    assert target.display_name == "rogue-app"
    assert target.target_type == "ServicePrincipal"
    assert target.actor == "attacker@example.com"


# ----------------- run: dry-run -----------------


def test_run_dry_run_emits_plan_with_two_actions():
    records = list(run([_finding()], graph_client=_FakeGraph()))
    assert len(records) == 1
    rec = records[0]
    assert rec["record_type"] == "remediation_plan"
    assert rec["status"] == STATUS_PLANNED
    assert rec["dry_run"] is True
    assert len(rec["actions"]) == 2
    assert rec["actions"][0]["step"] == "disable_service_principal"
    assert rec["actions"][1]["step"] == "list_credentials_and_assignments"
    # Triage payload not populated under dry-run (no Graph reads)
    assert rec["triage"] is None


def test_run_dry_run_does_not_touch_graph():
    graph = _FakeGraph()
    list(run([_finding()], graph_client=graph))
    assert graph.disabled == []


# ----------------- run: skip paths -----------------


def test_run_skips_finding_without_target_uid():
    records = list(run([_finding(omit_target_uid=True)], graph_client=_FakeGraph()))
    assert records[0]["status"] == STATUS_SKIPPED_NO_TARGET
    assert records[0]["actions"] == []


def test_run_skips_unsupported_target_type():
    records = list(run([_finding(target_type="Group")], graph_client=_FakeGraph()))
    assert records[0]["status"] == STATUS_SKIPPED_UNSUPPORTED_TYPE
    assert "Group" in records[0]["status_detail"]


def test_run_skips_protected_name_prefix_in_dry_run():
    records = list(
        run([_finding(display_name="break-glass-incident-app")], graph_client=_FakeGraph())
    )
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED
    assert "break-glass" in records[0]["status_detail"]


def test_run_skips_protected_object_id_in_apply():
    audit = _FakeAudit()
    graph = _FakeGraph()
    records = list(
        run(
            [_finding(object_id="bootstrap-sp-id")],
            graph_client=graph,
            apply=True,
            audit=audit,
            object_ids=("bootstrap-sp-id",),
            incident_id="INC-1",
            approver="alice",
            tenant_id="tenant-a",
            allowed_tenant_ids=("tenant-a",),
        )
    )
    assert records[0]["status"] == STATUS_SKIPPED_PROTECTED
    assert audit.writes == []
    assert graph.disabled == []


# ----------------- run: apply -----------------


def test_run_apply_disables_and_emits_triage_with_dual_audit():
    audit = _FakeAudit()
    graph = _FakeGraph(
        sps={"11111111-1111-1111-1111-111111111111": {"accountEnabled": True}},
        keys={"11111111-1111-1111-1111-111111111111": [{"keyId": "k-1"}, {"keyId": "k-2"}]},
        passwords={"11111111-1111-1111-1111-111111111111": [{"keyId": "p-1"}]},
        role_assignments={
            "11111111-1111-1111-1111-111111111111": [{"id": "ra-1", "appRoleId": "role-x"}]
        },
        oauth_grants={"11111111-1111-1111-1111-111111111111": []},
    )
    records = list(
        run(
            [_finding()],
            graph_client=graph,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            tenant_id="tenant-a",
            allowed_tenant_ids=("tenant-a",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["dry_run"] is False
    assert graph.disabled == ["11111111-1111-1111-1111-111111111111"]

    # Triage payload populated
    assert rec["triage"] is not None
    assert len(rec["triage"]["key_credentials"]) == 2
    assert len(rec["triage"]["password_credentials"]) == 1
    assert len(rec["triage"]["app_role_assignments"]) == 1

    # Audit: pre-disable IN_PROGRESS, post-disable SUCCESS, post-triage SUCCESS = 3 rows
    assert len(audit.writes) == 3
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[0]["step"] == "disable_service_principal"
    assert audit.writes[1]["status"] == STATUS_SUCCESS
    assert audit.writes[1]["step"] == "disable_service_principal"
    assert audit.writes[2]["status"] == STATUS_SUCCESS
    assert audit.writes[2]["step"] == "list_credentials_and_assignments"


def test_run_apply_writes_failure_audit_when_disable_throws():
    audit = _FakeAudit()
    graph = _FakeGraph(raise_on_disable=True)
    records = list(
        run(
            [_finding()],
            graph_client=graph,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            tenant_id="tenant-a",
            allowed_tenant_ids=("tenant-a",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_FAILURE
    assert "forbidden" in rec["actions"][0]["detail"]
    assert len(audit.writes) == 2
    assert audit.writes[1]["status"] == STATUS_FAILURE


def test_run_apply_disable_succeeds_even_if_triage_fails():
    """Containment is the priority. If triage list fails post-disable, the
    SP is still contained — record SUCCESS for disable but FAILURE for triage."""
    audit = _FakeAudit()
    graph = _FakeGraph(raise_on_triage=True)
    records = list(
        run(
            [_finding()],
            graph_client=graph,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            tenant_id="tenant-a",
            allowed_tenant_ids=("tenant-a",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS  # overall record reflects containment success
    assert graph.disabled == ["11111111-1111-1111-1111-111111111111"]
    assert rec["actions"][0]["status"] == "success"  # disable
    assert rec["actions"][1]["status"] == "failure"  # triage
    assert "triage list failed" in rec["actions"][1]["detail"]
    assert rec["triage"] is None


def test_run_apply_application_target_resolves_backing_service_principal():
    audit = _FakeAudit()
    graph = _FakeGraph(
        applications={"app-1": {"appId": "client-1", "displayName": "rogue-app"}},
        service_principals_by_app_id={
            "client-1": [{"id": "sp-1", "appId": "client-1", "displayName": "rogue-sp"}]
        },
        sps={"sp-1": {"accountEnabled": True, "displayName": "rogue-sp", "appId": "client-1"}},
    )
    records = list(
        run(
            [_finding(object_id="app-1", target_type="Application")],
            graph_client=graph,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            tenant_id="tenant-a",
            allowed_tenant_ids=("tenant-a",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert graph.disabled == ["sp-1"]
    assert rec["resolved_service_principal"]["object_id"] == "sp-1"
    assert audit.writes[0]["object_id"] == "sp-1"


def test_run_apply_requires_audit_writer():
    import pytest

    with pytest.raises(ValueError, match="audit writer is required"):
        list(
            run(
                [_finding()],
                graph_client=_FakeGraph(),
                apply=True,
                audit=None,
                tenant_id="tenant-a",
                allowed_tenant_ids=("tenant-a",),
            )
        )


def test_run_apply_rejects_wrong_tenant_boundary():
    import pytest

    with pytest.raises(ValueError, match="ALLOWED_TENANT_IDS"):
        list(
            run(
                [_finding()],
                graph_client=_FakeGraph(),
                apply=True,
                audit=_FakeAudit(),
                incident_id="INC-1",
                approver="alice",
                tenant_id="tenant-a",
                allowed_tenant_ids=("tenant-b",),
            )
        )


# ----------------- run: re-verify -----------------


def test_run_reverify_verified_when_sp_still_disabled():
    graph = _FakeGraph(sps={"11111111-1111-1111-1111-111111111111": {"accountEnabled": False}})
    records = list(run([_finding()], graph_client=graph, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"


def test_run_reverify_verified_when_sp_was_deleted():
    """Absence is stronger than disabled — count as verified containment."""
    graph = _FakeGraph(sps={})
    records = list(run([_finding()], graph_client=graph, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"
    assert "not found" in records[0]["actual_state"]


def test_run_reverify_drift_emits_ocsf_finding_alongside_verification():
    """DRIFT (SP was re-enabled) must yield BOTH a verification record AND
    an OCSF Detection Finding (class_uid 2004) so the gap flows through the
    same SIEM/SOAR pipeline."""
    graph = _FakeGraph(sps={"11111111-1111-1111-1111-111111111111": {"accountEnabled": True}})
    records = list(run([_finding()], graph_client=graph, reverify=True))
    assert len(records) == 2
    verification, finding = records
    assert verification["status"] == "drift"
    assert finding["class_uid"] == 2004
    assert finding["category_uid"] == 2
    assert finding["severity_id"] == 4
    assert finding["finding_info"]["types"] == ["remediation-drift"]
    assert any(
        obs["name"] == "remediation.skill" and obs["value"] == "remediate-entra-credential-revoke"
        for obs in finding["observables"]
    )


def test_run_reverify_unreachable_never_silently_downgrades():
    graph = _FakeGraph(raise_on_get=True)
    records = list(run([_finding()], graph_client=graph, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "unreachable"


def test_run_reverify_uses_finding_time_as_remediation_reference():
    graph = _FakeGraph(sps={"11111111-1111-1111-1111-111111111111": {"accountEnabled": False}})
    event = _finding()
    event["time"] = 1700000000789
    records = list(run([event], graph_client=graph, reverify=True))
    assert records[0]["reference"]["remediated_at_ms"] == 1700000000789


def test_run_reverify_application_target_uses_backing_service_principal():
    graph = _FakeGraph(
        applications={"app-1": {"appId": "client-1", "displayName": "rogue-app"}},
        service_principals_by_app_id={
            "client-1": [{"id": "sp-1", "appId": "client-1", "displayName": "rogue-sp"}]
        },
        sps={"sp-1": {"accountEnabled": False, "displayName": "rogue-sp", "appId": "client-1"}},
    )
    records = list(
        run(
            [_finding(object_id="app-1", target_type="Application")],
            graph_client=graph,
            reverify=True,
        )
    )
    assert len(records) == 1
    assert records[0]["status"] == "verified"


def test_run_reverify_skips_protected_target():
    graph = _FakeGraph()
    records = list(
        run([_finding(display_name="microsoft-internal-graph")], graph_client=graph, reverify=True)
    )
    # No graph call should fire
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED
