"""Tests for remediate-gcp-firewall-revoke."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    DEFAULT_INTENTIONALLY_OPEN_DESCRIPTION_MARKER,
    DEFAULT_PROTECTED_RULE_NAME_PREFIXES,
    MODE_DELETE,
    MODE_PATCH,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_TARGET,
    STATUS_SKIPPED_PROJECT_BOUNDARY,
    STATUS_SKIPPED_PROTECTED,
    STATUS_SUCCESS,
    STATUS_WOULD_VIOLATE_PROTECTED,
    GoogleComputeClient,
    Target,
    check_apply_gate,
    is_protected_firewall,
    parse_targets,
    run,
)


def _finding(
    *,
    rule_name: str = "allow-ssh-world",
    project_id: str = "p-1",
    network: str = "projects/p-1/global/networks/default",
    cidrs: list[str] | None = None,
    ports: list[int] | None = None,
    ip_protocol: str = "tcp",
    omit_target: bool = False,
) -> dict:
    cidrs = cidrs if cidrs is not None else ["0.0.0.0/0"]
    ports = ports if ports is not None else [22]
    obs: list[dict] = [
        {"name": "cloud.provider", "type": "Other", "value": "GCP"},
        {"name": "actor.name", "type": "Other", "value": "alice@example.com"},
        {"name": "api.operation", "type": "Other", "value": "compute.firewalls.insert_or_patch"},
        {"name": "rule", "type": "Other", "value": "open-gcp-firewall-ingress"},
        {"name": "target.name", "type": "Other", "value": rule_name},
        {"name": "target.type", "type": "Other", "value": "GcpFirewallRule"},
        {"name": "account.uid", "type": "Other", "value": project_id},
        {"name": "region", "type": "Other", "value": "global"},
        {"name": "permission.protocol", "type": "Other", "value": ip_protocol},
        {"name": "target.network", "type": "Other", "value": network},
    ]
    if not omit_target:
        obs.append({"name": "target.uid", "type": "Other", "value": rule_name})
    for c in cidrs:
        obs.append({"name": "permission.cidr", "type": "Other", "value": c})
    for p in ports:
        obs.append({"name": "permission.port", "type": "Other", "value": str(p)})
    return {
        "class_uid": 2004,
        "metadata": {"uid": "find-1", "product": {"feature": {"name": "detect-gcp-open-firewall"}}},
        "finding_info": {"uid": "find-1"},
        "observables": obs,
    }


@dataclass
class _FakeAudit:
    writes: list[dict] = field(default_factory=list)

    def record(self, *, target, step, status, detail, incident_id, approver):
        self.writes.append(
            {
                "rule_name": target.rule_name,
                "project_id": target.project_id,
                "step": step,
                "status": status,
                "detail": detail,
                "incident_id": incident_id,
                "approver": approver,
            }
        )
        return {
            "row_uid": f"row-{len(self.writes)}",
            "s3_evidence_uri": f"s3://bucket/{target.rule_name}-{len(self.writes)}.json",
        }


@dataclass
class _FakeCompute:
    firewalls: dict[tuple[str, str], dict] = field(default_factory=dict)
    raise_on_get: bool = False
    raise_on_patch: bool = False
    raise_on_delete: bool = False
    patches: list[tuple[str, str]] = field(default_factory=list)
    deletes: list[tuple[str, str]] = field(default_factory=list)

    def get_firewall(self, project, rule_name):
        if self.raise_on_get:
            raise RuntimeError("simulated compute 502")
        return self.firewalls.get((project, rule_name))

    def patch_firewall_disable(self, project, rule_name):
        if self.raise_on_patch:
            raise RuntimeError("simulated compute 403")
        self.patches.append((project, rule_name))
        fw = self.firewalls.setdefault(
            (project, rule_name),
            {"name": rule_name, "disabled": False, "description": ""},
        )
        fw["disabled"] = True

    def delete_firewall(self, project, rule_name):
        if self.raise_on_delete:
            raise RuntimeError("simulated compute 403")
        self.deletes.append((project, rule_name))
        self.firewalls.pop((project, rule_name), None)


# ---------- contract ----------


def test_accepted_producers_set():
    assert ACCEPTED_PRODUCERS == frozenset({"detect-gcp-open-firewall"})


def test_default_protected_name_prefixes_cover_default_rules():
    assert "default-" in DEFAULT_PROTECTED_RULE_NAME_PREFIXES


def test_intentionally_open_description_marker_default():
    assert DEFAULT_INTENTIONALLY_OPEN_DESCRIPTION_MARKER == "intentionally-open"


def test_check_apply_gate_requires_both_envs(monkeypatch):
    monkeypatch.delenv("GCP_FIREWALL_REVOKE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("GCP_FIREWALL_REVOKE_APPROVER", raising=False)
    monkeypatch.delenv("GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS", raising=False)
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("GCP_FIREWALL_REVOKE_INCIDENT_ID", "INC-1")
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("GCP_FIREWALL_REVOKE_APPROVER", "alice")
    ok, _ = check_apply_gate()
    assert ok is False
    monkeypatch.setenv("GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS", "p-1")
    ok, _ = check_apply_gate()
    assert ok is True


# ---------- parse_targets ----------


def test_parse_targets_extracts_full_target():
    target, _ = next(parse_targets([_finding(cidrs=["0.0.0.0/0", "::/0"], ports=[22, 3306])]))
    assert target.rule_name == "allow-ssh-world"
    assert target.project_id == "p-1"
    assert target.cidrs == ("0.0.0.0/0", "::/0")
    assert target.ports == (22, 3306)
    assert target.ip_protocol == "tcp"


def test_parse_targets_rejects_wrong_producer(capsys):
    e = _finding()
    e["metadata"]["product"]["feature"]["name"] = "detect-aws-open-security-group"
    target, _ = next(parse_targets([e]))
    assert target is None
    assert "unaccepted producer" in capsys.readouterr().err


# ---------- protected check ----------


def _t(**overrides) -> Target:
    base = dict(
        rule_name="allow-x",
        project_id="p-1",
        network="n",
        cidrs=("0.0.0.0/0",),
        ports=(22,),
        ip_protocol="tcp",
        actor="a",
        rule="r",
        producer_skill="detect-gcp-open-firewall",
        finding_uid="f",
    )
    base.update(overrides)
    return Target(**base)


def test_protected_default_rule_by_name_prefix():
    p, why = is_protected_firewall(
        _t(rule_name="default-allow-internal"),
        name_prefixes=("default-",),
        rule_names=(),
        intentionally_open_marker="intentionally-open",
        firewall_get=None,
    )
    assert p is True
    assert "default-" in why


def test_protected_via_env_rule_name_allowlist():
    p, why = is_protected_firewall(
        _t(rule_name="allow-bootstrap"),
        name_prefixes=(),
        rule_names=("allow-bootstrap",),
        intentionally_open_marker="intentionally-open",
        firewall_get=None,
    )
    assert p is True
    assert "allow-bootstrap" in why


def test_protected_via_intentionally_open_description():
    fw = {"name": "x", "description": "PUBLIC api - intentionally-open per ARCH-123"}
    p, why = is_protected_firewall(
        _t(),
        name_prefixes=(),
        rule_names=(),
        intentionally_open_marker="intentionally-open",
        firewall_get=fw,
    )
    assert p is True
    assert "intentionally-open" in why


def test_unprotected_when_no_match():
    p, _ = is_protected_firewall(
        _t(rule_name="my-prod-allow"),
        name_prefixes=("default-",),
        rule_names=(),
        intentionally_open_marker="intentionally-open",
        firewall_get={"description": ""},
    )
    assert p is False


# ---------- run: dry-run ----------


def test_run_dry_run_emits_plan():
    records = list(run([_finding()], compute_client=_FakeCompute()))
    rec = records[0]
    assert rec["record_type"] == "remediation_plan"
    assert rec["status"] == STATUS_PLANNED
    assert rec["dry_run"] is True
    assert rec["mode"] == MODE_PATCH
    assert rec["target"]["rule_name"] == "allow-ssh-world"
    assert rec["target"]["project_id"] == "p-1"
    assert rec["target"]["cidrs"] == ["0.0.0.0/0"]
    assert "dry-run" in rec["actions"][0]["detail"]


def test_run_dry_run_does_not_call_patch_or_delete():
    compute = _FakeCompute()
    list(run([_finding()], compute_client=compute))
    assert compute.patches == []
    assert compute.deletes == []


def test_run_dry_run_delete_mode_emits_delete_endpoint():
    records = list(run([_finding()], compute_client=_FakeCompute(), mode=MODE_DELETE))
    rec = records[0]
    assert rec["mode"] == MODE_DELETE
    assert "compute.firewalls.delete" in rec["actions"][0]["endpoint"]


# ---------- run: skip paths ----------


def test_run_skips_finding_without_target_pointers():
    records = list(run([_finding(omit_target=True)], compute_client=_FakeCompute()))
    assert records[0]["status"] == STATUS_SKIPPED_NO_TARGET


def test_run_skips_default_named_rule_in_dry_run():
    records = list(
        run([_finding(rule_name="default-allow-internal")], compute_client=_FakeCompute())
    )
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED
    assert "default-" in records[0]["status_detail"]


def test_run_skips_intentionally_open_described_rule_in_apply():
    audit = _FakeAudit()
    compute = _FakeCompute(
        firewalls={
            ("p-1", "allow-ssh-world"): {
                "name": "allow-ssh-world",
                "description": "ALB front door - intentionally-open per #777",
                "disabled": False,
            }
        }
    )
    records = list(
        run(
            [_finding()],
            compute_client=compute,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_project_ids=("p-1",),
        )
    )
    assert records[0]["status"] == STATUS_SKIPPED_PROTECTED
    assert compute.patches == []
    assert compute.deletes == []
    assert audit.writes == []


def test_run_skips_via_env_protected_rule_name():
    records = list(
        run(
            [_finding(rule_name="allow-bootstrap")],
            compute_client=_FakeCompute(),
            rule_names=("allow-bootstrap",),
        )
    )
    assert records[0]["status"] == STATUS_WOULD_VIOLATE_PROTECTED


# ---------- run: apply: missing env vars rejected ----------


def test_run_apply_requires_audit_writer():
    import pytest

    with pytest.raises(ValueError, match="audit writer is required"):
        list(
            run(
                [_finding()],
                compute_client=_FakeCompute(),
                apply=True,
                audit=None,
                allowed_project_ids=("p-1",),
            )
        )


def test_check_apply_gate_rejects_missing_envs(monkeypatch):
    monkeypatch.delenv("GCP_FIREWALL_REVOKE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("GCP_FIREWALL_REVOKE_APPROVER", raising=False)
    ok, reason = check_apply_gate()
    assert ok is False
    assert "GCP_FIREWALL_REVOKE_INCIDENT_ID" in reason


# ---------- run: apply happy path ----------


def test_run_apply_patches_with_dual_audit():
    audit = _FakeAudit()
    compute = _FakeCompute(
        firewalls={
            ("p-1", "allow-ssh-world"): {
                "name": "allow-ssh-world",
                "disabled": False,
                "description": "",
            }
        }
    )
    records = list(
        run(
            [_finding()],
            compute_client=compute,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            allowed_project_ids=("p-1",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["dry_run"] is False
    assert rec["mode"] == MODE_PATCH
    assert compute.patches == [("p-1", "allow-ssh-world")]
    assert compute.deletes == []
    # Verify rule is now disabled in fake state
    assert compute.firewalls[("p-1", "allow-ssh-world")]["disabled"] is True
    assert len(audit.writes) == 2
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[1]["status"] == STATUS_SUCCESS


def test_run_apply_delete_mode_calls_delete():
    audit = _FakeAudit()
    compute = _FakeCompute(
        firewalls={("p-1", "allow-ssh-world"): {"name": "allow-ssh-world", "disabled": False}}
    )
    records = list(
        run(
            [_finding()],
            compute_client=compute,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            mode=MODE_DELETE,
            allowed_project_ids=("p-1",),
        )
    )
    assert records[0]["status"] == STATUS_SUCCESS
    assert compute.deletes == [("p-1", "allow-ssh-world")]
    assert compute.patches == []


def test_run_apply_writes_failure_audit_when_patch_throws():
    audit = _FakeAudit()
    compute = _FakeCompute(raise_on_patch=True)
    records = list(
        run(
            [_finding()],
            compute_client=compute,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_project_ids=("p-1",),
        )
    )
    assert records[0]["status"] == STATUS_FAILURE
    assert len(audit.writes) == 2
    assert audit.writes[1]["status"] == STATUS_FAILURE


def test_run_unsupported_mode_raises():
    import pytest

    with pytest.raises(ValueError, match="unsupported mode"):
        list(run([_finding()], compute_client=_FakeCompute(), mode="purge"))


def test_run_apply_skips_wrong_project_boundary():
    audit = _FakeAudit()
    compute = _FakeCompute()
    records = list(
        run(
            [_finding()],
            compute_client=compute,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
            allowed_project_ids=("p-2",),
        )
    )
    assert records[0]["status"] == STATUS_SKIPPED_PROJECT_BOUNDARY
    assert compute.patches == []
    assert compute.deletes == []
    assert audit.writes == []


# ---------- run: re-verify ----------


def test_run_reverify_verified_when_rule_disabled():
    compute = _FakeCompute(
        firewalls={("p-1", "allow-ssh-world"): {"name": "allow-ssh-world", "disabled": True}}
    )
    records = list(run([_finding()], compute_client=compute, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"
    assert "disabled: true" in records[0]["actual_state"]


def test_run_reverify_verified_when_rule_deleted():
    """Absent rule = stronger than disabled = verified containment."""
    compute = _FakeCompute(firewalls={})
    records = list(run([_finding()], compute_client=compute, reverify=True))
    assert len(records) == 1
    assert records[0]["status"] == "verified"
    assert "not found" in records[0]["actual_state"]


def test_run_reverify_drift_emits_ocsf_finding_alongside_verification():
    compute = _FakeCompute(
        firewalls={("p-1", "allow-ssh-world"): {"name": "allow-ssh-world", "disabled": False}}
    )
    records = list(run([_finding()], compute_client=compute, reverify=True))
    assert len(records) == 2
    verification, finding = records
    assert verification["status"] == "drift"
    assert finding["class_uid"] == 2004
    assert finding["category_uid"] == 2
    assert finding["severity_id"] == 4
    assert finding["finding_info"]["types"] == ["remediation-drift"]
    assert any(
        obs["name"] == "remediation.skill" and obs["value"] == "remediate-gcp-firewall-revoke"
        for obs in finding["observables"]
    )


def test_run_reverify_uses_finding_time_as_remediation_reference():
    compute = _FakeCompute(
        firewalls={("p-1", "allow-ssh-world"): {"name": "allow-ssh-world", "disabled": True}}
    )
    event = _finding()
    event["time"] = 1700000000123
    records = list(run([event], compute_client=compute, reverify=True))
    assert records[0]["reference"]["remediated_at_ms"] == 1700000000123


def test_run_reverify_unreachable_never_silently_downgrades():
    compute = _FakeCompute(raise_on_get=True)
    records = list(run([_finding()], compute_client=compute, reverify=True))
    assert any(r["status"] == "unreachable" for r in records)


# ---------- google client mocking ----------


def test_google_compute_client_uses_googleapiclient_discovery():
    """Ensure the real client lazily imports and calls googleapiclient.discovery.build."""
    fake_discovery = MagicMock()
    fake_service = MagicMock()
    fake_discovery.build.return_value = fake_service
    fake_firewalls = MagicMock()
    fake_service.firewalls.return_value = fake_firewalls
    fake_get = MagicMock()
    fake_firewalls.get.return_value = fake_get
    fake_get.execute.return_value = {"name": "allow-ssh-world", "disabled": True}

    with patch.dict(
        sys.modules, {"googleapiclient": MagicMock(), "googleapiclient.discovery": fake_discovery}
    ):
        client = GoogleComputeClient()
        result = client.get_firewall("p-1", "allow-ssh-world")
        assert result == {"name": "allow-ssh-world", "disabled": True}
        fake_discovery.build.assert_called_with("compute", "v1", cache_discovery=False)
        fake_firewalls.get.assert_called_with(project="p-1", firewall="allow-ssh-world")


def test_google_compute_client_patch_sets_disabled_true():
    fake_discovery = MagicMock()
    fake_service = MagicMock()
    fake_discovery.build.return_value = fake_service
    fake_firewalls = MagicMock()
    fake_service.firewalls.return_value = fake_firewalls

    with patch.dict(
        sys.modules, {"googleapiclient": MagicMock(), "googleapiclient.discovery": fake_discovery}
    ):
        client = GoogleComputeClient()
        client.patch_firewall_disable("p-1", "allow-ssh-world")
        fake_firewalls.patch.assert_called_with(
            project="p-1", firewall="allow-ssh-world", body={"disabled": True}
        )
