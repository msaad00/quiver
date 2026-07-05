"""Tests for remediate-k8s-rbac-revoke."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from handler import (  # type: ignore[import-not-found]
    ACCEPTED_PRODUCERS,
    DEFAULT_DENY_BINDING_PREFIXES,
    DEFAULT_DENY_NAMESPACES,
    STATUS_DRIFT,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_PLANNED,
    STATUS_SKIPPED_CLUSTER_BOUNDARY,
    STATUS_SKIPPED_DENY_LIST,
    STATUS_SKIPPED_NO_BINDING,
    STATUS_SKIPPED_UNSUPPORTED_TYPE,
    STATUS_SUCCESS,
    STATUS_VERIFIED,
    STATUS_WOULD_VIOLATE_DENY_LIST,
    STATUS_WOULD_VIOLATE_PROTECTED_BINDING,
    check_apply_gate,
    is_protected_binding,
    is_protected_namespace,
    parse_targets,
    run,
)


def _finding(
    *,
    producer: str = "detect-privilege-escalation-k8s",
    binding_type: str = "rolebindings",
    binding_name: str = "attacker-grant",
    namespace: str = "payments",
    actor: str = "system:serviceaccount:payments:attacker-sa",
    rule: str = "r3-rbac-self-grant",
    finding_uid: str = "find-1",
    omit_binding: bool = False,
) -> dict:
    observables = [
        {"name": "actor.name", "type": "Other", "value": actor},
        {"name": "namespace", "type": "Other", "value": namespace},
        {"name": "rule", "type": "Other", "value": rule},
    ]
    if not omit_binding:
        observables.append({"name": "binding.type", "type": "Other", "value": binding_type})
        observables.append({"name": "binding.name", "type": "Other", "value": binding_name})
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
            "target": f"{target.binding_type}/{target.namespace or '_cluster'}/{target.binding_name}",
            "step": step,
            "status": status,
            "detail": detail,
            "incident_id": incident_id,
            "approver": approver,
        }
        self.writes.append(entry)
        return {
            "row_uid": f"row-{len(self.writes)}",
            "s3_evidence_uri": f"s3://bucket/{target.binding_name}-{len(self.writes)}.json",
        }


@dataclass
class _FakeKube:
    role_bindings: dict[tuple[str, str], dict] = field(default_factory=dict)
    cluster_role_bindings: dict[str, dict] = field(default_factory=dict)
    deletes: list[tuple[str, str, str]] = field(default_factory=list)
    raise_on_delete: bool = False

    def get_role_binding(self, namespace, name):
        return self.role_bindings.get((namespace, name))

    def get_cluster_role_binding(self, name):
        return self.cluster_role_bindings.get(name)

    def delete_role_binding(self, namespace, name):
        if self.raise_on_delete:
            raise RuntimeError("k8s api boom")
        self.deletes.append(("rolebindings", namespace, name))
        self.role_bindings.pop((namespace, name), None)

    def delete_cluster_role_binding(self, name):
        if self.raise_on_delete:
            raise RuntimeError("k8s api boom")
        self.deletes.append(("clusterrolebindings", "", name))
        self.cluster_role_bindings.pop(name, None)


# ----------------- helpers -----------------


def test_protected_namespace_matches_exact_and_prefix():
    assert is_protected_namespace("kube-system", DEFAULT_DENY_NAMESPACES) == (True, "kube-system")
    assert is_protected_namespace("linkerd-control", DEFAULT_DENY_NAMESPACES) == (True, "linkerd-")
    assert is_protected_namespace("payments", DEFAULT_DENY_NAMESPACES) == (False, "")
    assert is_protected_namespace("", DEFAULT_DENY_NAMESPACES) == (False, "")


def test_protected_binding_matches_system_prefix():
    assert is_protected_binding("system:masters", DEFAULT_DENY_BINDING_PREFIXES) == (
        True,
        "system:",
    )
    assert is_protected_binding("System:Public-Info-Viewer", DEFAULT_DENY_BINDING_PREFIXES) == (
        True,
        "system:",
    )
    assert is_protected_binding("attacker-grant", DEFAULT_DENY_BINDING_PREFIXES) == (False, "")
    assert is_protected_binding("", DEFAULT_DENY_BINDING_PREFIXES) == (False, "")


def test_accepted_producers_set_is_just_privesc():
    assert ACCEPTED_PRODUCERS == frozenset({"detect-privilege-escalation-k8s"})


def test_check_apply_gate_requires_both_envs(monkeypatch):
    monkeypatch.delenv("K8S_RBAC_REVOKE_INCIDENT_ID", raising=False)
    monkeypatch.delenv("K8S_RBAC_REVOKE_APPROVER", raising=False)
    monkeypatch.delenv("K8S_CLUSTER_NAME", raising=False)
    monkeypatch.delenv("K8S_RBAC_REVOKE_ALLOWED_CLUSTERS", raising=False)
    ok, reason = check_apply_gate()
    assert ok is False
    assert "INCIDENT_ID" in reason

    monkeypatch.setenv("K8S_RBAC_REVOKE_INCIDENT_ID", "INC-1")
    ok, reason = check_apply_gate()
    assert ok is False
    assert "APPROVER" in reason

    monkeypatch.setenv("K8S_RBAC_REVOKE_APPROVER", "alice@security")
    ok, reason = check_apply_gate()
    assert ok is False
    assert "K8S_CLUSTER_NAME" in reason

    monkeypatch.setenv("K8S_CLUSTER_NAME", "prod-cluster")
    ok, reason = check_apply_gate()
    assert ok is False
    assert "K8S_RBAC_REVOKE_ALLOWED_CLUSTERS" in reason

    monkeypatch.setenv("K8S_RBAC_REVOKE_ALLOWED_CLUSTERS", "staging-cluster")
    ok, reason = check_apply_gate()
    assert ok is False
    assert "prod-cluster" in reason

    monkeypatch.setenv("K8S_RBAC_REVOKE_ALLOWED_CLUSTERS", "prod-cluster,staging-cluster")
    ok, reason = check_apply_gate()
    assert ok is True
    assert reason == ""


# ----------------- parse_targets -----------------


def test_parse_targets_rejects_wrong_producer():
    targets = list(parse_targets([_finding(producer="detect-container-escape-k8s")]))
    assert targets == [(None, targets[0][1])]


def test_parse_targets_extracts_full_binding_target():
    targets = list(parse_targets([_finding()]))
    target, _ = targets[0]
    assert target is not None
    assert target.binding_type == "rolebindings"
    assert target.binding_name == "attacker-grant"
    assert target.namespace == "payments"
    assert target.actor == "system:serviceaccount:payments:attacker-sa"
    assert target.rule == "r3-rbac-self-grant"
    assert target.producer_skill == "detect-privilege-escalation-k8s"


def test_parse_targets_returns_partial_when_binding_missing():
    """When detector doesn't carry binding pointer (rules r1/r2/r4), we still
    build a partial Target so the run loop can emit a clean skip record."""
    targets = list(parse_targets([_finding(omit_binding=True, rule="r1-secret-enum")]))
    target, _ = targets[0]
    assert target is not None
    assert target.binding_type == ""
    assert target.binding_name == ""
    assert target.rule == "r1-secret-enum"


# ----------------- run: dry-run plan path -----------------


def test_run_dry_run_emits_plan_for_namespaced_binding():
    records = list(run([_finding()], kube_client=_FakeKube()))
    assert len(records) == 1
    rec = records[0]
    assert rec["record_type"] == "remediation_plan"
    assert rec["status"] == STATUS_PLANNED
    assert rec["dry_run"] is True
    assert rec["target"]["binding_type"] == "rolebindings"
    assert rec["target"]["binding_name"] == "attacker-grant"
    assert rec["actions"][0]["endpoint"].startswith(
        "DELETE /apis/rbac.authorization.k8s.io/v1/namespaces/payments/rolebindings/attacker-grant"
    )


def test_run_dry_run_emits_plan_for_cluster_binding():
    records = list(
        run(
            [
                _finding(
                    binding_type="clusterrolebindings",
                    binding_name="attacker-cluster-grant",
                    namespace="",
                )
            ],
            kube_client=_FakeKube(),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_PLANNED
    assert rec["actions"][0]["endpoint"].startswith(
        "DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/attacker-cluster-grant"
    )


# ----------------- run: skip paths -----------------


def test_run_skips_finding_without_binding_pointer():
    records = list(
        run([_finding(omit_binding=True, rule="r1-secret-enum")], kube_client=_FakeKube())
    )
    rec = records[0]
    assert rec["status"] == STATUS_SKIPPED_NO_BINDING
    assert rec["actions"] == []
    assert "r1-secret-enum" in rec["status_detail"]


def test_run_skips_protected_namespace_in_dry_run():
    records = list(run([_finding(namespace="kube-system")], kube_client=_FakeKube()))
    rec = records[0]
    assert rec["status"] == STATUS_WOULD_VIOLATE_DENY_LIST
    assert "kube-system" in rec["status_detail"]


def test_run_skips_protected_namespace_in_apply():
    audit = _FakeAudit()
    records = list(
        run(
            [_finding(namespace="kube-system")],
            kube_client=_FakeKube(),
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice",
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SKIPPED_DENY_LIST
    # Audit should NOT fire for skip records — they never reach the cloud API
    assert audit.writes == []


def test_run_skips_system_prefixed_binding_name():
    records = list(run([_finding(binding_name="system:masters")], kube_client=_FakeKube()))
    rec = records[0]
    assert rec["status"] == STATUS_WOULD_VIOLATE_PROTECTED_BINDING
    assert "system:" in rec["status_detail"]


def test_run_skips_unsupported_binding_type():
    records = list(run([_finding(binding_type="roles")], kube_client=_FakeKube()))
    rec = records[0]
    assert rec["status"] == STATUS_SKIPPED_UNSUPPORTED_TYPE
    assert "roles" in rec["status_detail"]


def test_run_does_not_check_namespace_for_cluster_bindings_in_protected_ns():
    """A ClusterRoleBinding has no namespace; even if observable namespace is
    kube-system the namespace deny-list does not apply (binding-name deny-list
    handles cluster-scoped protection via the system: prefix)."""
    records = list(
        run(
            [
                _finding(
                    binding_type="clusterrolebindings",
                    binding_name="custom-cluster-grant",
                    namespace="kube-system",
                )
            ],
            kube_client=_FakeKube(),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_PLANNED


# ----------------- run: apply path -----------------


def test_run_apply_revokes_namespaced_binding_with_dual_audit():
    audit = _FakeAudit()
    kube = _FakeKube(
        role_bindings={("payments", "attacker-grant"): {"metadata": {"name": "attacker-grant"}}}
    )
    records = list(
        run(
            [_finding()],
            kube_client=kube,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            cluster_name="prod-cluster",
            allowed_clusters=("prod-cluster",),
        )
    )

    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert rec["dry_run"] is False
    assert rec["incident_id"] == "INC-1"
    assert rec["approver"] == "alice@security"
    assert kube.deletes == [("rolebindings", "payments", "attacker-grant")]

    assert len(audit.writes) == 2
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[1]["status"] == STATUS_SUCCESS
    for entry in audit.writes:
        assert entry["incident_id"] == "INC-1"
        assert entry["approver"] == "alice@security"


def test_run_apply_revokes_cluster_binding():
    audit = _FakeAudit()
    kube = _FakeKube(
        cluster_role_bindings={
            "attacker-cluster-grant": {"metadata": {"name": "attacker-cluster-grant"}}
        }
    )
    records = list(
        run(
            [
                _finding(
                    binding_type="clusterrolebindings",
                    binding_name="attacker-cluster-grant",
                    namespace="",
                )
            ],
            kube_client=kube,
            apply=True,
            audit=audit,
            incident_id="INC-2",
            approver="bob@security",
            cluster_name="prod-cluster",
            allowed_clusters=("prod-cluster",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SUCCESS
    assert kube.deletes == [("clusterrolebindings", "", "attacker-cluster-grant")]


def test_run_apply_writes_failure_audit_when_kube_call_throws():
    audit = _FakeAudit()
    kube = _FakeKube(
        role_bindings={("payments", "attacker-grant"): {"metadata": {"name": "attacker-grant"}}},
        raise_on_delete=True,
    )
    records = list(
        run(
            [_finding()],
            kube_client=kube,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            cluster_name="prod-cluster",
            allowed_clusters=("prod-cluster",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_FAILURE
    assert "k8s api boom" in rec["actions"][0]["detail"]
    # Both pre-action and failure audit rows are written
    assert len(audit.writes) == 2
    assert audit.writes[0]["status"] == STATUS_IN_PROGRESS
    assert audit.writes[1]["status"] == STATUS_FAILURE


def test_run_apply_requires_audit_writer():
    import pytest

    with pytest.raises(ValueError, match="audit writer is required"):
        list(
            run(
                [_finding()],
                kube_client=_FakeKube(),
                apply=True,
                audit=None,
                cluster_name="prod-cluster",
                allowed_clusters=("prod-cluster",),
            )
        )


def test_run_apply_skips_cluster_outside_allow_list():
    audit = _FakeAudit()
    kube = _FakeKube(
        role_bindings={("payments", "attacker-grant"): {"metadata": {"name": "attacker-grant"}}}
    )
    records = list(
        run(
            [_finding()],
            kube_client=kube,
            apply=True,
            audit=audit,
            incident_id="INC-1",
            approver="alice@security",
            cluster_name="prod-cluster",
            allowed_clusters=("staging-cluster",),
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_SKIPPED_CLUSTER_BOUNDARY
    assert "prod-cluster" in rec["status_detail"]
    assert audit.writes == []
    assert kube.deletes == []


# ----------------- run: re-verify path -----------------


def test_run_reverify_reports_verified_when_binding_gone():
    records = list(
        run(
            [_finding()],
            kube_client=_FakeKube(role_bindings={}),  # binding already deleted
            reverify=True,
        )
    )
    rec = records[0]
    assert rec["record_type"] == "remediation_verification"
    assert rec["status"] == STATUS_VERIFIED


def test_run_reverify_reports_drift_when_binding_still_present():
    records = list(
        run(
            [_finding()],
            kube_client=_FakeKube(
                role_bindings={
                    ("payments", "attacker-grant"): {"metadata": {"name": "attacker-grant"}}
                }
            ),
            reverify=True,
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_DRIFT
    assert "still present" in rec["status_detail"]


def test_run_reverify_handles_cluster_binding():
    records = list(
        run(
            [
                _finding(
                    binding_type="clusterrolebindings",
                    binding_name="attacker-cluster-grant",
                    namespace="",
                )
            ],
            kube_client=_FakeKube(cluster_role_bindings={}),
            reverify=True,
        )
    )
    rec = records[0]
    assert rec["status"] == STATUS_VERIFIED
