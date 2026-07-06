"""Tests for detect-privilege-escalation-k8s.

Four rules, one golden-fixture parity check. Unit tests for each rule's
trigger logic, negative controls, windowing, and deterministic uid.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    R1_SUB_UID,
    R2_TECH_UID,
    R3_TECH_UID,
    R4_SUB_UID,
    RULE1_WINDOW_MS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SKILL_NAME,
    _is_admin,
    detect,
    load_jsonl,
    rule1_secret_enumeration,
    rule2_pod_exec,
    rule3_rbac_self_grant,
    rule4_token_self_grant,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
OCSF_INPUT = GOLDEN / "k8s_audit_sample.ocsf.jsonl"
EXPECTED = GOLDEN / "k8s_priv_esc_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _sa_event(
    *,
    verb: str,
    resource_type: str,
    time_ms: int = 1775797200000,
    name: str = "",
    namespace: str = "default",
    subresource: str = "",
    sa: str = "system:serviceaccount:default:builder",
) -> dict:
    r: dict = {"type": resource_type}
    if name:
        r["name"] = name
    if namespace:
        r["namespace"] = namespace
    if subresource:
        r["subresource"] = subresource
    return {
        "class_uid": 6003,
        "time": time_ms,
        "actor": {"user": {"name": sa, "type": "ServiceAccount"}},
        "api": {"operation": verb},
        "resources": [r],
    }


def _native_sa_event(
    *,
    verb: str,
    resource_type: str,
    time_ms: int = 1775797200000,
    name: str = "",
    namespace: str = "default",
    subresource: str = "",
    sa: str = "system:serviceaccount:default:builder",
    groups: list[str] | None = None,
) -> dict:
    r: dict = {"type": resource_type}
    if name:
        r["name"] = name
    if namespace:
        r["namespace"] = namespace
    if subresource:
        r["subresource"] = subresource
    return {
        "schema_mode": "native",
        "record_type": "api_activity",
        "provider": "Kubernetes",
        "time_ms": time_ms,
        "operation": verb,
        "actor": {
            "user": {
                "name": sa,
                "type": "ServiceAccount",
                "groups": [{"name": g} for g in (groups or [])],
            }
        },
        "resources": [r],
    }


# ── Rule 1: secret enumeration ────────────────────────────────────────


class TestRule1:
    def test_list_then_get_fires(self):
        events = [
            _sa_event(verb="list", resource_type="secrets", time_ms=1000),
            _sa_event(verb="get", resource_type="secrets", name="db", time_ms=2000),
        ]
        findings = list(rule1_secret_enumeration(events))
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["sub_technique_uid"] == R1_SUB_UID
        assert findings[0]["severity_id"] == SEVERITY_HIGH

    def test_get_without_list_does_not_fire(self):
        events = [_sa_event(verb="get", resource_type="secrets", name="db")]
        assert list(rule1_secret_enumeration(events)) == []

    def test_list_without_get_does_not_fire(self):
        events = [_sa_event(verb="list", resource_type="secrets")]
        assert list(rule1_secret_enumeration(events)) == []

    def test_outside_window_does_not_fire(self):
        t0 = 1000
        events = [
            _sa_event(verb="list", resource_type="secrets", time_ms=t0),
            _sa_event(
                verb="get", resource_type="secrets", name="db", time_ms=t0 + RULE1_WINDOW_MS + 1
            ),
        ]
        assert list(rule1_secret_enumeration(events)) == []

    def test_different_namespace_does_not_correlate(self):
        events = [
            _sa_event(verb="list", resource_type="secrets", namespace="default", time_ms=1000),
            _sa_event(
                verb="get",
                resource_type="secrets",
                name="db",
                namespace="kube-system",
                time_ms=2000,
            ),
        ]
        assert list(rule1_secret_enumeration(events)) == []

    def test_different_sa_does_not_correlate(self):
        events = [
            _sa_event(
                verb="list",
                resource_type="secrets",
                sa="system:serviceaccount:default:a",
                time_ms=1000,
            ),
            _sa_event(
                verb="get",
                resource_type="secrets",
                name="db",
                sa="system:serviceaccount:default:b",
                time_ms=2000,
            ),
        ]
        assert list(rule1_secret_enumeration(events)) == []

    def test_non_sa_actor_does_not_fire(self):
        events = [
            {
                "class_uid": 6003,
                "time": 1000,
                "actor": {"user": {"name": "alice", "type": "User"}},
                "api": {"operation": "list"},
                "resources": [{"type": "secrets", "namespace": "default"}],
            },
            {
                "class_uid": 6003,
                "time": 2000,
                "actor": {"user": {"name": "alice", "type": "User"}},
                "api": {"operation": "get"},
                "resources": [{"type": "secrets", "name": "db", "namespace": "default"}],
            },
        ]
        # Rule 1 requires a ServiceAccount actor
        assert list(rule1_secret_enumeration(events)) == []

    def test_wrong_resource_type_does_not_fire(self):
        events = [
            _sa_event(verb="list", resource_type="configmaps", time_ms=1000),
            _sa_event(verb="get", resource_type="configmaps", name="cm", time_ms=2000),
        ]
        assert list(rule1_secret_enumeration(events)) == []

    def test_idempotent_uid(self):
        events = [
            _sa_event(verb="list", resource_type="secrets", time_ms=1000),
            _sa_event(verb="get", resource_type="secrets", name="db", time_ms=2000),
        ]
        a = list(rule1_secret_enumeration(events))[0]["finding_uid"]
        b = list(rule1_secret_enumeration(events))[0]["finding_uid"]
        assert a == b

    def test_native_input_fires(self):
        events = [
            _native_sa_event(verb="list", resource_type="secrets", time_ms=1000),
            _native_sa_event(verb="get", resource_type="secrets", name="db", time_ms=2000),
        ]
        findings = list(rule1_secret_enumeration(events))
        assert len(findings) == 1
        assert findings[0]["rule_name"] == "r1-secret-enum"


# ── Rule 2: pod exec ──────────────────────────────────────────────────


class TestRule2:
    def test_exec_fires(self):
        events = [_sa_event(verb="create", resource_type="pods", name="web", subresource="exec")]
        findings = list(rule2_pod_exec(events))
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["technique_uid"] == R2_TECH_UID
        assert findings[0]["severity_id"] == SEVERITY_CRITICAL

    def test_pod_create_without_exec_subresource_does_not_fire(self):
        events = [_sa_event(verb="create", resource_type="pods", name="web")]
        assert list(rule2_pod_exec(events)) == []

    def test_different_subresource_does_not_fire(self):
        events = [_sa_event(verb="create", resource_type="pods", name="web", subresource="log")]
        assert list(rule2_pod_exec(events)) == []

    def test_non_sa_does_not_fire(self):
        events = [
            {
                "class_uid": 6003,
                "time": 1000,
                "actor": {"user": {"name": "alice", "type": "User"}},
                "api": {"operation": "create"},
                "resources": [{"type": "pods", "name": "web", "subresource": "exec"}],
            }
        ]
        assert list(rule2_pod_exec(events)) == []

    def test_deduplicated_per_actor_target(self):
        # Same SA execs into the same pod twice — only one finding.
        events = [
            _sa_event(
                verb="create", resource_type="pods", name="web", subresource="exec", time_ms=1000
            ),
            _sa_event(
                verb="create", resource_type="pods", name="web", subresource="exec", time_ms=2000
            ),
        ]
        assert len(list(rule2_pod_exec(events))) == 1

    def test_native_input_fires(self):
        events = [
            _native_sa_event(verb="create", resource_type="pods", name="web", subresource="exec")
        ]
        findings = list(rule2_pod_exec(events))
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"


# ── Rule 3: RBAC self-grant ───────────────────────────────────────────


class TestRule3:
    def _binding_event(
        self, *, rtype: str, name: str, actor_name: str, groups: list[str], user_type: str = "User"
    ) -> dict:
        return {
            "class_uid": 6003,
            "time": 1000,
            "actor": {
                "user": {
                    "name": actor_name,
                    "type": user_type,
                    "groups": [{"name": g} for g in groups],
                }
            },
            "api": {"operation": "create"},
            "resources": [{"type": rtype, "name": name}],
        }

    def test_non_admin_crb_fires(self):
        ev = self._binding_event(
            rtype="clusterrolebindings",
            name="attacker",
            actor_name="system:serviceaccount:default:builder",
            groups=["system:serviceaccounts"],
            user_type="ServiceAccount",
        )
        findings = list(rule3_rbac_self_grant([ev]))
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["technique_uid"] == R3_TECH_UID
        assert findings[0]["severity_id"] == SEVERITY_CRITICAL

    def test_non_admin_rb_fires(self):
        ev = self._binding_event(
            rtype="rolebindings", name="attacker", actor_name="user-bob", groups=[]
        )
        findings = list(rule3_rbac_self_grant([ev]))
        assert len(findings) == 1

    def test_system_masters_group_does_not_fire(self):
        ev = self._binding_event(
            rtype="clusterrolebindings",
            name="legitimate",
            actor_name="alice",
            groups=["system:masters", "system:authenticated"],
        )
        assert list(rule3_rbac_self_grant([ev])) == []

    def test_kube_admin_user_does_not_fire(self):
        ev = self._binding_event(
            rtype="clusterrolebindings", name="legitimate", actor_name="kubernetes-admin", groups=[]
        )
        assert list(rule3_rbac_self_grant([ev])) == []

    def test_is_admin_helper(self):
        assert _is_admin({"actor": {"user": {"name": "kubernetes-admin"}}})
        assert _is_admin({"actor": {"user": {"groups": [{"name": "system:masters"}]}}})
        assert not _is_admin(
            {"actor": {"user": {"name": "alice", "groups": [{"name": "system:authenticated"}]}}}
        )

    def test_non_binding_resource_does_not_fire(self):
        events = [_sa_event(verb="create", resource_type="pods", name="web")]
        assert list(rule3_rbac_self_grant(events)) == []

    def test_native_input_fires(self):
        event = {
            "schema_mode": "native",
            "record_type": "api_activity",
            "provider": "Kubernetes",
            "time_ms": 1000,
            "operation": "create",
            "actor": {"user": {"name": "user-bob", "type": "User", "groups": []}},
            "resources": [{"type": "rolebindings", "name": "attacker", "namespace": "default"}],
        }
        findings = list(rule3_rbac_self_grant([event]))
        assert len(findings) == 1
        assert findings[0]["rule_name"] == "r3-rbac-self-grant"


# ── Rule 4: token self-grant ──────────────────────────────────────────


class TestRule4:
    def test_serviceaccount_token_subresource_fires(self):
        events = [
            _sa_event(
                verb="create",
                resource_type="serviceaccounts",
                name="target-sa",
                subresource="token",
            )
        ]
        findings = list(rule4_token_self_grant(events))
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["sub_technique_uid"] == R4_SUB_UID

    def test_tokenrequest_subresource_fires(self):
        events = [
            _sa_event(
                verb="create",
                resource_type="serviceaccounts",
                name="target-sa",
                subresource="tokenrequest",
            )
        ]
        assert len(list(rule4_token_self_grant(events))) == 1

    def test_tokenreviews_resource_fires(self):
        events = [_sa_event(verb="create", resource_type="tokenreviews")]
        assert len(list(rule4_token_self_grant(events))) == 1

    def test_plain_serviceaccount_create_does_not_fire(self):
        events = [_sa_event(verb="create", resource_type="serviceaccounts", name="new-sa")]
        assert list(rule4_token_self_grant(events)) == []

    def test_non_sa_actor_does_not_fire(self):
        events = [
            {
                "class_uid": 6003,
                "time": 1000,
                "actor": {"user": {"name": "alice", "type": "User"}},
                "api": {"operation": "create"},
                "resources": [{"type": "serviceaccounts", "name": "sa", "subresource": "token"}],
            }
        ]
        assert list(rule4_token_self_grant(events)) == []

    def test_native_input_fires(self):
        events = [
            _native_sa_event(
                verb="create",
                resource_type="serviceaccounts",
                name="target-sa",
                subresource="token",
            )
        ]
        findings = list(rule4_token_self_grant(events))
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"


# ── Finding shape / OCSF compliance ───────────────────────────────────


class TestFindingShape:
    def test_class_and_metadata(self):
        events = [_sa_event(verb="create", resource_type="pods", name="web", subresource="exec")]
        f = list(detect(events))[0]
        assert f["class_uid"] == FINDING_CLASS_UID == 2004
        assert f["category_uid"] == FINDING_CATEGORY_UID == 2
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert f["metadata"]["version"] == "1.8.0"

    def test_attacks_inside_finding_info(self):
        # OCSF 1.8 Detection Finding — attacks MUST live inside finding_info
        events = [_sa_event(verb="create", resource_type="pods", name="web", subresource="exec")]
        f = list(detect(events))[0]
        assert "attacks" not in f, "attacks[] must NOT be at event root in OCSF 1.8"
        assert "attacks" in f["finding_info"]
        assert len(f["finding_info"]["attacks"]) == 1

    def test_native_output_has_no_ocsf_envelope(self):
        events = [_sa_event(verb="create", resource_type="pods", name="web", subresource="exec")]
        finding = list(detect(events, output_format="native"))[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["output_format"] == "native"
        assert "class_uid" not in finding
        assert "finding_info" not in finding
        assert finding["rule_name"] == "r2-pod-exec"

    def test_native_input_can_still_emit_ocsf(self):
        events = [
            _native_sa_event(verb="create", resource_type="pods", name="web", subresource="exec")
        ]
        finding = list(detect(events))[0]
        assert finding["class_uid"] == FINDING_CLASS_UID
        assert finding["finding_info"]["uid"].startswith("det-k8s-r2-pod-exec-")


# ── load_jsonl robustness ─────────────────────────────────────────────


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_skips_malformed_with_json_stderr(self, capsys, monkeypatch):
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["skill"] == SKILL_NAME
        assert payload["level"] == "warning"
        assert payload["event"] == "json_parse_failed"
        assert payload["line"] == 1


# ── Golden fixture parity ──────────────────────────────────────────────


class TestGoldenFixture:
    def test_fires_exactly_three_findings(self):
        events = _load(OCSF_INPUT)
        findings = list(detect(events))
        assert len(findings) == 3

    def test_findings_match_frozen_expected(self):
        events = _load(OCSF_INPUT)
        produced = list(detect(events))
        expected = _load(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e, (
                f"finding mismatch:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )

    def test_all_three_rules_fired(self):
        events = _load(OCSF_INPUT)
        findings = list(detect(events))
        rules = [f["finding_info"]["uid"].split("-")[2] for f in findings]
        assert set(rules) == {"r1", "r2", "r3"}

    def test_mitre_techniques_present(self):
        events = _load(OCSF_INPUT)
        techniques = {f["finding_info"]["attacks"][0]["technique"]["uid"] for f in detect(events)}
        assert techniques == {"T1552", "T1611", "T1098"}
