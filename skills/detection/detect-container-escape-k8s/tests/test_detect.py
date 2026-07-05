"""Tests for detect-container-escape-k8s."""

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
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SKILL_NAME,
    T1610_TECH_UID,
    T1611_TECH_UID,
    T1613_TECH_UID,
    WORKLOAD_RESOURCES,
    _extract_ephemeral_container_names,
    _find_risky_host_paths,
    _find_risky_settings,
    detect,
    rule1_risky_spec_patch,
    rule2_hostpath_injection,
    rule3_ephemeral_container_creation,
    rule4_unexpected_exec,
    rule5_runtime_fusion,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT_FIXTURE = GOLDEN / "k8s_container_escape_sample.ocsf.jsonl"
EXPECTED = GOLDEN / "k8s_container_escape_findings.ocsf.jsonl"


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    verb: str = "patch",
    resource_type: str = "pods",
    resource_name: str = "api-7d9b",
    namespace: str = "payments",
    subresource: str = "",
    time_ms: int = 1775798400000,
    actor: str = "system:serviceaccount:payments:builder",
    actor_type: str = "ServiceAccount",
    request_object: object | None = None,
    response_object: object | None = None,
) -> dict:
    resource: dict[str, object] = {
        "type": resource_type,
        "name": resource_name,
        "namespace": namespace,
    }
    if subresource:
        resource["subresource"] = subresource
    event: dict[str, object] = {
        "class_uid": 6003,
        "category_uid": 6,
        "time": time_ms,
        "actor": {"user": {"name": actor, "type": actor_type}},
        "api": {"operation": verb, "service": {"name": "kubernetes"}},
        "resources": [resource],
    }
    if request_object is not None or response_object is not None:
        event["unmapped"] = {"k8s": {}}
        if request_object is not None:
            event["unmapped"]["k8s"]["request_object"] = request_object  # type: ignore[index]
        if response_object is not None:
            event["unmapped"]["k8s"]["response_object"] = response_object  # type: ignore[index]
    return event


def _native_event(
    *,
    verb: str = "patch",
    resource_type: str = "pods",
    resource_name: str = "api-7d9b",
    namespace: str = "payments",
    subresource: str = "",
    time_ms: int = 1775798400000,
    actor: str = "system:serviceaccount:payments:builder",
    request_object: object | None = None,
    response_object: object | None = None,
) -> dict:
    resource: dict[str, object] = {
        "type": resource_type,
        "name": resource_name,
        "namespace": namespace,
    }
    if subresource:
        resource["subresource"] = subresource
    event: dict[str, object] = {
        "schema_mode": "native",
        "record_type": "api_activity",
        "provider": "Kubernetes",
        "time_ms": time_ms,
        "actor_name": actor,
        "operation": verb,
        "resources": [resource],
    }
    if request_object is not None or response_object is not None:
        event["unmapped"] = {"k8s": {}}
        if request_object is not None:
            event["unmapped"]["k8s"]["request_object"] = request_object  # type: ignore[index]
        if response_object is not None:
            event["unmapped"]["k8s"]["response_object"] = response_object  # type: ignore[index]
    return event


def _runtime_event(
    *,
    source: str = "falco",
    time_ms: int = 1775798460000,
    container_id: str = "containerd://abcd1234",
    pod_name: str = "api-7d9b",
    namespace: str = "payments",
    rule: str = "Terminal shell in container",
    description: str = "Terminal shell in container",
) -> dict:
    if source == "falco":
        return {
            "source": "falco",
            "time": time_ms,
            "rule": rule,
            "output": description,
            "output_fields": {
                "container.id": container_id,
                "k8s.ns.name": namespace,
                "k8s.pod.name": pod_name,
            },
        }
    return {
        "source": "tracee",
        "ts": time_ms,
        "eventName": rule,
        "description": description,
        "container": {"id": container_id},
        "kubernetes": {"namespace": namespace, "podName": pod_name},
    }


class TestPatchSignalExtraction:
    def test_extracts_risky_settings_from_merge_patch(self):
        payload = {
            "spec": {
                "hostPID": True,
                "containers": [
                    {
                        "name": "api",
                        "securityContext": {
                            "privileged": True,
                            "capabilities": {"add": ["CAP_SYS_ADMIN", "NET_ADMIN"]},
                        },
                    }
                ],
            }
        }
        assert _find_risky_settings(payload) == [
            "capability=CAP_SYS_ADMIN",
            "hostPID=true",
            "privileged=true",
        ]

    def test_extracts_risky_settings_from_json_patch(self):
        payload = [
            {"op": "add", "path": "/spec/containers/0/securityContext/privileged", "value": True},
            {
                "op": "add",
                "path": "/spec/containers/0/securityContext/capabilities/add",
                "value": ["CAP_SYS_PTRACE"],
            },
        ]
        assert _find_risky_settings(payload) == ["capability=CAP_SYS_PTRACE", "privileged=true"]

    def test_extracts_risky_host_paths(self):
        payload = {
            "spec": {
                "volumes": [
                    {"name": "host-root", "hostPath": {"path": "/"}},
                    {"name": "proc", "hostPath": {"path": "/proc"}},
                ]
            }
        }
        assert _find_risky_host_paths(payload) == ["/", "/proc"]

    def test_extracts_ephemeral_container_names(self):
        payload = {
            "spec": {
                "ephemeralContainers": [
                    {"name": "debugger", "image": "busybox"},
                    {"name": "inspector", "image": "busybox"},
                ]
            }
        }
        assert _extract_ephemeral_container_names(payload) == ["debugger", "inspector"]


class TestRule1RiskySpecPatch:
    def test_fires_on_privileged_patch(self):
        findings = list(
            rule1_risky_spec_patch(
                [
                    _event(
                        request_object={
                            "spec": {
                                "containers": [
                                    {
                                        "name": "api",
                                        "securityContext": {
                                            "privileged": True,
                                            "capabilities": {"add": ["CAP_SYS_ADMIN"]},
                                        },
                                    }
                                ]
                            }
                        }
                    )
                ]
            )
        )
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["technique_uid"] == T1611_TECH_UID
        assert findings[0]["severity_id"] == SEVERITY_CRITICAL

    def test_benign_patch_does_not_fire(self):
        findings = list(
            rule1_risky_spec_patch(
                [
                    _event(
                        request_object={
                            "spec": {
                                "containers": [{"name": "api", "image": "ghcr.io/acme/api:v2"}]
                            }
                        }
                    )
                ]
            )
        )
        assert findings == []

    def test_non_patch_verb_does_not_fire(self):
        findings = list(
            rule1_risky_spec_patch(
                [
                    _event(
                        verb="create",
                        request_object={"spec": {"hostNetwork": True}},
                    )
                ]
            )
        )
        assert findings == []


class TestRule2HostPathInjection:
    def test_fires_on_risky_hostpath(self):
        findings = list(
            rule2_hostpath_injection(
                [
                    _event(
                        resource_type="deployments",
                        resource_name="api",
                        request_object={
                            "spec": {
                                "template": {
                                    "spec": {
                                        "volumes": [
                                            {
                                                "name": "host-root",
                                                "hostPath": {"path": "/var/lib/containerd"},
                                            }
                                        ]
                                    }
                                }
                            }
                        },
                    )
                ]
            )
        )
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["technique_uid"] == T1611_TECH_UID
        assert findings[0]["severity_id"] == SEVERITY_CRITICAL

    def test_non_risky_hostpath_does_not_fire(self):
        findings = list(
            rule2_hostpath_injection(
                [
                    _event(
                        request_object={
                            "spec": {
                                "volumes": [
                                    {"name": "cache", "hostPath": {"path": "/var/cache/app"}}
                                ]
                            }
                        }
                    )
                ]
            )
        )
        assert findings == []


class TestRule3EphemeralContainer:
    def test_fires_on_ephemeralcontainers_subresource(self):
        findings = list(
            rule3_ephemeral_container_creation(
                [
                    _event(
                        subresource="ephemeralcontainers",
                        request_object={"spec": {"ephemeralContainers": [{"name": "debugger"}]}},
                    )
                ]
            )
        )
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["technique_uid"] == T1610_TECH_UID
        assert findings[0]["severity_id"] == SEVERITY_HIGH

    def test_plain_pod_patch_without_ephemeralcontainers_does_not_fire(self):
        findings = list(
            rule3_ephemeral_container_creation([_event(request_object={"spec": {"hostPID": True}})])
        )
        assert findings == []


class TestRule4UnexpectedExec:
    def test_fires_when_exec_actor_differs_from_recent_deploy_actor(self):
        findings = list(
            rule4_unexpected_exec(
                [
                    _event(
                        verb="create",
                        resource_type="pods",
                        resource_name="api-7d9b",
                        time_ms=1775798400000,
                        actor="alice@example.com",
                        actor_type="User",
                    ),
                    _event(
                        verb="create",
                        resource_type="pods",
                        resource_name="api-7d9b",
                        subresource="exec",
                        time_ms=1775798460000,
                        actor="system:serviceaccount:payments:debugger",
                        actor_type="ServiceAccount",
                    ),
                ]
            )
        )
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["technique_uid"] == T1613_TECH_UID
        assert findings[0]["severity_id"] == SEVERITY_HIGH

    def test_known_operator_exec_does_not_fire(self):
        findings = list(
            rule4_unexpected_exec(
                [
                    _event(
                        verb="create",
                        resource_type="pods",
                        resource_name="api-7d9b",
                        time_ms=1775798400000,
                        actor="alice@example.com",
                        actor_type="User",
                    ),
                    _event(
                        verb="create",
                        resource_type="pods",
                        resource_name="api-7d9b",
                        subresource="exec",
                        time_ms=1775798460000,
                        actor="alice@example.com",
                        actor_type="User",
                    ),
                ],
                known_operator_principals=("alice@example.com",),
            )
        )
        assert findings == []


class TestRule5RuntimeFusion:
    def test_fuses_falco_and_tracee_on_container_id(self):
        findings = list(
            rule5_runtime_fusion(
                [
                    _runtime_event(
                        source="falco",
                        rule="Terminal shell in container",
                        description="Terminal shell in container",
                    ),
                    _runtime_event(
                        source="tracee",
                        time_ms=1775798462000,
                        rule="container_drift",
                        description="Container drift detected",
                    ),
                ]
            )
        )
        assert len(findings) == 1
        assert findings[0]["mitre_attacks"][0]["technique_uid"] == T1611_TECH_UID
        assert findings[0]["severity_id"] == SEVERITY_CRITICAL
        observables = {item["name"]: item["value"] for item in findings[0]["observables"]}
        assert observables["container.id"] == "abcd1234"
        assert observables["runtime.sources"] == "falco, tracee"

    def test_single_runtime_signal_still_emits(self):
        findings = list(
            rule5_runtime_fusion(
                [
                    _runtime_event(
                        source="falco",
                        rule="Write below root",
                        description="Write below root",
                    )
                ]
            )
        )
        assert len(findings) == 1
        assert findings[0]["severity_id"] == SEVERITY_HIGH


class TestDetectorShape:
    def test_workload_resources_constant_covers_core_targets(self):
        assert {"pods", "deployments", "daemonsets", "statefulsets"} <= WORKLOAD_RESOURCES

    def test_class_pinning(self):
        finding = list(
            detect(
                [
                    _event(
                        request_object={"spec": {"hostNetwork": True}},
                    )
                ]
            )
        )[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["category_uid"] == FINDING_CATEGORY_UID == 2
        assert finding["type_uid"] == FINDING_TYPE_UID == 200401
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["metadata"]["version"] == "1.8.0"

    def test_attacks_live_inside_finding_info(self):
        finding = list(
            detect(
                [
                    _event(
                        request_object={"spec": {"hostNetwork": True}},
                    )
                ]
            )
        )[0]
        assert "attacks" not in finding
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == T1611_TECH_UID

    def test_native_input_can_emit_native_finding(self):
        findings = list(
            detect(
                [
                    _native_event(
                        request_object={"spec": {"hostNetwork": True}},
                    )
                ],
                output_format="native",
            )
        )
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["record_type"] == "detection_finding"
        assert findings[0]["rule_name"] == "r1-risky-spec-patch"
        assert "class_uid" not in findings[0]

    def test_deterministic_uid(self):
        events = [_event(request_object={"spec": {"hostNetwork": True}})]
        first = list(detect(events))[0]["finding_info"]["uid"]
        second = list(detect(events))[0]["finding_info"]["uid"]
        assert first == second
        assert first.startswith("det-k8s-r1-risky-spec-patch-")


class TestGoldenParity:
    def test_fixture_matches_frozen_golden(self):
        produced = list(detect(_load_jsonl(INPUT_FIXTURE)))
        expected = _load_jsonl(EXPECTED)
        assert len(produced) == len(expected) == 3
        for actual, frozen in zip(produced, expected):
            assert actual == frozen, (
                f"detector drift:\n  actual: {json.dumps(actual, sort_keys=True)}\n"
                f"  frozen: {json.dumps(frozen, sort_keys=True)}"
            )

    def test_followup_fixture_matches_frozen_golden(self):
        input_fixture = GOLDEN / "k8s_container_escape_followup_input.jsonl"
        expected_fixture = GOLDEN / "k8s_container_escape_followup_findings.ocsf.jsonl"
        produced = list(detect(_load_jsonl(input_fixture)))
        expected = _load_jsonl(expected_fixture)
        assert len(produced) == len(expected) == 2
        for actual, frozen in zip(produced, expected):
            assert actual == frozen, (
                f"follow-up detector drift:\n  actual: {json.dumps(actual, sort_keys=True)}\n"
                f"  frozen: {json.dumps(frozen, sort_keys=True)}"
            )
