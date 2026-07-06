"""Integration test for the K8s container-escape remediation dry-run path."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_ROOT = REPO_ROOT / "skills"
GOLDEN_DIR = SKILLS_ROOT / "detection-engineering" / "golden"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"could not spec {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@dataclass
class _FakeKube:
    pod_labels: dict[tuple[str, str], dict[str, str]] = field(
        default_factory=lambda: {
            ("payments", "api-7d9b"): {"app": "api", "pod-template-hash": "7d9b"}
        }
    )
    workload_selectors: dict[tuple[str, str, str], dict[str, str]] = field(
        default_factory=lambda: {("payments", "deployments", "api"): {"app": "api"}}
    )

    def get_pod_labels(self, namespace: str, pod_name: str):
        return self.pod_labels.get((namespace, pod_name))

    def get_pod_node_name(self, namespace: str, pod_name: str):
        return "node-a"

    def get_workload_selector(self, namespace: str, resource_type: str, resource_name: str):
        return self.workload_selectors.get((namespace, resource_type, resource_name))

    def apply_network_policy(self, namespace: str, manifest: dict):
        raise AssertionError("dry-run integration test must not mutate the cluster")

    def get_network_policy(self, namespace: str, name: str):
        return None

    def get_pod(self, namespace: str, pod_name: str):
        return None

    def delete_pod(self, namespace: str, pod_name: str):
        raise AssertionError("dry-run integration test must not mutate the cluster")

    def list_pods_on_node(self, node_name: str):
        return []

    def cordon_node(self, node_name: str):
        raise AssertionError("dry-run integration test must not mutate the cluster")

    def evict_pod(self, namespace: str, pod_name: str):
        raise AssertionError("dry-run integration test must not mutate the cluster")

    def get_node(self, node_name: str):
        return {"spec": {"unschedulable": False}}


class TestK8sContainerEscapeRemediationPipeline:
    def setup_method(self):
        self.remediate = _load_module(
            "_int_remediate_container_escape_k8s",
            SKILLS_ROOT / "remediation" / "remediate-container-escape-k8s" / "src" / "handler.py",
        )

    def test_frozen_findings_produce_three_dry_run_plans(self):
        findings = _load_jsonl(GOLDEN_DIR / "k8s_container_escape_findings.ocsf.jsonl")
        records = list(self.remediate.run(findings, kube_client=_FakeKube()))
        assert len(records) == 3
        assert {record["record_type"] for record in records} == {"remediation_plan"}
        assert {record["status"] for record in records} == {"planned"}
        assert all(record["dry_run"] is True for record in records)
        assert all(record["manifest"]["kind"] == "NetworkPolicy" for record in records)
        assert all(record["manifest"]["spec"]["ingress"] == [] for record in records)
        assert all(record["manifest"]["spec"]["egress"] == [] for record in records)

    def test_followup_findings_produce_pod_kill_plans(self):
        findings = _load_jsonl(GOLDEN_DIR / "k8s_container_escape_followup_findings.ocsf.jsonl")
        records = list(
            self.remediate.run(
                findings,
                kube_client=_FakeKube(),
                action_mode=self.remediate.ACTION_POD_KILL,
            )
        )
        assert len(records) == 2
        assert {record["status"] for record in records} == {"planned"}
        assert {record["action_mode"] for record in records} == {self.remediate.ACTION_POD_KILL}
        assert {record["target"]["pod_name"] for record in records} == {"api-7d9b"}
        assert all(record["dry_run"] is True for record in records)
        assert all(
            record["actions"][0]["endpoint"] == "DELETE /api/v1/namespaces/payments/pods/api-7d9b"
            for record in records
        )

    def test_followup_findings_produce_node_drain_plans(self):
        findings = _load_jsonl(GOLDEN_DIR / "k8s_container_escape_followup_findings.ocsf.jsonl")
        records = list(
            self.remediate.run(
                findings,
                kube_client=_FakeKube(),
                action_mode=self.remediate.ACTION_NODE_DRAIN,
            )
        )
        assert len(records) == 2
        assert {record["status"] for record in records} == {"planned"}
        assert {record["action_mode"] for record in records} == {self.remediate.ACTION_NODE_DRAIN}
        assert {record["node_name"] for record in records} == {"node-a"}
        assert all(record["dry_run"] is True for record in records)
        assert all(record["actions"][0]["step"] == "cordon_and_drain_node" for record in records)
