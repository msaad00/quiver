"""Integration-style test for K8s container-escape forensic bundle planning."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    handler: object
    pods: list[object] = field(default_factory=list)

    def get_pod_labels(self, namespace: str, pod_name: str):
        return {("payments", "api-7d9b"): {"app": "api", "pod-template-hash": "7d9b"}}.get(
            (namespace, pod_name)
        )

    def get_workload_selector(self, namespace: str, resource_type: str, resource_name: str):
        return {("payments", "deployments", "api"): {"app": "api"}}.get(
            (namespace, resource_type, resource_name)
        )

    def list_target_pods(self, namespace: str, selector: dict[str, str]):
        return [pod for pod in self.pods if pod.namespace == namespace]

    def create_volume_snapshot(
        self, namespace: str, pvc_name: str, snapshot_name: str, snapshot_class_name: str | None
    ):
        raise AssertionError("dry-run integration test must not create snapshots")


class TestK8sContainerEscapeForensicsPipeline:
    def setup_method(self):
        self.collector = _load_module(
            "_int_collect_container_escape_k8s",
            SKILLS_ROOT
            / "remediation"
            / "remediate-container-escape-k8s"
            / "src"
            / "forensic_collector.py",
        )

    def test_frozen_findings_produce_dry_run_forensic_plans(self, tmp_path: Path):
        proc_root = tmp_path / "proc"
        log_root = tmp_path / "var-log"
        (log_root / "containers").mkdir(parents=True)

        for pid, cid in (("101", "abcd1234"), ("102", "efgh5678")):
            pid_root = proc_root / pid
            pid_root.mkdir(parents=True)
            (pid_root / "cgroup").write_text(f"0::/kubepods/{cid}\n")
            (pid_root / "status").write_text("State:\tR\n")
            (pid_root / "maps").write_text("00400000-00452000 r-xp\n")
            root_fs = proc_root / "roots" / pid
            root_fs.mkdir(parents=True)
            (root_fs / "etc").mkdir()
            (pid_root / "root").symlink_to(root_fs, target_is_directory=True)

        (log_root / "containers" / "api-7d9b_payments_api-abcd1234.log").write_text(
            "runtime log line\n"
        )

        pods = [
            self.collector.PodContext(
                namespace="payments",
                pod_name="api-7d9b",
                pod_uid="pod-uid-1",
                node_name="worker-a",
                container_names=("api",),
                container_ids=("abcd1234",),
                pvc_names=("api-data",),
            )
        ]
        findings = _load_jsonl(GOLDEN_DIR / "k8s_container_escape_findings.ocsf.jsonl")
        records = list(
            self.collector.run(
                findings,
                kube_client=_FakeKube(handler=self.collector, pods=pods),
                proc_root=proc_root,
                log_root=log_root,
                collected_at=datetime(2026, 4, 19, 7, 10, tzinfo=timezone.utc),
            )
        )
        assert len(records) == 3
        assert {record["record_type"] for record in records} == {"remediation_plan"}
        assert {record["mode"] for record in records} == {"forensics"}
        assert all(record["bundle_size_bytes"] > 0 for record in records)
        assert all(record["artifacts"] for record in records)
