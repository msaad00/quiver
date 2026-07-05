"""Tests for remediate-container-escape-k8s forensic collector."""

from __future__ import annotations

import importlib.util
import sys
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SRC_DIR = ROOT / "skills" / "remediation" / "remediate-container-escape-k8s" / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

spec = importlib.util.spec_from_file_location(
    "cloud_security_forensic_collector_test",
    SRC_DIR / "forensic_collector.py",
)
assert spec and spec.loader
collector = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = collector
spec.loader.exec_module(collector)


def _finding(
    *,
    target: str = "deployments/payments/api",
    namespace: str = "payments",
    resource_type: str = "deployments",
    resource_name: str = "api",
    pod_name: str = "",
) -> dict:
    observables = [
        {"name": "namespace", "type": "Other", "value": namespace},
        {"name": "resource.type", "type": "Other", "value": resource_type},
        {"name": "resource.name", "type": "Other", "value": resource_name},
    ]
    if pod_name:
        observables.append({"name": "pod.name", "type": "Other", "value": pod_name})
    return {
        "class_uid": 2004,
        "target": target,
        "metadata": {
            "uid": "find-1",
            "product": {"feature": {"name": "detect-container-escape-k8s"}},
        },
        "finding_info": {"uid": "find-1"},
        "observables": observables,
    }


def _write_proc(
    proc_root: Path,
    pid: str,
    container_id: str,
    *,
    status: str = "State:\tR\n",
    maps: str = "00400000-00452000 r-xp\n",
) -> None:
    pid_root = proc_root / pid
    pid_root.mkdir(parents=True, exist_ok=True)
    (pid_root / "cgroup").write_text(f"0::/kubepods/{container_id}\n")
    (pid_root / "status").write_text(status)
    (pid_root / "maps").write_text(maps)
    root_fs = proc_root / "roots" / pid
    root_fs.mkdir(parents=True, exist_ok=True)
    (root_fs / "etc").mkdir()
    (root_fs / "var").mkdir()
    (pid_root / "root").symlink_to(root_fs, target_is_directory=True)


@dataclass
class _FakeKube:
    pod_labels: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)
    workload_selectors: dict[tuple[str, str, str], dict[str, str]] = field(default_factory=dict)
    pods: list[collector.PodContext] = field(default_factory=list)
    snapshots: list[tuple[str, str, str, str | None]] = field(default_factory=list)

    def get_pod_labels(self, namespace: str, pod_name: str):
        return self.pod_labels.get((namespace, pod_name))

    def get_workload_selector(self, namespace: str, resource_type: str, resource_name: str):
        return self.workload_selectors.get((namespace, resource_type, resource_name))

    def list_target_pods(self, namespace: str, selector: dict[str, str]):
        return [pod for pod in self.pods if pod.namespace == namespace]

    def create_volume_snapshot(
        self, namespace: str, pvc_name: str, snapshot_name: str, snapshot_class_name: str | None
    ):
        self.snapshots.append((namespace, pvc_name, snapshot_name, snapshot_class_name))
        return collector.VolumeSnapshotRef(
            namespace=namespace,
            pvc_name=pvc_name,
            snapshot_name=snapshot_name,
            snapshot_class_name=snapshot_class_name or "",
            status="created",
        )


@dataclass
class _FakeUploader:
    uploads: list[dict] = field(default_factory=list)

    def upload(self, *, bucket: str, key: str, body: bytes, kms_key_arn: str) -> str:
        self.uploads.append(
            {
                "bucket": bucket,
                "key": key,
                "body": body,
                "kms_key_arn": kms_key_arn,
            }
        )
        return f"s3://{bucket}/{key}"


def _pod_context() -> collector.PodContext:
    return collector.PodContext(
        namespace="payments",
        pod_name="api-7d9b",
        pod_uid="pod-uid-1",
        node_name="worker-a",
        container_names=("api",),
        container_ids=("abcd1234",),
        pvc_names=("api-data",),
    )


class TestHelpers:
    def test_discover_target_pids_filters_by_container_id(self, tmp_path: Path):
        proc_root = tmp_path / "proc"
        proc_root.mkdir()
        _write_proc(proc_root, "101", "abcd1234")
        _write_proc(proc_root, "102", "other9999")
        matches = collector._discover_target_pids(proc_root, ("abcd1234",))
        assert matches == ["101"]

    def test_bundle_is_deterministic(self):
        artifacts = {
            "b.txt": b"world\n",
            "a.txt": b"hello\n",
        }
        first, first_sha = collector._build_bundle(artifacts)
        second, second_sha = collector._build_bundle(artifacts)
        assert first == second
        assert first_sha == second_sha


class TestRun:
    def test_dry_run_collects_proc_and_runtime_log_artifacts(self, tmp_path: Path):
        proc_root = tmp_path / "proc"
        log_root = tmp_path / "var-log"
        (log_root / "containers").mkdir(parents=True)
        _write_proc(proc_root, "101", "abcd1234")
        (log_root / "containers" / "api-7d9b_payments_api-abcd1234.log").write_text(
            "runtime log line\n"
        )

        kube = _FakeKube(
            workload_selectors={("payments", "deployments", "api"): {"app": "api"}},
            pods=[_pod_context()],
        )
        record = next(
            collector.run(
                [_finding()],
                kube_client=kube,
                proc_root=proc_root,
                log_root=log_root,
                collected_at=datetime(2026, 4, 19, 7, 0, tzinfo=timezone.utc),
            )
        )
        assert record["record_type"] == "remediation_plan"
        assert record["mode"] == "forensics"
        assert record["status"] == "planned"
        assert record["dry_run"] is True
        artifact_paths = {item["path"] for item in record["artifacts"]}
        assert "manifest/collection.json" in artifact_paths
        assert "proc/api-7d9b/101/status.txt" in artifact_paths
        assert any(path.startswith("runtime-logs/api-7d9b/containers/") for path in artifact_paths)

    def test_upload_writes_bundle_and_creates_volume_snapshots(self, tmp_path: Path):
        proc_root = tmp_path / "proc"
        log_root = tmp_path / "var-log"
        (log_root / "containers").mkdir(parents=True)
        _write_proc(proc_root, "101", "abcd1234")
        (log_root / "containers" / "api-7d9b_payments_api-abcd1234.log").write_text(
            "runtime log line\n"
        )

        kube = _FakeKube(
            workload_selectors={("payments", "deployments", "api"): {"app": "api"}},
            pods=[_pod_context()],
        )
        uploader = _FakeUploader()
        collected_at = datetime(2026, 4, 19, 7, 5, tzinfo=timezone.utc)
        record = next(
            collector.run(
                [_finding()],
                kube_client=kube,
                proc_root=proc_root,
                log_root=log_root,
                upload=True,
                snapshot_volumes=True,
                snapshot_class_name="csi-snapshots",
                uploader=uploader,
                s3_bucket="sec-k8s-remediation",
                kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/test",
                incident_id="inc-2026-04-19-001",
                approver="alice@example.com",
                collected_at=collected_at,
            )
        )
        assert record["record_type"] == "remediation_action"
        assert record["status"] == "success"
        assert record["bundle_uri"].startswith("s3://sec-k8s-remediation/container-escape/audit/")
        assert record["incident_id"] == "inc-2026-04-19-001"
        assert record["approver"] == "alice@example.com"
        assert len(uploader.uploads) == 1
        assert kube.snapshots and kube.snapshots[0][1] == "api-data"
        with tarfile.open(
            fileobj=collector.io.BytesIO(uploader.uploads[0]["body"]), mode="r:gz"
        ) as tar:
            names = sorted(tar.getnames())
        assert "manifest/collection.json" in names
        assert "proc/api-7d9b/101/status.txt" in names

    def test_protected_namespace_yields_skip_record(self, tmp_path: Path):
        proc_root = tmp_path / "proc"
        log_root = tmp_path / "var-log"
        kube = _FakeKube(pods=[_pod_context()])
        record = next(
            collector.run(
                [
                    _finding(
                        namespace="kube-system",
                        target="pods/kube-system/api-7d9b",
                        resource_type="pods",
                        resource_name="api-7d9b",
                        pod_name="api-7d9b",
                    )
                ],
                kube_client=kube,
                proc_root=proc_root,
                log_root=log_root,
            )
        )
        assert record["status"] == "would-violate-deny-list"
