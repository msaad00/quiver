"""Collect forensic evidence for a quarantined Kubernetes container-escape target.

This module is intended to run inside a controlled sidecar or follow-up worker
after quarantine lands. It resolves the target pod set from the same
container-escape findings consumed by handler.py, discovers target PIDs by
matching container IDs against host-mounted /proc cgroup entries, captures
process and runtime-log artifacts, optionally creates CSI VolumeSnapshots, and
can upload a deterministic tar.gz evidence bundle to KMS-encrypted S3.
"""

from __future__ import annotations

import argparse
import dataclasses
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Protocol

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
SRC_DIR = Path(__file__).resolve().parent

if TYPE_CHECKING:
    from handler import ResolvedTarget, Target


def _load_handler_module() -> Any:
    module_name = "cloud_security_k8s_escape_handler_forensics"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing

    spec = importlib.util.spec_from_file_location(module_name, SRC_DIR / "handler.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_HANDLER = _load_handler_module()
CANONICAL_VERSION = _HANDLER.CANONICAL_VERSION
DEFAULT_DENY_NAMESPACES = _HANDLER.DEFAULT_DENY_NAMESPACES
RECORD_ACTION = _HANDLER.RECORD_ACTION
RECORD_PLAN = _HANDLER.RECORD_PLAN
STATUS_PLANNED = _HANDLER.STATUS_PLANNED
STATUS_SKIPPED_UNSUPPORTED_TARGET = _HANDLER.STATUS_SKIPPED_UNSUPPORTED_TARGET
STATUS_SUCCESS = _HANDLER.STATUS_SUCCESS
STATUS_WOULD_VIOLATE_DENY_LIST = _HANDLER.STATUS_WOULD_VIOLATE_DENY_LIST
check_apply_gate = _HANDLER.check_apply_gate
is_protected_namespace = _HANDLER.is_protected_namespace
load_jsonl = _HANDLER.load_jsonl
parse_targets = _HANDLER.parse_targets
resolve_target = _HANDLER.resolve_target

SKILL_NAME = "remediate-container-escape-k8s"
STEP_COLLECT_FORENSICS = "collect_forensic_bundle"
STEP_CREATE_VOLUME_SNAPSHOT = "create_volume_snapshot"
DEFAULT_PROC_ROOT = Path("/host/proc")
DEFAULT_LOG_ROOT = Path("/host/var/log")
MAX_ROOT_LISTING_ENTRIES = 128
MAX_LOG_BYTES = 1024 * 1024


@dataclasses.dataclass(frozen=True)
class PodContext:
    namespace: str
    pod_name: str
    pod_uid: str
    node_name: str
    container_names: tuple[str, ...]
    container_ids: tuple[str, ...]
    pvc_names: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class VolumeSnapshotRef:
    namespace: str
    pvc_name: str
    snapshot_name: str
    snapshot_class_name: str
    status: str


class KubernetesForensicsClient(Protocol):
    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str] | None: ...
    def get_workload_selector(
        self, namespace: str, resource_type: str, resource_name: str
    ) -> dict[str, str] | None: ...
    def list_target_pods(self, namespace: str, selector: dict[str, str]) -> list[PodContext]: ...
    def create_volume_snapshot(
        self,
        namespace: str,
        pvc_name: str,
        snapshot_name: str,
        snapshot_class_name: str | None,
    ) -> VolumeSnapshotRef: ...


class BundleUploader(Protocol):
    def upload(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        kms_key_arn: str,
    ) -> str: ...


@dataclasses.dataclass
class KubernetesApiForensicsClient:
    """Real Kubernetes client for forensic follow-up."""

    def _apis(self) -> tuple[Any, Any]:
        from kubernetes import client  # local import
        from kubernetes.config import load_incluster_config, load_kube_config

        try:
            load_incluster_config()
        except Exception:
            load_kube_config()
        return client.CoreV1Api(), client.CustomObjectsApi()

    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str] | None:
        core, _ = self._apis()
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
        labels = (
            (getattr(pod.metadata, "labels", None) or {}) if getattr(pod, "metadata", None) else {}
        )
        return dict(labels) if labels else None

    def get_workload_selector(
        self, namespace: str, resource_type: str, resource_name: str
    ) -> dict[str, str] | None:
        from kubernetes import client  # local import

        core, _ = self._apis()
        apps = client.AppsV1Api()
        batch = client.BatchV1Api()

        def _selector(obj: Any) -> dict[str, str] | None:
            spec = getattr(obj, "spec", None)
            if spec is None:
                return None
            selector = getattr(spec, "selector", None)
            labels = getattr(selector, "match_labels", None) if selector is not None else None
            if labels:
                return dict(labels)
            template = getattr(spec, "template", None)
            metadata = getattr(template, "metadata", None) if template is not None else None
            tmpl_labels = getattr(metadata, "labels", None) if metadata is not None else None
            return dict(tmpl_labels) if tmpl_labels else None

        if resource_type == "deployments":
            return _selector(
                apps.read_namespaced_deployment(name=resource_name, namespace=namespace)
            )
        if resource_type == "daemonsets":
            return _selector(
                apps.read_namespaced_daemon_set(name=resource_name, namespace=namespace)
            )
        if resource_type == "statefulsets":
            return _selector(
                apps.read_namespaced_stateful_set(name=resource_name, namespace=namespace)
            )
        if resource_type == "replicasets":
            return _selector(
                apps.read_namespaced_replica_set(name=resource_name, namespace=namespace)
            )
        if resource_type == "replicationcontrollers":
            return _selector(
                core.read_namespaced_replication_controller(name=resource_name, namespace=namespace)
            )
        if resource_type == "jobs":
            return _selector(batch.read_namespaced_job(name=resource_name, namespace=namespace))
        if resource_type == "cronjobs":
            return _selector(
                batch.read_namespaced_cron_job(name=resource_name, namespace=namespace)
            )
        return None

    def list_target_pods(self, namespace: str, selector: dict[str, str]) -> list[PodContext]:
        core, _ = self._apis()
        label_selector = ",".join(f"{key}={value}" for key, value in sorted(selector.items()))
        pods = core.list_namespaced_pod(namespace=namespace, label_selector=label_selector).items
        results: list[PodContext] = []
        for pod in pods:
            metadata = getattr(pod, "metadata", None)
            spec = getattr(pod, "spec", None)
            status = getattr(pod, "status", None)
            if metadata is None or spec is None:
                continue

            container_names: list[str] = []
            container_ids: list[str] = []
            for group in (
                getattr(status, "container_statuses", None) or [],
                getattr(status, "init_container_statuses", None) or [],
                getattr(status, "ephemeral_container_statuses", None) or [],
            ):
                for item in group:
                    name = str(getattr(item, "name", "") or "")
                    if name:
                        container_names.append(name)
                    raw_container_id = str(getattr(item, "container_id", "") or "")
                    container_id = _normalize_container_id(raw_container_id)
                    if container_id:
                        container_ids.append(container_id)

            pvc_names: list[str] = []
            for volume in getattr(spec, "volumes", None) or []:
                pvc = getattr(volume, "persistent_volume_claim", None)
                claim_name = str(getattr(pvc, "claim_name", "") or "")
                if claim_name:
                    pvc_names.append(claim_name)

            results.append(
                PodContext(
                    namespace=namespace,
                    pod_name=str(getattr(metadata, "name", "") or ""),
                    pod_uid=str(getattr(metadata, "uid", "") or ""),
                    node_name=str(getattr(spec, "node_name", "") or ""),
                    container_names=tuple(sorted(set(name for name in container_names if name))),
                    container_ids=tuple(sorted(set(cid for cid in container_ids if cid))),
                    pvc_names=tuple(sorted(set(name for name in pvc_names if name))),
                )
            )
        return results

    def create_volume_snapshot(
        self,
        namespace: str,
        pvc_name: str,
        snapshot_name: str,
        snapshot_class_name: str | None,
    ) -> VolumeSnapshotRef:
        _, custom = self._apis()
        body: dict[str, Any] = {
            "apiVersion": "snapshot.storage.k8s.io/v1",
            "kind": "VolumeSnapshot",
            "metadata": {"name": snapshot_name, "namespace": namespace},
            "spec": {"source": {"persistentVolumeClaimName": pvc_name}},
        }
        if snapshot_class_name:
            body["spec"]["volumeSnapshotClassName"] = snapshot_class_name
        custom.create_namespaced_custom_object(
            group="snapshot.storage.k8s.io",
            version="v1",
            plural="volumesnapshots",
            namespace=namespace,
            body=body,
        )
        return VolumeSnapshotRef(
            namespace=namespace,
            pvc_name=pvc_name,
            snapshot_name=snapshot_name,
            snapshot_class_name=snapshot_class_name or "",
            status="created",
        )


@dataclasses.dataclass
class KmsS3Uploader:
    def upload(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        kms_key_arn: str,
    ) -> str:
        import boto3  # local import

        boto3.client("s3").put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key_arn,
            ContentType="application/gzip",
        )
        return f"s3://{bucket}/{key}"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_container_id(value: str) -> str:
    raw = (value or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    return raw.strip()


def _sanitize_name(value: str, *, fallback: str) -> str:
    text = (value or "").strip().lower().replace("_", "-").replace(".", "-")
    text = re.sub(r"[^a-z0-9-]+", "-", text).strip("-")
    return text or fallback


def _bundle_prefix(incident_id: str) -> str:
    return f"container-escape/audit/{_sanitize_name(incident_id, fallback='incident')}"


def _bundle_name(target: Target, collected_at: datetime) -> str:
    stamp = collected_at.strftime("%Y%m%dT%H%M%SZ")
    base = _sanitize_name(target.pod_name or target.resource_name, fallback="target")
    return f"{stamp}-{target.namespace}-{base}-forensics.tar.gz"


def _bundle_key(target: Target, incident_id: str, collected_at: datetime) -> str:
    return f"{_bundle_prefix(incident_id)}/{_bundle_name(target, collected_at)}"


def _snapshot_name(namespace: str, pvc_name: str, collected_at: datetime) -> str:
    stamp = collected_at.strftime("%Y%m%d%H%M%S")
    base = _sanitize_name(pvc_name, fallback="pvc")
    digest = hashlib.sha256(f"{namespace}|{pvc_name}|{stamp}".encode("utf-8")).hexdigest()[:10]
    return f"ce-snap-{base[:39]}-{digest}"[:63].rstrip("-")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _discover_target_pids(proc_root: Path, container_ids: Iterable[str]) -> list[str]:
    ids = {cid for cid in (_normalize_container_id(value) for value in container_ids) if cid}
    if not ids or not proc_root.exists():
        return []

    matches: list[str] = []
    for entry in sorted(proc_root.iterdir(), key=lambda item: item.name):
        if not entry.is_dir() or not entry.name.isdigit():
            continue
        cgroup_path = entry / "cgroup"
        if not cgroup_path.exists():
            continue
        try:
            cgroup_text = _read_text(cgroup_path)
        except OSError:
            continue
        if any(cid in cgroup_text for cid in ids):
            matches.append(entry.name)
    return matches


def _root_listing(proc_root: Path, pid: str) -> bytes:
    root_path = proc_root / pid / "root"
    if not root_path.exists():
        return b"<missing>\n"
    try:
        if root_path.is_dir():
            items = sorted(child.name for child in root_path.iterdir())[:MAX_ROOT_LISTING_ENTRIES]
            return ("\n".join(items) + ("\n" if items else "")).encode("utf-8")
        return (str(root_path.resolve()) + "\n").encode("utf-8")
    except OSError as exc:
        return f"<error: {exc}>\n".encode("utf-8")


def _collect_proc_artifacts(proc_root: Path, pod: PodContext) -> dict[str, bytes]:
    artifacts: dict[str, bytes] = {}
    pids = _discover_target_pids(proc_root, pod.container_ids)
    for pid in pids:
        pid_root = proc_root / pid
        base = f"proc/{pod.pod_name}/{pid}"
        for name in ("status", "maps", "cgroup"):
            path = pid_root / name
            try:
                data = _read_bytes(path)
            except OSError:
                continue
            artifacts[f"{base}/{name}.txt"] = data
        artifacts[f"{base}/root_listing.txt"] = _root_listing(proc_root, pid)
    if not pids:
        artifacts[f"proc/{pod.pod_name}/no-matching-pids.txt"] = (
            "no host PIDs matched the target container IDs\n".encode("utf-8")
        )
    return artifacts


def _runtime_log_paths(log_root: Path, pod: PodContext) -> list[Path]:
    candidates: list[Path] = []
    container_dir = log_root / "containers"
    if container_dir.exists():
        for container_name in pod.container_names:
            pattern = f"{pod.pod_name}_{pod.namespace}_{container_name}-*.log"
            candidates.extend(sorted(container_dir.glob(pattern)))

    pod_dir = log_root / "pods" / f"{pod.namespace}_{pod.pod_name}_{pod.pod_uid}"
    if pod_dir.exists():
        for container_name in pod.container_names:
            container_path = pod_dir / container_name
            if container_path.exists():
                candidates.extend(sorted(container_path.glob("*.log")))

    unique: dict[str, Path] = {}
    for path in candidates:
        unique[str(path)] = path
    return [unique[key] for key in sorted(unique)]


def _collect_runtime_log_artifacts(log_root: Path, pod: PodContext) -> dict[str, bytes]:
    artifacts: dict[str, bytes] = {}
    for path in _runtime_log_paths(log_root, pod):
        try:
            data = _read_bytes(path)[:MAX_LOG_BYTES]
        except OSError:
            continue
        rel = path.relative_to(log_root)
        artifacts[f"runtime-logs/{pod.pod_name}/{rel.as_posix()}"] = data
    if not artifacts:
        artifacts[f"runtime-logs/{pod.pod_name}/no-runtime-logs.txt"] = (
            b"no runtime log files matched the target pod\n"
        )
    return artifacts


def _plan_volume_snapshots(
    *,
    pods: Iterable[PodContext],
    collected_at: datetime,
    snapshot_class_name: str | None,
) -> list[VolumeSnapshotRef]:
    planned: list[VolumeSnapshotRef] = []
    seen: set[tuple[str, str]] = set()
    for pod in pods:
        for pvc_name in pod.pvc_names:
            key = (pod.namespace, pvc_name)
            if key in seen:
                continue
            seen.add(key)
            planned.append(
                VolumeSnapshotRef(
                    namespace=pod.namespace,
                    pvc_name=pvc_name,
                    snapshot_name=_snapshot_name(pod.namespace, pvc_name, collected_at),
                    snapshot_class_name=snapshot_class_name or "",
                    status=STATUS_PLANNED,
                )
            )
    return planned


def _create_volume_snapshots(
    kube_client: KubernetesForensicsClient,
    *,
    pods: Iterable[PodContext],
    collected_at: datetime,
    snapshot_class_name: str | None,
) -> list[VolumeSnapshotRef]:
    created: list[VolumeSnapshotRef] = []
    for ref in _plan_volume_snapshots(
        pods=pods,
        collected_at=collected_at,
        snapshot_class_name=snapshot_class_name,
    ):
        created.append(
            kube_client.create_volume_snapshot(
                ref.namespace,
                ref.pvc_name,
                ref.snapshot_name,
                snapshot_class_name,
            )
        )
    return created


def _bundle_manifest(
    *,
    resolved: ResolvedTarget,
    pods: Iterable[PodContext],
    snapshots: Iterable[VolumeSnapshotRef],
    collected_at: datetime,
) -> bytes:
    payload = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "source_skill": SKILL_NAME,
        "collected_at": collected_at.isoformat(),
        "target": {
            "namespace": resolved.target.namespace,
            "resource_type": resolved.target.resource_type,
            "resource_name": resolved.target.resource_name,
            "pod_name": resolved.target.pod_name,
            "finding_uid": resolved.target.finding_uid,
        },
        "selector": resolved.selector,
        "pods": [
            {
                "namespace": pod.namespace,
                "pod_name": pod.pod_name,
                "pod_uid": pod.pod_uid,
                "node_name": pod.node_name,
                "container_names": list(pod.container_names),
                "container_ids": list(pod.container_ids),
                "pvc_names": list(pod.pvc_names),
            }
            for pod in pods
        ],
        "volume_snapshots": [dataclasses.asdict(snapshot) for snapshot in snapshots],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _build_bundle(artifacts: dict[str, bytes]) -> tuple[bytes, str]:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz_handle:
        with tarfile.open(fileobj=gz_handle, mode="w") as tar:
            for name in sorted(artifacts):
                data = artifacts[name]
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    bundle = buffer.getvalue()
    digest = hashlib.sha256(bundle).hexdigest()
    return bundle, digest


def _artifact_summary(artifacts: dict[str, bytes]) -> list[dict[str, Any]]:
    return [
        {
            "path": path,
            "size": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
        for path, body in sorted(artifacts.items())
    ]


def _resolve_pods(
    resolved: ResolvedTarget,
    kube_client: KubernetesForensicsClient,
) -> list[PodContext]:
    pods = kube_client.list_target_pods(resolved.target.namespace, resolved.selector)
    if resolved.target.pod_name:
        return [pod for pod in pods if pod.pod_name == resolved.target.pod_name]
    if resolved.target.resource_type == "pods":
        return [pod for pod in pods if pod.pod_name == resolved.target.resource_name]
    return pods


def _collection_record(
    resolved: ResolvedTarget,
    *,
    pods: list[PodContext],
    artifacts: dict[str, bytes],
    snapshots: list[VolumeSnapshotRef],
    status: str,
    dry_run: bool,
    bundle_sha256: str,
    bundle_size: int,
    bundle_uri: str | None,
    incident_id: str,
    approver: str,
    collected_at: datetime,
) -> dict[str, Any]:
    actions = [
        {
            "step": STEP_COLLECT_FORENSICS,
            "endpoint": bundle_uri
            or "PUT s3://<configured bucket>/container-escape/audit/<incident-id>/<bundle>",
            "status": status,
            "detail": "dry-run: would collect and upload forensic bundle"
            if dry_run
            else "forensic bundle uploaded",
        }
    ]
    if snapshots:
        actions.append(
            {
                "step": STEP_CREATE_VOLUME_SNAPSHOT,
                "endpoint": f"POST /apis/snapshot.storage.k8s.io/v1/namespaces/{resolved.target.namespace}/volumesnapshots",
                "status": status,
                "detail": (
                    "dry-run: would create VolumeSnapshot objects"
                    if dry_run
                    else "VolumeSnapshot objects created"
                ),
            }
        )
    record: dict[str, Any] = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "mode": "forensics",
        "target": {
            "provider": "Kubernetes",
            "namespace": resolved.target.namespace,
            "resource_type": resolved.target.resource_type,
            "resource_name": resolved.target.resource_name,
            "pod_name": resolved.target.pod_name,
        },
        "selector": resolved.selector,
        "pods": [
            {
                "namespace": pod.namespace,
                "pod_name": pod.pod_name,
                "pod_uid": pod.pod_uid,
                "node_name": pod.node_name,
                "container_names": list(pod.container_names),
                "pvc_names": list(pod.pvc_names),
            }
            for pod in pods
        ],
        "actions": actions,
        "status": status,
        "dry_run": dry_run,
        "bundle_sha256": bundle_sha256,
        "bundle_size_bytes": bundle_size,
        "bundle_uri": bundle_uri,
        "artifacts": _artifact_summary(artifacts),
        "volume_snapshots": [dataclasses.asdict(snapshot) for snapshot in snapshots],
        "finding_uid": resolved.target.finding_uid,
        "collected_at": collected_at.isoformat(),
        "time_ms": int(collected_at.timestamp() * 1000),
    }
    if incident_id:
        record["incident_id"] = incident_id
    if approver:
        record["approver"] = approver
    return record


def _skip_record(target: Target, *, status: str, detail: str) -> dict[str, Any]:
    now = _now_utc()
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN,
        "source_skill": SKILL_NAME,
        "mode": "forensics",
        "target": {
            "provider": "Kubernetes",
            "namespace": target.namespace,
            "resource_type": target.resource_type,
            "resource_name": target.resource_name,
            "pod_name": target.pod_name,
        },
        "actions": [],
        "status": status,
        "status_detail": detail,
        "dry_run": True,
        "finding_uid": target.finding_uid,
        "time_ms": int(now.timestamp() * 1000),
    }


def collect_forensics(
    resolved: ResolvedTarget,
    *,
    kube_client: KubernetesForensicsClient,
    proc_root: Path,
    log_root: Path,
    upload: bool = False,
    snapshot_volumes: bool = False,
    snapshot_class_name: str | None = None,
    uploader: BundleUploader | None = None,
    s3_bucket: str = "",
    kms_key_arn: str = "",
    incident_id: str = "",
    approver: str = "",
    collected_at: datetime | None = None,
) -> dict[str, Any]:
    collected_at = collected_at or _now_utc()
    pods = _resolve_pods(resolved, kube_client)
    if not pods:
        return _skip_record(
            resolved.target,
            status=STATUS_SKIPPED_UNSUPPORTED_TARGET,
            detail="could not resolve any pods from the target selector for forensic collection",
        )

    snapshots = (
        _plan_volume_snapshots(
            pods=pods, collected_at=collected_at, snapshot_class_name=snapshot_class_name
        )
        if snapshot_volumes and not upload
        else []
    )

    artifacts: dict[str, bytes] = {
        "manifest/collection.json": _bundle_manifest(
            resolved=resolved,
            pods=pods,
            snapshots=snapshots,
            collected_at=collected_at,
        )
    }
    for pod in pods:
        artifacts.update(_collect_proc_artifacts(proc_root, pod))
        artifacts.update(_collect_runtime_log_artifacts(log_root, pod))

    if snapshot_volumes and upload:
        snapshots = _create_volume_snapshots(
            kube_client,
            pods=pods,
            collected_at=collected_at,
            snapshot_class_name=snapshot_class_name,
        )
        artifacts["manifest/collection.json"] = _bundle_manifest(
            resolved=resolved,
            pods=pods,
            snapshots=snapshots,
            collected_at=collected_at,
        )

    bundle, bundle_sha256 = _build_bundle(artifacts)
    bundle_uri: str | None = None
    if upload:
        if uploader is None:
            raise ValueError("uploader is required when upload=True")
        if not s3_bucket:
            raise ValueError("s3_bucket is required when upload=True")
        if not kms_key_arn:
            raise ValueError("kms_key_arn is required when upload=True")
        bundle_uri = uploader.upload(
            bucket=s3_bucket,
            key=_bundle_key(resolved.target, incident_id, collected_at),
            body=bundle,
            kms_key_arn=kms_key_arn,
        )

    return _collection_record(
        resolved,
        pods=pods,
        artifacts=artifacts,
        snapshots=snapshots,
        status=STATUS_PLANNED if not upload else STATUS_SUCCESS,
        dry_run=not upload,
        bundle_sha256=bundle_sha256,
        bundle_size=len(bundle),
        bundle_uri=bundle_uri,
        incident_id=incident_id,
        approver=approver,
        collected_at=collected_at,
    )


def run(
    events: Iterable[dict[str, Any]],
    *,
    kube_client: KubernetesForensicsClient,
    proc_root: Path,
    log_root: Path,
    upload: bool = False,
    snapshot_volumes: bool = False,
    snapshot_class_name: str | None = None,
    uploader: BundleUploader | None = None,
    s3_bucket: str = "",
    kms_key_arn: str = "",
    incident_id: str = "",
    approver: str = "",
    collected_at: datetime | None = None,
) -> Iterator[dict[str, Any]]:
    for target, _ in parse_targets(events):
        if target is None:
            continue

        denied, matched = is_protected_namespace(target.namespace, DEFAULT_DENY_NAMESPACES)
        if denied:
            yield _skip_record(
                target,
                status=STATUS_WOULD_VIOLATE_DENY_LIST,
                detail=f"namespace `{target.namespace}` matched protected pattern `{matched}`",
            )
            continue

        resolved = resolve_target(target, kube_client)
        if resolved is None:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_UNSUPPORTED_TARGET,
                detail="could not resolve a pod or workload selector for forensic collection",
            )
            continue

        yield collect_forensics(
            resolved,
            kube_client=kube_client,
            proc_root=proc_root,
            log_root=log_root,
            upload=upload,
            snapshot_volumes=snapshot_volumes,
            snapshot_class_name=snapshot_class_name,
            uploader=uploader,
            s3_bucket=s3_bucket,
            kms_key_arn=kms_key_arn,
            incident_id=incident_id,
            approver=approver,
            collected_at=collected_at,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan or collect forensic evidence bundles for quarantined Kubernetes container-escape targets."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--upload", action="store_true", help="Upload the forensic bundle to KMS-encrypted S3."
    )
    parser.add_argument(
        "--snapshot-volumes",
        action="store_true",
        help="Plan or create CSI VolumeSnapshot objects for PVC-backed pod volumes.",
    )
    parser.add_argument("--snapshot-class", help="Optional VolumeSnapshotClass name.")
    parser.add_argument(
        "--proc-root", default=str(DEFAULT_PROC_ROOT), help="Mounted host /proc root."
    )
    parser.add_argument(
        "--log-root", default=str(DEFAULT_LOG_ROOT), help="Mounted host /var/log root."
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        incident_id = ""
        approver = ""
        uploader: BundleUploader | None = None
        s3_bucket = ""
        kms_key_arn = ""
        if args.upload or args.snapshot_volumes and args.upload:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.getenv("K8S_CONTAINER_ESCAPE_INCIDENT_ID", "").strip()
            approver = os.getenv("K8S_CONTAINER_ESCAPE_APPROVER", "").strip()
        if args.upload:
            uploader = KmsS3Uploader()
            s3_bucket = os.environ["K8S_REMEDIATION_AUDIT_BUCKET"]
            kms_key_arn = os.environ["KMS_KEY_ARN"]

        kube_client = KubernetesApiForensicsClient()
        for record in run(
            load_jsonl(in_stream),
            kube_client=kube_client,
            proc_root=Path(args.proc_root),
            log_root=Path(args.log_root),
            upload=args.upload,
            snapshot_volumes=args.snapshot_volumes,
            snapshot_class_name=args.snapshot_class,
            uploader=uploader,
            s3_bucket=s3_bucket,
            kms_key_arn=kms_key_arn,
            incident_id=incident_id,
            approver=approver,
        ):
            out_stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
