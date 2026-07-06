"""Contain a Kubernetes container-escape signal with a deny-all NetworkPolicy.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-container-escape-k8s. Plans (dry-run default), applies (--apply), or
re-verifies (--reverify) a namespace-scoped deny-all NetworkPolicy that
matches the target pod or workload selector.

Guardrails enforced in code:
- source-skill check rejects findings from any non-container-escape producer
- deny-list of protected namespaces (kube-system, kube-public, istio-system, linkerd*)
- --apply requires K8S_CONTAINER_ESCAPE_INCIDENT_ID + K8S_CONTAINER_ESCAPE_APPROVER
- dual-audit write (DynamoDB + S3) BEFORE and AFTER the NetworkPolicy write
- --reverify checks that the policy still exists and still matches the selector
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Protocol

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.remediation_verifier import (  # noqa: E402
    DEFAULT_VERIFICATION_SLA_MS,
    RemediationReference,
    VerificationResult,
    VerificationStatus,
    build_drift_finding,
    build_verification_record,
    sla_deadline,
)
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "remediate-container-escape-k8s"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset({"detect-container-escape-k8s"})

DEFAULT_DENY_NAMESPACES = (
    "kube-system",
    "kube-public",
    "istio-system",
    "linkerd",
    "linkerd-",
)

SUPPORTED_WORKLOAD_TYPES = frozenset(
    {
        "pods",
        "deployments",
        "daemonsets",
        "statefulsets",
        "replicasets",
        "replicationcontrollers",
        "jobs",
        "cronjobs",
    }
)

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_APPLY_QUARANTINE = "apply_quarantine_network_policy"
STEP_KILL_POD = "kill_target_pod"
STEP_DRAIN_NODE = "cordon_and_drain_node"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_DENY_LIST = "skipped_deny_list"
STATUS_WOULD_VIOLATE_DENY_LIST = "would-violate-deny-list"
STATUS_SKIPPED_UNSUPPORTED_TARGET = "skipped_unsupported_target"
STATUS_SKIPPED_CLUSTER_BOUNDARY = "skipped_cluster_boundary"

ACTION_QUARANTINE = "quarantine"
ACTION_POD_KILL = "pod-kill"
ACTION_NODE_DRAIN = "node-drain"
DESTRUCTIVE_ACTIONS = frozenset({ACTION_POD_KILL, ACTION_NODE_DRAIN})


@dataclasses.dataclass(frozen=True)
class Target:
    namespace: str
    resource_type: str
    resource_name: str
    pod_name: str
    producer_skill: str
    finding_uid: str


@dataclasses.dataclass(frozen=True)
class ResolvedTarget:
    target: Target
    selector: dict[str, str]
    policy_name: str
    manifest: dict[str, Any]
    effective_pod_name: str
    node_name: str


class KubernetesClient(Protocol):
    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str] | None: ...
    def get_pod_node_name(self, namespace: str, pod_name: str) -> str | None: ...
    def get_workload_selector(
        self, namespace: str, resource_type: str, resource_name: str
    ) -> dict[str, str] | None: ...
    def apply_network_policy(self, namespace: str, manifest: dict[str, Any]) -> None: ...
    def get_network_policy(self, namespace: str, name: str) -> dict[str, Any] | None: ...
    def get_pod(self, namespace: str, pod_name: str) -> dict[str, Any] | None: ...
    def delete_pod(self, namespace: str, pod_name: str) -> None: ...
    def list_pods_on_node(self, node_name: str) -> list[dict[str, Any]]: ...
    def cordon_node(self, node_name: str) -> None: ...
    def evict_pod(self, namespace: str, pod_name: str) -> None: ...
    def get_node(self, node_name: str) -> dict[str, Any] | None: ...


class AuditWriter(Protocol):
    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
        policy_name: str,
        action_mode: str,
        secondary_approver: str = "",
    ) -> dict[str, str]: ...


@dataclasses.dataclass
class KubernetesApiClient:
    """Real Kubernetes client. Imported lazily so tests can use stubs."""

    def _apis(self) -> tuple[Any, Any, Any, Any]:
        from kubernetes import client  # local import
        from kubernetes.config import load_incluster_config, load_kube_config

        try:
            load_incluster_config()
        except Exception:
            load_kube_config()
        return (
            client.CoreV1Api(),
            client.AppsV1Api(),
            client.BatchV1Api(),
            client.NetworkingV1Api(),
        )

    def get_pod_labels(self, namespace: str, pod_name: str) -> dict[str, str] | None:
        core, _, _, _ = self._apis()
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
        labels = (
            (getattr(pod.metadata, "labels", None) or {}) if getattr(pod, "metadata", None) else {}
        )
        return dict(labels) if labels else None

    def get_pod_node_name(self, namespace: str, pod_name: str) -> str | None:
        core, _, _, _ = self._apis()
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
        spec = getattr(pod, "spec", None)
        return (
            str(getattr(spec, "node_name", None) or getattr(spec, "nodeName", None) or "") or None
        )

    def get_workload_selector(
        self, namespace: str, resource_type: str, resource_name: str
    ) -> dict[str, str] | None:
        _, apps, batch, _ = self._apis()

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
            core, _, _, _ = self._apis()
            rc = core.read_namespaced_replication_controller(
                name=resource_name, namespace=namespace
            )
            return _selector(rc)
        if resource_type == "jobs":
            return _selector(batch.read_namespaced_job(name=resource_name, namespace=namespace))
        if resource_type == "cronjobs":
            return _selector(
                batch.read_namespaced_cron_job(name=resource_name, namespace=namespace)
            )
        return None

    def apply_network_policy(self, namespace: str, manifest: dict[str, Any]) -> None:
        _, _, _, net = self._apis()
        name = str((manifest.get("metadata") or {}).get("name") or "")
        try:
            net.read_namespaced_network_policy(name=name, namespace=namespace)
        except Exception:
            net.create_namespaced_network_policy(namespace=namespace, body=manifest)
            return
        net.replace_namespaced_network_policy(name=name, namespace=namespace, body=manifest)

    def get_network_policy(self, namespace: str, name: str) -> dict[str, Any] | None:
        _, _, _, net = self._apis()
        try:
            policy = net.read_namespaced_network_policy(name=name, namespace=namespace)
        except Exception:
            return None
        from kubernetes import client

        return client.ApiClient().sanitize_for_serialization(policy)

    def get_pod(self, namespace: str, pod_name: str) -> dict[str, Any] | None:
        core, _, _, _ = self._apis()
        try:
            pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
        except Exception:
            return None
        from kubernetes import client

        return client.ApiClient().sanitize_for_serialization(pod)

    def delete_pod(self, namespace: str, pod_name: str) -> None:
        core, _, _, _ = self._apis()
        core.delete_namespaced_pod(name=pod_name, namespace=namespace)

    def list_pods_on_node(self, node_name: str) -> list[dict[str, Any]]:
        core, _, _, _ = self._apis()
        pods = core.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={node_name}").items
        from kubernetes import client

        api_client = client.ApiClient()
        return [api_client.sanitize_for_serialization(pod) for pod in pods]

    def cordon_node(self, node_name: str) -> None:
        core, _, _, _ = self._apis()
        core.patch_node(name=node_name, body={"spec": {"unschedulable": True}})

    def evict_pod(self, namespace: str, pod_name: str) -> None:
        from kubernetes import client

        eviction = client.V1Eviction(
            metadata=client.V1ObjectMeta(name=pod_name, namespace=namespace)
        )
        client.PolicyV1Api().create_namespaced_pod_eviction(
            name=pod_name, namespace=namespace, body=eviction
        )

    def get_node(self, node_name: str) -> dict[str, Any] | None:
        core, _, _, _ = self._apis()
        try:
            node = core.read_node(name=node_name)
        except Exception:
            return None
        from kubernetes import client

        return client.ApiClient().sanitize_for_serialization(node)


@dataclasses.dataclass
class DualAuditWriter:
    dynamodb_table: str
    s3_bucket: str
    kms_key_arn: str

    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approver: str,
        policy_name: str,
        action_mode: str,
        secondary_approver: str = "",
    ) -> dict[str, str]:
        import boto3  # local import — tests inject a stub writer

        action_at = datetime.now(timezone.utc).isoformat()
        row_uid = _deterministic_uid(
            target.namespace, target.resource_type, target.resource_name, step, action_at
        )
        evidence_key = (
            "container-escape/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{target.namespace}/{target.resource_name}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "namespace": target.namespace,
            "resource_type": target.resource_type,
            "resource_name": target.resource_name,
            "pod_name": target.pod_name,
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
            "step": step,
            "status": status,
            "status_detail": detail,
            "incident_id": incident_id,
            "approver": approver,
            "policy_name": policy_name,
            "action_mode": action_mode,
            "action_at": action_at,
        }
        if secondary_approver:
            envelope["secondary_approver"] = secondary_approver
        body = json.dumps(envelope, separators=(",", ":"))

        boto3.client("s3").put_object(
            Bucket=self.s3_bucket,
            Key=evidence_key,
            Body=body.encode("utf-8"),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_arn,
            ContentType="application/json",
        )
        item = {
            "target_uid": {
                "S": f"{target.namespace}/{target.resource_type}/{target.resource_name}"
            },
            "action_at": {"S": action_at},
            "row_uid": {"S": row_uid},
            "step": {"S": step},
            "status": {"S": status},
            "incident_id": {"S": incident_id},
            "approver": {"S": approver},
            "namespace": {"S": target.namespace},
            "resource_type": {"S": target.resource_type},
            "resource_name": {"S": target.resource_name},
            "policy_name": {"S": policy_name},
            "action_mode": {"S": action_mode},
            "producer_skill": {"S": target.producer_skill},
            "finding_uid": {"S": target.finding_uid},
            "s3_evidence_uri": {"S": evidence_uri},
        }
        if secondary_approver:
            item["secondary_approver"] = {"S": secondary_approver}
        boto3.client("dynamodb").put_item(TableName=self.dynamodb_table, Item=item)
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"rce-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _finding_product(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _finding_uid(event: dict[str, Any]) -> str:
    return str(
        (event.get("finding_info") or {}).get("uid")
        or (event.get("metadata") or {}).get("uid")
        or ""
    )


def _observable_value(event: dict[str, Any], name: str) -> str:
    for obs in event.get("observables") or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("name") == name:
            return str(obs.get("value") or "")
    return ""


def _parse_target_string(value: str) -> tuple[str, str, str] | None:
    parts = [part for part in value.split("/") if part]
    if len(parts) < 3:
        return None
    resource_type = parts[0]
    namespace = parts[1]
    resource_name = parts[2]
    return resource_type, namespace, resource_name


def _target_from_event(event: dict[str, Any]) -> Target | None:
    producer = _finding_product(event)
    if producer not in ACCEPTED_PRODUCERS:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="wrong_source_skill",
            message=f"skipping finding from unaccepted producer `{producer or '<missing>'}`",
        )
        return None

    namespace = _observable_value(event, "namespace")
    pod_name = _observable_value(event, "pod.name")
    resource_type = _observable_value(event, "resource.type")
    resource_name = _observable_value(event, "resource.name")

    target_field = str(event.get("target") or "")
    parsed = _parse_target_string(target_field) if target_field else None
    if parsed:
        parsed_type, parsed_ns, parsed_name = parsed
        resource_type = resource_type or parsed_type
        namespace = namespace or parsed_ns
        resource_name = resource_name or parsed_name

    if pod_name:
        resource_type = resource_type or "pods"
        resource_name = resource_name or pod_name

    if not namespace or not resource_type or not resource_name:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="missing_target_context",
            message="skipping finding without enough namespace/resource context for quarantine planning",
        )
        return None

    return Target(
        namespace=namespace,
        resource_type=resource_type,
        resource_name=resource_name,
        pod_name=pod_name,
        producer_skill=producer,
        finding_uid=_finding_uid(event),
    )


def parse_targets(
    events: Iterable[dict[str, Any]],
) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_deny_namespaces() -> tuple[str, ...]:
    return DEFAULT_DENY_NAMESPACES


def load_allowed_clusters() -> tuple[str, ...]:
    raw = os.getenv("K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def is_protected_namespace(namespace: str, patterns: Iterable[str]) -> tuple[bool, str]:
    value = (namespace or "").strip().lower()
    for pattern in patterns:
        needle = pattern.lower()
        if needle.endswith("-"):
            if value.startswith(needle):
                return True, pattern
        elif value == needle:
            return True, pattern
    return False, ""


def _policy_name(
    namespace: str, resource_type: str, resource_name: str, selector: dict[str, str]
) -> str:
    material = json.dumps(selector, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(
        f"{namespace}|{resource_type}|{resource_name}|{material}".encode("utf-8")
    ).hexdigest()[:10]
    base = resource_name.lower().replace("_", "-").replace(".", "-")
    base = "".join(ch for ch in base if ch.isalnum() or ch == "-").strip("-") or "target"
    return f"ce-quarantine-{base[:35]}-{digest}"[:63].rstrip("-")


def build_network_policy(
    namespace: str, policy_name: str, selector: dict[str, str]
) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": SKILL_NAME,
                "security.company.io/quarantine": "true",
            },
        },
        "spec": {
            "podSelector": {"matchLabels": selector},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }


def _pod_node_name(kube_client: KubernetesClient, namespace: str, pod_name: str) -> str:
    # Some shared/test clients still only implement the pre-node-drain surface.
    getter = getattr(kube_client, "get_pod_node_name", None)
    if not callable(getter):
        return ""
    return str(getter(namespace, pod_name) or "")


def resolve_target(target: Target, kube_client: KubernetesClient) -> ResolvedTarget | None:
    selector: dict[str, str] | None
    effective_pod_name = target.pod_name
    node_name = ""
    if target.pod_name:
        selector = kube_client.get_pod_labels(target.namespace, target.pod_name)
        node_name = _pod_node_name(kube_client, target.namespace, target.pod_name)
    elif target.resource_type == "pods":
        selector = kube_client.get_pod_labels(target.namespace, target.resource_name)
        effective_pod_name = target.resource_name
        node_name = _pod_node_name(kube_client, target.namespace, target.resource_name)
    elif target.resource_type in SUPPORTED_WORKLOAD_TYPES:
        selector = kube_client.get_workload_selector(
            target.namespace, target.resource_type, target.resource_name
        )
    else:
        selector = None

    if not selector:
        return None

    policy_name = _policy_name(
        target.namespace, target.resource_type, target.resource_name, selector
    )
    return ResolvedTarget(
        target=target,
        selector=selector,
        policy_name=policy_name,
        manifest=build_network_policy(target.namespace, policy_name, selector),
        effective_pod_name=effective_pod_name,
        node_name=node_name,
    )


def check_apply_gate(*, action_mode: str = ACTION_QUARANTINE) -> tuple[bool, str]:
    incident_id = os.getenv("K8S_CONTAINER_ESCAPE_INCIDENT_ID", "").strip()
    approver = os.getenv("K8S_CONTAINER_ESCAPE_APPROVER", "").strip()
    cluster_name = os.getenv("K8S_CLUSTER_NAME", "").strip()
    allowed_clusters = load_allowed_clusters()
    if not incident_id:
        return False, "K8S_CONTAINER_ESCAPE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "K8S_CONTAINER_ESCAPE_APPROVER is required for --apply"
    if not cluster_name:
        return False, "K8S_CLUSTER_NAME is required for --apply"
    if not allowed_clusters:
        return False, "K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS is required for --apply"
    if cluster_name not in allowed_clusters:
        return False, (
            f"K8S_CLUSTER_NAME `{cluster_name}` is not listed in "
            "K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS"
        )
    if action_mode == ACTION_NODE_DRAIN:
        second = os.getenv("K8S_CONTAINER_ESCAPE_SECOND_APPROVER", "").strip()
        if not second:
            return (
                False,
                "K8S_CONTAINER_ESCAPE_SECOND_APPROVER is required for --approve-node-drain",
            )
        if second == approver:
            return (
                False,
                "K8S_CONTAINER_ESCAPE_SECOND_APPROVER must differ from K8S_CONTAINER_ESCAPE_APPROVER",
            )
    return True, ""


def _policy_endpoint(namespace: str, name: str) -> str:
    return f"UPSERT /apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/{name}"


def _pod_delete_endpoint(namespace: str, pod_name: str) -> str:
    return f"DELETE /api/v1/namespaces/{namespace}/pods/{pod_name}"


def _node_drain_endpoint(node_name: str) -> str:
    return f"PATCH /api/v1/nodes/{node_name} unschedulable=true + EVICT pods on node"


def _verification_endpoint(namespace: str, name: str) -> str:
    return f"GET /apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/{name}"


def _action_step(action_mode: str) -> str:
    if action_mode == ACTION_POD_KILL:
        return STEP_KILL_POD
    if action_mode == ACTION_NODE_DRAIN:
        return STEP_DRAIN_NODE
    return STEP_APPLY_QUARANTINE


def _action_endpoint(resolved: ResolvedTarget, action_mode: str) -> str:
    if action_mode == ACTION_POD_KILL:
        return _pod_delete_endpoint(resolved.target.namespace, resolved.effective_pod_name)
    if action_mode == ACTION_NODE_DRAIN:
        return _node_drain_endpoint(resolved.node_name)
    return _policy_endpoint(resolved.target.namespace, resolved.policy_name)


def _planned_detail(action_mode: str) -> str:
    if action_mode == ACTION_POD_KILL:
        return "dry-run: would delete the targeted pod after explicit HITL approval"
    if action_mode == ACTION_NODE_DRAIN:
        return "dry-run: would cordon the node and evict non-protected pods after dual approval"
    return "dry-run: would apply quarantine NetworkPolicy"


def _plan_record(
    resolved: ResolvedTarget,
    *,
    status: str,
    detail: str | None,
    dry_run: bool,
    action_mode: str = ACTION_QUARANTINE,
) -> dict[str, Any]:
    record = {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Kubernetes",
            "namespace": resolved.target.namespace,
            "resource_type": resolved.target.resource_type,
            "resource_name": resolved.target.resource_name,
            "pod_name": resolved.target.pod_name,
        },
        "action_mode": action_mode,
        "policy_name": resolved.policy_name,
        "selector": resolved.selector,
        "actions": [
            {
                "step": _action_step(action_mode),
                "endpoint": _action_endpoint(resolved, action_mode),
                "status": status,
                "detail": detail,
            }
        ],
        "status": status,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": resolved.target.finding_uid,
    }
    if action_mode == ACTION_QUARANTINE:
        record["manifest"] = resolved.manifest
    if resolved.effective_pod_name:
        record["effective_pod_name"] = resolved.effective_pod_name
    if resolved.node_name:
        record["node_name"] = resolved.node_name
    return record


def _skip_record(target: Target, *, status: str, detail: str, dry_run: bool) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
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
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


_VERIFY_STATUS_TO_CONTRACT = {
    STATUS_VERIFIED: VerificationStatus.VERIFIED,
    STATUS_DRIFT: VerificationStatus.DRIFT,
}


def _build_verification_outputs(
    resolved: ResolvedTarget,
    *,
    status: str,
    detail: str,
    expected_state: str,
    actual_state: str,
    remediated_at_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Translate a reverify outcome into the shared `_shared.remediation_verifier`
    contract. Emits one verification record always; on DRIFT also emits an OCSF
    1.8 Detection Finding so SIEM/SOAR picks it up via the same pipeline as
    every other finding.

    `remediated_at_ms` may be None when the verifier doesn't have access to the
    audit row (current code path); we use the verification time as the proxy and
    note within_sla=True. A future PR can wire DynamoDB lookup to populate this.
    """
    contract_status = _VERIFY_STATUS_TO_CONTRACT.get(status, VerificationStatus.UNREACHABLE)
    checked_at_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    remediated_at_ms = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=resolved.policy_name,
        target_provider="Kubernetes",
        target_identifier=(
            f"{resolved.target.namespace}/{resolved.target.resource_type}/{resolved.target.resource_name}"
        ),
        original_finding_uid=resolved.target.finding_uid,
        remediated_at_ms=remediated_at_ms,
    )
    result = VerificationResult(
        status=contract_status,
        checked_at_ms=checked_at_ms,
        sla_deadline_ms=sla_deadline(remediated_at_ms, DEFAULT_VERIFICATION_SLA_MS),
        expected_state=expected_state,
        actual_state=actual_state,
        detail=detail,
    )

    record = build_verification_record(
        reference=reference,
        result=result,
        verifier_skill=SKILL_NAME,
    )
    # Preserve skill-specific context that the shared contract doesn't model
    record["policy_name"] = resolved.policy_name
    record["selector"] = resolved.selector
    record["endpoint"] = _verification_endpoint(resolved.target.namespace, resolved.policy_name)
    # Preserve the legacy fields tests assert on, to keep drop-in compatibility
    record.setdefault("status_detail", detail)
    record["time_ms"] = checked_at_ms
    record["finding_uid"] = resolved.target.finding_uid
    record["target"] = {
        "provider": "Kubernetes",
        "namespace": resolved.target.namespace,
        "resource_type": resolved.target.resource_type,
        "resource_name": resolved.target.resource_name,
        "pod_name": resolved.target.pod_name,
    }

    outputs = [record]
    if contract_status == VerificationStatus.DRIFT:
        outputs.append(
            build_drift_finding(
                reference=reference,
                result=result,
                verifier_skill=SKILL_NAME,
            )
        )
    return outputs


def _verification_record(resolved: ResolvedTarget, *, status: str, detail: str) -> dict[str, Any]:
    """Back-compat single-record helper retained for tests that imported it
    directly. New code paths use `_build_verification_outputs` to also emit
    the drift finding when applicable."""
    expected = "quarantine NetworkPolicy present and matching expected selector + deny-all shape"
    actual = (
        "missing or modified" if status == STATUS_DRIFT else "present and matching expected shape"
    )
    return _build_verification_outputs(
        resolved,
        status=status,
        detail=detail,
        expected_state=expected,
        actual_state=actual,
    )[0]


def apply_quarantine(
    resolved: ResolvedTarget,
    *,
    kube_client: KubernetesClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
    secondary_approver: str = "",
) -> dict[str, Any]:
    first_audit = audit.record(
        target=resolved.target,
        step=STEP_APPLY_QUARANTINE,
        status=STATUS_IN_PROGRESS,
        detail="about to apply quarantine NetworkPolicy",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
        action_mode=ACTION_QUARANTINE,
        secondary_approver=secondary_approver,
    )
    try:
        kube_client.apply_network_policy(resolved.target.namespace, resolved.manifest)
    except Exception as exc:
        audit.record(
            target=resolved.target,
            step=STEP_APPLY_QUARANTINE,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
            policy_name=resolved.policy_name,
            action_mode=ACTION_QUARANTINE,
            secondary_approver=secondary_approver,
        )
        record = _plan_record(
            resolved,
            status=STATUS_FAILURE,
            detail=str(exc),
            dry_run=False,
            action_mode=ACTION_QUARANTINE,
        )
        record["audit"] = first_audit
        return record

    second_audit = audit.record(
        target=resolved.target,
        step=STEP_APPLY_QUARANTINE,
        status=STATUS_SUCCESS,
        detail="quarantine NetworkPolicy applied",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
        action_mode=ACTION_QUARANTINE,
        secondary_approver=secondary_approver,
    )
    record = _plan_record(
        resolved,
        status=STATUS_SUCCESS,
        detail="quarantine NetworkPolicy applied",
        dry_run=False,
        action_mode=ACTION_QUARANTINE,
    )
    record["audit"] = second_audit
    record["incident_id"] = incident_id
    record["approver"] = approver
    if secondary_approver:
        record["secondary_approver"] = secondary_approver
    return record


def _node_pods_violate_deny_list(
    node_pods: Iterable[dict[str, Any]],
    deny_namespaces: Iterable[str],
) -> tuple[bool, str]:
    for pod in node_pods:
        metadata = pod.get("metadata") or {}
        namespace = str(metadata.get("namespace") or "")
        name = str(metadata.get("name") or "")
        denied, matched = is_protected_namespace(namespace, deny_namespaces)
        if denied:
            return (
                True,
                f"node drain would touch protected pod `{namespace}/{name}` matched `{matched}`",
            )
    return False, ""


def apply_pod_kill(
    resolved: ResolvedTarget,
    *,
    kube_client: KubernetesClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
) -> dict[str, Any]:
    first_audit = audit.record(
        target=resolved.target,
        step=STEP_KILL_POD,
        status=STATUS_IN_PROGRESS,
        detail=f"about to delete pod `{resolved.effective_pod_name}`",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
        action_mode=ACTION_POD_KILL,
    )
    try:
        kube_client.delete_pod(resolved.target.namespace, resolved.effective_pod_name)
    except Exception as exc:
        audit.record(
            target=resolved.target,
            step=STEP_KILL_POD,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
            policy_name=resolved.policy_name,
            action_mode=ACTION_POD_KILL,
        )
        record = _plan_record(
            resolved,
            status=STATUS_FAILURE,
            detail=str(exc),
            dry_run=False,
            action_mode=ACTION_POD_KILL,
        )
        record["audit"] = first_audit
        return record

    second_audit = audit.record(
        target=resolved.target,
        step=STEP_KILL_POD,
        status=STATUS_SUCCESS,
        detail=f"deleted pod `{resolved.effective_pod_name}`",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
        action_mode=ACTION_POD_KILL,
    )
    record = _plan_record(
        resolved,
        status=STATUS_SUCCESS,
        detail=f"deleted pod `{resolved.effective_pod_name}`",
        dry_run=False,
        action_mode=ACTION_POD_KILL,
    )
    record["audit"] = second_audit
    record["incident_id"] = incident_id
    record["approver"] = approver
    return record


def apply_node_drain(
    resolved: ResolvedTarget,
    *,
    kube_client: KubernetesClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
    secondary_approver: str,
    deny_namespaces: Iterable[str],
) -> dict[str, Any]:
    node_pods = kube_client.list_pods_on_node(resolved.node_name)
    violates, detail = _node_pods_violate_deny_list(node_pods, deny_namespaces)
    if violates:
        record = _plan_record(
            resolved,
            status=STATUS_SKIPPED_DENY_LIST,
            detail=detail,
            dry_run=False,
            action_mode=ACTION_NODE_DRAIN,
        )
        record["incident_id"] = incident_id
        record["approver"] = approver
        record["secondary_approver"] = secondary_approver
        return record

    first_audit = audit.record(
        target=resolved.target,
        step=STEP_DRAIN_NODE,
        status=STATUS_IN_PROGRESS,
        detail=f"about to cordon node `{resolved.node_name}` and evict pods",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
        action_mode=ACTION_NODE_DRAIN,
        secondary_approver=secondary_approver,
    )
    try:
        kube_client.cordon_node(resolved.node_name)
        drained_pods: list[str] = []
        for pod in node_pods:
            metadata = pod.get("metadata") or {}
            namespace = str(metadata.get("namespace") or "")
            name = str(metadata.get("name") or "")
            if not namespace or not name:
                continue
            kube_client.evict_pod(namespace, name)
            drained_pods.append(f"{namespace}/{name}")
    except Exception as exc:
        audit.record(
            target=resolved.target,
            step=STEP_DRAIN_NODE,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
            policy_name=resolved.policy_name,
            action_mode=ACTION_NODE_DRAIN,
            secondary_approver=secondary_approver,
        )
        record = _plan_record(
            resolved,
            status=STATUS_FAILURE,
            detail=str(exc),
            dry_run=False,
            action_mode=ACTION_NODE_DRAIN,
        )
        record["audit"] = first_audit
        return record

    second_audit = audit.record(
        target=resolved.target,
        step=STEP_DRAIN_NODE,
        status=STATUS_SUCCESS,
        detail=f"cordoned node `{resolved.node_name}` and evicted {len(drained_pods)} pod(s)",
        incident_id=incident_id,
        approver=approver,
        policy_name=resolved.policy_name,
        action_mode=ACTION_NODE_DRAIN,
        secondary_approver=secondary_approver,
    )
    record = _plan_record(
        resolved,
        status=STATUS_SUCCESS,
        detail=f"cordoned node `{resolved.node_name}` and evicted {len(drained_pods)} pod(s)",
        dry_run=False,
        action_mode=ACTION_NODE_DRAIN,
    )
    record["audit"] = second_audit
    record["incident_id"] = incident_id
    record["approver"] = approver
    record["secondary_approver"] = secondary_approver
    record["drained_pods"] = drained_pods
    return record


def reverify_quarantine(
    resolved: ResolvedTarget, *, kube_client: KubernetesClient
) -> list[dict[str, Any]]:
    """Re-verify the quarantine NetworkPolicy. Returns a list of records:
    always one `remediation_verification` record, plus an OCSF Detection
    Finding (`finding_types: ["remediation-drift"]`) when status is DRIFT.

    Tests asserting on the verification record itself can use ``[0]``;
    pipelines should iterate the full list and emit each."""
    expected = "quarantine NetworkPolicy present, podSelector matches, deny-all (no ingress/egress, both policyTypes)"
    try:
        policy = kube_client.get_network_policy(resolved.target.namespace, resolved.policy_name)
    except Exception as exc:
        # Surface unreachability via the shared contract so it never silently
        # downgrades to VERIFIED. We piggy-back on _build_verification_outputs
        # by passing a non-mapped status — the contract maps it to UNREACHABLE.
        return _build_verification_outputs(
            resolved,
            status="unreachable",
            detail=f"kubernetes API unreachable: {exc}",
            expected_state=expected,
            actual_state="api call raised; cannot determine state",
        )

    if not policy:
        return _build_verification_outputs(
            resolved,
            status=STATUS_DRIFT,
            detail="quarantine NetworkPolicy not found",
            expected_state=expected,
            actual_state="NetworkPolicy missing from cluster",
        )

    actual_selector = ((policy.get("spec") or {}).get("podSelector") or {}).get("matchLabels") or {}
    ingress = (policy.get("spec") or {}).get("ingress")
    egress = (policy.get("spec") or {}).get("egress")
    policy_types = tuple((policy.get("spec") or {}).get("policyTypes") or [])
    if (
        actual_selector != resolved.selector
        or ingress != []
        or egress != []
        or set(policy_types) != {"Ingress", "Egress"}
    ):
        return _build_verification_outputs(
            resolved,
            status=STATUS_DRIFT,
            detail="quarantine NetworkPolicy drifted from expected selector or deny-all shape",
            expected_state=expected,
            actual_state=(
                f"selector={actual_selector} ingress={ingress} egress={egress} policyTypes={list(policy_types)}"
            ),
        )
    return _build_verification_outputs(
        resolved,
        status=STATUS_VERIFIED,
        detail="quarantine NetworkPolicy still present",
        expected_state=expected,
        actual_state="NetworkPolicy present and matching expected shape",
    )


def reverify_pod_kill(
    resolved: ResolvedTarget, *, kube_client: KubernetesClient
) -> list[dict[str, Any]]:
    pod = kube_client.get_pod(resolved.target.namespace, resolved.effective_pod_name)
    expected = f"pod `{resolved.effective_pod_name}` absent after approved kill"
    if pod is not None:
        return _build_verification_outputs(
            resolved,
            status=STATUS_DRIFT,
            detail="target pod still present after approved kill",
            expected_state=expected,
            actual_state="pod still exists in cluster",
        )
    return _build_verification_outputs(
        resolved,
        status=STATUS_VERIFIED,
        detail="target pod remains absent after approved kill",
        expected_state=expected,
        actual_state="pod no longer present",
    )


def reverify_node_drain(
    resolved: ResolvedTarget, *, kube_client: KubernetesClient
) -> list[dict[str, Any]]:
    node = kube_client.get_node(resolved.node_name)
    pod = kube_client.get_pod(resolved.target.namespace, resolved.effective_pod_name)
    node_unschedulable = (
        bool(((node or {}).get("spec") or {}).get("unschedulable")) if node else False
    )
    expected = (
        f"node `{resolved.node_name}` cordoned and pod `{resolved.effective_pod_name}` absent"
    )
    if not node_unschedulable or pod is not None:
        actual = f"node_unschedulable={node_unschedulable} pod_present={pod is not None}"
        return _build_verification_outputs(
            resolved,
            status=STATUS_DRIFT,
            detail="node drain no longer holds expected cordon/absence state",
            expected_state=expected,
            actual_state=actual,
        )
    return _build_verification_outputs(
        resolved,
        status=STATUS_VERIFIED,
        detail="node remains cordoned and target pod is absent",
        expected_state=expected,
        actual_state="node unschedulable and target pod absent",
    )


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}",
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="invalid_json_shape",
                message=f"skipping line {lineno}: not a JSON object",
                line=lineno,
            )


def run(
    events: Iterable[dict[str, Any]],
    *,
    kube_client: KubernetesClient,
    apply: bool = False,
    reverify: bool = False,
    action_mode: str = ACTION_QUARANTINE,
    audit: AuditWriter | None = None,
    deny_namespaces: Iterable[str] = DEFAULT_DENY_NAMESPACES,
    incident_id: str = "",
    approver: str = "",
    secondary_approver: str = "",
    cluster_name: str = "",
    allowed_clusters: Iterable[str] = (),
) -> Iterator[dict[str, Any]]:
    allowed_clusters = tuple(allowed_clusters)
    for target, _ in parse_targets(events):
        if target is None:
            continue

        denied, matched = is_protected_namespace(target.namespace, deny_namespaces)
        if denied:
            status = STATUS_SKIPPED_DENY_LIST if apply else STATUS_WOULD_VIOLATE_DENY_LIST
            yield _skip_record(
                target,
                status=status,
                detail=f"namespace `{target.namespace}` matched protected pattern `{matched}`",
                dry_run=not apply and not reverify,
            )
            continue

        if apply and not cluster_name:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_CLUSTER_BOUNDARY,
                detail="K8S_CLUSTER_NAME is required for --apply",
                dry_run=False,
            )
            continue

        if apply and cluster_name not in allowed_clusters:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_CLUSTER_BOUNDARY,
                detail=(
                    f"cluster `{cluster_name}` is not listed in "
                    "K8S_CONTAINER_ESCAPE_ALLOWED_CLUSTERS"
                ),
                dry_run=False,
            )
            continue

        resolved = resolve_target(target, kube_client)
        if resolved is None:
            dry_run = not apply and not reverify
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_UNSUPPORTED_TARGET,
                detail="could not resolve a pod or workload selector for quarantine planning",
                dry_run=dry_run,
            )
            continue

        if action_mode in DESTRUCTIVE_ACTIONS and not resolved.effective_pod_name:
            dry_run = not apply and not reverify
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_UNSUPPORTED_TARGET,
                detail="destructive response requires an explicit pod target (`pod.name`) from the detector",
                dry_run=dry_run,
            )
            continue

        if action_mode == ACTION_NODE_DRAIN:
            if not resolved.node_name:
                dry_run = not apply and not reverify
                yield _skip_record(
                    target,
                    status=STATUS_SKIPPED_UNSUPPORTED_TARGET,
                    detail="could not resolve node name for drain planning",
                    dry_run=dry_run,
                )
                continue
            node_pods = kube_client.list_pods_on_node(resolved.node_name)
            violates, detail = _node_pods_violate_deny_list(node_pods, deny_namespaces)
            if violates:
                status = STATUS_SKIPPED_DENY_LIST if apply else STATUS_WOULD_VIOLATE_DENY_LIST
                yield _plan_record(
                    resolved,
                    status=status,
                    detail=detail,
                    dry_run=not apply and not reverify,
                    action_mode=action_mode,
                )
                continue

        if reverify:
            if action_mode == ACTION_POD_KILL:
                yield from reverify_pod_kill(resolved, kube_client=kube_client)
            elif action_mode == ACTION_NODE_DRAIN:
                yield from reverify_node_drain(resolved, kube_client=kube_client)
            else:
                yield from reverify_quarantine(resolved, kube_client=kube_client)
            continue

        if not apply:
            yield _plan_record(
                resolved,
                status=STATUS_PLANNED,
                detail=_planned_detail(action_mode),
                dry_run=True,
                action_mode=action_mode,
            )
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        if action_mode == ACTION_POD_KILL:
            yield apply_pod_kill(
                resolved,
                kube_client=kube_client,
                audit=audit,
                incident_id=incident_id,
                approver=approver,
            )
        elif action_mode == ACTION_NODE_DRAIN:
            yield apply_node_drain(
                resolved,
                kube_client=kube_client,
                audit=audit,
                incident_id=incident_id,
                approver=approver,
                secondary_approver=secondary_approver,
                deny_namespaces=deny_namespaces,
            )
        else:
            yield apply_quarantine(
                resolved,
                kube_client=kube_client,
                audit=audit,
                incident_id=incident_id,
                approver=approver,
                secondary_approver=secondary_approver,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify Kubernetes container-escape quarantine NetworkPolicies."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the quarantine NetworkPolicy after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm the quarantine NetworkPolicy is still present.",
    )
    parser.add_argument(
        "--approve-pod-kill",
        action="store_true",
        help="Plan or apply the explicit destructive pod-delete path.",
    )
    parser.add_argument(
        "--approve-node-drain",
        action="store_true",
        help="Plan or apply the explicit destructive node-drain path.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2
    if args.approve_pod_kill and args.approve_node_drain:
        print("--approve-pod-kill and --approve-node-drain are mutually exclusive", file=sys.stderr)
        return 2

    action_mode = ACTION_QUARANTINE
    if args.approve_pod_kill:
        action_mode = ACTION_POD_KILL
    elif args.approve_node_drain:
        action_mode = ACTION_NODE_DRAIN

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        kube_client = KubernetesApiClient()
        audit: AuditWriter | None = None
        incident_id = ""
        approver = ""
        secondary_approver = ""
        if args.apply:
            ok, reason = check_apply_gate(action_mode=action_mode)
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.getenv("K8S_CONTAINER_ESCAPE_INCIDENT_ID", "").strip()
            approver = os.getenv("K8S_CONTAINER_ESCAPE_APPROVER", "").strip()
            secondary_approver = os.getenv("K8S_CONTAINER_ESCAPE_SECOND_APPROVER", "").strip()
            audit = DualAuditWriter(
                dynamodb_table=os.environ["K8S_REMEDIATION_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["K8S_REMEDIATION_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )

        for record in run(
            load_jsonl(in_stream),
            kube_client=kube_client,
            apply=args.apply,
            reverify=args.reverify,
            action_mode=action_mode,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
            secondary_approver=secondary_approver,
            cluster_name=os.getenv("K8S_CLUSTER_NAME", "").strip(),
            allowed_clusters=load_allowed_clusters(),
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
