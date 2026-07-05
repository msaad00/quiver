"""Revoke a Kubernetes RoleBinding or ClusterRoleBinding flagged by an RBAC self-grant finding.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-privilege-escalation-k8s. Plans (dry-run default), applies (--apply),
or re-verifies (--reverify) deletion of the offending RoleBinding or
ClusterRoleBinding identified by the detector's `binding.type` + `binding.name`
observables.

Scope honesty:
- Only rule `r3-rbac-self-grant` from detect-privilege-escalation-k8s carries
  an unambiguous `binding.type` + `binding.name` pointer. For findings without
  that pointer (rules r1/r2/r4 of privilege-escalation, and every finding from
  detect-sensitive-secret-read-k8s), this skill emits a `skipped_no_binding`
  record and tells the operator to triage manually. Discovery mode (list
  bindings for an actor across the cluster) is intentionally out of scope for
  this PR — it adds a large API surface and needs its own design pass.

Guardrails enforced in code:
- source-skill check rejects findings from any non-privilege-escalation producer
- protected namespace deny-list: kube-system, kube-public, istio-system, linkerd*
- protected binding name patterns: any binding starting with `system:` is denied
  (system:masters, system:basic-user, etc.) so the skill cannot revoke
  cluster-bootstrap bindings
- --apply requires K8S_RBAC_REVOKE_INCIDENT_ID + K8S_RBAC_REVOKE_APPROVER
- dual-audit write (DynamoDB + KMS-encrypted S3) BEFORE and AFTER each delete
- --reverify checks that the binding is no longer present
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

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "remediate-k8s-rbac-revoke"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset({"detect-privilege-escalation-k8s"})

DEFAULT_DENY_NAMESPACES = (
    "kube-system",
    "kube-public",
    "istio-system",
    "linkerd",
    "linkerd-",
)

DEFAULT_DENY_BINDING_PREFIXES = ("system:",)

SUPPORTED_BINDING_TYPES = frozenset({"rolebindings", "clusterrolebindings"})

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_REVOKE_BINDING = "revoke_rbac_binding"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_DENY_LIST = "skipped_deny_list"
STATUS_WOULD_VIOLATE_DENY_LIST = "would-violate-deny-list"
STATUS_SKIPPED_PROTECTED_BINDING = "skipped_protected_binding"
STATUS_WOULD_VIOLATE_PROTECTED_BINDING = "would-violate-protected-binding"
STATUS_SKIPPED_NO_BINDING = "skipped_no_binding_pointer"
STATUS_SKIPPED_UNSUPPORTED_TYPE = "skipped_unsupported_binding_type"
STATUS_SKIPPED_CLUSTER_BOUNDARY = "skipped_cluster_boundary"


@dataclasses.dataclass(frozen=True)
class Target:
    binding_type: str  # "rolebindings" or "clusterrolebindings"
    binding_name: str
    namespace: str  # empty for ClusterRoleBindings (cluster-scoped)
    actor: str
    producer_skill: str
    finding_uid: str
    rule: str


class KubernetesClient(Protocol):
    def get_role_binding(self, namespace: str, name: str) -> dict[str, Any] | None: ...
    def get_cluster_role_binding(self, name: str) -> dict[str, Any] | None: ...
    def delete_role_binding(self, namespace: str, name: str) -> None: ...
    def delete_cluster_role_binding(self, name: str) -> None: ...


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
    ) -> dict[str, str]: ...


@dataclasses.dataclass
class KubernetesRbacClient:
    """Real Kubernetes RBAC client. Imported lazily so tests can use stubs."""

    def _api(self) -> Any:
        from kubernetes import client  # local import
        from kubernetes.config import load_incluster_config, load_kube_config

        try:
            load_incluster_config()
        except Exception:
            load_kube_config()
        return client.RbacAuthorizationV1Api()

    def _serialize(self, obj: Any) -> dict[str, Any]:
        from kubernetes import client

        return client.ApiClient().sanitize_for_serialization(obj)

    def get_role_binding(self, namespace: str, name: str) -> dict[str, Any] | None:
        try:
            obj = self._api().read_namespaced_role_binding(name=name, namespace=namespace)
        except Exception:
            return None
        return self._serialize(obj)

    def get_cluster_role_binding(self, name: str) -> dict[str, Any] | None:
        try:
            obj = self._api().read_cluster_role_binding(name=name)
        except Exception:
            return None
        return self._serialize(obj)

    def delete_role_binding(self, namespace: str, name: str) -> None:
        self._api().delete_namespaced_role_binding(name=name, namespace=namespace)

    def delete_cluster_role_binding(self, name: str) -> None:
        self._api().delete_cluster_role_binding(name=name)


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
    ) -> dict[str, str]:
        import boto3  # local import — tests inject a stub writer

        action_at = datetime.now(timezone.utc).isoformat()
        target_uid = _target_uid(target)
        row_uid = _deterministic_uid(target_uid, step, action_at)
        evidence_key = (
            "k8s-rbac-revoke/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{target.binding_type}/{target.namespace or '_cluster'}/"
            f"{target.binding_name}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "binding_type": target.binding_type,
            "binding_name": target.binding_name,
            "namespace": target.namespace,
            "actor": target.actor,
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
            "rule": target.rule,
            "step": step,
            "status": status,
            "status_detail": detail,
            "incident_id": incident_id,
            "approver": approver,
            "action_at": action_at,
        }
        body = json.dumps(envelope, separators=(",", ":"))

        boto3.client("s3").put_object(
            Bucket=self.s3_bucket,
            Key=evidence_key,
            Body=body.encode("utf-8"),
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=self.kms_key_arn,
            ContentType="application/json",
        )
        boto3.client("dynamodb").put_item(
            TableName=self.dynamodb_table,
            Item={
                "target_uid": {"S": target_uid},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "binding_type": {"S": target.binding_type},
                "binding_name": {"S": target.binding_name},
                "namespace": {"S": target.namespace},
                "actor": {"S": target.actor},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "rule": {"S": target.rule},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"rbac-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _target_uid(target: Target) -> str:
    scope = target.namespace if target.binding_type == "rolebindings" else "_cluster"
    return f"{target.binding_type}/{scope}/{target.binding_name}"


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

    binding_type = _observable_value(event, "binding.type")
    binding_name = _observable_value(event, "binding.name")
    namespace = _observable_value(event, "namespace")
    actor = _observable_value(event, "actor.name")
    rule = _observable_value(event, "rule")

    if not binding_type or not binding_name:
        # Detector did not identify a specific binding (rule != r3-rbac-self-grant).
        # Build a placeholder Target that still carries actor + rule context so the
        # caller can emit a clean skip record without losing observability.
        return Target(
            binding_type="",
            binding_name="",
            namespace=namespace,
            actor=actor,
            producer_skill=producer,
            finding_uid=_finding_uid(event),
            rule=rule,
        )

    return Target(
        binding_type=binding_type,
        binding_name=binding_name,
        namespace=namespace,
        actor=actor,
        producer_skill=producer,
        finding_uid=_finding_uid(event),
        rule=rule,
    )


def parse_targets(
    events: Iterable[dict[str, Any]],
) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_deny_namespaces() -> tuple[str, ...]:
    return DEFAULT_DENY_NAMESPACES


def load_protected_binding_prefixes() -> tuple[str, ...]:
    return DEFAULT_DENY_BINDING_PREFIXES


def load_allowed_clusters() -> tuple[str, ...]:
    raw = os.getenv("K8S_RBAC_REVOKE_ALLOWED_CLUSTERS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def is_protected_namespace(namespace: str, patterns: Iterable[str]) -> tuple[bool, str]:
    value = (namespace or "").strip().lower()
    if not value:
        return False, ""
    for pattern in patterns:
        needle = pattern.lower()
        if needle.endswith("-"):
            if value.startswith(needle):
                return True, pattern
        elif value == needle:
            return True, pattern
    return False, ""


def is_protected_binding(name: str, prefixes: Iterable[str]) -> tuple[bool, str]:
    value = (name or "").strip().lower()
    if not value:
        return False, ""
    for prefix in prefixes:
        needle = prefix.lower()
        if value.startswith(needle):
            return True, prefix
    return False, ""


def _delete_endpoint(target: Target) -> str:
    if target.binding_type == "clusterrolebindings":
        return (
            f"DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{target.binding_name}"
        )
    return (
        f"DELETE /apis/rbac.authorization.k8s.io/v1/namespaces/"
        f"{target.namespace}/rolebindings/{target.binding_name}"
    )


def _verify_endpoint(target: Target) -> str:
    if target.binding_type == "clusterrolebindings":
        return f"GET /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{target.binding_name}"
    return (
        f"GET /apis/rbac.authorization.k8s.io/v1/namespaces/"
        f"{target.namespace}/rolebindings/{target.binding_name}"
    )


def _plan_record(
    target: Target, *, status: str, detail: str | None, dry_run: bool
) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Kubernetes",
            "binding_type": target.binding_type,
            "binding_name": target.binding_name,
            "namespace": target.namespace,
            "actor": target.actor,
            "rule": target.rule,
        },
        "actions": [
            {
                "step": STEP_REVOKE_BINDING,
                "endpoint": _delete_endpoint(target),
                "status": status,
                "detail": detail,
            }
        ],
        "status": status,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def _skip_record(target: Target, *, status: str, detail: str, dry_run: bool) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Kubernetes",
            "binding_type": target.binding_type,
            "binding_name": target.binding_name,
            "namespace": target.namespace,
            "actor": target.actor,
            "rule": target.rule,
        },
        "actions": [],
        "status": status,
        "status_detail": detail,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def _verification_record(target: Target, *, status: str, detail: str) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_VERIFICATION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "Kubernetes",
            "binding_type": target.binding_type,
            "binding_name": target.binding_name,
            "namespace": target.namespace,
            "actor": target.actor,
            "rule": target.rule,
        },
        "endpoint": _verify_endpoint(target),
        "status": status,
        "status_detail": detail,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("K8S_RBAC_REVOKE_INCIDENT_ID", "").strip()
    approver = os.getenv("K8S_RBAC_REVOKE_APPROVER", "").strip()
    cluster_name = os.getenv("K8S_CLUSTER_NAME", "").strip()
    allowed_clusters = load_allowed_clusters()
    if not incident_id:
        return False, "K8S_RBAC_REVOKE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "K8S_RBAC_REVOKE_APPROVER is required for --apply"
    if not cluster_name:
        return False, "K8S_CLUSTER_NAME is required for --apply"
    if not allowed_clusters:
        return False, "K8S_RBAC_REVOKE_ALLOWED_CLUSTERS is required for --apply"
    if cluster_name not in allowed_clusters:
        return (
            False,
            f"K8S_CLUSTER_NAME `{cluster_name}` is not listed in K8S_RBAC_REVOKE_ALLOWED_CLUSTERS",
        )
    return True, ""


def revoke_binding(
    target: Target,
    *,
    kube_client: KubernetesClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
) -> dict[str, Any]:
    first_audit = audit.record(
        target=target,
        step=STEP_REVOKE_BINDING,
        status=STATUS_IN_PROGRESS,
        detail=f"about to delete {target.binding_type}/{target.binding_name}",
        incident_id=incident_id,
        approver=approver,
    )
    try:
        if target.binding_type == "clusterrolebindings":
            kube_client.delete_cluster_role_binding(target.binding_name)
        else:
            kube_client.delete_role_binding(target.namespace, target.binding_name)
    except Exception as exc:
        audit.record(
            target=target,
            step=STEP_REVOKE_BINDING,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
        )
        record = _plan_record(target, status=STATUS_FAILURE, detail=str(exc), dry_run=False)
        record["audit"] = first_audit
        return record

    second_audit = audit.record(
        target=target,
        step=STEP_REVOKE_BINDING,
        status=STATUS_SUCCESS,
        detail=f"deleted {target.binding_type}/{target.binding_name}",
        incident_id=incident_id,
        approver=approver,
    )
    record = _plan_record(
        target,
        status=STATUS_SUCCESS,
        detail=f"deleted {target.binding_type}/{target.binding_name}",
        dry_run=False,
    )
    record["audit"] = second_audit
    record["incident_id"] = incident_id
    record["approver"] = approver
    return record


def reverify_revocation(target: Target, *, kube_client: KubernetesClient) -> dict[str, Any]:
    if target.binding_type == "clusterrolebindings":
        existing = kube_client.get_cluster_role_binding(target.binding_name)
    else:
        existing = kube_client.get_role_binding(target.namespace, target.binding_name)

    if existing is None:
        return _verification_record(
            target, status=STATUS_VERIFIED, detail="binding no longer present"
        )
    return _verification_record(
        target,
        status=STATUS_DRIFT,
        detail=f"{target.binding_type}/{target.binding_name} still present after revocation",
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
    audit: AuditWriter | None = None,
    deny_namespaces: Iterable[str] = DEFAULT_DENY_NAMESPACES,
    protected_prefixes: Iterable[str] = DEFAULT_DENY_BINDING_PREFIXES,
    incident_id: str = "",
    approver: str = "",
    cluster_name: str = "",
    allowed_clusters: Iterable[str] = (),
) -> Iterator[dict[str, Any]]:
    deny_namespaces = tuple(deny_namespaces)
    protected_prefixes = tuple(protected_prefixes)
    allowed_clusters = tuple(allowed_clusters)

    for target, _ in parse_targets(events):
        if target is None:
            # producer mismatch already logged by _target_from_event
            continue

        dry_run = not apply and not reverify

        # No binding pointer in the finding — we cannot revoke without manual triage
        if not target.binding_type or not target.binding_name:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_NO_BINDING,
                detail=(
                    "detector did not identify a revocable binding "
                    f"(rule=`{target.rule or '<unknown>'}`); manual triage required"
                ),
                dry_run=dry_run,
            )
            continue

        if target.binding_type not in SUPPORTED_BINDING_TYPES:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_UNSUPPORTED_TYPE,
                detail=(
                    f"binding.type=`{target.binding_type}` is not in supported set "
                    f"({sorted(SUPPORTED_BINDING_TYPES)})"
                ),
                dry_run=dry_run,
            )
            continue

        # ClusterRoleBindings have no namespace; namespaced check applies only to RoleBindings
        if target.binding_type == "rolebindings":
            denied, matched = is_protected_namespace(target.namespace, deny_namespaces)
            if denied:
                status = STATUS_SKIPPED_DENY_LIST if apply else STATUS_WOULD_VIOLATE_DENY_LIST
                yield _skip_record(
                    target,
                    status=status,
                    detail=f"namespace `{target.namespace}` matched protected pattern `{matched}`",
                    dry_run=dry_run,
                )
                continue

        protected, prefix = is_protected_binding(target.binding_name, protected_prefixes)
        if protected:
            status = (
                STATUS_SKIPPED_PROTECTED_BINDING
                if apply
                else STATUS_WOULD_VIOLATE_PROTECTED_BINDING
            )
            yield _skip_record(
                target,
                status=status,
                detail=f"binding name `{target.binding_name}` matched protected prefix `{prefix}`",
                dry_run=dry_run,
            )
            continue

        if reverify:
            yield reverify_revocation(target, kube_client=kube_client)
            continue

        if not apply:
            yield _plan_record(
                target,
                status=STATUS_PLANNED,
                detail=f"dry-run: would delete {target.binding_type}/{target.binding_name}",
                dry_run=True,
            )
            continue

        if not cluster_name:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_CLUSTER_BOUNDARY,
                detail="K8S_CLUSTER_NAME is required for --apply",
                dry_run=False,
            )
            continue
        if cluster_name not in allowed_clusters:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_CLUSTER_BOUNDARY,
                detail=(
                    f"cluster `{cluster_name}` is not listed in K8S_RBAC_REVOKE_ALLOWED_CLUSTERS"
                ),
                dry_run=False,
            )
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        yield revoke_binding(
            target,
            kube_client=kube_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify Kubernetes RBAC binding revocations."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete the offending binding after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm the binding is no longer present.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        kube_client = KubernetesRbacClient()
        audit: AuditWriter | None = None
        incident_id = ""
        approver = ""
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.getenv("K8S_RBAC_REVOKE_INCIDENT_ID", "").strip()
            approver = os.getenv("K8S_RBAC_REVOKE_APPROVER", "").strip()
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
            audit=audit,
            incident_id=incident_id,
            approver=approver,
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
