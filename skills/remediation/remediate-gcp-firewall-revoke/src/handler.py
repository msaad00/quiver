"""Revoke a GCP VPC firewall rule flagged as open to the internet.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-gcp-open-firewall (T1190 — Exploit Public-Facing Application).
Plans (dry-run default), applies (--apply), or re-verifies (--reverify)
removal of the offending firewall rule via Compute Engine
`firewalls.patch` (default safe mode: `disabled: true`) or
`firewalls.delete` (opt-in via `--mode delete`).

Why disable-by-default (not delete):
- Firewall rules are referenced by IaC, attached service descriptions,
  and operator playbooks. Deleting drops history and breaks references.
- `disabled: true` immediately stops the rule granting traffic but
  preserves the object for forensics and rollback.
- `--mode delete` remains available for operators who explicitly accept
  the loss of history.

Guardrails enforced in code:
- ACCEPTED_PRODUCERS limits input to detect-gcp-open-firewall
- Protected rule deny-list:
    * any rule name beginning with `default-` (the GCP project default rules)
    * any rule whose `description` contains `intentionally-open`
    * any rule name in GCP_FIREWALL_REVOKE_DENY_RULE_NAMES env var
- --apply requires GCP_FIREWALL_REVOKE_INCIDENT_ID + GCP_FIREWALL_REVOKE_APPROVER
- The Compute client respects whatever credentials the operator's
  environment provides; we never call cross-project from here
- Dual audit BEFORE and AFTER each Patch/Delete
- --reverify confirms the rule is absent or disabled; DRIFT (re-enabled
  or re-created) emits paired OCSF Detection Finding via the shared
  remediation_verifier contract
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

SKILL_NAME = "remediate-gcp-firewall-revoke"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset({"detect-gcp-open-firewall"})

DEFAULT_PROTECTED_RULE_NAME_PREFIXES = ("default-",)
DEFAULT_INTENTIONALLY_OPEN_DESCRIPTION_MARKER = "intentionally-open"

MODE_PATCH = "patch"
MODE_DELETE = "delete"
SUPPORTED_MODES = frozenset({MODE_PATCH, MODE_DELETE})

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_PATCH_DISABLE = "patch_firewall_disable"
STEP_DELETE_FIREWALL = "delete_firewall"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_PROTECTED = "skipped_protected_firewall"
STATUS_WOULD_VIOLATE_PROTECTED = "would-violate-protected-firewall"
STATUS_SKIPPED_NO_TARGET = "skipped_no_firewall_pointer"
STATUS_SKIPPED_PROJECT_BOUNDARY = "skipped_project_boundary"


@dataclasses.dataclass(frozen=True)
class Target:
    rule_name: str
    project_id: str
    network: str
    cidrs: tuple[str, ...]
    ports: tuple[int, ...]
    ip_protocol: str
    actor: str
    rule: str
    producer_skill: str
    finding_uid: str


class ComputeClient(Protocol):
    """Minimal Compute Engine surface this skill needs. Tests inject a stub."""

    def get_firewall(self, project: str, rule_name: str) -> dict[str, Any] | None: ...
    def patch_firewall_disable(self, project: str, rule_name: str) -> None: ...
    def delete_firewall(self, project: str, rule_name: str) -> None: ...


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
class GoogleComputeClient:
    """Real Compute client. Lazy-imports googleapiclient so tests don't need it."""

    def _client(self) -> Any:
        from googleapiclient.discovery import build

        # Credentials picked up from GOOGLE_APPLICATION_CREDENTIALS or ADC.
        return build("compute", "v1", cache_discovery=False)

    def get_firewall(self, project: str, rule_name: str) -> dict[str, Any] | None:
        try:
            return self._client().firewalls().get(project=project, firewall=rule_name).execute()
        except Exception:
            return None

    def patch_firewall_disable(self, project: str, rule_name: str) -> None:
        body = {"disabled": True}
        self._client().firewalls().patch(project=project, firewall=rule_name, body=body).execute()

    def delete_firewall(self, project: str, rule_name: str) -> None:
        self._client().firewalls().delete(project=project, firewall=rule_name).execute()


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
        import boto3

        action_at = datetime.now(timezone.utc).isoformat()
        row_uid = _deterministic_uid(target.rule_name, step, action_at)
        evidence_key = (
            "gcp-firewall-revoke/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(target.project_id)}/"
            f"{_safe_path_component(target.rule_name)}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "provider": "gcp",
            "rule_name": target.rule_name,
            "project_id": target.project_id,
            "cloud": {
                "provider": "GCP",
                "account": {"uid": target.project_id},
                "region": "global",
            },
            "network": target.network,
            "cidrs": list(target.cidrs),
            "ports": list(target.ports),
            "ip_protocol": target.ip_protocol,
            "actor": target.actor,
            "rule": target.rule,
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
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
                "rule_name": {"S": target.rule_name},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "project_id": {"S": target.project_id},
                "provider": {"S": "gcp"},
                "actor": {"S": target.actor},
                "rule": {"S": target.rule},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    return f"gfwrev-{hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()[:16]}"


def _safe_path_component(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (value or "_"))
    return safe[:120] or "_"


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
        if isinstance(obs, dict) and obs.get("name") == name and obs.get("value"):
            return str(obs["value"])
    return ""


def _observable_values(event: dict[str, Any], name: str) -> tuple[str, ...]:
    values = []
    for obs in event.get("observables") or []:
        if isinstance(obs, dict) and obs.get("name") == name and obs.get("value"):
            values.append(str(obs["value"]))
    return tuple(values)


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_reference_time_ms(event: dict[str, Any]) -> int | None:
    candidates = (
        event.get("remediated_at_ms"),
        event.get("time_ms"),
        event.get("time"),
        ((event.get("finding_info") or {}).get("last_seen_time")),
        ((event.get("finding_info") or {}).get("first_seen_time")),
    )
    for value in candidates:
        parsed = _safe_int(str(value)) if value is not None else None
        if parsed is not None and parsed > 0:
            return parsed
    return None


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

    rule_name = _observable_value(event, "target.uid")
    project_id = _observable_value(event, "account.uid")
    network = _observable_value(event, "target.network")
    actor = _observable_value(event, "actor.name")
    rule = _observable_value(event, "rule")
    ip_protocol = _observable_value(event, "permission.protocol") or "tcp"

    cidrs = _observable_values(event, "permission.cidr")
    port_strs = _observable_values(event, "permission.port")
    ports: list[int] = []
    for p in port_strs:
        parsed = _safe_int(p)
        if parsed is not None:
            ports.append(parsed)

    return Target(
        rule_name=rule_name,
        project_id=project_id,
        network=network,
        cidrs=cidrs,
        ports=tuple(ports),
        ip_protocol=ip_protocol,
        actor=actor,
        rule=rule,
        producer_skill=producer,
        finding_uid=_finding_uid(event),
    )


def parse_targets(
    events: Iterable[dict[str, Any]],
) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_protected_rule_names() -> tuple[str, ...]:
    raw = os.getenv("GCP_FIREWALL_REVOKE_DENY_RULE_NAMES", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def is_protected_firewall(
    target: Target,
    *,
    name_prefixes: Iterable[str],
    rule_names: Iterable[str],
    intentionally_open_marker: str,
    firewall_get: dict[str, Any] | None,
) -> tuple[bool, str]:
    if target.rule_name and target.rule_name in set(rule_names):
        return True, f"rule-name allowlist match `{target.rule_name}`"
    name_lc = (target.rule_name or "").strip().lower()
    if name_lc:
        for prefix in name_prefixes:
            if name_lc.startswith(prefix.lower()):
                return True, f"rule-name prefix `{prefix}`"
    # Description check requires a live get; if not provided, skip
    if firewall_get is not None:
        description = str(firewall_get.get("description") or "").lower()
        if intentionally_open_marker.lower() in description:
            return True, f"description contains `{intentionally_open_marker}`"
    return False, ""


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("GCP_FIREWALL_REVOKE_INCIDENT_ID", "").strip()
    approver = os.getenv("GCP_FIREWALL_REVOKE_APPROVER", "").strip()
    if not incident_id:
        return False, "GCP_FIREWALL_REVOKE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "GCP_FIREWALL_REVOKE_APPROVER is required for --apply"
    if not load_allowed_project_ids():
        return False, "GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS is required for --apply"
    return True, ""


def load_allowed_project_ids() -> tuple[str, ...]:
    raw = os.getenv("GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _action_endpoint(target: Target, mode: str) -> str:
    if mode == MODE_DELETE:
        return f"DELETE compute.firewalls.delete project={target.project_id} firewall={target.rule_name}"
    return (
        f"PATCH compute.firewalls.patch project={target.project_id} "
        f"firewall={target.rule_name} body={{'disabled': true}}"
    )


def _verify_endpoint(target: Target) -> str:
    return f"GET compute.firewalls.get project={target.project_id} firewall={target.rule_name}"


def _step_for_mode(mode: str) -> str:
    return STEP_DELETE_FIREWALL if mode == MODE_DELETE else STEP_PATCH_DISABLE


def _plan_record(
    target: Target, *, status: str, detail: str | None, dry_run: bool, mode: str
) -> dict[str, Any]:
    step = _step_for_mode(mode)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "GCP",
            "rule_name": target.rule_name,
            "project_id": target.project_id,
            "region": "global",
            "network": target.network,
            "cidrs": list(target.cidrs),
            "ports": list(target.ports),
            "ip_protocol": target.ip_protocol,
            "actor": target.actor,
            "rule": target.rule,
        },
        "actions": [
            {
                "step": step,
                "endpoint": _action_endpoint(target, mode),
                "status": status,
                "detail": detail,
            }
        ],
        "status": status,
        "mode": mode,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def _skip_record(
    target: Target, *, status: str, detail: str, dry_run: bool, mode: str
) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "GCP",
            "rule_name": target.rule_name,
            "project_id": target.project_id,
            "region": "global",
            "network": target.network,
            "cidrs": list(target.cidrs),
            "ports": list(target.ports),
            "ip_protocol": target.ip_protocol,
            "actor": target.actor,
            "rule": target.rule,
        },
        "actions": [],
        "status": status,
        "status_detail": detail,
        "mode": mode,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def revoke_firewall(
    target: Target,
    *,
    compute_client: ComputeClient,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
    mode: str,
) -> dict[str, Any]:
    step = _step_for_mode(mode)
    action_word = "delete" if mode == MODE_DELETE else "disable"
    first = audit.record(
        target=target,
        step=step,
        status=STATUS_IN_PROGRESS,
        detail=(
            f"about to {action_word} firewall `{target.rule_name}` in project "
            f"`{target.project_id}` (network={target.network or '<unknown>'})"
        ),
        incident_id=incident_id,
        approver=approver,
    )
    try:
        if mode == MODE_DELETE:
            compute_client.delete_firewall(target.project_id, target.rule_name)
        else:
            compute_client.patch_firewall_disable(target.project_id, target.rule_name)
    except Exception as exc:
        audit.record(
            target=target,
            step=step,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
        )
        rec = _plan_record(target, status=STATUS_FAILURE, detail=str(exc), dry_run=False, mode=mode)
        rec["audit"] = first
        return rec

    last = audit.record(
        target=target,
        step=step,
        status=STATUS_SUCCESS,
        detail=(f"{action_word}d firewall `{target.rule_name}` in project `{target.project_id}`"),
        incident_id=incident_id,
        approver=approver,
    )
    rec = _plan_record(target, status=STATUS_SUCCESS, detail=None, dry_run=False, mode=mode)
    rec["audit"] = last
    rec["incident_id"] = incident_id
    rec["approver"] = approver
    return rec


def reverify_target(
    target: Target,
    *,
    compute_client: ComputeClient,
    now_ms: int | None = None,
    remediated_at_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Re-verify the offending firewall is absent or disabled.
    Emits one verification record; on DRIFT also emits OCSF Detection Finding."""
    checked_at_ms = (
        now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    remediated_at_ms_resolved = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=_deterministic_uid(
            "revoke",
            target.project_id,
            target.rule_name,
            ",".join(target.cidrs),
            target.ip_protocol or "tcp",
        ),
        target_provider="GCP",
        target_identifier=f"{target.project_id}/global/firewalls/{target.rule_name}",
        original_finding_uid=target.finding_uid,
        remediated_at_ms=remediated_at_ms_resolved,
    )
    expected = (
        f"firewall rule `{target.rule_name}` in project `{target.project_id}` "
        "is absent or `disabled: true`"
    )

    try:
        firewall = compute_client.get_firewall(target.project_id, target.rule_name)
    except Exception as exc:
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="compute.firewalls.get raised; cannot determine state",
            detail=str(exc),
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = {
            "provider": "GCP",
            "rule_name": target.rule_name,
            "project_id": target.project_id,
        }
        return [record]

    if firewall is None:
        # Rule gone entirely → stronger than disabled; counts as VERIFIED
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="firewall rule not found (deleted) — stronger than disabled",
            detail="containment confirmed via absence",
        )
    else:
        disabled = bool(firewall.get("disabled"))
        if disabled:
            result = VerificationResult(
                status=VerificationStatus.VERIFIED,
                checked_at_ms=checked_at_ms,
                sla_deadline_ms=sla_deadline(
                    remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                ),
                expected_state=expected,
                actual_state="firewall rule present and `disabled: true`",
                detail="patch confirmed",
            )
        else:
            result = VerificationResult(
                status=VerificationStatus.DRIFT,
                checked_at_ms=checked_at_ms,
                sla_deadline_ms=sla_deadline(
                    remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                ),
                expected_state=expected,
                actual_state="firewall rule present and NOT disabled (re-enabled or re-created)",
                detail="ingress was re-enabled or never landed",
            )

    record = build_verification_record(
        reference=reference, result=result, verifier_skill=SKILL_NAME
    )
    record["target"] = {
        "provider": "GCP",
        "rule_name": target.rule_name,
        "project_id": target.project_id,
    }
    outputs: list[dict[str, Any]] = [record]
    if result.status == VerificationStatus.DRIFT:
        outputs.append(
            build_drift_finding(reference=reference, result=result, verifier_skill=SKILL_NAME)
        )
    return outputs


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


def run(
    events: Iterable[dict[str, Any]],
    *,
    compute_client: ComputeClient,
    apply: bool = False,
    reverify: bool = False,
    audit: AuditWriter | None = None,
    name_prefixes: Iterable[str] = DEFAULT_PROTECTED_RULE_NAME_PREFIXES,
    rule_names: Iterable[str] = (),
    intentionally_open_marker: str = DEFAULT_INTENTIONALLY_OPEN_DESCRIPTION_MARKER,
    incident_id: str = "",
    approver: str = "",
    mode: str = MODE_PATCH,
    allowed_project_ids: Iterable[str] = (),
) -> Iterator[dict[str, Any]]:
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"unsupported mode `{mode}`; expected one of {sorted(SUPPORTED_MODES)}")

    name_prefixes = tuple(name_prefixes)
    rule_names = tuple(rule_names)
    allowed_project_ids = tuple(allowed_project_ids)

    for target, event in parse_targets(events):
        if target is None:
            continue

        dry_run = not apply and not reverify

        if not target.rule_name or not target.project_id:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_NO_TARGET,
                detail="finding did not carry a target.uid (rule name) and account.uid (project) observable",
                dry_run=dry_run,
                mode=mode,
            )
            continue

        if apply and target.project_id not in allowed_project_ids:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_PROJECT_BOUNDARY,
                detail=(
                    f"target project `{target.project_id}` is not listed in "
                    "GCP_FIREWALL_REVOKE_ALLOWED_PROJECT_IDS"
                ),
                dry_run=False,
                mode=mode,
            )
            continue

        # Live description check requires a get call. We do it once per target.
        firewall_get: dict[str, Any] | None = None
        try:
            firewall_get = compute_client.get_firewall(target.project_id, target.rule_name)
        except Exception:
            firewall_get = None

        protected, why = is_protected_firewall(
            target,
            name_prefixes=name_prefixes,
            rule_names=rule_names,
            intentionally_open_marker=intentionally_open_marker,
            firewall_get=firewall_get,
        )
        if protected:
            status = STATUS_SKIPPED_PROTECTED if apply else STATUS_WOULD_VIOLATE_PROTECTED
            yield _skip_record(
                target,
                status=status,
                detail=f"target is protected: {why}",
                dry_run=dry_run,
                mode=mode,
            )
            continue

        if reverify:
            yield from reverify_target(
                target,
                compute_client=compute_client,
                remediated_at_ms=_event_reference_time_ms(event),
            )
            continue

        if not apply:
            action_word = "delete" if mode == MODE_DELETE else "disable (patch disabled=true)"
            yield _plan_record(
                target,
                status=STATUS_PLANNED,
                detail=(
                    f"dry-run: would {action_word} firewall `{target.rule_name}` "
                    f"in project `{target.project_id}` to revoke "
                    f"{list(target.cidrs)} on protocol {target.ip_protocol or 'tcp'}"
                ),
                dry_run=True,
                mode=mode,
            )
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        yield revoke_firewall(
            target,
            compute_client=compute_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
            mode=mode,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify GCP VPC firewall rule revocation."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Patch (disable) or delete the offending firewall after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm offending firewall is gone or disabled.",
    )
    parser.add_argument(
        "--mode",
        choices=sorted(SUPPORTED_MODES),
        default=MODE_PATCH,
        help="`patch` (default, sets disabled: true) or `delete` (opt-in, removes the rule).",
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        compute_client: ComputeClient = GoogleComputeClient()
        audit: AuditWriter | None = None
        incident_id = ""
        approver = ""
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.environ["GCP_FIREWALL_REVOKE_INCIDENT_ID"].strip()
            approver = os.environ["GCP_FIREWALL_REVOKE_APPROVER"].strip()
            audit = DualAuditWriter(
                dynamodb_table=os.environ["GCP_FIREWALL_REVOKE_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["GCP_FIREWALL_REVOKE_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )

        for record in run(
            load_jsonl(in_stream),
            compute_client=compute_client,
            apply=args.apply,
            reverify=args.reverify,
            audit=audit,
            rule_names=load_protected_rule_names(),
            incident_id=incident_id,
            approver=approver,
            mode=args.mode,
            allowed_project_ids=load_allowed_project_ids(),
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
