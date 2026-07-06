"""Revoke an AWS Security Group ingress rule flagged as open to the internet.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by
detect-aws-open-security-group (T1190 — Exploit Public-Facing Application).
Plans (dry-run default), applies (--apply), or re-verifies (--reverify)
deletion of the offending ingress rule via EC2 RevokeSecurityGroupIngress.

Why surgical revoke (not "delete the SG"):
- The SG may have legitimate other rules; deleting the SG breaks them
- Per the detector, the OFFENDING rule is identified by `permission.cidr`
  + `permission.port` observables. We revoke just that rule's IpPermission
- Operators retain the SG for the workload; only the public-internet
  exposure goes away

Guardrails enforced in code:
- ACCEPTED_PRODUCERS limits input to detect-aws-open-security-group
- Protected SG deny-list:
    * any SG name beginning with `default` (the AWS default SG per VPC)
    * any SG with the `intentionally-open` tag (operators wire this when
      the SG legitimately fronts a public service like an ALB on 443)
    * any SG id in AWS_SG_REVOKE_PROTECTED_IDS env var (comma-separated)
- --apply requires AWS_SG_REVOKE_INCIDENT_ID + AWS_SG_REVOKE_APPROVER
- Cross-account scoping: the EC2 client respects the AWS profile /
  AWS_REGION the operator runs under; we never call AssumeRole
  cross-account from here (the operator runs the skill under the right
  account context, or the runner does)
- Dual audit BEFORE and AFTER each Revoke
- --reverify confirms the offending IpPermission is no longer present;
  DRIFT (re-added) emits paired OCSF Detection Finding via the shared
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

SKILL_NAME = "remediate-aws-sg-revoke"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset({"detect-aws-open-security-group"})

DEFAULT_PROTECTED_SG_NAME_PREFIXES = ("default",)
DEFAULT_INTENTIONALLY_OPEN_TAG = "intentionally-open"

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_REVOKE_INGRESS = "revoke_security_group_ingress"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_PROTECTED = "skipped_protected_sg"
STATUS_WOULD_VIOLATE_PROTECTED = "would-violate-protected-sg"
STATUS_SKIPPED_NO_SG = "skipped_no_sg_pointer"
STATUS_SKIPPED_ACCOUNT_BOUNDARY = "skipped_account_boundary"


@dataclasses.dataclass(frozen=True)
class Target:
    sg_id: str
    sg_name: str
    region: str
    account_uid: str
    cidrs: tuple[str, ...]
    ports: tuple[int, ...]
    ip_protocol: str
    from_port: int | None
    to_port: int | None
    actor: str
    rule: str
    producer_skill: str
    finding_uid: str


class EC2Client(Protocol):
    """Minimal EC2 surface this skill needs. Tests inject a stub."""

    def describe_security_group(self, sg_id: str) -> dict[str, Any] | None: ...
    def revoke_security_group_ingress(
        self,
        sg_id: str,
        *,
        cidrs: list[str],
        ip_protocol: str,
        from_port: int | None,
        to_port: int | None,
    ) -> None: ...


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
class Boto3EC2Client:
    """Real EC2 client. Lazy-imports boto3 so tests don't need it."""

    region: str = ""
    profile: str = ""

    def _client(self) -> Any:
        import boto3

        session = boto3.Session(profile_name=self.profile or None)
        return session.client("ec2", region_name=self.region or None)

    def describe_security_group(self, sg_id: str) -> dict[str, Any] | None:
        try:
            response = self._client().describe_security_groups(GroupIds=[sg_id])
        except Exception:
            return None
        groups = response.get("SecurityGroups") or []
        return groups[0] if groups else None

    def revoke_security_group_ingress(
        self,
        sg_id: str,
        *,
        cidrs: list[str],
        ip_protocol: str,
        from_port: int | None,
        to_port: int | None,
    ) -> None:
        perm: dict[str, Any] = {
            "IpProtocol": ip_protocol or "tcp",
            "IpRanges": [{"CidrIp": cidr} for cidr in cidrs if "/" in cidr and ":" not in cidr],
            "Ipv6Ranges": [{"CidrIpv6": cidr} for cidr in cidrs if ":" in cidr],
        }
        if perm["IpProtocol"] != "-1":
            if from_port is not None:
                perm["FromPort"] = from_port
            if to_port is not None:
                perm["ToPort"] = to_port
        if not perm["IpRanges"]:
            del perm["IpRanges"]
        if not perm["Ipv6Ranges"]:
            del perm["Ipv6Ranges"]
        self._client().revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[perm])


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
        row_uid = _deterministic_uid(target.sg_id, step, action_at)
        evidence_key = (
            "aws-sg-revoke/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(target.sg_id)}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "sg_id": target.sg_id,
            "sg_name": target.sg_name,
            "region": target.region,
            "account_uid": target.account_uid,
            "cidrs": list(target.cidrs),
            "ports": list(target.ports),
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
                "sg_id": {"S": target.sg_id},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approver},
                "sg_name": {"S": target.sg_name},
                "region": {"S": target.region},
                "account_uid": {"S": target.account_uid},
                "actor": {"S": target.actor},
                "rule": {"S": target.rule},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    return f"sgrev-{hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()[:16]}"


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

    sg_id = _observable_value(event, "target.uid")
    sg_name = _observable_value(event, "target.name")
    region = _observable_value(event, "region")
    account_uid = _observable_value(event, "account.uid")
    actor = _observable_value(event, "actor.name")
    rule = _observable_value(event, "rule")

    cidrs = _observable_values(event, "permission.cidr")
    port_strs = _observable_values(event, "permission.port")
    ports: list[int] = []
    for p in port_strs:
        parsed = _safe_int(p)
        if parsed is not None:
            ports.append(parsed)
    ip_protocol = _observable_value(event, "permission.protocol") or "tcp"
    from_port = _safe_int(_observable_value(event, "permission.from_port"))
    to_port = _safe_int(_observable_value(event, "permission.to_port"))
    if from_port is None and len(ports) == 1:
        from_port = ports[0]
    if to_port is None and len(ports) == 1:
        to_port = ports[0]

    return Target(
        sg_id=sg_id,
        sg_name=sg_name,
        region=region,
        account_uid=account_uid,
        cidrs=cidrs,
        ports=tuple(ports),
        ip_protocol=ip_protocol,
        from_port=from_port,
        to_port=to_port,
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


def load_protected_sg_ids() -> tuple[str, ...]:
    raw = os.getenv("AWS_SG_REVOKE_PROTECTED_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def is_protected_sg(
    target: Target,
    *,
    name_prefixes: Iterable[str],
    sg_ids: Iterable[str],
    intentionally_open_tag: str,
    sg_describe: dict[str, Any] | None,
) -> tuple[bool, str]:
    if target.sg_id and target.sg_id in set(sg_ids):
        return True, f"sg-id allowlist match `{target.sg_id}`"
    name_lc = (target.sg_name or "").strip().lower()
    if name_lc:
        for prefix in name_prefixes:
            if name_lc.startswith(prefix.lower()):
                return True, f"sg-name prefix `{prefix}`"
    # Tag check requires a live describe; if not provided, skip
    if sg_describe is not None:
        for tag in sg_describe.get("Tags") or []:
            if isinstance(tag, dict) and tag.get("Key") == intentionally_open_tag:
                return True, f"tag `{intentionally_open_tag}={tag.get('Value')}`"
    return False, ""


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("AWS_SG_REVOKE_INCIDENT_ID", "").strip()
    approver = os.getenv("AWS_SG_REVOKE_APPROVER", "").strip()
    if not incident_id:
        return False, "AWS_SG_REVOKE_INCIDENT_ID is required for --apply"
    if not approver:
        return False, "AWS_SG_REVOKE_APPROVER is required for --apply"
    if not load_allowed_account_ids():
        return False, "AWS_SG_REVOKE_ALLOWED_ACCOUNT_IDS is required for --apply"
    return True, ""


def load_allowed_account_ids() -> tuple[str, ...]:
    raw = os.getenv("AWS_SG_REVOKE_ALLOWED_ACCOUNT_IDS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _resolve_current_account_id(*, profile: str = "", region: str = "") -> str:
    import boto3

    session = boto3.Session(profile_name=profile or None)
    client = session.client("sts", region_name=region or None)
    return str(client.get_caller_identity()["Account"])


def _revoke_endpoint(target: Target) -> str:
    return (
        "POST ec2:RevokeSecurityGroupIngress "
        f"GroupId={target.sg_id} IpProtocol={target.ip_protocol or 'tcp'} "
        f"FromPort={target.from_port!r} ToPort={target.to_port!r}"
    )


def _verify_endpoint(target: Target) -> str:
    return f"GET ec2:DescribeSecurityGroups GroupIds=[{target.sg_id}]"


def _plan_record(
    target: Target, *, status: str, detail: str | None, dry_run: bool
) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "AWS",
            "sg_id": target.sg_id,
            "sg_name": target.sg_name,
            "region": target.region,
            "account_uid": target.account_uid,
            "cidrs": list(target.cidrs),
            "ports": list(target.ports),
            "ip_protocol": target.ip_protocol,
            "from_port": target.from_port,
            "to_port": target.to_port,
            "actor": target.actor,
            "rule": target.rule,
        },
        "actions": [
            {
                "step": STEP_REVOKE_INGRESS,
                "endpoint": _revoke_endpoint(target),
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
            "provider": "AWS",
            "sg_id": target.sg_id,
            "sg_name": target.sg_name,
            "region": target.region,
            "account_uid": target.account_uid,
            "cidrs": list(target.cidrs),
            "ports": list(target.ports),
            "ip_protocol": target.ip_protocol,
            "from_port": target.from_port,
            "to_port": target.to_port,
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


def revoke_ingress(
    target: Target,
    *,
    ec2_client: EC2Client,
    audit: AuditWriter,
    incident_id: str,
    approver: str,
) -> dict[str, Any]:
    first = audit.record(
        target=target,
        step=STEP_REVOKE_INGRESS,
        status=STATUS_IN_PROGRESS,
        detail=(
            f"about to revoke {target.cidrs} protocol={target.ip_protocol or 'tcp'} "
            f"ports={target.from_port!r}-{target.to_port!r} on {target.sg_id}"
        ),
        incident_id=incident_id,
        approver=approver,
    )
    try:
        ec2_client.revoke_security_group_ingress(
            target.sg_id,
            cidrs=list(target.cidrs),
            ip_protocol=target.ip_protocol,
            from_port=target.from_port,
            to_port=target.to_port,
        )
    except Exception as exc:
        audit.record(
            target=target,
            step=STEP_REVOKE_INGRESS,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approver=approver,
        )
        rec = _plan_record(target, status=STATUS_FAILURE, detail=str(exc), dry_run=False)
        rec["audit"] = first
        return rec

    last = audit.record(
        target=target,
        step=STEP_REVOKE_INGRESS,
        status=STATUS_SUCCESS,
        detail=(
            f"revoked ingress {target.cidrs} protocol={target.ip_protocol or 'tcp'} "
            f"ports={target.from_port!r}-{target.to_port!r} on {target.sg_id}"
        ),
        incident_id=incident_id,
        approver=approver,
    )
    rec = _plan_record(target, status=STATUS_SUCCESS, detail=None, dry_run=False)
    rec["audit"] = last
    rec["incident_id"] = incident_id
    rec["approver"] = approver
    return rec


def reverify_target(
    target: Target,
    *,
    ec2_client: EC2Client,
    now_ms: int | None = None,
    remediated_at_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Re-verify the offending IpPermission is no longer present on the SG.
    Emits one verification record; on DRIFT also emits OCSF Detection Finding."""
    checked_at_ms = (
        now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    remediated_at_ms_resolved = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=_deterministic_uid(
            "revoke",
            target.sg_id,
            ",".join(target.cidrs),
            target.ip_protocol or "tcp",
            str(target.from_port),
            str(target.to_port),
        ),
        target_provider="AWS",
        target_identifier=(
            f"{target.sg_id}/{','.join(target.cidrs)}:"
            f"{target.ip_protocol or 'tcp'}:{target.from_port!r}-{target.to_port!r}"
        ),
        original_finding_uid=target.finding_uid,
        remediated_at_ms=remediated_at_ms_resolved,
    )
    expected = (
        f"no IpPermissions on `{target.sg_id}` granting `{list(target.cidrs)}` for protocol "
        f"`{target.ip_protocol or 'tcp'}` ports `{target.from_port!r}`-`{target.to_port!r}`"
    )

    try:
        sg = ec2_client.describe_security_group(target.sg_id)
    except Exception as exc:
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="ec2:DescribeSecurityGroups raised; cannot determine state",
            detail=str(exc),
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = {"provider": "AWS", "sg_id": target.sg_id, "sg_name": target.sg_name}
        return [record]

    if sg is None:
        # SG gone entirely → stronger than revoked; counts as VERIFIED
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="security group not found (deleted) — stronger than revoked",
            detail="containment confirmed via absence",
        )
    else:
        # Look for any IpPermission still granting the original protocol/range
        # shape to any cidr in target.cidrs.
        offending: list[dict[str, Any]] = []
        target_cidrs = set(target.cidrs)
        target_protocol = (target.ip_protocol or "tcp").lower()
        for perm in sg.get("IpPermissions") or []:
            perm_protocol = str(perm.get("IpProtocol") or "").lower()
            protocol_matches = perm_protocol == target_protocol
            if target_protocol == "-1":
                ports_match = True
            else:
                perm_from = (
                    _safe_int(str(perm.get("FromPort")))
                    if perm.get("FromPort") is not None
                    else None
                )
                perm_to = (
                    _safe_int(str(perm.get("ToPort"))) if perm.get("ToPort") is not None else None
                )
                ports_match = perm_from == target.from_port and perm_to == target.to_port
            cidrs_in_perm = {
                str((r or {}).get("CidrIp", "")) for r in perm.get("IpRanges") or []
            } | {str((r or {}).get("CidrIpv6", "")) for r in perm.get("Ipv6Ranges") or []}
            cidr_overlap = target_cidrs & cidrs_in_perm
            if protocol_matches and ports_match and cidr_overlap:
                offending.append(
                    {
                        "cidrs": sorted(cidr_overlap),
                        "ip_protocol": perm_protocol,
                        "from_port": perm.get("FromPort"),
                        "to_port": perm.get("ToPort"),
                    }
                )

        if offending:
            result = VerificationResult(
                status=VerificationStatus.DRIFT,
                checked_at_ms=checked_at_ms,
                sla_deadline_ms=sla_deadline(
                    remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                ),
                expected_state=expected,
                actual_state=f"offending permissions still present: {offending}",
                detail="ingress was re-added or never landed",
            )
        else:
            result = VerificationResult(
                status=VerificationStatus.VERIFIED,
                checked_at_ms=checked_at_ms,
                sla_deadline_ms=sla_deadline(
                    remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS
                ),
                expected_state=expected,
                actual_state="no offending permissions present",
                detail="revoke confirmed",
            )

    record = build_verification_record(
        reference=reference, result=result, verifier_skill=SKILL_NAME
    )
    record["target"] = {"provider": "AWS", "sg_id": target.sg_id, "sg_name": target.sg_name}
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
    ec2_client: EC2Client,
    apply: bool = False,
    reverify: bool = False,
    audit: AuditWriter | None = None,
    name_prefixes: Iterable[str] = DEFAULT_PROTECTED_SG_NAME_PREFIXES,
    sg_ids: Iterable[str] = (),
    intentionally_open_tag: str = DEFAULT_INTENTIONALLY_OPEN_TAG,
    incident_id: str = "",
    approver: str = "",
    allowed_account_ids: Iterable[str] = (),
    current_account_id: str = "",
) -> Iterator[dict[str, Any]]:
    name_prefixes = tuple(name_prefixes)
    sg_ids = tuple(sg_ids)
    allowed_account_ids = tuple(allowed_account_ids)

    for target, event in parse_targets(events):
        if target is None:
            continue

        dry_run = not apply and not reverify

        if not target.sg_id:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_NO_SG,
                detail="finding did not carry a target.uid (sg id) observable",
                dry_run=dry_run,
            )
            continue

        if apply:
            if (
                target.account_uid
                and allowed_account_ids
                and target.account_uid not in allowed_account_ids
            ):
                yield _skip_record(
                    target,
                    status=STATUS_SKIPPED_ACCOUNT_BOUNDARY,
                    detail=(
                        f"target account `{target.account_uid}` is not listed in "
                        "AWS_SG_REVOKE_ALLOWED_ACCOUNT_IDS"
                    ),
                    dry_run=False,
                )
                continue
            if (
                current_account_id
                and target.account_uid
                and target.account_uid != current_account_id
            ):
                yield _skip_record(
                    target,
                    status=STATUS_SKIPPED_ACCOUNT_BOUNDARY,
                    detail=(
                        f"target account `{target.account_uid}` does not match current AWS account "
                        f"`{current_account_id}`"
                    ),
                    dry_run=False,
                )
                continue

        # Live tag check requires a describe call. We do it once per target.
        sg_describe: dict[str, Any] | None = None
        try:
            sg_describe = ec2_client.describe_security_group(target.sg_id)
        except Exception:
            sg_describe = None

        protected, why = is_protected_sg(
            target,
            name_prefixes=name_prefixes,
            sg_ids=sg_ids,
            intentionally_open_tag=intentionally_open_tag,
            sg_describe=sg_describe,
        )
        if protected:
            status = STATUS_SKIPPED_PROTECTED if apply else STATUS_WOULD_VIOLATE_PROTECTED
            yield _skip_record(
                target,
                status=status,
                detail=f"target is protected: {why}",
                dry_run=dry_run,
            )
            continue

        if reverify:
            yield from reverify_target(
                target,
                ec2_client=ec2_client,
                remediated_at_ms=_event_reference_time_ms(event),
            )
            continue

        if not apply:
            yield _plan_record(
                target,
                status=STATUS_PLANNED,
                detail=(
                    f"dry-run: would revoke {list(target.cidrs)} protocol={target.ip_protocol or 'tcp'} "
                    f"ports={target.from_port!r}-{target.to_port!r} on {target.sg_id}"
                ),
                dry_run=True,
            )
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        yield revoke_ingress(
            target,
            ec2_client=ec2_client,
            audit=audit,
            incident_id=incident_id,
            approver=approver,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify AWS Security Group ingress revocation."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Revoke the offending ingress after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm offending ingress is gone.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        ec2_client: EC2Client = Boto3EC2Client(
            region=os.environ.get("AWS_REGION", ""),
            profile=os.environ.get("AWS_PROFILE", ""),
        )
        audit: AuditWriter | None = None
        incident_id = ""
        approver = ""
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            try:
                current_account_id = _resolve_current_account_id(
                    profile=os.environ.get("AWS_PROFILE", ""),
                    region=os.environ.get("AWS_REGION", ""),
                )
            except Exception as exc:
                print(f"failed to resolve current AWS account for --apply: {exc}", file=sys.stderr)
                return 2
            incident_id = os.environ["AWS_SG_REVOKE_INCIDENT_ID"].strip()
            approver = os.environ["AWS_SG_REVOKE_APPROVER"].strip()
            audit = DualAuditWriter(
                dynamodb_table=os.environ["AWS_SG_REVOKE_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["AWS_SG_REVOKE_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )
        else:
            current_account_id = ""

        for record in run(
            load_jsonl(in_stream),
            ec2_client=ec2_client,
            apply=args.apply,
            reverify=args.reverify,
            audit=audit,
            sg_ids=load_protected_sg_ids(),
            incident_id=incident_id,
            approver=approver,
            allowed_account_ids=load_allowed_account_ids(),
            current_account_id=current_account_id,
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
