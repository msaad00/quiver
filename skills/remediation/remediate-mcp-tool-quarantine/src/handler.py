"""Quarantine an MCP tool flagged by tool-drift or prompt-injection findings.

Consumes an OCSF 1.8 Detection Finding (class 2004) emitted by either
`detect-mcp-tool-drift` (T1195.001 — Compromise Software Supply Chain) or
`detect-prompt-injection-mcp-proxy` (MITRE ATLAS AML.T0051). Plans (dry-run
default), applies (--apply), or re-verifies (--reverify) an entry in a local
JSONL quarantine file that the operator's MCP client reads at startup or via
hot-reload to exclude the tool from its discoverable surface.

Why file-based + dual audit:
- The MCP attack surface is in-process from the agent's POV — no cloud API
  to call. The quarantine artifact is a small structured JSONL file the
  operator's MCP client filters its tool list against.
- The dual-audit pattern (DynamoDB + KMS-encrypted S3) is preserved for
  organizational traceability — same shape as the other 4 remediation
  skills, even though the cloud API surface here is just storage.
- Wiring `_shared/remediation_verifier.py` from day one means a re-verify
  that finds the tool removed from the quarantine file (drift) emits an
  OCSF Detection Finding through the same SIEM/SOAR pipeline as every
  other finding.

Guardrails enforced in code:
- ACCEPTED_PRODUCERS limits input to the two MCP detectors
- protected-tool deny-list: `mcp_*`, `system_*`, `internal_*` patterns
  refuse quarantine (operators should revoke, not auto-block, infrastructure
  tools)
- --apply requires MCP_QUARANTINE_INCIDENT_ID plus two distinct approvers
- audit row written BEFORE and AFTER each quarantine append
- --reverify reads the quarantine file and reports VERIFIED / DRIFT /
  UNREACHABLE via the shared verifier contract
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

SKILL_NAME = "remediate-mcp-tool-quarantine"
CANONICAL_VERSION = "2026-04"
ACCEPTED_PRODUCERS = frozenset(
    {
        "detect-mcp-tool-drift",
        "detect-prompt-injection-mcp-proxy",
    }
)

# Tools matching these prefixes are considered protected MCP infrastructure
# (the repo's own MCP server, system probes, etc.) and refuse quarantine.
# Operators should revoke / patch — not silently block — infrastructure tools.
DEFAULT_PROTECTED_TOOL_PREFIXES = (
    "mcp_",
    "system_",
    "internal_",
)

RECORD_PLAN = "remediation_plan"
RECORD_ACTION = "remediation_action"
RECORD_VERIFICATION = "remediation_verification"

STEP_QUARANTINE_TOOL = "append_to_quarantine_file"

STATUS_PLANNED = "planned"
STATUS_IN_PROGRESS = "in_progress"
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
STATUS_VERIFIED = "verified"
STATUS_DRIFT = "drift"
STATUS_SKIPPED_SOURCE = "skipped_wrong_source"
STATUS_SKIPPED_PROTECTED = "skipped_protected_tool"
STATUS_WOULD_VIOLATE_PROTECTED = "would-violate-protected-tool"
STATUS_SKIPPED_NO_TOOL = "skipped_no_tool_pointer"


@dataclasses.dataclass(frozen=True)
class Target:
    tool_name: str
    session_uid: str
    fingerprint: str  # tool.after_fingerprint or tool.description_sha256
    producer_skill: str
    finding_uid: str


class QuarantineStore(Protocol):
    """Read + append the quarantine list. File-based default; tests inject stub."""

    def list_tools(self) -> list[str]: ...
    def append(self, entry: dict[str, Any]) -> None: ...


class AuditWriter(Protocol):
    def record(
        self,
        *,
        target: Target,
        step: str,
        status: str,
        detail: str | None,
        incident_id: str,
        approvers: tuple[str, ...],
    ) -> dict[str, str]: ...


@dataclasses.dataclass
class JSONLQuarantineFile:
    """Default quarantine store: append-only JSONL on disk.

    The MCP client reads this file at startup (or via hot-reload) to filter
    its tool surface. Each line is one quarantined tool entry.
    """

    path: Path

    def list_tools(self) -> list[str]:
        if not self.path.exists():
            return []
        names: list[str] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict) and obj.get("tool_name"):
                    names.append(str(obj["tool_name"]))
        return names

    def append(self, entry: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


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
        approvers: tuple[str, ...],
    ) -> dict[str, str]:
        import boto3

        action_at = datetime.now(timezone.utc).isoformat()
        row_uid = _deterministic_uid(target.tool_name, target.session_uid, step, action_at)
        evidence_key = (
            "mcp-tool-quarantine/audit/"
            f"{action_at[:4]}/{action_at[5:7]}/{action_at[8:10]}/"
            f"{_safe_path_component(target.tool_name)}/{action_at}-{step}.json"
        )
        evidence_uri = f"s3://{self.s3_bucket}/{evidence_key}"

        envelope = {
            "schema_mode": "native",
            "canonical_schema_version": CANONICAL_VERSION,
            "record_type": "remediation_audit",
            "source_skill": SKILL_NAME,
            "row_uid": row_uid,
            "tool_name": target.tool_name,
            "session_uid": target.session_uid,
            "fingerprint": target.fingerprint,
            "producer_skill": target.producer_skill,
            "finding_uid": target.finding_uid,
            "step": step,
            "status": status,
            "status_detail": detail,
            "incident_id": incident_id,
            "approver": approvers[0] if approvers else "",
            "approvers": list(approvers),
            "approver_count": len(approvers),
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
                "tool_name": {"S": target.tool_name},
                "action_at": {"S": action_at},
                "row_uid": {"S": row_uid},
                "step": {"S": step},
                "status": {"S": status},
                "incident_id": {"S": incident_id},
                "approver": {"S": approvers[0] if approvers else ""},
                "approvers_csv": {"S": ",".join(approvers)},
                "approver_count": {"N": str(len(approvers))},
                "session_uid": {"S": target.session_uid},
                "fingerprint": {"S": target.fingerprint},
                "producer_skill": {"S": target.producer_skill},
                "finding_uid": {"S": target.finding_uid},
                "s3_evidence_uri": {"S": evidence_uri},
            },
        )
        return {"row_uid": row_uid, "s3_evidence_uri": evidence_uri}


def _deterministic_uid(*parts: str) -> str:
    material = "|".join(parts)
    return f"mcpq-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


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


def _observable_value(event: dict[str, Any], *names: str) -> str:
    """Return the first matching observable value across `names` (in order)."""
    for obs in event.get("observables") or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("name") in names:
            value = obs.get("value")
            if value:
                return str(value)
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

    tool_name = _observable_value(event, "tool.name")
    session_uid = _observable_value(event, "session.uid")
    fingerprint = _observable_value(
        event,
        "tool.after_fingerprint",
        "tool.description_sha256",
        "tool.before_fingerprint",
    )
    return Target(
        tool_name=tool_name,
        session_uid=session_uid,
        fingerprint=fingerprint,
        producer_skill=producer,
        finding_uid=_finding_uid(event),
    )


def parse_targets(
    events: Iterable[dict[str, Any]],
) -> Iterator[tuple[Target | None, dict[str, Any]]]:
    for event in events:
        yield _target_from_event(event), event


def load_protected_tool_prefixes() -> tuple[str, ...]:
    return DEFAULT_PROTECTED_TOOL_PREFIXES


def is_protected_tool(name: str, prefixes: Iterable[str]) -> tuple[bool, str]:
    value = (name or "").strip().lower()
    if not value:
        return False, ""
    for prefix in prefixes:
        needle = prefix.lower()
        if value.startswith(needle):
            return True, prefix
    return False, ""


def _parse_csv_env(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    values: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        normalized = part.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        values.append(normalized)
    return tuple(values)


def _load_apply_approvers() -> tuple[str, ...]:
    approver_ids = _parse_csv_env("MCP_QUARANTINE_APPROVER_IDS")
    approver_emails = _parse_csv_env("MCP_QUARANTINE_APPROVER_EMAILS")
    legacy = tuple(
        value
        for value in _parse_csv_env("MCP_QUARANTINE_APPROVER")
        + _parse_csv_env("MCP_QUARANTINE_SECOND_APPROVER")
        if value
    )
    if len(approver_emails) >= len(approver_ids) and approver_emails:
        return approver_emails
    if approver_ids:
        return approver_ids
    return tuple(dict.fromkeys(legacy))


def check_apply_gate() -> tuple[bool, str]:
    incident_id = os.getenv("MCP_QUARANTINE_INCIDENT_ID", "").strip()
    approvers = _load_apply_approvers()
    if not incident_id:
        return False, "MCP_QUARANTINE_INCIDENT_ID is required for --apply"
    if len(approvers) < 2:
        return (
            False,
            "two distinct approvers are required for --apply via "
            "MCP_QUARANTINE_APPROVER_EMAILS, MCP_QUARANTINE_APPROVER_IDS, "
            "or MCP_QUARANTINE_APPROVER + MCP_QUARANTINE_SECOND_APPROVER",
        )
    return True, ""


def _quarantine_entry(
    target: Target, *, incident_id: str, approvers: tuple[str, ...]
) -> dict[str, Any]:
    """Structured quarantine record the MCP client reads to filter its tool list."""
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "mcp_tool_quarantine_entry",
        "source_skill": SKILL_NAME,
        "tool_name": target.tool_name,
        "session_uid": target.session_uid,
        "fingerprint": target.fingerprint,
        "producer_skill": target.producer_skill,
        "finding_uid": target.finding_uid,
        "incident_id": incident_id,
        "approver": approvers[0] if approvers else "",
        "approvers": list(approvers),
        "approver_count": len(approvers),
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
    }


def _plan_record(
    target: Target,
    *,
    status: str,
    detail: str | None,
    dry_run: bool,
    entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": RECORD_PLAN if dry_run else RECORD_ACTION,
        "source_skill": SKILL_NAME,
        "target": {
            "provider": "MCP",
            "tool_name": target.tool_name,
            "session_uid": target.session_uid,
            "fingerprint": target.fingerprint,
        },
        "actions": [
            {
                "step": STEP_QUARANTINE_TOOL,
                "endpoint": "APPEND quarantine_file",
                "status": status,
                "detail": detail,
            }
        ],
        "quarantine_entry": entry,
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
            "provider": "MCP",
            "tool_name": target.tool_name,
            "session_uid": target.session_uid,
            "fingerprint": target.fingerprint,
        },
        "actions": [],
        "status": status,
        "status_detail": detail,
        "dry_run": dry_run,
        "time_ms": int(datetime.now(timezone.utc).timestamp() * 1000),
        "finding_uid": target.finding_uid,
    }


def quarantine_tool(
    target: Target,
    *,
    store: QuarantineStore,
    audit: AuditWriter,
    incident_id: str,
    approvers: tuple[str, ...],
) -> dict[str, Any]:
    entry = _quarantine_entry(target, incident_id=incident_id, approvers=approvers)
    first_audit = audit.record(
        target=target,
        step=STEP_QUARANTINE_TOOL,
        status=STATUS_IN_PROGRESS,
        detail=f"about to quarantine `{target.tool_name}`",
        incident_id=incident_id,
        approvers=approvers,
    )
    try:
        store.append(entry)
    except Exception as exc:
        audit.record(
            target=target,
            step=STEP_QUARANTINE_TOOL,
            status=STATUS_FAILURE,
            detail=str(exc),
            incident_id=incident_id,
            approvers=approvers,
        )
        record = _plan_record(
            target, status=STATUS_FAILURE, detail=str(exc), dry_run=False, entry=entry
        )
        record["audit"] = first_audit
        return record

    second_audit = audit.record(
        target=target,
        step=STEP_QUARANTINE_TOOL,
        status=STATUS_SUCCESS,
        detail=f"quarantined `{target.tool_name}`",
        incident_id=incident_id,
        approvers=approvers,
    )
    record = _plan_record(
        target,
        status=STATUS_SUCCESS,
        detail=f"appended `{target.tool_name}` to quarantine file",
        dry_run=False,
        entry=entry,
    )
    record["audit"] = second_audit
    record["incident_id"] = incident_id
    record["approver"] = approvers[0] if approvers else ""
    record["approvers"] = list(approvers)
    record["approver_count"] = len(approvers)
    return record


def reverify_target(
    target: Target,
    *,
    store: QuarantineStore,
    now_ms: int | None = None,
    remediated_at_ms: int | None = None,
) -> list[dict[str, Any]]:
    """Re-verify the tool is still on the quarantine list. Emits one
    `remediation_verification` record always; on DRIFT also emits an OCSF
    Detection Finding via the shared `_shared/remediation_verifier.py` contract."""
    checked_at_ms = (
        now_ms if now_ms is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    )
    remediated_at_ms_resolved = remediated_at_ms if remediated_at_ms is not None else checked_at_ms

    reference = RemediationReference(
        remediation_skill=SKILL_NAME,
        remediation_action_uid=_deterministic_uid(
            "quarantine", target.tool_name, target.session_uid
        ),
        target_provider="MCP",
        target_identifier=target.tool_name,
        original_finding_uid=target.finding_uid,
        remediated_at_ms=remediated_at_ms_resolved,
    )
    expected = f"`{target.tool_name}` present in MCP quarantine file"

    try:
        tools = store.list_tools()
    except Exception as exc:
        result = VerificationResult(
            status=VerificationStatus.UNREACHABLE,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="quarantine store unreadable; cannot determine state",
            detail=str(exc),
        )
        record = build_verification_record(
            reference=reference, result=result, verifier_skill=SKILL_NAME
        )
        record["target"] = {
            "provider": "MCP",
            "tool_name": target.tool_name,
            "session_uid": target.session_uid,
        }
        return [record]

    if target.tool_name in tools:
        result = VerificationResult(
            status=VerificationStatus.VERIFIED,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state=f"present in quarantine file (file lists {len(tools)} tools)",
            detail="quarantine entry confirmed",
        )
    else:
        result = VerificationResult(
            status=VerificationStatus.DRIFT,
            checked_at_ms=checked_at_ms,
            sla_deadline_ms=sla_deadline(remediated_at_ms_resolved, DEFAULT_VERIFICATION_SLA_MS),
            expected_state=expected,
            actual_state="not present in quarantine file — entry was removed or never landed",
            detail=f"tool `{target.tool_name}` is no longer quarantined",
        )

    record = build_verification_record(
        reference=reference, result=result, verifier_skill=SKILL_NAME
    )
    record["target"] = {
        "provider": "MCP",
        "tool_name": target.tool_name,
        "session_uid": target.session_uid,
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
    store: QuarantineStore,
    apply: bool = False,
    reverify: bool = False,
    audit: AuditWriter | None = None,
    protected_prefixes: Iterable[str] = DEFAULT_PROTECTED_TOOL_PREFIXES,
    incident_id: str = "",
    approvers: tuple[str, ...] = (),
) -> Iterator[dict[str, Any]]:
    protected_prefixes = tuple(protected_prefixes)

    for target, _ in parse_targets(events):
        if target is None:
            continue

        dry_run = not apply and not reverify

        if not target.tool_name:
            yield _skip_record(
                target,
                status=STATUS_SKIPPED_NO_TOOL,
                detail="finding did not carry a tool.name observable; cannot quarantine",
                dry_run=dry_run,
            )
            continue

        protected, prefix = is_protected_tool(target.tool_name, protected_prefixes)
        if protected:
            status = STATUS_SKIPPED_PROTECTED if apply else STATUS_WOULD_VIOLATE_PROTECTED
            yield _skip_record(
                target,
                status=status,
                detail=f"tool `{target.tool_name}` matched protected prefix `{prefix}`",
                dry_run=dry_run,
            )
            continue

        if reverify:
            yield from reverify_target(target, store=store)
            continue

        if not apply:
            entry = _quarantine_entry(target, incident_id=incident_id, approvers=approvers)
            yield _plan_record(
                target,
                status=STATUS_PLANNED,
                detail=f"dry-run: would quarantine `{target.tool_name}`",
                dry_run=True,
                entry=entry,
            )
            continue

        if audit is None:
            raise ValueError("audit writer is required under --apply")
        yield quarantine_tool(
            target,
            store=store,
            audit=audit,
            incident_id=incident_id,
            approvers=approvers,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan, apply, or re-verify MCP tool quarantine entries."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Append the offending tool to the quarantine file after approval gates pass.",
    )
    parser.add_argument(
        "--reverify",
        action="store_true",
        help="Read-only verification: confirm the tool is still on the quarantine list.",
    )
    parser.add_argument(
        "--quarantine-file",
        help=(
            "Path to the JSONL quarantine file the MCP client filters against. "
            "Defaults to $MCP_QUARANTINE_FILE or ~/.mcp-quarantine.jsonl"
        ),
    )
    args = parser.parse_args(argv)

    if args.apply and args.reverify:
        print("--apply and --reverify are mutually exclusive", file=sys.stderr)
        return 2

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    quarantine_path = Path(
        args.quarantine_file
        or os.environ.get("MCP_QUARANTINE_FILE")
        or (Path.home() / ".mcp-quarantine.jsonl")
    )
    store = JSONLQuarantineFile(path=quarantine_path)

    try:
        audit: AuditWriter | None = None
        incident_id = ""
        approvers: tuple[str, ...] = ()
        if args.apply:
            ok, reason = check_apply_gate()
            if not ok:
                print(reason, file=sys.stderr)
                return 2
            incident_id = os.environ["MCP_QUARANTINE_INCIDENT_ID"].strip()
            approvers = _load_apply_approvers()
            audit = DualAuditWriter(
                dynamodb_table=os.environ["MCP_QUARANTINE_AUDIT_DYNAMODB_TABLE"],
                s3_bucket=os.environ["MCP_QUARANTINE_AUDIT_BUCKET"],
                kms_key_arn=os.environ["KMS_KEY_ARN"],
            )

        for record in run(
            load_jsonl(in_stream),
            store=store,
            apply=args.apply,
            reverify=args.reverify,
            audit=audit,
            incident_id=incident_id,
            approvers=approvers,
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
