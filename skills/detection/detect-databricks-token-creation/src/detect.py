"""Detect Databricks personal access token (PAT) creation from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
Databricks audit-log ingest pipeline and emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1098.001 (Additional Cloud Credentials)
for every successful `tokens/create` issuance. PAT issuance is the workspace-
level persistence anchor for Databricks: once issued, the token grants
headless API access without an interactive login.

Contract: see ../SKILL.md and ../REFERENCES.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-databricks-token-creation", layer="detection")

SKILL_NAME = "detect-databricks-token-creation"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"

OUTPUT_FORMATS = ("ocsf", "native")

API_ACTIVITY_CLASS_UID = 6003
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

DATABRICKS_VENDOR_NAME = "Databricks"

# Source skills whose normalized output we trust as "Databricks API Activity".
# The dedicated `ingest-databricks-audit-ocsf` ingester is on the roadmap (see
# #436); until it lands we accept either that producer name or the read-only
# `source-databricks-query` adapter when the events carry the
# Databricks-shaped `unmapped.databricks` block.
ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-databricks-audit-ocsf",
        "source-databricks-query",
    }
)

# Databricks audit-log action names (Token Management surface). Only
# `tokens/create` is a persistence anchor; the other entries are listed so
# the detector can emit `unmapped_event_type` telemetry for unknown verbs in
# the same family without firing a false positive.
TOKEN_CREATE_OPERATION = "tokens/create"
KNOWN_TOKEN_OPERATIONS = frozenset(
    {
        TOKEN_CREATE_OPERATION,
        "tokens/list",
        "tokens/delete",
        "tokens/revoke",
        "tokens/get",
    }
)
TOKEN_FAMILY_PREFIX = "tokens/"

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098"
MITRE_TECHNIQUE_NAME = "Account Manipulation"
MITRE_SUBTECHNIQUE_UID = "T1098.001"
MITRE_SUBTECHNIQUE_NAME = "Additional Cloud Credentials"

# OWASP LLM Top 10 — token issuance with no human-in-the-loop check is a
# control-plane mirror of LLM02 (insecure output handling): the agent
# pipeline outputs a long-lived credential without operator approval.
OWASP_FINDING_TYPE = "OWASP-LLM-Top-10-LLM02"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    raw = event.get("time")
    if raw is None:
        raw = event.get("time_ms") or 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    return str(metadata.get("uid") or "")


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _vendor_name(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    return str(product.get("vendor_name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "").strip()


def _actor_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()


def _actor_email(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("email_addr") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("email_addr") or user.get("uid") or "").strip()


def _databricks_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("databricks") or {}
    return block if isinstance(block, dict) else {}


def _workspace_id(event: dict[str, Any]) -> str:
    raw = _databricks_block(event).get("workspace_id")
    return str(raw or "").strip()


def _token_id(event: dict[str, Any]) -> str:
    raw = _databricks_block(event).get("token_id")
    return str(raw or "").strip()


def _token_comment(event: dict[str, Any]) -> str:
    raw = _databricks_block(event).get("comment")
    return str(raw or "").strip()


def _token_lifetime_seconds(event: dict[str, Any]) -> int | None:
    raw = _databricks_block(event).get("lifetime_seconds")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "").strip()


def _is_databricks_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _vendor_name(event) == DATABRICKS_VENDOR_NAME:
        return True
    return _producer(event) in ACCEPTED_PRODUCERS


def _finding_uid(event_uid: str, actor_uid: str, workspace_id: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{actor_uid}|{workspace_id}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-databricks-token-create-{digest}"


def _build_native_finding(event: dict[str, Any]) -> dict[str, Any]:
    time_ms = _event_time(event) or _now_ms()
    actor_uid = _actor_uid(event)
    actor_email = _actor_email(event)
    actor_name = _actor_name(event)
    workspace_id = _workspace_id(event)
    token_id = _token_id(event)
    comment = _token_comment(event)
    lifetime = _token_lifetime_seconds(event)
    src_ip = _src_ip(event)
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(event_uid, actor_uid, workspace_id, time_ms)

    lifetime_phrase = (
        f"requested lifetime {lifetime} seconds"
        if lifetime is not None and lifetime > 0
        else "no expiry requested (default policy lets the token live indefinitely)"
    )
    description = (
        f"Databricks principal '{actor_name or actor_uid}' successfully created a "
        f"personal access token in workspace '{workspace_id or 'unknown'}' "
        f"({lifetime_phrase}). Once issued, a Databricks PAT grants headless API "
        f"access at the principal's full scope until explicitly revoked."
    )

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "Databricks"},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
    ]
    if actor_email:
        observables.append(
            {"name": "actor.user.email_addr", "type": "Email Address", "value": actor_email}
        )
    if workspace_id:
        observables.append(
            {"name": "databricks.workspace_id", "type": "Resource UID", "value": workspace_id}
        )
    observables.append({"name": "api.operation", "type": "Other", "value": TOKEN_CREATE_OPERATION})
    if token_id:
        observables.append(
            {"name": "databricks.token_id", "type": "Resource UID", "value": token_id}
        )
    if comment:
        observables.append({"name": "databricks.token_comment", "type": "Other", "value": comment})
    if lifetime is not None:
        observables.append(
            {"name": "databricks.token_lifetime_seconds", "type": "Other", "value": str(lifetime)}
        )
    if src_ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": src_ip})

    evidence: dict[str, Any] = {
        "events_observed": 1,
        "api_operation": TOKEN_CREATE_OPERATION,
        "workspace_id": workspace_id,
        "raw_event_uids": [event_uid] if event_uid else [],
    }
    if token_id:
        evidence["token_id"] = token_id
    if comment:
        evidence["token_comment"] = comment
    if lifetime is not None:
        evidence["token_lifetime_seconds"] = lifetime

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Databricks",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "Databricks personal access token created",
        "description": description,
        "finding_types": ["databricks-token-creation", OWASP_FINDING_TYPE],
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
                "sub_technique_uid": MITRE_SUBTECHNIQUE_UID,
                "sub_technique_name": MITRE_SUBTECHNIQUE_NAME,
            }
        ],
        "observables": observables,
        "evidence": evidence,
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
    attack = native_finding["mitre_attacks"][0]
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": native_finding["severity_id"],
        "status_id": native_finding["status_id"],
        "time": native_finding["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native_finding["event_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["data-warehouse", "databricks", "credentials", "persistence", "detection"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "first_seen_time": native_finding["first_seen_time_ms"],
            "last_seen_time": native_finding["last_seen_time_ms"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {"name": attack["tactic_name"], "uid": attack["tactic_uid"]},
                    "technique": {"name": attack["technique_name"], "uid": attack["technique_uid"]},
                    "sub_technique": {
                        "name": attack["sub_technique_name"],
                        "uid": attack["sub_technique_uid"],
                    },
                }
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP LLM Top 10"),
        "providers": ("databricks",),
        "asset_classes": ("warehouse", "tokens", "identities"),
        "attack_coverage": {
            "databricks": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": [TOKEN_CREATE_OPERATION],
                "techniques": [MITRE_TECHNIQUE_UID, MITRE_SUBTECHNIQUE_UID],
            }
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format: {output_format}",
            hint=f"choose one of: {', '.join(OUTPUT_FORMATS)}",
        )

    seen_uids: set[str] = set()
    for event in events:
        if not _is_databricks_event(event):
            continue
        operation = _api_operation(event)
        if not operation:
            continue
        op_lower = operation.lower()
        if op_lower != TOKEN_CREATE_OPERATION:
            # Stay quiet on non-token API noise; only flag unknown verbs in
            # the `tokens/*` family so operators can grep the unmapped feed
            # and propose new mappings.
            if op_lower.startswith(TOKEN_FAMILY_PREFIX) and op_lower not in KNOWN_TOKEN_OPERATIONS:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="unmapped_event_type",
                    message=(
                        f"unrecognized Databricks token-management operation `{operation}`; "
                        "treating as no-fire — propose a mapping if this should anchor a finding"
                    ),
                    api_operation=operation,
                    event_uid=_metadata_uid(event),
                )
            continue
        if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
            continue
        if not _actor_uid(event):
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_actor",
                message="skipping tokens/create event with no actor.user.uid or email_addr",
                event_uid=_metadata_uid(event),
            )
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in seen_uids:
            continue
        if meta_uid:
            seen_uids.add(meta_uid)

        native_finding = _build_native_finding(event)
        if output_format == "native":
            yield native_finding
        else:
            yield _render_ocsf_finding(native_finding)


def load_jsonl(stream: Iterable[str]) -> Iterator[dict[str, Any]]:
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
                error=str(exc),
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Detect Databricks personal access token creation from OCSF 1.8 "
            "API Activity 6003 input."
        )
    )
    parser.add_argument(
        "input", nargs="?", help="OCSF 1.8 API Activity 6003 JSONL input. Defaults to stdin."
    )
    parser.add_argument(
        "--output", "-o", help="Detection Finding JSONL output. Defaults to stdout."
    )
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Output format.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            "detect-databricks-token-creation starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-databricks-token-creation complete",
            extra={"findings_emitted": findings_emitted},
        )
    except SkillError as exc:
        return emit_error(SKILL_NAME, exc)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return emit_error(
            SKILL_NAME,
            ContractError(
                f"input is not JSONL: {exc}",
                hint="ensure each input line is a valid OCSF 1.8 API Activity 6003 JSON object",
            ),
        )
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
