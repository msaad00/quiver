"""Detect Databricks Unity Catalog cross-workspace / external Delta Sharing.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
Databricks audit-log ingest pipeline and emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1537 (Transfer Data to Cloud Account)
when a Delta Sharing recipient is created / updated as external (or outside
the operator allow-list) or when a Unity Catalog share is published to a
recipient outside the allow-list.

Contract: see ../SKILL.md and ../REFERENCES.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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

_log = get_logger(
    __name__,
    skill="detect-databricks-unity-catalog-cross-workspace-share",
    layer="detection",
)

SKILL_NAME = "detect-databricks-unity-catalog-cross-workspace-share"
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

ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-databricks-audit-ocsf",
        "source-databricks-query",
    }
)

AUTHORIZED_RECIPIENTS_ENV = "DATABRICKS_AUTHORIZED_RECIPIENTS"

# Recognized Unity Catalog Delta-Sharing operations.
RECIPIENT_OPERATIONS = frozenset(
    {
        "unityCatalog.CreateRecipient",
        "unityCatalog.UpdateRecipient",
    }
)
SHARE_OPERATIONS = frozenset(
    {
        "unityCatalog.CreateShare",
        "unityCatalog.UpdateShare",
    }
)
ANCHOR_OPERATIONS = RECIPIENT_OPERATIONS | SHARE_OPERATIONS

EXTERNAL_RECIPIENT_TYPE = "EXTERNAL"

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0010"
MITRE_TACTIC_NAME = "Exfiltration"
MITRE_TECHNIQUE_UID = "T1537"
MITRE_TECHNIQUE_NAME = "Transfer Data to Cloud Account"

OWASP_FINDING_TYPE = "OWASP-Top-10-A04"


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


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("email_addr") or user.get("uid") or "").strip()


def _databricks_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("databricks") or {}
    return block if isinstance(block, dict) else {}


def _workspace_id(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("workspace_id") or "").strip()


def _recipient_block(event: dict[str, Any]) -> dict[str, Any]:
    block = _databricks_block(event).get("recipient") or {}
    return block if isinstance(block, dict) else {}


def _recipient_id(event: dict[str, Any]) -> str:
    return str(
        _recipient_block(event).get("id") or _recipient_block(event).get("name") or ""
    ).strip()


def _recipient_type(event: dict[str, Any]) -> str:
    return str(_recipient_block(event).get("type") or "").strip().upper()


def _share_block(event: dict[str, Any]) -> dict[str, Any]:
    block = _databricks_block(event).get("share") or {}
    return block if isinstance(block, dict) else {}


def _share_name(event: dict[str, Any]) -> str:
    return str(_share_block(event).get("name") or "").strip()


def _share_recipients(event: dict[str, Any]) -> list[str]:
    raw = _share_block(event).get("recipients") or []
    if isinstance(raw, str):
        raw = [part.strip() for part in raw.split(",") if part.strip()]
    if not isinstance(raw, list):
        return []
    return sorted({str(item).strip() for item in raw if str(item).strip()})


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _authorized_recipients() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_RECIPIENTS_ENV)


def _is_databricks_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _vendor_name(event) == DATABRICKS_VENDOR_NAME:
        return True
    return _producer(event) in ACCEPTED_PRODUCERS


def _finding_uid(
    event_uid: str, actor_uid: str, recipient_id: str, share_name: str, time_ms: int
) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{actor_uid}|{recipient_id}|{share_name}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-databricks-uc-cross-workspace-share-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    *,
    operation: str,
    recipient_id: str,
    recipient_type: str,
    share_name: str,
    bound_recipients: list[str],
    allowlist_mode: str,
) -> dict[str, Any]:
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    workspace_id = _workspace_id(event)
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(event_uid, actor_uid, recipient_id, share_name, time_ms)

    if operation in RECIPIENT_OPERATIONS:
        title = (
            f"Databricks Delta Sharing recipient '{recipient_id}' bound as external "
            f"in workspace '{workspace_id or 'unknown'}'"
        )
        description = (
            f"Databricks principal '{actor_name or actor_uid}' configured Delta Sharing "
            f"recipient '{recipient_id}' (type={recipient_type or 'EXTERNAL'}) in workspace "
            f"'{workspace_id or 'unknown'}'. External Delta Sharing publishes catalog objects "
            "outside the producing workspace's audit and network controls."
        )
    else:
        title = (
            f"Databricks Unity Catalog share '{share_name}' bound to recipients outside "
            "the allow-list"
        )
        description = (
            f"Databricks principal '{actor_name or actor_uid}' attached Unity Catalog share "
            f"'{share_name}' to recipient(s) {bound_recipients or [recipient_id] or ['n/a']} "
            f"in workspace '{workspace_id or 'unknown'}'. The bound recipient(s) fall outside "
            "DATABRICKS_AUTHORIZED_RECIPIENTS — data leaves the producing workspace."
        )
    if allowlist_mode == "fail-open":
        description += (
            " DATABRICKS_AUTHORIZED_RECIPIENTS is empty; the detector fired in fail-open "
            "mode and surfaced every external recipient / share. Set the allow-list "
            "explicitly in production to scope the detection."
        )

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "Databricks"},
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
    ]
    if actor_name and actor_name != actor_uid:
        observables.append({"name": "actor.user.name", "type": "User Name", "value": actor_name})
    if workspace_id:
        observables.append(
            {"name": "databricks.workspace_id", "type": "Resource UID", "value": workspace_id}
        )
    observables.append({"name": "api.operation", "type": "Other", "value": operation})
    if recipient_id:
        observables.append(
            {"name": "databricks.recipient_id", "type": "Resource UID", "value": recipient_id}
        )
    if recipient_type:
        observables.append(
            {"name": "databricks.recipient_type", "type": "Other", "value": recipient_type}
        )
    if share_name:
        observables.append(
            {"name": "databricks.share_name", "type": "Resource UID", "value": share_name}
        )
    for bound in bound_recipients:
        observables.append(
            {"name": "databricks.share_recipient", "type": "Resource UID", "value": bound}
        )

    evidence: dict[str, Any] = {
        "events_observed": 1,
        "api_operation": operation,
        "workspace_id": workspace_id,
        "recipient_id": recipient_id,
        "recipient_type": recipient_type,
        "share_name": share_name,
        "share_recipients": bound_recipients,
        "allowlist_mode": allowlist_mode,
        "raw_event_uids": [event_uid] if event_uid else [],
    }

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
        "title": title,
        "description": description,
        "finding_types": ["databricks-uc-cross-workspace-share", OWASP_FINDING_TYPE],
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": MITRE_TACTIC_UID,
                "tactic_name": MITRE_TACTIC_NAME,
                "technique_uid": MITRE_TECHNIQUE_UID,
                "technique_name": MITRE_TECHNIQUE_NAME,
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
            "labels": [
                "data-warehouse",
                "databricks",
                "unity-catalog",
                "delta-sharing",
                "exfiltration",
                "detection",
            ],
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
                }
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    allowlist = _authorized_recipients()
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP Top 10"),
        "providers": ("databricks",),
        "asset_classes": ("warehouse", "unity-catalog", "delta-sharing"),
        "attack_coverage": {
            "databricks": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": sorted(ANCHOR_OPERATIONS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "authorized_recipient_count": len(allowlist),
            "allowlist_mode": "fail-open" if not allowlist else "enforced",
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

    allowlist = _authorized_recipients()
    allowlist_mode = "enforced" if allowlist else "fail-open"
    if allowlist_mode == "fail-open":
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="allowlist_fail_open",
            message=(
                "DATABRICKS_AUTHORIZED_RECIPIENTS is empty; firing on every external "
                "Delta Sharing recipient / off-allow-list share. Set the allow-list "
                "to scope the detection to documented data-sharing identities."
            ),
        )

    seen_uids: set[str] = set()
    for event in events:
        if not _is_databricks_event(event):
            continue
        operation = _api_operation(event)
        if operation not in ANCHOR_OPERATIONS:
            continue
        if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
            continue
        if not _actor_uid(event):
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_actor",
                message="skipping Unity Catalog event with no actor.user.uid",
                event_uid=_metadata_uid(event),
                api_operation=operation,
            )
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in seen_uids:
            continue

        recipient_id = _recipient_id(event)
        recipient_type = _recipient_type(event)
        share_name = _share_name(event)
        bound_recipients = _share_recipients(event)

        should_fire = False
        if operation in RECIPIENT_OPERATIONS:
            # Only fire when the recipient is external AND outside the allow-list.
            if recipient_type == EXTERNAL_RECIPIENT_TYPE:
                if allowlist_mode == "fail-open" or recipient_id not in allowlist:
                    should_fire = True
        else:
            # Share create / update — fire when any bound recipient is outside
            # the allow-list. The fail-open default treats every bound recipient
            # as off-allow-list.
            target_recipients = bound_recipients or ([recipient_id] if recipient_id else [])
            if target_recipients:
                if allowlist_mode == "fail-open":
                    should_fire = True
                else:
                    should_fire = any(rid not in allowlist for rid in target_recipients)

        if not should_fire:
            continue

        if meta_uid:
            seen_uids.add(meta_uid)

        native_finding = _build_native_finding(
            event,
            operation=operation,
            recipient_id=recipient_id,
            recipient_type=recipient_type,
            share_name=share_name,
            bound_recipients=bound_recipients,
            allowlist_mode=allowlist_mode,
        )
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
            "Detect Databricks Unity Catalog cross-workspace / external Delta Sharing "
            "from OCSF 1.8 API Activity 6003 input."
        )
    )
    parser.add_argument(
        "input", nargs="?", help="OCSF 1.8 API Activity 6003 JSONL input. Defaults to stdin."
    )
    parser.add_argument(
        "--output", "-o", help="Detection Finding JSONL output. Defaults to stdout."
    )
    parser.add_argument(
        "--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Output format."
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    findings_emitted = 0
    try:
        events = list(load_jsonl(in_stream))
        _log.info(
            "detect-databricks-unity-catalog-cross-workspace-share starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-databricks-unity-catalog-cross-workspace-share complete",
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
