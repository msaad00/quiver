"""Detect Snowflake replication-configuration changes to unauthorized accounts.

Reads OCSF 1.8 API Activity (class 6003) records carrying the Snowflake-shaped
`unmapped.snowflake.{database_name,target_accounts,operation_kind}` block and
emits OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1537
Transfer Data to Cloud Account whenever an account-replication or
database-replication operation targets an account not on the operator's
authorized list.

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
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import ContractError, SkillError, emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

_log = get_logger(__name__, skill="detect-snowflake-replication-config-change", layer="detection")

SKILL_NAME = "detect-snowflake-replication-config-change"
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

AUTHORIZED_TARGETS_ENV = "SNOWFLAKE_AUTHORIZED_REPLICATION_TARGETS"

REPLICATION_OPERATIONS = frozenset(
    {
        "ALTER_ACCOUNT_SET_REPLICATION",
        "ALTER_DATABASE_ENABLE_REPLICATION",
        "ALTER_DATABASE_ENABLE_FAILOVER",
        "CREATE_REPLICATION_GROUP",
        "ALTER_REPLICATION_GROUP",
        "CREATE_FAILOVER_GROUP",
        "ALTER_FAILOVER_GROUP",
    }
)

ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-snowflake-query-history-ocsf",
        "ingest-snowflake-access-history-ocsf",
        "source-snowflake-query",
    }
)

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


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "").replace("-", "_").upper()


def _actor_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "").strip()


def _snowflake_block(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped") or {}
    block = unmapped.get("snowflake") or {}
    return block if isinstance(block, dict) else {}


def _database_name(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("database_name") or "").strip()


def _operation_kind(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("operation_kind") or "").strip()


def _target_accounts(event: dict[str, Any]) -> list[str]:
    raw = _snowflake_block(event).get("target_accounts") or []
    if isinstance(raw, str):
        raw = [part.strip() for part in raw.split(",") if part.strip()]
    if not isinstance(raw, list):
        return []
    return sorted({str(account).strip() for account in raw if str(account).strip()})


def _authorized_targets() -> set[str]:
    raw = os.environ.get(AUTHORIZED_TARGETS_ENV, "")
    return {part.strip().upper() for part in raw.split(",") if part.strip()}


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if _api_operation(event) not in REPLICATION_OPERATIONS:
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    if not _actor_uid(event):
        return False
    return True


def _unauthorized_for(targets: list[str], allowlist: set[str]) -> list[str]:
    if not allowlist:
        # Fail open: every target is treated as unauthorized so the change is
        # surfaced regardless. The detector still emits a stderr warning so
        # operators see the missing allowlist.
        return list(targets)
    return [account for account in targets if account.upper() not in allowlist]


def _finding_uid(actor_uid: str, database_name: str, time_ms: int, operation: str) -> str:
    material = f"{actor_uid}|{database_name}|{time_ms}|{operation}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-snowflake-replication-config-change-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    unauthorized: list[str],
    allowlist_empty: bool,
) -> dict[str, Any]:
    actor_uid = _actor_uid(event)
    actor_name = _actor_name(event)
    database_name = _database_name(event) or "<account>"
    operation = _api_operation(event)
    operation_kind = _operation_kind(event) or operation.lower()
    target_accounts = _target_accounts(event)
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(actor_uid, database_name, time_ms, operation)

    if allowlist_empty and not target_accounts:
        # Account-level enablement with no specific targets but no allowlist
        # configured. Still high-signal.
        description = (
            f"Snowflake principal '{actor_name or actor_uid}' enabled account-level "
            "replication. No SNOWFLAKE_AUTHORIZED_REPLICATION_TARGETS allowlist is "
            "configured, so the change is reported for review. This primitive can be "
            "used to push entire databases to a controlled second account."
        )
        title = "Snowflake replication enabled (no allowlist configured)"
    else:
        description = (
            f"Snowflake principal '{actor_name or actor_uid}' issued {operation} on "
            f"database '{database_name}' targeting {len(unauthorized)} account(s) "
            f"({', '.join(unauthorized) or 'n/a'}) outside the authorized replication "
            "targets list. Replication / failover to an unauthorized account is a "
            "documented data-exfiltration path."
        )
        title = f"Snowflake replication configured to unauthorized account(s) for '{database_name}'"

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "actor.user.name", "type": "User Name", "value": actor_name or actor_uid},
        {"name": "snowflake.database_name", "type": "Resource UID", "value": database_name},
        {"name": "snowflake.operation", "type": "Other", "value": operation},
    ]
    observables.extend(
        {"name": "snowflake.target_account", "type": "Other", "value": account}
        for account in target_accounts
    )
    observables.extend(
        {"name": "snowflake.unauthorized_account", "type": "Other", "value": account}
        for account in unauthorized
    )

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Snowflake",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": title,
        "description": description,
        "finding_types": ["snowflake-replication-config-change", OWASP_FINDING_TYPE],
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
        "evidence": {
            "database_name": database_name,
            "operation": operation,
            "operation_kind": operation_kind,
            "target_accounts": target_accounts,
            "unauthorized_accounts": sorted(unauthorized),
            "allowlist_empty": allowlist_empty,
            "raw_event_uids": [event_uid] if event_uid else [],
        },
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
            "labels": ["data-warehouse", "snowflake", "exfiltration", "replication", "detection"],
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
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP Top 10"),
        "providers": ("snowflake",),
        "asset_classes": ("warehouse", "databases", "replication", "identities"),
        "attack_coverage": {
            "snowflake": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": sorted(REPLICATION_OPERATIONS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "allowlist_env": AUTHORIZED_TARGETS_ENV,
    }


def detect(
    events: Iterable[dict[str, Any]], output_format: str = "ocsf"
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(
            f"unsupported output_format: {output_format}",
            hint=f"choose one of: {', '.join(OUTPUT_FORMATS)}",
        )

    allowlist = _authorized_targets()
    allowlist_empty = not allowlist
    if allowlist_empty:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="allowlist_empty",
            message=(
                f"{AUTHORIZED_TARGETS_ENV} is empty; every replication configuration "
                "change will be reported. Set the env var to your authorized partner "
                "accounts to suppress benign rotations."
            ),
            env=AUTHORIZED_TARGETS_ENV,
        )

    dedupe: set[str] = set()
    for event in events:
        if not _is_relevant(event):
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in dedupe:
            continue
        if meta_uid:
            dedupe.add(meta_uid)
        targets = _target_accounts(event)
        unauthorized = _unauthorized_for(targets, allowlist)
        if not unauthorized and not allowlist_empty:
            # All targets are on the allowlist — benign rotation.
            continue
        native_finding = _build_native_finding(event, unauthorized, allowlist_empty)
        if output_format == "native":
            yield native_finding
        else:
            yield _render_ocsf_finding(native_finding)


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
        description="Detect Snowflake replication-configuration changes to unauthorized accounts."
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
            "detect-snowflake-replication-config-change starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-snowflake-replication-config-change complete",
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
