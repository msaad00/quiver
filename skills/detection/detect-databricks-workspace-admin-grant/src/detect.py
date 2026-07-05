"""Detect Databricks workspace / account admin grants from OCSF 1.8 events.

Reads OCSF 1.8 API Activity (class 6003) records emitted by the upstream
Databricks audit-log ingest pipeline and emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1098.003 (Additional Cloud Roles)
when a workspace or account admin grant happens outside the
break-glass / change-window combination.

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

_log = get_logger(__name__, skill="detect-databricks-workspace-admin-grant", layer="detection")

SKILL_NAME = "detect-databricks-workspace-admin-grant"
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

ACCOUNT_SET_ADMIN_OPERATION = "accounts.setAdmin"
ADD_USER_TO_GROUP_OPERATION = "iam.addUserToGroup"
ANCHOR_OPERATIONS = frozenset({ACCOUNT_SET_ADMIN_OPERATION, ADD_USER_TO_GROUP_OPERATION})

ADMIN_GROUP_NAMES = frozenset({"admins", "account_admins"})

AUTHORIZED_GRANTERS_ENV = "DATABRICKS_AUTHORIZED_GRANTERS"
GRANT_WINDOW_ENV = "DATABRICKS_GRANT_WINDOW_HOURS_UTC"
DEFAULT_GRANT_WINDOW = "08-18"

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0003"
MITRE_TACTIC_NAME = "Persistence"
MITRE_TECHNIQUE_UID = "T1098.003"
MITRE_TECHNIQUE_NAME = "Additional Cloud Roles"

OWASP_FINDING_TYPE = "OWASP-Top-10-A01"


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


def _event_utc_hour(event: dict[str, Any]) -> int:
    time_ms = _event_time(event)
    if time_ms <= 0:
        return -1
    dt = datetime.fromtimestamp(time_ms / 1000.0, tz=timezone.utc)
    return dt.hour


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


def _group_name(event: dict[str, Any]) -> str:
    return str(_databricks_block(event).get("group_name") or "").strip().lower()


def _grantee(event: dict[str, Any]) -> str:
    raw = _databricks_block(event).get("grantee") or {}
    if isinstance(raw, dict):
        return str(raw.get("uid") or raw.get("email_addr") or raw.get("name") or "").strip()
    return str(raw or "").strip()


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _authorized_granters() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_GRANTERS_ENV)


def _grant_window_hours() -> tuple[int, int]:
    raw = os.environ.get(GRANT_WINDOW_ENV, "").strip() or DEFAULT_GRANT_WINDOW
    parts = raw.split("-")
    if len(parts) != 2:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="invalid_grant_window",
            message=(
                f"{GRANT_WINDOW_ENV}={raw!r} did not parse as `HH-HH`; falling "
                f"back to default {DEFAULT_GRANT_WINDOW}."
            ),
            env=GRANT_WINDOW_ENV,
            raw=raw,
        )
        parts = DEFAULT_GRANT_WINDOW.split("-")
    try:
        start = int(parts[0])
        end = int(parts[1])
    except ValueError:
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="invalid_grant_window",
            message=(
                f"{GRANT_WINDOW_ENV}={raw!r} contained non-integer hours; "
                f"falling back to default {DEFAULT_GRANT_WINDOW}."
            ),
            env=GRANT_WINDOW_ENV,
            raw=raw,
        )
        start, end = (int(part) for part in DEFAULT_GRANT_WINDOW.split("-"))
    if not (0 <= start <= 23 and 0 <= end <= 23):
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="invalid_grant_window",
            message=(
                f"{GRANT_WINDOW_ENV}={raw!r} hours out of 0-23 range; "
                f"falling back to default {DEFAULT_GRANT_WINDOW}."
            ),
            env=GRANT_WINDOW_ENV,
            raw=raw,
        )
        start, end = (int(part) for part in DEFAULT_GRANT_WINDOW.split("-"))
    return start, end


def _within_window(hour: int, start: int, end: int) -> bool:
    if hour < 0:
        return False
    if start <= end:
        return start <= hour < end
    # Wraps midnight, e.g. 22-06.
    return hour >= start or hour < end


def _is_databricks_event(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _vendor_name(event) == DATABRICKS_VENDOR_NAME:
        return True
    return _producer(event) in ACCEPTED_PRODUCERS


def _finding_uid(granter: str, grantee: str, group: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{granter}|{grantee}|{group}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-databricks-workspace-admin-grant-{digest}"


def _build_native_finding(
    event: dict[str, Any],
    *,
    operation: str,
    grantee: str,
    group: str,
    granter_authorized: bool,
    within_window: bool,
    allowlist_mode: str,
    event_hour: int,
    window_start: int,
    window_end: int,
) -> dict[str, Any]:
    granter = _actor_uid(event)
    granter_name = _actor_name(event)
    workspace_id = _workspace_id(event)
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(granter, grantee, group, time_ms)

    reasons: list[str] = []
    if not granter_authorized:
        if allowlist_mode == "fail-open":
            reasons.append("DATABRICKS_AUTHORIZED_GRANTERS empty (fail-open)")
        else:
            reasons.append("granter not in DATABRICKS_AUTHORIZED_GRANTERS")
    if not within_window:
        reasons.append(
            f"event hour {event_hour:02d} outside DATABRICKS_GRANT_WINDOW_HOURS_UTC "
            f"({window_start:02d}-{window_end:02d})"
        )

    description = (
        f"Databricks principal '{granter_name or granter}' granted admin privilege "
        f"to '{grantee}' (group '{group or 'unknown'}', operation '{operation}') in "
        f"workspace '{workspace_id or 'unknown'}'. " + " · ".join(reasons) + "."
    )

    observables: list[dict[str, Any]] = [
        {"name": "cloud.provider", "type": "Other", "value": "Databricks"},
        {"name": "actor.user.uid", "type": "User Name", "value": granter},
    ]
    if granter_name and granter_name != granter:
        observables.append({"name": "actor.user.name", "type": "User Name", "value": granter_name})
    if workspace_id:
        observables.append(
            {"name": "databricks.workspace_id", "type": "Resource UID", "value": workspace_id}
        )
    observables.append({"name": "api.operation", "type": "Other", "value": operation})
    if grantee:
        observables.append({"name": "databricks.grantee", "type": "User Name", "value": grantee})
    if group:
        observables.append({"name": "databricks.group_name", "type": "Other", "value": group})
    observables.append(
        {"name": "databricks.event_utc_hour", "type": "Other", "value": str(event_hour)}
    )

    evidence: dict[str, Any] = {
        "events_observed": 1,
        "api_operation": operation,
        "granter": granter,
        "grantee": grantee,
        "group_name": group,
        "workspace_id": workspace_id,
        "allowlist_mode": allowlist_mode,
        "granter_authorized": granter_authorized,
        "within_change_window": within_window,
        "event_utc_hour": event_hour,
        "change_window_utc": f"{window_start:02d}-{window_end:02d}",
        "violations": reasons,
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
        "title": (f"Databricks admin privilege granted to '{grantee}' outside change window"),
        "description": description,
        "finding_types": ["databricks-workspace-admin-grant", OWASP_FINDING_TYPE],
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
                "identities",
                "rbac",
                "persistence",
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
    allowlist = _authorized_granters()
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14", "OWASP Top 10"),
        "providers": ("databricks",),
        "asset_classes": ("warehouse", "identities", "rbac"),
        "attack_coverage": {
            "databricks": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": sorted(ANCHOR_OPERATIONS),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "authorized_granter_count": len(allowlist),
            "allowlist_mode": "fail-open" if not allowlist else "enforced",
            "default_change_window_utc": DEFAULT_GRANT_WINDOW,
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

    allowlist = _authorized_granters()
    allowlist_mode = "enforced" if allowlist else "fail-open"
    if allowlist_mode == "fail-open":
        emit_stderr_event(
            SKILL_NAME,
            level="warning",
            event="allowlist_fail_open",
            message=(
                "DATABRICKS_AUTHORIZED_GRANTERS is empty; firing on every admin "
                "grant whose hour is also outside the change window OR (and) the "
                "granter is unknown. Set the allow-list to scope to break-glass identities."
            ),
        )

    window_start, window_end = _grant_window_hours()
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
                message="skipping admin-grant event with no actor.user.uid",
                event_uid=_metadata_uid(event),
                api_operation=operation,
            )
            continue
        group = _group_name(event)
        if operation == ADD_USER_TO_GROUP_OPERATION and group not in ADMIN_GROUP_NAMES:
            continue
        grantee = _grantee(event)
        if not grantee:
            continue
        meta_uid = _metadata_uid(event)
        if meta_uid and meta_uid in seen_uids:
            continue

        granter = _actor_uid(event)
        granter_authorized = granter in allowlist if allowlist_mode == "enforced" else False
        event_hour = _event_utc_hour(event)
        within_window = _within_window(event_hour, window_start, window_end)

        if granter_authorized and within_window:
            continue

        if meta_uid:
            seen_uids.add(meta_uid)

        # accounts.setAdmin implies the account_admins group even when the
        # upstream ingester did not surface it explicitly.
        effective_group = group
        if not effective_group and operation == ACCOUNT_SET_ADMIN_OPERATION:
            effective_group = "account_admins"

        native_finding = _build_native_finding(
            event,
            operation=operation,
            grantee=grantee,
            group=effective_group,
            granter_authorized=granter_authorized,
            within_window=within_window,
            allowlist_mode=allowlist_mode,
            event_hour=event_hour,
            window_start=window_start,
            window_end=window_end,
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
            "Detect Databricks workspace / account admin grants outside the change "
            "window from OCSF 1.8 API Activity 6003 input."
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
            "detect-databricks-workspace-admin-grant starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-databricks-workspace-admin-grant complete",
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
