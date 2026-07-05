"""Detect Snowflake privileged-role grants by unauthorized granters from OCSF 1.8.

Reads OCSF 1.8 API Activity (class 6003) records carrying the Snowflake-shaped
`unmapped.snowflake.{granted_role,grantee_user,grantee_role}` block and emits
OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1098.003.

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

_log = get_logger(__name__, skill="detect-snowflake-unauthorized-grant", layer="detection")

SKILL_NAME = "detect-snowflake-unauthorized-grant"
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

ANCHOR_OPERATION = "GRANT_ROLE"

DEFAULT_PRIVILEGED_ROLES = ("ACCOUNTADMIN", "SECURITYADMIN", "ORGADMIN")
PRIVILEGED_ROLES_ENV = "SNOWFLAKE_PRIVILEGED_ROLES"
AUTHORIZED_GRANTERS_ENV = "SNOWFLAKE_AUTHORIZED_GRANTERS"

ACCEPTED_PRODUCERS = frozenset(
    {
        "ingest-snowflake-query-history-ocsf",
        "ingest-snowflake-access-history-ocsf",
        "source-snowflake-query",
    }
)

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
    return str(api.get("operation") or "").upper()


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


def _granted_role(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("granted_role") or "").strip().upper()


def _grantee_user(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("grantee_user") or "").strip()


def _grantee_role(event: dict[str, Any]) -> str:
    return str(_snowflake_block(event).get("grantee_role") or "").strip()


def _parse_env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return frozenset()
    return frozenset(part.strip().upper() for part in raw.split(",") if part.strip())


def _privileged_roles() -> frozenset[str]:
    parsed = _parse_env_set(PRIVILEGED_ROLES_ENV)
    return parsed or frozenset(DEFAULT_PRIVILEGED_ROLES)


def _authorized_granters() -> frozenset[str]:
    return _parse_env_set(AUTHORIZED_GRANTERS_ENV)


def _is_authorized(granter: str, allowlist: frozenset[str]) -> bool:
    return granter.strip().upper() in allowlist


def _is_relevant(event: dict[str, Any]) -> bool:
    if event.get("class_uid") != API_ACTIVITY_CLASS_UID:
        return False
    if _producer(event) not in ACCEPTED_PRODUCERS:
        return False
    if _api_operation(event) != ANCHOR_OPERATION:
        return False
    if event.get("status_id", STATUS_SUCCESS) != STATUS_SUCCESS:
        return False
    if not _actor_uid(event):
        return False
    granted = _granted_role(event)
    if not granted or granted not in _privileged_roles():
        return False
    if not (_grantee_user(event) or _grantee_role(event)):
        return False
    return True


def _finding_uid(granter: str, granted_role: str, grantee: str, time_ms: int) -> str:
    material = f"{granter}|{granted_role}|{grantee}|{time_ms}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-snowflake-unauthorized-grant-{digest}"


def _build_native_finding(event: dict[str, Any], allowlist_mode: str) -> dict[str, Any]:
    granter = _actor_uid(event)
    granter_name = _actor_name(event)
    granted_role = _granted_role(event)
    grantee_user = _grantee_user(event)
    grantee_role = _grantee_role(event)
    grantee = grantee_user or grantee_role
    time_ms = _event_time(event) or _now_ms()
    event_uid = _metadata_uid(event)
    finding_uid = _finding_uid(granter, granted_role, grantee, time_ms)

    description = (
        f"Snowflake principal '{granter_name or granter}' granted privileged role "
        f"'{granted_role}' to '{grantee}'. "
    )
    if allowlist_mode == "fail-open":
        description += (
            "SNOWFLAKE_AUTHORIZED_GRANTERS is empty; the detector fired in fail-open "
            "mode and surfaced every privileged grant. Set the allow-list explicitly "
            "in production to scope the detection to break-glass identities."
        )
    else:
        description += (
            "The granter is not on the SNOWFLAKE_AUTHORIZED_GRANTERS allow-list, "
            "so this grant falls outside the documented break-glass process."
        )

    observables: list[dict[str, Any]] = [
        {"name": "actor.user.uid", "type": "User Name", "value": granter},
        {"name": "actor.user.name", "type": "User Name", "value": granter_name or granter},
        {"name": "snowflake.granted_role", "type": "Role", "value": granted_role},
    ]
    if grantee_user:
        observables.append(
            {"name": "snowflake.grantee_user", "type": "User Name", "value": grantee_user}
        )
    if grantee_role:
        observables.append(
            {"name": "snowflake.grantee_role", "type": "Role", "value": grantee_role}
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
        "title": f"Snowflake privileged role '{granted_role}' granted by unauthorized identity",
        "description": description,
        "finding_types": ["snowflake-unauthorized-grant", OWASP_FINDING_TYPE],
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
            "granter": granter,
            "granted_role": granted_role,
            "grantee_user": grantee_user,
            "grantee_role": grantee_role,
            "allowlist_mode": allowlist_mode,
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
            "labels": ["data-warehouse", "snowflake", "persistence", "detection", "rbac"],
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
        "providers": ("snowflake",),
        "asset_classes": ("warehouse", "identities", "rbac"),
        "attack_coverage": {
            "snowflake": {
                "principal_types": ["human-users", "service-principals"],
                "anchor_operations": [ANCHOR_OPERATION],
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "thresholds": {
            "privileged_roles": sorted(_privileged_roles()),
            "authorized_granter_count": len(allowlist),
            "allowlist_mode": "fail-open" if not allowlist else "enforced",
        },
    }


def detect(
    events: Iterable[dict[str, Any]], output_format: str = "ocsf"
) -> Iterable[dict[str, Any]]:
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
                "SNOWFLAKE_AUTHORIZED_GRANTERS is empty; firing on every privileged "
                "grant. Set the allow-list to scope the detection to break-glass identities."
            ),
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
        granter = _actor_uid(event)
        if allowlist_mode == "enforced" and _is_authorized(granter, allowlist):
            continue
        native_finding = _build_native_finding(event, allowlist_mode)
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
        description="Detect Snowflake privileged-role grants by unauthorized granters from OCSF 1.8 input."
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
            "detect-snowflake-unauthorized-grant starting",
            extra={"input_event_count": len(events), "output_format": args.output_format},
        )
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
            findings_emitted += 1
        _log.info(
            "detect-snowflake-unauthorized-grant complete",
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
