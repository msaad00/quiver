"""Detect SAP privileged user access from normalized Security Audit Log events."""

from __future__ import annotations

import argparse
import fnmatch
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

SKILL_NAME = "detect-sap-priv-user-access"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-06"
REPO_NAME = "cloud-ai-security-skills"

_log = get_logger(__name__, skill=SKILL_NAME, layer="detection")

OUTPUT_FORMATS = ("ocsf", "native")
APP_ACTIVITY_CLASS_UID = 6002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

SAP_INGEST_SKILL = "ingest-sap-audit-log-ocsf"
PRIVILEGED_USERS_ENV = "SAP_PRIVILEGED_USERS"
PRIVILEGED_PROFILES_ENV = "SAP_PRIVILEGED_PROFILES"
APPROVED_USERS_ENV = "SAP_APPROVED_PRIVILEGED_USERS"
DEFAULT_PRIVILEGED_USERS = ("SAP*", "DDIC", "EARLYWATCH")
DEFAULT_PRIVILEGED_PROFILES = ("SAP_ALL", "SAP_NEW")

MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0004"
MITRE_TACTIC_NAME = "Privilege Escalation"
MITRE_TECHNIQUE_UID = "T1078"
MITRE_TECHNIQUE_NAME = "Valid Accounts"
OWASP_FINDING_TYPE = "OWASP-Top-10-A01"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _parse_env_list(name: str, default: Iterable[str] = ()) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return tuple(default)
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _event_time(event: dict[str, Any]) -> int:
    try:
        return int(event.get("time_ms") or event.get("time") or 0)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    return str(event.get("event_uid") or (event.get("metadata") or {}).get("uid") or "")


def _producer(event: dict[str, Any]) -> str:
    if event.get("source_skill"):
        return str(event["source_skill"])
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _sap_block(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("schema_mode") in {"canonical", "native"}:
        block = event.get("sap")
        return block if isinstance(block, dict) else {}
    block = ((event.get("unmapped") or {}).get("sap")) or {}
    return block if isinstance(block, dict) else {}


def _family(event: dict[str, Any]) -> str:
    return str(_sap_block(event).get("event_family") or "").strip().lower()


def _actor_id(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("name") or "").strip()


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "").strip()


def _client(event: dict[str, Any]) -> str:
    return str(_sap_block(event).get("client") or "").strip()


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "").strip()


def _transaction(event: dict[str, Any]) -> str:
    return str(_sap_block(event).get("transaction_code") or "").strip().upper()


def _privilege_names(event: dict[str, Any]) -> set[str]:
    raw = _sap_block(event).get("privilege_names") or []
    if isinstance(raw, list):
        return {str(item).upper() for item in raw if item}
    return {part.strip().upper() for part in str(raw).replace(";", ",").split(",") if part.strip()}


def _matches_any(value: str, patterns: Iterable[str]) -> bool:
    value_upper = value.upper()
    short_value = value_upper.split(":", 1)[-1]
    for pattern in patterns:
        pattern_upper = pattern.upper()
        if fnmatch.fnmatchcase(value_upper, pattern_upper) or fnmatch.fnmatchcase(
            short_value, pattern_upper
        ):
            return True
    return False


def _is_sap_event(event: dict[str, Any]) -> bool:
    if (
        event.get("class_uid") != APP_ACTIVITY_CLASS_UID
        and event.get("record_type") != "application_activity"
    ):
        return False
    return _producer(event) == SAP_INGEST_SKILL


def _is_privileged_access(
    event: dict[str, Any], privileged_users: tuple[str, ...], privileged_profiles: tuple[str, ...]
) -> bool:
    if not _is_sap_event(event):
        return False
    if _family(event) not in {"login", "privileged_access", "transaction"}:
        return False
    actor = _actor_id(event)
    profiles = _privilege_names(event)
    if _matches_any(actor, privileged_users):
        return True
    return bool({profile.upper() for profile in privileged_profiles}.intersection(profiles))


def _finding_uid(event: dict[str, Any]) -> str:
    material = f"{_metadata_uid(event)}|{_actor_id(event)}|{_client(event)}|{_transaction(event)}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"det-sap-priv-user-access-{digest}"


def _build_native_finding(
    event: dict[str, Any], matched_users: tuple[str, ...], matched_profiles: tuple[str, ...]
) -> dict[str, Any]:
    time_ms = _event_time(event) or _now_ms()
    finding_uid = _finding_uid(event)
    actor_uid = _actor_id(event)
    actor_name = _actor_name(event)
    client = _client(event)
    tx_code = _transaction(event)
    profiles = sorted(_privilege_names(event))
    src_ip = _src_ip(event)
    description = (
        f"SAP privileged principal '{actor_name or actor_uid}' accessed client '{client or 'unknown'}' "
        f"with transaction '{tx_code or 'unknown'}'. Matched privileged users {list(matched_users)} "
        f"or profiles {list(matched_profiles)}; review business justification and recent role changes."
    )
    observables = [
        {"name": "actor.user.uid", "type": "User Name", "value": actor_uid},
        {"name": "sap.client", "type": "Resource Name", "value": client},
    ]
    if tx_code:
        observables.append(
            {"name": "sap.transaction_code", "type": "Process Name", "value": tx_code}
        )
    if src_ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": src_ip})
    for profile in profiles:
        observables.append({"name": "sap.privilege", "type": "Resource Name", "value": profile})
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "SAP",
        "time_ms": time_ms,
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": STATUS_SUCCESS,
        "title": "SAP privileged user access observed",
        "description": description,
        "finding_types": ["sap-privileged-user-access", OWASP_FINDING_TYPE],
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
            "actor": actor_uid,
            "client": client,
            "transaction_code": tx_code,
            "privilege_names": profiles,
            "src_ip": src_ip,
            "raw_event_uid": _metadata_uid(event),
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
            "labels": ["sap", "privileged-access", "detection"],
        },
        "finding_info": {
            "uid": native_finding["finding_uid"],
            "title": native_finding["title"],
            "desc": native_finding["description"],
            "types": native_finding["finding_types"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {"uid": attack["tactic_uid"], "name": attack["tactic_name"]},
                    "technique": {"uid": attack["technique_uid"], "name": attack["technique_name"]},
                }
            ],
        },
        "evidence": native_finding["evidence"],
        "observables": native_finding["observables"],
    }


def iter_records(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, raw in enumerate(stream, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=str(exc),
                line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj


def detect(stream: Iterable[str], output_format: str = "ocsf") -> list[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ContractError(f"unsupported output_format `{output_format}`")
    privileged_users = _parse_env_list(PRIVILEGED_USERS_ENV, DEFAULT_PRIVILEGED_USERS)
    privileged_profiles = _parse_env_list(PRIVILEGED_PROFILES_ENV, DEFAULT_PRIVILEGED_PROFILES)
    approved_users = _parse_env_list(APPROVED_USERS_ENV)
    findings: list[dict[str, Any]] = []
    for event in iter_records(stream):
        actor = _actor_id(event)
        if actor and _matches_any(actor, approved_users):
            continue
        if _is_privileged_access(event, privileged_users, privileged_profiles):
            native = _build_native_finding(event, privileged_users, privileged_profiles)
            findings.append(native if output_format == "native" else _render_ocsf_finding(native))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect SAP privileged user access.")
    parser.add_argument("input", nargs="?", help="Input OCSF/native JSONL. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for finding in detect(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    except SkillError as exc:
        emit_error(SKILL_NAME, exc)
        return 2
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
