"""Detect repeated Okta Verify push-denial bursts from Okta authentication events.

Reads OCSF 1.8 Authentication (class 3002) events or the native authentication
projection produced by ingest-okta-system-log-ocsf and emits OCSF 1.8 Detection
Finding (class 2004) by default when a single user receives repeated Okta
Verify push challenges and denies or generic MFA verification failures inside a
short time window.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.env import env_int  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-okta-mfa-fatigue"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

OUTPUT_FORMATS = ("ocsf", "native")

AUTH_CLASS_UID = 3002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_FAILURE = 2

WINDOW_MS = 10 * 60 * 1000
MIN_RELEVANT_EVENTS = 3
MIN_CHALLENGES = 2
MIN_DENIALS = 1
WINDOW_ENV = "DETECT_OKTA_MFA_FATIGUE_WINDOW_MS"
MIN_RELEVANT_ENV = "DETECT_OKTA_MFA_FATIGUE_MIN_RELEVANT_EVENTS"
MIN_CHALLENGES_ENV = "DETECT_OKTA_MFA_FATIGUE_MIN_CHALLENGES"
MIN_DENIALS_ENV = "DETECT_OKTA_MFA_FATIGUE_MIN_DENIALS"

OKTA_INGEST_SKILL = "ingest-okta-system-log-ocsf"
CHALLENGE_EVENT_TYPES = {"system.push.send_factor_verify_push"}
DENY_EVENT_TYPES = {
    "user.mfa.okta_verify.deny_push",
    "user.mfa.okta_verify.deny_push_upgrade_needed",
}
GENERIC_MFA_EVENT_TYPE = "user.authentication.auth_via_mfa"
OKTA_VERIFY_RESOURCE_MARKERS = {"okta verify", "okta_verify"}

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0006"
MITRE_TACTIC_NAME = "Credential Access"
MITRE_TECHNIQUE_UID = "T1621"
MITRE_TECHNIQUE_NAME = "Multi-Factor Authentication Request Generation"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    try:
        return int(event.get("time_ms") or event.get("time") or 0)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    return str(event.get("event_uid") or (event.get("metadata") or {}).get("uid") or "")

def _okta_event_type(event: dict[str, Any]) -> str:
    return str(event.get("event_type") or (((event.get("unmapped") or {}).get("okta")) or {}).get("event_type") or "")

def _source_skill(event: dict[str, Any]) -> str:
    if event.get("source_skill"):
        return str(event["source_skill"])
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _user_info(event: dict[str, Any]) -> tuple[str, str]:
    user = event.get("user") or {}
    uid = str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()
    name = str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _source_ip(event: dict[str, Any]) -> str:
    return str((event.get("src_endpoint") or {}).get("ip") or "")


def _session_uid(event: dict[str, Any]) -> str:
    return str((event.get("session") or {}).get("uid") or "")


def _resource_names(event: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for resource in event.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        name = resource.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    service_name = (event.get("service") or {}).get("name")
    if isinstance(service_name, str) and service_name:
        names.append(service_name)
    return names


def _is_okta_verify_factor(event: dict[str, Any]) -> bool:
    normalized = {name.strip().lower() for name in _resource_names(event)}
    return any(marker in normalized for marker in OKTA_VERIFY_RESOURCE_MARKERS)


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != AUTH_CLASS_UID:
            return None
        return {
            "source_format": "ocsf",
            "source_skill": _source_skill(event),
            "event_uid": _metadata_uid(event),
            "time_ms": _event_time(event),
            "status_id": int(event.get("status_id") or 0),
            "status_detail": str(event.get("status_detail") or ""),
            "user": event.get("user") or {},
            "src_endpoint": event.get("src_endpoint") or {},
            "session": event.get("session") or {},
            "resources": event.get("resources") or [],
            "service": event.get("service") or {},
            "event_type": _okta_event_type(event),
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    if str(event.get("record_type") or "").strip().lower() not in {"", "authentication"}:
        return None
    return {
        "source_format": schema_mode or "native",
        "source_skill": _source_skill(event),
        "event_uid": _metadata_uid(event),
        "time_ms": _event_time(event),
        "status_id": int(event.get("status_id") or 0),
        "status_detail": str(event.get("status_detail") or ""),
        "user": event.get("user") or {},
        "src_endpoint": event.get("src_endpoint") or {},
        "session": event.get("session") or {},
        "resources": event.get("resources") or [],
        "service": event.get("service") or {},
        "event_type": _okta_event_type(event),
    }


def _classify_relevant_event(event: dict[str, Any]) -> str | None:
    normalized = _normalize_event(event)
    if normalized is None:
        return None
    if normalized["source_skill"] != OKTA_INGEST_SKILL:
        return None

    event_type = normalized["event_type"]
    if event_type in CHALLENGE_EVENT_TYPES:
        return "challenge"
    if event_type in DENY_EVENT_TYPES:
        return "deny"
    if (
        event_type == GENERIC_MFA_EVENT_TYPE
        and normalized["status_id"] == STATUS_FAILURE
        and _is_okta_verify_factor(normalized)
    ):
        return "deny"
    return None


def _finding_uid(user_uid: str, first_uid: str, last_uid: str) -> str:
    material = f"{user_uid}|{first_uid}|{last_uid}"
    return f"det-okta-mfa-fatigue-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(user_uid: str, user_name: str, burst: list[dict[str, Any]]) -> dict[str, Any]:
    first = burst[0]
    last = burst[-1]
    first_uid = first["event_uid"]
    last_uid = last["event_uid"]
    finding_uid = _finding_uid(user_uid, first_uid, last_uid)

    challenge_count = sum(1 for item in burst if item["kind"] == "challenge")
    denial_count = sum(1 for item in burst if item["kind"] == "deny")
    source_ips = sorted({str((item["src_endpoint"] or {}).get("ip") or "") for item in burst if (item["src_endpoint"] or {}).get("ip")})
    session_uids = sorted({str((item["session"] or {}).get("uid") or "") for item in burst if (item["session"] or {}).get("uid")})
    event_uids = [item["event_uid"] for item in burst]
    window_ms = _window_ms()

    description = (
        f"User '{user_name or user_uid}' received {challenge_count} Okta Verify push challenge events and "
        f"{denial_count} denial or verification-failure events within {window_ms // 60000} minutes. "
        "This is a high-signal MFA fatigue pattern aligned to repeated push prompts and user rejection."
    )

    observables = [
        {"name": "user.uid", "type": "User Name", "value": user_uid},
        {"name": "user.name", "type": "User Name", "value": user_name or user_uid},
        {"name": "challenge.count", "type": "Other", "value": str(challenge_count)},
        {"name": "denial.count", "type": "Other", "value": str(denial_count)},
    ]
    observables.extend({"name": "src.ip", "type": "IP Address", "value": ip} for ip in source_ips)
    observables.extend({"name": "session.uid", "type": "Other", "value": uid} for uid in session_uids)

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Okta",
        "time_ms": last["time_ms"] or _now_ms(),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "title": "Repeated Okta Verify MFA push denials for one user",
        "description": description,
        "finding_types": ["okta-mfa-fatigue", "mfa-request-generation"],
        "first_seen_time_ms": first["time_ms"],
        "last_seen_time_ms": last["time_ms"],
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
            "events_observed": len(burst),
            "challenge_events": challenge_count,
            "denial_events": denial_count,
            "source_ips": source_ips,
            "session_uids": session_uids,
            "raw_event_uids": event_uids,
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
            "labels": ["identity", "okta", "mfa", "fatigue", "detection"],
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
    window_ms = _window_ms()
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("okta",),
        "asset_classes": ("identities", "authentication", "mfa", "sessions"),
        "attack_coverage": {
            "okta": {
                "principal_types": ["human-users"],
                "anchor_event_types": sorted(CHALLENGE_EVENT_TYPES | DENY_EVENT_TYPES | {GENERIC_MFA_EVENT_TYPE}),
                "techniques": [MITRE_TECHNIQUE_UID],
            }
        },
        "window_ms": window_ms,
        "thresholds": {
            "min_relevant_events": _min_relevant_events(),
            "min_challenges": _min_challenges(),
            "min_denials": _min_denials(),
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format: {output_format}")
    dedupe: set[str] = set()
    states: dict[str, list[dict[str, Any]]] = {}
    active_bursts: set[str] = set()

    relevant: list[dict[str, Any]] = []
    for event in events:
        kind = _classify_relevant_event(event)
        if kind is None:
            continue
        normalized = _normalize_event(event)
        if normalized is None:
            continue
        metadata_uid = normalized["event_uid"]
        if metadata_uid and metadata_uid in dedupe:
            continue
        if metadata_uid:
            dedupe.add(metadata_uid)
        user_uid, user_name = _user_info(normalized)
        if not user_uid:
            continue
        normalized["kind"] = kind
        normalized["user_uid"] = user_uid
        normalized["user_name"] = user_name
        relevant.append(normalized)

    relevant.sort(key=lambda item: (item["user_uid"], item["time_ms"], item["event_uid"]))

    for item in relevant:
        user_uid = item["user_uid"]
        current_time = item["time_ms"]
        burst = states.setdefault(user_uid, [])
        window_ms = _window_ms()

        if burst and current_time - burst[-1]["time_ms"] > window_ms:
            burst.clear()
            active_bursts.discard(user_uid)

        cutoff = current_time - window_ms
        burst[:] = [entry for entry in burst if entry["time_ms"] >= cutoff]
        burst.append(item)

        challenge_count = sum(1 for entry in burst if entry["kind"] == "challenge")
        denial_count = sum(1 for entry in burst if entry["kind"] == "deny")
        if user_uid in active_bursts:
            continue
        if (
            len(burst) >= _min_relevant_events()
            and challenge_count >= _min_challenges()
            and denial_count >= _min_denials()
        ):
            native_finding = _build_native_finding(user_uid, item["user_name"], burst)
            if output_format == "native":
                yield native_finding
            else:
                yield _render_ocsf_finding(native_finding)
            active_bursts.add(user_uid)


def _env_int(name: str, default: int) -> int:
    value = env_int(name, default, skill_name=SKILL_NAME)
    return value if value > 0 else default


def _window_ms() -> int:
    return _env_int(WINDOW_ENV, WINDOW_MS)


def _min_relevant_events() -> int:
    return _env_int(MIN_RELEVANT_ENV, MIN_RELEVANT_EVENTS)


def _min_challenges() -> int:
    return _env_int(MIN_CHALLENGES_ENV, MIN_CHALLENGES)


def _min_denials() -> int:
    return _env_int(MIN_DENIALS_ENV, MIN_DENIALS)


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
    parser = argparse.ArgumentParser(description="Detect repeated Okta Verify MFA push-denial bursts from native or OCSF input.")
    parser.add_argument("input", nargs="?", help="Authentication JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Detection Finding JSONL output. Defaults to stdout.")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, default="ocsf", help="Output format.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        events = list(load_jsonl(in_stream))
        for finding in detect(events, output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
