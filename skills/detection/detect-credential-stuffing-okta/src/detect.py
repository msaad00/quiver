"""Detect Okta credential-stuffing / password-spraying bursts.

Reads OCSF 1.8 Authentication (class 3002) events or the native authentication
projection produced by ingest-okta-system-log-ocsf. Emits OCSF 1.8 Detection
Finding (class 2004) when a user receives a burst of failed sign-ins from
multiple source IPs followed by a successful sign-in inside a short window.

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

SKILL_NAME = "detect-credential-stuffing-okta"
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
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

WINDOW_MS = 5 * 60 * 1000
MIN_FAILURES = 5
MIN_UNIQUE_IPS = 2
WINDOW_ENV = "DETECT_OKTA_STUFFING_WINDOW_MS"
MIN_FAILURES_ENV = "DETECT_OKTA_STUFFING_MIN_FAILURES"
MIN_UNIQUE_IPS_ENV = "DETECT_OKTA_STUFFING_MIN_UNIQUE_IPS"

OKTA_INGEST_SKILL = "ingest-okta-system-log-ocsf"
# Okta event types that represent a sign-in attempt (success or failure).
AUTH_EVENT_TYPES = {
    "user.session.start",
    "user.authentication.auth",
    "user.authentication.sso",
    "user.authentication.auth_via_mfa",
}

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
MITRE_TACTIC_UID = "TA0006"
MITRE_TACTIC_NAME = "Credential Access"
MITRE_TECHNIQUE_UID = "T1110"
MITRE_TECHNIQUE_NAME = "Brute Force"
MITRE_SUBTECHNIQUE_UID = "T1110.003"
MITRE_SUBTECHNIQUE_NAME = "Password Spraying"


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
    return str(
        event.get("event_type")
        or (((event.get("unmapped") or {}).get("okta")) or {}).get("event_type")
        or ""
    )


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
        "event_type": _okta_event_type(event),
    }


def _classify_auth_event(event: dict[str, Any]) -> str | None:
    """Return 'failure' or 'success' for Okta auth events from the right ingester."""
    normalized = _normalize_event(event)
    if normalized is None:
        return None
    if normalized["source_skill"] != OKTA_INGEST_SKILL:
        return None
    if normalized["event_type"] not in AUTH_EVENT_TYPES:
        return None
    if normalized["status_id"] == STATUS_FAILURE:
        return "failure"
    if normalized["status_id"] == STATUS_SUCCESS:
        return "success"
    return None


def _finding_uid(user_uid: str, success_uid: str, first_failure_uid: str) -> str:
    material = f"{user_uid}|{first_failure_uid}|{success_uid}"
    return f"det-okta-cred-stuffing-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    user_uid: str,
    user_name: str,
    failures: list[dict[str, Any]],
    success: dict[str, Any],
) -> dict[str, Any]:
    first_failure = failures[0]
    first_failure_uid = first_failure["event_uid"]
    success_uid = success["event_uid"]
    finding_uid = _finding_uid(user_uid, success_uid, first_failure_uid)

    failure_ips = sorted({ip for item in failures if (ip := _source_ip(item))})
    success_ip = _source_ip(success)
    session_uids = sorted(
        {uid for item in (*failures, success) if (uid := _session_uid(item))}
    )
    raw_event_uids = [item["event_uid"] for item in failures] + [success_uid]

    window_ms = _window_ms()
    description = (
        f"User '{user_name or user_uid}' received {len(failures)} failed Okta "
        f"sign-in attempts from {len(failure_ips)} distinct source IPs, "
        f"immediately followed by a successful sign-in"
        f"{(' from ' + success_ip) if success_ip else ''}, all inside "
        f"{window_ms // 60000} minute(s). This matches the credential-stuffing / "
        "password-spraying pattern (T1110.003) with a downstream account compromise."
    )

    observables = [
        {"name": "user.uid", "type": "User Name", "value": user_uid},
        {"name": "user.name", "type": "User Name", "value": user_name or user_uid},
        {"name": "failure.count", "type": "Other", "value": str(len(failures))},
        {"name": "unique.failure.ips", "type": "Other", "value": str(len(failure_ips))},
    ]
    if success_ip:
        observables.append({"name": "success.ip", "type": "IP Address", "value": success_ip})
    observables.extend({"name": "failure.ip", "type": "IP Address", "value": ip} for ip in failure_ips)
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
        "time_ms": success["time_ms"] or _now_ms(),
        "severity": "high",
        "severity_id": SEVERITY_HIGH,
        "status": "success",
        "status_id": 1,
        "title": "Okta credential stuffing: failed-login burst followed by successful sign-in",
        "description": description,
        "finding_types": ["okta-credential-stuffing", "brute-force"],
        "first_seen_time_ms": first_failure["time_ms"],
        "last_seen_time_ms": success["time_ms"],
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
        "evidence": {
            "failure_events": len(failures),
            "success_event_uid": success_uid,
            "source_ips": failure_ips,
            "success_ip": success_ip,
            "session_uids": session_uids,
            "raw_event_uids": raw_event_uids,
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
            "labels": ["identity", "okta", "credential-stuffing", "brute-force", "detection"],
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
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("okta",),
        "asset_classes": ("identities", "authentication", "sessions"),
        "attack_coverage": {
            "okta": {
                "principal_types": ["human-users"],
                "anchor_event_types": sorted(AUTH_EVENT_TYPES),
                "techniques": [MITRE_TECHNIQUE_UID, MITRE_SUBTECHNIQUE_UID],
            }
        },
        "window_ms": _window_ms(),
        "thresholds": {
            "min_failures": _min_failures(),
            "min_unique_ips": _min_unique_ips(),
        },
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format: {output_format}")
    dedupe: set[str] = set()

    relevant: list[dict[str, Any]] = []
    for event in events:
        kind = _classify_auth_event(event)
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

    window_ms = _window_ms()
    min_failures = _min_failures()
    min_unique_ips = _min_unique_ips()

    # Per-user rolling window of recent failures. On a success, if the window
    # holds enough failures from enough distinct IPs, emit one finding.
    failures_by_user: dict[str, list[dict[str, Any]]] = {}
    fired_for_user: set[str] = set()

    for item in relevant:
        user_uid = item["user_uid"]
        current_time = item["time_ms"]
        failures = failures_by_user.setdefault(user_uid, [])

        # Trim failures outside the window, measured back from current event.
        cutoff = current_time - window_ms
        failures[:] = [entry for entry in failures if entry["time_ms"] >= cutoff]

        if item["kind"] == "failure":
            failures.append(item)
            continue

        # Success event. Only evaluate firing if the user isn't already flagged.
        if user_uid in fired_for_user:
            continue

        unique_ips = {_source_ip(f) for f in failures if _source_ip(f)}
        if len(failures) >= min_failures and len(unique_ips) >= min_unique_ips:
            native_finding = _build_native_finding(user_uid, item["user_name"], list(failures), item)
            if output_format == "native":
                yield native_finding
            else:
                yield _render_ocsf_finding(native_finding)
            fired_for_user.add(user_uid)
            # Reset the failure buffer so a second burst after cooldown can fire again.
            failures.clear()


def _env_int(name: str, default: int) -> int:
    value = env_int(name, default, skill_name=SKILL_NAME)
    return value if value > 0 else default


def _window_ms() -> int:
    return _env_int(WINDOW_ENV, WINDOW_MS)


def _min_failures() -> int:
    return _env_int(MIN_FAILURES_ENV, MIN_FAILURES)


def _min_unique_ips() -> int:
    return _env_int(MIN_UNIQUE_IPS_ENV, MIN_UNIQUE_IPS)


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
        description="Detect Okta credential-stuffing bursts followed by successful sign-in."
    )
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
