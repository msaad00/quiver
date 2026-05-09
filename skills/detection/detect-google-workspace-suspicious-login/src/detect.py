"""Detect suspicious Google Workspace login patterns from OCSF or native auth events."""

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

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-google-workspace-suspicious-login"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

OUTPUT_FORMATS = ("ocsf", "native")

WORKSPACE_INGEST_SKILL = "ingest-google-workspace-login-ocsf"
AUTH_CLASS_UID = 3002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
STATUS_SUCCESS = 1
STATUS_FAILURE = 2

WINDOW_MS = 10 * 60 * 1000
MIN_FAILURES = 3

MITRE_VERSION = "v14"
TACTIC_UID = "TA0006"
TACTIC_NAME = "Credential Access"
BRUTE_FORCE_UID = "T1110"
BRUTE_FORCE_NAME = "Brute Force"
VALID_ACCOUNTS_UID = "T1078"
VALID_ACCOUNTS_NAME = "Valid Accounts"


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _event_time(event: dict[str, Any]) -> int:
    try:
        return int(event.get("time_ms") or event.get("time") or 0)
    except (TypeError, ValueError):
        return 0


def _metadata_uid(event: dict[str, Any]) -> str:
    return str(event.get("event_uid") or (event.get("metadata") or {}).get("uid") or "")


def _feature_name(event: dict[str, Any]) -> str:
    if event.get("source_skill"):
        return str(event["source_skill"])
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _workspace_payload(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("schema_mode") in {"canonical", "native"} or event.get("source_format"):
        return {
            "event_name": event.get("event_name"),
            "parameters": event.get("parameters") or {},
        }
    return ((event.get("unmapped") or {}).get("google_workspace_login")) or {}


def _workspace_params(event: dict[str, Any]) -> dict[str, Any]:
    payload = _workspace_payload(event)
    params = payload.get("parameters") or {}
    return params if isinstance(params, dict) else {}


def _workspace_event_name(event: dict[str, Any]) -> str:
    return str(_workspace_payload(event).get("event_name") or "")


def _user_info(event: dict[str, Any]) -> tuple[str, str]:
    user = event.get("user") or {}
    uid = str(user.get("uid") or user.get("email_addr") or user.get("name") or "").strip()
    name = str(user.get("email_addr") or user.get("name") or user.get("uid") or "").strip()
    return uid, name


def _source_ip(event: dict[str, Any]) -> str:
    return str(event.get("src_ip") or (event.get("src_endpoint") or {}).get("ip") or "")


def _session_uid(event: dict[str, Any]) -> str:
    return str(event.get("session_uid") or (event.get("session") or {}).get("uid") or "")


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != AUTH_CLASS_UID:
            return None
        return {
            "source_format": "ocsf",
            "source_skill": _feature_name(event),
            "event_uid": _metadata_uid(event),
            "time_ms": _event_time(event),
            "user": event.get("user") or {},
            "src_endpoint": event.get("src_endpoint") or {},
            "session": event.get("session") or {},
            "event_name": _workspace_event_name(event),
            "parameters": _workspace_params(event),
            "status_id": event.get("status_id"),
            "status_detail": event.get("status_detail"),
        }

    source_format = str(event.get("source_format") or "").strip().lower()
    if source_format in {"ocsf", "native", "canonical"} and event.get("event_name"):
        return {
            "source_format": source_format,
            "source_skill": str(event.get("source_skill") or ""),
            "event_uid": _metadata_uid(event),
            "time_ms": _event_time(event),
            "user": event.get("user") or {},
            "src_endpoint": event.get("src_endpoint") or {},
            "session": event.get("session") or {},
            "event_name": str(event.get("event_name") or ""),
            "parameters": event.get("parameters") or {},
            "status_id": event.get("status_id"),
            "status_detail": event.get("status_detail"),
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    if str(event.get("record_type") or "").strip().lower() != "authentication":
        return None
    return {
        "source_format": schema_mode or "native",
        "source_skill": str(event.get("source_skill") or ""),
        "event_uid": _metadata_uid(event),
        "time_ms": _event_time(event),
        "user": event.get("user") or {},
        "src_endpoint": event.get("src_endpoint") or {},
        "session": event.get("session") or {},
        "event_name": str(event.get("event_name") or ""),
        "parameters": event.get("parameters") or {},
        "status_id": event.get("status_id"),
        "status_detail": event.get("status_detail"),
    }


def _login_kind(event: dict[str, Any]) -> str | None:
    normalized = _normalize_event(event)
    if not normalized:
        return None
    if str(normalized.get("source_skill") or "") != WORKSPACE_INGEST_SKILL:
        return None
    event_name = str(normalized["event_name"])
    if event_name == "login_failure":
        return "failure"
    if event_name == "login_success":
        return "success"
    return None


def _is_suspicious(event: dict[str, Any]) -> bool:
    return _workspace_params(event).get("is_suspicious") is True


def _finding_uid(user_uid: str, first_uid: str, last_uid: str, kind: str) -> str:
    material = f"{kind}|{user_uid}|{first_uid}|{last_uid}"
    return f"det-workspace-login-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_finding(
    *,
    user_uid: str,
    user_name: str,
    ip: str,
    related: list[dict[str, Any]],
    finding_kind: str,
) -> dict[str, Any]:
    first = related[0]
    last = related[-1]
    first_uid = _metadata_uid(first)
    last_uid = _metadata_uid(last)
    finding_uid = _finding_uid(user_uid, first_uid, last_uid, finding_kind)
    raw_event_uids = [_metadata_uid(event) for event in related]
    session_uids = sorted({_session_uid(event) for event in related if _session_uid(event)})
    failure_count = sum(1 for event in related if _login_kind(event) == "failure")
    success_count = sum(1 for event in related if _login_kind(event) == "success")
    suspicious_flags = sum(1 for event in related if _is_suspicious(event))

    if finding_kind == "workspace-suspicious-flag":
        title = "Google Workspace marked a login as suspicious"
        desc = (
            f"Google Workspace marked login activity for '{user_name or user_uid}' from {ip or 'an unknown IP'} "
            "as suspicious. This detector preserves the provider-side signal and surfaces it as a normalized "
            "OCSF Detection Finding for downstream triage and correlation."
        )
        severity_id = SEVERITY_HIGH
    else:
        title = "Repeated Google Workspace login failures followed by success"
        desc = (
            f"User '{user_name or user_uid}' had {failure_count} failed Google Workspace logins followed by "
            f"{success_count} successful login from {ip or 'an unknown IP'} inside {WINDOW_MS // 60000} minutes. "
            "This is a narrow suspicious-login pattern aligned to brute-force or valid-account follow-through."
        )
        severity_id = SEVERITY_HIGH

    observables = [
        {"name": "user.uid", "type": "User Name", "value": user_uid},
        {"name": "user.name", "type": "User Name", "value": user_name or user_uid},
    ]
    if ip:
        observables.append({"name": "src.ip", "type": "IP Address", "value": ip})
    observables.extend({"name": "session.uid", "type": "Other", "value": uid} for uid in session_uids)

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": finding_uid,
        "event_uid": finding_uid,
        "provider": "Google Workspace",
        "time_ms": _event_time(last) or _now_ms(),
        "severity": "high",
        "status": "success",
        "activity_id": FINDING_ACTIVITY_CREATE,
        "severity_id": severity_id,
        "status_id": STATUS_SUCCESS,
        "title": title,
        "description": desc,
        "finding_types": ["google-workspace-suspicious-login"],
        "first_seen_time_ms": _event_time(first),
        "last_seen_time_ms": _event_time(last),
        "mitre_attacks": [
            {
                "version": MITRE_VERSION,
                "tactic_uid": TACTIC_UID,
                "tactic_name": TACTIC_NAME,
                "technique_uid": BRUTE_FORCE_UID,
                "technique_name": BRUTE_FORCE_NAME,
            },
            {
                "version": MITRE_VERSION,
                "tactic_uid": TACTIC_UID,
                "tactic_name": TACTIC_NAME,
                "technique_uid": VALID_ACCOUNTS_UID,
                "technique_name": VALID_ACCOUNTS_NAME,
            },
        ],
        "user_uid": user_uid,
        "user_name": user_name,
        "src_ip": ip,
        "observables": observables,
        "evidence": {
            "raw_event_uids": raw_event_uids,
            "failure_count": failure_count,
            "success_count": success_count,
            "suspicious_flag_events": suspicious_flags,
            "session_uids": session_uids,
        },
    }


def _render_ocsf_finding(native_finding: dict[str, Any]) -> dict[str, Any]:
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
            "labels": ["identity", "google-workspace", "login", "suspicious", "detection"],
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
                for attack in native_finding["mitre_attacks"]
            ],
        },
        "observables": native_finding["observables"],
        "evidence": native_finding["evidence"],
    }


def coverage_metadata() -> dict[str, Any]:
    return {
        "frameworks": ("OCSF 1.8.0", "MITRE ATT&CK v14"),
        "providers": ("google-workspace",),
        "asset_classes": ("identities", "authentication", "sessions", "mfa"),
        "attack_coverage": {
            "google-workspace": {
                "principal_types": ["human-users"],
                "anchor_event_types": ["login_failure", "login_success"],
                "techniques": [BRUTE_FORCE_UID, VALID_ACCOUNTS_UID],
            }
        },
        "window_ms": WINDOW_MS,
        "thresholds": {"min_failures": MIN_FAILURES},
    }


def detect(events: Iterable[dict[str, Any]], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    dedupe: set[str] = set()
    relevant: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for event in events:
        normalized = _normalize_event(event)
        if not normalized:
            continue
        kind = _login_kind(event)
        if kind is None:
            continue
        metadata_uid = str(normalized["event_uid"])
        if metadata_uid and metadata_uid in dedupe:
            continue
        if metadata_uid:
            dedupe.add(metadata_uid)

        user_uid, user_name = _user_info(normalized)
        if not user_uid:
            continue

        relevant.append(
            {
                "event": normalized,
                "kind": kind,
                "user_uid": user_uid,
                "user_name": user_name,
                "ip": _source_ip(normalized),
            }
        )

    relevant.sort(
        key=lambda item: (
            item["user_uid"],
            item["ip"],
            _event_time(item["event"]),
            _metadata_uid(item["event"]),
        )
    )

    seen_findings: set[str] = set()

    # Direct suspicious-flag path.
    for item in relevant:
        if not _is_suspicious(item["event"]):
            continue
        finding = _build_finding(
            user_uid=item["user_uid"],
            user_name=item["user_name"],
            ip=item["ip"],
            related=[item["event"]],
            finding_kind="workspace-suspicious-flag",
        )
        uid = finding["event_uid"]
        uid = finding["event_uid"]
        if uid in seen_findings:
            continue
        seen_findings.add(uid)
        findings.append(_render_ocsf_finding(finding) if output_format == "ocsf" else finding)

    # Failure burst followed by success path.
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in relevant:
        grouped.setdefault((item["user_uid"], item["ip"]), []).append(item)

    for (user_uid, ip), items in grouped.items():
        failures: list[dict[str, Any]] = []
        user_name = items[0]["user_name"]

        for item in items:
            event = item["event"]
            time_ms = _event_time(event)

            failures = [failure for failure in failures if time_ms - _event_time(failure["event"]) <= WINDOW_MS]

            if item["kind"] == "failure":
                failures.append(item)
                continue

            if item["kind"] != "success":
                continue

            if len(failures) < MIN_FAILURES:
                continue

            first_time = _event_time(failures[0]["event"])
            if time_ms - first_time > WINDOW_MS:
                continue

            related = [failure["event"] for failure in failures] + [event]
            finding = _build_finding(
                user_uid=user_uid,
                user_name=user_name,
                ip=ip,
                related=related,
                finding_kind="workspace-failure-burst",
            )
            uid = finding["event_uid"]
            if uid in seen_findings:
                continue
            seen_findings.add(uid)
            findings.append(_render_ocsf_finding(finding) if output_format == "ocsf" else finding)
            failures = []

    findings.sort(key=lambda item: (_event_time(item), _metadata_uid(item)))
    yield from findings


def load_jsonl(lines: Iterable[str]) -> Iterable[dict[str, Any]]:
    for idx, line in enumerate(lines, start=1):
        raw = line.strip()
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="json_parse_failed",
                message=f"skipping line {idx}: invalid JSON",
                line=idx,
            )
            continue
        if isinstance(item, dict):
            yield item


def _iter_input(paths: list[str]) -> Iterable[str]:
    if not paths:
        yield from sys.stdin
        return
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            yield from handle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect suspicious Google Workspace login patterns.")
    parser.add_argument("paths", nargs="*", help="Input OCSF JSONL files. Reads stdin when omitted.")
    parser.add_argument("--output", help="Optional file path to write JSONL findings.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
        help="Render OCSF Detection Findings (default) or the native canonical projection.",
    )
    args = parser.parse_args(argv)

    findings = list(detect(load_jsonl(_iter_input(args.paths)), output_format=args.output_format))
    rendered = "\n".join(json.dumps(finding, sort_keys=True, separators=(",", ":")) for finding in findings)
    if rendered:
        rendered += "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
