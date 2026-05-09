"""Convert GCP Security Command Center findings to OCSF 1.8 Detection Finding.

Output defaults to OCSF JSONL, or emits the repo's native enriched finding
shape when --output-format native is selected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "ingest-gcp-scc-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"

CLASS_UID = 2004
CLASS_NAME = "Detection Finding"
CATEGORY_UID = 2
CATEGORY_NAME = "Findings"
ACTIVITY_CREATE = 1
TYPE_UID = CLASS_UID * 100 + ACTIVITY_CREATE

STATUS_SUCCESS = 1

SEVERITY_INFORMATIONAL = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

_PROJECT_RE = re.compile(r"/projects/([^/]+)")


def parse_ts_ms(value: str | None) -> int:
    if not value:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    try:
        cleaned = value.replace("Z", "+00:00")
        if "." in cleaned:
            head, _, tail = cleaned.partition(".")
            frac, sep, tz = tail.partition("+")
            if not sep:
                frac, sep, tz = tail.partition("-")
            if frac and len(frac) > 6:
                frac = frac[:6]
            cleaned = head + "." + frac + (sep + tz if sep else "")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def severity_to_id(value: str | None) -> int:
    mapping = {
        "CRITICAL": SEVERITY_CRITICAL,
        "HIGH": SEVERITY_HIGH,
        "MEDIUM": SEVERITY_MEDIUM,
        "LOW": SEVERITY_LOW,
        "INFORMATIONAL": SEVERITY_INFORMATIONAL,
        "UNSPECIFIED": SEVERITY_INFORMATIONAL,
    }
    return mapping.get((value or "").upper(), SEVERITY_INFORMATIONAL)


def validate_finding(finding: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(finding, dict):
        return False, "not a dict"
    for field in ("name", "category", "resourceName"):
        if not finding.get(field):
            return False, f"missing required field: {field}"
    return True, ""


def _project_id(finding: dict[str, Any]) -> str:
    for source in (finding.get("resourceName"), finding.get("name"), finding.get("parent")):
        if isinstance(source, str):
            match = _PROJECT_RE.search(source)
            if match:
                return match.group(1)
    return ""


def _build_canonical_finding(finding: dict[str, Any]) -> dict[str, Any]:
    project = _project_id(finding)
    event_time = parse_ts_ms(finding.get("eventTime") or finding.get("createTime"))
    finding_uid = f"det-scc-{hashlib.sha256(str(finding.get('name', '')).encode()).hexdigest()[:8]}"
    resource_name = str(finding.get("resourceName") or "")
    category = str(finding.get("category") or "Security Command Center finding")
    description = str(finding.get("description") or category)
    state = str(finding.get("state") or "")
    finding_class = str(finding.get("findingClass") or "")
    severity = str(finding.get("severity") or "UNSPECIFIED")

    canonical: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "event_uid": str(finding.get("name") or finding_uid),
        "finding_uid": finding_uid,
        "provider": "GCP",
        "account_uid": project,
        "region": "",
        "time_ms": event_time,
        "severity_id": severity_to_id(severity),
        "status_id": STATUS_SUCCESS,
        "status": "success",
        "severity": severity,
        "title": category,
        "description": description,
        "finding_types": [category],
        "first_seen_time_ms": event_time,
        "last_seen_time_ms": event_time,
        "attacks": [],
        "resources": [{"name": resource_name, "type": finding_class or "scc-finding"}] if resource_name else [],
        "cloud": {"provider": "GCP"},
        "source": {
            "kind": "gcp.security-command-center",
            "finding_name": str(finding.get("name") or ""),
            "state": state,
            "category": category,
            "finding_class": finding_class,
            "resource_name": resource_name,
        },
        "evidence": {
            "events_observed": 1,
            "first_seen_time": event_time,
            "last_seen_time": event_time,
            "raw_events": [{"uid": str(finding.get("name") or ""), "product": "gcp-security-command-center"}],
        },
    }
    if project:
        canonical["cloud"]["account"] = {"uid": project}
    return canonical


def _build_observables(canonical: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"name": "scc.name", "type": "Other", "value": canonical["source"]["finding_name"]},
        {"name": "scc.state", "type": "Other", "value": canonical["source"]["state"]},
        {"name": "scc.category", "type": "Other", "value": canonical["source"]["category"]},
        {"name": "scc.severity", "type": "Other", "value": canonical["severity"]},
        {"name": "scc.finding_class", "type": "Other", "value": canonical["source"]["finding_class"]},
    ]


def _render_ocsf_finding(canonical: dict[str, Any]) -> dict[str, Any]:
    event: dict[str, Any] = {
        "activity_id": ACTIVITY_CREATE,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": TYPE_UID,
        "severity_id": canonical["severity_id"],
        "status_id": canonical["status_id"],
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "gcp", "scc", "ingest", "passthrough"],
        },
        "finding_info": {
            "uid": canonical["finding_uid"],
            "title": canonical["title"],
            "desc": canonical["description"],
            "types": canonical["finding_types"],
            "first_seen_time": canonical["first_seen_time_ms"],
            "last_seen_time": canonical["last_seen_time_ms"],
            "attacks": canonical["attacks"],
        },
        "resources": canonical["resources"],
        "cloud": canonical["cloud"],
        "observables": _build_observables(canonical),
        "evidence": canonical["evidence"],
    }
    return event


def _render_native_finding(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return _render_ocsf_finding(_build_canonical_finding(finding))


def convert_finding_native(finding: dict[str, Any]) -> dict[str, Any]:
    return _render_native_finding(_build_canonical_finding(finding))


def iter_raw_findings(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    text = "".join(stream).strip()
    if not text:
        return
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                if isinstance(obj.get("finding"), dict):
                    yield obj["finding"]
                elif isinstance(obj.get("findings"), list):
                    for finding in obj["findings"]:
                        if isinstance(finding, dict):
                            yield finding
                else:
                    yield obj
        return

    items = parsed if isinstance(parsed, list) else [parsed]
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("finding"), dict):
            yield item["finding"]
        elif isinstance(item.get("findings"), list):
            for finding in item["findings"]:
                if isinstance(finding, dict):
                    yield finding
        else:
            yield item


def ingest(stream: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    for finding in iter_raw_findings(stream):
        valid, reason = validate_finding(finding)
        if not valid:
            print(f"[{SKILL_NAME}] skipping finding: {reason}", file=sys.stderr)
            continue
        canonical = _build_canonical_finding(finding)
        if output_format == "native":
            yield _render_native_finding(canonical)
        else:
            yield _render_ocsf_finding(canonical)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert GCP SCC findings to OCSF 1.8 Detection Finding JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON or JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=("ocsf", "native"), default="ocsf", help="Output shape. Defaults to ocsf.")
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")
    try:
        for event in ingest(in_stream, output_format=args.output_format):
            out_stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
