"""Detect MCP requests matching the adversarial-input fingerprint catalog.

Reads OCSF 1.8 Application Activity (class 6002) events emitted by
`ingest-mcp-proxy-ocsf`, scans every `unmapped.mcp.prompt` and
`unmapped.mcp.request.params.messages[].content` against the frozen
fingerprint catalog at `src/fingerprints.json`, and emits one Detection
Finding per matching request (MITRE ATLAS AML.T0043 Craft Adversarial Data,
OWASP LLM Top 10 LLM01 / LLM07).
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

SKILL_NAME = "detect-mcp-adversarial-input-corpus"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"
REPO_NAME = "cloud-ai-security-skills"
OUTPUT_FORMATS = ("ocsf", "native")

APPLICATION_ACTIVITY_UID = 6002
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5
SEVERITY_NAME_TO_ID = {
    "low": SEVERITY_LOW,
    "medium": SEVERITY_MEDIUM,
    "high": SEVERITY_HIGH,
    "critical": SEVERITY_CRITICAL,
}
SEVERITY_ID_TO_NAME = {v: k for k, v in SEVERITY_NAME_TO_ID.items()}

ATLAS_VERSION = "current"
ATLAS_TACTIC_UID = "AML.TA0000"
ATLAS_TACTIC_NAME = "ML Attack Staging"
ATLAS_TECHNIQUE_UID = "AML.T0043"
ATLAS_TECHNIQUE_NAME = "Craft Adversarial Data"

FINGERPRINTS_PATH = Path(__file__).resolve().parent / "fingerprints.json"


class _Fingerprint:
    __slots__ = ("name", "mitre_id", "pattern", "severity_id", "severity", "source")

    def __init__(
        self,
        name: str,
        mitre_id: str,
        pattern: re.Pattern[str],
        severity: str,
        source: str,
    ) -> None:
        self.name = name
        self.mitre_id = mitre_id
        self.pattern = pattern
        self.severity = severity
        self.severity_id = SEVERITY_NAME_TO_ID.get(severity.lower(), SEVERITY_MEDIUM)
        self.source = source


def _load_fingerprints(path: Path = FINGERPRINTS_PATH) -> list[_Fingerprint]:
    if not path.exists():
        print(
            f"[{SKILL_NAME}] fingerprint catalog not found at {path} — failing open.",
            file=sys.stderr,
        )
        return []
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(
            f"[{SKILL_NAME}] fingerprint catalog at {path} is malformed JSON: {exc} — failing open.",
            file=sys.stderr,
        )
        return []
    if not isinstance(raw, dict) or "fingerprints" not in raw:
        print(
            f"[{SKILL_NAME}] fingerprint catalog at {path} missing `fingerprints` key — failing open.",
            file=sys.stderr,
        )
        return []
    entries: list[_Fingerprint] = []
    for idx, entry in enumerate(raw.get("fingerprints", [])):
        if not isinstance(entry, dict):
            print(
                f"[{SKILL_NAME}] fingerprint #{idx} is not an object — skipped.",
                file=sys.stderr,
            )
            continue
        name = str(entry.get("name") or "").strip()
        regex_pattern = str(entry.get("regex_pattern") or "").strip()
        severity = str(entry.get("severity") or "medium").strip().lower()
        mitre_id = str(entry.get("mitre_id") or "AML.T0043").strip()
        source = str(entry.get("source") or "").strip()
        if not name or not regex_pattern:
            print(
                f"[{SKILL_NAME}] fingerprint #{idx} missing name or regex_pattern — skipped.",
                file=sys.stderr,
            )
            continue
        try:
            pattern = re.compile(regex_pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            print(
                f"[{SKILL_NAME}] fingerprint `{name}` regex did not compile ({exc}) — skipped.",
                file=sys.stderr,
            )
            continue
        entries.append(_Fingerprint(name, mitre_id, pattern, severity, source))
    return entries


_CATALOG: list[_Fingerprint] = _load_fingerprints()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _unmapped_mcp(event: dict[str, Any]) -> dict[str, Any]:
    unmapped = event.get("unmapped")
    if isinstance(unmapped, dict):
        mcp = unmapped.get("mcp")
        if isinstance(mcp, dict):
            return mcp
    return {}


def _scan_strings(unmapped_mcp: dict[str, Any]) -> list[tuple[str, str]]:
    """Yield (field_label, content_string) tuples to scan."""
    out: list[tuple[str, str]] = []
    prompt = unmapped_mcp.get("prompt")
    if isinstance(prompt, str) and prompt:
        out.append(("prompt", prompt))
    request = unmapped_mcp.get("request")
    if isinstance(request, dict):
        params = request.get("params")
        if isinstance(params, dict):
            messages = params.get("messages")
            if isinstance(messages, list):
                for i, msg in enumerate(messages):
                    if isinstance(msg, dict):
                        content = msg.get("content")
                        if isinstance(content, str) and content:
                            out.append((f"messages[{i}].content", content))
    return out


def _normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if "class_uid" in event:
        if event.get("class_uid") != APPLICATION_ACTIVITY_UID:
            return None
        mcp = event.get("mcp") or {}
        unmapped_mcp = _unmapped_mcp(event)
        session_uid = str(
            mcp.get("session_uid") or unmapped_mcp.get("session_uid") or "sess-unknown"
        )
        request_uid = str(
            mcp.get("request_uid")
            or unmapped_mcp.get("request_uid")
            or (event.get("metadata") or {}).get("uid")
            or ""
        )
        scan_targets = _scan_strings(unmapped_mcp)
        if not scan_targets:
            return None
        return {
            "session_uid": session_uid,
            "request_uid": request_uid,
            "time_ms": _safe_int(event.get("time")),
            "scan_targets": scan_targets,
            "raw_event": event,
        }

    schema_mode = str(event.get("schema_mode") or "").strip().lower()
    if schema_mode and schema_mode not in {"canonical", "native"}:
        return None
    record_type = str(event.get("record_type") or "").strip().lower()
    if record_type and record_type != "application_activity":
        return None
    unmapped_mcp = _unmapped_mcp(event)
    session_uid = str(event.get("session_uid") or unmapped_mcp.get("session_uid") or "sess-unknown")
    request_uid = str(event.get("request_uid") or unmapped_mcp.get("request_uid") or "")
    # On native, the prompt may live at the top-level too.
    extra_prompt = event.get("prompt")
    scan_targets = _scan_strings(unmapped_mcp)
    if (
        isinstance(extra_prompt, str)
        and extra_prompt
        and not any(label == "prompt" for label, _ in scan_targets)
    ):
        scan_targets.append(("prompt", extra_prompt))
    if not scan_targets:
        return None
    return {
        "session_uid": session_uid,
        "request_uid": request_uid,
        "time_ms": _safe_int(event.get("time_ms") or event.get("time")),
        "scan_targets": scan_targets,
        "raw_event": event,
    }


def _finding_uid(session_uid: str, request_uid: str, scanned_hash: str) -> str:
    safe_req = request_uid or scanned_hash
    return f"det-mcp-adv-input-{session_uid}-{safe_req}"


def _build_native_finding(
    session_uid: str,
    request_uid: str,
    scanned_hash: str,
    matches: list[tuple[_Fingerprint, str]],
    time_ms: int,
) -> dict[str, Any]:
    uid = _finding_uid(session_uid, request_uid, scanned_hash)
    max_sev_id = max(fp.severity_id for fp, _ in matches)
    max_sev = SEVERITY_ID_TO_NAME.get(max_sev_id, "medium")
    names = sorted({fp.name for fp, _ in matches})
    sources_fields = sorted({field for _, field in matches})
    desc = (
        f"MCP request in session '{session_uid}' matched {len(names)} adversarial-input "
        f"fingerprint(s): {', '.join(names)}. Scanned fields: {', '.join(sources_fields)}. "
        f"This is the MITRE ATLAS AML.T0043 Craft Adversarial Data pattern — the prompt "
        f"contains a deterministic signature documented in public prompt-injection / "
        f"jailbreak / system-prompt-leak research. Investigate the upstream client and "
        f"correlate with any downstream tool calls in the same session."
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "output_format": "native",
        "finding_uid": uid,
        "event_uid": uid,
        "provider": "MCP",
        "time_ms": int(time_ms or _now_ms()),
        "severity": max_sev,
        "severity_id": max_sev_id,
        "status": "success",
        "status_id": 1,
        "activity_id": FINDING_ACTIVITY_CREATE,
        "title": "MCP request matched the adversarial-input fingerprint catalog",
        "description": desc,
        "finding_types": ["mcp-adversarial-input", "llm-prompt-injection"],
        "first_seen_time_ms": int(time_ms or 0),
        "last_seen_time_ms": int(time_ms or 0),
        "session_uid": session_uid,
        "request_uid": request_uid,
        "matched_fingerprints": names,
        "match_count": len(names),
        "scanned_fields": sources_fields,
        "mitre_attacks": [
            {
                "version": ATLAS_VERSION,
                "tactic_uid": ATLAS_TACTIC_UID,
                "tactic_name": ATLAS_TACTIC_NAME,
                "technique_uid": ATLAS_TECHNIQUE_UID,
                "technique_name": ATLAS_TECHNIQUE_NAME,
            }
        ],
        "observables": [
            {"name": "session.uid", "type": "Other", "value": session_uid},
            {"name": "request.uid", "type": "Other", "value": request_uid},
            {"name": "matched.fingerprints", "type": "Other", "value": ",".join(names)},
            {"name": "matched.count", "type": "Other", "value": str(len(names))},
            {"name": "scanned.fields", "type": "Other", "value": ",".join(sources_fields)},
        ],
        "evidence_count": len(matches),
    }


def _render_ocsf_finding(native: dict[str, Any]) -> dict[str, Any]:
    attack = native["mitre_attacks"][0]
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": native["severity_id"],
        "status_id": native["status_id"],
        "time": native["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native["event_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "mcp", "ai", "prompt-injection", "atlas"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": native["title"],
            "desc": native["description"],
            "types": native["finding_types"],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": attack["version"],
                    "tactic": {"uid": attack["tactic_uid"], "name": attack["tactic_name"]},
                    "technique": {"uid": attack["technique_uid"], "name": attack["technique_name"]},
                }
            ],
        },
        "observables": native["observables"],
        "evidence": {
            "events_observed": native["evidence_count"],
            "matched_fingerprints": native["matched_fingerprints"],
            "scanned_fields": native["scanned_fields"],
            "match_count": native["match_count"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    output_format: str = "ocsf",
    *,
    catalog: list[_Fingerprint] | None = None,
) -> Iterable[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    fingerprints = catalog if catalog is not None else _CATALOG
    if not fingerprints:
        return

    seen_uids: set[str] = set()

    normalized: list[dict[str, Any]] = []
    for event in events:
        n = _normalize_event(event)
        if n is not None:
            normalized.append(n)
    normalized.sort(key=lambda e: (e["session_uid"], e["time_ms"], e["request_uid"]))

    for event in normalized:
        matches: list[tuple[_Fingerprint, str]] = []
        scanned_concat_parts: list[str] = []
        for field_label, content in event["scan_targets"]:
            scanned_concat_parts.append(content)
            for fp in fingerprints:
                if fp.pattern.search(content):
                    matches.append((fp, field_label))
        if not matches:
            continue
        scanned_hash = _short("\n".join(scanned_concat_parts))
        native = _build_native_finding(
            event["session_uid"],
            event["request_uid"],
            scanned_hash,
            matches,
            event["time_ms"],
        )
        if native["finding_uid"] in seen_uids:
            continue
        seen_uids.add(native["finding_uid"])
        yield native if output_format == "native" else _render_ocsf_finding(native)


def load_jsonl(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
    for lineno, line in enumerate(stream, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            print(
                f"[{SKILL_NAME}] skipping line {lineno}: json parse failed: {exc}", file=sys.stderr
            )
            continue
        if isinstance(obj, dict):
            yield obj
        else:
            print(f"[{SKILL_NAME}] skipping line {lineno}: not a JSON object", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", help="OCSF JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL path. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=OUTPUT_FORMATS,
        default="ocsf",
    )
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
