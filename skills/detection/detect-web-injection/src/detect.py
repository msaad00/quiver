"""Detect OWASP Top 10 A03:2021 (Injection) signals in HTTP access logs.

Reads OCSF 1.8 HTTP Activity (class 4002) records from stdin or a file.
Fires when the request query string, URL path, body, or one of a small
list of operator-controllable headers matches a curated injection
signature. Each signature is tagged with an injection family
(sql / command / ldap / nosql / xpath / template).

Output: OCSF 1.8 Detection Finding (class 2004), tagged MITRE ATT&CK
T1190 + OWASP A03.

Why deterministic regex (and not ML):
- The SKILL_CONTRACT bars LLM/ML detection in this skill.
- The pattern catalogue is curated for low-FP — common probe payloads
  every reviewer can recognise on sight.
- Operators extend `INJECTION_PATTERNS` or pass `extra_patterns=` to
  `detect(...)` for org-specific payloads.

Redaction: the finding's `payload_excerpt` is truncated to 60 characters
to avoid leaking full request bodies into downstream SIEMs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.errors import emit_error  # noqa: E402
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402
from skills._shared.logging import get_logger  # noqa: E402
from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-web-injection"
LAYER = "detection"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"

log = get_logger(__name__, skill=SKILL_NAME, layer=LAYER)

FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

HTTP_ACTIVITY_CLASS_UID = 4002

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

MITRE_VERSION = "v14"
TACTIC_UID = "TA0001"
TACTIC_NAME = "Initial Access"
TECHNIQUE_UID = "T1190"
TECHNIQUE_NAME = "Exploit Public-Facing Application"

OWASP_TOP_10 = "A03:2021-Injection"

OUTPUT_FORMATS = frozenset({"ocsf", "native"})

PAYLOAD_EXCERPT_LEN = 60

# Curated low-FP payloads. Each entry: (family, label, regex). The regex is
# applied to URL-decoded text where possible — for the body we accept whatever
# the ingester gave us.
INJECTION_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # --- SQL ---
    ("sql", "union-select", re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE)),
    ("sql", "or-1-equals-1", re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE)),
    (
        "sql",
        "tautology-quoted",
        re.compile(r"['\"]\s*or\s*['\"]?\s*1\s*['\"]?\s*=\s*['\"]?\s*1", re.IGNORECASE),
    ),
    (
        "sql",
        "comment-tail",
        re.compile(r"(--\s|#\s|/\*).*?(\bor\b|\bunion\b|\bdrop\b|\bselect\b)", re.IGNORECASE),
    ),
    ("sql", "drop-table", re.compile(r"\bdrop\s+table\b", re.IGNORECASE)),
    (
        "sql",
        "stacked-query",
        re.compile(r";\s*(select|insert|update|delete|drop|exec)\b", re.IGNORECASE),
    ),
    (
        "sql",
        "sleep-time-based",
        re.compile(r"\b(sleep|pg_sleep|waitfor\s+delay)\s*\(", re.IGNORECASE),
    ),
    # --- Command ---
    ("command", "shell-substitute", re.compile(r"\$\([^)]{1,40}\)")),
    ("command", "backticks", re.compile(r"`[^`]{1,40}`")),
    ("command", "pipe-rm", re.compile(r"[|;&]\s*(rm|cat|wget|curl|nc|bash|sh|python|perl)\b")),
    ("command", "etc-passwd", re.compile(r"/etc/(passwd|shadow)\b")),
    # --- LDAP ---
    ("ldap", "wildcard-bypass", re.compile(r"\(\|?\(?(uid|cn|userPassword)\s*=\s*\*")),
    ("ldap", "or-injection", re.compile(r"\)\s*\(\s*\|\s*\(")),
    # --- NoSQL ---
    ("nosql", "ne-operator", re.compile(r"\$ne\b")),
    ("nosql", "where-injection", re.compile(r"\$where\b")),
    ("nosql", "regex-injection", re.compile(r'"\$regex"\s*:')),
    # --- XPath ---
    ("xpath", "or-true", re.compile(r"\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1", re.IGNORECASE)),
    # --- Template / SSTI ---
    ("template", "jinja-arith", re.compile(r"\{\{\s*\d+\s*[*+\-/]\s*\d+\s*\}\}")),
    ("template", "twig-config", re.compile(r"\{\{\s*_self\b")),
    ("template", "el-runtime", re.compile(r"\$\{Runtime\.")),
)


def _request(event: dict[str, Any]) -> dict[str, Any]:
    req = event.get("http_request") or {}
    return req if isinstance(req, dict) else {}


def _path(event: dict[str, Any]) -> str:
    url = _request(event).get("url") or {}
    return str(url.get("path") or "") if isinstance(url, dict) else ""


def _query_string(event: dict[str, Any]) -> str:
    url = _request(event).get("url") or {}
    return str(url.get("query_string") or "") if isinstance(url, dict) else ""


def _body(event: dict[str, Any]) -> str:
    body = _request(event).get("body")
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        return json.dumps(body, separators=(",", ":"), sort_keys=True)
    unmapped = event.get("unmapped") or {}
    if isinstance(unmapped, dict):
        ub = unmapped.get("body")
        if isinstance(ub, str):
            return ub
        if isinstance(ub, dict):
            return json.dumps(ub, separators=(",", ":"), sort_keys=True)
    return ""


def _watched_headers(event: dict[str, Any]) -> dict[str, str]:
    """Return a name→value dict for the small set of operator-watched headers
    that commonly carry injection (Referer/User-Agent/X-Forwarded-For)."""
    out: dict[str, str] = {}
    headers = _request(event).get("headers") or []
    watched = {"referer", "user-agent", "x-forwarded-for"}
    if isinstance(headers, list):
        for h in headers:
            if not isinstance(h, dict):
                continue
            name = str(h.get("name") or "").lower()
            if name in watched:
                value = h.get("value")
                if value:
                    out[name] = str(value)
    elif isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() in watched and v:
                out[str(k).lower()] = str(v)
    return out


def _method(event: dict[str, Any]) -> str:
    return str(_request(event).get("http_method") or "").upper()


def _status_code(event: dict[str, Any]) -> int:
    resp = event.get("http_response") or {}
    code = resp.get("status_code") if isinstance(resp, dict) else None
    try:
        return int(code) if code is not None else 0
    except (TypeError, ValueError):
        return 0


def _src_ip(event: dict[str, Any]) -> str:
    src = event.get("src_endpoint") or {}
    return str(src.get("ip") or "")


def _actor_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("name") or "")


def _time_ms(event: dict[str, Any]) -> int:
    t = event.get("time")
    try:
        return int(t) if t is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    except (TypeError, ValueError):
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _redact(text: str) -> str:
    if len(text) <= PAYLOAD_EXCERPT_LEN:
        return text
    return text[:PAYLOAD_EXCERPT_LEN] + "..."


def _finding_uid(family: str, label: str, src_ip: str, path: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{family}|{label}|{src_ip}|{path}|{time_ms}"
    return f"inj-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native(
    *,
    event: dict[str, Any],
    family: str,
    label: str,
    surface: str,
    excerpt: str,
) -> dict[str, Any]:
    time_ms = _time_ms(event)
    finding_uid = _finding_uid(family, label, _src_ip(event), _path(event), time_ms)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "injection",
        "injection_family": family,
        "signature_label": label,
        "matched_surface": surface,
        "payload_excerpt": _redact(excerpt),
        "actor_uid": _actor_uid(event),
        "src_ip": _src_ip(event),
        "http_method": _method(event),
        "http_path": _path(event),
        "http_status_code": _status_code(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    title = (
        f"{native['injection_family'].upper()} injection signature `{native['signature_label']}` matched "
        f"in {native['matched_surface']} of {native['http_method']} {native['http_path']} from "
        f"{native['src_ip'] or '<unknown>'}"
    )
    description = (
        f"OWASP A03:2021 (Injection). Family: `{native['injection_family']}`. "
        f"Signature: `{native['signature_label']}`. Surface: `{native['matched_surface']}`. "
        f"Excerpt (redacted): `{native['payload_excerpt']}`."
    )

    observables = [
        {"name": "rule", "type": "Other", "value": "injection"},
        {"name": "injection.family", "type": "Other", "value": native["injection_family"]},
        {"name": "injection.signature_label", "type": "Other", "value": native["signature_label"]},
        {"name": "injection.matched_surface", "type": "Other", "value": native["matched_surface"]},
        {"name": "injection.payload_excerpt", "type": "Other", "value": native["payload_excerpt"]},
        {"name": "actor.user.uid", "type": "User", "value": native["actor_uid"] or "unknown"},
        {"name": "src.ip", "type": "IP Address", "value": native["src_ip"]},
        {"name": "http_request.http_method", "type": "Other", "value": native["http_method"]},
        {"name": "http_request.url.path", "type": "URL String", "value": native["http_path"]},
        {
            "name": "http_response.status_code",
            "type": "Other",
            "value": str(native["http_status_code"]),
        },
    ]

    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_HIGH,
        "status_id": STATUS_SUCCESS,
        "time": native["first_seen_time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": native["finding_uid"],
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["owasp-top-10", "A03:2021", "injection", native["injection_family"]],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": title,
            "desc": description,
            "types": [OWASP_TOP_10, native["injection_family"]],
            "first_seen_time": native["first_seen_time_ms"],
            "last_seen_time": native["last_seen_time_ms"],
            "attacks": [
                {
                    "version": MITRE_VERSION,
                    "tactic_uid": TACTIC_UID,
                    "tactic_name": TACTIC_NAME,
                    "technique_uid": TECHNIQUE_UID,
                    "technique_name": TECHNIQUE_NAME,
                }
            ],
        },
        "observables": observables,
        "evidence": {
            "matched_surface": native["matched_surface"],
            "signature_label": native["signature_label"],
            "injection_family": native["injection_family"],
            "payload_excerpt": native["payload_excerpt"],
        },
    }


def _is_http_activity(event: dict[str, Any]) -> bool:
    return event.get("class_uid") == HTTP_ACTIVITY_CLASS_UID or "http_request" in event


def _scan_surface(
    text: str,
    patterns: tuple[tuple[str, str, re.Pattern[str]], ...],
) -> tuple[str, str, str] | None:
    """Return (family, label, matched_excerpt) on first hit, else None."""
    if not text:
        return None
    for family, label, regex in patterns:
        m = regex.search(text)
        if m:
            return family, label, m.group(0)
    return None


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
    extra_patterns: Iterable[tuple[str, str, re.Pattern[str]]] = (),
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    patterns = INJECTION_PATTERNS + tuple(extra_patterns)

    for event in events:
        if not _is_http_activity(event):
            continue

        # Order matters: query string is the most common surface, then body,
        # then path-segment, then headers. We yield one finding per matched
        # surface (an attack often appears in more than one surface and the
        # forensic story benefits from seeing each).
        surfaces = (
            ("query_string", _query_string(event)),
            ("body", _body(event)),
            ("path", _path(event)),
        )
        for surface_name, text in surfaces:
            hit = _scan_surface(text, patterns)
            if hit:
                family, label, excerpt = hit
                native = _build_native(
                    event=event,
                    family=family,
                    label=label,
                    surface=surface_name,
                    excerpt=excerpt,
                )
                yield native if output_format == "native" else _to_ocsf(native)

        for header_name, header_value in _watched_headers(event).items():
            hit = _scan_surface(header_value, patterns)
            if hit:
                family, label, excerpt = hit
                native = _build_native(
                    event=event,
                    family=family,
                    label=label,
                    surface=f"header:{header_name}",
                    excerpt=excerpt,
                )
                yield native if output_format == "native" else _to_ocsf(native)


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
            )
            continue
        if isinstance(obj, dict):
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect OWASP A03:2021 (Injection) signatures in OCSF HTTP Activity.",
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for finding in detect(load_jsonl(in_stream), output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    except Exception as exc:  # pragma: no cover - defensive
        return emit_error(SKILL_NAME, exc)
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
