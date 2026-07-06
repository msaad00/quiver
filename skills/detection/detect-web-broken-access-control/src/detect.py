"""Detect OWASP Top 10 A01:2021 (Broken Access Control) signals.

Reads OCSF 1.8 HTTP Activity (class 4002) records from stdin or a file.
Fires on two deterministic patterns:

1. IDOR — the URL path embeds an id (`/users/<id>/...`,
   `/accounts/<id>/...`, `/orgs/<id>/...`, `/tenants/<id>/...`,
   `/customers/<id>/...`) that does not match `actor.user.uid` or any
   `user.groups[].uid`. Horizontal privilege escalation.

2. Auth-swap flip — within a configurable window (default 60s), a 4XX
   (`401`/`403`) on a `(src_endpoint.ip, http_request.url.path)` pair
   is followed by a 2XX (`200`/`201`/`204`) on the same pair AND the
   `Authorization` header value (compared as a redacted hash) differs.
   Token-replay / stolen-token bypass.

Both patterns produce an OCSF 1.8 Detection Finding (class 2004) tagged
MITRE ATT&CK T1212 + OWASP A01.

Why deterministic: the SKILL_CONTRACT bars LLM/heuristic detection here.
The two rules above are the cheapest high-precision signals an operator
gets from raw access logs without per-route authz instrumentation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import deque
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

SKILL_NAME = "detect-web-broken-access-control"
LAYER = "detection"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"

log = get_logger(__name__, skill=SKILL_NAME, layer=LAYER)

# OCSF Detection Finding 2004
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

# OCSF HTTP Activity (input)
HTTP_ACTIVITY_CLASS_UID = 4002

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

# MITRE ATT&CK v14 — broken-access-control fits T1212
MITRE_VERSION = "v14"
TACTIC_UID = "TA0006"
TACTIC_NAME = "Credential Access"
TECHNIQUE_UID = "T1212"
TECHNIQUE_NAME = "Exploitation for Credential Access"

OWASP_TOP_10 = "A01:2021-Broken-Access-Control"

OUTPUT_FORMATS = frozenset({"ocsf", "native"})

# Path templates that bind <id> to a principal claim. Operator overrides via
# DETECT_WEB_BAC_ID_PATHS (comma-separated) or pass into detect(...).
DEFAULT_ID_PATH_PATTERNS: tuple[str, ...] = (
    r"^/users/(?P<id>[A-Za-z0-9._-]+)(/.*)?$",
    r"^/accounts/(?P<id>[A-Za-z0-9._-]+)(/.*)?$",
    r"^/orgs/(?P<id>[A-Za-z0-9._-]+)(/.*)?$",
    r"^/tenants/(?P<id>[A-Za-z0-9._-]+)(/.*)?$",
    r"^/customers/(?P<id>[A-Za-z0-9._-]+)(/.*)?$",
)

DEFAULT_AUTH_SWAP_WINDOW_MS = 60 * 1000  # 60s
FORBIDDEN_STATUS = frozenset({401, 403})
SUCCESS_STATUS = frozenset({200, 201, 204})


def _request(event: dict[str, Any]) -> dict[str, Any]:
    req = event.get("http_request") or {}
    return req if isinstance(req, dict) else {}


def _response(event: dict[str, Any]) -> dict[str, Any]:
    resp = event.get("http_response") or {}
    return resp if isinstance(resp, dict) else {}


def _path(event: dict[str, Any]) -> str:
    req = _request(event)
    url = req.get("url") or {}
    if isinstance(url, dict):
        return str(url.get("path") or "")
    return ""


def _method(event: dict[str, Any]) -> str:
    return str(_request(event).get("http_method") or "").upper()


def _status_code(event: dict[str, Any]) -> int:
    code = _response(event).get("status_code")
    try:
        return int(code) if code is not None else 0
    except (TypeError, ValueError):
        return 0


def _actor_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("uid") or user.get("name") or "")


def _actor_groups(event: dict[str, Any]) -> list[str]:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    groups = user.get("groups") or []
    out: list[str] = []
    if isinstance(groups, list):
        for g in groups:
            if isinstance(g, dict):
                gid = g.get("uid") or g.get("name")
                if gid:
                    out.append(str(gid))
    return out


def _src_ip(event: dict[str, Any]) -> str:
    src = event.get("src_endpoint") or {}
    return str(src.get("ip") or "")


def _time_ms(event: dict[str, Any]) -> int:
    t = event.get("time")
    try:
        return int(t) if t is not None else int(datetime.now(timezone.utc).timestamp() * 1000)
    except (TypeError, ValueError):
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _authz_header_hash(event: dict[str, Any]) -> str:
    """Return a stable hash of the Authorization header (or ""). We never echo
    the raw token — this is purely a "did the credential change" signal."""
    headers = _request(event).get("headers") or []
    if isinstance(headers, list):
        for h in headers:
            if not isinstance(h, dict):
                continue
            if str(h.get("name") or "").lower() == "authorization":
                value = str(h.get("value") or "")
                if not value:
                    return ""
                return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    # Some pipelines pass it as a dict
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "authorization" and v:
                return hashlib.sha256(str(v).encode("utf-8")).hexdigest()[:16]
    return ""


def _match_id_path(path: str, patterns: tuple[re.Pattern[str], ...]) -> tuple[str, str]:
    """Return (matched_pattern_label, captured_id) or ("", "")."""
    for pat in patterns:
        m = pat.match(path)
        if m:
            return pat.pattern, m.group("id")
    return "", ""


def _finding_uid(rule: str, key: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{rule}|{key}|{time_ms}"
    return f"bac-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native(
    *,
    rule: str,
    event: dict[str, Any],
    actor_uid: str,
    target_id: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    time_ms = _time_ms(event)
    finding_uid = _finding_uid(rule, f"{actor_uid or '<anon>'}|{target_id}|{_path(event)}", time_ms)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": rule,
        "actor_uid": actor_uid,
        "target_id": target_id,
        "src_ip": _src_ip(event),
        "http_method": _method(event),
        "http_path": _path(event),
        "status_code": _status_code(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "evidence": extra or {},
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    rule = native["rule"]
    actor = native["actor_uid"] or "<unauthenticated>"
    title_map = {
        "idor": (
            f"User `{actor}` accessed resource id `{native['target_id']}` they do not own "
            f"({native['http_method']} {native['http_path']})"
        ),
        "auth-swap-flip": (
            f"Authorization swap on `{native['http_path']}` flipped {native['evidence'].get('first_status')} → "
            f"{native['evidence'].get('second_status')} from {native['src_ip']} within "
            f"{native['evidence'].get('window_ms')}ms"
        ),
    }
    title = title_map.get(rule, f"Broken access control: {rule}")
    description = (
        f"OWASP A01:2021 (Broken Access Control). Rule: `{rule}`. "
        f"Actor `{actor}` from {native['src_ip'] or '<unknown>'} on "
        f"{native['http_method']} {native['http_path']}."
    )

    observables = [
        {"name": "rule", "type": "Other", "value": rule},
        {"name": "actor.user.uid", "type": "User", "value": native["actor_uid"] or "unknown"},
        {"name": "src.ip", "type": "IP Address", "value": native["src_ip"]},
        {"name": "http_request.http_method", "type": "Other", "value": native["http_method"]},
        {"name": "http_request.url.path", "type": "URL String", "value": native["http_path"]},
        {"name": "http_response.status_code", "type": "Other", "value": str(native["status_code"])},
        {"name": "target.uid", "type": "Other", "value": native["target_id"]},
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
            "labels": ["owasp-top-10", "A01:2021", "broken-access-control"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": title,
            "desc": description,
            "types": [OWASP_TOP_10, rule],
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
        "evidence": native["evidence"] or {},
    }


def _is_http_activity(event: dict[str, Any]) -> bool:
    return event.get("class_uid") == HTTP_ACTIVITY_CLASS_UID or "http_request" in event


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
    id_path_patterns: Iterable[str] = DEFAULT_ID_PATH_PATTERNS,
    auth_swap_window_ms: int = DEFAULT_AUTH_SWAP_WINDOW_MS,
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    compiled = tuple(re.compile(p) for p in id_path_patterns)

    # Sliding window for auth-swap flip: keyed by (src_ip, path) → deque of
    # (time_ms, status_code, authz_hash, raw_event).
    swap_state: dict[tuple[str, str], deque[tuple[int, int, str, dict[str, Any]]]] = {}

    for event in events:
        if not _is_http_activity(event):
            continue

        path = _path(event)
        if not path:
            continue

        # ---------- Rule 1: IDOR ----------
        actor_uid = _actor_uid(event)
        groups = _actor_groups(event)
        pattern_label, captured_id = _match_id_path(path, compiled)
        if pattern_label and captured_id:
            # Anonymous request to an id-bearing path → still a finding.
            mismatch = bool(actor_uid) and captured_id != actor_uid and captured_id not in groups
            if mismatch or not actor_uid:
                native = _build_native(
                    rule="idor",
                    event=event,
                    actor_uid=actor_uid,
                    target_id=captured_id,
                    extra={
                        "path_pattern": pattern_label,
                        "captured_id": captured_id,
                        "actor_uid": actor_uid,
                        "actor_groups": groups,
                    },
                )
                yield native if output_format == "native" else _to_ocsf(native)

        # ---------- Rule 2: Auth-swap flip ----------
        ip = _src_ip(event)
        status = _status_code(event)
        if not ip or status == 0:
            continue
        key = (ip, path)
        now = _time_ms(event)
        bucket = swap_state.setdefault(key, deque())
        cutoff = now - auth_swap_window_ms
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()
        authz_hash = _authz_header_hash(event)
        bucket.append((now, status, authz_hash, event))

        if status in SUCCESS_STATUS:
            # Look back for a forbidden record on the same key with a different authz hash.
            for prior_time, prior_status, prior_hash, prior_event in list(bucket)[:-1]:
                if prior_status not in FORBIDDEN_STATUS:
                    continue
                # Both hashes must be present and DIFFERENT to flag a swap.
                if not authz_hash or not prior_hash or authz_hash == prior_hash:
                    continue
                native = _build_native(
                    rule="auth-swap-flip",
                    event=event,
                    actor_uid=_actor_uid(event),
                    target_id=path,
                    extra={
                        "first_status": prior_status,
                        "second_status": status,
                        "first_time_ms": prior_time,
                        "second_time_ms": now,
                        "window_ms": now - prior_time,
                        "first_authz_hash": prior_hash,
                        "second_authz_hash": authz_hash,
                    },
                )
                yield native if output_format == "native" else _to_ocsf(native)
                break  # one finding per success record


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
        description="Detect OWASP A01:2021 (Broken Access Control) in OCSF HTTP Activity.",
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    parser.add_argument(
        "--auth-swap-window-ms",
        type=int,
        default=DEFAULT_AUTH_SWAP_WINDOW_MS,
        help=f"Auth-swap flip window in ms (default {DEFAULT_AUTH_SWAP_WINDOW_MS}).",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for finding in detect(
            load_jsonl(in_stream),
            output_format=args.output_format,
            auth_swap_window_ms=args.auth_swap_window_ms,
        ):
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
