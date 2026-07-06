"""Detect OWASP Top 10 A07:2021 (Identification and Authentication Failures).

Reads OCSF 1.8 HTTP Activity (class 4002) records from stdin or a file.
Fires on three deterministic patterns over recognised login endpoints:

1. Brute-force burst — ≥ N failed login attempts (401 / 403 / 429) from
   the same `src_endpoint.ip` within a window (default 60s, N=5).
2. Stuffing flip — burst of failures from one IP followed by a 2XX
   success on the same login endpoint inside the window.
3. Weak login — a 2XX `/oauth/token` response with `grant_type=password`
   in the request body, OR a 2XX login without an MFA challenge from
   the same IP in the window. Tagged T1078 (Valid Accounts).

Brute-force / stuffing tag: T1110 (Brute Force). Weak login tag: T1078
(Valid Accounts). Both under tactic TA0006 (Credential Access).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict, deque
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

SKILL_NAME = "detect-web-auth-failures"
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
TACTIC_UID = "TA0006"
TACTIC_NAME = "Credential Access"
TECHNIQUE_BRUTE_FORCE_UID = "T1110"
TECHNIQUE_BRUTE_FORCE_NAME = "Brute Force"
TECHNIQUE_VALID_ACCOUNTS_UID = "T1078"
TECHNIQUE_VALID_ACCOUNTS_NAME = "Valid Accounts"

OWASP_TOP_10 = "A07:2021-Identification-And-Authentication-Failures"

OUTPUT_FORMATS = frozenset({"ocsf", "native"})

DEFAULT_WINDOW_MS = 60 * 1000  # 60s
DEFAULT_MIN_FAILURES = 5

DEFAULT_LOGIN_PATH_PATTERNS: tuple[str, ...] = (
    r"^/login(/.*)?$",
    r"^/signin(/.*)?$",
    r"^/auth(/.*)?$",
    r"^/oauth(/.*)?$",
    r"^/api/login(/.*)?$",
    r"^/api/auth(/.*)?$",
)

# MFA-challenge endpoints — when a 2XX login appears WITHOUT one of these in
# the same window from the same IP, that's the "weak-login no-MFA" signal.
DEFAULT_MFA_PATH_PATTERNS: tuple[str, ...] = (
    r"^/auth/mfa(/.*)?$",
    r"^/auth/2fa(/.*)?$",
    r"^/login/mfa(/.*)?$",
    r"^/api/mfa(/.*)?$",
    r"^/oauth/.*?mfa.*$",
)

FAILED_AUTH_STATUS = frozenset({401, 403, 429})
SUCCESS_STATUS = frozenset({200, 201, 204})


def _request(event: dict[str, Any]) -> dict[str, Any]:
    req = event.get("http_request") or {}
    return req if isinstance(req, dict) else {}


def _path(event: dict[str, Any]) -> str:
    url = _request(event).get("url") or {}
    return str(url.get("path") or "") if isinstance(url, dict) else ""


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


def _body_text(event: dict[str, Any]) -> str:
    body = _request(event).get("body")
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        return json.dumps(body, separators=(",", ":"))
    unmapped = event.get("unmapped") or {}
    if isinstance(unmapped, dict):
        ub = unmapped.get("body")
        if isinstance(ub, str):
            return ub
        if isinstance(ub, dict):
            return json.dumps(ub, separators=(",", ":"))
    return ""


def _is_password_grant(event: dict[str, Any]) -> bool:
    body = _body_text(event)
    if not body:
        return False
    return bool(re.search(r"grant_type\s*[=:]\s*\"?password\"?", body, re.IGNORECASE))


def _path_matches(path: str, compiled: tuple[re.Pattern[str], ...]) -> bool:
    return any(p.match(path) for p in compiled)


def _finding_uid(rule: str, key: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{rule}|{key}|{time_ms}"
    return f"auth-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native(
    *,
    rule: str,
    event: dict[str, Any],
    extra: dict[str, Any],
    technique_uid: str,
    technique_name: str,
) -> dict[str, Any]:
    time_ms = _time_ms(event)
    finding_uid = _finding_uid(rule, f"{_src_ip(event)}|{_path(event)}", time_ms)
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": rule,
        "technique_uid": technique_uid,
        "technique_name": technique_name,
        "actor_uid": _actor_uid(event),
        "src_ip": _src_ip(event),
        "http_method": _method(event),
        "http_path": _path(event),
        "http_status_code": _status_code(event),
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
        "evidence": extra,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    rule = native["rule"]
    title_map = {
        "brute-force-burst": (
            f"{native['evidence'].get('failure_count')} login failures from "
            f"{native['src_ip']} on {native['http_path']} within "
            f"{native['evidence'].get('window_ms')}ms"
        ),
        "stuffing-flip": (
            f"Login burst from {native['src_ip']} on {native['http_path']} flipped to success "
            f"after {native['evidence'].get('failure_count')} failures"
        ),
        "weak-login": (
            f"Weak login on {native['http_path']} from {native['src_ip']}: "
            f"{native['evidence'].get('reason')}"
        ),
    }
    title = title_map.get(rule, f"Authentication failure: {rule}")
    description = (
        f"OWASP A07:2021 (Identification and Authentication Failures). Rule: `{rule}`. "
        f"src.ip=`{native['src_ip'] or '<unknown>'}` path=`{native['http_path']}`."
    )

    observables = [
        {"name": "rule", "type": "Other", "value": rule},
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
    failure_count = native["evidence"].get("failure_count")
    if failure_count is not None:
        observables.append(
            {"name": "auth.failure_count", "type": "Other", "value": str(failure_count)}
        )
    unique_users = native["evidence"].get("unique_users")
    if unique_users is not None:
        observables.append(
            {"name": "auth.unique_users", "type": "Other", "value": str(unique_users)}
        )
    reason = native["evidence"].get("reason")
    if reason:
        observables.append({"name": "auth.reason", "type": "Other", "value": reason})

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
            "labels": ["owasp-top-10", "A07:2021", "auth-failures", rule],
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
                    "technique_uid": native["technique_uid"],
                    "technique_name": native["technique_name"],
                }
            ],
        },
        "observables": observables,
        "evidence": native["evidence"],
    }


def _is_http_activity(event: dict[str, Any]) -> bool:
    return event.get("class_uid") == HTTP_ACTIVITY_CLASS_UID or "http_request" in event


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
    login_path_patterns: Iterable[str] = DEFAULT_LOGIN_PATH_PATTERNS,
    mfa_path_patterns: Iterable[str] = DEFAULT_MFA_PATH_PATTERNS,
    window_ms: int = DEFAULT_WINDOW_MS,
    min_failures: int = DEFAULT_MIN_FAILURES,
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    login_patterns = tuple(re.compile(p) for p in login_path_patterns)
    mfa_patterns = tuple(re.compile(p) for p in mfa_path_patterns)

    # Per-IP windows.
    failures: dict[str, deque[tuple[int, dict[str, Any]]]] = defaultdict(deque)
    mfa_seen: dict[str, deque[int]] = defaultdict(deque)
    # Track which IP windows have already emitted a brute-force burst, so we
    # don't re-emit on every additional failure inside the same window.
    burst_emitted_until: dict[str, int] = {}

    for event in events:
        if not _is_http_activity(event):
            continue
        path = _path(event)
        if not path:
            continue
        ip = _src_ip(event)
        if not ip:
            continue
        now = _time_ms(event)
        cutoff = now - window_ms

        # Maintain MFA window for this ip
        mfa_q = mfa_seen[ip]
        while mfa_q and mfa_q[0] < cutoff:
            mfa_q.popleft()
        if _path_matches(path, mfa_patterns) and _status_code(event) in SUCCESS_STATUS:
            mfa_q.append(now)

        if not _path_matches(path, login_patterns):
            continue

        status = _status_code(event)

        # Maintain failure window for this ip
        bucket = failures[ip]
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        if status in FAILED_AUTH_STATUS:
            bucket.append((now, event))
            # Rule 1: brute-force burst
            if len(bucket) >= min_failures and burst_emitted_until.get(ip, 0) < bucket[0][0]:
                unique_users = len({_actor_uid(e) for _, e in bucket if _actor_uid(e)})
                native = _build_native(
                    rule="brute-force-burst",
                    event=event,
                    extra={
                        "failure_count": len(bucket),
                        "unique_users": unique_users,
                        "window_ms": now - bucket[0][0],
                        "window_start_ms": bucket[0][0],
                        "window_end_ms": now,
                    },
                    technique_uid=TECHNIQUE_BRUTE_FORCE_UID,
                    technique_name=TECHNIQUE_BRUTE_FORCE_NAME,
                )
                burst_emitted_until[ip] = now  # de-dupe within the window
                yield native if output_format == "native" else _to_ocsf(native)
            continue

        if status in SUCCESS_STATUS:
            # Rule 2: stuffing flip — bucket has >= min_failures failures and now success.
            if len(bucket) >= min_failures:
                unique_users = len({_actor_uid(e) for _, e in bucket if _actor_uid(e)})
                native = _build_native(
                    rule="stuffing-flip",
                    event=event,
                    extra={
                        "failure_count": len(bucket),
                        "unique_users": unique_users,
                        "window_ms": now - bucket[0][0],
                        "window_start_ms": bucket[0][0],
                        "window_end_ms": now,
                    },
                    technique_uid=TECHNIQUE_BRUTE_FORCE_UID,
                    technique_name=TECHNIQUE_BRUTE_FORCE_NAME,
                )
                # Reset bucket — the burst has been "consumed" by the success.
                bucket.clear()
                yield native if output_format == "native" else _to_ocsf(native)
                continue

            # Rule 3a: weak login — password grant on /oauth/token
            if path.startswith("/oauth") and _is_password_grant(event):
                native = _build_native(
                    rule="weak-login",
                    event=event,
                    extra={"reason": "oauth-password-grant"},
                    technique_uid=TECHNIQUE_VALID_ACCOUNTS_UID,
                    technique_name=TECHNIQUE_VALID_ACCOUNTS_NAME,
                )
                yield native if output_format == "native" else _to_ocsf(native)
                continue

            # Rule 3b: weak login — 2XX login from this IP without an MFA
            # challenge from the same IP in the same window.
            if not mfa_q:
                native = _build_native(
                    rule="weak-login",
                    event=event,
                    extra={"reason": "no-mfa-challenge-in-window"},
                    technique_uid=TECHNIQUE_VALID_ACCOUNTS_UID,
                    technique_name=TECHNIQUE_VALID_ACCOUNTS_NAME,
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
        description="Detect OWASP A07:2021 (Authentication Failures) in OCSF HTTP Activity.",
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
        "--window-ms",
        type=int,
        default=DEFAULT_WINDOW_MS,
        help=f"Per-IP window size in ms (default {DEFAULT_WINDOW_MS}).",
    )
    parser.add_argument(
        "--min-failures",
        type=int,
        default=DEFAULT_MIN_FAILURES,
        help=f"Minimum failures in window to flag burst (default {DEFAULT_MIN_FAILURES}).",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for finding in detect(
            load_jsonl(in_stream),
            output_format=args.output_format,
            window_ms=args.window_ms,
            min_failures=args.min_failures,
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
