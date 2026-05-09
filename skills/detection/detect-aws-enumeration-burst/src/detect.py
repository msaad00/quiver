"""Detect AWS CloudTrail discovery enumeration bursts.

Reads OCSF 1.8 API Activity (class 6003) records emitted by
`ingest-cloudtrail-ocsf` from stdin or a file. Fires on short-window bursts of
curated high-signal AWS discovery APIs and emits an OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1526 (Cloud Service Discovery).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-aws-enumeration-burst"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_MEDIUM = 3
STATUS_SUCCESS = 1

MITRE_VERSION = "v14"
TACTIC_UID = "TA0007"
TACTIC_NAME = "Discovery"
TECHNIQUE_UID = "T1526"
TECHNIQUE_NAME = "Cloud Service Discovery"

ACCEPTED_PRODUCERS = frozenset({"ingest-cloudtrail-ocsf"})
OUTPUT_FORMATS = frozenset({"ocsf", "native"})

WINDOW_MS = 5 * 60 * 1000
MIN_TOTAL_EVENTS = 6
MIN_DISTINCT_CALLS = 5

DISCOVERY_CALLS = frozenset(
    {
        ("cloudtrail.amazonaws.com", "DescribeTrails"),
        ("ec2.amazonaws.com", "DescribeInstances"),
        ("ec2.amazonaws.com", "DescribeSecurityGroups"),
        ("ec2.amazonaws.com", "DescribeSubnets"),
        ("ec2.amazonaws.com", "DescribeVpcs"),
        ("eks.amazonaws.com", "ListClusters"),
        ("iam.amazonaws.com", "GetAccountAuthorizationDetails"),
        ("iam.amazonaws.com", "ListPolicies"),
        ("iam.amazonaws.com", "ListRoles"),
        ("iam.amazonaws.com", "ListUsers"),
        ("kms.amazonaws.com", "ListKeys"),
        ("lambda.amazonaws.com", "ListFunctions"),
        ("organizations.amazonaws.com", "DescribeOrganization"),
        ("organizations.amazonaws.com", "ListAccounts"),
        ("s3.amazonaws.com", "ListBuckets"),
    }
)


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _api_service(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    service = api.get("service") or {}
    return str(service.get("name") or "")


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == STATUS_SUCCESS


def _actor_name(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _session_uid(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    session = actor.get("session") or {}
    return str(session.get("uid") or "")


def _account(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _src_ip(event: dict[str, Any]) -> str:
    endpoint = event.get("src_endpoint") or {}
    return str(endpoint.get("ip") or "")


def _event_uid(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    return str(metadata.get("uid") or "")


def _time_ms(event: dict[str, Any]) -> int:
    return int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)


def _call_label(service: str, operation: str) -> str:
    return f"{service}:{operation}"


def _principal_key(event: dict[str, Any]) -> str:
    return _session_uid(event) or _actor_name(event)


def _finding_uid(
    *,
    account_uid: str,
    region: str,
    principal_key: str,
    first_seen_time_ms: int,
    last_seen_time_ms: int,
    calls: list[str],
) -> str:
    material = "|".join(
        [
            SKILL_NAME,
            account_uid,
            region,
            principal_key,
            str(first_seen_time_ms),
            str(last_seen_time_ms),
            ",".join(calls),
        ]
    )
    return f"aeb-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    actor_name: str,
    actor_session_uid: str,
    account_uid: str,
    region: str,
    src_ip: str,
    first_seen_time_ms: int,
    last_seen_time_ms: int,
    total_events: int,
    distinct_calls: int,
    observed_calls: list[str],
) -> dict[str, Any]:
    principal_key = actor_session_uid or actor_name
    finding_uid = _finding_uid(
        account_uid=account_uid,
        region=region,
        principal_key=principal_key,
        first_seen_time_ms=first_seen_time_ms,
        last_seen_time_ms=last_seen_time_ms,
        calls=observed_calls,
    )
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "aws-enumeration-burst",
        "actor_name": actor_name,
        "actor_session_uid": actor_session_uid,
        "account_uid": account_uid,
        "region": region,
        "src_ip": src_ip,
        "total_events": total_events,
        "distinct_calls": distinct_calls,
        "observed_calls": observed_calls,
        "first_seen_time_ms": first_seen_time_ms,
        "last_seen_time_ms": last_seen_time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    description = (
        f"Principal `{native['actor_name'] or native['actor_session_uid'] or 'unknown'}` "
        f"made `{native['total_events']}` high-signal AWS discovery calls across "
        f"`{native['distinct_calls']}` distinct APIs within five minutes in account "
        f"`{native['account_uid']}` ({native['region']}). Calls observed: "
        f"{', '.join(native['observed_calls'])}. Source IP: "
        f"{native['src_ip'] or '<unknown>'}."
    )
    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {
            "name": "actor.name",
            "type": "Other",
            "value": native["actor_name"] or native["actor_session_uid"] or "unknown",
        },
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "account.uid", "type": "Other", "value": native["account_uid"]},
        {"name": "region", "type": "Other", "value": native["region"]},
        {"name": "events.total", "type": "Other", "value": str(native["total_events"])},
        {"name": "calls.distinct", "type": "Other", "value": str(native["distinct_calls"])},
        {"name": "calls.observed", "type": "Other", "value": ", ".join(native["observed_calls"])},
    ]
    if native["actor_session_uid"]:
        observables.append(
            {"name": "actor.session.uid", "type": "Other", "value": native["actor_session_uid"]}
        )
    if native["src_ip"]:
        observables.append({"name": "src.ip", "type": "IP Address", "value": native["src_ip"]})
    return {
        "activity_id": FINDING_ACTIVITY_CREATE,
        "category_uid": FINDING_CATEGORY_UID,
        "category_name": FINDING_CATEGORY_NAME,
        "class_uid": FINDING_CLASS_UID,
        "class_name": FINDING_CLASS_NAME,
        "type_uid": FINDING_TYPE_UID,
        "severity_id": SEVERITY_MEDIUM,
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
            "labels": ["aws", "cloudtrail", "discovery", "enumeration"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": "AWS discovery API burst",
            "desc": description,
            "types": ["aws-enumeration-burst"],
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
            "events_observed": native["total_events"],
            "distinct_calls": native["distinct_calls"],
            "observed_calls": native["observed_calls"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        producer = _producer(event)
        if producer not in ACCEPTED_PRODUCERS:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="wrong_source",
                message=f"skipping event from non-cloudtrail producer `{producer}`",
            )
            continue
        if not _is_success(event):
            continue
        service = _api_service(event)
        operation = _api_operation(event)
        if (service, operation) not in DISCOVERY_CALLS:
            continue
        actor_name = _actor_name(event)
        actor_session_uid = _session_uid(event)
        principal_key = actor_session_uid or actor_name
        if not principal_key:
            emit_stderr_event(
                SKILL_NAME,
                level="warning",
                event="missing_actor",
                message="skipping discovery event with no actor or session identifier",
            )
            continue
        account_uid = _account(event)
        region = _region(event)
        key = (account_uid, region, principal_key)
        grouped[key].append(
            {
                "event_uid": _event_uid(event),
                "time_ms": _time_ms(event),
                "actor_name": actor_name,
                "actor_session_uid": actor_session_uid,
                "account_uid": account_uid,
                "region": region,
                "src_ip": _src_ip(event),
                "service": service,
                "operation": operation,
                "call_label": _call_label(service, operation),
            }
        )

    findings: list[dict[str, Any]] = []
    for key in sorted(grouped):
        window: deque[dict[str, Any]] = deque()
        events_for_key = sorted(grouped[key], key=lambda item: (item["time_ms"], item["event_uid"]))
        for summary in events_for_key:
            while window and summary["time_ms"] - window[0]["time_ms"] > WINDOW_MS:
                window.popleft()
            window.append(summary)
            distinct_calls = sorted({item["call_label"] for item in window})
            if len(window) < MIN_TOTAL_EVENTS or len(distinct_calls) < MIN_DISTINCT_CALLS:
                continue
            native = _build_native_finding(
                actor_name=summary["actor_name"],
                actor_session_uid=summary["actor_session_uid"],
                account_uid=summary["account_uid"],
                region=summary["region"],
                src_ip=summary["src_ip"],
                first_seen_time_ms=window[0]["time_ms"],
                last_seen_time_ms=window[-1]["time_ms"],
                total_events=len(window),
                distinct_calls=len(distinct_calls),
                observed_calls=distinct_calls,
            )
            findings.append(native if output_format == "native" else _to_ocsf(native))
            window.clear()

    for finding in findings:
        yield finding


def _iter_jsonl(path: str | None) -> Iterator[dict[str, Any]]:
    handle = open(path, "r", encoding="utf-8") if path else sys.stdin
    with handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="invalid_json",
                    message=f"skipping line {line_number}: invalid JSON ({exc.msg})",
                )
                continue
            if isinstance(obj, dict):
                yield obj
            else:
                emit_stderr_event(
                    SKILL_NAME,
                    level="warning",
                    event="wrong_shape",
                    message=f"skipping line {line_number}: expected JSON object",
                )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="optional JSONL input path; defaults to stdin")
    parser.add_argument(
        "--output-format",
        choices=sorted(OUTPUT_FORMATS),
        default="ocsf",
        help="emit OCSF Detection Finding 2004 (default) or native findings",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    for finding in detect(_iter_jsonl(args.path), output_format=args.output_format):
        json.dump(finding, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
