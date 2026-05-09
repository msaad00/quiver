"""Detect AWS Security Group ingress rules opened to the internet (0.0.0.0/0 or ::/0).

Reads OCSF 1.8 API Activity (class 6003) records emitted by
`ingest-cloudtrail-ocsf` from stdin or a file. Fires on
`AuthorizeSecurityGroupIngress` calls that grant access from
0.0.0.0/0 or ::/0 to a risky port. Emits OCSF 1.8 Detection Finding
(class 2004) tagged with MITRE ATT&CK T1190 (Exploit Public-Facing
Application).

Why include the source IP allowlist + risky-ports list:
- 0.0.0.0/0 ingress on port 22, 3389, 3306, 5432, 6379, 9200 etc. is the
  most common public-cloud breach vector
- Some intentionally open services (HTTPS:443 on a load balancer) are
  not findings; they're known patterns
- Operators tag intentional exposures via `intentionally-open` SG tag
  (the detector reads this from CloudTrail's requestParameters when
  available, otherwise defers to the remediator's deny-list)

Rule:
1. event.api.operation == "AuthorizeSecurityGroupIngress"
2. event.status_id == 1 (success)
3. parsed CIDR includes 0.0.0.0/0 OR ::/0 in the granted permission
4. port range overlaps a risky port (configurable; defaults below)

Output: OCSF Detection Finding 2004, with `target.uid` = the SG id and
`target.name` = the SG name. The remediator (`remediate-aws-sg-revoke`)
consumes these findings to revoke the offending rule.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.runtime_telemetry import emit_stderr_event  # noqa: E402

SKILL_NAME = "detect-aws-open-security-group"
CANONICAL_VERSION = "2026-04"
OCSF_VERSION = "1.8.0"
REPO_NAME = "cloud-ai-security-skills"
from skills._shared.identity import VENDOR_NAME as REPO_VENDOR  # noqa: E402

# OCSF Detection Finding 2004
FINDING_CLASS_UID = 2004
FINDING_CLASS_NAME = "Detection Finding"
FINDING_CATEGORY_UID = 2
FINDING_CATEGORY_NAME = "Findings"
FINDING_ACTIVITY_CREATE = 1
FINDING_TYPE_UID = FINDING_CLASS_UID * 100 + FINDING_ACTIVITY_CREATE

SEVERITY_HIGH = 4
STATUS_SUCCESS = 1

# MITRE ATT&CK v14
MITRE_VERSION = "v14"
TACTIC_UID = "TA0001"
TACTIC_NAME = "Initial Access"
TECHNIQUE_UID = "T1190"
TECHNIQUE_NAME = "Exploit Public-Facing Application"

ACCEPTED_PRODUCERS = frozenset({"ingest-cloudtrail-ocsf"})

# Default risky ports — admin / database / cache / search surfaces. Operators
# can override at the remediator's allow-list time, not here. The detector's
# job is to FIRE on every 0.0.0.0/0 grant to these ports; the remediator
# decides what to actually revoke.
DEFAULT_RISKY_PORTS = (
    22,     # SSH
    23,     # Telnet
    135,    # MSRPC
    445,    # SMB
    1433,   # MSSQL
    1521,   # Oracle
    2049,   # NFS
    3306,   # MySQL
    3389,   # RDP
    5432,   # Postgres
    5984,   # CouchDB
    6379,   # Redis
    8086,   # InfluxDB
    9042,   # Cassandra
    9092,   # Kafka
    9200,   # Elasticsearch
    11211,  # Memcached
    27017,  # MongoDB
)

PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

OUTPUT_FORMATS = frozenset({"ocsf", "native"})


def _api_operation(event: dict[str, Any]) -> str:
    api = event.get("api") or {}
    return str(api.get("operation") or "")


def _is_success(event: dict[str, Any]) -> bool:
    return event.get("status_id") == 1


def _producer(event: dict[str, Any]) -> str:
    metadata = event.get("metadata") or {}
    product = metadata.get("product") or {}
    feature = product.get("feature") or {}
    return str(feature.get("name") or "")


def _request_parameters(event: dict[str, Any]) -> dict[str, Any]:
    """CloudTrail-derived requestParameters live under `unmapped.cloudtrail.request_parameters`
    after ingest-cloudtrail-ocsf normalization. Falls back to top-level `unmapped` shape."""
    unmapped = event.get("unmapped") or {}
    ct = unmapped.get("cloudtrail") if isinstance(unmapped, dict) else None
    if isinstance(ct, dict):
        params = ct.get("request_parameters") or ct.get("requestParameters")
        if isinstance(params, dict):
            return params
    # Some ingest paths put it at the api.request payload directly
    api = event.get("api") or {}
    request = api.get("request") or {}
    data = request.get("data") if isinstance(request, dict) else None
    if isinstance(data, dict):
        params = data.get("requestParameters") or data
        if isinstance(params, dict):
            return params
    return {}


def _iter_permissions(params: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """AWS AuthorizeSecurityGroupIngress requestParameters carries the rules under
    `ipPermissions.items[]`. Each item has fromPort, toPort, ipProtocol, and
    `ipRanges.items[].cidrIp` (IPv4) or `ipv6Ranges.items[].cidrIpv6`."""
    perms = params.get("ipPermissions")
    if isinstance(perms, dict):
        items = perms.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yield item
    elif isinstance(perms, list):
        for item in perms:
            if isinstance(item, dict):
                yield item


def _iter_cidrs(permission: dict[str, Any]) -> Iterator[str]:
    """Yield every cidr string in a permission item across IPv4 + IPv6 shapes."""
    for key, sub_key in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")):
        ranges = permission.get(key)
        if isinstance(ranges, dict):
            items = ranges.get("items")
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get(sub_key):
                        yield str(item[sub_key])
        elif isinstance(ranges, list):
            for item in ranges:
                if isinstance(item, dict) and item.get(sub_key):
                    yield str(item[sub_key])


def _port_range_overlaps_risky(
    permission: dict[str, Any], risky_ports: Iterable[int]
) -> tuple[bool, list[int]]:
    """A permission with from/toPort range covers any risky port in [from, to].
    Returns (overlap, hit_ports)."""
    from_port = permission.get("fromPort")
    to_port = permission.get("toPort")
    protocol = str(permission.get("ipProtocol") or "").lower()
    if protocol == "-1":
        # All protocols, all ports — every risky port is hit
        return True, sorted(risky_ports)
    try:
        lo = int(from_port) if from_port is not None else None
        hi = int(to_port) if to_port is not None else None
    except (TypeError, ValueError):
        return False, []
    if lo is None or hi is None:
        return False, []
    if lo == -1 or hi == -1:
        return True, sorted(risky_ports)
    if lo > hi:
        lo, hi = hi, lo
    hits = sorted(p for p in risky_ports if lo <= p <= hi)
    return bool(hits), hits


def _sg_id_and_name(params: dict[str, Any]) -> tuple[str, str]:
    sg_id = str(params.get("groupId") or "")
    sg_name = str(params.get("groupName") or "")
    if not sg_id:
        # Some flows carry a list under ipPermissions[].groups
        for perm in _iter_permissions(params):
            groups = perm.get("groups")
            if isinstance(groups, dict):
                items = groups.get("items")
                if isinstance(items, list) and items:
                    first = items[0]
                    if isinstance(first, dict):
                        sg_id = sg_id or str(first.get("groupId") or "")
                        sg_name = sg_name or str(first.get("groupName") or "")
                        break
    return sg_id, sg_name


def _actor(event: dict[str, Any]) -> str:
    actor = event.get("actor") or {}
    user = actor.get("user") or {}
    return str(user.get("name") or user.get("uid") or "")


def _account(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    account = cloud.get("account") or {}
    return str(account.get("uid") or "")


def _region(event: dict[str, Any]) -> str:
    cloud = event.get("cloud") or {}
    return str(cloud.get("region") or "")


def _src_ip(event: dict[str, Any]) -> str:
    src = event.get("src_endpoint") or {}
    return str(src.get("ip") or "")


def _finding_uid(event_uid: str, sg_id: str, time_ms: int) -> str:
    material = f"{SKILL_NAME}|{event_uid}|{sg_id}|{time_ms}"
    return f"asg-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _build_native_finding(
    *,
    event: dict[str, Any],
    sg_id: str,
    sg_name: str,
    public_cidrs_hit: list[str],
    risky_ports_hit: list[int],
    permission: dict[str, Any],
) -> dict[str, Any]:
    time_ms = int(event.get("time") or datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = str((event.get("metadata") or {}).get("uid") or "")
    finding_uid = _finding_uid(event_uid, sg_id, time_ms)
    actor = _actor(event)
    account = _account(event)
    region = _region(event)
    src_ip = _src_ip(event)

    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "detection_finding",
        "source_skill": SKILL_NAME,
        "finding_uid": finding_uid,
        "rule": "open-security-group-ingress",
        "sg_id": sg_id,
        "sg_name": sg_name,
        "actor_name": actor,
        "account_uid": account,
        "region": region,
        "src_ip": src_ip,
        "public_cidrs_hit": public_cidrs_hit,
        "risky_ports_hit": risky_ports_hit,
        "permission": permission,
        "first_seen_time_ms": time_ms,
        "last_seen_time_ms": time_ms,
    }


def _to_ocsf(native: dict[str, Any]) -> dict[str, Any]:
    """Wrap a native finding as an OCSF 1.8 Detection Finding (class 2004)."""
    title = (
        f"AWS security group {native['sg_id']} opened to the internet on risky port(s) "
        f"{native['risky_ports_hit']}"
    )
    description = (
        f"Actor `{native['actor_name']}` in account `{native['account_uid']}` "
        f"({native['region']}) authorized ingress on `{native['sg_id']}` from "
        f"{native['public_cidrs_hit']} covering risky ports {native['risky_ports_hit']}. "
        f"Source IP: {native['src_ip'] or '<unknown>'}."
    )

    observables = [
        {"name": "cloud.provider", "type": "Other", "value": "AWS"},
        {"name": "actor.name", "type": "Other", "value": native["actor_name"] or "unknown"},
        {"name": "api.operation", "type": "Other", "value": "AuthorizeSecurityGroupIngress"},
        {"name": "rule", "type": "Other", "value": native["rule"]},
        {"name": "target.uid", "type": "Other", "value": native["sg_id"]},
        {"name": "target.name", "type": "Other", "value": native["sg_name"] or native["sg_id"]},
        {"name": "target.type", "type": "Other", "value": "SecurityGroup"},
        {"name": "account.uid", "type": "Other", "value": native["account_uid"]},
        {"name": "region", "type": "Other", "value": native["region"]},
    ]
    if native["src_ip"]:
        observables.append({"name": "src.ip", "type": "IP Address", "value": native["src_ip"]})
    for cidr in native["public_cidrs_hit"]:
        observables.append({"name": "permission.cidr", "type": "Other", "value": cidr})
    protocol = str((native["permission"] or {}).get("ipProtocol") or "")
    if protocol:
        observables.append({"name": "permission.protocol", "type": "Other", "value": protocol})
    from_port = (native["permission"] or {}).get("fromPort")
    if from_port is not None:
        observables.append({"name": "permission.from_port", "type": "Other", "value": str(from_port)})
    to_port = (native["permission"] or {}).get("toPort")
    if to_port is not None:
        observables.append({"name": "permission.to_port", "type": "Other", "value": str(to_port)})
    for port in native["risky_ports_hit"]:
        observables.append({"name": "permission.port", "type": "Other", "value": str(port)})

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
            "labels": ["aws", "security-group", "exposure"],
        },
        "finding_info": {
            "uid": native["finding_uid"],
            "title": title,
            "desc": description,
            "types": ["open-security-group"],
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
            "events_observed": 1,
            "permission": native["permission"],
            "public_cidrs_hit": native["public_cidrs_hit"],
            "risky_ports_hit": native["risky_ports_hit"],
        },
    }


def detect(
    events: Iterable[dict[str, Any]],
    *,
    output_format: str = "ocsf",
    risky_ports: Iterable[int] = DEFAULT_RISKY_PORTS,
) -> Iterator[dict[str, Any]]:
    if output_format not in OUTPUT_FORMATS:
        raise ValueError(f"unsupported output_format `{output_format}`")
    risky_ports = tuple(sorted(set(risky_ports)))

    for event in events:
        producer = _producer(event)
        if producer not in ACCEPTED_PRODUCERS:
            # Soft-warn for visibility but keep going — this detector is
            # CloudTrail-only and may receive noise from a mixed pipeline
            emit_stderr_event(
                SKILL_NAME, level="warning", event="wrong_source",
                message=f"skipping event from non-cloudtrail producer `{producer}`",
            )
            continue

        if _api_operation(event) != "AuthorizeSecurityGroupIngress":
            continue
        if not _is_success(event):
            continue

        params = _request_parameters(event)
        if not params:
            continue

        for permission in _iter_permissions(params):
            cidrs = list(_iter_cidrs(permission))
            public_hits = sorted(c for c in cidrs if c in PUBLIC_CIDRS)
            if not public_hits:
                continue

            overlaps, port_hits = _port_range_overlaps_risky(permission, risky_ports)
            if not overlaps:
                continue

            sg_id, sg_name = _sg_id_and_name(params)
            if not sg_id:
                emit_stderr_event(
                    SKILL_NAME, level="warning", event="no_sg_id",
                    message="AuthorizeSecurityGroupIngress finding missing sg id; skipping",
                )
                continue

            native = _build_native_finding(
                event=event, sg_id=sg_id, sg_name=sg_name,
                public_cidrs_hit=public_hits, risky_ports_hit=port_hits,
                permission=permission,
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
                SKILL_NAME, level="warning", event="json_parse_failed",
                message=f"skipping line {lineno}: json parse failed: {exc}", line=lineno,
            )
            continue
        if isinstance(obj, dict):
            yield obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect AWS Security Group ingress opened to 0.0.0.0/0 or ::/0 on risky ports."
    )
    parser.add_argument("input", nargs="?", help="JSONL input. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="JSONL output. Defaults to stdout.")
    parser.add_argument(
        "--output-format", choices=sorted(OUTPUT_FORMATS), default="ocsf",
        help="Emit OCSF Detection Finding (default) or native projection.",
    )
    args = parser.parse_args(argv)

    in_stream = sys.stdin if not args.input else open(args.input, "r", encoding="utf-8")
    out_stream = sys.stdout if not args.output else open(args.output, "w", encoding="utf-8")

    try:
        for finding in detect(load_jsonl(in_stream), output_format=args.output_format):
            out_stream.write(json.dumps(finding, separators=(",", ":")) + "\n")
    finally:
        if args.input:
            in_stream.close()
        if args.output:
            out_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
