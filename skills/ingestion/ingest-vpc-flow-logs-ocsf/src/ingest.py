"""Convert raw AWS VPC Flow Logs (v5) to OCSF 1.8 Network Activity (class 4001).

Input:  VPC Flow Log records in v5 space-delimited format. Optional header
        line declaring the field order; when absent, falls back to the
        canonical v5 default.
Output: JSONL of OCSF 1.8 Network Activity events by default, or the repo's
        native enriched network-activity shape when --output-format native is
        selected.

Contract: see ../OCSF_CONTRACT.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "ingest-vpc-flow-logs-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"

# OCSF Network Activity (4001)
CLASS_UID = 4001
CLASS_NAME = "Network Activity"
CATEGORY_UID = 4
CATEGORY_NAME = "Network Activity"

# Activity enum (OCSF 1.8 Network Activity)
ACTIVITY_UNKNOWN = 0
ACTIVITY_TRAFFIC = 6  # Traffic (ACCEPT)
ACTIVITY_DENIED = 7  # Traffic Denied (REJECT)

SEVERITY_INFORMATIONAL = 1

STATUS_SUCCESS = 1

# Canonical v5 field order when no header line is present.
# See https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records
_DEFAULT_V5_FIELDS: tuple[str, ...] = (
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
)


# ---------------------------------------------------------------------------
# Protocol number → name (IANA subset that VPC Flow actually emits)
# ---------------------------------------------------------------------------

_PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


def protocol_name(num: int | str) -> str:
    """Map an IANA protocol number to a canonical short name, or '' if unknown."""
    try:
        n = int(num)
    except (TypeError, ValueError):
        return ""
    return _PROTOCOL_NAMES.get(n, "")


# ---------------------------------------------------------------------------
# TCP flags bitmask decoder
# ---------------------------------------------------------------------------

# Standard TCP flag bits in the order VPC Flow reports them.
_TCP_FLAG_BITS: tuple[tuple[int, str], ...] = (
    (1, "FIN"),
    (2, "SYN"),
    (4, "RST"),
    (8, "PSH"),
    (16, "ACK"),
    (32, "URG"),
)


def decode_tcp_flags(value: int | str | None) -> str:
    """Decode a TCP flags bitmask into a comma-joined symbolic string.

    >>> decode_tcp_flags(18)
    'SYN,ACK'
    >>> decode_tcp_flags(2)
    'SYN'
    >>> decode_tcp_flags(0)
    ''
    >>> decode_tcp_flags("-")
    ''
    """
    if value is None or value == "-" or value == "":
        return ""
    try:
        bits = int(value)
    except (TypeError, ValueError):
        return ""
    if bits == 0:
        return ""
    return ",".join(name for mask, name in _TCP_FLAG_BITS if bits & mask)


# ---------------------------------------------------------------------------
# Action → activity_id
# ---------------------------------------------------------------------------


def activity_id_for_action(action: str) -> int:
    """Map a VPC Flow action to an OCSF Network Activity activity_id."""
    if not action or action == "-":
        return ACTIVITY_UNKNOWN
    a = action.upper()
    if a == "ACCEPT":
        return ACTIVITY_TRAFFIC
    if a == "REJECT":
        return ACTIVITY_DENIED
    return ACTIVITY_UNKNOWN


# ---------------------------------------------------------------------------
# Time helpers — VPC Flow uses epoch seconds; OCSF uses epoch milliseconds
# ---------------------------------------------------------------------------


def sec_to_ms(value: str | int | None) -> int | None:
    """Convert seconds-epoch to ms-epoch, or None if unparseable / missing."""
    if value is None or value == "-" or value == "":
        return None
    try:
        return int(value) * 1000
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Record parsing
# ---------------------------------------------------------------------------


def parse_header(line: str) -> tuple[str, ...] | None:
    """Parse a VPC Flow Logs header line if present.

    Headers from CloudWatch delivery look like:
        version account-id interface-id srcaddr dstaddr srcport dstport protocol ...

    Returns a tuple of field names, or None if the line doesn't look like a header.
    A real header starts with the literal word `version` as the first whitespace-split token.
    """
    if not line:
        return None
    tokens = line.strip().split()
    if not tokens or tokens[0] != "version":
        return None
    return tuple(tokens)


def parse_record(line: str, fields: tuple[str, ...]) -> dict[str, str] | None:
    """Split a VPC Flow record line by whitespace and zip with the field order.

    Returns a dict, or None if the line has too few tokens.
    """
    tokens = line.strip().split()
    if len(tokens) < len(fields):
        return None
    # Extra trailing tokens are ignored — VPC Flow pads nothing, and
    # users sometimes append their own annotations via downstream tools.
    return dict(zip(fields, tokens[: len(fields)]))


# ---------------------------------------------------------------------------
# OCSF event builder
# ---------------------------------------------------------------------------


def _port(value: str | None) -> int | None:
    if value is None or value == "-" or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "-" or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _str_or_skip(value: str | None) -> str | None:
    if value is None or value == "-" or value == "":
        return None
    return value


def _src_endpoint(record: dict[str, str]) -> dict[str, Any]:
    ep: dict[str, Any] = {}
    if ip := _str_or_skip(record.get("srcaddr")):
        ep["ip"] = ip
    if port := _port(record.get("srcport")):
        ep["port"] = port
    if iface := _str_or_skip(record.get("interface-id")):
        ep["interface_uid"] = iface
    if instance := _str_or_skip(record.get("instance-id")):
        ep["instance_uid"] = instance
    if subnet := _str_or_skip(record.get("subnet-id")):
        ep["subnet_uid"] = subnet
    return ep


def _dst_endpoint(record: dict[str, str]) -> dict[str, Any]:
    ep: dict[str, Any] = {}
    if ip := _str_or_skip(record.get("dstaddr")):
        ep["ip"] = ip
    if port := _port(record.get("dstport")):
        ep["port"] = port
    return ep


def _traffic(record: dict[str, str]) -> dict[str, Any]:
    t: dict[str, Any] = {}
    if pkts := _int_or_none(record.get("packets")):
        t["packets"] = pkts
    if b := _int_or_none(record.get("bytes")):
        t["bytes"] = b
    return t


def _connection_info(record: dict[str, str]) -> dict[str, Any]:
    ci: dict[str, Any] = {}
    proto_num = _int_or_none(record.get("protocol"))
    if proto_num is not None:
        ci["protocol_num"] = proto_num
        name = _PROTOCOL_NAMES.get(proto_num, "")
        if name:
            ci["protocol_name"] = name
    tcp_flags = decode_tcp_flags(record.get("tcp-flags"))
    if tcp_flags:
        ci["tcp_flags"] = tcp_flags
    if direction := _str_or_skip(record.get("flow-direction")):
        ci["direction"] = direction
    if vpc := _str_or_skip(record.get("vpc-id")):
        ci["boundary"] = vpc
    return ci


def _cloud(record: dict[str, str]) -> dict[str, Any]:
    cloud: dict[str, Any] = {"provider": "AWS"}
    if account := _str_or_skip(record.get("account-id")):
        cloud["account"] = {"uid": account}
    if region := _str_or_skip(record.get("region")):
        cloud["region"] = region
    return cloud


def _build_canonical_record(record: dict[str, str]) -> dict[str, Any] | None:
    """Convert one parsed VPC Flow record into the repo's canonical event shape.

    Returns None if the record is a NODATA / SKIPDATA entry (no real flow data).
    """
    status = (record.get("log-status") or "").upper()
    if status in ("NODATA", "SKIPDATA"):
        return None

    action = record.get("action") or ""
    activity_id = activity_id_for_action(action)
    metadata_uid = hashlib.sha256(
        json.dumps(
            {
                "account-id": record.get("account-id", ""),
                "interface-id": record.get("interface-id", ""),
                "srcaddr": record.get("srcaddr", ""),
                "dstaddr": record.get("dstaddr", ""),
                "srcport": record.get("srcport", ""),
                "dstport": record.get("dstport", ""),
                "protocol": record.get("protocol", ""),
                "start": record.get("start", ""),
                "end": record.get("end", ""),
                "action": action,
                "bytes": record.get("bytes", ""),
                "packets": record.get("packets", ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    start_ms = sec_to_ms(record.get("start"))
    end_ms = sec_to_ms(record.get("end"))
    # OCSF `time` is the event's effective time; for a flow, the end-time is
    # the most useful because it's when the accumulated counters were flushed.
    event_time = end_ms or start_ms or 0

    canonical: dict[str, Any] = {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "network_activity",
        "event_uid": metadata_uid,
        "provider": "AWS",
        "account_uid": _str_or_skip(record.get("account-id")) or "",
        "region": _str_or_skip(record.get("region")) or "",
        "time_ms": event_time,
        "start_time_ms": start_ms,
        "end_time_ms": end_ms,
        "activity_id": activity_id,
        "activity_name": {ACTIVITY_TRAFFIC: "traffic", ACTIVITY_DENIED: "denied", ACTIVITY_UNKNOWN: "unknown"}.get(
            activity_id, "unknown"
        ),
        "status_id": STATUS_SUCCESS,
        "status": "success",
        "src": _src_endpoint(record),
        "dst": _dst_endpoint(record),
        "traffic": _traffic(record),
        "connection": _connection_info(record),
        "cloud": _cloud(record),
        "disposition": (record.get("action") or "").upper() or "UNKNOWN",
        "source": {
            "kind": "aws.vpc-flow-logs",
            "interface_id": _str_or_skip(record.get("interface-id")) or "",
            "vpc_id": _str_or_skip(record.get("vpc-id")) or "",
            "subnet_id": _str_or_skip(record.get("subnet-id")) or "",
            "instance_id": _str_or_skip(record.get("instance-id")) or "",
            "flow_direction": _str_or_skip(record.get("flow-direction")) or "",
            "log_status": status,
        },
    }
    return canonical


def _render_ocsf_record(canonical: dict[str, Any]) -> dict[str, Any]:
    activity_id = int(canonical["activity_id"])
    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + activity_id,
        "severity_id": SEVERITY_INFORMATIONAL,
        "status_id": STATUS_SUCCESS,
        "time": canonical["time_ms"],
        "metadata": {
            "version": OCSF_VERSION,
            "uid": canonical["event_uid"],
            "product": {
                "name": "cloud-ai-security-skills",
                "vendor_name": VENDOR_NAME,
                "feature": {"name": SKILL_NAME},
            },
            "labels": ["detection-engineering", "aws", "vpc-flow-logs", "ingest"],
        },
        "src_endpoint": canonical["src"],
        "dst_endpoint": canonical["dst"],
        "traffic": canonical["traffic"],
        "connection_info": canonical["connection"],
        "cloud": canonical["cloud"],
    }
    if canonical.get("start_time_ms") is not None:
        event["start_time"] = canonical["start_time_ms"]
    if canonical.get("end_time_ms") is not None:
        event["end_time"] = canonical["end_time_ms"]

    return event


def _render_native_record(canonical: dict[str, Any]) -> dict[str, Any]:
    native = dict(canonical)
    native["schema_mode"] = "native"
    native["source_skill"] = SKILL_NAME
    native["output_format"] = "native"
    return native


def convert_record(record: dict[str, str]) -> dict[str, Any] | None:
    """Convert one parsed VPC Flow record into one OCSF Network Activity event."""
    canonical = _build_canonical_record(record)
    if canonical is None:
        return None
    return _render_ocsf_record(canonical)


def convert_record_native(record: dict[str, str]) -> dict[str, Any] | None:
    """Convert one parsed VPC Flow record into the native enriched flow shape."""
    canonical = _build_canonical_record(record)
    if canonical is None:
        return None
    return _render_native_record(canonical)


# ---------------------------------------------------------------------------
# Stream processing
# ---------------------------------------------------------------------------


def ingest(lines: Iterable[str], output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    """Yield events for a stream of VPC Flow Log lines.

    The first non-blank line is inspected: if it's a header, it sets the field
    order for every subsequent line. Otherwise, the canonical v5 default order
    is used and the first line is parsed as a record.
    """
    fields: tuple[str, ...] = _DEFAULT_V5_FIELDS
    header_consumed = False

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue

        if not header_consumed:
            header = parse_header(line)
            header_consumed = True
            if header is not None:
                fields = header
                continue
            # Not a header — fall through and parse this line as a record

        record = parse_record(line, fields)
        if record is None:
            print(
                f"[{SKILL_NAME}] skipping line {lineno}: too few tokens for field order ({len(fields)} expected)",
                file=sys.stderr,
            )
            continue

        try:
            canonical = _build_canonical_record(record)
        except Exception as e:
            print(f"[{SKILL_NAME}] skipping line {lineno}: convert error: {e}", file=sys.stderr)
            continue

        if canonical is None:
            # NODATA / SKIPDATA — silently skip, those are legitimate
            # flow-log entries that carry no real flow data
            continue

        if output_format == "native":
            yield _render_native_record(canonical)
        else:
            yield _render_ocsf_record(canonical)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert AWS VPC Flow Logs (v5) to OCSF 1.8 Network Activity JSONL.")
    parser.add_argument("input", nargs="?", help="Input flow log file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument("--output-format", choices=("ocsf", "native"), default="ocsf", help="Render OCSF network activity or the native enriched network-flow shape.")
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
