"""Convert raw GCP VPC Flow Logs to OCSF or repo-native Network Activity."""

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

from skills._shared.identity import VENDOR_NAME  # noqa: E402

SKILL_NAME = "ingest-vpc-flow-logs-gcp-ocsf"
OCSF_VERSION = "1.8.0"
CANONICAL_VERSION = "2026-04"

CLASS_UID = 4001
CLASS_NAME = "Network Activity"
CATEGORY_UID = 4
CATEGORY_NAME = "Network Activity"

ACTIVITY_UNKNOWN = 0
ACTIVITY_TRAFFIC = 6
ACTIVITY_DENIED = 7

SEVERITY_INFORMATIONAL = 1
STATUS_SUCCESS = 1

_PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
}


def protocol_name(num: int | str | None) -> str:
    if num is None or num == "":
        return ""
    try:
        return _PROTOCOL_NAMES.get(int(num), "")
    except (TypeError, ValueError):
        return str(num).upper() if isinstance(num, str) else ""


def activity_id_for_disposition(disposition: str | None) -> int:
    if not disposition:
        return ACTIVITY_TRAFFIC
    value = disposition.upper()
    if value in {"ACCEPT", "ALLOWED"}:
        return ACTIVITY_TRAFFIC
    if value in {"DENIED", "REJECT", "DROPPED"}:
        return ACTIVITY_DENIED
    return ACTIVITY_UNKNOWN


def parse_ts_ms(value: str | int | float | None) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        raw = int(value)
        return raw if raw > 10_000_000_000 else raw * 1000
    try:
        cleaned = str(value).replace("Z", "+00:00")
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
        return None


def _payload(entry: dict[str, Any]) -> dict[str, Any]:
    payload = entry.get("jsonPayload")
    return payload if isinstance(payload, dict) else entry


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _cloud(entry: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    cloud: dict[str, Any] = {"provider": "GCP"}
    src_vpc = payload.get("src_vpc") or {}
    dst_vpc = payload.get("dest_vpc") or {}
    resource_labels = ((entry.get("resource") or {}).get("labels")) or {}
    project_id = src_vpc.get("project_id") or dst_vpc.get("project_id") or resource_labels.get("project_id")
    region = (
        ((payload.get("src_instance") or {}).get("region"))
        or ((payload.get("dest_instance") or {}).get("region"))
        or resource_labels.get("location")
    )
    if project_id:
        cloud["account"] = {"uid": project_id}
    if region:
        cloud["region"] = region
    return cloud


def _endpoint(connection: dict[str, Any], side: str, payload: dict[str, Any]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {}
    ip_key = "src_ip" if side == "src" else "dest_ip"
    port_key = "src_port" if side == "src" else "dest_port"
    instance_key = "src_instance" if side == "src" else "dest_instance"
    vpc_key = "src_vpc" if side == "src" else "dest_vpc"

    if ip := connection.get(ip_key):
        endpoint["ip"] = ip
    if port := _int_or_none(connection.get(port_key)):
        endpoint["port"] = port

    instance = payload.get(instance_key) or {}
    if vm_name := instance.get("vm_name") or instance.get("instance_name"):
        endpoint["instance_uid"] = vm_name

    vpc = payload.get(vpc_key) or {}
    if subnet := vpc.get("subnetwork_name"):
        endpoint["subnet_uid"] = subnet

    return endpoint


def _traffic(payload: dict[str, Any]) -> dict[str, Any]:
    traffic: dict[str, Any] = {}
    packets = sum(
        value
        for value in (
            _int_or_none(payload.get("packets_sent")),
            _int_or_none(payload.get("packets_received")),
        )
        if value is not None
    )
    bytes_total = sum(
        value
        for value in (
            _int_or_none(payload.get("bytes_sent")),
            _int_or_none(payload.get("bytes_received")),
        )
        if value is not None
    )
    if packets:
        traffic["packets"] = packets
    if bytes_total:
        traffic["bytes"] = bytes_total
    return traffic


def _connection_info(connection: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    info: dict[str, Any] = {}
    proto = _int_or_none(connection.get("protocol")) or connection.get("protocol")
    if isinstance(proto, int):
        info["protocol_num"] = proto
    if name := protocol_name(proto):
        info["protocol_name"] = name

    reporter = str(payload.get("reporter") or "").upper()
    if reporter == "SRC":
        info["direction"] = "egress"
    elif reporter == "DEST":
        info["direction"] = "ingress"

    if boundary := ((payload.get("src_vpc") or {}).get("vpc_name")) or ((payload.get("dest_vpc") or {}).get("vpc_name")):
        info["boundary"] = boundary

    return info


def _build_canonical_record(entry: dict[str, Any]) -> dict[str, Any] | None:
    payload = _payload(entry)
    connection = payload.get("connection") or {}
    if not isinstance(connection, dict) or not connection:
        return None

    activity_id = activity_id_for_disposition(payload.get("disposition"))
    start_ms = parse_ts_ms(payload.get("start_time"))
    end_ms = parse_ts_ms(payload.get("end_time"))
    event_time = end_ms or start_ms or parse_ts_ms(entry.get("timestamp")) or int(datetime.now(timezone.utc).timestamp() * 1000)
    event_uid = hashlib.sha256(
        json.dumps(
            {
                "project_id": (((payload.get("src_vpc") or {}).get("project_id")) or ((payload.get("dest_vpc") or {}).get("project_id")) or (((entry.get("resource") or {}).get("labels")) or {}).get("project_id", "")),
                "start_time": payload.get("start_time", ""),
                "end_time": payload.get("end_time", ""),
                "src_ip": connection.get("src_ip", ""),
                "dest_ip": connection.get("dest_ip", ""),
                "src_port": connection.get("src_port", ""),
                "dest_port": connection.get("dest_port", ""),
                "protocol": connection.get("protocol", ""),
                "reporter": payload.get("reporter", ""),
                "disposition": payload.get("disposition", ""),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    cloud = _cloud(entry, payload)
    return {
        "schema_mode": "canonical",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "network_activity",
        "event_uid": event_uid,
        "provider": "GCP",
        "account_uid": ((cloud.get("account") or {}).get("uid")) or "",
        "region": cloud.get("region") or "",
        "time_ms": event_time,
        "start_time_ms": start_ms,
        "end_time_ms": end_ms,
        "activity_id": activity_id,
        "activity_name": {ACTIVITY_TRAFFIC: "traffic", ACTIVITY_DENIED: "denied", ACTIVITY_UNKNOWN: "unknown"}.get(
            activity_id, "unknown"
        ),
        "status_id": STATUS_SUCCESS,
        "status": "success",
        "src": _endpoint(connection, "src", payload),
        "dst": _endpoint(connection, "dst", payload),
        "traffic": _traffic(payload),
        "connection": _connection_info(connection, payload),
        "cloud": cloud,
        "disposition": (payload.get("disposition") or "").upper() or "UNKNOWN",
        "source": {
            "kind": "gcp.vpc-flow-logs",
            "reporter": payload.get("reporter") or "",
            "src_vpc": ((payload.get("src_vpc") or {}).get("vpc_name")) or "",
            "dest_vpc": ((payload.get("dest_vpc") or {}).get("vpc_name")) or "",
        },
    }


def _render_ocsf_record(canonical: dict[str, Any]) -> dict[str, Any]:
    event: dict[str, Any] = {
        "activity_id": canonical["activity_id"],
        "category_uid": CATEGORY_UID,
        "category_name": CATEGORY_NAME,
        "class_uid": CLASS_UID,
        "class_name": CLASS_NAME,
        "type_uid": CLASS_UID * 100 + canonical["activity_id"],
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
            "labels": ["detection-engineering", "gcp", "vpc-flow-logs", "ingest"],
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


def convert_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    canonical = _build_canonical_record(entry)
    if canonical is None:
        return None
    return _render_ocsf_record(canonical)


def convert_entry_native(entry: dict[str, Any]) -> dict[str, Any] | None:
    canonical = _build_canonical_record(entry)
    if canonical is None:
        return None
    return _render_native_record(canonical)


def iter_raw_entries(stream: Iterable[str]) -> Iterable[dict[str, Any]]:
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
                yield obj
        return

    if isinstance(parsed, list):
        for obj in parsed:
            if isinstance(obj, dict):
                yield obj
        return

    if isinstance(parsed, dict):
        yield parsed


def ingest(stream: Iterable[str], *, output_format: str = "ocsf") -> Iterable[dict[str, Any]]:
    for entry in iter_raw_entries(stream):
        canonical = _build_canonical_record(entry)
        if canonical is not None:
            if output_format == "native":
                yield _render_native_record(canonical)
            else:
                yield _render_ocsf_record(canonical)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert GCP VPC Flow Logs to OCSF 1.8 Network Activity JSONL.")
    parser.add_argument("input", nargs="?", help="Input JSON or JSONL file. Defaults to stdin.")
    parser.add_argument("--output", "-o", help="Output JSONL file. Defaults to stdout.")
    parser.add_argument(
        "--output-format",
        choices=("ocsf", "native"),
        default="ocsf",
        help="Render OCSF network activity or the native enriched network-activity shape.",
    )
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
