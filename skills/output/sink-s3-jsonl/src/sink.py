"""Persist JSONL records into a new immutable S3 object."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable

SKILL_NAME = "sink-s3-jsonl"
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
PREFIX_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._=-]+$")


@dataclass(frozen=True)
class PreparedRow:
    payload_json: str
    schema_mode: str
    event_uid: str
    finding_uid: str


def _normalize_bucket(raw_bucket: str) -> str:
    bucket = raw_bucket.strip()
    if not bucket:
        raise ValueError("bucket must not be empty")
    if not BUCKET_RE.fullmatch(bucket):
        raise ValueError(f"invalid S3 bucket name `{bucket}`")
    if ".." in bucket or ".-" in bucket or "-." in bucket:
        raise ValueError(f"invalid S3 bucket name `{bucket}`")
    return bucket


def _normalize_prefix(raw_prefix: str) -> str:
    prefix = raw_prefix.strip().strip("/")
    if not prefix:
        raise ValueError("prefix must not be empty")
    parts = prefix.split("/")
    for part in parts:
        if not part or not PREFIX_SEGMENT_RE.fullmatch(part):
            raise ValueError(f"invalid S3 prefix segment `{part or raw_prefix}`")
    return "/".join(parts)


def _extract_schema_mode(record: dict[str, Any]) -> str:
    schema_mode = record.get("schema_mode")
    if isinstance(schema_mode, str) and schema_mode.strip():
        return schema_mode
    if "class_uid" in record or "finding_info" in record or "metadata" in record:
        return "ocsf"
    return "raw"


def _extract_event_uid(record: dict[str, Any]) -> str:
    event_uid = record.get("event_uid")
    if isinstance(event_uid, str):
        return event_uid
    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        metadata_uid = metadata.get("uid")
        if isinstance(metadata_uid, str):
            return metadata_uid
    return ""


def _extract_finding_uid(record: dict[str, Any]) -> str:
    finding_uid = record.get("finding_uid")
    if isinstance(finding_uid, str):
        return finding_uid
    finding_info = record.get("finding_info")
    if isinstance(finding_info, dict):
        finding_info_uid = finding_info.get("uid")
        if isinstance(finding_info_uid, str):
            return finding_info_uid
    return ""


def _prepare_rows(stdin: Iterable[str]) -> list[PreparedRow]:
    rows: list[PreparedRow] = []
    for line_number, raw_line in enumerate(stdin, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON ({exc.msg})") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"line {line_number}: expected a JSON object")
        rows.append(
            PreparedRow(
                payload_json=json.dumps(payload, separators=(",", ":"), sort_keys=True),
                schema_mode=_extract_schema_mode(payload),
                event_uid=_extract_event_uid(payload),
                finding_uid=_extract_finding_uid(payload),
            )
        )
    return rows


def _object_key(prefix: str, rows: list[PreparedRow], now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    digest = hashlib.sha256(
        "\n".join(row.payload_json for row in rows).encode("utf-8")
    ).hexdigest()[:12]
    return f"{prefix}/{moment:%Y/%m/%d}/{moment:%Y%m%dT%H%M%SZ}-{digest}.jsonl"


def _body(rows: list[PreparedRow]) -> bytes:
    return ("\n".join(row.payload_json for row in rows) + "\n").encode("utf-8")


def _client() -> Any:
    import boto3

    region_name = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    kwargs: dict[str, str] = {}
    if region_name:
        kwargs["region_name"] = region_name
    return boto3.client("s3", **kwargs)


def _write_object(bucket: str, object_key: str, rows: list[PreparedRow]) -> int:
    client = _client()
    client.put_object(
        Bucket=bucket,
        Key=object_key,
        Body=_body(rows),
        ContentType="application/x-ndjson",
    )
    return len(rows)


def _summary(
    *,
    bucket: str,
    prefix: str,
    object_key: str,
    rows: list[PreparedRow],
    dry_run: bool,
    written_records: int,
) -> dict[str, Any]:
    schema_modes = Counter(row.schema_mode for row in rows)
    return {
        "schema_mode": "native",
        "canonical_schema_version": "v1",
        "record_type": "sink_result",
        "sink": "s3",
        "bucket": bucket,
        "prefix": prefix,
        "object_key": object_key,
        "dry_run": dry_run,
        "input_records": len(rows),
        "written_objects": 0 if dry_run else 1,
        "written_records": written_records,
        "would_write_objects": 1 if dry_run else 0,
        "would_write_records": len(rows) if dry_run else 0,
        "schema_modes": dict(sorted(schema_modes.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Persist JSONL records into a new immutable S3 object."
    )
    parser.add_argument("--bucket", required=True, help="Target S3 bucket.")
    parser.add_argument(
        "--prefix", required=True, help="Target S3 key prefix for new immutable objects."
    )
    parser.add_argument(
        "--output-format",
        choices=("native",),
        default="native",
        help="Declared output rendering mode for the sink result.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Validate and summarize without writing.",
    )
    mode.add_argument(
        "--apply", dest="dry_run", action="store_false", help="Write a new NDJSON object to S3."
    )
    parser.set_defaults(dry_run=True)
    args = parser.parse_args(argv)

    try:
        bucket = _normalize_bucket(args.bucket)
        prefix = _normalize_prefix(args.prefix)
        rows = _prepare_rows(sys.stdin)
        if not rows:
            raise ValueError("stdin did not contain any JSONL records")
        object_key = _object_key(prefix, rows)
        written_records = 0 if args.dry_run else _write_object(bucket, object_key, rows)
        sys.stdout.write(
            json.dumps(
                _summary(
                    bucket=bucket,
                    prefix=prefix,
                    object_key=object_key,
                    rows=rows,
                    dry_run=args.dry_run,
                    written_records=written_records,
                ),
                separators=(",", ":"),
            )
            + "\n"
        )
    except Exception as exc:
        print(f"[{SKILL_NAME}] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
