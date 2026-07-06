"""Append JSONL records into a pre-provisioned ClickHouse table."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable

SKILL_NAME = "sink-clickhouse-jsonl"
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,254}$")


@dataclass(frozen=True)
class PreparedRow:
    payload_json: str
    schema_mode: str
    event_uid: str
    finding_uid: str


def _quote_identifier(identifier: str) -> str:
    if not IDENTIFIER_RE.fullmatch(identifier):
        raise ValueError(f"invalid ClickHouse identifier `{identifier}`")
    return identifier


def _normalize_table_name(raw_table: str) -> str:
    table = raw_table.strip()
    if not table:
        raise ValueError("table must not be empty")
    parts = table.split(".")
    if not 1 <= len(parts) <= 2:
        raise ValueError("table must be one of: table or database.table")
    return ".".join(_quote_identifier(part) for part in parts)


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


def _connect() -> Any:
    import clickhouse_connect

    kwargs: dict[str, Any] = {
        "host": os.environ["CLICKHOUSE_HOST"],
        "username": os.environ.get("CLICKHOUSE_USER", "default"),
        "password": os.environ.get("CLICKHOUSE_PASSWORD", ""),
    }
    if port := os.environ.get("CLICKHOUSE_PORT"):
        kwargs["port"] = int(port)
    if database := os.environ.get("CLICKHOUSE_DATABASE"):
        kwargs["database"] = database
    if secure := os.environ.get("CLICKHOUSE_SECURE"):
        kwargs["secure"] = secure.lower() not in {"0", "false", "no"}
    return clickhouse_connect.get_client(**kwargs)


def _insert_rows(table_name: str, rows: list[PreparedRow]) -> int:
    client = _connect()
    try:
        client.insert(
            table=table_name,
            data=[
                [row.payload_json, row.schema_mode, row.event_uid, row.finding_uid] for row in rows
            ],
            column_names=["payload", "schema_mode", "event_uid", "finding_uid"],
        )
    finally:
        client.close()
    return len(rows)


def _summary(
    table_name: str, rows: list[PreparedRow], dry_run: bool, inserted: int
) -> dict[str, Any]:
    schema_modes = Counter(row.schema_mode for row in rows)
    return {
        "schema_mode": "native",
        "canonical_schema_version": "v1",
        "record_type": "sink_result",
        "sink": "clickhouse",
        "table": table_name,
        "dry_run": dry_run,
        "input_records": len(rows),
        "inserted_records": inserted,
        "would_insert_records": len(rows) if dry_run else 0,
        "schema_modes": dict(sorted(schema_modes.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Append JSONL records into a pre-provisioned ClickHouse table."
    )
    parser.add_argument(
        "--table", required=True, help="Target ClickHouse table: table or database.table."
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
        help="Validate and summarize without inserting.",
    )
    mode.add_argument(
        "--apply", dest="dry_run", action="store_false", help="Execute ClickHouse inserts."
    )
    parser.set_defaults(dry_run=True)
    args = parser.parse_args(argv)

    try:
        table_name = _normalize_table_name(args.table)
        rows = _prepare_rows(sys.stdin)
        if not rows:
            raise ValueError("stdin did not contain any JSONL records")
        inserted = 0 if args.dry_run else _insert_rows(table_name, rows)
        sys.stdout.write(
            json.dumps(_summary(table_name, rows, args.dry_run, inserted), separators=(",", ":"))
            + "\n"
        )
    except Exception as exc:
        print(f"[{SKILL_NAME}] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
