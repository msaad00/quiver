"""Run a read-only ClickHouse query and emit raw JSONL rows."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Iterable

from skills._shared.read_only_sql import normalize_read_only_query

SKILL_NAME = "source-clickhouse-query"


def _read_query(cli_query: str | None, stdin: Iterable[str]) -> str:
    if cli_query and cli_query.strip():
        return cli_query.strip()
    stdin_text = "".join(stdin).strip()
    if stdin_text:
        return stdin_text
    raise ValueError("provide a read-only SQL query via --query or stdin")


def _normalize_query(query: str) -> str:
    return normalize_read_only_query(query)


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


def fetch_rows(query: str) -> list[dict[str, Any]]:
    client = _connect()
    try:
        result = client.query(_normalize_query(query))
        column_names = list(result.column_names)
        rows = [
            {column_names[i]: value for i, value in enumerate(row)} for row in result.result_rows
        ]
    finally:
        client.close()
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a read-only ClickHouse query and emit raw JSONL rows."
    )
    parser.add_argument(
        "--query", help="Read-only SQL query to run. If omitted, the query is read from stdin."
    )
    parser.add_argument(
        "--output-format",
        choices=("raw",),
        default="raw",
        help="Declared output rendering mode for this source adapter.",
    )
    args = parser.parse_args(argv)

    try:
        query = _read_query(args.query, sys.stdin)
        for row in fetch_rows(query):
            sys.stdout.write(json.dumps(row, default=str, separators=(",", ":")) + "\n")
    except Exception as exc:
        print(f"[{SKILL_NAME}] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
