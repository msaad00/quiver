"""Run a read-only Snowflake query and emit raw JSONL rows."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Iterable

from skills._shared.read_only_sql import normalize_read_only_query

SKILL_NAME = "source-snowflake-query"


def _configure_snowflake_logging() -> None:
    logging.getLogger("snowflake.connector").setLevel(logging.WARNING)


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
    import snowflake.connector

    _configure_snowflake_logging()
    kwargs: dict[str, str] = {
        "account": os.environ["SNOWFLAKE_ACCOUNT"],
        "user": os.environ["SNOWFLAKE_USER"],
        "password": os.environ["SNOWFLAKE_PASSWORD"],
    }
    for env_name, key in (
        ("SNOWFLAKE_WAREHOUSE", "warehouse"),
        ("SNOWFLAKE_DATABASE", "database"),
        ("SNOWFLAKE_SCHEMA", "schema"),
        ("SNOWFLAKE_ROLE", "role"),
    ):
        value = os.environ.get(env_name)
        if value:
            kwargs[key] = value
    return snowflake.connector.connect(**kwargs)


def _dict_cursor_class() -> Any:
    import snowflake.connector

    return snowflake.connector.DictCursor


def fetch_rows(query: str) -> list[dict[str, Any]]:
    conn = _connect()
    try:
        cursor = conn.cursor(_dict_cursor_class())
        try:
            cursor.execute(_normalize_query(query))
            rows = cursor.fetchall()
        finally:
            cursor.close()
    finally:
        conn.close()

    normalized: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            normalized.append(dict(row))
        else:
            normalized.append({"value": row})
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a read-only Snowflake query and emit raw JSONL rows."
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
