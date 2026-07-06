"""Run a read-only S3 Select query and emit raw JSONL rows."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Iterable

SKILL_NAME = "source-s3-select"
ALLOWED_PREFIXES = ("SELECT",)


def _read_expression(cli_expression: str | None, stdin: Iterable[str]) -> str:
    if cli_expression and cli_expression.strip():
        return cli_expression.strip()
    stdin_text = "".join(stdin).strip()
    if stdin_text:
        return stdin_text
    raise ValueError("provide a read-only S3 Select expression via --expression or stdin")


def _normalize_expression(expression: str) -> str:
    cleaned = expression.strip()
    if not cleaned:
        raise ValueError("expression must not be empty")
    while cleaned.endswith(";"):
        cleaned = cleaned[:-1].rstrip()
    if ";" in cleaned:
        raise ValueError("multiple SQL statements are not allowed")

    head = cleaned.lstrip("(\n\t ").upper()
    if not any(head.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        raise ValueError("only SELECT statements are allowed")
    return cleaned


def _input_serialization(kind: str, compression_type: str) -> dict[str, Any]:
    json_kind = "LINES" if kind == "lines" else "DOCUMENT"
    serialization: dict[str, Any] = {"JSON": {"Type": json_kind}}
    if compression_type != "none":
        serialization["CompressionType"] = compression_type.upper()
    return serialization


def _client() -> Any:
    import boto3

    region_name = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    kwargs: dict[str, str] = {}
    if region_name:
        kwargs["region_name"] = region_name
    return boto3.client("s3", **kwargs)


def _iter_record_payloads(payload: Iterable[dict[str, Any]]) -> Iterable[str]:
    buffer = ""
    for event in payload:
        if "Records" not in event:
            continue
        chunk = event["Records"].get("Payload", b"")
        if not chunk:
            continue
        buffer += chunk.decode("utf-8")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            stripped = line.strip()
            if stripped:
                yield stripped
    if buffer.strip():
        yield buffer.strip()


def fetch_rows(
    *,
    bucket: str,
    key: str,
    expression: str,
    input_serialization: str,
    compression_type: str,
) -> list[dict[str, Any]]:
    response = _client().select_object_content(
        Bucket=bucket,
        Key=key,
        ExpressionType="SQL",
        Expression=_normalize_expression(expression),
        InputSerialization=_input_serialization(input_serialization, compression_type),
        OutputSerialization={"JSON": {"RecordDelimiter": "\n"}},
    )

    normalized: list[dict[str, Any]] = []
    for line in _iter_record_payloads(response["Payload"]):
        value = json.loads(line)
        if isinstance(value, dict):
            normalized.append(value)
        else:
            normalized.append({"value": value})
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a read-only S3 Select query and emit raw JSONL rows."
    )
    parser.add_argument("--bucket", required=True, help="S3 bucket containing the object to query.")
    parser.add_argument("--key", required=True, help="S3 object key to query with S3 Select.")
    parser.add_argument(
        "--expression",
        help="Read-only S3 Select SQL expression. If omitted, the expression is read from stdin.",
    )
    parser.add_argument(
        "--input-serialization",
        choices=("lines", "document"),
        default="lines",
        help="JSON input shape for S3 Select: newline-delimited JSON or a JSON document.",
    )
    parser.add_argument(
        "--compression-type",
        choices=("none", "gzip", "bzip2"),
        default="none",
        help="Compression type for the source object.",
    )
    parser.add_argument(
        "--output-format",
        choices=("raw",),
        default="raw",
        help="Declared output rendering mode for this source adapter.",
    )
    args = parser.parse_args(argv)

    try:
        expression = _read_expression(args.expression, sys.stdin)
        for row in fetch_rows(
            bucket=args.bucket,
            key=args.key,
            expression=expression,
            input_serialization=args.input_serialization,
            compression_type=args.compression_type,
        ):
            sys.stdout.write(json.dumps(row, default=str, separators=(",", ":")) + "\n")
    except Exception as exc:
        print(f"[{SKILL_NAME}] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
