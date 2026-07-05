from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

_DEFAULT_DEDUPE_TTL_DAYS = 30
_MAX_SNS_BATCH_SIZE = 10
_SECONDS_PER_DAY = 86_400

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover - exercised only in minimal local test envs
    boto3 = None

    class ClientError(Exception):
        pass


def _sns_client():
    if boto3 is None:
        raise RuntimeError("boto3 is required for the AWS runner")
    return boto3.client("sns")


def _dynamodb_resource():
    if boto3 is None:
        raise RuntimeError("boto3 is required for the AWS runner")
    return boto3.resource("dynamodb")


def _skill_command() -> list[str]:
    raw = os.environ.get("DETECT_SKILL_CMD", "").strip()
    if not raw:
        raise ValueError("DETECT_SKILL_CMD is required")
    return shlex.split(raw)


def _run_skill(lines: list[str]) -> list[str]:
    completed = subprocess.run(
        _skill_command(),
        input="\n".join(lines) + ("\n" if lines else ""),
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "detect skill failed")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def _extract_uid(record: dict[str, Any]) -> str:
    finding_info = record.get("finding_info")
    if isinstance(finding_info, dict):
        uid = finding_info.get("uid")
        if isinstance(uid, str) and uid:
            return uid

    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        uid = metadata.get("uid")
        if isinstance(uid, str) and uid:
            return uid

    event_uid = record.get("event_uid")
    if isinstance(event_uid, str) and event_uid:
        return event_uid

    raise ValueError("record is missing finding_info.uid, metadata.uid, and event_uid")


def _dedupe_table():
    table_name = os.environ.get("DEDUPE_TABLE", "").strip()
    if not table_name:
        raise ValueError("DEDUPE_TABLE is required")
    return _dynamodb_resource().Table(table_name)


def _dedupe_ttl_days() -> int:
    raw = os.environ.get("DEDUPE_TTL_DAYS", "").strip()
    if not raw:
        return _DEFAULT_DEDUPE_TTL_DAYS
    try:
        days = int(raw)
    except ValueError as exc:
        raise ValueError(f"DEDUPE_TTL_DAYS must be an integer, got {raw!r}") from exc
    if days < 1 or days > 365:
        raise ValueError(f"DEDUPE_TTL_DAYS must be between 1 and 365, got {days}")
    return days


def _expires_at(now: float | None = None) -> int:
    current = time.time() if now is None else now
    return int(current) + _dedupe_ttl_days() * _SECONDS_PER_DAY


def _sns_topic() -> str:
    topic = os.environ.get("SNS_TOPIC_ARN", "").strip()
    if not topic:
        raise ValueError("SNS_TOPIC_ARN is required")
    return topic


def _batched(items: list[tuple[str, str]], size: int) -> list[list[tuple[str, str]]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _publish_findings(records: list[tuple[str, str]]) -> None:
    client = _sns_client()
    topic = _sns_topic()
    for batch_index, batch in enumerate(_batched(records, _MAX_SNS_BATCH_SIZE)):
        response = client.publish_batch(
            TopicArn=topic,
            PublishBatchRequestEntries=[
                {
                    "Id": f"{batch_index}-{entry_index}",
                    "Message": line,
                    "Subject": f"skill-finding:{uid}",
                }
                for entry_index, (line, uid) in enumerate(batch)
            ],
        )
        failed = response.get("Failed", [])
        if failed:
            raise RuntimeError(f"SNS publish_batch failed for {len(failed)} finding(s)")


def _put_if_new(uid: str, payload: str) -> bool:
    table = _dedupe_table()
    item = {
        "pk": uid,
        "seen_at": datetime.now(UTC).isoformat(),
        "payload_sha256": sha256(payload.encode("utf-8")).hexdigest(),
        "expires_at": _expires_at(),
    }
    try:
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, int]:
    input_lines = [record["body"] for record in event.get("Records", [])]
    findings = _run_skill(input_lines)

    to_publish: list[tuple[str, str]] = []
    duplicates = 0
    for line in findings:
        record = json.loads(line)
        uid = _extract_uid(record)
        if _put_if_new(uid, line):
            to_publish.append((line, uid))
        else:
            duplicates += 1

    if to_publish:
        _publish_findings(to_publish)

    return {
        "messages_processed": len(input_lines),
        "published": len(to_publish),
        "duplicates": duplicates,
    }
