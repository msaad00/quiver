from __future__ import annotations

import base64
import json
import os
import shlex
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

_DEFAULT_DEDUPE_TTL_DAYS = 30

try:
    from google.api_core.exceptions import Conflict
    from google.cloud import firestore, pubsub_v1
except ImportError:  # pragma: no cover - exercised only in minimal local test envs
    Conflict = RuntimeError
    firestore = None
    pubsub_v1 = None


def _firestore_client():
    if firestore is None:
        raise RuntimeError("google-cloud-firestore is required for the GCP runner")
    return firestore.Client()


def _publisher_client():
    if pubsub_v1 is None:
        raise RuntimeError("google-cloud-pubsub is required for the GCP runner")
    return pubsub_v1.PublisherClient()


def _skill_command() -> list[str]:
    raw = os.environ.get("DETECT_SKILL_CMD", "").strip()
    if not raw:
        raise ValueError("DETECT_SKILL_CMD is required")
    return shlex.split(raw)


def _dedupe_collection() -> str:
    name = os.environ.get("DEDUPE_COLLECTION", "").strip()
    if not name:
        raise ValueError("DEDUPE_COLLECTION is required")
    return name


def _findings_topic() -> str:
    topic = os.environ.get("FINDINGS_TOPIC", "").strip()
    if not topic:
        raise ValueError("FINDINGS_TOPIC is required")
    return topic


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


def _expires_at(now: datetime | None = None) -> datetime:
    current = datetime.now(UTC) if now is None else now
    return current + timedelta(days=_dedupe_ttl_days())


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


def _decode_pubsub_event(event: dict[str, Any]) -> list[str]:
    data = event.get("data")
    if not data:
        return []
    payload = base64.b64decode(data).decode("utf-8")
    return [line for line in payload.splitlines() if line.strip()]


def _publish_findings(
    publisher: Any,
    topic: str,
    records: list[tuple[str, str]],
) -> None:
    # PublisherClient batches outstanding publish() calls under the hood. Keep
    # the futures unresolved until the full batch is queued, then wait once.
    futures = [publisher.publish(topic, line.encode("utf-8")) for line, _uid in records]
    for future in futures:
        future.result()


def _put_if_new(uid: str, payload: str) -> bool:
    document = _firestore_client().collection(_dedupe_collection()).document(uid)
    item = {
        "seen_at": datetime.now(UTC).isoformat(),
        "payload_sha256": sha256(payload.encode("utf-8")).hexdigest(),
        "expires_at": _expires_at(),
    }
    try:
        document.create(item)
        return True
    except Conflict:
        return False


def handle_pubsub_event(event: dict[str, Any], _context: Any) -> dict[str, int]:
    input_lines = _decode_pubsub_event(event)
    findings = _run_skill(input_lines)

    to_publish: list[tuple[str, str]] = []
    duplicates = 0
    topic = _findings_topic()
    publisher = _publisher_client()

    for line in findings:
        record = json.loads(line)
        uid = _extract_uid(record)
        if _put_if_new(uid, line):
            to_publish.append((line, uid))
        else:
            duplicates += 1

    if to_publish:
        _publish_findings(publisher, topic, to_publish)

    return {
        "messages_processed": len(input_lines),
        "published": len(to_publish),
        "duplicates": duplicates,
    }
