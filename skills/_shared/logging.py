"""Structured logger for shipped skills.

Every log record is a single-line JSON object on stderr, tagged with the
skill name, layer, correlation_id, and (optional) step. SIEMs ingest one
shape across every skill; operator tails parse the same shape with
`jq`.

The logger is a thin wrapper around `logging.LoggerAdapter` so callers
can keep using `logger.info("...", arg)` without learning a new API.

Usage:

    from skills._shared.logging import get_logger
    log = get_logger(__name__, skill="detect-okta-mfa-fatigue", layer="detection")
    log.info("processing batch", extra={"batch_size": 1000})

The `SKILL_CORRELATION_ID` env var is read once at logger construction
and stamped into every record so MCP-wrapped invocations and runner
invocations both produce records that join on `correlation_id` after
the fact.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import MutableMapping
from datetime import UTC, datetime
from typing import Any

_RESERVED_LOGRECORD_KEYS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "asctime",
        "taskName",
    }
)


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a sorted-key JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Pick up any extras the caller passed via `extra=` or our adapter.
        for key, value in record.__dict__.items():
            if key in _RESERVED_LOGRECORD_KEYS or key.startswith("_"):
                continue
            try:
                json.dumps(value)  # ensure serialisable
            except (TypeError, ValueError):
                value = repr(value)
            payload[key] = value
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class _ContextAdapter(logging.LoggerAdapter):
    """Stamp every log line with the skill / layer / correlation_id."""

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        existing_extra = kwargs.get("extra", {}) or {}
        merged = {**self.extra, **existing_extra} if self.extra else dict(existing_extra)
        kwargs["extra"] = merged
        return msg, kwargs


def _ensure_handler(logger: logging.Logger) -> None:
    if logger.handlers:
        return
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False


def get_logger(
    name: str,
    *,
    skill: str = "",
    layer: str = "",
    level: int = logging.INFO,
) -> logging.LoggerAdapter:
    """Build a structured logger pinned to one skill name + layer.

    The skill name and layer are stamped into every record alongside
    the correlation_id from `SKILL_CORRELATION_ID`. Multiple calls with
    the same `name` reuse the same underlying `Logger`; the adapter is
    cheap to recreate.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    _ensure_handler(logger)

    correlation_id = os.environ.get("SKILL_CORRELATION_ID", "")
    extras: dict[str, Any] = {}
    if skill:
        extras["skill"] = skill
    if layer:
        extras["layer"] = layer
    if correlation_id:
        extras["correlation_id"] = correlation_id
    return _ContextAdapter(logger, extras)
