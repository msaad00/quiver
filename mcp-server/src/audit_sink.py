"""Durable, append-only audit sink for the MCP wrapper.

`_emit_audit_event` historically wrote one JSON line to stderr and returned.
That satisfies the "every call is audited" claim only when the supervising
process captures stderr — a stdio MCP client that closes or ignores stderr
loses the audit trail entirely.

This module adds an optional file sink with three additive guarantees:

1. **Append-only on disk.** A configurable file path receives one JSON line
   per resolved tool call. Open / write / fsync per event so a crash mid-call
   still leaves the previous events durable.
2. **Tamper-evident chain.** When `CLOUD_SECURITY_AUDIT_HMAC_KEY` is set, each
   event carries `prev_hash` and `chain_hash` fields computed as
   `HMAC-SHA-256(key, prev_hash || canonical_event_json)`. A verifier script
   (`scripts/verify_audit_chain.py`) replays the chain and surfaces gaps.
3. **stderr stays the fallback.** When no file sink is configured, behaviour
   is unchanged — every event still lands on stderr. When a file sink is
   configured, both happen so existing supervisors continue to work.

The sink is intentionally process-local: chain hashes are scoped to a single
server process. Multi-process supervisors should aggregate across processes
on the consumer side (each process writes its own segment, the verifier
joins by `correlation_id` order).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

AUDIT_LOG_ENV = "CLOUD_SECURITY_MCP_AUDIT_LOG"
AUDIT_HMAC_KEY_ENV = "CLOUD_SECURITY_AUDIT_HMAC_KEY"

# Sentinel for the genesis event in a chain. Any non-empty deterministic value
# works; this one is documented so verifiers can recognise the boundary.
GENESIS_PREV_HASH = "0" * 64


def _canonical_event_bytes(event: dict[str, Any]) -> bytes:
    """Stable, sorted JSON encoding so the chain hash is reproducible across
    Python versions and dict insertion orders."""
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _chain_hash(prev_hash: str, event: dict[str, Any], key: bytes) -> str:
    payload = prev_hash.encode("ascii") + b"\n" + _canonical_event_bytes(event)
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


class AuditSink:
    """Process-local audit sink. Holds the previous chain hash so successive
    events link. Construct once per server process; never reuse across forks.
    """

    def __init__(
        self,
        log_path: str | os.PathLike[str] | None,
        hmac_key: bytes | None,
    ) -> None:
        self._log_path = Path(log_path) if log_path else None
        self._hmac_key = hmac_key
        self._prev_hash = GENESIS_PREV_HASH
        if self._log_path is not None:
            # Touch the parent directory so a misconfigured path fails fast at
            # server start instead of at the first call.
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            # If the file already has content and chaining is on, seed
            # `_prev_hash` from the last event's `chain_hash` so a restart
            # extends the existing chain instead of starting a new one.
            if self._hmac_key is not None and self._log_path.exists():
                last = _read_last_chain_hash(self._log_path)
                if last is not None:
                    self._prev_hash = last

    @property
    def file_enabled(self) -> bool:
        return self._log_path is not None

    @property
    def chain_enabled(self) -> bool:
        return self._hmac_key is not None

    def annotate(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return a new event dict with chain fields populated when chaining
        is enabled. The original event is left untouched so callers can keep
        a pristine copy for stderr if they prefer."""
        if not self.chain_enabled:
            return event
        annotated = dict(event)
        annotated["prev_hash"] = self._prev_hash
        # Compute chain_hash over the event WITHOUT chain_hash (otherwise it
        # depends on itself). prev_hash is included.
        annotated["chain_hash"] = _chain_hash(
            self._prev_hash, annotated, self._hmac_key or b""
        )
        self._prev_hash = annotated["chain_hash"]
        return annotated

    def write_file(self, event: dict[str, Any]) -> None:
        if self._log_path is None:
            return
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        # `open` + write + fsync per event so a crash mid-write doesn't lose
        # the trail. Throughput-conscious deployments can buffer at the OS
        # level by setting CLOUD_SECURITY_MCP_AUDIT_LOG to a path on a
        # write-ahead-logged filesystem; for a security audit trail
        # correctness beats throughput.
        fd = os.open(
            self._log_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)


def _read_last_chain_hash(path: Path) -> str | None:
    """Read the last line of `path`, parse it, and return its `chain_hash`.

    Returns None if the file is empty, the last line is not JSON, or the
    last record has no chain_hash. Used to extend an existing chain across
    server restarts so verifiers see one continuous chain.
    """
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            if size == 0:
                return None
            # Walk backwards until we find a newline preceded by content.
            # 4KB lookback covers our 1-2KB events comfortably.
            chunk_size = min(size, 4096)
            fh.seek(size - chunk_size, os.SEEK_SET)
            tail = fh.read(chunk_size)
        last_line = tail.splitlines()[-1] if tail else b""
        if not last_line:
            return None
        record = json.loads(last_line.decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    last_hash = record.get("chain_hash")
    return last_hash if isinstance(last_hash, str) else None


def sink_from_env(env: dict[str, str] | None = None) -> AuditSink:
    """Build the sink from environment variables. Both vars are optional; the
    default sink keeps the legacy stderr-only behaviour."""
    src = os.environ if env is None else env
    log_path = (src.get(AUDIT_LOG_ENV) or "").strip() or None
    raw_key = (src.get(AUDIT_HMAC_KEY_ENV) or "").strip()
    hmac_key = raw_key.encode("utf-8") if raw_key else None
    return AuditSink(log_path=log_path, hmac_key=hmac_key)
