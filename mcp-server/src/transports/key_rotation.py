"""Bearer-key rotation contract for the SSE / streamable-HTTP transport.

Slice 2 of #415 wires the transport into deployable surfaces. One of
the gaps slice 1 left explicit was rotating the bearer keys without a
listener restart. This module fills it.

Contract
--------

* Keys live on a JSON file: a top-level array of objects with `kid`,
  `secret`, `issued`, `expires` (ISO-8601 UTC; `expires` is optional —
  unset means "never expires"). Path comes from
  `MCP_SSE_BEARER_KEYS_FILE`.

* Reads are cached behind `KeyStore`. The store loads at construction
  time and reloads on `SIGHUP`. On every successful reload the store
  emits a `bearer_key_rotated` audit record through the same
  `audit_sink.AuditSink` the dispatch path uses, so the chain stays
  unbroken.

* Rotation is overlap-friendly: validation accepts ANY non-expired
  secret in the store. Cut a new key, deploy, retire the old one — no
  client downtime.

* Backward-compat: when `MCP_SSE_BEARER_KEYS_FILE` is unset, the store
  falls back to parsing `MCP_SSE_BEARER_KEYS` (the slice-1 env-only
  path). Those keys carry a synthetic kid (`env-<index>`) and never
  expire. The fallback path emits no rotation audit (it is the
  pre-rotation contract).

* Refusal: when the file path is set but the file resolves to zero
  valid keys (parse error, schema mismatch, every key expired), the
  store raises `EmptyKeyStoreError`. The transport catches this in
  `create_app` and exits — an open-door deploy is never the right
  default.

Audit record shape
------------------

::

    {
      "event": "bearer_key_rotated",
      "transport": "sse",
      "timestamp": "2026-05-10T12:34:56.789Z",
      "kids_added":   ["k2"],
      "kids_removed": ["k0"],
      "kids_active":  ["k1", "k2"],
      "source":       "file",
      "reason":       "boot" | "sighup"
    }

Secrets never appear in the audit record — only `kid` values do. The
record is annotated with `prev_hash` / `chain_hash` by the shared sink
just like every other audit event.
"""

from __future__ import annotations

import hmac
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

KEYS_FILE_ENV = "MCP_SSE_BEARER_KEYS_FILE"
KEYS_ENV_FALLBACK = "MCP_SSE_BEARER_KEYS"

_BEARER_KEY_ROTATED_EVENT = "bearer_key_rotated"


class EmptyKeyStoreError(RuntimeError):
    """Raised when a configured keys file resolves to zero usable keys.

    The transport refuses to start in that state — the file path was
    explicitly configured, so a silent fall-through to "no auth"
    would be a footgun.
    """


class _Key:
    """Internal record for one configured key.

    `expires` is `None` when the key never expires (env-fallback path
    or omitted in the file). Comparisons use timezone-aware UTC.
    """

    __slots__ = ("kid", "secret", "issued", "expires")

    def __init__(
        self,
        kid: str,
        secret: str,
        issued: datetime | None,
        expires: datetime | None,
    ) -> None:
        self.kid = kid
        self.secret = secret
        self.issued = issued
        self.expires = expires

    def is_expired(self, now: datetime) -> bool:
        return self.expires is not None and self.expires <= now


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601(value: str | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"timestamp must be a string, got {type(value).__name__}")
    raw = value.strip()
    if not raw:
        return None
    # `datetime.fromisoformat` accepts "+00:00" but not the trailing
    # "Z" form callers tend to write. Normalise so both round-trip.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _coerce_keys_payload(payload: Any) -> list[_Key]:
    """Validate the shape of the on-disk keys file and produce `_Key`s.

    The file contract is intentionally rigid — typos on field names
    should not silently drop keys. Each entry must carry `kid` and
    `secret`; `issued` / `expires` are optional. Unknown fields are
    ignored (forward-compat for future metadata such as `purpose`).
    """
    if not isinstance(payload, list):
        raise ValueError("keys file must contain a top-level JSON array")
    keys: list[_Key] = []
    seen_kids: set[str] = set()
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise ValueError(f"key entry {index} is not an object")
        kid = entry.get("kid")
        secret = entry.get("secret")
        if not isinstance(kid, str) or not kid.strip():
            raise ValueError(f"key entry {index} missing non-empty `kid`")
        if not isinstance(secret, str) or not secret.strip():
            raise ValueError(f"key {kid!r} missing non-empty `secret`")
        if kid in seen_kids:
            raise ValueError(f"duplicate kid {kid!r}")
        seen_kids.add(kid)
        issued = _parse_iso8601(entry.get("issued"))
        expires = _parse_iso8601(entry.get("expires"))
        keys.append(_Key(kid=kid, secret=secret, issued=issued, expires=expires))
    return keys


def _load_keys_from_file(path: Path) -> list[_Key]:
    raw = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"keys file {path} is not valid JSON: {exc}") from exc
    return _coerce_keys_payload(payload)


def _load_keys_from_env(value: str) -> list[_Key]:
    """Parse the legacy comma-separated env into synthetic Keys.

    Slice 1 accepted `MCP_SSE_BEARER_KEYS=k1,k2`; we keep that contract
    so a deploy upgrading to slice 2 without changing config still
    boots. Synthetic kids (`env-0`, `env-1`, ...) make audit records
    distinguishable from file-loaded keys.
    """
    keys: list[_Key] = []
    for index, part in enumerate(value.split(",")):
        secret = part.strip()
        if not secret:
            continue
        keys.append(_Key(kid=f"env-{index}", secret=secret, issued=None, expires=None))
    return keys


class KeyStore:
    """Process-local bearer-key store with SIGHUP-driven reloads.

    Thread-safe: every public method takes an internal lock. Verifying
    a token is cheap (linear scan over a few keys); the lock contention
    is dominated by the audited reload, not the request path.
    """

    def __init__(
        self,
        *,
        env: dict[str, str] | None = None,
        emit_audit: Callable[[dict[str, Any]], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._env = os.environ if env is None else env
        self._emit_audit = emit_audit
        self._clock = clock or _utc_now
        self._lock = threading.Lock()
        self._keys: list[_Key] = []
        self._source: str = "none"
        self._file_path: Path | None = None
        self._sighup_installed = False
        self._initial_load()

    # ---------------------------------------------------------------
    # Loading
    # ---------------------------------------------------------------

    def _initial_load(self) -> None:
        file_value = (self._env.get(KEYS_FILE_ENV) or "").strip()
        if file_value:
            self._file_path = Path(file_value)
            self._reload(reason="boot", source="file")
        else:
            env_value = (self._env.get(KEYS_ENV_FALLBACK) or "").strip()
            if env_value:
                self._keys = _load_keys_from_env(env_value)
                self._source = "env"
            # No source configured -> empty store. The transport's
            # bind-safety check decides whether that is fatal.

    def _reload(self, *, reason: str, source: str) -> None:
        """Reload from the configured source and emit the rotation audit.

        Called from `__init__` (`reason="boot"`) and from the SIGHUP
        handler (`reason="sighup"`). Refuses to swap in an empty key
        list when the source is the file path — that would silently
        lock everyone out.
        """
        assert self._file_path is not None, "_reload only valid for file source"
        new_keys = _load_keys_from_file(self._file_path)
        now = self._clock()
        usable = [k for k in new_keys if not k.is_expired(now)]
        if not usable:
            raise EmptyKeyStoreError(f"keys file {self._file_path} resolved to 0 usable keys")
        with self._lock:
            previous_kids = {k.kid for k in self._keys}
            new_kids = {k.kid for k in new_keys}
            self._keys = new_keys
            self._source = source
        added = sorted(new_kids - previous_kids)
        removed = sorted(previous_kids - new_kids)
        active = sorted(k.kid for k in new_keys if not k.is_expired(now))
        self._emit_rotation_audit(
            reason=reason,
            source=source,
            added=added,
            removed=removed,
            active=active,
        )

    # ---------------------------------------------------------------
    # SIGHUP wiring
    # ---------------------------------------------------------------

    def install_sighup_handler(self) -> None:
        """Wire `SIGHUP` to a synchronous reload.

        Idempotent. No-op on platforms that do not support `SIGHUP`
        (Windows). The handler only schedules the reload; the actual
        work happens on the main thread when Python next services
        signals — that keeps the file IO off the asyncio loop.
        """
        if self._sighup_installed:
            return
        sighup = getattr(signal, "SIGHUP", None)
        if sighup is None:  # pragma: no cover - non-POSIX
            return
        try:
            signal.signal(sighup, self._on_sighup)
        except ValueError:  # pragma: no cover - non-main thread
            return
        self._sighup_installed = True

    def reload_now(self) -> None:
        """Trigger a reload synchronously. Exposed for tests + the
        rotation script's `--reload-running-pid` helper."""
        if self._file_path is None:
            return
        self._reload(reason="manual", source="file")

    def _on_sighup(self, signum: int, frame: Any) -> None:  # noqa: ARG002
        # Never raise out of a signal handler — the supervisor cannot
        # tell which user-thread would unwind.
        try:
            self._reload(reason="sighup", source="file")
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[mcp-sse] SIGHUP reload failed: {exc!s}; keeping previous keys\n")
            sys.stderr.flush()

    # ---------------------------------------------------------------
    # Verification
    # ---------------------------------------------------------------

    def verify_token(self, token: str) -> bool:
        """Constant-time check across all non-expired keys.

        Empty `token` always returns False. Empty store returns False.
        The comparison runs against every non-expired key — the
        overlap window is the entire purpose of the rotation contract.
        """
        if not token:
            return False
        presented = token.encode("utf-8")
        now = self._clock()
        with self._lock:
            usable = [k for k in self._keys if not k.is_expired(now)]
        for key in usable:
            if hmac.compare_digest(presented, key.secret.encode("utf-8")):
                return True
        return False

    def has_keys(self) -> bool:
        """True when at least one non-expired key is currently loaded."""
        now = self._clock()
        with self._lock:
            return any(not k.is_expired(now) for k in self._keys)

    @property
    def source(self) -> str:
        return self._source

    def active_kids(self) -> list[str]:
        """Snapshot of currently-active (non-expired) kids. Test hook."""
        now = self._clock()
        with self._lock:
            return sorted(k.kid for k in self._keys if not k.is_expired(now))

    # ---------------------------------------------------------------
    # Audit
    # ---------------------------------------------------------------

    def _emit_rotation_audit(
        self,
        *,
        reason: str,
        source: str,
        added: Iterable[str],
        removed: Iterable[str],
        active: Iterable[str],
    ) -> None:
        if self._emit_audit is None:
            return
        record: dict[str, Any] = {
            "event": _BEARER_KEY_ROTATED_EVENT,
            "transport": "sse",
            "timestamp": _iso8601(self._clock()),
            "reason": reason,
            "source": source,
            "kids_added": sorted(added),
            "kids_removed": sorted(removed),
            "kids_active": sorted(active),
        }
        try:
            self._emit_audit(record)
        except Exception as exc:  # noqa: BLE001
            # Audit emission failure must not bring the listener down.
            # The supervisor will see the rotation succeeded on the
            # next request; the audit gap is logged here so a SIEM
            # tail can flag it.
            sys.stderr.write(f"[mcp-sse] failed to emit bearer_key_rotated audit: {exc!s}\n")
            sys.stderr.flush()


def _iso8601(value: datetime) -> str:
    """Millisecond-precision UTC ISO-8601 with trailing `Z`.

    Matches the formatting used by `_call_tool` so a SIEM that already
    parses the tool-call audit timestamps does not need a second
    pattern for rotation events.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
