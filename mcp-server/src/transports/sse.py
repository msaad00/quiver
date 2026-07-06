"""SSE / streamable-HTTP transport for the MCP wrapper.

This is slice 1 of issue #415 — the transport listener + bearer auth +
audit-chain integration. The cloud-runner wiring (Helm/Docker) and key
rotation arrive in slice 2.

The transport speaks the same JSON-RPC contract as `server.py` (stdio).
Both surfaces call into `dispatch.handle_request`; the only difference
on the audit record is `transport="sse"`. The HMAC chain in
`audit_sink.AuditSink` is shared across both surfaces — `dispatch`
serialises every emit through `_AUDIT_LOCK` so concurrent SSE clients
cannot interleave their chain links.

Endpoints
---------
- `GET /healthz` — unauthenticated liveness probe.
- `GET /sse`    — opens the long-lived SSE event stream (one per
                  client session). First event is `event: endpoint`
                  carrying `/messages?session=<token>`; subsequent
                  events are JSON-RPC responses keyed by request id.
                  Requires `Authorization: Bearer <key>`.
- `POST /messages?session=<token>` — accepts one JSON-RPC message,
                  hands it to `dispatch.handle_request`, queues the
                  response onto the matching SSE stream, and returns
                  `202 Accepted`. Requires `Authorization: Bearer <key>`.

Bind defaults are `127.0.0.1:8765`. The server refuses to bind to a
public address unless `MCP_SSE_ALLOW_PUBLIC_BIND=1` AND at least one
bearer key is configured — accidental exposure is the primary concern
this guard addresses.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

import dispatch  # noqa: E402
from key_rotation import (  # noqa: E402
    KEYS_ENV_FALLBACK,
    KEYS_FILE_ENV,
    EmptyKeyStoreError,
    KeyStore,
)

try:  # pragma: no cover - exercised only when the extra is missing
    from sse_starlette.sse import EventSourceResponse
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "mcp-server SSE transport requires `sse-starlette`, `starlette`, and "
        "`uvicorn`. Install with "
        "`uv sync --group dev --group mcp-sse --group http-runtime` or pin "
        "those packages in your deployment image."
    ) from exc

SSE_TRANSPORT_LABEL = "sse"
BIND_ENV = "MCP_SSE_BIND"
PORT_ENV = "MCP_SSE_PORT"
KEYS_ENV = KEYS_ENV_FALLBACK
ALLOW_PUBLIC_BIND_ENV = "MCP_SSE_ALLOW_PUBLIC_BIND"

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8765

# Localhost forms that do not count as "public" for the bind guard.
_LOCAL_BINDS = frozenset({"127.0.0.1", "localhost", "::1"})


def _bearer_keys(env: dict[str, str] | None = None) -> set[str]:
    """Parse `MCP_SSE_BEARER_KEYS` into a set. Empty / unset -> empty set."""
    src = os.environ if env is None else env
    raw = (src.get(KEYS_ENV) or "").strip()
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def _bind_is_public(bind: str) -> bool:
    """`0.0.0.0` and any non-localhost address counts as public."""
    return bind not in _LOCAL_BINDS


def _truthy_env(name: str, env: dict[str, str] | None = None) -> bool:
    src = os.environ if env is None else env
    return (src.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _check_bind_safety(bind: str, has_keys: bool, env: dict[str, str] | None = None) -> None:
    """Raise SystemExit when the requested bind is unsafe.

    The two cases that fail:
    - Public bind without `MCP_SSE_ALLOW_PUBLIC_BIND=1` (operators must
      acknowledge the broader exposure).
    - Public bind with the override on but no bearer keys configured
      (an open door is never the right default).

    Both write a one-line rationale to stderr so a misconfigured deploy
    surfaces the cause in the supervisor's logs.
    """
    if not _bind_is_public(bind):
        return
    if not _truthy_env(ALLOW_PUBLIC_BIND_ENV, env):
        sys.stderr.write(
            f"[mcp-sse] refusing to bind on public address {bind!r}: set "
            f"{ALLOW_PUBLIC_BIND_ENV}=1 to acknowledge the exposure and "
            f"configure {KEYS_ENV} or {KEYS_FILE_ENV} with at least one "
            f"bearer key.\n"
        )
        sys.stderr.flush()
        raise SystemExit(2)
    if not has_keys:
        sys.stderr.write(
            f"[mcp-sse] refusing to bind on public address {bind!r} without "
            f"bearer keys configured: set {KEYS_ENV}=key1[,key2,...] or "
            f"{KEYS_FILE_ENV}=/path/to/keys.json before enabling "
            f"{ALLOW_PUBLIC_BIND_ENV}.\n"
        )
        sys.stderr.flush()
        raise SystemExit(2)


def _verify_bearer(request: Request, key_store: KeyStore) -> bool:
    """Constant-time bearer-token check against the live key store.

    Empty store => unauthenticated mode is forbidden: this function
    always returns False. The `_check_bind_safety` guard already keeps
    public binds from reaching here without keys; this is the second
    gate so a localhost-bound deploy still requires a key.
    """
    raw = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not raw.lower().startswith("bearer "):
        return False
    presented = raw.split(" ", 1)[1].strip()
    if not presented:
        return False
    return bool(key_store.verify_token(presented))


class _Session:
    """One SSE stream + its inbound queue.

    The session owns an `asyncio.Queue` of dicts; the POST handler
    writes JSON-RPC responses into it, the SSE handler drains them
    onto the wire. Cap the queue at a small bound so a stuck client
    cannot OOM the server.
    """

    def __init__(self) -> None:
        self.queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=64)


class _SessionRegistry:
    """Process-local map of session token -> session.

    Sessions are created by `GET /sse` and torn down when the client
    disconnects. Tokens are 256-bit URL-safe randoms — `secrets.token_urlsafe(32)`.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._sessions: dict[str, _Session] = {}

    async def open(self) -> tuple[str, _Session]:
        token = secrets.token_urlsafe(32)
        session = _Session()
        async with self._lock:
            self._sessions[token] = session
        return token, session

    async def get(self, token: str) -> _Session | None:
        async with self._lock:
            return self._sessions.get(token)

    async def close(self, token: str) -> None:
        async with self._lock:
            session = self._sessions.pop(token, None)
        if session is not None:
            # Sentinel wakes the SSE generator so it exits cleanly.
            await session.queue.put(None)


def create_app(
    *,
    bind: str | None = None,
    env: dict[str, str] | None = None,
    install_sighup: bool = False,
) -> Starlette:
    """Build the Starlette app. Performs the bind-safety check up-front
    so a misconfigured operator never gets a half-bound listener.

    When `install_sighup=True` (set by `serve()`), the resulting key
    store wires `SIGHUP` to a synchronous reload so operators can
    rotate bearer keys without bouncing the listener. Tests leave the
    flag off so signal handlers do not leak across the suite.
    """
    src = os.environ if env is None else env
    effective_bind = (
        bind if bind is not None else (src.get(BIND_ENV) or DEFAULT_BIND).strip() or DEFAULT_BIND
    )
    try:
        key_store = KeyStore(env=src, emit_audit=dispatch.emit_audit_event)
    except EmptyKeyStoreError as exc:
        sys.stderr.write(f"[mcp-sse] {exc}\n")
        sys.stderr.flush()
        raise SystemExit(2) from exc
    except ValueError as exc:
        sys.stderr.write(f"[mcp-sse] keys file is malformed: {exc}\n")
        sys.stderr.flush()
        raise SystemExit(2) from exc
    if install_sighup:
        key_store.install_sighup_handler()
    _check_bind_safety(effective_bind, key_store.has_keys(), env)

    registry = _SessionRegistry()

    async def healthz(request: Request) -> Response:  # noqa: ARG001
        return JSONResponse({"status": "ok", "service": "mcp-sse"})

    async def sse(request: Request) -> Response:
        if not _verify_bearer(request, key_store):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token, session = await registry.open()

        async def event_stream() -> Any:
            # Hand the client the URL it should POST inbound JSON-RPC to.
            yield {
                "event": "endpoint",
                "data": f"/messages?session={token}",
            }
            try:
                while True:
                    message = await session.queue.get()
                    if message is None:
                        return
                    yield {
                        "event": "message",
                        "data": json.dumps(message, sort_keys=True),
                    }
            finally:
                await registry.close(token)

        return EventSourceResponse(event_stream())

    async def messages(request: Request) -> Response:
        if not _verify_bearer(request, key_store):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        token = request.query_params.get("session", "")
        if not token:
            return JSONResponse({"error": "missing_session"}, status_code=400)
        session = await registry.get(token)
        if session is None:
            return JSONResponse({"error": "unknown_session"}, status_code=404)
        try:
            payload = await request.json()
        except (ValueError, json.JSONDecodeError):
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "invalid_payload"}, status_code=400)

        # Dispatch off the event loop — the per-tool subprocess can take
        # multiple seconds and we don't want to wedge the listener.
        response = await asyncio.to_thread(
            dispatch.handle_request, payload, transport=SSE_TRANSPORT_LABEL
        )
        if response is not None:
            await session.queue.put(response)
        return JSONResponse({"accepted": True}, status_code=202)

    async def rpc(request: Request) -> Response:
        """Synchronous JSON-RPC convenience endpoint.

        The canonical MCP SSE pair (`GET /sse` + `POST /messages`) is
        the right shape for streaming clients; programmatic callers
        and tests do not need a session — they can POST one JSON-RPC
        message and read the JSON response inline. Audit emission is
        identical (`transport="sse"`) so this stays one auditable
        surface, not two.
        """
        if not _verify_bearer(request, key_store):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            payload = await request.json()
        except (ValueError, json.JSONDecodeError):
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "invalid_payload"}, status_code=400)
        response = await asyncio.to_thread(
            dispatch.handle_request, payload, transport=SSE_TRANSPORT_LABEL
        )
        if response is None:
            return Response(status_code=204)
        return JSONResponse(response)

    return Starlette(
        debug=False,
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/sse", sse, methods=["GET"]),
            Route("/messages", messages, methods=["POST"]),
            Route("/rpc", rpc, methods=["POST"]),
        ],
    )


def serve() -> int:
    """Bind + run the SSE listener under uvicorn."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise ModuleNotFoundError(
            "mcp-server SSE transport requires `uvicorn`. Install with "
            "`uv sync --group dev --group http-runtime`."
        ) from exc
    bind = (os.environ.get(BIND_ENV) or DEFAULT_BIND).strip() or DEFAULT_BIND
    port_raw = (os.environ.get(PORT_ENV) or "").strip()
    port = int(port_raw) if port_raw else DEFAULT_PORT
    app = create_app(bind=bind, install_sighup=True)
    uvicorn.run(app, host=bind, port=port, log_level="info", access_log=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(serve())
