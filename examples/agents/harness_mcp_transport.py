"""Operator-owned stdio transport for harness MCP execution reports.

This helper speaks the repo MCP server's content-length-framed JSON-RPC
transport. It is intentionally separate from the graph: the graph produces an
audited plan, and an operator can evaluate that plan with this transport in a
second step.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import time
from collections.abc import Mapping, Sequence
from typing import Any, BinaryIO

SAFE_ENV_NAMES = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
    "VIRTUAL_ENV",
    "WINDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
}

MCP_POLICY_ENV_NAMES = {
    "CLOUD_SECURITY_MCP_ALLOWED_SKILLS",
    "CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS",
    "CLOUD_SECURITY_MCP_TIMEOUT_SECONDS",
}


def safe_mcp_env(*, allowed_skills: Sequence[str] = ()) -> dict[str, str]:
    """Return a subprocess env that excludes credentials and arbitrary tokens."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key in SAFE_ENV_NAMES or key in MCP_POLICY_ENV_NAMES
    }
    if allowed_skills:
        env["CLOUD_SECURITY_MCP_ALLOWED_SKILLS"] = ",".join(sorted(set(allowed_skills)))
        env["CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS"] = "true"
    return env


def _write_message(stream: BinaryIO, message: Mapping[str, Any]) -> None:
    payload = json.dumps(message, sort_keys=True).encode("utf-8")
    stream.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8"))
    stream.write(payload)
    stream.flush()


def _readline(stream: BinaryIO, *, deadline: float) -> bytes:
    timeout = max(0.0, deadline - time.monotonic())
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        raise TimeoutError("timed out waiting for MCP response header")
    return stream.readline()


def _read_exact(stream: BinaryIO, length: int, *, deadline: float) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        timeout = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([stream], [], [], timeout)
        if not ready:
            raise TimeoutError("timed out waiting for MCP response body")
        chunk = stream.read(remaining)
        if not chunk:
            raise RuntimeError("MCP server closed stdout before response body completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_message(stream: BinaryIO, *, deadline: float) -> dict[str, Any]:
    headers: dict[str, str] = {}
    while True:
        line = _readline(stream, deadline=deadline)
        if not line:
            raise RuntimeError("MCP server closed stdout before returning a response")
        if line in (b"\r\n", b"\n"):
            break
        key, value = line.decode("utf-8").split(":", 1)
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        raise RuntimeError("MCP response missing content-length")
    payload = _read_exact(stream, length, deadline=deadline)
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RuntimeError("MCP response payload must be a JSON object")
    return decoded


class McpStdioTransport:
    """Long-lived stdio JSON-RPC transport for planned MCP calls."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float = 30,
    ) -> None:
        if not command:
            raise ValueError("MCP stdio command must not be empty")
        self.command = list(command)
        self.env = dict(env or safe_mcp_env())
        self.timeout_seconds = timeout_seconds
        self._process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "McpStdioTransport":
        self._process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            bufsize=0,
        )
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        process = self._process
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def __call__(self, request: dict[str, Any]) -> Mapping[str, Any]:
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise RuntimeError("MCP stdio transport is not started")
        started = time.monotonic()
        _write_message(process.stdin, request)
        if process.poll() is not None:
            raise RuntimeError(f"MCP server exited with code {process.returncode}")
        return _read_message(process.stdout, deadline=started + self.timeout_seconds)
