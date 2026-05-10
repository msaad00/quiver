"""Long-running JSON-RPC harness for evaluation skill entrypoints.

A skill that wants to opt into the persistent-worker pool wraps its
existing one-shot `main()` like this:

    if __name__ == "__main__":
        if "--worker" in sys.argv:
            from skills._shared.worker_harness import run_worker
            raise SystemExit(run_worker(main))
        raise SystemExit(main())

`run_worker(main)` keeps the interpreter resident and reads
Content-Length-framed JSON-RPC messages on stdin. For each call it:

1. Replaces `sys.argv` with `[entrypoint, *params.args]`.
2. Replaces `sys.stdin` with the per-call input string (if any).
3. Captures `sys.stdout` / `sys.stderr` for the duration of the call
   and treats `SystemExit` as the skill's exit code.
4. Replies with one framed JSON-RPC message carrying `stdout`,
   `stderr`, and `exit_code`.

Trust model is identical to the one-shot path — the *parent* (the MCP
wrapper) still owns env scrubbing, RLIMIT enforcement, and sandbox
wrap. The harness does not relax any of those; it only re-uses the
warmed interpreter.

No persistent state across calls. Skills that read module-level state
do so at their own contract risk — the harness deliberately does NOT
re-import the skill between calls; that's the whole point of warming.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from typing import Any, BinaryIO


def _read_framed(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        try:
            name, value = line.decode("utf-8").split(":", 1)
        except ValueError:
            return None
        headers[name.strip().lower()] = value.strip()
    try:
        length = int(headers.get("content-length", "0"))
    except ValueError:
        return None
    if length <= 0:
        return None
    payload = stream.read(length)
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def _write_framed(stream: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    stream.write(body)
    stream.flush()


def _dispatch_one(main: Callable[[], Any], params: dict[str, Any]) -> dict[str, Any]:
    """Run `main()` once with the requested args / stdin and capture
    stdout / stderr / exit code."""
    raw_args = params.get("args") if isinstance(params, dict) else None
    if not isinstance(raw_args, list):
        raw_args = []
    args: list[str] = [str(arg) for arg in raw_args]

    raw_input = params.get("input") if isinstance(params, dict) else ""
    stdin_text = raw_input if isinstance(raw_input, str) else ""

    saved_argv = sys.argv
    saved_stdin = sys.stdin
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr

    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    exit_code = 0

    try:
        # `sys.argv[0]` mirrors the one-shot path so argparse's program
        # name is consistent with the existing CLI.
        sys.argv = [saved_argv[0], *args]
        sys.stdin = io.StringIO(stdin_text)
        sys.stdout = captured_stdout
        sys.stderr = captured_stderr
        try:
            result = main()
        except SystemExit as exc:
            code = exc.code
            if code is None:
                exit_code = 0
            elif isinstance(code, int):
                exit_code = code
            else:
                exit_code = 1
                captured_stderr.write(str(code))
        except BaseException as exc:  # noqa: BLE001 - report any exception cleanly
            exit_code = 1
            captured_stderr.write(f"{type(exc).__name__}: {exc}\n")
        else:
            if isinstance(result, int):
                exit_code = result
    finally:
        sys.argv = saved_argv
        sys.stdin = saved_stdin
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr

    return {
        "stdout": captured_stdout.getvalue(),
        "stderr": captured_stderr.getvalue(),
        "exit_code": exit_code,
    }


def run_worker(main: Callable[[], Any]) -> int:
    """Read framed JSON-RPC `tools/call` messages on stdin and reply on
    stdout. Returns 0 on clean EOF.

    The contract is intentionally narrow — only `tools/call` is
    handled; any other method gets a `-32601` error. Parent process
    (the MCP wrapper) is the only expected caller; broader RPC
    semantics are server.py's job, not the worker's.
    """
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        message = _read_framed(stdin)
        if message is None:
            return 0
        request_id = message.get("id")
        method = message.get("method")
        if method != "tools/call":
            _write_framed(
                stdout,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"worker only handles tools/call (got {method!r})",
                    },
                },
            )
            continue
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        result = _dispatch_one(main, params)
        _write_framed(
            stdout,
            {"jsonrpc": "2.0", "id": request_id, "result": result},
        )
