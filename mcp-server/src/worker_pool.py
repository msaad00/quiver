"""Opt-in persistent-worker pool for hot skill loops.

Cold-start `subprocess.run` per skill call dominates wall time on
benchmarks that iterate dozens of controls — every CSPM call re-imports
`boto3` / `google-cloud-*` / `azure-mgmt-*`, and on the audit machine
that's 12-18s of pure import latency before the first byte of work.
This module keeps an interpreter warm per skill name and pipes one
JSON-RPC `tools/call`-shaped message per invocation over the worker's
stdin/stdout, framed exactly like the existing wrapper protocol.

Design constraints (mirrored from the PR brief):

- **Off by default.** Operators opt in via
  `CLOUD_SECURITY_MCP_WORKER_POOL=on`. Existing deployments unaffected.
- **One worker per skill name.** Spawned lazily on first call; reused
  for subsequent calls; killed on idle TTL or process exit.
- **Idle TTL.** 5 minutes default, tunable via
  `CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS`.
- **Hard kill on output overflow.** A single call producing more than
  `CLOUD_SECURITY_MCP_WORKER_MAX_BYTES` (default 10 MB) of stdout kills
  the worker; the next call re-spawns cold.
- **No semantic change.** Audit envelope still fires once per resolved
  tool call. RLIMIT and the sandbox wrapper still apply — the worker
  process is the one that hits the cap and gets wrapped in `bwrap` /
  `sandbox-exec` when sandboxing is on.
- **No persistent state across invocations.** Each `invoke()` is
  independent at the skill level; reuse of the worker is a latency
  optimisation, not a contract for cross-call state.
- **Bounded outputs.** A worker that prints 1 GB of stdout doesn't OOM
  the parent — we drain into a bounded buffer and kill at MAX_BYTES.
"""

from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    from tool_registry import SkillSpec

WORKER_POOL_ENV = "CLOUD_SECURITY_MCP_WORKER_POOL"
WORKER_IDLE_SECONDS_ENV = "CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS"
WORKER_MAX_BYTES_ENV = "CLOUD_SECURITY_MCP_WORKER_MAX_BYTES"

DEFAULT_IDLE_SECONDS = 300  # 5 minutes
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB

_TRUTHY = frozenset({"1", "true", "yes", "on"})

# Hard-coded list of evaluation-layer skills that are wired to support
# the long-running worker harness. Keep in lockstep with the
# `__main__` blocks in each skill's `checks.py`.
SUPPORTED_SKILL_NAMES: frozenset[str] = frozenset(
    {
        "cspm-aws-cis-benchmark",
        "cspm-gcp-cis-benchmark",
        "cspm-azure-cis-benchmark",
        "k8s-security-benchmark",
        "container-security",
    }
)


def is_enabled(env: dict[str, str] | None = None) -> bool:
    """Return True when `CLOUD_SECURITY_MCP_WORKER_POOL` is truthy.

    Truthy values match the rest of the wrapper: `1`, `true`, `yes`,
    `on` (case-insensitive). Missing / empty / anything else is off.
    """
    src = os.environ if env is None else env
    return src.get(WORKER_POOL_ENV, "").strip().lower() in _TRUTHY


def _idle_seconds(env: dict[str, str] | None = None) -> int:
    src = os.environ if env is None else env
    raw = (src.get(WORKER_IDLE_SECONDS_ENV) or "").strip()
    if not raw:
        return DEFAULT_IDLE_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_IDLE_SECONDS
    return max(value, 1)


def _max_bytes(env: dict[str, str] | None = None) -> int:
    src = os.environ if env is None else env
    raw = (src.get(WORKER_MAX_BYTES_ENV) or "").strip()
    if not raw:
        return DEFAULT_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_BYTES
    return max(value, 1024)


@dataclass
class CompletedProcessShape:
    """Minimal `subprocess.CompletedProcess`-shaped record returned by
    `WorkerPool.invoke()` so server.py can treat it identically to the
    one-shot path."""

    returncode: int
    stdout: str
    stderr: str
    args: list[str] = field(default_factory=list)


def _read_framed(stream: Any, max_bytes: int) -> tuple[bytes, bool]:
    """Read one Content-Length-framed JSON message from `stream`.

    Returns `(payload_bytes, overflow)`. When `overflow` is True the
    declared length exceeded `max_bytes` and the caller must kill the
    worker — we still drain enough to keep the framing consistent for
    the next message would not be valid anyway.
    """
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return b"", False
        if line in (b"\r\n", b"\n"):
            break
        try:
            name, value = line.decode("utf-8").split(":", 1)
        except ValueError:
            return b"", False
        headers[name.strip().lower()] = value.strip()
    length_raw = headers.get("content-length", "0")
    try:
        length = int(length_raw)
    except ValueError:
        return b"", False
    if length <= 0:
        return b"", False
    if length > max_bytes:
        return b"", True
    payload = stream.read(length)
    return payload, False


def _write_framed(stream: Any, message: dict[str, Any]) -> None:
    body = json.dumps(message).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    stream.write(body)
    stream.flush()


@dataclass
class _Worker:
    """One long-running interpreter for a single skill name."""

    skill_name: str
    process: subprocess.Popen[bytes]
    lock: threading.Lock = field(default_factory=threading.Lock)
    last_used: float = field(default_factory=time.monotonic)


class WorkerPool:
    """Process-local pool keyed by skill name.

    Concurrency model: one worker per name, serialised by a per-worker
    lock. The pool dictionary is guarded by `_pool_lock` so spawn / kill
    decisions don't race across threads.
    """

    def __init__(self) -> None:
        self._workers: dict[str, _Worker] = {}
        self._pool_lock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------------
    # public surface

    def invoke(
        self,
        skill: SkillSpec,
        args: list[str],
        stdin_text: str,
        env: dict[str, str],
        timeout: int,
        *,
        spawn_command: list[str] | None = None,
    ) -> CompletedProcessShape:
        """Send one call to the warm worker for `skill.name`, spawning
        one if absent."""
        self._reap_idle()
        worker = self._get_or_spawn(skill, env, spawn_command=spawn_command)
        # Per-worker serialisation: a second concurrent `invoke()` for
        # the same skill name queues behind this one. One worker per
        # name is the contract.
        with worker.lock:
            try:
                completed = self._dispatch(worker, args, stdin_text, timeout)
            except _WorkerOverflowError:
                self._kill_locked(worker)
                return CompletedProcessShape(
                    returncode=1,
                    stdout="",
                    stderr=(
                        "worker output exceeded "
                        f"CLOUD_SECURITY_MCP_WORKER_MAX_BYTES "
                        f"({_max_bytes()} bytes); worker killed"
                    ),
                    args=args,
                )
            except _WorkerCrashError as exc:
                self._kill_locked(worker)
                return CompletedProcessShape(
                    returncode=1,
                    stdout="",
                    stderr=f"worker crashed: {exc}",
                    args=args,
                )
            worker.last_used = time.monotonic()
            return completed

    def shutdown(self) -> None:
        """Kill every worker and forget them. Idempotent."""
        with self._pool_lock:
            self._closed = True
            workers = list(self._workers.values())
            self._workers.clear()
        for worker in workers:
            self._terminate(worker.process)

    # Test / introspection helpers -------------------------------------

    def _has_worker(self, name: str) -> bool:
        with self._pool_lock:
            return name in self._workers

    # ------------------------------------------------------------------
    # internals

    def _get_or_spawn(
        self,
        skill: SkillSpec,
        env: dict[str, str],
        *,
        spawn_command: list[str] | None,
    ) -> _Worker:
        with self._pool_lock:
            if self._closed:
                raise RuntimeError("worker pool is shut down")
            existing = self._workers.get(skill.name)
            if existing is not None and existing.process.poll() is None:
                return existing
            if existing is not None:
                self._workers.pop(skill.name, None)
            worker = self._spawn(skill, env, spawn_command=spawn_command)
            self._workers[skill.name] = worker
            return worker

    def _spawn(
        self,
        skill: SkillSpec,
        env: dict[str, str],
        *,
        spawn_command: list[str] | None,
    ) -> _Worker:
        if spawn_command is None:
            entrypoint = skill.entrypoint
            if entrypoint is None:
                raise ValueError(f"skill {skill.name} has no entrypoint")
            spawn_command = [sys.executable, str(entrypoint), "--worker"]
        process = subprocess.Popen(
            spawn_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(_repo_root()),
        )
        return _Worker(skill_name=skill.name, process=process)

    def _dispatch(
        self,
        worker: _Worker,
        args: list[str],
        stdin_text: str,
        timeout: int,
    ) -> CompletedProcessShape:
        process = worker.process
        if process.poll() is not None or process.stdin is None or process.stdout is None:
            raise _WorkerCrashError(
                f"worker for {worker.skill_name} not running (exit={process.returncode})"
            )
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "args": args,
                "input": stdin_text,
                "timeout_seconds": timeout,
            },
        }
        try:
            _write_framed(process.stdin, request)
        except (BrokenPipeError, OSError) as exc:
            raise _WorkerCrashError(str(exc)) from exc

        max_bytes = _max_bytes()
        # Read the framed reply. We deliberately do NOT use a thread to
        # enforce wall-clock here — RLIMIT_CPU on the worker plus the
        # outer wrapper's `subprocess.run` timeout handle that on the
        # one-shot path. The worker is expected to honour `timeout`
        # internally; if it stalls, the operator's existing timeout
        # signal (SIGTERM / pool shutdown / idle reap) cleans it up.
        payload, overflow = _read_framed(process.stdout, max_bytes)
        if overflow:
            raise _WorkerOverflowError()
        if not payload:
            stderr_text = ""
            if process.stderr is not None:
                try:
                    stderr_text = process.stderr.read(8192).decode("utf-8", errors="replace")
                except Exception:  # pragma: no cover - best-effort drain
                    stderr_text = ""
            raise _WorkerCrashError(stderr_text or "worker closed stdout")

        if len(payload) > max_bytes:
            raise _WorkerOverflowError()

        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _WorkerCrashError(f"worker reply not JSON: {exc}") from exc

        result = decoded.get("result") if isinstance(decoded, dict) else None
        if not isinstance(result, dict):
            err = decoded.get("error") if isinstance(decoded, dict) else None
            message = ""
            if isinstance(err, dict):
                message = str(err.get("message", ""))
            return CompletedProcessShape(
                returncode=1,
                stdout="",
                stderr=message or "worker returned malformed reply",
                args=args,
            )

        stdout = str(result.get("stdout", ""))
        stderr = str(result.get("stderr", ""))
        returncode = int(result.get("exit_code", 0))
        if len(stdout.encode("utf-8")) > max_bytes:
            raise _WorkerOverflowError()
        return CompletedProcessShape(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            args=args,
        )

    def _reap_idle(self) -> None:
        ttl = _idle_seconds()
        now = time.monotonic()
        stale: list[_Worker] = []
        with self._pool_lock:
            for name, worker in list(self._workers.items()):
                if now - worker.last_used > ttl or worker.process.poll() is not None:
                    stale.append(worker)
                    self._workers.pop(name, None)
        for worker in stale:
            self._terminate(worker.process)

    def _kill_locked(self, worker: _Worker) -> None:
        with self._pool_lock:
            current = self._workers.get(worker.skill_name)
            if current is worker:
                self._workers.pop(worker.skill_name, None)
        self._terminate(worker.process)

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
        except Exception:  # pragma: no cover - already gone
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except Exception:  # pragma: no cover - already gone
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:  # pragma: no cover - kernel slow
                pass


class _WorkerOverflowError(Exception):
    """Raised when a worker exceeded `CLOUD_SECURITY_MCP_WORKER_MAX_BYTES`."""


class _WorkerCrashError(Exception):
    """Raised when a worker process exited or closed its pipes mid-call."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


# Module-level singleton + atexit cleanup. The cleanup runs on normal
# interpreter shutdown so we don't leak warmed Python interpreters
# after the wrapper exits.
pool = WorkerPool()


def _atexit_shutdown() -> None:  # pragma: no cover - exercised via atexit
    pool.shutdown()


atexit.register(_atexit_shutdown)
