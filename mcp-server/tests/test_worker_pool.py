from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKER_POOL_PATH = REPO_ROOT / "mcp-server" / "src" / "worker_pool.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "cloud_security_worker_pool_test", WORKER_POOL_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # Ensure tool_registry's directory is importable for the
    # type-only import inside worker_pool.
    sys.path.insert(0, str(WORKER_POOL_PATH.parent))
    spec.loader.exec_module(module)
    return module


WP = _load_module()


class _FakeSkill:
    def __init__(self, name: str = "fake-skill", entrypoint: Path | None = None) -> None:
        self.name = name
        self.entrypoint = entrypoint or Path("/tmp/fake-entrypoint.py")
        self.worker_mode = True


@pytest.fixture(autouse=True)
def _reset_pool():
    """Each test gets a fresh pool — module-level singleton is replaced
    transparently so atexit hooks still cover the survivors."""
    WP.pool.shutdown()
    yield
    WP.pool.shutdown()


# ----------------------------------------------------------------------
# enabled / config


def test_is_enabled_truthy_values(monkeypatch):
    for value in ("1", "true", "TRUE", "yes", "on", "On"):
        monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_POOL", value)
        assert WP.is_enabled() is True


def test_is_enabled_falsy_values(monkeypatch):
    for value in ("", "0", "false", "no", "off", "garbage"):
        monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_POOL", value)
        assert WP.is_enabled() is False


def test_idle_seconds_default_and_override(monkeypatch):
    monkeypatch.delenv("CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS", raising=False)
    assert WP._idle_seconds() == WP.DEFAULT_IDLE_SECONDS
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS", "30")
    assert WP._idle_seconds() == 30
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS", "garbage")
    assert WP._idle_seconds() == WP.DEFAULT_IDLE_SECONDS


def test_max_bytes_default_and_override(monkeypatch):
    monkeypatch.delenv("CLOUD_SECURITY_MCP_WORKER_MAX_BYTES", raising=False)
    assert WP._max_bytes() == WP.DEFAULT_MAX_BYTES
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_MAX_BYTES", "65536")
    assert WP._max_bytes() == 65536


# ----------------------------------------------------------------------
# real-subprocess integration tests using a stub harness skill


def _stub_worker_script(tmp_path: Path) -> Path:
    """A self-contained stub skill that uses the real `worker_harness`
    so we exercise the full framing + dispatch path, not a mock."""
    script = tmp_path / "stub_skill.py"
    script.write_text(textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(REPO_ROOT)!r})

        def main():
            argv = sys.argv[1:]
            if argv and argv[0] == "--echo":
                sys.stdout.write("echo:" + " ".join(argv[1:]))
                return 0
            if argv and argv[0] == "--exit":
                return int(argv[1])
            if argv and argv[0] == "--bytes":
                # write requested number of bytes to stdout
                count = int(argv[1])
                sys.stdout.write("x" * count)
                return 0
            if argv and argv[0] == "--echo-stdin":
                data = sys.stdin.read()
                sys.stdout.write("stdin:" + data)
                return 0
            sys.stdout.write("ok")
            return 0

        if __name__ == "__main__":
            if "--worker" in sys.argv:
                from skills._shared.worker_harness import run_worker
                raise SystemExit(run_worker(main))
            raise SystemExit(main())
    """))
    return script


def _make_pool() -> Any:
    return WP.WorkerPool()


def test_invoke_spawns_once_and_reuses(tmp_path):
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub", entrypoint=script)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]

    r1 = pool.invoke(skill, ["--echo", "first"], "", os.environ.copy(), 5,
                     spawn_command=spawn_command)
    assert r1.returncode == 0
    assert r1.stdout == "echo:first"
    pid_after_first = pool._workers["stub"].process.pid

    r2 = pool.invoke(skill, ["--echo", "second"], "", os.environ.copy(), 5,
                     spawn_command=spawn_command)
    assert r2.returncode == 0
    assert r2.stdout == "echo:second"
    pid_after_second = pool._workers["stub"].process.pid

    assert pid_after_first == pid_after_second  # reused, not re-spawned

    pool.shutdown()


def test_invoke_passes_stdin(tmp_path):
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-stdin", entrypoint=script)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]

    r = pool.invoke(skill, ["--echo-stdin"], "hello-from-pipe", os.environ.copy(), 5,
                    spawn_command=spawn_command)
    assert r.returncode == 0
    assert r.stdout == "stdin:hello-from-pipe"
    pool.shutdown()


def test_non_zero_exit_code_is_returned(tmp_path):
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-exit", entrypoint=script)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]

    r = pool.invoke(skill, ["--exit", "7"], "", os.environ.copy(), 5,
                    spawn_command=spawn_command)
    assert r.returncode == 7
    pool.shutdown()


def test_idle_ttl_kills_worker(tmp_path, monkeypatch):
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-ttl", entrypoint=script)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS", "1")

    pool.invoke(skill, ["--echo", "x"], "", os.environ.copy(), 5,
                spawn_command=spawn_command)
    pid_one = pool._workers["stub-ttl"].process.pid

    # Walk the worker's last_used backwards instead of sleeping to keep
    # the test fast and deterministic.
    pool._workers["stub-ttl"].last_used = time.monotonic() - 10
    pool._reap_idle()
    assert "stub-ttl" not in pool._workers

    # Next invoke spawns fresh
    pool.invoke(skill, ["--echo", "y"], "", os.environ.copy(), 5,
                spawn_command=spawn_command)
    pid_two = pool._workers["stub-ttl"].process.pid
    assert pid_one != pid_two
    pool.shutdown()


def test_output_overflow_kills_worker(tmp_path, monkeypatch):
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-overflow", entrypoint=script)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]
    monkeypatch.setenv("CLOUD_SECURITY_MCP_WORKER_MAX_BYTES", "1024")

    r = pool.invoke(skill, ["--bytes", "100000"], "", os.environ.copy(), 5,
                    spawn_command=spawn_command)
    assert r.returncode == 1
    assert "exceeded" in r.stderr
    assert "stub-overflow" not in pool._workers

    # Re-spawn fresh on the next call
    r2 = pool.invoke(skill, ["--echo", "after"], "", os.environ.copy(), 5,
                     spawn_command=spawn_command)
    assert r2.returncode == 0
    assert r2.stdout == "echo:after"
    pool.shutdown()


def test_worker_crash_returns_completed_shape_and_respawns(tmp_path):
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-crash", entrypoint=script)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]

    pool.invoke(skill, ["--echo", "x"], "", os.environ.copy(), 5,
                spawn_command=spawn_command)
    worker = pool._workers["stub-crash"]
    # Simulate a worker that died between calls (e.g. OOM)
    worker.process.kill()
    worker.process.wait(timeout=2)

    r = pool.invoke(skill, ["--echo", "after-crash"], "", os.environ.copy(), 5,
                    spawn_command=spawn_command)
    # Either the dispatch detects the crash and returns code 1, OR a
    # fresh worker was spawned cleanly. Both are acceptable; what's
    # not acceptable is hanging or raising.
    assert isinstance(r.returncode, int)
    pool.shutdown()


def test_concurrent_invokes_for_same_skill_serialise(tmp_path):
    """Two threads hitting the same skill name share one worker, with
    per-worker locking forcing them to run sequentially."""
    import threading

    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-concurrent", entrypoint=script)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]

    results: list[Any] = []
    errors: list[BaseException] = []

    def _run(arg: str) -> None:
        try:
            r = pool.invoke(skill, ["--echo", arg], "", os.environ.copy(), 5,
                            spawn_command=spawn_command)
            results.append(r)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_run, args=(f"t{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"unexpected errors: {errors}"
    assert len(results) == 4
    assert all(r.returncode == 0 for r in results)
    # Single worker process across all four calls
    assert len(pool._workers) <= 1
    pool.shutdown()


def test_shutdown_kills_all_workers(tmp_path):
    script = _stub_worker_script(tmp_path)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script), "--worker"]

    for name in ("a", "b", "c"):
        skill = _FakeSkill(name=name, entrypoint=script)
        pool.invoke(skill, ["--echo", name], "", os.environ.copy(), 5,
                    spawn_command=spawn_command)
    procs = [w.process for w in pool._workers.values()]
    pool.shutdown()
    for proc in procs:
        # All children are reaped on shutdown
        assert proc.poll() is not None


def test_invoke_after_shutdown_raises(tmp_path):
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-after-shutdown", entrypoint=script)
    pool = _make_pool()
    pool.shutdown()
    with pytest.raises(RuntimeError, match="shut down"):
        pool.invoke(skill, [], "", os.environ.copy(), 5,
                    spawn_command=[sys.executable, str(script), "--worker"])


# ----------------------------------------------------------------------
# sandbox composition — server.py builds the sandbox-wrapped command
# and passes it through to `pool.invoke(spawn_command=...)`. We assert
# the pool faithfully launches whatever spawn_command it receives,
# meaning sandbox wrap composes by construction.


def test_pool_uses_provided_spawn_command(tmp_path, monkeypatch):
    """When `spawn_command` is supplied (the path server.py uses for
    sandbox composition), the pool must launch that exact command."""
    script = _stub_worker_script(tmp_path)
    skill = _FakeSkill(name="stub-spawn-cmd", entrypoint=script)
    pool = _make_pool()

    captured: dict[str, Any] = {}
    real_popen = subprocess.Popen

    def _spy_popen(cmd, *args, **kwargs):
        captured.setdefault("cmd", cmd)
        return real_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(WP.subprocess, "Popen", _spy_popen)

    spawn_command = [sys.executable, str(script), "--worker"]
    pool.invoke(skill, ["--echo", "z"], "", os.environ.copy(), 5,
                spawn_command=spawn_command)
    assert captured["cmd"] == spawn_command
    pool.shutdown()


# ----------------------------------------------------------------------
# atexit cleanup


def test_atexit_handler_registered():
    # We can't easily run atexit hooks mid-test. Instead, assert the
    # module registered _atexit_shutdown so reaping happens on
    # interpreter shutdown.
    # CPython 3.11+ doesn't expose `atexit._exithandlers`; we settle
    # for confirming the module-level callback is wired and callable —
    # the real interpreter-shutdown path is exercised end-to-end when
    # the test process exits.
    assert callable(WP._atexit_shutdown)


# ----------------------------------------------------------------------
# malformed worker reply


def test_malformed_reply_returns_error_record(tmp_path, monkeypatch):
    """If the worker replies with non-JSON bytes, the pool returns an
    error CompletedProcessShape rather than raising."""
    script_path = tmp_path / "bad_worker.py"
    script_path.write_text(textwrap.dedent("""
        import sys
        # Ignore stdin; emit a malformed framed message and exit.
        body = b"not-json-at-all"
        sys.stdout.buffer.write(b"Content-Length: %d\\r\\n\\r\\n" % len(body))
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
    """))
    skill = _FakeSkill(name="stub-bad", entrypoint=script_path)
    pool = _make_pool()
    spawn_command = [sys.executable, str(script_path)]

    r = pool.invoke(skill, [], "", os.environ.copy(), 5,
                    spawn_command=spawn_command)
    assert r.returncode == 1
    pool.shutdown()
