"""Tests for `resource_limits.py` and the wrapper's RLIMIT enforcement.

The end-to-end path is exercised by spawning a real subprocess that
tries to allocate more memory than the cap allows, so we can prove the
kernel rejects the allocation rather than the wrapper itself dying.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RL_PATH = REPO_ROOT / "mcp-server" / "src" / "resource_limits.py"
spec = importlib.util.spec_from_file_location("cloud_security_resource_limits_test", RL_PATH)
assert spec and spec.loader
RL = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = RL
spec.loader.exec_module(RL)


def test_from_env_uses_defaults_when_unset(monkeypatch):
    for k in (
        "CLOUD_SECURITY_SKILL_MAX_BYTES",
        "CLOUD_SECURITY_SKILL_MAX_FILE_BYTES",
        "CLOUD_SECURITY_SKILL_MAX_PROCESSES",
    ):
        monkeypatch.delenv(k, raising=False)
    limits = RL.from_env(timeout_seconds=60)
    assert limits.max_bytes == RL.DEFAULT_MAX_BYTES
    assert limits.max_file_bytes == RL.DEFAULT_MAX_FILE_BYTES
    # NPROC is opt-in (RLIMIT_NPROC is per-UID; a low cap kills dev hosts).
    assert limits.max_processes == 0
    assert limits.cpu_seconds == 65  # 60 + grace


def test_from_env_overrides_apply(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_SKILL_MAX_BYTES", "536870912")  # 512 MB
    monkeypatch.setenv("CLOUD_SECURITY_SKILL_MAX_FILE_BYTES", "1048576")
    monkeypatch.setenv("CLOUD_SECURITY_SKILL_MAX_PROCESSES", "8")
    limits = RL.from_env(timeout_seconds=10)
    assert limits.max_bytes == 536_870_912
    assert limits.max_file_bytes == 1_048_576
    assert limits.max_processes == 8
    assert limits.cpu_seconds == 15


def test_from_env_ignores_garbage(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_SKILL_MAX_BYTES", "not-a-number")
    limits = RL.from_env(timeout_seconds=60)
    assert limits.max_bytes == RL.DEFAULT_MAX_BYTES


def test_apply_in_child_handles_missing_resource_module():
    """Documented Windows behaviour — `resource` import fails, helper
    silently no-ops so the wrapper still works.

    Exercised via subprocess so the limits are not applied to pytest's
    own process (RLIMIT_FSIZE on the parent would break later forks).
    """
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                f"""
                import importlib.util, sys
                # Block the `resource` import to simulate Windows.
                class _Blocker:
                    def find_spec(self, name, path=None, target=None):
                        if name == "resource":
                            raise ImportError("simulated absence")
                sys.meta_path.insert(0, _Blocker())
                spec = importlib.util.spec_from_file_location("rl", {str(RL_PATH)!r})
                mod = importlib.util.module_from_spec(spec)
                sys.modules["rl"] = mod
                spec.loader.exec_module(mod)
                limits = mod.ResourceLimits(
                    max_bytes=1024 * 1024 * 1024,
                    max_file_bytes=1024 * 1024,
                    max_processes=8,
                    cpu_seconds=10,
                )
                mod.apply_in_child(limits)  # must not raise
                print("OK")
                """
            ).strip(),
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "OK"


@pytest.mark.skipif(
    os.name != "posix" or sys.platform == "darwin",
    reason="RLIMIT_AS is enforced by the Linux kernel; macOS reports the value but does not cap virtual memory",
)
def test_rlimit_as_actually_caps_allocation(tmp_path):
    """End-to-end: spawn a subprocess that tries to allocate 256 MB with
    a 64 MB virtual-memory cap. The child must die with a non-zero exit
    code; the parent (this test) must keep running.

    This proves the cap is enforced at the kernel level, not just
    declared in the audit record.
    """
    script = tmp_path / "balloon.py"
    script.write_text(
        textwrap.dedent(
            """
            from runner_helper import apply_limits  # type: ignore[import-not-found]
            apply_limits()
            try:
                # Allocation must exceed the 384 MB cap set in apply_limits.
                bytearray(768 * 1024 * 1024)
                print("OK")
            except MemoryError:
                print("MEMORY_ERROR")
                raise SystemExit(2)
            """
        ).strip()
        + "\n"
    )
    helper = tmp_path / "runner_helper.py"
    helper.write_text(
        textwrap.dedent(
            f"""
            import importlib.util
            import sys
            spec = importlib.util.spec_from_file_location(
                "rl", {str(RL_PATH)!r}
            )
            assert spec and spec.loader
            RL = importlib.util.module_from_spec(spec)
            sys.modules["rl"] = RL
            spec.loader.exec_module(RL)
            def apply_limits():
                RL.apply_in_child(RL.ResourceLimits(
                    max_bytes=384 * 1024 * 1024,  # leave Python interpreter room to start
                    max_file_bytes=1024 * 1024,
                    max_processes=0,  # opt-in — RLIMIT_NPROC counts per-UID; leave alone in tests
                    cpu_seconds=10,
                ))
            """
        ).strip()
        + "\n"
    )
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    # The child exits 2 (our explicit raise) on MemoryError, or non-zero
    # if the kernel killed it with SIGKILL/SIGSEGV. Either way: not 0.
    assert completed.returncode != 0
    assert "OK" not in completed.stdout


@pytest.mark.skipif(os.name != "posix", reason="preexec_fn is POSIX-only")
def test_make_preexec_returns_callable():
    limits = RL.ResourceLimits(
        max_bytes=128 * 1024 * 1024,
        max_file_bytes=1024,
        max_processes=8,
        cpu_seconds=10,
    )
    fn = RL.make_preexec(limits)
    assert callable(fn)


@pytest.mark.skipif(
    os.name != "posix" or sys.platform == "darwin",
    reason="end-to-end RLIMIT_AS check requires Linux (macOS reports the value but does not enforce it)",
)
def test_subprocess_run_with_preexec_caps_child_memory(tmp_path):
    """Mirror the wrapper's call shape: `subprocess.run(...,
    preexec_fn=make_preexec(limits))`. Validates that nothing in the
    parent process changes (the parent never inherits the child's
    limits)."""
    import resource as _resource  # local import so non-POSIX collection skips above

    parent_before = _resource.getrlimit(_resource.RLIMIT_AS)
    limits = RL.ResourceLimits(
        max_bytes=128 * 1024 * 1024,
        max_file_bytes=4096,
        max_processes=0,  # opt-in; leave alone here so fork() works on dev hosts
        cpu_seconds=10,
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])",
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        preexec_fn=RL.make_preexec(limits),
    )
    assert completed.returncode == 0
    child_soft = int(completed.stdout.strip())
    assert child_soft <= 128 * 1024 * 1024

    # Parent untouched.
    assert _resource.getrlimit(_resource.RLIMIT_AS) == parent_before
