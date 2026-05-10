"""Tests for `sandbox.py` — the opt-in OS-level sandbox wrapper.

These tests don't actually exec sandboxed subprocesses. We
monkeypatch `shutil.which`, `sys.platform`, and the env so the unit
tests stay fast and host-independent. The real bwrap / sandbox-exec
invocations get exercised by the operator hands-on smoke (and by
release pipelines on the supported platforms).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SB_PATH = REPO_ROOT / "mcp-server" / "src" / "sandbox.py"
spec = importlib.util.spec_from_file_location("cloud_security_sandbox_test", SB_PATH)
assert spec and spec.loader
SB = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = SB
spec.loader.exec_module(SB)


class _FakeSkill:
    """Stand-in for `SkillSpec`; only the fields sandbox.py reads."""

    def __init__(self, name: str = "fake-skill", network_egress: tuple[str, ...] = ()):
        self.name = name
        self.network_egress = network_egress


@pytest.fixture(autouse=True)
def _clear_warning_cache():
    SB._FALLBACK_WARNED.clear()
    yield
    SB._FALLBACK_WARNED.clear()


# ── is_enabled() truthy parsing ─────────────────────────────────────


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "YES", "on", "On"])
def test_is_enabled_truthy(monkeypatch, value):
    monkeypatch.setenv(SB.SANDBOX_ENV, value)
    assert SB.is_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_is_enabled_falsy(monkeypatch, value):
    monkeypatch.setenv(SB.SANDBOX_ENV, value)
    assert SB.is_enabled() is False


def test_is_enabled_default_off(monkeypatch):
    monkeypatch.delenv(SB.SANDBOX_ENV, raising=False)
    assert SB.is_enabled() is False


def test_is_enabled_accepts_explicit_env_dict():
    assert SB.is_enabled({SB.SANDBOX_ENV: "yes"}) is True
    assert SB.is_enabled({SB.SANDBOX_ENV: "no"}) is False
    assert SB.is_enabled({}) is False


# ── wrap_command no-op paths ────────────────────────────────────────


def test_wrap_command_returns_input_when_disabled(monkeypatch):
    monkeypatch.delenv(SB.SANDBOX_ENV, raising=False)
    cmd = ["python", "src/detect.py"]
    assert SB.wrap_command(cmd, _FakeSkill()) == cmd


def test_wrap_command_no_op_on_unsupported_platform(monkeypatch):
    monkeypatch.setenv(SB.SANDBOX_ENV, "on")
    monkeypatch.setattr(SB.sys, "platform", "win32")
    cmd = ["python", "src/detect.py"]
    assert SB.wrap_command(cmd, _FakeSkill()) == cmd


def test_wrap_command_no_op_when_bwrap_missing(monkeypatch, capsys):
    monkeypatch.setenv(SB.SANDBOX_ENV, "1")
    monkeypatch.setattr(SB.sys, "platform", "linux")
    monkeypatch.setattr(SB.shutil, "which", lambda _name: None)
    cmd = ["python", "src/detect.py"]
    assert SB.wrap_command(cmd, _FakeSkill()) == cmd
    captured = capsys.readouterr()
    assert "bwrap_not_installed" in captured.err


def test_wrap_command_no_op_when_sandbox_exec_missing(monkeypatch, capsys):
    monkeypatch.setenv(SB.SANDBOX_ENV, "1")
    monkeypatch.setattr(SB.sys, "platform", "darwin")
    monkeypatch.setattr(SB.shutil, "which", lambda _name: None)
    cmd = ["python", "src/detect.py"]
    assert SB.wrap_command(cmd, _FakeSkill()) == cmd
    captured = capsys.readouterr()
    assert "sandbox_exec_not_installed" in captured.err


def test_fallback_warning_emitted_once_per_reason(monkeypatch, capsys):
    monkeypatch.setenv(SB.SANDBOX_ENV, "1")
    monkeypatch.setattr(SB.sys, "platform", "linux")
    monkeypatch.setattr(SB.shutil, "which", lambda _name: None)
    SB.wrap_command(["x"], _FakeSkill())
    SB.wrap_command(["x"], _FakeSkill())
    captured = capsys.readouterr()
    assert captured.err.count("bwrap_not_installed") == 1


# ── Linux (bwrap) ───────────────────────────────────────────────────


def test_bwrap_prefix_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv(SB.SANDBOX_ENV, "1")
    monkeypatch.setattr(SB.sys, "platform", "linux")
    monkeypatch.setattr(SB.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "bwrap" else None)
    skill = _FakeSkill(network_egress=("api.example.com",))
    cmd = ["python", "skills/foo/src/detect.py"]
    wrapped = SB.wrap_command(cmd, skill, repo_root=tmp_path)
    assert wrapped[0] == "bwrap"
    # Network kept on for declared egress.
    assert "--share-net" in wrapped
    assert "--unshare-net" not in wrapped
    # Original command lives after the `--` terminator.
    assert wrapped[-len(cmd):] == cmd
    assert wrapped[-len(cmd) - 1] == "--"
    # Repo binding present.
    assert "--bind" in wrapped
    assert str(tmp_path) in wrapped


def test_bwrap_unshare_net_when_egress_empty(monkeypatch, tmp_path):
    monkeypatch.setenv(SB.SANDBOX_ENV, "on")
    monkeypatch.setattr(SB.sys, "platform", "linux")
    monkeypatch.setattr(SB.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "bwrap" else None)
    skill = _FakeSkill(network_egress=())
    wrapped = SB.wrap_command(["python", "src/x.py"], skill, repo_root=tmp_path)
    assert "--unshare-net" in wrapped
    assert "--share-net" not in wrapped


# ── macOS (sandbox-exec) ────────────────────────────────────────────


def test_sandbox_exec_prefix_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv(SB.SANDBOX_ENV, "yes")
    monkeypatch.setattr(SB.sys, "platform", "darwin")
    monkeypatch.setattr(
        SB.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name == "sandbox-exec" else None,
    )
    skill = _FakeSkill(network_egress=("login.microsoftonline.com",))
    cmd = ["python", "skills/foo/src/detect.py"]
    wrapped = SB.wrap_command(cmd, skill, repo_root=tmp_path)
    assert wrapped[0] == "sandbox-exec"
    assert wrapped[1] == "-f"
    profile_path = Path(wrapped[2])
    assert profile_path.exists()
    profile = profile_path.read_text(encoding="utf-8")
    assert "(deny default)" in profile
    assert "(allow network*)" in profile
    assert "(deny network*)" not in profile
    assert str(tmp_path) in profile
    assert wrapped[3:] == cmd
    profile_path.unlink()


def test_sandbox_exec_denies_network_when_egress_empty(monkeypatch, tmp_path):
    monkeypatch.setenv(SB.SANDBOX_ENV, "on")
    monkeypatch.setattr(SB.sys, "platform", "darwin")
    monkeypatch.setattr(
        SB.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name == "sandbox-exec" else None,
    )
    skill = _FakeSkill(network_egress=())
    wrapped = SB.wrap_command(["python", "src/x.py"], skill, repo_root=tmp_path)
    profile_path = Path(wrapped[2])
    profile = profile_path.read_text(encoding="utf-8")
    assert "(deny network*)" in profile
    assert "(allow network*)" not in profile
    profile_path.unlink()
