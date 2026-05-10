"""Tests for `skills/_shared/errors.py`."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ERR_PATH = REPO_ROOT / "skills" / "_shared" / "errors.py"
spec = importlib.util.spec_from_file_location("cs_errors_test", ERR_PATH)
assert spec and spec.loader
ERR = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ERR
spec.loader.exec_module(ERR)


def test_skill_error_classes_have_distinct_buckets():
    assert ERR.ConfigError.error_class == "config"
    assert ERR.AuthError.error_class == "auth"
    assert ERR.PermanentError.error_class == "permanent"
    assert ERR.TransientError.error_class == "transient"
    assert ERR.ContractError.error_class == "contract"


def test_only_transient_is_retryable():
    assert ERR.TransientError("x").retryable is True
    for cls in (ERR.ConfigError, ERR.AuthError, ERR.PermanentError, ERR.ContractError):
        assert cls("x").retryable is False


def test_emit_error_writes_envelope_to_stdout_and_stderr(monkeypatch):
    monkeypatch.setenv("SKILL_CORRELATION_ID", "corr-abc")
    out, err = io.StringIO(), io.StringIO()
    code = ERR.emit_error(
        "detect-x",
        ERR.PermanentError("not found", redacted="resource missing", hint="check the region"),
        stdout=out,
        stderr=err,
    )
    assert code == 1
    parsed = json.loads(out.getvalue())
    assert parsed["event"] == "skill_error"
    assert parsed["skill"] == "detect-x"
    assert parsed["error_class"] == "permanent"
    assert parsed["error_type"] == "PermanentError"
    assert parsed["retryable"] is False
    assert parsed["message"] == "resource missing"
    assert parsed["hint"] == "check the region"
    assert parsed["correlation_id"] == "corr-abc"
    # stderr gets a copy.
    assert err.getvalue() == out.getvalue()


def test_transient_error_returns_ex_tempfail(monkeypatch):
    out, err = io.StringIO(), io.StringIO()
    code = ERR.emit_error("detect-x", ERR.TransientError("rate limit"), stdout=out, stderr=err)
    assert code == 75


def test_auth_error_returns_2(monkeypatch):
    out, err = io.StringIO(), io.StringIO()
    code = ERR.emit_error("detect-x", ERR.AuthError("403"), stdout=out, stderr=err)
    assert code == 2


def test_unknown_exception_marked_unhandled(monkeypatch):
    monkeypatch.delenv("SKILL_CORRELATION_ID", raising=False)
    out, err = io.StringIO(), io.StringIO()
    code = ERR.emit_error("detect-x", ValueError("oops"), stdout=out, stderr=err)
    assert code == 1
    parsed = json.loads(out.getvalue())
    assert parsed["error_class"] == "unhandled"
    assert parsed["error_type"] == "ValueError"
    assert parsed["correlation_id"] == ""


def test_extra_keys_round_trip(monkeypatch):
    out, err = io.StringIO(), io.StringIO()
    ERR.emit_error(
        "detect-x",
        ERR.ConfigError("missing env"),
        stdout=out,
        stderr=err,
        extra={"region": "us-east-1", "account_id": "123456789012"},
    )
    parsed = json.loads(out.getvalue())
    assert parsed["region"] == "us-east-1"
    assert parsed["account_id"] == "123456789012"


def test_extra_collision_with_reserved_keys_raises():
    out, err = io.StringIO(), io.StringIO()
    import pytest

    with pytest.raises(ValueError):
        ERR.emit_error(
            "detect-x",
            ERR.ConfigError("x"),
            stdout=out,
            stderr=err,
            extra={"skill": "spoofed"},
        )
