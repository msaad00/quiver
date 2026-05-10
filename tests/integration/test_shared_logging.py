"""Tests for `skills/_shared/logging.py`."""

from __future__ import annotations

import importlib.util
import io
import json
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_PATH = REPO_ROOT / "skills" / "_shared" / "logging.py"
spec = importlib.util.spec_from_file_location("cs_logging_test", LOG_PATH)
assert spec and spec.loader
SH_LOG = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = SH_LOG
spec.loader.exec_module(SH_LOG)


def _attach_capture(logger_name: str) -> io.StringIO:
    """Replace the module's stderr handler with a StringIO so we can read
    the JSON output."""
    sink = io.StringIO()
    logger = logging.getLogger(logger_name)
    # Drop any existing handlers from a previous test run.
    logger.handlers.clear()
    handler = logging.StreamHandler(sink)
    handler.setFormatter(SH_LOG._JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return sink


def test_log_record_is_single_line_json(monkeypatch):
    sink = _attach_capture("cs_log_test_1")
    log = SH_LOG.get_logger(
        "cs_log_test_1",
        skill="detect-x",
        layer="detection",
    )
    log.info("hello world", extra={"batch_size": 100})
    line = sink.getvalue().strip()
    assert "\n" not in line, "log record must be one line"
    parsed = json.loads(line)
    assert parsed["message"] == "hello world"
    assert parsed["level"] == "info"
    assert parsed["skill"] == "detect-x"
    assert parsed["layer"] == "detection"
    assert parsed["batch_size"] == 100


def test_correlation_id_is_stamped_from_env(monkeypatch):
    monkeypatch.setenv("SKILL_CORRELATION_ID", "corr-zzz")
    sink = _attach_capture("cs_log_test_2")
    log = SH_LOG.get_logger("cs_log_test_2", skill="detect-x", layer="detection")
    log.warning("rate limited")
    parsed = json.loads(sink.getvalue().strip())
    assert parsed["correlation_id"] == "corr-zzz"


def test_correlation_id_omitted_when_env_unset(monkeypatch):
    monkeypatch.delenv("SKILL_CORRELATION_ID", raising=False)
    sink = _attach_capture("cs_log_test_3")
    log = SH_LOG.get_logger("cs_log_test_3", skill="detect-x", layer="detection")
    log.info("no correlation")
    parsed = json.loads(sink.getvalue().strip())
    assert "correlation_id" not in parsed


def test_unserialisable_extras_are_repr_d(monkeypatch):
    sink = _attach_capture("cs_log_test_4")
    log = SH_LOG.get_logger("cs_log_test_4", skill="detect-x", layer="detection")

    class _Unserialisable:
        def __repr__(self) -> str:
            return "<Unserialisable>"

    log.info("test", extra={"obj": _Unserialisable()})
    parsed = json.loads(sink.getvalue().strip())
    assert parsed["obj"] == "<Unserialisable>"


def test_exc_info_is_captured_as_string(monkeypatch):
    sink = _attach_capture("cs_log_test_5")
    log = SH_LOG.get_logger("cs_log_test_5", skill="detect-x", layer="detection")
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        log.exception("failed")
    parsed = json.loads(sink.getvalue().strip())
    assert "RuntimeError: boom" in parsed["exc_info"]


def test_logger_does_not_propagate_to_root(monkeypatch):
    """Skills run inside the wrapper which catches stderr — the logger
    must not double-emit through the root logger handler chain."""
    sink = _attach_capture("cs_log_test_6")
    log = SH_LOG.get_logger("cs_log_test_6", skill="detect-x", layer="detection")
    log.info("once")
    assert sink.getvalue().count("\n") == 1
