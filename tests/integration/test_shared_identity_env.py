from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared import env, identity  # noqa: E402


def test_vendor_name_default_matches_constant():
    assert identity.vendor_name() == identity.DEFAULT_VENDOR_NAME
    assert identity.VENDOR_NAME == identity.DEFAULT_VENDOR_NAME


def test_vendor_name_env_override(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_VENDOR_NAME", "acmecorp/internal-fork")
    assert identity.vendor_name() == "acmecorp/internal-fork"


def test_vendor_name_blank_override_falls_back(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_VENDOR_NAME", "   ")
    assert identity.vendor_name() == identity.DEFAULT_VENDOR_NAME


def test_product_and_information_uri_overrides(monkeypatch):
    monkeypatch.setenv("CLOUD_SECURITY_PRODUCT_NAME", "acme-detections")
    monkeypatch.setenv("CLOUD_SECURITY_INFORMATION_URI", "https://acme.example/sec")
    assert identity.product_name() == "acme-detections"
    assert identity.information_uri() == "https://acme.example/sec"


def test_env_int_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv("WIDGET_THRESHOLD", raising=False)
    assert env.env_int("WIDGET_THRESHOLD", 7, skill_name="test-skill") == 7


def test_env_int_parses_valid(monkeypatch):
    monkeypatch.setenv("WIDGET_THRESHOLD", "42")
    assert env.env_int("WIDGET_THRESHOLD", 7, skill_name="test-skill") == 42


def test_env_int_warns_on_parse_failure(monkeypatch, capsys):
    monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
    monkeypatch.setenv("WIDGET_THRESHOLD", "seven")
    monkeypatch.delenv("CLOUD_SECURITY_STRICT_ENV", raising=False)

    result = env.env_int("WIDGET_THRESHOLD", 7, skill_name="test-skill")
    assert result == 7

    err = capsys.readouterr().err.strip().splitlines()
    assert err, "expected stderr telemetry on parse failure"
    payload = json.loads(err[-1])
    assert payload["event"] == "env_parse_failed"
    assert payload["env"] == "WIDGET_THRESHOLD"
    assert payload["raw"] == "seven"
    assert payload["default"] == 7


def test_env_int_strict_mode_raises(monkeypatch):
    monkeypatch.setenv("WIDGET_THRESHOLD", "seven")
    monkeypatch.setenv("CLOUD_SECURITY_STRICT_ENV", "1")
    try:
        env.env_int("WIDGET_THRESHOLD", 7, skill_name="test-skill")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError under strict mode")


def test_env_float_parses_and_warns(monkeypatch, capsys):
    monkeypatch.setenv("RATIO", "0.25")
    assert env.env_float("RATIO", 0.5, skill_name="test-skill") == 0.25

    monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
    monkeypatch.setenv("RATIO", "half")
    monkeypatch.delenv("CLOUD_SECURITY_STRICT_ENV", raising=False)
    assert env.env_float("RATIO", 0.5, skill_name="test-skill") == 0.5
    payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert payload["event"] == "env_parse_failed"


def test_module_constants_resolve_at_import_time():
    importlib.reload(identity)
    assert identity.VENDOR_NAME == identity.DEFAULT_VENDOR_NAME
    assert identity.PRODUCT_NAME == identity.DEFAULT_PRODUCT_NAME
