"""Tests for `runners/webhook-receiver/src/router.py`."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = REPO_ROOT / "runners" / "webhook-receiver" / "src" / "router.py"
spec = importlib.util.spec_from_file_location("webhook_router_test", SRC)
assert spec and spec.loader
ROUTER = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ROUTER
spec.loader.exec_module(ROUTER)


def test_unknown_skill_is_not_found(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    result = ROUTER.resolve("does-not-exist")
    assert result.found is False
    assert result.allowed is False
    assert "unknown" in result.reason


def test_known_ingest_skill_not_in_allowlist_is_denied(monkeypatch):
    """Default-deny: even if the skill ships, the receiver refuses to
    route it until the operator opts it in."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "")
    result = ROUTER.resolve("ingest-cloudtrail-ocsf")
    assert result.found is True
    assert result.allowed is False
    assert "WEBHOOK_ALLOWED_SKILLS" in result.reason


def test_allowlisted_ingest_skill_is_allowed(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    result = ROUTER.resolve("ingest-cloudtrail-ocsf")
    assert result.found is True
    assert result.allowed is True
    assert result.skill is not None
    assert result.skill.category == "ingestion"


def test_detection_skill_is_refused(monkeypatch):
    """Detect / remediate / evaluate are not routable on the webhook
    surface — they consume OCSF, not raw payloads, or carry HITL gates
    the receiver cannot honour."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "detect-okta-mfa-fatigue")
    result = ROUTER.resolve("detect-okta-mfa-fatigue")
    assert result.found is True
    assert result.allowed is False
    assert "ingestion" in result.reason


def test_remediation_skill_is_refused(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "remediate-mcp-tool-quarantine")
    result = ROUTER.resolve("remediate-mcp-tool-quarantine")
    assert result.found is True
    assert result.allowed is False
    assert "ingestion" in result.reason
