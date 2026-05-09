"""End-to-end tests for the FastAPI receiver. Skipped when fastapi /
httpx are not available — they are an opt-in extra."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVER_PATH = REPO_ROOT / "runners" / "webhook-receiver" / "src" / "server.py"
spec = importlib.util.spec_from_file_location("webhook_server_test", SERVER_PATH)
assert spec and spec.loader


def _load_server(monkeypatch):
    """Reload the server module so test env vars take effect."""
    if "webhook_server_test" in sys.modules:
        del sys.modules["webhook_server_test"]
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _hex_hmac(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def test_healthz_returns_ok(monkeypatch):
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "webhook-receiver"}


def test_unknown_skill_returns_404(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post("/webhook/this-skill-does-not-exist", content=b"{}")
    assert resp.status_code == 404


def test_known_skill_outside_allowlist_returns_403(monkeypatch):
    """Default-deny — the skill ships but the operator has not opted it in."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}")
    assert resp.status_code == 403


def test_remediation_skill_is_refused_even_if_allowlisted(monkeypatch):
    """Receiver refuses non-ingestion categories regardless of allowlist."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "remediate-mcp-tool-quarantine")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post("/webhook/remediate-mcp-tool-quarantine", content=b"{}")
    assert resp.status_code == 403
    assert "ingestion" in resp.json()["detail"]


def test_missing_signature_returns_401(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv(
        "WEBHOOK_HMAC_SECRETS",
        json.dumps({"ingest-cloudtrail-ocsf": "secret"}),
    )
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing_signature"


def test_invalid_signature_returns_401(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv(
        "WEBHOOK_HMAC_SECRETS",
        json.dumps({"ingest-cloudtrail-ocsf": "secret"}),
    )
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=b"{}",
        headers={"X-Hub-Signature-256": "sha256=" + ("0" * 64)},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "signature_invalid"


def test_bearer_required_when_configured(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv("WEBHOOK_BEARER_TOKEN", "real")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)
    resp = client.post("/webhook/ingest-cloudtrail-ocsf", content=b"{}")
    # 401 for missing bearer (no HMAC configured here)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing_bearer"


def test_valid_signature_routes_to_skill(monkeypatch, tmp_path):
    """Smoke test the happy path: POST a CloudTrail-shape payload, confirm
    the receiver invokes the skill, captures stdout, and returns a 200
    with the skill_exit_code surfaced."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_SKILLS", "ingest-cloudtrail-ocsf")
    monkeypatch.setenv(
        "WEBHOOK_HMAC_SECRETS",
        json.dumps({"ingest-cloudtrail-ocsf": "secret"}),
    )
    monkeypatch.setenv("WEBHOOK_SINK_TARGETS", "")
    server = _load_server(monkeypatch)
    client = TestClient(server.app)

    body = (
        REPO_ROOT
        / "skills"
        / "detection-engineering"
        / "golden"
        / "cloudtrail_raw_sample.jsonl"
    ).read_bytes()
    sig = _hex_hmac("secret", body)
    resp = client.post(
        "/webhook/ingest-cloudtrail-ocsf",
        content=body,
        headers={
            "X-Hub-Signature-256": f"sha256={sig}",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["skill"] == "ingest-cloudtrail-ocsf"
    assert payload["skill_exit_code"] == 0
    assert payload["stdout_length"] > 0
    assert payload["sink_results"] == []  # no sinks configured
