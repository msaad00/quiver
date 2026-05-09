"""Tests for `runners/webhook-receiver/src/auth.py`."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC = REPO_ROOT / "runners" / "webhook-receiver" / "src" / "auth.py"
spec = importlib.util.spec_from_file_location("webhook_auth_test", SRC)
assert spec and spec.loader
AUTH = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = AUTH
spec.loader.exec_module(AUTH)


def _hex_hmac(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def test_hmac_passes_with_no_secret_configured():
    result = AUTH.verify_hmac("any-skill", {}, b"body", env={})
    assert result.ok is True


def test_hmac_rejects_when_secret_set_but_no_header():
    env = {"WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-x": "secret"})}
    result = AUTH.verify_hmac("ingest-x", {}, b"body", env=env)
    assert result.ok is False
    assert result.reason == "missing_signature"


def test_hmac_rejects_invalid_signature():
    env = {"WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-x": "secret"})}
    headers = {"x-hub-signature-256": "sha256=" + ("0" * 64)}
    result = AUTH.verify_hmac("ingest-x", headers, b"body", env=env)
    assert result.ok is False
    assert result.reason == "signature_invalid"


def test_hmac_accepts_sha256_prefix_signature():
    env = {"WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-x": "secret"})}
    body = b'{"evt": 1}'
    sig = _hex_hmac("secret", body)
    headers = {"x-hub-signature-256": f"sha256={sig}"}
    assert AUTH.verify_hmac("ingest-x", headers, body, env=env).ok is True


def test_hmac_accepts_bare_hex_signature():
    env = {"WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-x": "secret"})}
    body = b'{"evt": 1}'
    sig = _hex_hmac("secret", body)
    headers = {"x-hub-signature-256": sig}
    assert AUTH.verify_hmac("ingest-x", headers, body, env=env).ok is True


def test_hmac_custom_header_name():
    env = {
        "WEBHOOK_HMAC_SECRETS": json.dumps({"ingest-x": "secret"}),
        "WEBHOOK_HMAC_HEADER": "X-Vendor-Sig",
    }
    body = b'{"evt": 1}'
    sig = _hex_hmac("secret", body)
    headers = {"x-vendor-sig": sig}
    assert AUTH.verify_hmac("ingest-x", headers, body, env=env).ok is True


def test_bearer_passes_when_no_token_configured():
    assert AUTH.verify_bearer({}, env={}).ok is True


def test_bearer_rejects_missing_header():
    env = {"WEBHOOK_BEARER_TOKEN": "real"}
    result = AUTH.verify_bearer({}, env=env)
    assert result.ok is False
    assert result.reason == "missing_bearer"


def test_bearer_rejects_wrong_token():
    env = {"WEBHOOK_BEARER_TOKEN": "real"}
    headers = {"authorization": "Bearer fake"}
    result = AUTH.verify_bearer(headers, env=env)
    assert result.ok is False
    assert result.reason == "bearer_invalid"


def test_bearer_accepts_correct_token():
    env = {"WEBHOOK_BEARER_TOKEN": "real"}
    headers = {"authorization": "Bearer real"}
    assert AUTH.verify_bearer(headers, env=env).ok is True


def test_hmac_secrets_silently_ignores_malformed_json():
    """Misconfigured env should not crash the receiver; it should
    fall through to default-deny on the routing layer instead."""
    env = {"WEBHOOK_HMAC_SECRETS": "not-json"}
    result = AUTH.verify_hmac("anything", {}, b"x", env=env)
    # No secret resolved → ok=True (HMAC is opt-in per skill).
    assert result.ok is True
