"""Request authentication for the webhook receiver.

Two layers, either or both can be required:

1. **HMAC-SHA-256** of the raw request body, keyed per skill via
   `WEBHOOK_HMAC_SECRETS` (JSON object). The signature header is
   configurable (`WEBHOOK_HMAC_HEADER`, default `X-Hub-Signature-256`)
   and accepts either `sha256=<hex>` or bare hex.
2. **Bearer token** for internal webhooks where the upstream cannot
   sign. Configured via `WEBHOOK_BEARER_TOKEN`.

The verifier is body-first: an invalid signature is rejected before the
skill subprocess is spawned, and the audit record still fires with
`result: error` so post-hoc reviewers see the rejected attempt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    reason: str = ""


def _const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _hmac_secrets(env: dict[str, str] | None = None) -> dict[str, str]:
    src = os.environ if env is None else env
    raw = (src.get("WEBHOOK_HMAC_SECRETS") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items() if isinstance(v, str)}


def _hmac_header_name(env: dict[str, str] | None = None) -> str:
    src = os.environ if env is None else env
    name = (src.get("WEBHOOK_HMAC_HEADER") or "").strip()
    return name or "X-Hub-Signature-256"


def _normalised_signature(value: str) -> str:
    """Accept `sha256=<hex>` or bare `<hex>` so the receiver works with
    GitHub-style and bare-hex sigs without per-vendor branches."""
    cleaned = value.strip()
    if cleaned.lower().startswith("sha256="):
        cleaned = cleaned.split("=", 1)[1].strip()
    return cleaned.lower()


def _expected_signature(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_hmac(
    skill_name: str,
    headers: dict[str, str],
    body: bytes,
    *,
    env: dict[str, str] | None = None,
) -> AuthResult:
    """Verify the HMAC signature for one webhook request. Returns ok=True
    when no secret is configured for the skill (signature is optional)."""
    secrets = _hmac_secrets(env)
    secret = secrets.get(skill_name)
    if secret is None:
        # No per-skill secret configured -> HMAC layer is opt-in. The bearer
        # layer is the alternative authenticator.
        return AuthResult(ok=True)
    header_name = _hmac_header_name(env).lower()
    # Header lookup is case-insensitive (FastAPI lowercases by default).
    raw_sig = headers.get(header_name) or headers.get(_hmac_header_name(env))
    if not raw_sig:
        return AuthResult(ok=False, reason="missing_signature")
    presented = _normalised_signature(raw_sig)
    expected = _expected_signature(secret, body)
    if not _const_eq(presented, expected):
        return AuthResult(ok=False, reason="signature_invalid")
    return AuthResult(ok=True)


def verify_bearer(headers: dict[str, str], *, env: dict[str, str] | None = None) -> AuthResult:
    """Verify the bearer token, if one is configured."""
    src = os.environ if env is None else env
    expected = (src.get("WEBHOOK_BEARER_TOKEN") or "").strip()
    if not expected:
        return AuthResult(ok=True)
    raw = headers.get("authorization") or headers.get("Authorization") or ""
    if not raw.lower().startswith("bearer "):
        return AuthResult(ok=False, reason="missing_bearer")
    token = raw.split(" ", 1)[1].strip()
    if not _const_eq(token, expected):
        return AuthResult(ok=False, reason="bearer_invalid")
    return AuthResult(ok=True)
