"""Tests for the bearer-key rotation contract (slice 2 of #415).

The contract that has to hold across every code path here:

- File source loads at boot and emits a `bearer_key_rotated` record
  with `reason="boot"`.
- SIGHUP reload re-reads the file and emits a `bearer_key_rotated`
  record with `reason="sighup"`. Added / removed kids surface in the
  audit.
- Overlap window: while two keys overlap, BOTH bearer secrets must
  authenticate. After the old key's `expires` ticks past, only the
  new key works.
- Refusal: a configured file path that resolves to zero usable keys
  is fatal (`EmptyKeyStoreError`). The transport upgrades that into a
  `SystemExit(2)`.
- Audit privacy: only `kid` values appear in the rotation record;
  `secret` never does.
- Env fallback (slice-1 contract) still works when the file env is
  unset, and emits no rotation audit (legacy contract).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
KEY_ROTATION_PATH = REPO_ROOT / "mcp-server" / "src" / "transports" / "key_rotation.py"
SSE_TRANSPORT_PATH = REPO_ROOT / "mcp-server" / "src" / "transports" / "sse.py"
SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
DISPATCH_PATH = REPO_ROOT / "mcp-server" / "src" / "dispatch.py"

# sse-starlette + starlette are gated by the `mcp-sse` extra; the SSE
# integration tests below need them. The pure-unit tests on `KeyStore`
# do not.
sse_starlette = pytest.importorskip("sse_starlette")
starlette = pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

SRC_DIR = str(SERVER_PATH.parent)
TRANSPORTS_DIR = str(KEY_ROTATION_PATH.parent)
for path in (SRC_DIR, TRANSPORTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load_or_reuse(name: str, file_path: Path):
    """Reuse the cached module if `test_sse_transport.py` already loaded it.

    Both test files manipulate `sys.modules['server']` etc. — if we
    `spec_from_file_location` a second copy here, the audit sink ends
    up split across two server modules and the existing concurrency
    tests start seeing spurious genesis prev_hash records.
    """
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, file_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SERVER = _load_or_reuse("server", SERVER_PATH)
DISPATCH = _load_or_reuse("dispatch", DISPATCH_PATH)
KEY_ROTATION = _load_or_reuse("key_rotation", KEY_ROTATION_PATH)
# The transport module under its canonical key — same module name that
# `test_sse_transport.py` uses, so we share state with it.
TRANSPORT = _load_or_reuse("cloud_security_sse_test", SSE_TRANSPORT_PATH)


def _write_keys_file(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps(entries), encoding="utf-8")


def _iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# 1) Pure-unit tests on `KeyStore` (no transport, no Starlette)
# ---------------------------------------------------------------------------


class TestKeyStoreFileLoad:
    def test_loads_from_file_and_emits_boot_audit(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(
            keys_path,
            [
                {"kid": "k1", "secret": "secret-one", "issued": "2026-01-01T00:00:00Z"},
                {"kid": "k2", "secret": "secret-two", "issued": "2026-02-01T00:00:00Z"},
            ],
        )
        emitted: list[dict] = []
        store = KEY_ROTATION.KeyStore(
            env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            emit_audit=emitted.append,
        )
        assert store.has_keys()
        assert sorted(store.active_kids()) == ["k1", "k2"]
        assert store.verify_token("secret-one")
        assert store.verify_token("secret-two")
        assert not store.verify_token("not-a-key")
        assert len(emitted) == 1
        record = emitted[0]
        assert record["event"] == "bearer_key_rotated"
        assert record["transport"] == "sse"
        assert record["reason"] == "boot"
        assert record["source"] == "file"
        assert record["kids_added"] == ["k1", "k2"]
        assert record["kids_removed"] == []
        assert record["kids_active"] == ["k1", "k2"]
        # Privacy: secrets are never in the audit record.
        serialized = json.dumps(record)
        assert "secret-one" not in serialized
        assert "secret-two" not in serialized

    def test_refuses_empty_file(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(keys_path, [])
        with pytest.raises(KEY_ROTATION.EmptyKeyStoreError):
            KEY_ROTATION.KeyStore(
                env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            )

    def test_refuses_all_expired(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(
            keys_path,
            [
                {"kid": "k1", "secret": "old", "expires": "2024-01-01T00:00:00Z"},
            ],
        )
        with pytest.raises(KEY_ROTATION.EmptyKeyStoreError):
            KEY_ROTATION.KeyStore(
                env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            )

    def test_rejects_malformed_file(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        keys_path.write_text("not-json", encoding="utf-8")
        with pytest.raises(ValueError):
            KEY_ROTATION.KeyStore(
                env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            )

    def test_rejects_missing_kid(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(keys_path, [{"secret": "x"}])
        with pytest.raises(ValueError, match="missing non-empty `kid`"):
            KEY_ROTATION.KeyStore(
                env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            )

    def test_rejects_duplicate_kid(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(
            keys_path,
            [
                {"kid": "k1", "secret": "a"},
                {"kid": "k1", "secret": "b"},
            ],
        )
        with pytest.raises(ValueError, match="duplicate kid"):
            KEY_ROTATION.KeyStore(
                env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            )


class TestKeyStoreEnvFallback:
    def test_env_fallback_when_file_unset(self):
        emitted: list[dict] = []
        store = KEY_ROTATION.KeyStore(
            env={"MCP_SSE_BEARER_KEYS": "k1,k2"},
            emit_audit=emitted.append,
        )
        assert store.has_keys()
        assert store.verify_token("k1")
        assert store.verify_token("k2")
        # Env-fallback is the legacy contract — no rotation audit on boot.
        assert emitted == []
        assert store.source == "env"

    def test_unset_env_yields_empty_store(self):
        store = KEY_ROTATION.KeyStore(env={})
        assert not store.has_keys()
        assert not store.verify_token("anything")

    def test_file_takes_precedence_over_env(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(keys_path, [{"kid": "k1", "secret": "from-file"}])
        store = KEY_ROTATION.KeyStore(
            env={
                "MCP_SSE_BEARER_KEYS_FILE": str(keys_path),
                "MCP_SSE_BEARER_KEYS": "from-env",
            },
        )
        assert store.verify_token("from-file")
        assert not store.verify_token("from-env")


class TestKeyStoreOverlap:
    def test_old_and_new_both_valid_until_old_expires(self, tmp_path):
        """Rotation overlap: cut a new key, deploy, retire old later."""
        keys_path = tmp_path / "keys.json"
        clock_now = datetime(2026, 5, 10, tzinfo=timezone.utc)
        old_expires = clock_now + timedelta(hours=1)
        _write_keys_file(
            keys_path,
            [
                {"kid": "old", "secret": "old-secret", "expires": _iso(old_expires)},
                {"kid": "new", "secret": "new-secret"},
            ],
        )
        # Stage 1: both keys valid (now is before old.expires).
        emitted: list[dict] = []
        store = KEY_ROTATION.KeyStore(
            env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            emit_audit=emitted.append,
            clock=lambda: clock_now,
        )
        assert store.verify_token("old-secret")
        assert store.verify_token("new-secret")

        # Stage 2: time advances past `expires`. Old becomes invalid;
        # new still works.
        future = clock_now + timedelta(hours=2)
        store_after = KEY_ROTATION.KeyStore(
            env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            emit_audit=[].append,
            clock=lambda: future,
        )
        assert not store_after.verify_token("old-secret")
        assert store_after.verify_token("new-secret")
        assert store_after.active_kids() == ["new"]


class TestKeyStoreReload:
    def test_sighup_handler_reloads_and_emits_audit(self, tmp_path, monkeypatch):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(keys_path, [{"kid": "k1", "secret": "v1"}])
        emitted: list[dict] = []
        store = KEY_ROTATION.KeyStore(
            env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            emit_audit=emitted.append,
        )
        # Boot record is record #0.
        assert len(emitted) == 1
        assert emitted[0]["reason"] == "boot"

        # Cut a new key, retire the old one.
        _write_keys_file(keys_path, [{"kid": "k2", "secret": "v2"}])
        store.reload_now()

        assert len(emitted) == 2
        rotated = emitted[1]
        assert rotated["reason"] == "manual"
        assert rotated["kids_added"] == ["k2"]
        assert rotated["kids_removed"] == ["k1"]
        assert rotated["kids_active"] == ["k2"]

        assert store.verify_token("v2")
        assert not store.verify_token("v1")

    def test_sighup_failure_keeps_previous_keys(self, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(keys_path, [{"kid": "k1", "secret": "v1"}])
        emitted: list[dict] = []
        store = KEY_ROTATION.KeyStore(
            env={"MCP_SSE_BEARER_KEYS_FILE": str(keys_path)},
            emit_audit=emitted.append,
        )
        # Make the file unreadable (truncate to invalid JSON).
        keys_path.write_text("garbage", encoding="utf-8")
        # _on_sighup must not raise; previous keys must still work.
        store._on_sighup(1, None)
        assert store.verify_token("v1")
        assert store.active_kids() == ["k1"]


# ---------------------------------------------------------------------------
# 2) End-to-end: SSE transport accepts both old + new bearers during overlap.
# ---------------------------------------------------------------------------


class TestSseTransportRotation:
    def _build_app(self, monkeypatch, tmp_path, *, keys: list[dict]):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(keys_path, keys)
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("MCP_SSE_BEARER_KEYS_FILE", str(keys_path))
        monkeypatch.delenv("MCP_SSE_BEARER_KEYS", raising=False)
        monkeypatch.delenv("MCP_SSE_ALLOW_PUBLIC_BIND", raising=False)
        monkeypatch.setenv("CLOUD_SECURITY_MCP_AUDIT_LOG", str(log_path))
        monkeypatch.setenv("CLOUD_SECURITY_AUDIT_HMAC_KEY", "rot-chain-key")
        SERVER._reset_audit_sink_for_tests()
        app = TRANSPORT.create_app(bind="127.0.0.1")
        return app, log_path

    def test_overlap_accepts_both_secrets(self, monkeypatch, tmp_path):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        app, log_path = self._build_app(
            monkeypatch,
            tmp_path,
            keys=[
                {"kid": "old", "secret": "secret-old", "expires": future},
                {"kid": "new", "secret": "secret-new"},
            ],
        )
        with TestClient(app) as client:
            for token in ("secret-old", "secret-new"):
                response = client.post(
                    "/rpc",
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert response.status_code == 200, token
            # Wrong key still 401s.
            response = client.post(
                "/rpc",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Authorization": "Bearer wrong"},
            )
            assert response.status_code == 401

        # The boot rotation record landed in the shared audit log,
        # chained with the same HMAC key as the tool-call records.
        records = [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        rotation_records = [r for r in records if r.get("event") == "bearer_key_rotated"]
        assert len(rotation_records) == 1
        rec = rotation_records[0]
        assert rec["transport"] == "sse"
        assert sorted(rec["kids_active"]) == ["new", "old"]
        assert "secret-old" not in json.dumps(rec)
        assert "secret-new" not in json.dumps(rec)
        # Chain fields present (annotated by AuditSink).
        assert "prev_hash" in rec
        assert "chain_hash" in rec

    def test_empty_file_blocks_create_app(self, monkeypatch, tmp_path):
        keys_path = tmp_path / "keys.json"
        _write_keys_file(keys_path, [])
        monkeypatch.setenv("MCP_SSE_BEARER_KEYS_FILE", str(keys_path))
        monkeypatch.delenv("MCP_SSE_BEARER_KEYS", raising=False)
        monkeypatch.delenv("MCP_SSE_ALLOW_PUBLIC_BIND", raising=False)
        SERVER._reset_audit_sink_for_tests()
        with pytest.raises(SystemExit) as excinfo:
            TRANSPORT.create_app(bind="127.0.0.1")
        assert excinfo.value.code == 2
