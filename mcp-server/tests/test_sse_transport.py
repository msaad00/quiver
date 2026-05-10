"""Tests for the SSE / streamable-HTTP MCP transport.

Coverage matrix:

- 401 on missing / bad Authorization header.
- Successful tool call over SSE returns the same structural payload as
  a stdio-served call for an identical request (correlation_id and
  duration are stripped — they are wrapper-generated per call).
- The audit log captures `transport="sse"` and the HMAC chain links to
  the previous stdio record (verifier replays both lines under one key).
- Public-bind refusal without keys (sys.exit + stderr rationale).
- Concurrent SSE clients do not corrupt the audit chain (3 threads
  hammer `/rpc`, then verify_audit_chain.py replays the resulting log).

The tests use Starlette's `TestClient` (synchronous, no running uvicorn
needed) for the HTTP path, and a `subprocess.Popen` for the stdio
parity comparison.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TRANSPORT_PATH = REPO_ROOT / "mcp-server" / "src" / "transports" / "sse.py"
DISPATCH_PATH = REPO_ROOT / "mcp-server" / "src" / "dispatch.py"
SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_audit_chain.py"
GOLDEN_DIR = REPO_ROOT / "skills" / "detection-engineering" / "golden"

# Tests that exercise a real subprocess can be slow on cold caches; the
# golden corpus is also used by the existing stdio integration tests so
# the read-only path is well-trodden.

# Skip the whole suite when sse-starlette / starlette is not installed
# in the active venv. The repo's `mcp-sse` extra pulls them in; CI
# pre-installs the dev group + all extras.
sse_starlette = pytest.importorskip("sse_starlette")
starlette = pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

# Load `server` and `dispatch` under their canonical module names so
# the SSE transport's `import dispatch` (which itself does
# `import server`) resolves to the same module objects we hold here.
# Otherwise the cached audit sink lives in two separate globals and
# the test's `_reset_audit_sink_for_tests()` resets only one of them.
SRC_DIR = str(SERVER_PATH.parent)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

SERVER_SPEC = importlib.util.spec_from_file_location("server", SERVER_PATH)
assert SERVER_SPEC and SERVER_SPEC.loader
SERVER = importlib.util.module_from_spec(SERVER_SPEC)
sys.modules["server"] = SERVER
SERVER_SPEC.loader.exec_module(SERVER)

DISPATCH_SPEC = importlib.util.spec_from_file_location("dispatch", DISPATCH_PATH)
assert DISPATCH_SPEC and DISPATCH_SPEC.loader
DISPATCH = importlib.util.module_from_spec(DISPATCH_SPEC)
sys.modules["dispatch"] = DISPATCH
DISPATCH_SPEC.loader.exec_module(DISPATCH)

TRANSPORT_SPEC = importlib.util.spec_from_file_location(
    "cloud_security_sse_test", TRANSPORT_PATH
)
assert TRANSPORT_SPEC and TRANSPORT_SPEC.loader
TRANSPORT = importlib.util.module_from_spec(TRANSPORT_SPEC)
sys.modules[TRANSPORT_SPEC.name] = TRANSPORT
TRANSPORT_SPEC.loader.exec_module(TRANSPORT)


# A small read-only skill known to be exposed on tools/list — keeps the
# tests fast and side-effect-free. detect-okta-mfa-fatigue ships golden
# fixtures the existing test_server.py already drives.
TOOL_NAME = "detect-okta-mfa-fatigue"


def _golden_input() -> str | None:
    """Return one OCSF JSONL line known to drive the detector to a
    deterministic result. Falls back to empty input when the golden
    corpus is not present (parity test still meaningful — both surfaces
    handle the empty case identically)."""
    fixture = GOLDEN_DIR / "okta-mfa-fatigue.jsonl"
    if fixture.exists():
        return fixture.read_text(encoding="utf-8")
    return ""


def _normalise_payload(payload: dict) -> dict:
    """Strip per-call identifiers + skill-internal log streams so stdio
    and SSE payloads can be compared structurally.

    The skill writes its own structured logs to stderr (with their own
    timestamp + correlation_id), so `stderr` and `correlation_id` can
    never match across two independent calls. We compare every other
    field — exit code, content shape, capability metadata, isError —
    as the parity guarantee."""
    cleaned = json.loads(json.dumps(payload))
    if isinstance(cleaned, dict):
        result = cleaned.get("result")
        if isinstance(result, dict):
            structured = result.get("structuredContent")
            if isinstance(structured, dict):
                structured.pop("correlation_id", None)
                # `stderr` carries the skill's own per-call log line;
                # equality across calls would require a deterministic
                # clock + identical correlation_id which is by design
                # not the case.
                structured.pop("stderr", None)
    return cleaned


def _stdio_call(tool: str, args: list[str], stdin_text: str) -> dict:
    """Drive the stdio server end-to-end so the parity check actually
    compares two production code paths (not two function calls into the
    same module)."""
    proc = subprocess.Popen(
        [sys.executable, str(SERVER_PATH)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=REPO_ROOT,
    )
    try:
        def send(payload):
            body = json.dumps(payload).encode("utf-8")
            assert proc.stdin is not None
            proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
            proc.stdin.write(body)
            proc.stdin.flush()

        def read():
            assert proc.stdout is not None
            headers = {}
            while True:
                line = proc.stdout.readline()
                assert line, (proc.stderr.read() or b"").decode("utf-8")
                if line in (b"\r\n", b"\n"):
                    break
                name, value = line.decode("utf-8").split(":", 1)
                headers[name.strip().lower()] = value.strip()
            length = int(headers["content-length"])
            return json.loads(proc.stdout.read(length).decode("utf-8"))

        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        read()
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": {"args": args, "input": stdin_text},
            },
        })
        return read()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _build_app(monkeypatch, tmp_path, *, key="test-key", bind="127.0.0.1", hmac_key="chain-key"):
    """Wire env, reset the cached audit sink, and build the Starlette app.

    The audit sink is a process-local global; each test that wants its
    own log file needs to wipe the cache so the new env wins.
    """
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MCP_SSE_BEARER_KEYS", key)
    monkeypatch.setenv("CLOUD_SECURITY_MCP_AUDIT_LOG", str(log_path))
    monkeypatch.setenv("CLOUD_SECURITY_AUDIT_HMAC_KEY", hmac_key)
    monkeypatch.delenv("MCP_SSE_ALLOW_PUBLIC_BIND", raising=False)
    SERVER._reset_audit_sink_for_tests()
    app = TRANSPORT.create_app(bind=bind)
    return app, log_path


# ---------------------------------------------------------------------------
# 1) Auth — 401 on missing / bad bearer.
# ---------------------------------------------------------------------------


class TestSseAuth:
    def test_rpc_rejects_missing_authorization(self, monkeypatch, tmp_path):
        app, _ = _build_app(monkeypatch, tmp_path)
        with TestClient(app) as client:
            response = client.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert response.status_code == 401

    def test_rpc_rejects_wrong_bearer(self, monkeypatch, tmp_path):
        app, _ = _build_app(monkeypatch, tmp_path)
        with TestClient(app) as client:
            response = client.post(
                "/rpc",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Authorization": "Bearer not-the-key"},
            )
        assert response.status_code == 401

    def test_sse_endpoint_rejects_missing_bearer(self, monkeypatch, tmp_path):
        app, _ = _build_app(monkeypatch, tmp_path)
        with TestClient(app) as client:
            response = client.get("/sse")
        assert response.status_code == 401

    def test_messages_endpoint_rejects_missing_bearer(self, monkeypatch, tmp_path):
        app, _ = _build_app(monkeypatch, tmp_path)
        with TestClient(app) as client:
            response = client.post(
                "/messages?session=anything",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
        assert response.status_code == 401

    def test_healthz_is_open(self, monkeypatch, tmp_path):
        app, _ = _build_app(monkeypatch, tmp_path)
        with TestClient(app) as client:
            response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["service"] == "mcp-sse"

    def test_rpc_accepts_valid_bearer(self, monkeypatch, tmp_path):
        app, _ = _build_app(monkeypatch, tmp_path)
        with TestClient(app) as client:
            response = client.post(
                "/rpc",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Authorization": "Bearer test-key"},
            )
        assert response.status_code == 200
        assert response.json()["result"] == {}


# ---------------------------------------------------------------------------
# 2) Parity — SSE returns the same structural payload as stdio.
# ---------------------------------------------------------------------------


class TestStdioSseParity:
    def test_same_tool_call_returns_structurally_equal_result(self, monkeypatch, tmp_path):
        stdin_text = _golden_input()
        sse_app, _ = _build_app(monkeypatch, tmp_path)
        with TestClient(sse_app) as client:
            sse_response = client.post(
                "/rpc",
                json={
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {
                        "name": TOOL_NAME,
                        "arguments": {"args": [], "input": stdin_text},
                    },
                },
                headers={"Authorization": "Bearer test-key"},
            )
        assert sse_response.status_code == 200
        sse_payload = _normalise_payload(sse_response.json())

        stdio_payload = _normalise_payload(_stdio_call(TOOL_NAME, [], stdin_text))

        # Both surfaces must agree on the structured tool-call shape.
        sse_struct = sse_payload["result"]["structuredContent"]
        stdio_struct = stdio_payload["result"]["structuredContent"]
        assert sse_struct == stdio_struct
        assert sse_payload["result"]["isError"] == stdio_payload["result"]["isError"]


# ---------------------------------------------------------------------------
# 3) Audit chain — transport="sse" + chain links to previous stdio record.
# ---------------------------------------------------------------------------


def _read_audit_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class TestAuditChain:
    def test_sse_call_records_transport_sse(self, monkeypatch, tmp_path):
        app, log_path = _build_app(monkeypatch, tmp_path)
        with TestClient(app) as client:
            response = client.post(
                "/rpc",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": TOOL_NAME,
                        "arguments": {"args": [], "input": ""},
                    },
                },
                headers={"Authorization": "Bearer test-key"},
            )
        assert response.status_code == 200
        records = _read_audit_records(log_path)
        assert len(records) == 1
        assert records[0]["transport"] == "sse"
        assert records[0]["tool"] == TOOL_NAME

    def test_chain_links_across_stdio_then_sse(self, monkeypatch, tmp_path):
        # First write a stdio record straight into the same log file via
        # the shared dispatch path. The SSE call then has to extend that
        # chain, and the verifier has to replay them as one stream.
        log_path = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CLOUD_SECURITY_MCP_AUDIT_LOG", str(log_path))
        monkeypatch.setenv("CLOUD_SECURITY_AUDIT_HMAC_KEY", "chain-key")
        SERVER._reset_audit_sink_for_tests()

        # Synthetic stdio audit event — bypass tool subprocess so the
        # test stays hermetic. The shape matches `_call_tool` enough for
        # the verifier; in production the full event is richer.
        SERVER._emit_audit_event({
            "event": "mcp_tool_call",
            "transport": "stdio",
            "tool": "synthetic-stdio",
            "result": "success",
            "correlation_id": "stdio-1",
        })

        # Now the SSE call goes into the same sink. Reuse the cached
        # sink instance — that's the production behaviour: one process,
        # one chain.
        monkeypatch.setenv("MCP_SSE_BEARER_KEYS", "test-key")
        monkeypatch.delenv("MCP_SSE_ALLOW_PUBLIC_BIND", raising=False)
        app = TRANSPORT.create_app(bind="127.0.0.1")
        with TestClient(app) as client:
            response = client.post(
                "/rpc",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": TOOL_NAME,
                        "arguments": {"args": [], "input": ""},
                    },
                },
                headers={"Authorization": "Bearer test-key"},
            )
        assert response.status_code == 200

        records = _read_audit_records(log_path)
        assert len(records) == 2
        assert records[0]["transport"] == "stdio"
        assert records[1]["transport"] == "sse"
        # Chain link: each SSE record's `prev_hash` must equal the
        # previous record's `chain_hash`.
        assert records[1]["prev_hash"] == records[0]["chain_hash"]

        # And the canonical verifier must accept the joined log.
        env = {**os.environ, "CLOUD_SECURITY_AUDIT_HMAC_KEY": "chain-key"}
        result = subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT), str(log_path)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "verified 2 records, 0 error(s)" in result.stdout


# ---------------------------------------------------------------------------
# 4) Public-bind refusal without keys.
# ---------------------------------------------------------------------------


class TestPublicBindGuard:
    def test_refuses_public_bind_without_keys(self, monkeypatch, capsys):
        monkeypatch.delenv("MCP_SSE_BEARER_KEYS", raising=False)
        monkeypatch.delenv("MCP_SSE_ALLOW_PUBLIC_BIND", raising=False)
        with pytest.raises(SystemExit) as excinfo:
            TRANSPORT.create_app(bind="0.0.0.0")
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "refusing to bind on public address" in captured.err
        assert "MCP_SSE_ALLOW_PUBLIC_BIND" in captured.err

    def test_refuses_public_bind_when_override_set_but_no_keys(self, monkeypatch, capsys):
        monkeypatch.delenv("MCP_SSE_BEARER_KEYS", raising=False)
        monkeypatch.setenv("MCP_SSE_ALLOW_PUBLIC_BIND", "1")
        with pytest.raises(SystemExit) as excinfo:
            TRANSPORT.create_app(bind="0.0.0.0")
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "without bearer keys" in captured.err

    def test_allows_public_bind_when_override_set_and_keys_present(self, monkeypatch, tmp_path):
        monkeypatch.setenv("MCP_SSE_BEARER_KEYS", "k1,k2")
        monkeypatch.setenv("MCP_SSE_ALLOW_PUBLIC_BIND", "1")
        monkeypatch.setenv("CLOUD_SECURITY_MCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
        SERVER._reset_audit_sink_for_tests()
        # Should not raise.
        TRANSPORT.create_app(bind="0.0.0.0")

    def test_localhost_is_always_allowed(self, monkeypatch):
        monkeypatch.delenv("MCP_SSE_BEARER_KEYS", raising=False)
        monkeypatch.delenv("MCP_SSE_ALLOW_PUBLIC_BIND", raising=False)
        # Localhost binds skip the public-bind guard entirely; the
        # bearer check still rejects every request, so an unkeyed
        # localhost server is safe to construct.
        TRANSPORT.create_app(bind="127.0.0.1")
        TRANSPORT.create_app(bind="localhost")
        TRANSPORT.create_app(bind="::1")


# ---------------------------------------------------------------------------
# 5) Concurrency — N parallel clients do not corrupt the audit chain.
# ---------------------------------------------------------------------------


class TestConcurrentClients:
    def test_three_concurrent_clients_keep_chain_intact(self, monkeypatch, tmp_path):
        app, log_path = _build_app(monkeypatch, tmp_path)
        client = TestClient(app)

        errors: list[BaseException] = []

        def worker(idx: int) -> None:
            try:
                response = client.post(
                    "/rpc",
                    json={
                        "jsonrpc": "2.0",
                        "id": idx,
                        "method": "tools/call",
                        "params": {
                            "name": TOOL_NAME,
                            "arguments": {"args": [], "input": ""},
                        },
                    },
                    headers={"Authorization": "Bearer test-key"},
                )
                assert response.status_code == 200, response.text
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        client.close()
        assert not errors, errors

        records = _read_audit_records(log_path)
        assert len(records) == 4
        for record in records:
            assert record["transport"] == "sse"

        # The verifier is the canonical chain check: replay the log
        # under the configured key and assert zero errors.
        env = {**os.environ, "CLOUD_SECURITY_AUDIT_HMAC_KEY": "chain-key"}
        result = subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT), str(log_path)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "verified 4 records, 0 error(s)" in result.stdout
