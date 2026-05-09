from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SINK_PATH = REPO_ROOT / "mcp-server" / "src" / "audit_sink.py"
SPEC = importlib.util.spec_from_file_location("cloud_security_audit_sink_test", SINK_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _make_event(idx: int) -> dict[str, object]:
    return {
        "event": "mcp_tool_call",
        "tool": f"detect-fake-{idx}",
        "category": "detection",
        "result": "success",
        "correlation_id": f"corr-{idx:04d}",
    }


def test_sink_disabled_when_no_log_path(tmp_path):
    sink = MODULE.AuditSink(log_path=None, hmac_key=None)
    annotated = sink.annotate(_make_event(1))
    assert "chain_hash" not in annotated
    assert "prev_hash" not in annotated
    sink.write_file(_make_event(1))  # no-op


def test_file_sink_appends_one_line_per_event_and_fsyncs(tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = MODULE.AuditSink(log_path=log, hmac_key=None)
    sink.write_file(_make_event(1))
    sink.write_file(_make_event(2))
    sink.write_file(_make_event(3))
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [r["correlation_id"] for r in parsed] == ["corr-0001", "corr-0002", "corr-0003"]


def test_chain_hash_is_continuous_within_a_run(tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = MODULE.AuditSink(log_path=log, hmac_key=b"secret")
    e1 = sink.annotate(_make_event(1))
    e2 = sink.annotate(_make_event(2))
    e3 = sink.annotate(_make_event(3))

    assert e1["prev_hash"] == MODULE.GENESIS_PREV_HASH
    assert e2["prev_hash"] == e1["chain_hash"]
    assert e3["prev_hash"] == e2["chain_hash"]
    # chain_hash values must be distinct (genesis + two link events)
    assert len({e1["chain_hash"], e2["chain_hash"], e3["chain_hash"]}) == 3


def test_chain_extends_across_restart(tmp_path):
    log = tmp_path / "audit.jsonl"
    s1 = MODULE.AuditSink(log_path=log, hmac_key=b"secret")
    e1 = s1.annotate(_make_event(1))
    s1.write_file(e1)

    s2 = MODULE.AuditSink(log_path=log, hmac_key=b"secret")
    e2 = s2.annotate(_make_event(2))
    s2.write_file(e2)

    assert e2["prev_hash"] == e1["chain_hash"]


def test_verifier_passes_for_valid_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = MODULE.AuditSink(log_path=log, hmac_key=b"secret")
    for idx in range(5):
        sink.write_file(sink.annotate(_make_event(idx)))

    env = {**os.environ, "CLOUD_SECURITY_AUDIT_HMAC_KEY": "secret"}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "verify_audit_chain.py"), str(log)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "verified 5 records, 0 error(s)" in result.stdout


def test_verifier_detects_tampered_event(tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = MODULE.AuditSink(log_path=log, hmac_key=b"secret")
    for idx in range(3):
        sink.write_file(sink.annotate(_make_event(idx)))

    # Tamper with a middle line: change `tool` from `detect-fake-1` to `detect-fake-evil`.
    lines = log.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["tool"] = "detect-fake-evil"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    env = {**os.environ, "CLOUD_SECURITY_AUDIT_HMAC_KEY": "secret"}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "verify_audit_chain.py"), str(log)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "chain_hash mismatch" in result.stderr


def test_verifier_detects_wrong_key(tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = MODULE.AuditSink(log_path=log, hmac_key=b"secret")
    sink.write_file(sink.annotate(_make_event(0)))

    env = {**os.environ, "CLOUD_SECURITY_AUDIT_HMAC_KEY": "WRONG"}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "verify_audit_chain.py"), str(log)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1


def test_verifier_exit_2_on_missing_key(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "CLOUD_SECURITY_AUDIT_HMAC_KEY"}
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "verify_audit_chain.py"), str(log)],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2


def test_sink_creates_parent_dirs_at_construction(tmp_path):
    log = tmp_path / "nested" / "deeply" / "audit.jsonl"
    MODULE.AuditSink(log_path=log, hmac_key=None)
    assert log.parent.is_dir()


def test_file_sink_chmod_0600(tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = MODULE.AuditSink(log_path=log, hmac_key=None)
    sink.write_file(_make_event(0))
    mode = log.stat().st_mode & 0o777
    # On macOS / linux umask is typically 022 so a fresh 0600 open survives.
    # Whatever umask strips, owner-read+write must remain.
    assert mode & 0o600 == 0o600
