"""Tests for detect-agent-credential-leak-mcp."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

THIS = Path(__file__).resolve().parent
SRC = THIS.parent / "src" / "detect.py"
SPEC = importlib.util.spec_from_file_location("detect_agent_credential_leak_under_test", SRC)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

APPLICATION_ACTIVITY_UID = MODULE.APPLICATION_ACTIVITY_UID
CANONICAL_VERSION = MODULE.CANONICAL_VERSION
FINDING_CLASS_UID = MODULE.FINDING_CLASS_UID
OUTPUT_FORMATS = MODULE.OUTPUT_FORMATS
_matched_secrets = MODULE._matched_secrets
_normalize_event = MODULE._normalize_event
_credential_leak_event = MODULE._credential_leak_event
detect = MODULE.detect
load_jsonl = MODULE.load_jsonl

GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
INPUT_FIXTURE = GOLDEN / "mcp_credential_leak_input.native.jsonl"
EXPECTED_FINDING = GOLDEN / "mcp_credential_leak_findings.ocsf.jsonl"
TEST_TIME_MS = 1_700_000_000_100


def _load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _ev(
    session: str, tool: str, body: Any, time_ms: int, *, source_skill: str = "ingest-mcp-proxy-ocsf"
) -> dict:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "application_activity",
        "source_skill": source_skill,
        "event_uid": f"{session}-{tool}-{time_ms}",
        "provider": "MCP",
        "time_ms": time_ms,
        "session_uid": session,
        "method": "tools/call",
        "direction": "response",
        "tool": {"name": tool},
        "body": body,
    }


class TestSignals:
    def test_matches_aws_key(self):
        matches = _matched_secrets({"text": "AKIA1234567890ABCDEF"})
        assert matches[0]["signal"] == "aws-access-key-id"

    def test_matches_github_token(self):
        matches = _matched_secrets({"text": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"})
        assert matches[0]["signal"] == "github-token"

    def test_benign_body_does_not_match(self):
        assert _matched_secrets({"text": "hello world"}) == []


class TestNormalize:
    def test_normalizes_native_event(self):
        event = _normalize_event(_ev("s1", "query_db", {"text": "ok"}, TEST_TIME_MS))
        assert event is not None
        assert event["source_format"] == "native"
        assert event["tool_name"] == "query_db"

    def test_normalizes_ocsf_event_when_body_present(self):
        event = {
            "class_uid": APPLICATION_ACTIVITY_UID,
            "time": TEST_TIME_MS,
            "metadata": {"uid": "evt-1", "product": {"feature": {"name": "ingest-mcp-proxy-ocsf"}}},
            "mcp": {
                "session_uid": "s1",
                "method": "tools/call",
                "direction": "response",
                "tool": {"name": "query_db"},
            },
            "body": {"text": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
        }
        normalized = _normalize_event(event)
        assert normalized is not None
        assert normalized["source_format"] == "ocsf"


class TestFilter:
    def test_ignores_wrong_source(self):
        assert (
            _credential_leak_event(
                _ev(
                    "s1",
                    "tool",
                    {"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
                    TEST_TIME_MS,
                    source_skill="other",
                )
            )
            is None
        )

    def test_ignores_wrong_method(self):
        event = _ev(
            "s1", "tool", {"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}, TEST_TIME_MS
        )
        event["method"] = "tools/list"
        assert _credential_leak_event(event) is None

    def test_accepts_leaking_response(self):
        event = _credential_leak_event(
            _ev("s1", "tool", {"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}, TEST_TIME_MS)
        )
        assert event is not None
        assert event["matches"][0]["signal"] == "github-token"


class TestDetect:
    def test_empty_stream(self):
        assert list(detect([])) == []

    def test_benign_response_does_not_fire(self):
        assert list(detect([_ev("s1", "tool", {"text": "all good"}, TEST_TIME_MS)])) == []

    def test_leaking_response_fires(self):
        findings = list(
            detect(
                [
                    _ev(
                        "s1",
                        "tool",
                        {"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
                        TEST_TIME_MS,
                    )
                ]
            )
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID
        assert "mcp-credential-exposure" in finding["finding_info"]["types"]

    def test_deterministic_finding_uid(self):
        event = _ev(
            "s1", "tool", {"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}, TEST_TIME_MS
        )
        first = list(detect([event]))[0]["finding_info"]["uid"]
        second = list(detect([event]))[0]["finding_info"]["uid"]
        assert first == second

    def test_native_output_keeps_masked_matches_only(self):
        findings = list(
            detect(
                [
                    _ev(
                        "s1",
                        "tool",
                        {"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
                        TEST_TIME_MS,
                    )
                ],
                output_format="native",
            )
        )
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["matches"][0]["masked"].startswith("ghp_")
        assert "abcdefghijklmnopqrstuvwxyz1234567890" not in json.dumps(findings[0])

    def test_load_jsonl_skips_invalid_lines(self, tmp_path: Path, capsys):
        path = tmp_path / "bad.jsonl"
        path.write_text('{"ok":1}\nnot-json\n[]\n')
        records = load_jsonl(str(path))
        assert records == [{"ok": 1}]
        stderr = capsys.readouterr().err
        assert "json parse failed" in stderr
        assert "expected JSON object" in stderr

    def test_golden_fixture_parity(self):
        findings = list(detect(_load(INPUT_FIXTURE)))
        assert findings == _load(EXPECTED_FINDING)
