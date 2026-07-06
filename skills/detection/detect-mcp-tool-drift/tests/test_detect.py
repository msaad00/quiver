"""Tests for detect-mcp-tool-drift.

Uses the frozen OCSF golden fixture from ingest-mcp-proxy-ocsf and verifies:
  1. Exactly one drift finding is produced (query_db in sess-abc)
  2. MITRE ATT&CK T1195.001 is populated
  3. Deterministic finding UID (re-runs are idempotent)
  4. Stable-fingerprint tools (read_file) do NOT fire
  5. Single-occurrence tools (sess-xyz / read_file) do NOT fire
  6. The full OCSF Detection Finding matches the frozen golden fixture exactly
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detect import (  # type: ignore[import-not-found]
    CANONICAL_VERSION,
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TACTIC_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    SEVERITY_HIGH,
    SKILL_NAME,
    _is_tools_list_response_with_fingerprint,
    _normalize_event,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS.parents[2] / "detection-engineering" / "golden"
OCSF_FIXTURE = GOLDEN / "mcp_proxy_sample.ocsf.jsonl"
EXPECTED_FINDING = GOLDEN / "tool_drift_finding.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ── Filter helper ──────────────────────────────────────────────────────


class TestFilter:
    def test_ignores_wrong_class(self):
        e = {
            "class_uid": 1234,
            "mcp": {
                "method": "tools/list",
                "direction": "response",
                "tool": {"name": "x", "fingerprint": "sha256:f"},
            },
        }
        assert not _is_tools_list_response_with_fingerprint(e)

    def test_ignores_wrong_method(self):
        e = {
            "class_uid": 6002,
            "mcp": {
                "method": "tools/call",
                "direction": "response",
                "tool": {"name": "x", "fingerprint": "sha256:f"},
            },
        }
        assert not _is_tools_list_response_with_fingerprint(e)

    def test_ignores_wrong_direction(self):
        e = {
            "class_uid": 6002,
            "mcp": {
                "method": "tools/list",
                "direction": "request",
                "tool": {"name": "x", "fingerprint": "sha256:f"},
            },
        }
        assert not _is_tools_list_response_with_fingerprint(e)

    def test_ignores_missing_tool(self):
        e = {"class_uid": 6002, "mcp": {"method": "tools/list", "direction": "response"}}
        assert not _is_tools_list_response_with_fingerprint(e)

    def test_ignores_missing_fingerprint(self):
        e = {
            "class_uid": 6002,
            "mcp": {"method": "tools/list", "direction": "response", "tool": {"name": "x"}},
        }
        assert not _is_tools_list_response_with_fingerprint(e)

    def test_accepts_valid(self):
        e = {
            "class_uid": 6002,
            "mcp": {
                "method": "tools/list",
                "direction": "response",
                "tool": {"name": "x", "fingerprint": "sha256:f"},
            },
        }
        assert _is_tools_list_response_with_fingerprint(e)

    def test_accepts_valid_native(self):
        assert _is_tools_list_response_with_fingerprint(_native_ev("s1", "x", "sha256:f", 100))


class TestNormalize:
    def test_normalizes_ocsf_event(self):
        normalized = _normalize_event(_ev("s1", "x", "sha256:f", 100))
        assert normalized is not None
        assert normalized["source_format"] == "ocsf"
        assert normalized["tool_name"] == "x"

    def test_normalizes_native_event(self):
        normalized = _normalize_event(_native_ev("s1", "x", "sha256:f", 100))
        assert normalized is not None
        assert normalized["source_format"] == "native"
        assert normalized["tool_name"] == "x"


# ── detect() behaviour ─────────────────────────────────────────────────


def _ev(session: str, tool: str, fp: str, time_ms: int) -> dict:
    return {
        "class_uid": 6002,
        "time": time_ms,
        "mcp": {
            "session_uid": session,
            "method": "tools/list",
            "direction": "response",
            "tool": {"name": tool, "fingerprint": fp},
        },
    }


def _native_ev(session: str, tool: str, fp: str, time_ms: int) -> dict:
    return {
        "schema_mode": "native",
        "canonical_schema_version": CANONICAL_VERSION,
        "record_type": "application_activity",
        "provider": "MCP",
        "time_ms": time_ms,
        "session_uid": session,
        "method": "tools/list",
        "direction": "response",
        "tool": {"name": tool, "fingerprint": fp},
    }


class TestDetect:
    def test_empty_stream(self):
        assert list(detect([])) == []

    def test_single_occurrence_does_not_fire(self):
        findings = list(detect([_ev("s1", "t1", "sha256:a", 100)]))
        assert findings == []

    def test_same_fingerprint_republished_does_not_fire(self):
        findings = list(
            detect(
                [
                    _ev("s1", "t1", "sha256:a", 100),
                    _ev("s1", "t1", "sha256:a", 200),
                ]
            )
        )
        assert findings == []

    def test_drift_in_same_session_fires_once(self):
        findings = list(
            detect(
                [
                    _ev("s1", "t1", "sha256:a", 100),
                    _ev("s1", "t1", "sha256:b", 200),
                ]
            )
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID
        assert f["category_uid"] == FINDING_CATEGORY_UID
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_mitre_populated_inside_finding_info(self):
        # OCSF 1.8 Detection Finding — attacks[] lives inside finding_info,
        # not at the event root (that was the deprecated Security Finding layout).
        findings = list(
            detect(
                [
                    _ev("s1", "t1", "sha256:a", 100),
                    _ev("s1", "t1", "sha256:b", 200),
                ]
            )
        )
        assert "attacks" not in findings[0], "attacks[] must NOT be at event root in OCSF 1.8"
        attacks = findings[0]["finding_info"]["attacks"]
        assert len(attacks) == 1
        assert attacks[0]["tactic"]["uid"] == MITRE_TACTIC_UID
        assert attacks[0]["technique"]["uid"] == MITRE_TECHNIQUE_UID

    def test_cross_session_drift_does_not_fire(self):
        # Same tool, different sessions — MCP server was upgraded between
        # sessions, not mid-session. Legitimate; covered by a different
        # detector in the roadmap.
        findings = list(
            detect(
                [
                    _ev("s1", "t1", "sha256:a", 100),
                    _ev("s2", "t1", "sha256:b", 200),
                ]
            )
        )
        assert findings == []

    def test_deterministic_finding_uid(self):
        events = [
            _ev("s1", "t1", "sha256:aaaa1111", 100),
            _ev("s1", "t1", "sha256:bbbb2222", 200),
        ]
        a = list(detect(events))[0]["finding_info"]["uid"]
        b = list(detect(events))[0]["finding_info"]["uid"]
        assert a == b
        assert "aaaa1111"[:8] in a
        assert "bbbb2222"[:8] in a

    def test_multiple_drifts_one_per_transition(self):
        # Fingerprint goes a -> b -> c. We should see TWO findings:
        # a→b and b→c. Re-stating c doesn't fire again.
        events = [
            _ev("s1", "t1", "sha256:a", 100),
            _ev("s1", "t1", "sha256:b", 200),
            _ev("s1", "t1", "sha256:c", 300),
            _ev("s1", "t1", "sha256:c", 400),
        ]
        findings = list(detect(events))
        assert len(findings) == 2

    def test_out_of_order_input_still_detected(self):
        # Sort-by-time means we don't rely on input ordering.
        events = [
            _ev("s1", "t1", "sha256:b", 200),
            _ev("s1", "t1", "sha256:a", 100),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        # The drift should still be a → b chronologically.
        obs = {o["name"]: o["value"] for o in findings[0]["observables"]}
        assert obs["tool.before_fingerprint"] == "sha256:a"
        assert obs["tool.after_fingerprint"] == "sha256:b"

    def test_native_input_can_emit_native_finding(self):
        findings = list(
            detect(
                [
                    _native_ev("s1", "t1", "sha256:a", 100),
                    _native_ev("s1", "t1", "sha256:b", 200),
                ],
                output_format="native",
            )
        )
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        finding = findings[0]
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert finding["provider"] == "MCP"
        assert finding["session_uid"] == "s1"
        assert "class_uid" not in finding

    def test_native_input_can_emit_ocsf_finding(self):
        findings = list(
            detect(
                [
                    _native_ev("s1", "t1", "sha256:a", 100),
                    _native_ev("s1", "t1", "sha256:b", 200),
                ],
                output_format="ocsf",
            )
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID
        assert finding["finding_info"]["uid"].startswith("det-mcp-drift-")

    def test_rejects_unsupported_output_format(self):
        try:
            list(detect([], output_format="bridge"))
        except ValueError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected unsupported output_format to raise")


# ── load_jsonl robustness ──────────────────────────────────────────────


class TestLoadJsonl:
    def test_skips_malformed_without_crash(self, capsys):
        lines = ['{"not": "json"', '{"ok": true}']
        out = list(load_jsonl(lines))
        assert out == [{"ok": True}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_skips_non_object(self, capsys):
        lines = ["[1,2,3]", '{"ok": true}']
        out = list(load_jsonl(lines))
        assert out == [{"ok": True}]
        assert "not a JSON object" in capsys.readouterr().err


# ── Golden fixture parity ──────────────────────────────────────────────


class TestGoldenFixture:
    def test_exactly_one_finding_from_fixture(self):
        events = _load(OCSF_FIXTURE)
        findings = list(detect(events))
        assert len(findings) == 1, (
            f"expected exactly 1 finding from the fixture (query_db drift in sess-abc), got {len(findings)}"
        )

    def test_finding_is_query_db_in_sess_abc(self):
        events = _load(OCSF_FIXTURE)
        findings = list(detect(events))
        obs = {o["name"]: o["value"] for o in findings[0]["observables"]}
        assert obs["session.uid"] == "sess-abc"
        assert obs["tool.name"] == "query_db"

    def test_read_file_does_not_drift(self):
        events = _load(OCSF_FIXTURE)
        findings = list(detect(events))
        for f in findings:
            obs = {o["name"]: o["value"] for o in f["observables"]}
            assert obs["tool.name"] != "read_file", (
                "read_file has stable fingerprint and must not fire"
            )

    def test_sess_xyz_does_not_fire(self):
        events = _load(OCSF_FIXTURE)
        findings = list(detect(events))
        for f in findings:
            obs = {o["name"]: o["value"] for o in f["observables"]}
            assert obs["session.uid"] != "sess-xyz", (
                "sess-xyz only has one tools/list event — must not fire"
            )

    def test_finding_matches_frozen_golden_exactly(self):
        events = _load(OCSF_FIXTURE)
        produced = list(detect(events))
        expected = _load(EXPECTED_FINDING)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e, (
                f"finding mismatch:\n  produced: {json.dumps(p, sort_keys=True)}\n  expected: {json.dumps(e, sort_keys=True)}"
            )
