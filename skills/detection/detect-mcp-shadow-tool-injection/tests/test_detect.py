"""Tests for detect-mcp-shadow-tool-injection."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    MITRE_TECHNIQUE_UID,
    OUTPUT_FORMATS,
    SEVERITY_HIGH,
    SKILL_NAME,
    _sha256_hex,
    _stable_schema_json,
    detect,
    load_baseline,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT_FIXTURE = GOLDEN / "mcp_shadow_tool_injection_input.ocsf.jsonl"
EXPECTED = GOLDEN / "mcp_shadow_tool_injection_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _ev(session: str, name: str, description: str, schema: dict, time_ms: int = 100) -> dict:
    return {
        "class_uid": 6002,
        "time": time_ms,
        "mcp": {
            "session_uid": session,
            "method": "tools/list",
            "direction": "response",
            "tool": {"name": name, "description": description, "inputSchema": schema},
        },
    }


_BASELINE_QUERY = {
    "description_sha256": _sha256_hex("Run a read-only SQL query against the analytics warehouse."),
    "schema_sha256": _sha256_hex(
        _stable_schema_json({"type": "object", "properties": {"sql": {"type": "string"}}})
    ),
    "registered_at": "2026-05-10T12:00:00Z",
}
BASELINE = {"query_db": _BASELINE_QUERY}


class TestLoadBaseline:
    def test_returns_empty_for_no_path(self, capsys):
        out = load_baseline(None)
        assert out == {}

    def test_missing_file_fails_open(self, tmp_path, capsys):
        out = load_baseline(tmp_path / "missing.json")
        assert out == {}
        assert "baseline file not found" in capsys.readouterr().err

    def test_malformed_file_fails_open(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        out = load_baseline(bad)
        assert out == {}
        assert "malformed JSON" in capsys.readouterr().err

    def test_missing_tools_key_fails_open(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text('{"something": "else"}')
        out = load_baseline(bad)
        assert out == {}
        assert "missing `tools`" in capsys.readouterr().err

    def test_loads_valid_baseline(self, tmp_path):
        good = tmp_path / "good.json"
        good.write_text(
            json.dumps(
                {
                    "tools": {
                        "x": {
                            "description_sha256": "deadbeef",
                            "schema_sha256": "cafefade",
                            "registered_at": "2026-05-10T12:00:00Z",
                        }
                    }
                }
            )
        )
        out = load_baseline(good)
        assert out["x"]["description_sha256"] == "deadbeef"


class TestDetect:
    def test_empty_baseline_no_findings(self, capsys):
        events = [_ev("s", "query_db", "DIFFERENT", {"type": "object"})]
        assert list(detect(events, baseline={})) == []

    def test_matching_description_and_schema_no_finding(self):
        events = [
            _ev(
                "s",
                "query_db",
                "Run a read-only SQL query against the analytics warehouse.",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
            )
        ]
        assert list(detect(events, baseline=BASELINE)) == []

    def test_description_divergence_fires(self):
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED DESCRIPTION",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
            )
        ]
        findings = list(detect(events, baseline=BASELINE))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID
        assert f["category_uid"] == FINDING_CATEGORY_UID
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert "description" in f["evidence"]["diverged_parts"]

    def test_schema_divergence_fires(self):
        events = [
            _ev(
                "s",
                "query_db",
                "Run a read-only SQL query against the analytics warehouse.",
                {
                    "type": "object",
                    "properties": {"sql": {"type": "string"}, "write": {"type": "boolean"}},
                },
            )
        ]
        findings = list(detect(events, baseline=BASELINE))
        assert len(findings) == 1
        assert "schema" in findings[0]["evidence"]["diverged_parts"]

    def test_both_divergence_fires_once_with_both_parts(self):
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"x": {"type": "boolean"}}},
            )
        ]
        f = list(detect(events, baseline=BASELINE))[0]
        assert "description" in f["evidence"]["diverged_parts"]
        assert "schema" in f["evidence"]["diverged_parts"]

    def test_unknown_tool_ignored(self):
        # Tool not in baseline → ignored (different defect class).
        events = [_ev("s", "weather", "whatever", {"type": "object"})]
        assert list(detect(events, baseline=BASELINE)) == []

    def test_idempotent_same_divergence_in_same_session(self):
        # Two events with the same divergence in the same session → one finding.
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
                time_ms=100,
            ),
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
                time_ms=200,
            ),
        ]
        assert len(list(detect(events, baseline=BASELINE))) == 1

    def test_separate_sessions_separate_findings(self):
        events = [
            _ev(
                "s1",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
                time_ms=100,
            ),
            _ev(
                "s2",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
                time_ms=200,
            ),
        ]
        assert len(list(detect(events, baseline=BASELINE))) == 2

    def test_mitre_attack_populated(self):
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
            )
        ]
        finding = list(detect(events, baseline=BASELINE))[0]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID

    def test_wrong_class_ignored(self):
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
            )
        ]
        events[0]["class_uid"] = 1234
        assert list(detect(events, baseline=BASELINE)) == []

    def test_wrong_method_ignored(self):
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
            )
        ]
        events[0]["mcp"]["method"] = "tools/call"
        assert list(detect(events, baseline=BASELINE)) == []

    def test_wrong_vendor_name_still_processed(self):
        # Detector trusts the class_uid + tools/list shape; vendor in
        # metadata doesn't gate.
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
            )
        ]
        events[0]["metadata"] = {"product": {"vendor_name": "other-vendor"}}
        assert len(list(detect(events, baseline=BASELINE))) == 1

    def test_malformed_event_ignored(self):
        events = [{"class_uid": 6002, "time": 1, "mcp": {}}]
        assert list(detect(events, baseline=BASELINE)) == []

    def test_native_output_shape(self):
        events = [
            _ev(
                "s",
                "query_db",
                "POISONED",
                {"type": "object", "properties": {"sql": {"type": "string"}}},
            )
        ]
        f = list(detect(events, output_format="native", baseline=BASELINE))[0]
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert f["schema_mode"] == "native"
        assert f["record_type"] == "detection_finding"
        assert "class_uid" not in f

    def test_rejects_unsupported_output_format(self):
        try:
            list(detect([], output_format="bridge", baseline=BASELINE))
        except ValueError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        lines = ["{not json", '{"ok":true}']
        assert list(load_jsonl(lines)) == [{"ok": True}]
        assert "skipping line 1" in capsys.readouterr().err


class TestGoldenFixture:
    def test_expected_finding_count(self):
        events = _load(INPUT_FIXTURE)
        findings = list(detect(events, baseline=BASELINE))
        # Fixture is designed so exactly one tool diverges (sess-poison),
        # the matching baseline session does not fire, and the unknown
        # tool is ignored.
        assert len(findings) == 1

    def test_finding_matches_frozen_golden(self):
        events = _load(INPUT_FIXTURE)
        produced = list(detect(events, baseline=BASELINE))
        expected = _load(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e
