"""Tests for detect-mcp-unbounded-tool-output."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ATLAS_TECHNIQUE_UID,
    DEFAULT_BYTES_THRESHOLD,
    DEFAULT_LINES_THRESHOLD,
    DEFAULT_REPEATED_BREACH_THRESHOLD,
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    OUTPUT_FORMATS,
    SEVERITY_MEDIUM,
    SKILL_NAME,
    _normalize_event,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT_FIXTURE = GOLDEN / "mcp_unbounded_tool_output_input.ocsf.jsonl"
EXPECTED = GOLDEN / "mcp_unbounded_tool_output_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _ev(
    session: str,
    tool: str,
    bytes_count: int,
    lines_count: int = 0,
    time_ms: int = 100,
) -> dict:
    return {
        "class_uid": 6002,
        "time": time_ms,
        "mcp": {"session_uid": session, "tool": {"name": tool}},
        "unmapped": {
            "mcp": {
                "tool_name": tool,
                "response_size_bytes": bytes_count,
                "response_line_count": lines_count,
            }
        },
    }


class TestNormalize:
    def test_ignores_wrong_class(self):
        e = _ev("s", "t", 100)
        e["class_uid"] = 1234
        assert _normalize_event(e) is None

    def test_ignores_missing_tool_name(self):
        e = _ev("s", "", 100)
        assert _normalize_event(e) is None

    def test_ignores_event_with_no_size_or_lines(self):
        e = _ev("s", "t", 0, 0)
        assert _normalize_event(e) is None


class TestDetect:
    def test_empty_stream(self):
        assert list(detect([])) == []

    def test_under_threshold_no_fire(self):
        # 4 small responses well under any threshold; no breaches.
        events = [_ev("s", "t", 1024, time_ms=i * 1000) for i in range(10)]
        assert list(detect(events)) == []

    def test_single_breach_does_not_fire(self):
        # One breach is not enough to trigger; need >= repeat threshold.
        events = [
            _ev("s", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000)
            for i in range(2)
        ]
        assert list(detect(events)) == []

    def test_repeated_breaches_fires_once(self):
        # 5 breaches in the same (session, tool) => fire.
        events = [
            _ev("s", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000)
            for i in range(DEFAULT_REPEATED_BREACH_THRESHOLD)
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID
        assert f["category_uid"] == FINDING_CATEGORY_UID
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_MEDIUM
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_threshold_edge_strictly_greater(self):
        # Exactly at threshold is NOT a breach (must be strictly greater).
        events = [
            _ev("s", "t", DEFAULT_BYTES_THRESHOLD, time_ms=i * 1000)
            for i in range(DEFAULT_REPEATED_BREACH_THRESHOLD)
        ]
        assert list(detect(events)) == []

    def test_lines_threshold_also_triggers(self):
        events = [
            _ev("s", "t", 100, DEFAULT_LINES_THRESHOLD + 1, time_ms=i * 1000)
            for i in range(DEFAULT_REPEATED_BREACH_THRESHOLD)
        ]
        assert len(list(detect(events))) == 1

    def test_multi_event_aggregation_after_first_fire_no_duplicate(self):
        # 8 breaches > 5 should still fire only once (idempotent on the same key).
        events = [
            _ev("s", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000)
            for i in range(8)
        ]
        assert len(list(detect(events))) == 1

    def test_separate_sessions_counted_separately(self):
        # 4 breaches in s1, 4 in s2 → no fire.
        events = []
        for i in range(4):
            events.append(_ev("s1", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000))
            events.append(_ev("s2", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000))
        assert list(detect(events)) == []

    def test_separate_tools_counted_separately(self):
        events = []
        for i in range(4):
            events.append(_ev("s", "a", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000))
            events.append(_ev("s", "b", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000))
        assert list(detect(events)) == []

    def test_atlas_attack_populated(self):
        events = [
            _ev("s", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000)
            for i in range(DEFAULT_REPEATED_BREACH_THRESHOLD)
        ]
        finding = list(detect(events))[0]
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == ATLAS_TECHNIQUE_UID

    def test_wrong_vendor_name_still_processed(self):
        # Detector trusts events that carry the class_uid + unmapped fields.
        # A different upstream vendor producing the same shape is still processed.
        events = [
            _ev("s", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000)
            for i in range(DEFAULT_REPEATED_BREACH_THRESHOLD)
        ]
        for e in events:
            e["metadata"] = {"product": {"vendor_name": "other-vendor"}}
        assert len(list(detect(events))) == 1

    def test_malformed_event_ignored(self):
        # Missing fields should not crash; just return no findings.
        events = [{"class_uid": 6002, "time": 1, "mcp": {}, "unmapped": {}}]
        assert list(detect(events)) == []

    def test_native_output_shape(self):
        events = [
            _ev("s", "t", DEFAULT_BYTES_THRESHOLD + 1, time_ms=i * 1000)
            for i in range(DEFAULT_REPEATED_BREACH_THRESHOLD)
        ]
        f = list(detect(events, output_format="native"))[0]
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert f["schema_mode"] == "native"
        assert f["record_type"] == "detection_finding"
        assert "class_uid" not in f

    def test_rejects_unsupported_output_format(self):
        try:
            list(detect([], output_format="bridge"))
        except ValueError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        lines = ['{not json', '{"ok":true}']
        assert list(load_jsonl(lines)) == [{"ok": True}]
        assert "skipping line 1" in capsys.readouterr().err


class TestGoldenFixture:
    def test_exactly_one_finding_from_fixture(self):
        events = _load(INPUT_FIXTURE)
        findings = list(detect(events))
        assert len(findings) == 1

    def test_finding_matches_frozen_golden(self):
        events = _load(INPUT_FIXTURE)
        produced = list(detect(events))
        expected = _load(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e
