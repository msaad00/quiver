"""Tests for detect-mcp-model-artifact-tampering."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ATLAS_TECHNIQUE_UID,
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    OUTPUT_FORMATS,
    SEVERITY_HIGH,
    SKILL_NAME,
    _is_artifact_event,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT_FIXTURE = GOLDEN / "mcp_model_artifact_tampering_input.ocsf.jsonl"
EXPECTED = GOLDEN / "mcp_model_artifact_tampering_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _ev(session: str, tool: str, artifact: str, time_ms: int) -> dict:
    return {
        "class_uid": 6002,
        "time": time_ms,
        "metadata": {"product": {"feature": {"name": "ingest-mcp-proxy-ocsf"}}},
        "mcp": {"session_uid": session, "method": "tools/call", "direction": "response"},
        "unmapped": {
            "mcp": {"session_uid": session, "tool_name": tool, "model_artifact_sha256": artifact}
        },
    }


class TestFilter:
    def test_ignores_wrong_class(self):
        e = _ev("s1", "t", "sha256:a", 100)
        e["class_uid"] = 1234
        assert not _is_artifact_event(e)

    def test_ignores_missing_artifact(self):
        e = _ev("s1", "t", "", 100)
        assert not _is_artifact_event(e)

    def test_ignores_missing_tool_name(self):
        e = _ev("s1", "", "sha256:a", 100)
        assert not _is_artifact_event(e)

    def test_accepts_valid_event(self):
        assert _is_artifact_event(_ev("s1", "t", "sha256:a", 100))


class TestDetect:
    def test_empty_stream_no_findings(self):
        assert list(detect([])) == []

    def test_single_event_sets_baseline_only(self):
        findings = list(detect([_ev("s1", "t", "sha256:a", 100)]))
        assert findings == []

    def test_baseline_stable_no_fire(self):
        findings = list(
            detect(
                [
                    _ev("s1", "t", "sha256:a", 100),
                    _ev("s1", "t", "sha256:a", 200),
                    _ev("s1", "t", "sha256:a", 300),
                ]
            )
        )
        assert findings == []

    def test_divergent_artifact_fires_once_high(self):
        events = [
            _ev("s1", "t", "sha256:baseline", 100),
            _ev("s1", "t", "sha256:tampered", 200),
        ]
        findings = list(detect(events))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID
        assert f["category_uid"] == FINDING_CATEGORY_UID
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_mitre_atlas_populated(self):
        events = [
            _ev("s1", "t", "sha256:a", 100),
            _ev("s1", "t", "sha256:b", 200),
        ]
        finding = list(detect(events))[0]
        attacks = finding["finding_info"]["attacks"]
        assert attacks[0]["technique"]["uid"] == ATLAS_TECHNIQUE_UID

    def test_cross_session_baselines_independent(self):
        events = [
            _ev("s1", "t", "sha256:a", 100),
            _ev("s2", "t", "sha256:b", 110),
        ]
        # Two different sessions: each sets baseline; no finding.
        assert list(detect(events)) == []

    def test_multi_transition_one_finding_per_change(self):
        events = [
            _ev("s1", "t", "sha256:a", 100),
            _ev("s1", "t", "sha256:b", 200),
            _ev("s1", "t", "sha256:c", 300),
        ]
        assert len(list(detect(events))) == 2

    def test_native_output_shape(self):
        events = [
            _ev("s1", "t", "sha256:a", 100),
            _ev("s1", "t", "sha256:b", 200),
        ]
        finding = list(detect(events, output_format="native"))[0]
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert finding["schema_mode"] == "native"
        assert finding["record_type"] == "detection_finding"
        assert "class_uid" not in finding

    def test_rejects_unsupported_output_format(self):
        try:
            list(detect([], output_format="bridge"))
        except ValueError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected unsupported output_format to raise")


class TestLoadJsonl:
    def test_skips_malformed(self, capsys):
        lines = ['{"not": "json"', '{"ok": true}']
        out = list(load_jsonl(lines))
        assert out == [{"ok": True}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_skips_non_object(self, capsys):
        lines = ["[1,2]", '{"ok": true}']
        out = list(load_jsonl(lines))
        assert out == [{"ok": True}]
        assert "not a JSON object" in capsys.readouterr().err


class TestGoldenFixture:
    def test_exactly_one_finding_from_fixture(self):
        events = _load(INPUT_FIXTURE)
        findings = list(detect(events))
        assert len(findings) == 1

    def test_finding_session_is_sess_aaa(self):
        events = _load(INPUT_FIXTURE)
        finding = list(detect(events))[0]
        obs = {o["name"]: o["value"] for o in finding["observables"]}
        assert obs["session.uid"] == "sess-aaa"
        assert obs["tool.name"] == "llm.generate"

    def test_finding_matches_frozen_golden_exactly(self):
        events = _load(INPUT_FIXTURE)
        produced = list(detect(events))
        expected = _load(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e
