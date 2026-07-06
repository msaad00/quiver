"""Tests for detect-mcp-model-token-flood."""

from __future__ import annotations

import json
from pathlib import Path

from detect import (  # type: ignore[import-not-found]
    ATLAS_TECHNIQUE_UID,
    DEFAULT_BUDGET,
    DEFAULT_WINDOW_MIN,
    FINDING_CATEGORY_UID,
    FINDING_CLASS_UID,
    FINDING_TYPE_UID,
    OUTPUT_FORMATS,
    SEVERITY_HIGH,
    SKILL_NAME,
    _normalize_event,
    detect,
    load_jsonl,
)

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT_FIXTURE = GOLDEN / "mcp_token_flood_input.ocsf.jsonl"
EXPECTED = GOLDEN / "mcp_token_flood_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _ev(user: str, model: str, tokens: int, time_ms: int) -> dict:
    return {
        "class_uid": 6002,
        "time": time_ms,
        "actor": {"user": {"uid": user}},
        "unmapped": {"mcp": {"prompt_tokens": tokens, "model_name": model}},
    }


class TestNormalize:
    def test_ignores_wrong_class(self):
        e = _ev("u", "m", 100, 1)
        e["class_uid"] = 1234
        assert _normalize_event(e) is None

    def test_ignores_missing_tokens(self):
        e = _ev("u", "m", 0, 1)
        assert _normalize_event(e) is None

    def test_ignores_missing_model(self):
        e = _ev("u", "", 100, 1)
        assert _normalize_event(e) is None

    def test_accepts_valid(self):
        assert _normalize_event(_ev("u", "m", 100, 1)) is not None


class TestDetect:
    def test_empty_stream(self):
        assert list(detect([])) == []

    def test_under_threshold_no_fire(self):
        events = [_ev("u", "m", 50_000, i * 30_000) for i in range(3)]  # 150k
        assert (
            list(detect(events, token_budget=DEFAULT_BUDGET, window_minutes=DEFAULT_WINDOW_MIN))
            == []
        )

    def test_over_threshold_fires_once(self):
        # 3 events × 80k = 240k > 200k inside the default 5-min window
        events = [_ev("u", "m", 80_000, i * 60_000) for i in range(3)]
        findings = list(detect(events))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID
        assert f["category_uid"] == FINDING_CATEGORY_UID
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME

    def test_threshold_edge_just_at_budget_no_fire(self):
        # Total exactly equals threshold; not strictly greater → no fire.
        events = [
            _ev("u", "m", 100_000, 0),
            _ev("u", "m", 100_000, 60_000),
        ]
        assert list(detect(events, token_budget=200_000)) == []

    def test_threshold_edge_one_over_fires(self):
        events = [
            _ev("u", "m", 100_000, 0),
            _ev("u", "m", 100_001, 60_000),
        ]
        assert len(list(detect(events, token_budget=200_000))) == 1

    def test_mitre_atlas_populated(self):
        events = [_ev("u", "m", 80_000, i * 60_000) for i in range(3)]
        finding = list(detect(events))[0]
        attacks = finding["finding_info"]["attacks"]
        assert attacks[0]["technique"]["uid"] == ATLAS_TECHNIQUE_UID

    def test_separate_users_accounted_separately(self):
        events = [
            _ev("alice", "m", 150_000, 0),
            _ev("bob", "m", 150_000, 60_000),
        ]
        assert list(detect(events, token_budget=200_000)) == []

    def test_separate_models_accounted_separately(self):
        events = [
            _ev("u", "m1", 150_000, 0),
            _ev("u", "m2", 150_000, 60_000),
        ]
        assert list(detect(events, token_budget=200_000)) == []

    def test_window_evicts_old_events(self):
        # Tokens spread across > window minutes should not aggregate.
        events = [
            _ev("u", "m", 150_000, 0),
            _ev("u", "m", 150_000, 10 * 60_000),  # 10 minutes later
        ]
        assert list(detect(events, token_budget=200_000, window_minutes=5)) == []

    def test_wrong_vendor_name_still_processed(self):
        # The detector trusts events that carry class_uid 6002 + the unmapped fields.
        # A different vendor producing the same shape is still processed.
        events = [_ev("u", "m", 80_000, i * 60_000) for i in range(3)]
        for e in events:
            e["metadata"] = {"product": {"vendor_name": "other-vendor"}}
        assert len(list(detect(events))) == 1

    def test_native_output_shape(self):
        events = [_ev("u", "m", 80_000, i * 60_000) for i in range(3)]
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
        lines = ['{"not json"', '{"ok":true}']
        assert list(load_jsonl(lines)) == [{"ok": True}]
        assert "skipping line 1" in capsys.readouterr().err


class TestGoldenFixture:
    def test_exactly_one_finding_from_fixture(self):
        events = _load(INPUT_FIXTURE)
        findings = list(detect(events))
        assert len(findings) == 1

    def test_alice_fires_bob_does_not(self):
        events = _load(INPUT_FIXTURE)
        finding = list(detect(events))[0]
        obs = {o["name"]: o["value"] for o in finding["observables"]}
        assert obs["user.uid"] == "user-alice"

    def test_finding_matches_frozen_golden_exactly(self):
        events = _load(INPUT_FIXTURE)
        produced = list(detect(events))
        expected = _load(EXPECTED)
        assert len(produced) == len(expected)
        for p, e in zip(produced, expected):
            assert p == e
