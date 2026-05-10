"""Unit tests for the per-detector precision/recall scorer.

These tests exercise score.py without invoking real detector
subprocesses. Subprocess execution is covered by the smoke run in the
``detector-scoring`` GitHub Actions job.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCORE_PATH = REPO_ROOT / "skills" / "detection-engineering" / "scoring" / "score.py"
SPEC = importlib.util.spec_from_file_location("detection_scoring_score_under_test", SCORE_PATH)
assert SPEC and SPEC.loader
SCORE = importlib.util.module_from_spec(SPEC)
# Register in sys.modules before execution so @dataclass can resolve the
# module (Python 3.13's dataclasses internals look the module up by name).
sys.modules[SPEC.name] = SCORE
SPEC.loader.exec_module(SCORE)


def _entry(**overrides: Any) -> Any:
    base = {
        "detector_name": "detect-fake",
        "input_fixture": "skills/detection-engineering/scoring/fixtures/_does_not_matter.jsonl",
        "labels": {"a": True, "b": True, "c": False},
        "mode": "event_uid",
        "finding_event_uid_path": "evidence.raw_event_uids",
        "synthetic": True,
    }
    base.update(overrides)
    return SCORE.CorpusEntry.from_dict(base)


def test_perfect_precision_and_recall(monkeypatch: pytest.MonkeyPatch) -> None:
    findings = [
        {"evidence": {"raw_event_uids": ["a", "b"]}},
    ]
    monkeypatch.setattr(SCORE, "run_detector", lambda entry: findings)
    score = SCORE.score_entry(_entry())
    assert score.tp == 2
    assert score.fp == 0
    assert score.fn == 0
    assert score.precision == pytest.approx(1.0)
    assert score.recall == pytest.approx(1.0)
    assert score.f1 == pytest.approx(1.0)
    assert score.error is None


def test_missing_one_event_drops_recall(monkeypatch: pytest.MonkeyPatch) -> None:
    findings = [{"evidence": {"raw_event_uids": ["a"]}}]
    monkeypatch.setattr(SCORE, "run_detector", lambda entry: findings)
    score = SCORE.score_entry(_entry())
    assert score.tp == 1
    assert score.fp == 0
    assert score.fn == 1
    assert score.precision == pytest.approx(1.0)
    assert score.recall == pytest.approx(0.5)
    assert score.f1 == pytest.approx(2 / 3)


def test_firing_on_negative_label_is_a_false_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 'c' is in the corpus universe but labelled false. Detector
    # mistakenly fires on it -> one false positive.
    findings = [{"evidence": {"raw_event_uids": ["a", "b", "c"]}}]
    monkeypatch.setattr(SCORE, "run_detector", lambda entry: findings)
    score = SCORE.score_entry(_entry())
    assert score.tp == 2
    assert score.fp == 1
    assert score.fn == 0
    assert score.precision == pytest.approx(2 / 3)
    assert score.recall == pytest.approx(1.0)


def test_unlabelled_predictions_are_ignored_in_event_uid_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 'z' is not in the corpus at all; honest scoring leaves it alone
    # rather than flagging the detector for an event the corpus has no
    # opinion on.
    findings = [{"evidence": {"raw_event_uids": ["a", "b", "z"]}}]
    monkeypatch.setattr(SCORE, "run_detector", lambda entry: findings)
    score = SCORE.score_entry(_entry())
    assert score.tp == 2
    assert score.fp == 0
    assert score.fn == 0


def test_finding_uid_mode_counts_unknown_findings_as_fp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = [
        {"metadata": {"uid": "expected-1"}},
        {"metadata": {"uid": "rogue-finding"}},
    ]
    monkeypatch.setattr(SCORE, "run_detector", lambda entry: findings)
    entry = _entry(mode="finding_uid", labels={"expected-1": True})
    score = SCORE.score_entry(entry)
    assert score.tp == 1
    assert score.fp == 1
    assert score.fn == 0
    assert score.precision == pytest.approx(0.5)
    assert score.recall == pytest.approx(1.0)


def test_missing_fixture_returns_error_score(monkeypatch: pytest.MonkeyPatch) -> None:
    def _explode(entry: Any) -> Any:
        raise FileNotFoundError("input fixture not found: nope.jsonl")

    monkeypatch.setattr(SCORE, "run_detector", _explode)
    score = SCORE.score_entry(_entry())
    assert score.error is not None
    assert "fixture" in score.error
    # FN should reflect missed positives so the user notices.
    assert score.fn == 2
    assert score.precision == 0.0
    assert score.recall == 0.0


def test_aggregate_handles_mixed_results() -> None:
    scores = [
        SCORE.DetectorScore(
            detector_name="d1",
            mode="event_uid",
            tp=2,
            fp=1,
            fn=0,
            precision=2 / 3,
            recall=1.0,
            f1=0.8,
        ),
        SCORE.DetectorScore(
            detector_name="d2",
            mode="finding_uid",
            tp=1,
            fp=0,
            fn=1,
            precision=1.0,
            recall=0.5,
            f1=2 / 3,
        ),
    ]
    totals = SCORE.aggregate(scores)
    assert totals["tp"] == 3
    assert totals["fp"] == 1
    assert totals["fn"] == 1
    assert totals["detectors_scored"] == 2
    assert totals["detectors_errored"] == 0
    assert totals["precision"] == pytest.approx(0.75)
    assert totals["recall"] == pytest.approx(0.75)


def test_aggregate_reports_zero_on_empty_corpus() -> None:
    totals = SCORE.aggregate([])
    assert totals["tp"] == 0
    assert totals["fp"] == 0
    assert totals["fn"] == 0
    assert totals["precision"] == 0.0
    assert totals["recall"] == 0.0
    assert totals["f1"] == 0.0
    assert totals["detectors_scored"] == 0


def test_load_corpus_round_trips_yaml(tmp_path: Path) -> None:
    corpus_yaml = tmp_path / "corpus.yaml"
    corpus_yaml.write_text(
        "entries:\n"
        "  - detector_name: detect-foo\n"
        "    input_fixture: skills/x/fixture.jsonl\n"
        "    mode: event_uid\n"
        "    synthetic: true\n"
        "    labels:\n"
        "      a: true\n"
        "      b: false\n"
    )
    entries = SCORE.load_corpus(corpus_yaml)
    assert len(entries) == 1
    assert entries[0].detector_name == "detect-foo"
    assert entries[0].labels == {"a": True, "b": False}
    assert entries[0].mode == "event_uid"


def test_load_corpus_rejects_bad_mode(tmp_path: Path) -> None:
    corpus_yaml = tmp_path / "corpus.yaml"
    corpus_yaml.write_text(
        "entries:\n"
        "  - detector_name: detect-foo\n"
        "    input_fixture: x.jsonl\n"
        "    mode: not_a_real_mode\n"
        "    labels: {a: true}\n"
    )
    with pytest.raises(ValueError, match="unsupported mode"):
        SCORE.load_corpus(corpus_yaml)


def test_load_corpus_rejects_non_mapping_labels(tmp_path: Path) -> None:
    corpus_yaml = tmp_path / "corpus.yaml"
    corpus_yaml.write_text(
        "entries:\n"
        "  - detector_name: detect-foo\n"
        "    input_fixture: x.jsonl\n"
        "    labels: [a, b]\n"
    )
    with pytest.raises(ValueError, match="labels"):
        SCORE.load_corpus(corpus_yaml)


def test_render_markdown_includes_aggregate_row() -> None:
    scores = [
        SCORE.DetectorScore(
            detector_name="d1",
            mode="event_uid",
            tp=1,
            fp=0,
            fn=0,
            precision=1.0,
            recall=1.0,
            f1=1.0,
        ),
    ]
    totals = SCORE.aggregate(scores)
    md = SCORE.render_markdown(scores, totals)
    assert "| d1 |" in md
    assert "**aggregate**" in md
    assert "1.000" in md


def test_extract_event_uids_walks_dotted_path() -> None:
    findings = [
        {"evidence": {"raw_event_uids": ["a", "b"]}},
        {"evidence": {"raw_event_uids": ["b", "c"]}},
        {"evidence": {}},  # missing path is fine
        {},
    ]
    out = SCORE.extract_event_uids(findings, "evidence.raw_event_uids")
    assert out == {"a", "b", "c"}


def test_extract_event_uids_handles_string_value() -> None:
    findings = [{"correlation": {"event_uid": "single"}}]
    out = SCORE.extract_event_uids(findings, "correlation.event_uid")
    assert out == {"single"}


def test_main_writes_json_to_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_yaml = tmp_path / "corpus.yaml"
    corpus_yaml.write_text(
        "entries:\n"
        "  - detector_name: detect-foo\n"
        "    input_fixture: x.jsonl\n"
        "    mode: finding_uid\n"
        "    labels:\n"
        "      uid-good: true\n"
    )
    monkeypatch.setattr(
        SCORE, "run_detector", lambda entry: [{"metadata": {"uid": "uid-good"}}]
    )
    rc = SCORE.main(["--corpus", str(corpus_yaml)])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 0
    assert payload["aggregate"]["tp"] == 1
    assert payload["per_detector"][0]["detector_name"] == "detect-foo"


def test_main_returns_nonzero_when_detector_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_yaml = tmp_path / "corpus.yaml"
    corpus_yaml.write_text(
        "entries:\n"
        "  - detector_name: detect-broken\n"
        "    input_fixture: missing.jsonl\n"
        "    mode: finding_uid\n"
        "    labels:\n"
        "      uid-x: true\n"
    )

    def _explode(entry: Any) -> Any:
        raise FileNotFoundError("missing")

    monkeypatch.setattr(SCORE, "run_detector", _explode)
    rc = SCORE.main(["--corpus", str(corpus_yaml)])
    assert rc == 1
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["per_detector"][0]["error"]


def test_main_handles_empty_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_yaml = tmp_path / "corpus.yaml"
    corpus_yaml.write_text("entries: []\n")
    rc = SCORE.main(["--corpus", str(corpus_yaml)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["per_detector"] == []
    assert payload["aggregate"]["detectors_scored"] == 0


def test_main_filters_to_single_detector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus_yaml = tmp_path / "corpus.yaml"
    corpus_yaml.write_text(
        "entries:\n"
        "  - detector_name: detect-a\n"
        "    input_fixture: x.jsonl\n"
        "    mode: finding_uid\n"
        "    labels: {good-a: true}\n"
        "  - detector_name: detect-b\n"
        "    input_fixture: y.jsonl\n"
        "    mode: finding_uid\n"
        "    labels: {good-b: true}\n"
    )
    monkeypatch.setattr(
        SCORE,
        "run_detector",
        lambda entry: [{"metadata": {"uid": f"good-{entry.detector_name[-1]}"}}],
    )
    rc = SCORE.main(["--corpus", str(corpus_yaml), "--detector", "detect-b"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["per_detector"]) == 1
    assert payload["per_detector"][0]["detector_name"] == "detect-b"


def test_repository_corpus_loads_and_validates() -> None:
    """Smoke test: the shipped corpus.yaml must parse cleanly."""

    corpus_path = REPO_ROOT / "skills" / "detection-engineering" / "scoring" / "corpus.yaml"
    entries = SCORE.load_corpus(corpus_path)
    assert entries, "corpus.yaml must define at least one entry"
    detector_names = {e.detector_name for e in entries}
    # Issue #419 calls for at least three detectors at launch.
    assert len(detector_names) >= 3
    for entry in entries:
        # Honesty rule from skills/detection-engineering/golden/README.md.
        assert entry.synthetic is True, (
            f"{entry.detector_name}: corpus entry must declare synthetic: true "
            "until the captured-traffic corpus (#420) lands."
        )
        # Every input fixture must exist on disk.
        assert (REPO_ROOT / entry.input_fixture).exists(), (
            f"{entry.detector_name}: input_fixture {entry.input_fixture} not found"
        )
