from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/detection/detect-mass-termination-anomaly/src/detect.py"
spec = importlib.util.spec_from_file_location("workday_mass_termination_detect", MODULE_PATH)
assert spec and spec.loader
detect_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect_mod
spec.loader.exec_module(detect_mod)


def _event(worker_id: int, batch_id: str = "batch-1", minutes: int = 0) -> dict[str, object]:
    return {
        "class_uid": 3001,
        "time": 1780754400000 + minutes * 60 * 1000,
        "metadata": {
            "uid": f"evt-{worker_id}",
            "product": {"feature": {"name": "ingest-workday-audit-ocsf"}},
        },
        "user": {"uid": f"W-{worker_id:04d}", "email_addr": f"worker{worker_id}@example.com"},
        "unmapped": {
            "workday": {
                "event_family": "termination",
                "worker_id": f"W-{worker_id:04d}",
                "worker_email": f"worker{worker_id}@example.com",
                "supervisory_org": "Engineering",
                "raw": {"batchId": batch_id},
            }
        },
    }


def test_detects_mass_termination_threshold(monkeypatch) -> None:
    monkeypatch.setenv("WORKDAY_TERMINATION_COUNT_THRESHOLD", "3")
    events = "\n".join(json.dumps(_event(i)) for i in range(1, 4)) + "\n"

    findings = detect_mod.detect(StringIO(events), output_format="native")

    assert len(findings) == 1
    assert findings[0]["evidence"]["termination_count"] == 3
    assert findings[0]["evidence"]["workers"][0] == "worker1@example.com"
    assert findings[0]["mitre_attacks"][0]["technique_uid"] == "T1098"


def test_ignores_events_below_threshold(monkeypatch) -> None:
    monkeypatch.setenv("WORKDAY_TERMINATION_COUNT_THRESHOLD", "4")
    events = "\n".join(json.dumps(_event(i)) for i in range(1, 4)) + "\n"

    assert detect_mod.detect(StringIO(events), output_format="native") == []


def test_ignores_approved_batch(monkeypatch) -> None:
    monkeypatch.setenv("WORKDAY_TERMINATION_COUNT_THRESHOLD", "3")
    monkeypatch.setenv("WORKDAY_APPROVED_TERMINATION_BATCH_IDS", "batch-1")
    events = "\n".join(json.dumps(_event(i)) for i in range(1, 4)) + "\n"

    assert detect_mod.detect(StringIO(events), output_format="native") == []


def test_cli_outputs_ocsf(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WORKDAY_TERMINATION_COUNT_THRESHOLD", "3")
    src = tmp_path / "workday-events.jsonl"
    src.write_text("\n".join(json.dumps(_event(i)) for i in range(1, 4)) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "WORKDAY_TERMINATION_COUNT_THRESHOLD": "3"},
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["class_uid"] == 2004
    assert lines[0]["finding_info"]["attacks"][0]["technique"]["uid"] == "T1098"
