from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/detection/detect-sap-mass-change/src/detect.py"
spec = importlib.util.spec_from_file_location("sap_mass_change_detect", MODULE_PATH)
assert spec and spec.loader
detect_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect_mod
spec.loader.exec_module(detect_mod)


def _event(change_count: int = 12, minutes: int = 0, tx_code: str = "SM30") -> dict[str, object]:
    return {
        "class_uid": 6002,
        "time": 1780920000000 + minutes * 60 * 1000,
        "metadata": {
            "uid": f"sap-change-{minutes}-{change_count}",
            "product": {"feature": {"name": "ingest-sap-audit-log-ocsf"}},
        },
        "actor": {"user": {"uid": "100:FI_ADMIN", "name": "FI_ADMIN"}},
        "unmapped": {
            "sap": {
                "event_family": "change",
                "client": "100",
                "transaction_code": tx_code,
                "change_count": change_count,
            }
        },
    }


def test_detects_mass_change_in_window(monkeypatch) -> None:
    monkeypatch.setenv("SAP_MASS_CHANGE_EVENT_THRESHOLD", "20")
    stream = json.dumps(_event(12)) + "\n" + json.dumps(_event(13, minutes=4)) + "\n"

    findings = detect_mod.detect(StringIO(stream), output_format="native")

    assert len(findings) == 1
    assert findings[0]["evidence"]["change_count"] == 25
    assert findings[0]["mitre_attacks"][0]["technique_uid"] == "T1565"


def test_ignores_non_sensitive_transaction(monkeypatch) -> None:
    monkeypatch.setenv("SAP_MASS_CHANGE_EVENT_THRESHOLD", "1")

    assert (
        detect_mod.detect(
            StringIO(json.dumps(_event(5, tx_code="VA01")) + "\n"), output_format="native"
        )
        == []
    )


def test_cli_outputs_ocsf(tmp_path: Path) -> None:
    src = tmp_path / "events.jsonl"
    src.write_text(json.dumps(_event(30)) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "SAP_MASS_CHANGE_EVENT_THRESHOLD": "20"},
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["class_uid"] == 2004
    assert lines[0]["finding_info"]["attacks"][0]["technique"]["uid"] == "T1565"
