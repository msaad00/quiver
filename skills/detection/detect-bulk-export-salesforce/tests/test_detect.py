from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/detection/detect-bulk-export-salesforce/src/detect.py"
spec = importlib.util.spec_from_file_location("salesforce_bulk_export_detect", MODULE_PATH)
assert spec and spec.loader
detect_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect_mod
spec.loader.exec_module(detect_mod)


def _event(family: str, rows: int = 25000, minutes: int = 0) -> dict[str, object]:
    return {
        "class_uid": 6002,
        "time": 1780920000000 + minutes * 60 * 1000,
        "metadata": {
            "uid": f"evt-{family}-{minutes}",
            "product": {"feature": {"name": "ingest-salesforce-event-mon-ocsf"}},
        },
        "actor": {
            "user": {
                "uid": "005xx000001",
                "email_addr": "analyst@example.com",
                "name": "analyst@example.com",
            }
        },
        "src_endpoint": {"ip": "198.51.100.20"},
        "session": {"uid": "sess-1"},
        "unmapped": {
            "salesforce": {
                "event_family": family,
                "client_name": "DataLoader",
                "rows_processed": rows,
                "bytes": 0,
                "session_key": "sess-1",
                "request_id": f"req-{family}",
            }
        },
    }


def test_detects_large_export_followed_by_logout(monkeypatch) -> None:
    monkeypatch.setenv("SALESFORCE_BULK_EXPORT_MIN_ROWS", "1000")
    stream = (
        json.dumps(_event("export")) + "\n" + json.dumps(_event("logout", rows=0, minutes=5)) + "\n"
    )

    findings = detect_mod.detect(StringIO(stream), output_format="native")

    assert len(findings) == 1
    assert findings[0]["evidence"]["rows_processed"] == 25000
    assert findings[0]["mitre_attacks"][0]["technique_uid"] == "T1567"


def test_ignores_approved_export_user(monkeypatch) -> None:
    monkeypatch.setenv("SALESFORCE_BULK_EXPORT_MIN_ROWS", "1000")
    monkeypatch.setenv("SALESFORCE_APPROVED_EXPORT_USERS", "005xx000001")
    stream = (
        json.dumps(_event("export")) + "\n" + json.dumps(_event("logout", rows=0, minutes=5)) + "\n"
    )

    assert detect_mod.detect(StringIO(stream), output_format="native") == []


def test_cli_outputs_ocsf(tmp_path: Path) -> None:
    src = tmp_path / "events.jsonl"
    src.write_text(
        json.dumps(_event("export"))
        + "\n"
        + json.dumps(_event("logout", rows=0, minutes=5))
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "SALESFORCE_BULK_EXPORT_MIN_ROWS": "1000"},
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["class_uid"] == 2004
    assert lines[0]["finding_info"]["attacks"][0]["technique"]["uid"] == "T1567"
