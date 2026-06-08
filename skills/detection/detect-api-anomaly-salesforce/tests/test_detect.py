from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/detection/detect-api-anomaly-salesforce/src/detect.py"
spec = importlib.util.spec_from_file_location("salesforce_api_anomaly_detect", MODULE_PATH)
assert spec and spec.loader
detect_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect_mod
spec.loader.exec_module(detect_mod)


def _event(idx: int, client: str = "UnknownClient", ip: str = "203.0.113.88") -> dict[str, object]:
    return {
        "class_uid": 6002,
        "time": 1780920000000 + idx * 1000,
        "metadata": {
            "uid": f"evt-api-{idx}",
            "product": {"feature": {"name": "ingest-salesforce-event-mon-ocsf"}},
        },
        "actor": {"user": {"uid": "005svc", "email_addr": "svc@example.com", "name": "svc@example.com"}},
        "src_endpoint": {"ip": ip},
        "api": {"operation": "query", "service": {"name": "salesforce.event_monitoring"}},
        "unmapped": {
            "salesforce": {
                "event_family": "api",
                "client_name": client,
                "operation": "query",
                "request_id": f"req-{idx}",
            }
        },
    }


def test_detects_client_outside_baseline(monkeypatch) -> None:
    baseline = {"005svc": {"client_names": ["ApprovedClient"], "ips": ["203.0.113.88"], "max_events": 100}}
    monkeypatch.setenv("SALESFORCE_API_BASELINE_JSON", json.dumps(baseline))
    stream = json.dumps(_event(1, client="UnknownClient")) + "\n"

    findings = detect_mod.detect(StringIO(stream), output_format="native")

    assert len(findings) == 1
    assert "client outside baseline" in findings[0]["evidence"]["reason"]
    assert findings[0]["mitre_attacks"][0]["technique_uid"] == "T1078.004"


def test_ignores_activity_inside_baseline(monkeypatch) -> None:
    baseline = {"005svc": {"client_names": ["ApprovedClient"], "ips": ["203.0.113.88"], "max_events": 100}}
    monkeypatch.setenv("SALESFORCE_API_BASELINE_JSON", json.dumps(baseline))
    stream = json.dumps(_event(1, client="ApprovedClient")) + "\n"

    assert detect_mod.detect(StringIO(stream), output_format="native") == []


def test_detects_no_baseline_high_event_count(monkeypatch) -> None:
    monkeypatch.setenv("SALESFORCE_API_ANOMALY_EVENT_THRESHOLD", "3")
    stream = "\n".join(json.dumps(_event(i, client="BatchJob")) for i in range(1, 4)) + "\n"

    findings = detect_mod.detect(StringIO(stream), output_format="native")

    assert len(findings) == 1
    assert findings[0]["evidence"]["event_count"] == 3


def test_cli_outputs_ocsf(tmp_path: Path) -> None:
    src = tmp_path / "events.jsonl"
    src.write_text(json.dumps(_event(1, client="UnknownClient")) + "\n", encoding="utf-8")
    baseline = json.dumps({"005svc": {"client_names": ["ApprovedClient"], "ips": ["203.0.113.88"], "max_events": 100}})

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "SALESFORCE_API_BASELINE_JSON": baseline},
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["class_uid"] == 2004
    assert lines[0]["finding_info"]["attacks"][0]["technique"]["uid"] == "T1078.004"
