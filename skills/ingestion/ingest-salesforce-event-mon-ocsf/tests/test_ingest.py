from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/ingestion/ingest-salesforce-event-mon-ocsf/src/ingest.py"
spec = importlib.util.spec_from_file_location("salesforce_event_mon_ingest", MODULE_PATH)
assert spec and spec.loader
ingest_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ingest_mod
spec.loader.exec_module(ingest_mod)


def _record(event_type: str = "ReportExport") -> dict[str, object]:
    return {
        "EVENT_TYPE": event_type,
        "TIMESTAMP": "2026-06-08T12:00:00.000Z",
        "USER_ID": "005xx000001",
        "USERNAME": "analyst@example.com",
        "CLIENT_IP": "198.51.100.20",
        "CLIENT_NAME": "DataLoader",
        "SESSION_KEY": "sess-1",
        "REQUEST_ID": "req-1",
        "ROWS_PROCESSED": "25000",
        "REPORT_ID": "00Oxx000001",
    }


def test_ingests_json_wrapper_as_application_activity() -> None:
    records = list(
        ingest_mod.ingest(StringIO(json.dumps({"records": [_record()]})), output_format="ocsf")
    )

    assert len(records) == 1
    event = records[0]
    assert event["class_uid"] == 6002
    assert event["class_name"] == "Application Activity"
    assert event["unmapped"]["salesforce"]["event_family"] == "export"
    assert event["unmapped"]["salesforce"]["rows_processed"] == 25000
    assert event["actor"]["user"]["email_addr"] == "analyst@example.com"


def test_ingests_event_log_csv() -> None:
    csv_payload = (
        "EVENT_TYPE,TIMESTAMP,USER_ID,USERNAME,CLIENT_IP,CLIENT_NAME,SESSION_KEY,REQUEST_ID,ROWS_PROCESSED\n"
        "API,2026-06-08T12:01:00.000Z,005xx000002,svc@example.com,203.0.113.9,PartnerApp,sess-2,req-2,5\n"
    )
    records = list(ingest_mod.ingest(StringIO(csv_payload), output_format="native"))

    assert len(records) == 1
    assert records[0]["schema_mode"] == "native"
    assert records[0]["salesforce"]["event_family"] == "api"
    assert records[0]["salesforce"]["client_name"] == "PartnerApp"


def test_skips_invalid_record() -> None:
    assert list(ingest_mod.ingest(StringIO(json.dumps({"foo": "bar"})), output_format="ocsf")) == []


def test_cli_outputs_jsonl(tmp_path: Path) -> None:
    src = tmp_path / "salesforce.json"
    src.write_text(json.dumps({"records": [_record("Logout")]}), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["metadata"]["product"]["feature"]["name"] == "ingest-salesforce-event-mon-ocsf"
    assert lines[0]["unmapped"]["salesforce"]["event_family"] == "logout"
