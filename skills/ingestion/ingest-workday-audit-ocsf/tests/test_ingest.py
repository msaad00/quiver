from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/ingestion/ingest-workday-audit-ocsf/src/ingest.py"
spec = importlib.util.spec_from_file_location("workday_audit_ingest", MODULE_PATH)
assert spec and spec.loader
ingest_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ingest_mod
spec.loader.exec_module(ingest_mod)


def _termination(
    worker_id: str = "W-1001", email: str = "departed@example.com"
) -> dict[str, object]:
    return {
        "eventName": "Terminate Employee",
        "eventTime": "2026-06-06T14:30:00Z",
        "workerId": worker_id,
        "workerEmail": email,
        "businessProcess": "Terminate Employee",
        "supervisoryOrg": "Engineering",
        "terminationDate": "2026-06-06",
        "reason": "Voluntary",
        "initiatedBy": {"id": "hr-admin-1", "emailAddress": "hr@example.com"},
        "batchId": "offboarding-2026-06-06",
    }


def test_ingests_workday_report_entry_as_account_change() -> None:
    payload = {"Report_Entry": [_termination()]}
    records = list(ingest_mod.ingest(StringIO(json.dumps(payload)), output_format="ocsf"))

    assert len(records) == 1
    record = records[0]
    assert record["class_uid"] == 3001
    assert record["class_name"] == "Account Change"
    assert record["activity_id"] == 4
    assert record["user"]["uid"] == "W-1001"
    assert record["user"]["email_addr"] == "departed@example.com"
    assert record["unmapped"]["workday"]["event_family"] == "termination"
    assert record["unmapped"]["workday"]["raw"]["batchId"] == "offboarding-2026-06-06"


def test_native_projection_preserves_workday_fields() -> None:
    records = list(ingest_mod.ingest(StringIO(json.dumps(_termination())), output_format="native"))

    assert len(records) == 1
    record = records[0]
    assert record["schema_mode"] == "native"
    assert record["record_type"] == "account_change"
    assert record["event_family"] == "termination"
    assert record["workday"]["business_process"] == "Terminate Employee"
    assert record["actor"]["user"]["email_addr"] == "hr@example.com"


def test_ingests_jsonl_data_wrapper() -> None:
    payload = {"data": [_termination("W-1002", "worker2@example.com")]}
    records = list(ingest_mod.ingest(StringIO(json.dumps(payload) + "\n"), output_format="ocsf"))

    assert len(records) == 1
    assert records[0]["user"]["email_addr"] == "worker2@example.com"


def test_skips_invalid_record() -> None:
    assert (
        list(ingest_mod.ingest(StringIO(json.dumps({"not": "workday"})), output_format="ocsf"))
        == []
    )


def test_cli_outputs_jsonl(tmp_path: Path) -> None:
    src = tmp_path / "workday.json"
    src.write_text(json.dumps({"Report_Entry": [_termination()]}), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["metadata"]["product"]["feature"]["name"] == "ingest-workday-audit-ocsf"
