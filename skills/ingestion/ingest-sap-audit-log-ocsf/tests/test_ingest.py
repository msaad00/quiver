from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/ingestion/ingest-sap-audit-log-ocsf/src/ingest.py"
spec = importlib.util.spec_from_file_location("sap_audit_log_ingest", MODULE_PATH)
assert spec and spec.loader
ingest_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ingest_mod
spec.loader.exec_module(ingest_mod)


def _record(message: str = "User SAP* successful logon with profile SAP_ALL") -> dict[str, object]:
    return {
        "timestamp": "2026-06-08T12:00:00Z",
        "client": "100",
        "user": "SAP*",
        "terminal": "jumpbox-1",
        "source_ip": "198.51.100.10",
        "transaction": "SU01",
        "message_id": "AUDIT_LOGON",
        "message_text": message,
        "profiles": "SAP_ALL",
    }


def test_ingests_json_wrapper_as_application_activity() -> None:
    records = list(
        ingest_mod.ingest(
            StringIO(json.dumps({"SecurityAuditLog": [_record()]})), output_format="ocsf"
        )
    )

    assert len(records) == 1
    event = records[0]
    assert event["class_uid"] == 6002
    assert event["class_name"] == "Application Activity"
    assert event["metadata"]["product"]["feature"]["name"] == "ingest-sap-audit-log-ocsf"
    assert event["unmapped"]["sap"]["event_family"] == "login"
    assert event["unmapped"]["sap"]["privileged"] is True
    assert event["actor"]["user"]["uid"] == "100:SAP*"


def test_ingests_csv_mass_change_row() -> None:
    csv_payload = (
        "timestamp,client,user,source_ip,transaction,message_text,change_count\n"
        "2026-06-08T12:01:00Z,200,FI_ADMIN,203.0.113.8,SM30,Table maintenance changed records,41\n"
    )
    records = list(ingest_mod.ingest(StringIO(csv_payload), output_format="native"))

    assert len(records) == 1
    event = records[0]
    assert event["schema_mode"] == "native"
    assert event["sap"]["event_family"] == "change"
    assert event["sap"]["transaction_code"] == "SM30"
    assert event["sap"]["change_count"] == 41


def test_ingests_pipe_delimited_text() -> None:
    payload = "2026-06-08|12:02:00|300|BASIS_ADMIN|10.0.0.4|PFCG|Role changed in production\n"
    records = list(ingest_mod.ingest(StringIO(payload), output_format="native"))

    assert len(records) == 1
    assert records[0]["sap"]["event_family"] == "change"
    assert records[0]["sap"]["client"] == "300"
    assert records[0]["sap"]["transaction_code"] == "PFCG"


def test_skips_invalid_record() -> None:
    assert list(ingest_mod.ingest(StringIO(json.dumps({"foo": "bar"})), output_format="ocsf")) == []


def test_cli_outputs_jsonl(tmp_path: Path) -> None:
    src = tmp_path / "sap-sal.json"
    src.write_text(
        json.dumps({"records": [_record("Transaction SU01 started by SAP* with SAP_ALL")]}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["metadata"]["product"]["feature"]["name"] == "ingest-sap-audit-log-ocsf"
    assert lines[0]["unmapped"]["sap"]["transaction_code"] == "SU01"
