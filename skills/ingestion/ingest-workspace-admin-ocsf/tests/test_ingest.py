from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/ingestion/ingest-workspace-admin-ocsf/src/ingest.py"
spec = importlib.util.spec_from_file_location("workspace_admin_ingest", MODULE_PATH)
assert spec and spec.loader
ingest_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ingest_mod
spec.loader.exec_module(ingest_mod)


def _activity(
    application: str, event_name: str, params: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "id": {
            "time": "2026-06-06T04:00:00.000Z",
            "uniqueQualifier": f"{application}-{event_name}-1",
            "applicationName": application,
            "customerId": "C123",
        },
        "actor": {"email": "alice@example.com", "profileId": "1001", "callerType": "USER"},
        "ipAddress": "203.0.113.10",
        "ownerDomain": "example.com",
        "events": [{"type": "event", "name": event_name, "parameters": params}],
    }


def test_ingests_login_authentication_from_items_object() -> None:
    payload = {"items": [_activity("login", "login_success", [])]}
    records = list(ingest_mod.ingest(StringIO(json.dumps(payload)), output_format="ocsf"))

    assert len(records) == 1
    record = records[0]
    assert record["class_uid"] == 3002
    assert record["class_name"] == "Authentication"
    assert record["unmapped"]["google_workspace_admin"]["application_name"] == "login"


def test_ingests_token_authorize_as_account_change() -> None:
    payload = _activity(
        "token",
        "authorize",
        [
            {"name": "app_name", "value": "Risky CRM Sync"},
            {"name": "client_id", "value": "oauth-client-1"},
            {"name": "scope", "value": "https://www.googleapis.com/auth/drive.readonly"},
        ],
    )
    records = list(ingest_mod.ingest(StringIO(json.dumps(payload)), output_format="ocsf"))

    assert len(records) == 1
    record = records[0]
    assert record["class_uid"] == 3001
    assert record["class_name"] == "Account Change"
    assert record["resources"][0]["uid"] == "oauth-client-1"
    params = record["unmapped"]["google_workspace_admin"]["parameters"]
    assert params["scope"] == "https://www.googleapis.com/auth/drive.readonly"


def test_ingests_admin_role_grant_as_account_change() -> None:
    payload = _activity(
        "admin",
        "ASSIGN_ROLE",
        [
            {"name": "role_name", "value": "Super Admin"},
            {"name": "assigned_to", "value": "bob@example.com"},
        ],
    )
    records = list(ingest_mod.ingest(StringIO(json.dumps(payload)), output_format="native"))

    assert len(records) == 1
    record = records[0]
    assert record["record_type"] == "account_change"
    assert record["application_name"] == "admin"
    assert record["parameters"]["role_name"] == "Super Admin"
    assert record["user"]["email_addr"] == "bob@example.com"


def test_skips_unsupported_event() -> None:
    payload = _activity("admin", "CHANGE_CALENDAR_SETTING", [{"name": "setting", "value": "x"}])
    assert list(ingest_mod.ingest(StringIO(json.dumps(payload)), output_format="ocsf")) == []


def test_cli_outputs_jsonl(tmp_path: Path) -> None:
    src = tmp_path / "workspace.json"
    src.write_text(json.dumps(_activity("login", "logout", [])), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["activity_id"] == 2
