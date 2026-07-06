from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/detection/detect-suspicious-oauth-grant-workspace/src/detect.py"
spec = importlib.util.spec_from_file_location("workspace_oauth_detect", MODULE_PATH)
assert spec and spec.loader
detect_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect_mod
spec.loader.exec_module(detect_mod)


def _event(scope: str = "https://www.googleapis.com/auth/drive.readonly") -> dict[str, object]:
    return {
        "class_uid": 3001,
        "time": 1780708800000,
        "metadata": {
            "uid": "evt-1",
            "product": {"feature": {"name": "ingest-workspace-admin-ocsf"}},
        },
        "actor": {
            "user": {"uid": "1001", "email_addr": "alice@example.com", "name": "alice@example.com"}
        },
        "unmapped": {
            "google_workspace_admin": {
                "application_name": "token",
                "event_name": "authorize",
                "parameters": {
                    "app_name": "Risky CRM Sync",
                    "client_id": "oauth-client-1",
                    "scope": scope,
                },
            }
        },
    }


def test_detects_high_risk_oauth_scope() -> None:
    findings = detect_mod.detect(StringIO(json.dumps(_event()) + "\n"), output_format="native")

    assert len(findings) == 1
    assert findings[0]["evidence"]["client_id"] == "oauth-client-1"
    assert findings[0]["mitre_attacks"][0]["technique_uid"] == "T1550.001"


def test_ignores_preapproved_client(monkeypatch) -> None:
    monkeypatch.setenv("WORKSPACE_PREAPPROVED_OAUTH_CLIENT_IDS", "oauth-client-1")

    findings = detect_mod.detect(StringIO(json.dumps(_event()) + "\n"), output_format="native")

    assert findings == []


def test_ignores_low_risk_scope() -> None:
    event = _event("openid email profile")

    findings = detect_mod.detect(StringIO(json.dumps(event) + "\n"), output_format="native")

    assert findings == []


def test_cli_outputs_ocsf(tmp_path: Path) -> None:
    src = tmp_path / "events.jsonl"
    src.write_text(json.dumps(_event()) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["class_uid"] == 2004
    assert lines[0]["finding_info"]["attacks"][0]["technique"]["uid"] == "T1550.001"
