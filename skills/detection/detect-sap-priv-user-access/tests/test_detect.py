from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
MODULE_PATH = ROOT / "skills/detection/detect-sap-priv-user-access/src/detect.py"
spec = importlib.util.spec_from_file_location("sap_priv_user_detect", MODULE_PATH)
assert spec and spec.loader
detect_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = detect_mod
spec.loader.exec_module(detect_mod)


def _event(user: str = "SAP*", profile: str = "SAP_ALL") -> dict[str, object]:
    return {
        "class_uid": 6002,
        "time": 1780920000000,
        "metadata": {
            "uid": "sap-priv-1",
            "product": {"feature": {"name": "ingest-sap-audit-log-ocsf"}},
        },
        "actor": {"user": {"uid": f"100:{user}", "name": user}},
        "src_endpoint": {"ip": "198.51.100.10"},
        "unmapped": {
            "sap": {
                "event_family": "login",
                "client": "100",
                "transaction_code": "SU01",
                "privilege_names": [profile],
            }
        },
    }


def test_detects_sap_all_login() -> None:
    findings = detect_mod.detect(StringIO(json.dumps(_event()) + "\n"), output_format="native")

    assert len(findings) == 1
    assert findings[0]["evidence"]["client"] == "100"
    assert findings[0]["mitre_attacks"][0]["technique_uid"] == "T1078"


def test_ignores_approved_privileged_user(monkeypatch) -> None:
    monkeypatch.setenv("SAP_APPROVED_PRIVILEGED_USERS", "100:SAP*")

    assert detect_mod.detect(StringIO(json.dumps(_event()) + "\n"), output_format="native") == []


def test_cli_outputs_ocsf(tmp_path: Path) -> None:
    src = tmp_path / "events.jsonl"
    src.write_text(json.dumps(_event("DDIC", "")) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), str(src)],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "SAP_PRIVILEGED_USERS": "DDIC"},
    )

    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["class_uid"] == 2004
    assert lines[0]["finding_info"]["attacks"][0]["technique"]["uid"] == "T1078"
