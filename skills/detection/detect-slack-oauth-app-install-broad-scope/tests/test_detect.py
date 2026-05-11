"""Tests for detect-slack-oauth-app-install-broad-scope."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "detect.py"
_SPEC = importlib.util.spec_from_file_location("detect_slack_oauth_app_install_broad_scope", _SRC)
assert _SPEC and _SPEC.loader
_DETECT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _DETECT
_SPEC.loader.exec_module(_DETECT)

ACCEPTED_PRODUCERS = _DETECT.ACCEPTED_PRODUCERS
ANCHOR_ACTIONS = _DETECT.ANCHOR_ACTIONS
API_ACTIVITY_CLASS_UID = _DETECT.API_ACTIVITY_CLASS_UID
FINDING_CLASS_UID = _DETECT.FINDING_CLASS_UID
FINDING_TYPE_UID = _DETECT.FINDING_TYPE_UID
MITRE_TECHNIQUE_UID = _DETECT.MITRE_TECHNIQUE_UID
OUTPUT_FORMATS = _DETECT.OUTPUT_FORMATS
OWASP_FINDING_TYPE = _DETECT.OWASP_FINDING_TYPE
READ_SCOPES = _DETECT.READ_SCOPES
REPO_NAME = _DETECT.REPO_NAME
REPO_VENDOR = _DETECT.REPO_VENDOR
SEVERITY_HIGH = _DETECT.SEVERITY_HIGH
SKILL_NAME = _DETECT.SKILL_NAME
WRITE_SCOPE = _DETECT.WRITE_SCOPE
coverage_metadata = _DETECT.coverage_metadata
detect = _DETECT.detect
load_jsonl = _DETECT.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "slack_oauth_app_install_broad_scope_input.ocsf.jsonl"
EXPECTED = GOLDEN / "slack_oauth_app_install_broad_scope_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int = 2_000_000,
    action: str = "app_installed",
    actor_uid: str = "U_INSTALLER",
    actor_name: str = "alice@example.com",
    app_id: str = "A0BROAD",
    app_name: str = "Notes Bot",
    scopes: list[str] | None = None,
    producer: str = "ingest-slack-audit-ocsf",
) -> dict:
    if scopes is None:
        scopes = ["chat:write", "files:read", "channels:read"]
    slack_block: dict = {
        "action": action,
        "app": {"id": app_id, "name": app_name, "is_distributed": True},
        "scopes": scopes,
    }
    return {
        "activity_id": 1,
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "type_uid": API_ACTIVITY_CLASS_UID * 100 + 1,
        "severity_id": 1,
        "status_id": 1,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": REPO_VENDOR,
                "feature": {"name": producer},
            },
        },
        "actor": {"user": {"uid": actor_uid, "name": actor_name, "type": "user"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"slack": slack_block},
    }


class TestDetection:
    def test_chat_write_plus_files_read_fires(self) -> None:
        findings = list(detect([_event(uid="b1")]))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert "chat:write" in finding["evidence"]["broad_scope_reason"] or "files:read" in finding["evidence"]["broad_scope_reason"]

    def test_wildcard_scope_fires(self) -> None:
        findings = list(detect([_event(uid="b2", scopes=["*:write"])]))
        assert len(findings) == 1
        assert "wildcard" in findings[0]["evidence"]["broad_scope_reason"]

    def test_app_approved_action_fires(self) -> None:
        findings = list(detect([_event(uid="b3", action="app_approved")]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["action"] == "app_approved"

    def test_preapproved_app_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv("SLACK_PREAPPROVED_APP_IDS", "A0BROAD,A0001")
        assert list(detect([_event(uid="b4")])) == []

    def test_narrow_scope_does_not_fire(self) -> None:
        # chat:read alone is not in our broad-scope rule
        assert list(detect([_event(uid="b5", scopes=["chat:read", "users:read"])])) == []

    def test_chat_write_without_read_does_not_fire(self) -> None:
        # chat:write alone, no read scope
        assert list(detect([_event(uid="b6", scopes=["chat:write"])])) == []

    def test_missing_scopes_is_ignored(self) -> None:
        assert list(detect([_event(uid="b7", scopes=[])])) == []

    def test_non_slack_producer_is_ignored(self) -> None:
        assert list(detect([_event(uid="b8", producer="ingest-cloudtrail-ocsf")])) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [_event(uid="dup"), _event(uid="dup")]
        assert len(list(detect(events))) == 1

    def test_native_output_format(self) -> None:
        findings = list(detect([_event(uid="b9")], output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["provider"] == "Slack"

    def test_scope_string_shape_is_accepted(self) -> None:
        # Some Slack payload shapes deliver scopes as a comma-joined string;
        # the ingester normalizes that, but the detector also has to be robust.
        event = _event(uid="b10")
        event["unmapped"]["slack"]["scopes"] = "chat:write,files:read"
        findings = list(detect([event]))
        assert len(findings) == 1

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected ContractError")

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("slack",)
        assert "app_installed" in metadata["attack_coverage"]["slack"]["anchor_actions"]
        assert WRITE_SCOPE == "chat:write"
        assert "files:read" in READ_SCOPES
        assert "ingest-slack-audit-ocsf" in ACCEPTED_PRODUCERS
        assert "app_installed" in ANCHOR_ACTIONS


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err
