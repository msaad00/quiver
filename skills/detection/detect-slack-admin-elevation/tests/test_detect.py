"""Tests for detect-slack-admin-elevation."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "detect.py"
_SPEC = importlib.util.spec_from_file_location("detect_slack_admin_elevation", _SRC)
assert _SPEC and _SPEC.loader
_DETECT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _DETECT
_SPEC.loader.exec_module(_DETECT)

ACCEPTED_PRODUCERS = _DETECT.ACCEPTED_PRODUCERS
ANCHOR_ACTIONS = _DETECT.ANCHOR_ACTIONS
DEFAULT_WINDOW = _DETECT.DEFAULT_WINDOW
FINDING_CLASS_UID = _DETECT.FINDING_CLASS_UID
FINDING_TYPE_UID = _DETECT.FINDING_TYPE_UID
MITRE_TECHNIQUE_UID = _DETECT.MITRE_TECHNIQUE_UID
OUTPUT_FORMATS = _DETECT.OUTPUT_FORMATS
OWASP_FINDING_TYPE = _DETECT.OWASP_FINDING_TYPE
REPO_NAME = _DETECT.REPO_NAME
REPO_VENDOR = _DETECT.REPO_VENDOR
SEVERITY_HIGH = _DETECT.SEVERITY_HIGH
SKILL_NAME = _DETECT.SKILL_NAME
USER_ACCESS_CLASS_UID = _DETECT.USER_ACCESS_CLASS_UID
_parse_window = _DETECT._parse_window
coverage_metadata = _DETECT.coverage_metadata
detect = _DETECT.detect
load_jsonl = _DETECT.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "slack_admin_elevation_input.ocsf.jsonl"
EXPECTED = GOLDEN / "slack_admin_elevation_findings.ocsf.jsonl"

# In-window UTC time: 2024-06-14T12:00:00Z
IN_WINDOW_MS = 1_718_366_400_000
# Out-of-window UTC time: 2024-06-14T00:03:20Z
OUT_WINDOW_MS = 1_718_323_400_000


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int = IN_WINDOW_MS,
    action: str = "role_change_to_admin",
    granter_uid: str = "U_GRANTER",
    granter_name: str = "alice@example.com",
    grantee_uid: str = "U_GRANTEE",
    grantee_name: str = "bob@example.com",
    new_role: str = "admin",
    producer: str = "ingest-slack-audit-ocsf",
) -> dict:
    slack_block: dict = {
        "action": action,
        "new_role": new_role,
        "previous_role": "user",
    }
    return {
        "activity_id": 1,
        "category_uid": 3,
        "category_name": "Identity & Access Management",
        "class_uid": USER_ACCESS_CLASS_UID,
        "class_name": "User Access Management",
        "type_uid": USER_ACCESS_CLASS_UID * 100 + 1,
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
        "actor": {"user": {"uid": granter_uid, "name": granter_name, "type": "user"}},
        "user": {"uid": grantee_uid, "name": grantee_name, "email_addr": grantee_name},
        "unmapped": {"slack": slack_block},
    }


class TestDetection:
    def test_unauthorized_granter_in_window_fires(self, monkeypatch) -> None:
        monkeypatch.setenv("SLACK_AUTHORIZED_GRANTERS", "U_BREAKGLASS,U_SECOPS_BOT")
        findings = list(detect([_event(uid="a1")]))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["allowlist_mode"] == "enforced-violation"
        assert finding["evidence"]["new_role"] == "admin"

    def test_authorized_granter_in_window_does_not_fire(self, monkeypatch) -> None:
        monkeypatch.setenv("SLACK_AUTHORIZED_GRANTERS", "U_BREAKGLASS,U_SECOPS_BOT")
        assert list(detect([_event(uid="a2", granter_uid="U_BREAKGLASS")])) == []

    def test_authorized_granter_outside_window_still_fires(self, monkeypatch) -> None:
        monkeypatch.setenv("SLACK_AUTHORIZED_GRANTERS", "U_BREAKGLASS")
        findings = list(
            detect([_event(uid="a3", granter_uid="U_BREAKGLASS", time_ms=OUT_WINDOW_MS)])
        )
        assert len(findings) == 1
        assert findings[0]["evidence"]["window_violation"] is True
        assert findings[0]["evidence"]["allowlist_mode"] == "enforced-window-only"

    def test_fail_open_fires_on_every_grant(self) -> None:
        # No env var → fail-open
        findings = list(detect([_event(uid="a4", granter_uid="ANY_USER")]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["allowlist_mode"] == "fail-open"

    def test_role_change_to_owner_fires(self, monkeypatch) -> None:
        monkeypatch.setenv("SLACK_AUTHORIZED_GRANTERS", "U_BREAKGLASS")
        findings = list(detect([_event(uid="a5", action="role_change_to_owner", new_role="owner")]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["new_role"] == "owner"

    def test_non_slack_producer_is_ignored(self) -> None:
        assert list(detect([_event(uid="a6", producer="ingest-okta-system-log-ocsf")])) == []

    def test_role_change_to_user_is_ignored(self, monkeypatch) -> None:
        # Demotions aren't admin elevations.
        monkeypatch.setenv("SLACK_AUTHORIZED_GRANTERS", "U_BREAKGLASS")
        event = _event(uid="a7", action="role_change_to_user", new_role="user")
        assert list(detect([event])) == []

    def test_custom_window_env_override(self, monkeypatch) -> None:
        monkeypatch.setenv("SLACK_AUTHORIZED_GRANTERS", "U_GRANTER")
        # 12 UTC is inside 08-18 default, but outside a custom 14-18 window.
        monkeypatch.setenv("SLACK_GRANT_WINDOW_HOURS_UTC", "14-18")
        findings = list(detect([_event(uid="a8", granter_uid="U_GRANTER")]))
        assert len(findings) == 1
        assert findings[0]["evidence"]["change_window_utc"] == "14-18"

    def test_invalid_window_falls_back_to_default(self) -> None:
        assert _parse_window("not-a-window") == (8, 18)
        assert _parse_window("99-100") == (8, 18)

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [_event(uid="dup"), _event(uid="dup")]
        assert len(list(detect(events))) == 1

    def test_native_output_format(self) -> None:
        findings = list(detect([_event(uid="a9")], output_format="native"))
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert len(findings) == 1
        assert findings[0]["schema_mode"] == "native"
        assert findings[0]["provider"] == "Slack"

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
    def test_coverage_metadata_defaults(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("slack",)
        assert "role_change_to_admin" in metadata["attack_coverage"]["slack"]["anchor_actions"]
        assert "ingest-slack-audit-ocsf" in ACCEPTED_PRODUCERS
        assert "role_change_to_owner" in ANCHOR_ACTIONS
        assert DEFAULT_WINDOW == "08-18"
        assert metadata["thresholds"]["allowlist_mode"] == "fail-open"


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 3005}']))
        assert out == [{"class_uid": 3005}]
        assert "skipping line 1" in capsys.readouterr().err
