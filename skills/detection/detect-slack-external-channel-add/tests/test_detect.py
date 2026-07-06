"""Tests for detect-slack-external-channel-add."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "detect.py"
_SPEC = importlib.util.spec_from_file_location("detect_slack_external_channel_add", _SRC)
assert _SPEC and _SPEC.loader
_DETECT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _DETECT
_SPEC.loader.exec_module(_DETECT)

ACCEPTED_PRODUCERS = _DETECT.ACCEPTED_PRODUCERS
ANCHOR_ACTIONS = _DETECT.ANCHOR_ACTIONS
DEFAULT_SENSITIVE_PATTERN = _DETECT.DEFAULT_SENSITIVE_PATTERN
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
coverage_metadata = _DETECT.coverage_metadata
detect = _DETECT.detect
load_jsonl = _DETECT.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "slack_external_channel_add_input.ocsf.jsonl"
EXPECTED = GOLDEN / "slack_external_channel_add_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int = 1_000_000,
    action: str = "private_channel_member_added",
    actor_uid: str = "U_ADDER",
    actor_name: str = "alice@example.com",
    added_uid: str = "UEXT_GUEST",
    added_name: str = "eve@partner-corp.com",
    channel_name: str = "security-private",
    channel_id: str = "C_SEC_PRIV",
    workspace_type: str = "external",
    producer: str = "ingest-slack-audit-ocsf",
) -> dict:
    slack_block: dict = {
        "action": action,
        "workspace": {"type": "enterprise", "id": "E0001"},
    }
    if workspace_type:
        slack_block["workspace_type"] = workspace_type
    if channel_name or channel_id:
        slack_block["channel"] = {"id": channel_id, "name": channel_name}
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
        "actor": {"user": {"uid": actor_uid, "name": actor_name, "type": "user"}},
        "user": {"uid": added_uid, "name": added_name, "email_addr": added_name},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"slack": slack_block},
    }


class TestDetection:
    def test_external_add_to_sensitive_channel_fires(self) -> None:
        findings = list(detect([_event(uid="e1")]))
        assert len(findings) == 1
        finding = findings[0]
        assert finding["class_uid"] == FINDING_CLASS_UID == 2004
        assert finding["type_uid"] == FINDING_TYPE_UID
        assert finding["severity_id"] == SEVERITY_HIGH
        assert finding["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert OWASP_FINDING_TYPE in finding["finding_info"]["types"]
        assert finding["evidence"]["channel_name"] == "security-private"
        assert finding["evidence"]["workspace_type"] == "external"

    def test_workspace_user_added_external_fires(self) -> None:
        findings = list(
            detect(
                [
                    _event(
                        uid="e2",
                        action="workspace_user_added_to_workspace",
                        channel_name="exec-leadership",
                        channel_id="C_EXEC",
                    )
                ]
            )
        )
        assert len(findings) == 1
        assert findings[0]["evidence"]["action"] == "workspace_user_added_to_workspace"

    def test_internal_workspace_does_not_fire(self) -> None:
        events = [_event(uid="e3", workspace_type="internal")]
        assert list(detect(events)) == []

    def test_missing_workspace_type_does_not_fire(self) -> None:
        events = [_event(uid="e4", workspace_type="")]
        assert list(detect(events)) == []

    def test_external_add_to_non_sensitive_channel_does_not_fire(self) -> None:
        events = [_event(uid="e5", channel_name="random-chat", channel_id="C_RAND")]
        assert list(detect(events)) == []

    def test_missing_channel_name_does_not_fire(self) -> None:
        events = [_event(uid="e6", channel_name="", channel_id="")]
        assert list(detect(events)) == []

    def test_non_slack_producer_is_ignored(self) -> None:
        events = [_event(uid="e7", producer="ingest-okta-system-log-ocsf")]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [_event(uid="dup"), _event(uid="dup")]
        assert len(list(detect(events))) == 1

    def test_custom_pattern_env_override(self, monkeypatch) -> None:
        # The default pattern doesn't match `crown-jewels-product` — a custom regex should.
        events = [_event(uid="e8", channel_name="crown-jewels-product", channel_id="C_CJ")]
        assert list(detect(events)) == []
        monkeypatch.setenv("SLACK_SENSITIVE_CHANNEL_PATTERNS", r"(?i)crown-jewels")
        assert len(list(detect(events))) == 1

    def test_native_output_format(self) -> None:
        findings = list(detect([_event(uid="e9")], output_format="native"))
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
    def test_coverage_metadata(self) -> None:
        metadata = coverage_metadata()
        assert metadata["providers"] == ("slack",)
        assert (
            "private_channel_member_added" in metadata["attack_coverage"]["slack"]["anchor_actions"]
        )
        assert "ingest-slack-audit-ocsf" in ACCEPTED_PRODUCERS
        assert "private_channel_member_added" in ANCHOR_ACTIONS
        assert DEFAULT_SENSITIVE_PATTERN.startswith("(?i)")


class TestLoadJsonl:
    def test_skips_malformed(self, capsys) -> None:
        out = list(load_jsonl(['{"bad": ', '{"class_uid": 3005}']))
        assert out == [{"class_uid": 3005}]
        assert "skipping line 1" in capsys.readouterr().err
