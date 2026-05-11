"""Tests for detect-github-pat-creation."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "detect.py"
_SPEC = importlib.util.spec_from_file_location("detect_github_pat_creation", _SRC)
assert _SPEC and _SPEC.loader
_DETECT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _DETECT
_SPEC.loader.exec_module(_DETECT)

ACCEPTED_PRODUCERS = _DETECT.ACCEPTED_PRODUCERS
API_ACTIVITY_CLASS_UID = _DETECT.API_ACTIVITY_CLASS_UID
FINDING_CLASS_UID = _DETECT.FINDING_CLASS_UID
FINDING_TYPE_UID = _DETECT.FINDING_TYPE_UID
GITHUB_VENDOR_FEATURE = _DETECT.GITHUB_VENDOR_FEATURE
KNOWN_PAT_OPERATIONS = _DETECT.KNOWN_PAT_OPERATIONS
MITRE_SUBTECHNIQUE_UID = _DETECT.MITRE_SUBTECHNIQUE_UID
MITRE_TECHNIQUE_UID = _DETECT.MITRE_TECHNIQUE_UID
OUTPUT_FORMATS = _DETECT.OUTPUT_FORMATS
OWASP_FINDING_TYPE = _DETECT.OWASP_FINDING_TYPE
PAT_CREATE_OPERATIONS = _DETECT.PAT_CREATE_OPERATIONS
REPO_NAME = _DETECT.REPO_NAME
SEVERITY_HIGH = _DETECT.SEVERITY_HIGH
SKILL_NAME = _DETECT.SKILL_NAME
coverage_metadata = _DETECT.coverage_metadata
detect = _DETECT.detect
load_jsonl = _DETECT.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "github_pat_creation_input.ocsf.jsonl"
EXPECTED = GOLDEN / "github_pat_creation_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "1001",
    actor_name: str = "alice",
    api_operation: str = "personal_access_token.access_granted",
    org: str = "acme",
    token_id: str = "tok-abc",
    programmatic_access_type: str = "fine_grained_personal_access_token",
    scopes: list[str] | None = None,
    producer: str = GITHUB_VENDOR_FEATURE,
    status_id: int = 1,
) -> dict:
    if scopes is None:
        scopes = ["repo", "workflow"]
    github_block: dict = {
        "action": api_operation,
        "org": org,
        "token_id": token_id,
        "programmatic_access_type": programmatic_access_type,
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
        "status_id": status_id,
        "time": time_ms,
        "metadata": {
            "version": "1.8.0",
            "uid": uid,
            "product": {
                "name": REPO_NAME,
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": producer},
            },
        },
        "actor": {"user": {"uid": actor_uid, "name": actor_name}},
        "api": {"operation": api_operation, "service": {"name": "github.personal_access_token"}},
        "src_endpoint": {"ip": "203.0.113.10"},
        "unmapped": {"github": github_block},
    }


class TestDetection:
    def test_access_granted_fires_once(self) -> None:
        findings = list(detect([_event(uid="ev-1", time_ms=1_000_000)]))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID == 2004
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        assert f["status_id"] == 1
        assert f["metadata"]["product"]["feature"]["name"] == SKILL_NAME
        attack = f["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert attack["sub_technique"]["uid"] == MITRE_SUBTECHNIQUE_UID
        assert OWASP_FINDING_TYPE in f["finding_info"]["types"]
        assert "github-pat-creation" in f["finding_info"]["types"]
        assert f["evidence"]["events_observed"] == 1
        assert f["evidence"]["org"] == "acme"

    def test_classic_pat_create_fires(self) -> None:
        findings = list(
            detect([_event(uid="ev-2", time_ms=1_000, api_operation="personal_access_token.create")])
        )
        assert len(findings) == 1

    def test_request_denied_does_not_fire(self) -> None:
        events = [_event(uid="ev-deny", time_ms=1_000, api_operation="personal_access_token.request_denied")]
        assert list(detect(events)) == []

    def test_failed_pat_create_does_not_fire(self) -> None:
        events = [_event(uid="ev-fail", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_non_github_event_is_ignored(self) -> None:
        events = [_event(uid="ev-other", time_ms=1_000, producer="ingest-cloudtrail-ocsf")]
        assert list(detect(events)) == []

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_multi_token_burst_fires_once_per_token(self) -> None:
        events = [
            _event(uid=f"ev-burst-{i}", time_ms=1_000 + i, token_id=f"tok-{i}")
            for i in range(4)
        ]
        findings = list(detect(events))
        assert len(findings) == 4
        uids = {f["metadata"]["uid"] for f in findings}
        assert len(uids) == 4

    def test_unmapped_pat_operation_emits_telemetry(self, capsys, monkeypatch) -> None:
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        events = [
            _event(uid="ev-future", time_ms=1_000, api_operation="personal_access_token.futureverb")
        ]
        assert list(detect(events)) == []
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["event"] == "unmapped_event_type"
        assert payload["api_operation"] == "personal_access_token.futureverb"
        assert payload["skill"] == SKILL_NAME

    def test_known_non_create_op_does_not_emit_unmapped(self, capsys) -> None:
        events = [
            _event(uid="ev-rev", time_ms=1_000, api_operation="personal_access_token.access_revoked")
        ]
        assert list(detect(events)) == []
        assert "unmapped_event_type" not in capsys.readouterr().err

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [_event(uid="ev-dup", time_ms=1_000), _event(uid="ev-dup", time_ms=1_000)]
        assert len(list(detect(events))) == 1

    def test_native_output_format(self) -> None:
        findings = list(detect([_event(uid="ev-nat", time_ms=1_000)], output_format="native"))
        assert len(findings) == 1
        f = findings[0]
        assert f["schema_mode"] == "native"
        assert f["record_type"] == "detection_finding"
        assert f["provider"] == "GitHub"
        assert "class_uid" not in f

    def test_rejects_unsupported_output_format(self) -> None:
        from skills._shared.errors import ContractError

        try:
            list(detect([], output_format="parquet"))
        except ContractError as exc:
            assert "unsupported output_format" in str(exc)
        else:
            raise AssertionError("expected unsupported output_format to raise")

    def test_missing_actor_is_skipped_with_telemetry(self, capsys, monkeypatch) -> None:
        monkeypatch.setenv("SKILL_LOG_FORMAT", "json")
        bad = _event(uid="ev-no-actor", time_ms=1_000)
        bad["actor"] = {"user": {}}
        assert list(detect([bad])) == []
        payload = json.loads(capsys.readouterr().err.strip())
        assert payload["event"] == "missing_actor"

    def test_golden_fixture_matches(self) -> None:
        findings = list(detect(_load(INPUT)))
        assert findings == _load(EXPECTED)


class TestMetadata:
    def test_coverage_metadata(self) -> None:
        m = coverage_metadata()
        assert m["providers"] == ("github",)
        assert MITRE_TECHNIQUE_UID in m["attack_coverage"]["github"]["techniques"]
        assert MITRE_SUBTECHNIQUE_UID in m["attack_coverage"]["github"]["techniques"]
        assert GITHUB_VENDOR_FEATURE in ACCEPTED_PRODUCERS
        assert "personal_access_token.create" in PAT_CREATE_OPERATIONS
        assert "personal_access_token.access_revoked" in KNOWN_PAT_OPERATIONS
        assert OUTPUT_FORMATS == ("ocsf", "native")
