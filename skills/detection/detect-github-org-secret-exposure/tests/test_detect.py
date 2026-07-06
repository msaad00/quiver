"""Tests for detect-github-org-secret-exposure."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "detect.py"
_SPEC = importlib.util.spec_from_file_location("detect_github_org_secret_exposure", _SRC)
assert _SPEC and _SPEC.loader
_DETECT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _DETECT
_SPEC.loader.exec_module(_DETECT)

ACCEPTED_PRODUCERS = _DETECT.ACCEPTED_PRODUCERS
API_ACTIVITY_CLASS_UID = _DETECT.API_ACTIVITY_CLASS_UID
DEFAULT_REPO_DELTA = _DETECT.DEFAULT_REPO_DELTA
FINDING_CLASS_UID = _DETECT.FINDING_CLASS_UID
FINDING_TYPE_UID = _DETECT.FINDING_TYPE_UID
GITHUB_VENDOR_FEATURE = _DETECT.GITHUB_VENDOR_FEATURE
MITRE_SUBTECHNIQUE_UID = _DETECT.MITRE_SUBTECHNIQUE_UID
MITRE_TECHNIQUE_UID = _DETECT.MITRE_TECHNIQUE_UID
ORG_SECRET_OPERATIONS = _DETECT.ORG_SECRET_OPERATIONS
OUTPUT_FORMATS = _DETECT.OUTPUT_FORMATS
OWASP_FINDING_TYPE = _DETECT.OWASP_FINDING_TYPE
SEVERITY_HIGH = _DETECT.SEVERITY_HIGH
SEVERITY_MEDIUM = _DETECT.SEVERITY_MEDIUM
SKILL_NAME = _DETECT.SKILL_NAME
coverage_metadata = _DETECT.coverage_metadata
detect = _DETECT.detect
load_jsonl = _DETECT.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "github_org_secret_exposure_input.ocsf.jsonl"
EXPECTED = GOLDEN / "github_org_secret_exposure_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "1001",
    actor_name: str = "alice",
    api_operation: str = "actions.org_secret_update",
    org: str = "acme",
    secret_name: str = "DEPLOY_KEY",
    visibility: str = "all",
    before_visibility: str = "selected",
    selected_repositories: list | None = None,
    before_selected_repositories: list | None = None,
    producer: str = GITHUB_VENDOR_FEATURE,
    status_id: int = 1,
) -> dict:
    if selected_repositories is None:
        selected_repositories = []
    if before_selected_repositories is None:
        before_selected_repositories = [101, 202, 303]
    github_block: dict = {
        "action": api_operation,
        "org": org,
        "secret_name": secret_name,
        "visibility": visibility,
        "before_visibility": before_visibility,
        "selected_repositories": selected_repositories,
        "before_selected_repositories": before_selected_repositories,
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
                "name": "cloud-ai-security-skills",
                "vendor_name": "msaad00/cloud-ai-security-skills",
                "feature": {"name": producer},
            },
        },
        "actor": {"user": {"uid": actor_uid, "name": actor_name}},
        "api": {"operation": api_operation, "service": {"name": "github.actions"}},
        "src_endpoint": {"ip": "203.0.113.20"},
        "unmapped": {"github": github_block},
    }


class TestDetection:
    def test_visibility_flip_to_all_fires_high(self) -> None:
        findings = list(detect([_event(uid="ev-flip", time_ms=1_000_000)]))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID == 2004
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_HIGH
        attack = f["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert attack["sub_technique"]["uid"] == MITRE_SUBTECHNIQUE_UID
        assert OWASP_FINDING_TYPE in f["finding_info"]["types"]
        assert "github-org-secret-exposure" in f["finding_info"]["types"]
        assert f["evidence"]["reason"] == "visibility_flip_to_all"

    def test_repo_expansion_past_threshold_fires_medium(self) -> None:
        findings = list(
            detect(
                [
                    _event(
                        uid="ev-expand",
                        time_ms=1_000,
                        visibility="selected",
                        before_visibility="selected",
                        before_selected_repositories=[1],
                        selected_repositories=[1, 2, 3, 4, 5, 6, 7, 8],  # +7
                    )
                ]
            )
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["severity_id"] == SEVERITY_MEDIUM
        assert f["evidence"]["reason"] == "selected_repositories_expanded"
        assert f["evidence"]["repo_delta"] == 7

    def test_repo_shrink_does_not_fire(self) -> None:
        events = [
            _event(
                uid="ev-shrink",
                time_ms=1_000,
                visibility="selected",
                before_visibility="selected",
                before_selected_repositories=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                selected_repositories=[1],
            )
        ]
        assert list(detect(events)) == []

    def test_repo_expansion_below_threshold_does_not_fire(self) -> None:
        events = [
            _event(
                uid="ev-small",
                time_ms=1_000,
                visibility="selected",
                before_visibility="selected",
                before_selected_repositories=[1],
                selected_repositories=[1, 2, 3, 4],  # +3, below default 5
            )
        ]
        assert list(detect(events)) == []

    def test_failed_event_does_not_fire(self) -> None:
        events = [_event(uid="ev-fail", time_ms=1_000, status_id=2)]
        assert list(detect(events)) == []

    def test_non_github_event_is_ignored(self) -> None:
        events = [_event(uid="ev-other", time_ms=1_000, producer="ingest-cloudtrail-ocsf")]
        assert list(detect(events)) == []

    def test_threshold_override_via_env(self, monkeypatch) -> None:
        monkeypatch.setenv("GITHUB_ORG_SECRET_REPO_DELTA", "10")
        events = [
            _event(
                uid="ev-th",
                time_ms=1_000,
                visibility="selected",
                before_visibility="selected",
                before_selected_repositories=[1],
                selected_repositories=list(range(1, 9)),  # +7, below override 10
            )
        ]
        assert list(detect(events)) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        events = [_event(uid="ev-dup", time_ms=1_000), _event(uid="ev-dup", time_ms=1_000)]
        assert len(list(detect(events))) == 1

    def test_native_output_format(self) -> None:
        findings = list(detect([_event(uid="ev-nat", time_ms=1_000)], output_format="native"))
        assert len(findings) == 1
        f = findings[0]
        assert f["schema_mode"] == "native"
        assert f["provider"] == "GitHub"
        assert "class_uid" not in f

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

    def test_codespaces_secret_operation_also_fires(self) -> None:
        findings = list(
            detect(
                [_event(uid="ev-cs", time_ms=1_000, api_operation="codespaces.org_secret_update")]
            )
        )
        assert len(findings) == 1

    def test_dependabot_secret_operation_also_fires(self) -> None:
        findings = list(
            detect([_event(uid="ev-dep", time_ms=1_000, api_operation="dependabot_secrets.update")])
        )
        assert len(findings) == 1

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
        assert "actions.org_secret_update" in ORG_SECRET_OPERATIONS
        assert DEFAULT_REPO_DELTA == 5
        assert OUTPUT_FORMATS == ("ocsf", "native")
        # Skill name is wired into the SkillContract surface.
        assert SKILL_NAME == "detect-github-org-secret-exposure"
