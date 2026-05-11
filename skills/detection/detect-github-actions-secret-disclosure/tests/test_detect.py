"""Tests for detect-github-actions-secret-disclosure."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "detect.py"
_SPEC = importlib.util.spec_from_file_location("detect_github_actions_secret_disclosure", _SRC)
assert _SPEC and _SPEC.loader
_DETECT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _DETECT
_SPEC.loader.exec_module(_DETECT)

ACCEPTED_PRODUCERS = _DETECT.ACCEPTED_PRODUCERS
API_ACTIVITY_CLASS_UID = _DETECT.API_ACTIVITY_CLASS_UID
FINDING_CLASS_UID = _DETECT.FINDING_CLASS_UID
FINDING_TYPE_UID = _DETECT.FINDING_TYPE_UID
GITHUB_VENDOR_FEATURE = _DETECT.GITHUB_VENDOR_FEATURE
MIN_ENCODED_LENGTH = _DETECT.MIN_ENCODED_LENGTH
MITRE_SUBTECHNIQUE_UID = _DETECT.MITRE_SUBTECHNIQUE_UID
MITRE_TECHNIQUE_UID = _DETECT.MITRE_TECHNIQUE_UID
OUTPUT_FORMATS = _DETECT.OUTPUT_FORMATS
OWASP_FINDING_TYPE = _DETECT.OWASP_FINDING_TYPE
REDACTION_MARKER = _DETECT.REDACTION_MARKER
SEVERITY_CRITICAL = _DETECT.SEVERITY_CRITICAL
SKILL_NAME = _DETECT.SKILL_NAME
_find_high_entropy_candidates = _DETECT._find_high_entropy_candidates
_is_high_entropy = _DETECT._is_high_entropy
coverage_metadata = _DETECT.coverage_metadata
detect = _DETECT.detect
load_jsonl = _DETECT.load_jsonl

THIS = Path(__file__).resolve().parent
GOLDEN = THIS / "golden"
INPUT = GOLDEN / "github_actions_secret_disclosure_input.ocsf.jsonl"
EXPECTED = GOLDEN / "github_actions_secret_disclosure_findings.ocsf.jsonl"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# Pre-built encoded payloads (each 32+ chars, high-entropy).
HIGH_ENTROPY_B64 = base64.b64encode(b"my-deploy-key-shh-do-not-share-1234").decode("ascii")
HIGH_ENTROPY_HEX = "deadbeefcafef00d0123456789abcdef00112233"  # 40 hex chars
JWT_LIKE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJjaSIsImlhdCI6MTczNTY4OTYwMH0."
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"
)
LOW_ENTROPY = "a" * 64  # 64 chars, but Shannon = 0


def _event(
    *,
    uid: str,
    time_ms: int,
    actor_uid: str = "1001",
    actor_name: str = "alice",
    api_operation: str = "workflows.completed_workflow_run",
    repo: str = "acme/svc",
    workflow_id: str = "wf-100",
    workflow_status: str = "completed",
    log_excerpt: str = "",
    producer: str = GITHUB_VENDOR_FEATURE,
    status_id: int = 1,
) -> dict:
    github_block: dict = {
        "action": api_operation,
        "repo": repo,
        "workflow_id": workflow_id,
        "workflow_status": workflow_status,
        "workflow_log_excerpt": log_excerpt,
    }
    return {
        "activity_id": 99,
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": API_ACTIVITY_CLASS_UID,
        "class_name": "API Activity",
        "type_uid": API_ACTIVITY_CLASS_UID * 100 + 99,
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
        "src_endpoint": {"ip": "203.0.113.30"},
        "unmapped": {"github": github_block},
    }


class TestEntropyHelpers:
    def test_high_entropy_base64(self) -> None:
        assert _is_high_entropy(HIGH_ENTROPY_B64.encode("ascii"))

    def test_low_entropy_rejected(self) -> None:
        assert not _is_high_entropy(b"a" * 64)

    def test_too_short_rejected(self) -> None:
        assert not _is_high_entropy(b"short")
        assert MIN_ENCODED_LENGTH == 32

    def test_find_high_entropy_extracts_jwt(self) -> None:
        excerpt = f"::add-mask::*** token printed: {JWT_LIKE} done"
        hits = _find_high_entropy_candidates(excerpt)
        assert len(hits) >= 1
        assert JWT_LIKE in hits

    def test_find_high_entropy_extracts_base64(self) -> None:
        excerpt = f"::add-mask::*** value: {HIGH_ENTROPY_B64} done"
        hits = _find_high_entropy_candidates(excerpt)
        assert len(hits) >= 1


class TestDetection:
    def test_b64_disclosure_fires_critical(self) -> None:
        excerpt = (
            f"Step 1: echo $MY_SECRET | base64\n"
            f"redacted echo: {REDACTION_MARKER}\n"
            f"encoded form: {HIGH_ENTROPY_B64}\n"
        )
        findings = list(detect([_event(uid="ev-b64", time_ms=1_000_000, log_excerpt=excerpt)]))
        assert len(findings) == 1
        f = findings[0]
        assert f["class_uid"] == FINDING_CLASS_UID == 2004
        assert f["type_uid"] == FINDING_TYPE_UID
        assert f["severity_id"] == SEVERITY_CRITICAL
        attack = f["finding_info"]["attacks"][0]
        assert attack["technique"]["uid"] == MITRE_TECHNIQUE_UID
        assert attack["sub_technique"]["uid"] == MITRE_SUBTECHNIQUE_UID
        assert OWASP_FINDING_TYPE in f["finding_info"]["types"]

    def test_jwt_disclosure_fires(self) -> None:
        excerpt = f"Step 1: API call\nresponse: {REDACTION_MARKER} (auth) {JWT_LIKE}"
        findings = list(detect([_event(uid="ev-jwt", time_ms=1_000, log_excerpt=excerpt)]))
        assert len(findings) == 1

    def test_hex_disclosure_fires(self) -> None:
        excerpt = f"Mask hit: {REDACTION_MARKER} encoded as hex {HIGH_ENTROPY_HEX} bytes"
        findings = list(detect([_event(uid="ev-hex", time_ms=1_000, log_excerpt=excerpt)]))
        assert len(findings) == 1

    def test_redaction_marker_alone_does_not_fire(self) -> None:
        excerpt = f"Step 1: deploy\nMask hit: {REDACTION_MARKER} only marker, no encoded form"
        assert list(detect([_event(uid="ev-mark-only", time_ms=1_000, log_excerpt=excerpt)])) == []

    def test_high_entropy_alone_does_not_fire(self) -> None:
        excerpt = f"build log: {HIGH_ENTROPY_B64} no marker — secret was never in scope"
        assert list(detect([_event(uid="ev-ent-only", time_ms=1_000, log_excerpt=excerpt)])) == []

    def test_failed_workflow_run_does_not_fire(self) -> None:
        excerpt = f"redacted: {REDACTION_MARKER} encoded: {HIGH_ENTROPY_B64}"
        evt = _event(uid="ev-fail", time_ms=1_000, log_excerpt=excerpt, workflow_status="failure")
        assert list(detect([evt])) == []

    def test_low_entropy_candidate_does_not_fire(self) -> None:
        excerpt = f"redacted: {REDACTION_MARKER} value: {LOW_ENTROPY} which is repeated"
        assert list(detect([_event(uid="ev-low", time_ms=1_000, log_excerpt=excerpt)])) == []

    def test_non_github_event_is_ignored(self) -> None:
        excerpt = f"{REDACTION_MARKER} {HIGH_ENTROPY_B64}"
        assert list(
            detect(
                [
                    _event(
                        uid="ev-other",
                        time_ms=1_000,
                        log_excerpt=excerpt,
                        producer="ingest-cloudtrail-ocsf",
                    )
                ]
            )
        ) == []

    def test_duplicate_metadata_uid_does_not_inflate(self) -> None:
        excerpt = f"redacted: {REDACTION_MARKER} encoded: {HIGH_ENTROPY_B64}"
        evt = _event(uid="ev-dup", time_ms=1_000, log_excerpt=excerpt)
        assert len(list(detect([evt, evt]))) == 1

    def test_native_output_format(self) -> None:
        excerpt = f"redacted: {REDACTION_MARKER} encoded: {HIGH_ENTROPY_B64}"
        findings = list(
            detect([_event(uid="ev-nat", time_ms=1_000, log_excerpt=excerpt)], output_format="native")
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["schema_mode"] == "native"
        assert f["provider"] == "GitHub"
        assert f["severity"] == "critical"
        assert "class_uid" not in f

    def test_finding_preview_truncates_secret(self) -> None:
        excerpt = f"{REDACTION_MARKER} {HIGH_ENTROPY_B64}"
        findings = list(detect([_event(uid="ev-preview", time_ms=1_000, log_excerpt=excerpt)]))
        previews = findings[0]["evidence"]["previews"]
        assert previews
        # No preview should be the full secret.
        for preview in previews:
            assert HIGH_ENTROPY_B64 not in preview

    def test_malformed_payload_is_skipped(self, capsys) -> None:
        out = list(load_jsonl(['{"bad":', '{"class_uid": 6003}']))
        assert out == [{"class_uid": 6003}]
        assert "skipping line 1" in capsys.readouterr().err

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
        assert OUTPUT_FORMATS == ("ocsf", "native")
        assert SKILL_NAME == "detect-github-actions-secret-disclosure"
