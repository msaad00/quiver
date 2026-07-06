"""End-to-end integration test for the K8s container-escape detector pipeline."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_ROOT = REPO_ROOT / "skills"
INGESTION_DIR = SKILLS_ROOT / "ingestion"
DETECTION_DIR = SKILLS_ROOT / "detection"
GOLDEN_DIR = SKILLS_ROOT / "detection-engineering" / "golden"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"could not spec {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class TestK8sContainerEscapePipelineEndToEnd:
    def setup_method(self):
        self.ingest = _load_module(
            "_int_ingest_k8s_audit_ocsf_escape",
            INGESTION_DIR / "ingest-k8s-audit-ocsf" / "src" / "ingest.py",
        )
        self.detect = _load_module(
            "_int_detect_container_escape_k8s",
            DETECTION_DIR / "detect-container-escape-k8s" / "src" / "detect.py",
        )

    def test_raw_to_ocsf_to_findings_matches_frozen_golden(self):
        raw_lines = (GOLDEN_DIR / "k8s_container_escape_raw_sample.jsonl").read_text().splitlines()
        ocsf_events = list(self.ingest.ingest(raw_lines))
        assert len(ocsf_events) == 4

        findings = list(self.detect.detect(ocsf_events))
        expected = _load_jsonl(GOLDEN_DIR / "k8s_container_escape_findings.ocsf.jsonl")
        assert len(findings) == len(expected) == 3
        for produced, frozen in zip(findings, expected):
            assert produced == frozen, (
                f"K8s container-escape drift.\n"
                f"  produced: {json.dumps(produced, sort_keys=True)}\n"
                f"  frozen:   {json.dumps(frozen, sort_keys=True)}"
            )

    def test_findings_emit_detection_finding_2004(self):
        raw_lines = (GOLDEN_DIR / "k8s_container_escape_raw_sample.jsonl").read_text().splitlines()
        findings = list(self.detect.detect(self.ingest.ingest(raw_lines)))
        for finding in findings:
            assert finding["class_uid"] == 2004
            assert finding["type_uid"] == 200401
            assert finding["metadata"]["version"] == "1.8.0"

    def test_expected_mitre_techniques_present(self):
        raw_lines = (GOLDEN_DIR / "k8s_container_escape_raw_sample.jsonl").read_text().splitlines()
        findings = list(self.detect.detect(self.ingest.ingest(raw_lines)))
        techniques = {
            finding["finding_info"]["attacks"][0]["technique"]["uid"] for finding in findings
        }
        assert techniques == {"T1610", "T1611"}

    def test_followup_input_matches_frozen_followup_golden(self):
        ocsf_events = _load_jsonl(GOLDEN_DIR / "k8s_container_escape_followup_input.jsonl")
        findings = list(self.detect.detect(ocsf_events))
        expected = _load_jsonl(GOLDEN_DIR / "k8s_container_escape_followup_findings.ocsf.jsonl")
        assert len(findings) == len(expected) == 2
        for produced, frozen in zip(findings, expected):
            assert produced == frozen, (
                f"K8s container-escape follow-up drift.\n"
                f"  produced: {json.dumps(produced, sort_keys=True)}\n"
                f"  frozen:   {json.dumps(frozen, sort_keys=True)}"
            )

    def test_followup_findings_add_exec_and_runtime_techniques(self):
        findings = list(
            self.detect.detect(
                _load_jsonl(GOLDEN_DIR / "k8s_container_escape_followup_input.jsonl")
            )
        )
        techniques = {
            finding["finding_info"]["attacks"][0]["technique"]["uid"] for finding in findings
        }
        assert techniques == {"T1611", "T1613"}
