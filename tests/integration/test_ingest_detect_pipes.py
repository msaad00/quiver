"""Golden ingest→detect pipe tests (#607)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipe_harness import (  # noqa: E402
    GOLDEN_DIR,
    IngestDetectPipe,
    load_jsonl,
    run_ingest_detect_pipe,
)

INGEST_DETECT_PIPES = (
    IngestDetectPipe(
        name="mcp_tool_drift",
        ingest_skill="ingest-mcp-proxy-ocsf",
        detect_skill="detect-mcp-tool-drift",
        raw_fixture="mcp_proxy_raw_sample.jsonl",
        expected_fixture="tool_drift_finding.ocsf.jsonl",
        expected_ocsf_count=7,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="mcp_prompt_injection",
        ingest_skill="ingest-mcp-proxy-ocsf",
        detect_skill="detect-prompt-injection-mcp-proxy",
        raw_fixture="mcp_prompt_injection_raw.jsonl",
        expected_fixture="mcp_prompt_injection_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=2,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="entra_credential_addition",
        ingest_skill="ingest-entra-directory-audit-ocsf",
        detect_skill="detect-entra-credential-addition",
        raw_fixture="entra_directory_audit_raw_sample.json",
        expected_fixture="entra_credential_addition_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="google_workspace_suspicious_login",
        ingest_skill="ingest-google-workspace-login-ocsf",
        detect_skill="detect-google-workspace-suspicious-login",
        raw_fixture="google_workspace_login_raw_sample.json",
        expected_fixture="google_workspace_suspicious_login_pipe_findings.ocsf.jsonl",
        raw_json_document=True,
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="cloudtrail_access_key_creation",
        ingest_skill="ingest-cloudtrail-ocsf",
        detect_skill="detect-aws-access-key-creation",
        raw_fixture="cloudtrail_raw_sample.jsonl",
        expected_fixture="cloudtrail_access_key_creation_pipe_findings.ocsf.jsonl",
        expected_finding_count=1,
    ),
    IngestDetectPipe(
        name="k8s_sensitive_secret_read",
        ingest_skill="ingest-k8s-audit-ocsf",
        detect_skill="detect-sensitive-secret-read-k8s",
        raw_fixture="k8s_audit_raw_sample.jsonl",
        expected_fixture="k8s_sensitive_secret_read_pipe_findings.ocsf.jsonl",
        expected_ocsf_count=5,
        expected_finding_count=1,
    ),
)


@pytest.mark.parametrize("pipe", INGEST_DETECT_PIPES, ids=lambda p: p.name)
class TestIngestDetectGoldenPipes:
    def test_raw_to_findings_matches_frozen_golden(self, pipe: IngestDetectPipe):
        ocsf_events, findings = run_ingest_detect_pipe(pipe)
        expected = load_jsonl(GOLDEN_DIR / pipe.expected_fixture)

        if pipe.expected_ocsf_count is not None:
            assert len(ocsf_events) == pipe.expected_ocsf_count

        if pipe.expected_finding_count is not None:
            assert len(findings) == pipe.expected_finding_count == len(expected), (
                f"{pipe.name}: finding count drift (produced {len(findings)}, "
                f"expected {len(expected)})"
            )

        for produced, expected_f in zip(findings, expected):
            assert produced == expected_f, (
                f"{pipe.name}: wire-contract drift between {pipe.ingest_skill} and "
                f"{pipe.detect_skill}.\n"
                f"  produced: {json.dumps(produced, sort_keys=True)}\n"
                f"  expected: {json.dumps(expected_f, sort_keys=True)}"
            )

    def test_findings_use_detection_finding_class_uid(self, pipe: IngestDetectPipe):
        _, findings = run_ingest_detect_pipe(pipe)
        for finding in findings:
            assert finding["class_uid"] == 2004
            assert finding["metadata"]["version"] == "1.8.0"
            assert "attacks" not in finding
            assert "attacks" in finding["finding_info"]
