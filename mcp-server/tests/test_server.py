from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
GOLDEN_DIR = REPO_ROOT / "skills" / "detection-engineering" / "golden"


def _send_message(proc: subprocess.Popen[bytes], payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8"))
    proc.stdin.write(body)
    proc.stdin.flush()


def _read_message(proc: subprocess.Popen[bytes]) -> dict:
    headers: dict[str, str] = {}
    while True:
        line = proc.stdout.readline()
        assert line, proc.stderr.read().decode("utf-8")
        if line in (b"\r\n", b"\n"):
            break
        name, value = line.decode("utf-8").split(":", 1)
        headers[name.strip().lower()] = value.strip()
    length = int(headers["content-length"])
    return json.loads(proc.stdout.read(length).decode("utf-8"))


def _start_server() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, str(SERVER_PATH)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=REPO_ROOT,
    )


def _initialize(proc: subprocess.Popen[bytes]) -> None:
    _send_message(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    response = _read_message(proc)
    assert response["result"]["serverInfo"]["name"] == "cloud-ai-security-skills"
    _send_message(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})


class TestMcpServer:
    def test_tools_list_exposes_supported_skills(self):
        proc = _start_server()
        try:
            _initialize(proc)
            _send_message(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            response = _read_message(proc)
            names = {tool["name"] for tool in response["result"]["tools"]}
            assert "ingest-cloudtrail-ocsf" in names
            assert "ingest-entra-directory-audit-ocsf" in names
            assert "ingest-okta-system-log-ocsf" in names
            assert "ingest-google-workspace-login-ocsf" in names
            assert "detect-lateral-movement" in names
            assert "detect-okta-mfa-fatigue" in names
            assert "detect-entra-credential-addition" in names
            assert "detect-entra-role-grant-escalation" in names
            assert "detect-google-workspace-suspicious-login" in names
            assert "model-serving-security" in names
            assert "remediate-mcp-tool-quarantine" in names
            # iam-departures-{aws,azure-entra,gcp} are exposed via top-level
            # src/handler.py shims as of #411. --apply still refuses on
            # this surface; the destructive path is the deployed runner.
            assert "iam-departures-aws" in names
            assert "iam-departures-azure-entra" in names
            assert "iam-departures-gcp" in names
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_can_call_handler_based_remediation_in_dry_run_mode(self):
        proc = _start_server()
        try:
            _initialize(proc)
            finding = json.dumps(
                {
                    "class_uid": 2004,
                    "metadata": {
                        "uid": "find-1",
                        "product": {"feature": {"name": "detect-mcp-tool-drift"}},
                    },
                    "finding_info": {"uid": "find-1"},
                    "observables": [
                        {"name": "session.uid", "type": "Other", "value": "sess-1"},
                        {"name": "tool.name", "type": "Other", "value": "rogue-search"},
                        {
                            "name": "tool.after_fingerprint",
                            "type": "Fingerprint",
                            "value": "sha256:abcd",
                        },
                    ],
                }
            )
            _send_message(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "remediate-mcp-tool-quarantine",
                        "arguments": {
                            "input": finding,
                            "_approval_context": {
                                "approver_ids": ["ap-1", "ap-2"],
                                "approver_emails": ["lead@example.com", "commander@example.com"],
                                "ticket_id": "SEC-1",
                            },
                        },
                    },
                },
            )
            response = _read_message(proc)
            assert response["result"]["isError"] is False
            output_lines = [
                json.loads(line)
                for line in response["result"]["structuredContent"]["stdout"].splitlines()
                if line.strip()
            ]
            assert output_lines[0]["source_skill"] == "remediate-mcp-tool-quarantine"
            assert output_lines[0]["status"] == "planned"
            assert output_lines[0]["dry_run"] is True
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_can_call_ingest_detect_and_evaluate_tools(self, tmp_path: Path):
        proc = _start_server()
        try:
            _initialize(proc)

            raw_cloudtrail = (GOLDEN_DIR / "cloudtrail_raw_sample.jsonl").read_text()
            _send_message(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "ingest-cloudtrail-ocsf",
                        "arguments": {"input": raw_cloudtrail},
                    },
                },
            )
            ingest_response = _read_message(proc)
            assert ingest_response["result"]["isError"] is False
            ingest_lines = [
                json.loads(line)
                for line in ingest_response["result"]["structuredContent"]["stdout"].splitlines()
                if line.strip()
            ]
            assert ingest_lines[0]["class_uid"] == 6003

            detect_input = (GOLDEN_DIR / "lateral_movement_input.ocsf.jsonl").read_text()
            _send_message(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "detect-lateral-movement",
                        "arguments": {"input": detect_input},
                    },
                },
            )
            detect_response = _read_message(proc)
            assert detect_response["result"]["isError"] is False
            finding_lines = [
                json.loads(line)
                for line in detect_response["result"]["structuredContent"]["stdout"].splitlines()
                if line.strip()
            ]
            assert finding_lines[0]["class_uid"] == 2004

            config_path = tmp_path / "model-serving.json"
            config_path.write_text(
                json.dumps(
                    {
                        "endpoints": [
                            {
                                "name": "inference",
                                "auth": {
                                    "type": "oauth2",
                                    "enabled": True,
                                    "roles": ["admin", "user"],
                                    "identity": "svc-model-serving",
                                },
                                "rate_limit": {"enabled": True, "rpm": 100},
                                "limits": {"max_tokens": 4096},
                                "url": "https://model.internal:8443",
                                "visibility": "private",
                                "network": {"vpc": True, "private_endpoint": True},
                                "guardrails": {"enabled": True},
                                "logging": {"enabled": True},
                            }
                        ],
                        "containers": [
                            {
                                "name": "model",
                                "security_context": {
                                    "privileged": False,
                                    "readOnlyRootFilesystem": True,
                                    "runAsNonRoot": True,
                                    "runAsUser": 1000,
                                },
                            }
                        ],
                        "safety": {
                            "output_filter": True,
                            "prompt_injection": True,
                            "enabled": True,
                            "categories": ["violence", "hate", "self-harm", "sexual"],
                        },
                        "guardrails": {"enabled": True},
                        "logging": {"log_requests": True, "redact_pii": True},
                        "models": [{"name": "claude", "version": "3.5-sonnet-20241022"}],
                    }
                )
            )
            _send_message(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "model-serving-security",
                        "arguments": {"args": [str(config_path), "--output", "json"]},
                    },
                },
            )
            evaluate_response = _read_message(proc)
            assert evaluate_response["result"]["isError"] is False
            findings = json.loads(evaluate_response["result"]["structuredContent"]["stdout"])
            assert findings
            assert all(finding["status"] not in {"FAIL", "ERROR"} for finding in findings)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_can_request_native_output_for_supported_tools(self):
        proc = _start_server()
        try:
            _initialize(proc)

            raw_cloudtrail = (GOLDEN_DIR / "cloudtrail_raw_sample.jsonl").read_text()
            _send_message(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "ingest-cloudtrail-ocsf",
                        "arguments": {"input": raw_cloudtrail, "output_format": "native"},
                    },
                },
            )
            ingest_response = _read_message(proc)
            assert ingest_response["result"]["isError"] is False
            ingest_lines = [
                json.loads(line)
                for line in ingest_response["result"]["structuredContent"]["stdout"].splitlines()
                if line.strip()
            ]
            assert ingest_lines[0]["schema_mode"] == "native"
            assert "class_uid" not in ingest_lines[0]
            assert ingest_response["result"]["structuredContent"]["output_format"] == "native"
        finally:
            proc.terminate()
            proc.wait(timeout=5)
