"""Shared wiring for Anthropic, OpenAI, and LangChain SDK reference examples.

Customization path: load a harness profile JSON, intersect with MCP
allowlists, and speak the repo MCP server over stdio JSON-RPC. Remediation
skills stay on a separate allowlist and chain — never mixed with read-only
tools in the same agent loop.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from harness_mcp_transport import safe_mcp_env

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER = REPO_ROOT / "mcp-server" / "src" / "server.py"
DEFAULT_PROFILE = Path(__file__).resolve().parent / "harness_profiles" / "sdk-cspm-agent.json"

# Separate remediation surface — never combine with read-only tools in one loop.
REMEDIATION_SKILL = "iam-departures-aws"


def _write_message(stream, message: dict[str, Any]) -> None:
    payload = json.dumps(message, sort_keys=True).encode("utf-8")
    stream.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8"))
    stream.write(payload)
    stream.flush()


def _read_message(stream, *, deadline: float) -> dict[str, Any]:
    headers: dict[str, str] = {}
    while True:
        timeout = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([stream], [], [], timeout)
        if not ready:
            raise TimeoutError("timed out waiting for MCP response header")
        line = stream.readline()
        if not line:
            raise RuntimeError("MCP server closed stdout before returning a response")
        if line in (b"\r\n", b"\n"):
            break
        key, value = line.decode("utf-8").split(":", 1)
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        raise RuntimeError("MCP response missing content-length")
    body = b""
    while len(body) < length:
        timeout = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([stream], [], [], timeout)
        if not ready:
            raise TimeoutError("timed out waiting for MCP response body")
        chunk = stream.read(length - len(body))
        if not chunk:
            raise RuntimeError("MCP server closed stdout before response body completed")
        body += chunk
    decoded = json.loads(body.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RuntimeError("MCP response payload must be a JSON object")
    return decoded


def load_sdk_profile(path: str | Path | None = None) -> dict[str, Any]:
    """Load operator profile metadata without reading credentials."""
    selected = path or os.environ.get("CLOUD_SECURITY_HARNESS_PROFILE") or DEFAULT_PROFILE
    payload = json.loads(Path(selected).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("harness profile must be a JSON object")
    return payload


def read_allowlist(profile: dict[str, Any]) -> list[str]:
    skills = profile.get("allowed_skills") or []
    return [skill for skill in skills if isinstance(skill, str) and skill.strip()]


def remediation_allowlist() -> list[str]:
    return [REMEDIATION_SKILL]


def caller_context_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
    caller = dict(profile.get("caller_context") or {})
    allowed = caller.get("allowed_skills") or profile.get("allowed_skills") or []
    if isinstance(allowed, str):
        allowed_skills = [part.strip() for part in allowed.split(",") if part.strip()]
    else:
        allowed_skills = [skill for skill in allowed if isinstance(skill, str) and skill.strip()]
    return {
        "user_id": str(caller.get("user_id", "sdk-agent")),
        "email": str(caller.get("email", "sdk-agent@example.com")),
        "session_id": str(caller.get("session_id", "sdk-demo-session")),
        "roles": str(caller.get("roles", "security_engineer")),
        "allowed_skills": allowed_skills,
    }


def mcp_stdio_command() -> list[str]:
    return [sys.executable, str(MCP_SERVER)]


def mcp_list_tool_names(
    allowlist: list[str],
    *,
    caller_context: dict[str, Any] | None = None,
) -> list[str]:
    """Discover tools exposed by the MCP server for the given allowlist."""
    if os.environ.get("DEMO_SKIP_MCP_DISCOVERY") == "yes":
        return sorted(allowlist)
    list_params: dict[str, Any] = {}
    if caller_context is not None:
        list_params["_caller_context"] = caller_context
    proc = subprocess.Popen(
        mcp_stdio_command(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=REPO_ROOT,
        env=safe_mcp_env(allowed_skills=allowlist),
        bufsize=0,
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None
        started = time.monotonic()
        deadline = started + 20

        def send(payload: dict[str, Any]) -> dict[str, Any] | None:
            _write_message(proc.stdin, payload)
            if "id" not in payload:
                return None
            return _read_message(proc.stdout, deadline=deadline)

        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        response = send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": list_params,
            }
        )
        assert response is not None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    tools = (response.get("result") or {}).get("tools") or []
    names = [tool["name"] for tool in tools if isinstance(tool, dict) and tool.get("name")]
    return sorted(names)


def emit_audit_event(
    *,
    tool: str,
    caller_context: dict[str, str],
    correlation_id: str,
    read_only: bool = True,
    result: str = "success",
) -> None:
    audit = {
        "event": "mcp_tool_call",
        "tool": tool,
        "correlation_id": correlation_id,
        "caller_id": caller_context.get("user_id", "unknown"),
        "read_only": read_only,
        "result": result,
    }
    sys.stderr.write(json.dumps(audit) + "\n")


def simulated_cspm_findings() -> list[dict[str, Any]]:
    """Deterministic stand-in when no cloud creds are configured."""
    return [
        {"finding": "CIS 2.1.1 bucket public", "severity_id": 4, "resource": "s3://demo"},
        {"finding": "CIS 1.4 root MFA", "severity_id": 5, "resource": "root"},
    ]


def run_cspm_triage(profile: dict[str, Any], *, correlation_id: str) -> dict[str, Any]:
    """Read-only triage: discover MCP tools, emit audit trail, return findings."""
    allowlist = read_allowlist(profile)
    caller = caller_context_from_profile(profile)
    tool_names = mcp_list_tool_names(allowlist, caller_context=caller)
    emit_audit_event(
        tool="cspm-aws-cis-benchmark",
        caller_context=caller,
        correlation_id=correlation_id,
        read_only=True,
    )
    findings = simulated_cspm_findings()
    return {
        "stage": "triage",
        "profile_id": profile.get("profile_id"),
        "mcp_tools_discovered": tool_names,
        "findings_count": len(findings),
        "high_severity": [finding for finding in findings if finding.get("severity_id", 0) >= 4],
        "caller_context": caller,
    }


def human_approval_gate(_findings: dict[str, Any]) -> dict[str, str] | None:
    if os.environ.get("DEMO_APPROVE") != "yes":
        print("[HITL] No approval present — skipping remediation chain.", file=sys.stderr)
        return None
    return {
        "approver_id": os.environ.get("DEMO_APPROVER", "operator@example.com"),
        "ticket_id": os.environ.get("DEMO_TICKET", "SEC-DEMO-1"),
        "approval_timestamp": "2026-07-06T12:00:00+00:00",
    }


def dry_run_remediation(
    caller_context: dict[str, str],
    approval_context: dict[str, str],
) -> dict[str, Any]:
    """Shell into the IAM departures reconciler in dry-run mode."""
    import subprocess

    cmd = [
        sys.executable,
        str(
            REPO_ROOT
            / "skills"
            / "remediation"
            / "iam-departures-aws"
            / "src"
            / "reconciler"
            / "handler.py"
        ),
        "--dry-run",
    ]
    env = safe_mcp_env(allowed_skills=remediation_allowlist())
    result = subprocess.run(
        cmd,
        input=json.dumps({"caller_context": caller_context, "approval_context": approval_context}),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )
    return {
        "stage": "remediation_dry_run",
        "skill": REMEDIATION_SKILL,
        "exit_code": result.returncode,
        "stdout_excerpt": (result.stdout or "")[:200],
        "approval": approval_context,
    }
