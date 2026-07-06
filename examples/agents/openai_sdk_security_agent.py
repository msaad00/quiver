"""OpenAI Agents SDK — parallel of the Anthropic example for portability.

Shows the same three-stage pattern:

  1. Read-only CSPM + triage loop with a scoped MCP allowlist
  2. Stub HITL gate
  3. Dry-run remediation chain with `caller_context` + `approval_context`

The OpenAI Agents SDK surfaces MCP via
`openai.agents.McpServer(command=..., args=..., env=...)`. This example
demonstrates the wiring without pinning the SDK as a repo dep.

Prerequisites:

    uv sync --group dev --extra aws
    Configure OpenAI SDK credentials outside this repo if you run live SDK calls.

Run:

    python examples/agents/openai_sdk_security_agent.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER = REPO_ROOT / "mcp-server" / "src" / "server.py"

# Same read-only allowlist posture as the Anthropic example — any agent
# framework we ship docs for uses the same list.
ALLOWED_SKILLS_READ_ONLY = ",".join(
    [
        "cspm-aws-cis-benchmark",
        "cspm-gcp-cis-benchmark",
        "cspm-azure-cis-benchmark",
        "detect-lateral-movement",
        "detect-privilege-escalation-k8s",
        "convert-ocsf-to-sarif",
    ]
)


def build_mcp_config() -> dict[str, Any]:
    """The block you'd pass to `openai.agents.McpServer(...)` in a real loop."""
    return {
        "name": "cloud-ai-security-skills",
        "command": "python3",
        "args": [str(MCP_SERVER)],
        "env": {
            **os.environ,
            "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": ALLOWED_SKILLS_READ_ONLY,
            "PYTHONUNBUFFERED": "1",
        },
    }


def run_cspm_triage(caller_context: dict[str, str]) -> dict[str, Any]:
    """Equivalent to running an Agents-SDK loop against the MCP server.

    Real code (when the OpenAI Agents SDK is installed):

        from openai.agents import Agent, McpServer
        mcp = McpServer(**build_mcp_config())
        agent = Agent(
            model="gpt-5-2025-...",
            instructions="Perform a CSPM scan and summarize findings.",
            mcp_servers=[mcp],
        )
        result = agent.run(caller_context=caller_context)
    """
    audit = {
        "event": "mcp_tool_call",
        "tool": "cspm-aws-cis-benchmark",
        "correlation_id": "openai-demo-1",
        "caller_id": caller_context.get("user_id", "unknown"),
        "read_only": True,
        "result": "success",
    }
    sys.stderr.write(json.dumps(audit) + "\n")
    return {
        "stage": "triage",
        "findings_count": 2,
        "tool_config": build_mcp_config()["name"],
        "caller_context": caller_context,
    }


def human_approval_gate(_findings: dict[str, Any]) -> dict[str, str] | None:
    if os.environ.get("DEMO_APPROVE") != "yes":
        print("[HITL] No approval — skipping remediation chain.", file=sys.stderr)
        return None
    return {
        "approver_id": os.environ.get("DEMO_APPROVER", "operator@example.com"),
        "ticket_id": os.environ.get("DEMO_TICKET", "SEC-DEMO-2"),
        "approval_timestamp": "2026-04-18T12:00:00Z",
    }


def main() -> int:
    caller = {
        "user_id": "demo-operator",
        "email": "demo-operator@example.com",
        "session_id": "openai-demo-session-1",
        "roles": "security_engineer",
    }
    triage = run_cspm_triage(caller)
    print(json.dumps(triage, indent=2))
    approval = human_approval_gate(triage)
    if approval is None:
        return 0
    print(
        json.dumps(
            {
                "stage": "remediation_dry_run",
                "caller_context": caller,
                "approval_context": approval,
                "note": "In a real run this would shell into iam-departures-aws --dry-run",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
