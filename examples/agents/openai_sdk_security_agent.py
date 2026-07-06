"""OpenAI Agents SDK — parallel of the Anthropic example for portability.

Same three-stage pattern with harness-profile-driven customization:

  1. Read-only CSPM + triage via MCP stdio (discover tools/list)
  2. Stub HITL gate
  3. Dry-run remediation chain with caller_context + approval_context

The OpenAI Agents SDK surfaces MCP via
``openai.agents.McpServer(command=..., args=..., env=...)``. This example
demonstrates the wiring without pinning the SDK as a repo dep.

Prerequisites:

    uv sync --group dev --extra aws

Run:

    python examples/agents/openai_sdk_security_agent.py

    DEMO_APPROVE=yes python examples/agents/openai_sdk_security_agent.py
"""

from __future__ import annotations

import json
from typing import Any

from harness_mcp_transport import safe_mcp_env
from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    mcp_stdio_command,
    read_allowlist,
    run_cspm_triage,
)


def build_mcp_config(profile: dict[str, Any]) -> dict[str, Any]:
    """Block passed to ``openai.agents.McpServer(...)`` in a live Agents-SDK loop."""
    allowlist = read_allowlist(profile)
    return {
        "name": "cloud-ai-security-skills",
        "command": mcp_stdio_command()[0],
        "args": mcp_stdio_command()[1:],
        "env": safe_mcp_env(allowed_skills=allowlist),
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="openai-demo-1")
    triage["tool_config"] = build_mcp_config(profile)["name"]
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
