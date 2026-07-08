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

from ide_mcp_bindings import build_openai_agents_mcp_server
from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    run_cspm_triage,
)


def openai_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    mcp_server = build_openai_agents_mcp_server(profile)
    return {
        "integration": "openai_agents_mcp_server",
        "config_path": "openai.agents.McpServer(...)",
        "docs": "docs/AGENT_QUICKSTART.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_openai_tools",
        "mcp_server": mcp_server,
        "remediation_chain": "separate_agent_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="openai-demo-1")
    binding = openai_binding_notes(profile)
    triage["openai_binding"] = binding
    triage["tool_config"] = binding["mcp_server"]["name"]
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
