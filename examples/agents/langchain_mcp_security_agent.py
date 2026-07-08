"""LangChain agents — MCP interoperability pattern (not LCEL skill wrappers).

Supported integration path for LangChain, LangGraph, and other agent frameworks:

  1. Spawn the repo MCP server as a stdio JSON-RPC subprocess.
  2. Bind MCP ``tools/list`` results to your agent (``langchain-mcp-adapters``,
     OpenAI Agents SDK ``McpServer``, Anthropic MCP config, etc.).
  3. Never re-wrap skill CLIs as ``@tool`` decorators or LCEL chains — that
     forks the audit contract, HITL gates, and allowlist enforcement.

This reference runs offline: it loads a harness profile, discovers tools via
live MCP, and stops at the HITL gate unless ``DEMO_APPROVE=yes``.

Real LangChain wiring (when ``langchain-mcp-adapters`` is installed):

    from langchain_mcp_adapters.client import MultiServerMCPClient

    client = MultiServerMCPClient(build_langchain_mcp_servers(profile))
    tools = await client.get_tools()
    agent = create_react_agent(model, tools)  # framework-specific

Run:

    python examples/agents/langchain_mcp_security_agent.py

    DEMO_APPROVE=yes python examples/agents/langchain_mcp_security_agent.py
"""

from __future__ import annotations

import json
from typing import Any

from ide_mcp_bindings import build_langchain_mcp_servers
from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    run_cspm_triage,
)


def langchain_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    """Operator-facing metadata — no live LangChain import required."""
    return {
        "integration": "mcp_stdio_jsonrpc",
        "anti_pattern": "do_not_wrap_skill_clis_as_langchain_tools",
        "recommended_packages": ["langchain-mcp-adapters", "langgraph"],
        "mcp_servers": build_langchain_mcp_servers(profile),
        "remediation_chain": "separate_agent_loop_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="langchain-mcp-demo-1")
    triage["langchain_binding"] = langchain_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
