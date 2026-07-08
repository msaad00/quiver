"""Claude Desktop — MCP-first security agent example.

Claude Desktop loads skills through ``claude_desktop_config.json`` (stdio MCP,
absolute paths). This reference shows the same harness-profile + live
``tools/list`` path as the other SDK examples — no skill CLI wrappers.

Run:

    python examples/agents/claude_desktop_mcp_security_agent.py
"""

from __future__ import annotations

import json
from typing import Any

from ide_mcp_bindings import build_claude_desktop_mcp_config
from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    run_cspm_triage,
)


def claude_desktop_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "claude_desktop_mcp_json",
        "config_path": "~/Library/Application Support/Claude/claude_desktop_config.json",
        "docs": "docs/integrations/claude-desktop.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_claude_desktop_tools",
        "mcp_config": build_claude_desktop_mcp_config(profile),
        "path_note": "Claude Desktop does not expand ~ — use an absolute clone path before paste",
        "remediation_chain": "separate_chat_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="claude-desktop-mcp-demo-1")
    triage["claude_desktop_binding"] = claude_desktop_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
