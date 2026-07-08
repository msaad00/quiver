"""Cursor — MCP-first security agent example.

Cursor loads skills through project-scoped ``.cursor/mcp.json`` (stdio MCP).
This reference shows the same harness-profile + live ``tools/list`` path as
the Anthropic, OpenAI, and LangChain SDK examples — no skill CLI wrappers.

Run:

    python examples/agents/cursor_mcp_security_agent.py
"""

from __future__ import annotations

import json
from typing import Any

from ide_mcp_bindings import build_cursor_mcp_config
from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    run_cspm_triage,
)


def cursor_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "cursor_mcp_json",
        "config_path": ".cursor/mcp.json",
        "docs": "docs/integrations/cursor.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_cursor_tools",
        "mcp_config": build_cursor_mcp_config(profile),
        "remediation_chain": "separate_composer_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="cursor-mcp-demo-1")
    triage["cursor_binding"] = cursor_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
