"""Continue — MCP-first security agent example.

Continue loads MCP servers through ``~/.continue/config.yaml`` (YAML list
shape, absolute paths). This reference shows the harness-profile + live
``tools/list`` path — no skill CLI wrappers.

Run:

    python examples/agents/continue_mcp_security_agent.py
"""

from __future__ import annotations

import json
from typing import Any

from ide_mcp_bindings import build_continue_mcp_servers, build_continue_mcp_yaml
from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    run_cspm_triage,
)


def continue_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "continue_mcp_yaml",
        "config_path": "~/.continue/config.yaml",
        "docs": "docs/integrations/ide-agents.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_continue_tools",
        "continue_mcp_servers": build_continue_mcp_servers(profile),
        "mcp_yaml": build_continue_mcp_yaml(profile),
        "path_note": "Replace server args with an absolute clone path before paste",
        "reload_note": "Continue: Reload Config from the command palette after edits",
        "remediation_chain": "separate_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="continue-mcp-demo-1")
    triage["continue_binding"] = continue_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
