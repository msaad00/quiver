"""Cortex Code CLI — MCP-first security agent example.

Cortex loads skills through project-scoped ``.cortex/mcp.json`` (stdio MCP).
This reference shows the same harness-profile + live ``tools/list`` path as
the other SDK examples — no skill CLI wrappers.

Run:

    python examples/agents/cortex_mcp_security_agent.py
"""

from __future__ import annotations

import json
from typing import Any

from ide_mcp_bindings import build_cortex_mcp_config
from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    run_cspm_triage,
)


def cortex_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "cortex_mcp_json",
        "config_path": ".cortex/mcp.json",
        "docs": "docs/integrations/cortex.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_cortex_tools",
        "mcp_config": build_cortex_mcp_config(profile),
        "remediation_chain": "separate_cortex_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="cortex-mcp-demo-1")
    triage["cortex_binding"] = cortex_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
