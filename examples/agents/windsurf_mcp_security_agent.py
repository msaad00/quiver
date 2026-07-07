"""Windsurf — MCP-first security agent example.

Windsurf (Codeium Cascade) loads skills through ``~/.codeium/windsurf/mcp_config.json``
(stdio MCP, absolute paths). This reference shows the same harness-profile +
live ``tools/list`` path as the other SDK examples — no skill CLI wrappers.

Run:

    python examples/agents/windsurf_mcp_security_agent.py
"""

from __future__ import annotations

import json
from typing import Any

from harness_mcp_transport import safe_mcp_env
from sdk_agent_common import (
    REPO_ROOT,
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    mcp_stdio_command,
    read_allowlist,
    run_cspm_triage,
)

MCP_SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"


def build_windsurf_mcp_config(profile: dict[str, Any]) -> dict[str, Any]:
    """Block for ``~/.codeium/windsurf/mcp_config.json`` (absolute path required)."""
    allowlist = read_allowlist(profile)
    return {
        "mcpServers": {
            "cloud-ai-security-skills": {
                "command": mcp_stdio_command()[0],
                "args": [str(MCP_SERVER_PATH)],
                "env": {
                    **safe_mcp_env(allowed_skills=allowlist),
                    "CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS": "true",
                },
            }
        }
    }


def windsurf_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "windsurf_mcp_config_json",
        "config_path": "~/.codeium/windsurf/mcp_config.json",
        "docs": "docs/integrations/windsurf.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_cascade_tools",
        "mcp_config": build_windsurf_mcp_config(profile),
        "path_note": "Windsurf does not expand ~ — replace with an absolute clone path before paste",
        "remediation_chain": "separate_cascade_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="windsurf-mcp-demo-1")
    triage["windsurf_binding"] = windsurf_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
