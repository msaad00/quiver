"""Zed — MCP-first security agent example.

Zed loads skills through ``~/.config/zed/settings.json`` (``context_servers``,
stdio MCP, absolute paths). This reference shows the same harness-profile +
live ``tools/list`` path as the other SDK examples — no skill CLI wrappers.

Run:

    python examples/agents/zed_mcp_security_agent.py
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


def build_zed_context_servers(profile: dict[str, Any]) -> dict[str, Any]:
    """Block for ``~/.config/zed/settings.json`` — absolute path required."""
    allowlist = read_allowlist(profile)
    return {
        "context_servers": {
            "cloud-ai-security-skills": {
                "command": {
                    "path": mcp_stdio_command()[0],
                    "args": [str(MCP_SERVER_PATH)],
                    "env": {
                        **safe_mcp_env(allowed_skills=allowlist),
                        "CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS": "true",
                    },
                },
            }
        }
    }


def zed_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "zed_context_servers_json",
        "config_path": "~/.config/zed/settings.json",
        "docs": "docs/integrations/zed.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_zed_tools",
        "context_servers": build_zed_context_servers(profile),
        "path_note": "Zed does not expand ~ — replace with an absolute clone path before paste",
        "remediation_chain": "separate_assistant_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="zed-mcp-demo-1")
    triage["zed_binding"] = zed_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
