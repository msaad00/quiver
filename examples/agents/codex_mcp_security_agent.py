"""Codex — MCP-first security agent example.

Codex CLI and IDE extensions load skills through ``~/.codex/config.toml`` (stdio
MCP, absolute paths). This reference shows the same harness-profile + live
``tools/list`` path as the other SDK examples — no skill CLI wrappers.

Run:

    python examples/agents/codex_mcp_security_agent.py
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


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_codex_mcp_toml(profile: dict[str, Any]) -> str:
    """Fragment for ``~/.codex/config.toml`` — absolute path required."""
    allowlist = read_allowlist(profile)
    env = {
        **safe_mcp_env(allowed_skills=allowlist),
        "CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS": "true",
    }
    env_pairs = ", ".join(f"{key} = {_toml_string(value)}" for key, value in sorted(env.items()))
    command = mcp_stdio_command()[0]
    return (
        "[mcp_servers.cloud-ai-security-skills]\n"
        f"command = {_toml_string(command)}\n"
        f"args = [{_toml_string(str(MCP_SERVER_PATH))}]\n"
        f"env = {{ {env_pairs} }}\n"
    )


def codex_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "integration": "codex_config_toml",
        "config_path": "~/.codex/config.toml",
        "docs": "docs/integrations/codex.md",
        "anti_pattern": "do_not_wrap_skill_clis_as_codex_tools",
        "mcp_toml": build_codex_mcp_toml(profile),
        "path_note": "Replace the args path with your clone location before paste",
        "remediation_chain": "separate_codex_session_with_HITL_approval_context",
    }


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="codex-mcp-demo-1")
    triage["codex_binding"] = codex_binding_notes(profile)
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
