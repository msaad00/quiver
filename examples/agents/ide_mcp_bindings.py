"""Shared MCP client config builders for IDE and framework reference examples.

Each agent script stays a thin runnable wrapper; this module centralizes
allowlist → env policy and server path shapes so Cursor/Cortex/Windsurf/Codex/Zed
and LangChain MCP adapters stay consistent.
"""

from __future__ import annotations

from typing import Any

from harness_mcp_transport import safe_mcp_env
from sdk_agent_common import REPO_ROOT, mcp_stdio_command, read_allowlist

MCP_SERVER_PATH = REPO_ROOT / "mcp-server" / "src" / "server.py"
WORKSPACE_SERVER_ARG = "${workspaceFolder}/mcp-server/src/server.py"


def mcp_policy_env(profile: dict[str, Any]) -> dict[str, str]:
    """Harness allowlist as MCP subprocess env (includes caller-skill enforcement)."""
    return safe_mcp_env(allowed_skills=read_allowlist(profile))


def build_mcp_servers_json(profile: dict[str, Any], *, server_arg: str) -> dict[str, Any]:
    """JSON ``mcpServers`` block used by Cursor, Cortex, and Windsurf."""
    return {
        "mcpServers": {
            "cloud-ai-security-skills": {
                "command": mcp_stdio_command()[0],
                "args": [server_arg],
                "env": mcp_policy_env(profile),
            }
        }
    }


def build_cursor_mcp_config(profile: dict[str, Any]) -> dict[str, Any]:
    """``.cursor/mcp.json`` — portable with ``${workspaceFolder}``."""
    return build_mcp_servers_json(profile, server_arg=WORKSPACE_SERVER_ARG)


def build_cortex_mcp_config(profile: dict[str, Any]) -> dict[str, Any]:
    """``.cortex/mcp.json`` — portable with ``${workspaceFolder}``."""
    return build_mcp_servers_json(profile, server_arg=WORKSPACE_SERVER_ARG)


def build_windsurf_mcp_config(profile: dict[str, Any]) -> dict[str, Any]:
    """``~/.codeium/windsurf/mcp_config.json`` — absolute path required."""
    return build_mcp_servers_json(profile, server_arg=str(MCP_SERVER_PATH))


def build_claude_desktop_mcp_config(profile: dict[str, Any]) -> dict[str, Any]:
    """``claude_desktop_config.json`` — absolute path required."""
    return build_mcp_servers_json(profile, server_arg=str(MCP_SERVER_PATH))


def build_anthropic_mcp_config(profile: dict[str, Any]) -> dict[str, Any]:
    """Anthropic Agent SDK / project MCP — same ``mcpServers`` JSON shape as Claude Desktop."""
    return build_claude_desktop_mcp_config(profile)


def build_openai_agents_mcp_server(profile: dict[str, Any]) -> dict[str, Any]:
    """Block passed to ``openai.agents.McpServer(...)`` in a live Agents-SDK loop."""
    command = mcp_stdio_command()
    return {
        "name": "cloud-ai-security-skills",
        "command": command[0],
        "args": command[1:],
        "env": mcp_policy_env(profile),
    }


DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"


def build_ollama_openai_compat_binding(
    profile: dict[str, Any], *, base_url: str = DEFAULT_OLLAMA_BASE_URL
) -> dict[str, Any]:
    """OpenAI-compatible Ollama runtime + the same MCP stdio server block as OpenAI Agents."""
    return {
        "integration": "ollama_openai_compat_agents",
        "docs": "docs/integrations/ollama.md",
        "ollama_base_url": base_url,
        "ollama_api_key": "ollama",
        "preset_recommendation": "presets/preset-open-model-readonly.json",
        "guardrail_note": "read_only_skills_only_no_remediation_in_allowlist",
        "anti_pattern": "do_not_wrap_skill_clis_as_openai_tools",
        "mcp_server": build_openai_agents_mcp_server(profile),
    }


def build_zed_context_servers(profile: dict[str, Any]) -> dict[str, Any]:
    """``~/.config/zed/settings.json`` ``context_servers`` block."""
    return {
        "context_servers": {
            "cloud-ai-security-skills": {
                "command": {
                    "path": mcp_stdio_command()[0],
                    "args": [str(MCP_SERVER_PATH)],
                    "env": mcp_policy_env(profile),
                },
            }
        }
    }


def _toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_codex_mcp_toml(profile: dict[str, Any]) -> str:
    """Fragment for ``~/.codex/config.toml`` — absolute path required."""
    env = mcp_policy_env(profile)
    env_pairs = ", ".join(f"{key} = {_toml_string(value)}" for key, value in sorted(env.items()))
    command = mcp_stdio_command()[0]
    return (
        "[mcp_servers.cloud-ai-security-skills]\n"
        f"command = {_toml_string(command)}\n"
        f"args = [{_toml_string(str(MCP_SERVER_PATH))}]\n"
        f"env = {{ {env_pairs} }}\n"
    )


def build_langchain_mcp_servers(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Config block for ``MultiServerMCPClient`` / LangGraph MCP tool nodes."""
    command = mcp_stdio_command()
    return {
        "cloud-ai-security-skills": {
            "transport": "stdio",
            "command": command[0],
            "args": command[1:],
            "env": mcp_policy_env(profile),
        }
    }
