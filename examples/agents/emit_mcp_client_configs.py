"""Emit IDE MCP client config blocks from a harness profile.

Offline generator for operators wiring multiple IDE clients from one harness
profile. Does not spawn MCP, call cloud APIs, or run remediation.

Run:

    python examples/agents/emit_mcp_client_configs.py
    python examples/agents/emit_mcp_client_configs.py --client cursor
    python examples/agents/emit_mcp_client_configs.py \\
      --profile examples/agents/harness_profiles/sdk-cspm-agent.json \\
      --output artifacts/mcp-client-configs.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Literal

from ide_mcp_bindings import (
    build_codex_mcp_toml,
    build_cortex_mcp_config,
    build_cursor_mcp_config,
    build_windsurf_mcp_config,
    build_zed_context_servers,
)
from sdk_agent_common import DEFAULT_PROFILE, load_sdk_profile

ClientName = Literal["cursor", "cortex", "windsurf", "codex", "zed", "all"]
CLIENT_NAMES: tuple[ClientName, ...] = ("cursor", "cortex", "windsurf", "codex", "zed", "all")


def _client_payload(client: str, profile: dict[str, Any]) -> dict[str, Any]:
    if client == "cursor":
        return {
            "integration": "cursor_mcp_json",
            "config_path": ".cursor/mcp.json",
            "docs": "docs/integrations/cursor.md",
            "mcp_config": build_cursor_mcp_config(profile),
        }
    if client == "cortex":
        return {
            "integration": "cortex_mcp_json",
            "config_path": ".cortex/mcp.json",
            "docs": "docs/integrations/cortex.md",
            "mcp_config": build_cortex_mcp_config(profile),
        }
    if client == "windsurf":
        return {
            "integration": "windsurf_mcp_config_json",
            "config_path": "~/.codeium/windsurf/mcp_config.json",
            "docs": "docs/integrations/windsurf.md",
            "mcp_config": build_windsurf_mcp_config(profile),
            "path_note": "Replace server args with an absolute clone path before paste",
        }
    if client == "codex":
        return {
            "integration": "codex_config_toml",
            "config_path": "~/.codex/config.toml",
            "docs": "docs/integrations/codex.md",
            "mcp_toml": build_codex_mcp_toml(profile),
            "path_note": "Replace server args with an absolute clone path before paste",
        }
    if client == "zed":
        return {
            "integration": "zed_context_servers_json",
            "config_path": "~/.config/zed/settings.json",
            "docs": "docs/integrations/zed.md",
            "context_servers": build_zed_context_servers(profile),
            "path_note": "Replace server args with an absolute clone path before paste",
        }
    raise ValueError(f"unsupported client: {client}")


def emit_client_configs(profile: dict[str, Any], *, client: ClientName = "all") -> dict[str, Any]:
    selected = CLIENT_NAMES[:-1] if client == "all" else (client,)
    return {name: _client_payload(name, profile) for name in selected}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        type=Path,
        default=DEFAULT_PROFILE,
        help="Harness profile JSON (default: harness_profiles/sdk-cspm-agent.json)",
    )
    parser.add_argument(
        "--client",
        choices=CLIENT_NAMES,
        default="all",
        help="Emit one client block or all five IDE clients",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write JSON (stdout when omitted)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    profile = load_sdk_profile(args.profile)
    payload = {
        "schema_version": "mcp-client-config-bundle-v1",
        "profile_id": profile.get("profile_id"),
        "clients": emit_client_configs(profile, client=args.client),
    }
    rendered = json.dumps(payload, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
