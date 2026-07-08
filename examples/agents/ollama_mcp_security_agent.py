"""Ollama (OpenAI-compatible) — read-only MCP security agent reference.

Ollama is not an MCP client. Bridge it through the OpenAI Agents SDK (or any
OpenAI-compatible client) with a **read-only** MCP allowlist. Open models have
weaker tool-call accuracy — keep the surface small via
``presets/preset-open-model-readonly.json``.

Prerequisites:

    uv sync --group dev --extra aws

Run:

    CLOUD_SECURITY_HARNESS_PROFILE=examples/agents/harness_profiles/sdk-open-model-readonly.json \
    CLOUD_SECURITY_MCP_PRESET=presets/preset-open-model-readonly.json \
      python examples/agents/ollama_mcp_security_agent.py

Remediation is intentionally out of scope for open-model loops. Use a separate
human-gated workflow if write paths are required.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ide_mcp_bindings import DEFAULT_OLLAMA_BASE_URL, build_ollama_openai_compat_binding
from sdk_agent_common import (
    human_approval_gate,
    load_sdk_profile,
    read_allowlist,
    run_cspm_triage,
)


def ollama_binding_notes(profile: dict[str, Any]) -> dict[str, Any]:
    base_url = os.environ.get("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL)
    binding = build_ollama_openai_compat_binding(profile, base_url=base_url)
    binding["openai_client_shape"] = {
        "base_url": base_url,
        "api_key": "ollama",
    }
    return binding


def main() -> int:
    profile = load_sdk_profile()
    allowlist = read_allowlist(profile)
    if any(
        skill.startswith("remediate-") or skill.startswith("iam-departures") for skill in allowlist
    ):
        raise SystemExit("open-model profile must not include remediation skills")

    triage = run_cspm_triage(profile, correlation_id="ollama-demo-1")
    binding = ollama_binding_notes(profile)
    triage["ollama_binding"] = binding
    triage["tool_config"] = binding["mcp_server"]["name"]
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    raise SystemExit(
        "open-model loops must not reach remediation; remove DEMO_APPROVE for this example"
    )


if __name__ == "__main__":
    raise SystemExit(main())
