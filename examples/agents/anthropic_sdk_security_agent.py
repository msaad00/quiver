"""Anthropic Agent SDK — CSPM scan + triage against cloud-ai-security-skills.

Loads a harness profile for customizable allowlists and caller context,
then wires the repo MCP server over stdio JSON-RPC. Remediation stays on a
separate chain gated by operator approval.

Prerequisites:

    uv sync --group dev --extra aws
    Configure Anthropic SDK credentials outside this repo if you run live SDK calls.

Run:

    python examples/agents/anthropic_sdk_security_agent.py

    CLOUD_SECURITY_HARNESS_PROFILE=examples/agents/harness_profiles/sdk-cspm-agent.json \\
      DEMO_APPROVE=yes python examples/agents/anthropic_sdk_security_agent.py
"""

from __future__ import annotations

import json

from sdk_agent_common import (
    dry_run_remediation,
    human_approval_gate,
    load_sdk_profile,
    run_cspm_triage,
)


def main() -> int:
    profile = load_sdk_profile()
    triage = run_cspm_triage(profile, correlation_id="anthropic-demo-1")
    print(json.dumps(triage, indent=2))

    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    remediation = dry_run_remediation(triage["caller_context"], approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
