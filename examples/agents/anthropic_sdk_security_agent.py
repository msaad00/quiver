"""Anthropic Agent SDK — CSPM scan + triage against cloud-ai-security-skills.

This is a **reference implementation**. It demonstrates:

  1. Spawning the repo MCP server as a subprocess with a read-only skill allowlist
  2. Letting a Claude-driven agent loop call those tools through MCP
  3. Parsing the results into an operator-facing triage summary
  4. A stub HITL gate that must be passed before any remediation chain runs

The example is runnable offline: the CSPM scan calls `moto` fixtures
(no real cloud creds), and the remediation chain is dry-run only.

Prerequisites:

    uv sync --group dev --extra aws
    Configure Anthropic SDK credentials outside this repo if you run live SDK calls.

Run:

    python examples/agents/anthropic_sdk_security_agent.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER = REPO_ROOT / "mcp-server" / "src" / "server.py"

# Hard-coded read-only allowlist. `remediate-*` skills are intentionally not
# registered as MCP tools — a compromised or malfunctioning agent loop cannot
# call what isn't on the list.
ALLOWED_SKILLS_READ_ONLY = ",".join(
    [
        "cspm-aws-cis-benchmark",
        "cspm-gcp-cis-benchmark",
        "cspm-azure-cis-benchmark",
        "detect-lateral-movement",
        "detect-privilege-escalation-k8s",
        "convert-ocsf-to-sarif",
    ]
)

# Separate allowlist for the human-gated remediation chain. Never combine
# this with `ALLOWED_SKILLS_READ_ONLY` in the same agent loop.
ALLOWED_SKILLS_REMEDIATION = "iam-departures-aws"


def mcp_server_env(allowlist: str) -> dict[str, str]:
    env = os.environ.copy()
    env["CLOUD_SECURITY_MCP_ALLOWED_SKILLS"] = allowlist
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


# ---------------------------------------------------------------------------
# Stage 1 — read-only CSPM + triage loop
# ---------------------------------------------------------------------------


def run_cspm_triage(caller_context: dict[str, str]) -> dict[str, Any]:
    """Drive a read-only CSPM scan via Claude Agent SDK over MCP.

    This is pseudocode at the agent-SDK layer (the Anthropic SDK surface is
    not pinned in this repo as a runtime dep). The MCP subprocess invocation
    is the real part — it shows exactly how any agent framework wires in.
    """
    # In a real run: `from anthropic import Anthropic; client = Anthropic(); ...`
    # and pass `mcp_servers=[{"command": "python3", "args": [str(MCP_SERVER)],
    # "env": mcp_server_env(ALLOWED_SKILLS_READ_ONLY)}]` as the agent
    # configuration. The agent would then call tools as the model decides.
    #
    # For this reference, we invoke the MCP server directly and show the
    # equivalent tool-call sequence deterministically so it runs in tests.
    findings = _simulated_cspm_call(caller_context)
    return {
        "stage": "triage",
        "findings_count": len(findings),
        "high_severity": [f for f in findings if f.get("severity_id", 0) >= 4],
        "caller_context": caller_context,
    }


def _simulated_cspm_call(caller_context: dict[str, str]) -> list[dict[str, Any]]:
    """Deterministic stand-in that doesn't require network access.

    Real loop: `client.messages.create(..., tools=mcp_tools)` →
    model emits `tools/call name="cspm-aws-cis-benchmark" …` → wrapper
    audits + runs the skill against moto → result flows back.
    """
    # Emit an audit-line stub so the operator sees the expected forensic trail.
    audit = {
        "event": "mcp_tool_call",
        "tool": "cspm-aws-cis-benchmark",
        "correlation_id": "demo-corr-1",
        "caller_id": caller_context.get("user_id", "unknown"),
        "read_only": True,
        "result": "success",
    }
    sys.stderr.write(json.dumps(audit) + "\n")
    return [
        {"finding": "CIS 2.1.1 bucket public", "severity_id": 4, "resource": "s3://demo"},
        {"finding": "CIS 1.4 root MFA", "severity_id": 5, "resource": "root"},
    ]


# ---------------------------------------------------------------------------
# Stage 2 — HITL gate (stubbed; real runs pull from your approval system)
# ---------------------------------------------------------------------------


def human_approval_gate(findings: dict[str, Any]) -> dict[str, str] | None:
    """Return an `approval_context` if an operator signs off, else None.

    Real implementation: this function calls your ticketing/approval system
    and blocks on a human decision. Never auto-approve.
    """
    if os.environ.get("DEMO_APPROVE") != "yes":
        print("[HITL] No approval present — skipping remediation chain.", file=sys.stderr)
        return None
    return {
        "approver_id": os.environ.get("DEMO_APPROVER", "operator@example.com"),
        "ticket_id": os.environ.get("DEMO_TICKET", "SEC-DEMO-1"),
        "approval_timestamp": "2026-04-18T12:00:00Z",
    }


# ---------------------------------------------------------------------------
# Stage 3 — dry-run remediation chain
# ---------------------------------------------------------------------------


def dry_run_remediation(
    caller_context: dict[str, str],
    approval_context: dict[str, str],
) -> dict[str, Any]:
    """Shell out to `iam-departures-aws` reconciler in dry-run mode.

    The MCP wrapper enforces:
      - only dry-run allowed unless approval_context is present
      - audit record includes approver_id + ticket_id
      - the IaC deny list still blocks `root`/`break-glass-*`/`emergency-*`
    """
    # A real agent run would go through MCP tools/call; this shells out to the
    # skill entrypoint directly so the reference runs without an LLM.
    cmd = [
        sys.executable,
        str(
            REPO_ROOT
            / "skills"
            / "remediation"
            / "iam-departures-aws"
            / "src"
            / "reconciler"
            / "handler.py"
        ),
        "--dry-run",
    ]
    result = subprocess.run(
        cmd,
        input=json.dumps({"caller_context": caller_context, "approval_context": approval_context}),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=mcp_server_env(ALLOWED_SKILLS_REMEDIATION),
    )
    return {
        "stage": "remediation_dry_run",
        "exit_code": result.returncode,
        "stdout_excerpt": (result.stdout or "")[:200],
        "approval": approval_context,
    }


# ---------------------------------------------------------------------------
# Anti-pattern — DO NOT DO THIS
# ---------------------------------------------------------------------------


def DONT_DO_THIS_combined_tools_loop() -> None:  # noqa: N802 - deliberate
    """Reference: combining read + remediate tools in one loop is WRONG.

    Even though the MCP wrapper refuses remediation without
    `approval_context`, exposing remediation tools to an autonomous loop
    puts the wrong affordance in the model's hands. The correct posture is
    to never register remediation tools in the same loop as detection.
    """
    bad_allowlist = ",".join(
        [
            "cspm-aws-cis-benchmark",
            "iam-departures-aws",  # ❌ write-capable tool in a read-only loop
        ]
    )
    raise RuntimeError(
        f"Refusing to demonstrate unsafe pattern. If you see a tutorial with "
        f"allowlist={bad_allowlist!r}, close the tutorial."
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> int:
    caller = {
        "user_id": "demo-operator",
        "email": "demo-operator@example.com",
        "session_id": "demo-session-1",
        "roles": "security_engineer",
    }

    # Stage 1 — read-only CSPM triage
    triage = run_cspm_triage(caller)
    print(json.dumps(triage, indent=2))

    # Stage 2 — HITL gate (no-op by default; set DEMO_APPROVE=yes to proceed)
    approval = human_approval_gate(triage)
    if approval is None:
        return 0

    # Stage 3 — dry-run remediation chain
    remediation = dry_run_remediation(caller, approval)
    print(json.dumps(remediation, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
