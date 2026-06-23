"""Execute or re-evaluate a LangGraph harness MCP call plan.

This command consumes a JSON summary produced by `run_langgraph_harness.py` or
`langgraph_security_graph.py`. By default it stays offline and reports what
the profile policy would do. It only starts a local MCP stdio server when the
summary profile has `runtime.mcp_execution.mode=operator_stdio` and the
operator passes `--allow-operator-stdio`.

Run:

    python examples/agents/run_langgraph_harness.py \
      --profile examples/agents/harness_profiles/readonly-soc.json \
      --output artifacts/harness-summary.json

    python examples/agents/execute_langgraph_mcp_plan.py \
      --summary artifacts/harness-summary.json \
      --output artifacts/harness-mcp-execution.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from harness_mcp_bridge import execute_mcp_call_plan
from harness_mcp_transport import McpStdioTransport, safe_mcp_env

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_json(path: Path | None) -> dict[str, Any]:
    text = sys.stdin.read() if path is None else path.read_text(encoding="utf-8")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("harness summary must be a JSON object")
    return payload


def _mcp_command(args: argparse.Namespace) -> list[str]:
    if args.mcp_server_arg:
        return [args.mcp_server_command, *args.mcp_server_arg]
    return [args.mcp_server_command, str(REPO_ROOT / "mcp-server" / "src" / "server.py")]


def _execution_report(summary: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    profile = summary.get("profile") or {}
    call_plan = summary.get("mcp_call_plan") or []
    if not isinstance(call_plan, list):
        raise ValueError("summary.mcp_call_plan must be an array")
    runtime = (profile.get("runtime") or {}).get("mcp_execution") or {}
    allowed_skills = summary.get("effective_allowed_skills") or []
    if (
        args.allow_operator_stdio
        and runtime.get("mode") == "operator_stdio"
        and runtime.get("execute_planned_calls") is True
    ):
        command = _mcp_command(args)
        with McpStdioTransport(
            command,
            env=safe_mcp_env(allowed_skills=allowed_skills),
            timeout_seconds=args.timeout_seconds,
        ) as transport:
            return execute_mcp_call_plan(
                call_plan=call_plan,
                profile=profile,
                transport=transport,
            )
    return execute_mcp_call_plan(call_plan=call_plan, profile=profile)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, help="Harness summary JSON path; defaults to stdin")
    parser.add_argument("--output", type=Path, help="Optional JSON report output path")
    parser.add_argument(
        "--allow-operator-stdio",
        action="store_true",
        help="Permit local stdio MCP execution when the summary profile also opts into operator_stdio",
    )
    parser.add_argument(
        "--mcp-server-command",
        default=sys.executable,
        help="Command used for the local MCP stdio server",
    )
    parser.add_argument(
        "--mcp-server-arg",
        action="append",
        default=[],
        help="Argument for --mcp-server-command; repeat for multiple args",
    )
    parser.add_argument("--timeout-seconds", type=float, default=30)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = _load_json(args.summary)
        report = _execution_report(summary, args)
    except Exception as exc:
        sys.stderr.write(f"langgraph MCP plan execution failed: {exc}\n")
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
