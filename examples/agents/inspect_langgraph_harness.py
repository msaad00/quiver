"""Inspect a LangGraph SOC harness profile before running the graph.

The inspector loads metadata only. It does not read cloud credentials, replay
evidence, call a model, request approval, or execute remediation.

Run:

    python examples/agents/inspect_langgraph_harness.py \
      --profile examples/agents/harness_profiles/readonly-soc.json

    python examples/agents/inspect_langgraph_harness.py \
      --profile examples/agents/harness_profiles/dry-run-remediation.json \
      --approval-context-present \
      --require-remediation-ready
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from langgraph_security_graph import load_harness_profile, preview_agent_policy


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, help="Harness profile JSON path")
    parser.add_argument(
        "--approval-context-present",
        action="store_true",
        help="Preview policy as if an external approval context is present",
    )
    parser.add_argument(
        "--require-remediation-ready",
        action="store_true",
        help="Exit nonzero unless dry-run remediation would be allowed",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    profile = load_harness_profile(str(args.profile) if args.profile else None)
    report = preview_agent_policy(
        profile,
        approval_context_present=args.approval_context_present,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    if args.require_remediation_ready and not report["remediation_preflight"]["would_plan_dry_run"]:
        sys.stderr.write("remediation preflight is not ready for dry-run planning\n")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
