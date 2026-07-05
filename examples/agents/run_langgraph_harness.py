"""Run the LangGraph SOC harness through the importable runtime wrapper.

This is the operator-facing CLI for the executable harness. It loads profile
metadata, optional evidence fixtures, optional caller context overrides, then
runs either the deterministic route mirror or the real LangGraph StateGraph.

The runner does not read cloud credentials or call live models. Approval
metadata is carried in graph state; remediation still requires the profile
allowlist and remains dry-run only.

Run:

    python examples/agents/run_langgraph_harness.py \
      --profile examples/agents/harness_profiles/readonly-soc.json

    python examples/agents/run_langgraph_harness.py \
      --profile examples/agents/harness_profiles/dry-run-remediation.json \
      --approve --approver reviewer@example.com --ticket SEC-123
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator, Mapping

from harness_runtime import HarnessRunConfig, run_harness_summary

SECRET_FIELD_RE = re.compile(
    r"(?i)(password|passwd|pwd|pat|personal[_-]?access[_-]?token|api[_-]?key|"
    r"secret|private[_-]?key|access[_-]?key|session[_-]?token|bearer)"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|"
    r"sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def _assert_no_secret_material(payload: Any, *, path: str) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(key)
            if SECRET_FIELD_RE.search(key_text):
                raise ValueError(
                    f"{path}.{key_text} must not contain passwords, PATs, tokens, or secrets"
                )
            _assert_no_secret_material(value, path=f"{path}.{key_text}")
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            _assert_no_secret_material(value, path=f"{path}[{index}]")
    elif isinstance(payload, str) and (
        SECRET_FIELD_RE.search(payload) or SECRET_VALUE_RE.search(payload)
    ):
        raise ValueError(f"{path} must not contain password, PAT, token, or secret material")


def _load_json_or_jsonl(path: Path) -> Any:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"{path} is empty")
    if text[0] in "[{":
        return json.loads(text)
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return rows


def _load_mapping_argument(value: str | None, *, label: str) -> dict[str, Any] | None:
    if not value:
        return None
    candidate = Path(value)
    payload = _load_json_or_jsonl(candidate) if candidate.exists() else json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _load_raw_events(path: Path | None) -> tuple[Mapping[str, Any], ...] | None:
    if not path:
        return None
    payload = _load_json_or_jsonl(path)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise ValueError(
            "--raw-events must be a JSON object, JSON array of objects, or JSONL objects"
        )
    return tuple(payload)


def _approval_context_from_args(args: argparse.Namespace) -> dict[str, Any] | None:
    explicit = _load_mapping_argument(args.approval_context, label="--approval-context")
    if explicit:
        _assert_no_secret_material(explicit, path="approval_context")
        return explicit
    if not args.approve:
        return None
    return {
        "approver_id": args.approver,
        "ticket_id": args.ticket,
        "approval_timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }


@contextmanager
def _temporary_demo_approval(args: argparse.Namespace) -> Iterator[None]:
    keys = ("DEMO_APPROVE", "DEMO_APPROVER", "DEMO_TICKET")
    previous = {key: os.environ.get(key) for key in keys}
    try:
        if args.approve:
            for key in keys:
                os.environ.pop(key, None)
        elif args.clear_approval_env:
            for key in keys:
                os.environ.pop(key, None)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, help="Harness profile JSON path")
    parser.add_argument(
        "--raw-events",
        type=Path,
        help="Optional JSON object, JSON array, or JSONL evidence fixture",
    )
    parser.add_argument(
        "--caller-context",
        help="JSON object or path to a JSON object merged over profile caller_context",
    )
    parser.add_argument(
        "--langgraph-runtime",
        action="store_true",
        help="Run through compiled LangGraph StateGraph instead of the deterministic mirror",
    )
    parser.add_argument("--checkpoint", type=Path, help="Write a replay checkpoint artifact")
    parser.add_argument(
        "--replay-checkpoint", type=Path, help="Replay a checkpoint without running nodes"
    )
    parser.add_argument("--output", type=Path, help="Optional JSON summary output path")
    parser.add_argument(
        "--no-check", action="store_true", help="Emit summary even if wrapper validation fails"
    )
    parser.add_argument(
        "--approval-context",
        help="JSON object or path with approver_id, ticket_id, and approval_timestamp",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Populate demo approval context for HITL-gated dry-run planning",
    )
    parser.add_argument(
        "--approver", default="operator@example.com", help="Approver identity for --approve"
    )
    parser.add_argument("--ticket", default="SEC-LANGGRAPH-1", help="Ticket id for --approve")
    parser.add_argument(
        "--clear-approval-env",
        action="store_true",
        help="Ignore inherited DEMO_APPROVE/DEMO_APPROVER/DEMO_TICKET values for this run",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.checkpoint and args.replay_checkpoint:
        sys.stderr.write("--checkpoint and --replay-checkpoint are mutually exclusive\n")
        return 2
    try:
        config = HarnessRunConfig(
            profile_path=args.profile,
            raw_events=_load_raw_events(args.raw_events),
            caller_context=_load_mapping_argument(args.caller_context, label="--caller-context"),
            approval_context=_approval_context_from_args(args),
            use_langgraph_runtime=args.langgraph_runtime,
            checkpoint_path=args.checkpoint,
            replay_checkpoint_path=args.replay_checkpoint,
        )
        with _temporary_demo_approval(args):
            summary = run_harness_summary(config, check=not args.no_check)
    except Exception as exc:
        sys.stderr.write(f"langgraph harness run failed: {exc}\n")
        return 1

    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
