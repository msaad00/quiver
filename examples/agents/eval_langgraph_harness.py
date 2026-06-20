"""Offline eval runner for the LangGraph agent harness example.

This is intentionally not an LLM-as-judge. It replays golden cases through the
same deterministic graph and checks bounded agent outputs, HITL routing, model
metadata, idempotency, and profile allowlist behavior.

Run:

    python examples/agents/eval_langgraph_harness.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from langgraph_security_graph import load_harness_profile, run_graph, summarize

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = Path(__file__).with_name("evals") / "langgraph_triage_golden.json"


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else REPO_ROOT / path


def _without_approval_env() -> dict[str, str | None]:
    saved = {
        "DEMO_APPROVE": os.environ.get("DEMO_APPROVE"),
        "DEMO_APPROVER": os.environ.get("DEMO_APPROVER"),
        "DEMO_TICKET": os.environ.get("DEMO_TICKET"),
    }
    for key in saved:
        os.environ.pop(key, None)
    return saved


def _restore_env(saved: dict[str, str | None]) -> None:
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _first_recommendation(summary: dict[str, Any]) -> dict[str, Any]:
    recommendations = summary.get("agent_recommendations") or []
    if not recommendations:
        return {}
    return recommendations[0]


def _triage_agent(summary: dict[str, Any]) -> dict[str, Any]:
    for agent in summary.get("agents") or []:
        if agent.get("agent_id") == "triage-agent":
            return agent
    return {}


def _check(name: str, actual: Any, expected: Any) -> dict[str, Any]:
    return {
        "name": name,
        "actual": actual,
        "expected": expected,
        "passed": actual == expected,
    }


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    saved_env = _without_approval_env()
    try:
        profile = load_harness_profile(str(_resolve(case["profile"])))
        initial = {
            "harness_profile": profile,
            "caller_context": profile["caller_context"],
            "raw_events": case.get("raw_events") or [{"source": "demo"}],
        }
        summary = summarize(run_graph(initial))
    finally:
        _restore_env(saved_env)

    expected = case["expected"]
    recommendation = _first_recommendation(summary)
    triage_agent = _triage_agent(summary)
    checks = [
        _check("profile_id", summary["profile"]["profile_id"], expected["profile_id"]),
        _check("harness_mode", summary["harness"]["mode"], expected["harness_mode"]),
        _check("recommendation_action", recommendation.get("recommended_action"), expected["recommendation_action"]),
        _check("recommendation_priority", recommendation.get("priority"), expected["recommendation_priority"]),
        _check("review_status", summary["review"]["status"], expected["review_status"]),
        _check("remediation_status", summary["remediation"]["status"], expected["remediation_status"]),
        _check("route_after_review", summary["audit"]["route"]["after_review"], expected["route_after_review"]),
        _check("planned_steps_absent", "planned_steps" not in summary["remediation"], expected["planned_steps_absent"]),
    ]

    if "recommendation_generated_by" in expected:
        checks.append(_check(
            "recommendation_generated_by",
            recommendation.get("generated_by"),
            expected["recommendation_generated_by"],
        ))

    for skill in expected.get("effective_allowed_includes", []):
        checks.append(_check(
            f"effective_allowed_includes:{skill}",
            skill in summary["effective_allowed_skills"],
            True,
        ))

    for skill in expected.get("effective_allowed_excludes", []):
        checks.append(_check(
            f"effective_allowed_excludes:{skill}",
            skill not in summary["effective_allowed_skills"],
            True,
        ))

    for field in expected.get("triage_forbidden_outputs", []):
        checks.append(_check(
            f"triage_forbidden_output:{field}",
            field in triage_agent.get("forbidden_outputs", []),
            True,
        ))

    passed = all(check["passed"] for check in checks)
    return {
        "case_id": case["case_id"],
        "status": "pass" if passed else "fail",
        "output_hash": _stable_hash({
            "profile": summary["profile"]["profile_id"],
            "recommendation": recommendation,
            "review": summary["review"],
            "remediation": summary["remediation"],
            "route": summary["audit"]["route"],
            "effective_allowed_skills": summary["effective_allowed_skills"],
        })[:16],
        "checks": checks,
    }


def run_dataset(dataset_path: Path) -> dict[str, Any]:
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    results = [run_case(case) for case in dataset["cases"]]
    passed = sum(1 for result in results if result["status"] == "pass")
    total = len(results)
    return {
        "event": "langgraph_agent_harness_eval",
        "dataset_version": dataset["dataset_version"],
        "dataset_hash": _stable_hash(dataset)[:16],
        "cases_total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": passed / total if total else 0.0,
        "model_policy": "llm_may_rank_summarize_draft_only",
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--min-pass-rate", type=float, default=1.0)
    parser.add_argument("--check", action="store_true", help="exit nonzero when pass rate is below threshold")
    args = parser.parse_args()

    report = run_dataset(args.dataset)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.check and report["pass_rate"] < args.min_pass_rate:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
