"""LangGraph native interrupt/resume at the analyst HITL gate.

Production pattern for human-in-the-loop remediation:

  1. Compile the SOC graph with ``interrupt_before=["review"]`` and a
     LangGraph checkpointer (``MemorySaver`` in this demo).
  2. ``invoke`` until the graph pauses *before* ``review`` — no
     ``DEMO_APPROVE`` shortcut and no hallucinated approval context.
  3. Operator (or ticketing webhook) supplies ``approval_context`` via
     ``update_state``.
  4. ``invoke(None, config)`` resumes; remediation runs dry-run only when
     the profile grants the remediation skill.

Requires LangGraph (optional dependency group):

    uv sync --group dev --group langgraph

Run:

    PYTHONPATH=examples/agents python examples/agents/langgraph_hitl_interrupt_resume.py

    CLOUD_SECURITY_HARNESS_PROFILE=examples/agents/harness_profiles/dry-run-remediation.json \\
      PYTHONPATH=examples/agents python examples/agents/langgraph_hitl_interrupt_resume.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EXAMPLES_DIR = Path(__file__).resolve().parent
DEFAULT_PROFILE = EXAMPLES_DIR / "harness_profiles" / "dry-run-remediation.json"
INTERRUPT_NODE = "review"


def _build_interrupt_app() -> Any:
    try:
        from langgraph.checkpoint.memory import MemorySaver
        from langgraph.graph import END, START, StateGraph
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised without langgraph
        raise RuntimeError(
            "LangGraph is not installed. Run `uv sync --group dev --group langgraph`."
        ) from exc

    from langgraph_security_graph import (
        GraphState,
        analyst_review_node,
        audit_eval_writeback_node,
        confidence_node,
        correlate_node,
        dry_run_remediation_node,
        enrich_node,
        escalation_node,
        ingest_node,
        llm_triage_node,
        map_node,
        normalize_node,
        retry_queue_node,
        route_after_remediation,
        route_after_review,
    )

    graph = StateGraph(GraphState)
    for name, handler in (
        ("ingest", ingest_node),
        ("normalize", normalize_node),
        ("enrich", enrich_node),
        ("correlate", correlate_node),
        ("confidence", confidence_node),
        ("map", map_node),
        ("llm_triage", llm_triage_node),
        ("review", analyst_review_node),
        ("remediate", dry_run_remediation_node),
        ("retry_queue", retry_queue_node),
        ("escalate", escalation_node),
        ("writeback", audit_eval_writeback_node),
    ):
        graph.add_node(name, handler)

    graph.add_edge(START, "ingest")
    graph.add_edge("ingest", "normalize")
    graph.add_edge("normalize", "enrich")
    graph.add_edge("enrich", "correlate")
    graph.add_edge("correlate", "confidence")
    graph.add_edge("confidence", "map")
    graph.add_edge("map", "llm_triage")
    graph.add_edge("llm_triage", "review")
    graph.add_conditional_edges(
        "review",
        route_after_review,
        {"remediate": "remediate", "writeback": "writeback"},
    )
    graph.add_conditional_edges(
        "remediate",
        route_after_remediation,
        {
            "retry_queue": "retry_queue",
            "escalate": "escalate",
            "writeback": "writeback",
        },
    )
    graph.add_edge("retry_queue", "writeback")
    graph.add_edge("escalate", "writeback")
    graph.add_edge("writeback", END)

    return graph.compile(
        checkpointer=MemorySaver(),
        interrupt_before=[INTERRUPT_NODE],
    )


def _operator_approval() -> dict[str, str]:
    return {
        "approver_id": os.environ.get("DEMO_APPROVER", "analyst@example.com"),
        "ticket_id": os.environ.get("DEMO_TICKET", "SEC-HITL-INTERRUPT-1"),
        "approval_timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }


def run_hitl_interrupt_demo() -> dict[str, Any]:
    from langgraph_security_graph import GraphState, load_harness_profile, summarize

    profile_path = (
        os.environ.get("CLOUD_SECURITY_HARNESS_PROFILE")
        or os.environ.get("DEMO_HARNESS_PROFILE")
        or str(DEFAULT_PROFILE)
    )
    profile = load_harness_profile(profile_path)
    initial: GraphState = {
        "harness_profile": profile,
        "caller_context": profile["caller_context"],
        "raw_events": [{"source": "cloudtrail", "event_name": "CreateAccessKey"}],
    }
    thread_id = os.environ.get("DEMO_HITL_THREAD_ID", "hitl-interrupt-demo-1")
    config = {"configurable": {"thread_id": thread_id}}

    app = _build_interrupt_app()
    app.invoke(dict(initial), config)
    snapshot = app.get_state(config)
    paused_at_review = snapshot.next == (INTERRUPT_NODE,)

    approval = _operator_approval()
    app.update_state(config, {"approval_context": approval})
    final = dict(app.invoke(None, config))

    review = final.get("review_decision") or {}
    remediation = final.get("remediation_result") or {}
    return {
        "schema_version": "langgraph-hitl-interrupt-resume-v1",
        "interrupt_before": INTERRUPT_NODE,
        "thread_id": thread_id,
        "profile_id": profile.get("profile_id"),
        "phases": {
            "paused_at_review": paused_at_review,
            "resumed_with_approval": True,
            "approval_ticket": approval["ticket_id"],
        },
        "review_decision": {
            "status": review.get("status"),
            "reason": review.get("reason"),
        },
        "remediation_result": {
            "status": remediation.get("status"),
            "skill": remediation.get("skill"),
            "dry_run": remediation.get("dry_run"),
        },
        "summary": summarize(final),
    }


def main() -> int:
    try:
        payload = run_hitl_interrupt_demo()
    except RuntimeError as exc:
        print(
            json.dumps(
                {
                    "schema_version": "langgraph-hitl-interrupt-resume-v1",
                    "status": "skipped",
                    "reason": str(exc),
                },
                indent=2,
            )
        )
        return 0
    print(json.dumps(payload, indent=2))
    if payload["phases"]["paused_at_review"] is not True:
        print(
            f"expected interrupt before {INTERRUPT_NODE!r}, got {payload['phases']!r}",
            file=sys.stderr,
        )
        return 1
    if payload["review_decision"]["status"] != "approved":
        return 1
    if payload["remediation_result"]["status"] != "dry_run":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
