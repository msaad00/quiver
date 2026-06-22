"""Importable runtime wrapper for the LangGraph SOC harness example.

`docs/HARNESS.md` is the operator contract. This module is the small code
surface a CI job, MCP wrapper, SOAR playbook, or customer-owned LangGraph app
can import when it wants the demo harness behavior without shelling out to the
example CLI.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from langgraph_security_graph import (
    CHECKPOINT_SCHEMA_VERSION,
    GraphState,
    load_checkpoint,
    load_harness_profile,
    run_graph,
    run_langgraph,
    summarize,
    write_checkpoint,
)

HARNESS_RUNTIME_VERSION = "langgraph-soc-harness-runtime-v1"


@dataclass(frozen=True)
class HarnessRunConfig:
    """Operator-owned run settings for the example harness wrapper."""

    profile_path: str | Path | None = None
    raw_events: tuple[Mapping[str, Any], ...] | None = None
    caller_context: Mapping[str, Any] | None = None
    use_langgraph_runtime: bool = False
    checkpoint_path: str | Path | None = None
    replay_checkpoint_path: str | Path | None = None


@dataclass(frozen=True)
class HarnessRunResult:
    """Structured result returned by `run_harness`."""

    runtime: dict[str, Any]
    final_state: GraphState
    summary: dict[str, Any]
    checkpoint: dict[str, Any] | None
    validation_errors: tuple[str, ...]


def build_initial_state(config: HarnessRunConfig | None = None) -> GraphState:
    """Create initial graph state from an operator profile and evidence rows."""
    config = config or HarnessRunConfig()
    profile_path = str(config.profile_path) if config.profile_path else None
    profile = load_harness_profile(profile_path)
    caller_context = dict(profile["caller_context"])
    if config.caller_context:
        caller_context.update(config.caller_context)
    raw_events = [dict(event) for event in (config.raw_events or ({"source": "demo"},))]
    return {
        "harness_profile": profile,
        "caller_context": caller_context,
        "raw_events": raw_events,
    }


def validate_harness_summary(summary: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate wrapper-level invariants without re-running graph nodes."""
    errors: list[str] = []
    trace = list(summary.get("trace") or [])
    if not trace or trace[0] != "ingest" or trace[-1] != "writeback":
        errors.append("trace must run from ingest to writeback")

    harness = summary.get("harness") or {}
    allowed_outputs = set(harness.get("allowed_outputs") or [])
    forbidden_harness_outputs = {
        "approval",
        "cvss",
        "mitre",
        "epss",
        "kev",
        "tenant_scope",
        "idempotency_key",
        "write_intent",
        "call_write_tools",
    }
    if allowed_outputs.intersection(forbidden_harness_outputs):
        errors.append("llm harness exposes forbidden authoritative outputs")

    token_usage = summary.get("token_budget_usage") or {}
    token_budget = harness.get("token_budget") or {}
    model_policy = harness.get("model_policy") or {}
    if model_policy.get("selected_model_tier") != token_budget.get("model_tier"):
        errors.append("model policy selected tier must match token budget tier")
    if model_policy.get("selection_source") not in {"profile_model_policy", "env_override"}:
        errors.append("model policy selection source must be recorded")
    if token_usage.get("status") not in {"within_budget", "fallback"}:
        errors.append("token budget status must be within_budget or fallback")
    if (
        token_usage.get("status") == "within_budget"
        and token_usage.get("compact_input_tokens_estimate", 0) > token_budget.get("max_input_tokens", 0)
    ):
        errors.append("compact LLM input exceeds max_input_tokens")
    if (
        token_usage.get("status") == "within_budget"
        and token_usage.get("compact_evidence_chars", 0) > token_budget.get("max_evidence_chars", 0)
    ):
        errors.append("compact LLM evidence exceeds max_evidence_chars")

    for card in summary.get("llm_evidence_cards") or []:
        if "raw_events" in card or "ocsf_events" in card:
            errors.append("llm evidence cards must not include raw or full OCSF events")
            break

    review = summary.get("review") or {}
    remediation = summary.get("remediation") or {}
    if remediation.get("status") == "dry_run" and review.get("status") != "approved":
        errors.append("dry-run remediation requires approved review state")

    integrity = summary.get("integrity") or {}
    audit = summary.get("audit") or {}
    if integrity.get("state_hash") != audit.get("state_hash"):
        errors.append("audit state_hash must match integrity state_hash")

    contract = summary.get("pipeline_contract") or {}
    triage_nodes = [
        node
        for node in contract.get("nodes") or []
        if node.get("node") == "llm_triage"
    ]
    if not triage_nodes:
        errors.append("pipeline contract must include llm_triage node")
    else:
        guardrails = set(triage_nodes[0].get("guardrails") or [])
        for required in ("closed_adapter_schema", "compact_evidence_only", "token_budget_enforced"):
            if required not in guardrails:
                errors.append(f"llm_triage guardrail missing: {required}")

    return tuple(errors)


def run_harness(config: HarnessRunConfig | None = None, *, check: bool = True) -> HarnessRunResult:
    """Run or replay the example harness and return state plus summary.

    Set `use_langgraph_runtime=True` to execute through a compiled LangGraph
    StateGraph. The default deterministic runner mirrors the same route
    decisions and keeps local/CI runs dependency-light.
    """
    config = config or HarnessRunConfig()
    checkpoint: dict[str, Any] | None = None
    replayed = bool(config.replay_checkpoint_path)
    if config.replay_checkpoint_path:
        final = load_checkpoint(Path(config.replay_checkpoint_path))
        execution_mode = "checkpoint_replay"
    else:
        initial = build_initial_state(config)
        if config.use_langgraph_runtime:
            final = run_langgraph(initial)
            execution_mode = "langgraph_stategraph"
        else:
            final = run_graph(initial)
            execution_mode = "deterministic_runner"
        if config.checkpoint_path:
            checkpoint = write_checkpoint(final, Path(config.checkpoint_path))

    summary = summarize(final)
    validation_errors = validate_harness_summary(summary)
    if check and validation_errors:
        raise ValueError("; ".join(validation_errors))

    runtime = {
        "schema_version": HARNESS_RUNTIME_VERSION,
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "execution_mode": execution_mode,
        "replayed": replayed,
        "profile_id": (summary.get("profile") or {}).get("profile_id"),
        "trace": summary.get("trace"),
        "validation_status": "pass" if not validation_errors else "fail",
    }
    return HarnessRunResult(
        runtime=runtime,
        final_state=final,
        summary=summary,
        checkpoint=checkpoint,
        validation_errors=validation_errors,
    )


def run_harness_summary(config: HarnessRunConfig | None = None, *, check: bool = True) -> dict[str, Any]:
    """Return the operator-facing summary with wrapper runtime metadata."""
    result = run_harness(config, check=check)
    return {
        "harness_runtime": result.runtime,
        **result.summary,
    }
