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
    approval_context: Mapping[str, Any] | None = None
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
    state: GraphState = {
        "harness_profile": profile,
        "caller_context": caller_context,
        "raw_events": raw_events,
    }
    if config.approval_context:
        state["approval_context"] = dict(config.approval_context)
    return state


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
    if token_usage.get("status") == "within_budget" and token_usage.get(
        "compact_input_tokens_estimate", 0
    ) > token_budget.get("max_input_tokens", 0):
        errors.append("compact LLM input exceeds max_input_tokens")
    if token_usage.get("status") == "within_budget" and token_usage.get(
        "compact_evidence_chars", 0
    ) > token_budget.get("max_evidence_chars", 0):
        errors.append("compact LLM evidence exceeds max_evidence_chars")

    for card in summary.get("llm_evidence_cards") or []:
        if "raw_events" in card or "ocsf_events" in card:
            errors.append("llm evidence cards must not include raw or full OCSF events")
            break

    agents = {agent.get("agent_id"): agent for agent in summary.get("agents") or []}
    triage_agent = agents.get("triage-agent") or {}
    if triage_agent.get("privilege_boundary") != "no_tool_writes":
        errors.append("triage-agent must use no_tool_writes privilege boundary")
    if triage_agent.get("skill_scope") not in ((), []):
        errors.append("triage-agent must not have direct skill scope")
    if {"approval", "write_intent"} - set(triage_agent.get("forbidden_outputs") or []):
        errors.append("triage-agent must forbid approval and write_intent outputs")
    if triage_agent.get("model_tier") not in set(model_policy.get("allowed_model_tiers") or []):
        errors.append("triage-agent model tier must be allowed by model policy")

    remediation_agent = agents.get("remediation-planner") or {}
    if remediation_agent.get("requires_human_approval") is not True:
        errors.append("remediation-planner must require human approval")
    if remediation_agent.get("privilege_boundary") != "dry_run_write_planning":
        errors.append("remediation-planner must stay dry-run write planning only")

    agent_policy = summary.get("agent_policy") or {}
    if agent_policy.get("schema_version") != "langgraph-agent-policy-v1":
        errors.append("agent policy report must use langgraph-agent-policy-v1")
    if not agent_policy.get("policy_hash"):
        errors.append("agent policy report must include policy_hash")
    policy_entries = {entry.get("agent_id"): entry for entry in agent_policy.get("entries") or []}
    triage_policy = policy_entries.get("triage-agent") or {}
    if triage_policy.get("effective_skill_grants") not in ((), []):
        errors.append("triage-agent policy must not grant tool skills")
    if triage_policy.get("decision") != "no_direct_tools":
        errors.append("triage-agent policy decision must be no_direct_tools")
    remediation_policy = policy_entries.get("remediation-planner") or {}
    if remediation_policy.get("write_policy") != "dry_run_only_after_hitl":
        errors.append("remediation-planner policy must stay dry-run-only after HITL")

    review = summary.get("review") or {}
    remediation = summary.get("remediation") or {}
    if remediation.get("status") == "dry_run" and review.get("status") != "approved":
        errors.append("dry-run remediation requires approved review state")

    mcp_call_plan = list(summary.get("mcp_call_plan") or [])
    if not mcp_call_plan:
        errors.append("summary must include MCP call plan")
    planned_mcp_calls = [call for call in mcp_call_plan if call.get("status") == "planned"]
    for call in planned_mcp_calls:
        request = call.get("request") or {}
        params = request.get("params") or {}
        arguments = params.get("arguments") or {}
        if request.get("method") != "tools/call":
            errors.append("planned MCP call must use tools/call")
        if params.get("name") != call.get("skill"):
            errors.append("planned MCP call name must match skill")
        caller_context = arguments.get("_caller_context") or {}
        caller_allowed = set(caller_context.get("allowed_skills") or [])
        if call.get("skill") not in caller_allowed:
            errors.append("planned MCP call skill must be in caller allowed_skills")
        if call.get("write_capable") and not arguments.get("_approval_context"):
            errors.append("planned write-capable MCP call must attach approval context")
        if call.get("write_capable") and "--apply" in set(arguments.get("args") or []):
            errors.append("planned write-capable MCP call must not include --apply")
    for call in mcp_call_plan:
        if str(call.get("status", "")).startswith("blocked_") and call.get("request") is not None:
            errors.append("blocked MCP calls must not carry executable requests")

    integrity = summary.get("integrity") or {}
    audit = summary.get("audit") or {}
    if integrity.get("state_hash") != audit.get("state_hash"):
        errors.append("audit state_hash must match integrity state_hash")
    if audit.get("mcp_planned_call_count") != len(planned_mcp_calls):
        errors.append("audit MCP planned call count must match call plan")

    mcp_execution = summary.get("mcp_execution") or {}
    if mcp_execution.get("schema_version") != "langgraph-mcp-execution-v1":
        errors.append("summary must include MCP execution report")
    if mcp_execution.get("planned_call_count") != len(planned_mcp_calls):
        errors.append("MCP execution planned count must match call plan")
    if mcp_execution.get("write_executed_count", 0) > 0:
        errors.append("example harness must not execute write-capable MCP calls")
    if mcp_execution.get("mode") == "plan_only":
        if mcp_execution.get("executed_call_count") != 0:
            errors.append("plan_only MCP execution must not execute calls")
        status_counts = mcp_execution.get("status_counts") or {}
        if status_counts.get("skipped_plan_only", 0) != len(planned_mcp_calls):
            errors.append("plan_only MCP execution must skip every planned call")
    if audit.get("mcp_executed_call_count") != mcp_execution.get("executed_call_count"):
        errors.append("audit MCP executed count must match execution report")
    if audit.get("mcp_write_executed_count") != mcp_execution.get("write_executed_count"):
        errors.append("audit MCP write executed count must match execution report")

    contract = summary.get("pipeline_contract") or {}
    triage_nodes = [
        node for node in contract.get("nodes") or [] if node.get("node") == "llm_triage"
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


def run_harness_summary(
    config: HarnessRunConfig | None = None, *, check: bool = True
) -> dict[str, Any]:
    """Return the operator-facing summary with wrapper runtime metadata."""
    result = run_harness(config, check=check)
    return {
        "harness_runtime": result.runtime,
        **result.summary,
    }
