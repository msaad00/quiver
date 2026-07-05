"""LangGraph-style SOC workflow with deterministic skill boundaries.

The production shape this models is:

    ingest -> normalize -> enrich -> correlate -> confidence score
    -> MITRE/CVSS/EPSS/KEV map -> bounded LLM triage
    -> analyst review -> dry-run remediation -> audit/eval writeback

Each node is intentionally a thin, deterministic wrapper around what a real
LangGraph node would call through MCP, CLI, CI, runner, or library surfaces.
LangGraph owns state, branches, retries, and checkpointing. The skill bundles
still own facts, schemas, scores, mappings, dry-run behavior, HITL gates, and
audit/eval artifacts.

The LangGraph SDK is optional. This module stays runnable offline, and
`DEMO_LANGGRAPH_RUNTIME=yes` compiles the same nodes into a real StateGraph
with conditional edges for HITL, retry, escalation, and writeback routing.

Run:

    python examples/agents/langgraph_security_graph.py
    DEMO_APPROVE=yes python examples/agents/langgraph_security_graph.py
    DEMO_LANGGRAPH_RUNTIME=yes python examples/agents/langgraph_security_graph.py
    DEMO_CHECKPOINT_PATH=/tmp/langgraph-checkpoint.json python examples/agents/langgraph_security_graph.py
    DEMO_REPLAY_CHECKPOINT=/tmp/langgraph-checkpoint.json python examples/agents/langgraph_security_graph.py
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypedDict

from harness_adapters import (
    build_harness_config,
    deterministic_triage_recommendation,
    select_triage_adapter,
    validate_adapter_recommendation,
)
from harness_mcp_bridge import build_mcp_call_plan, execute_mcp_call_plan

ALLOWED_SKILLS_READ_ONLY_LIST = [
    "ingest-cloudtrail-ocsf",
    "source-snowflake-query",
    "source-clickhouse-query",
    "source-databricks-query",
    "detect-lateral-movement",
    "cspm-aws-cis-benchmark",
    "discover-control-evidence",
    "convert-ocsf-to-sarif",
]
ALLOWED_SKILLS_READ_ONLY = ",".join(ALLOWED_SKILLS_READ_ONLY_LIST)
ALLOWED_SKILLS_REMEDIATION = "iam-departures-aws"

WorkflowStage = Literal[
    "ingest",
    "normalize",
    "enrich",
    "correlate",
    "confidence",
    "map",
    "llm_triage",
    "review",
    "remediate",
    "retry_queue",
    "escalate",
    "writeback",
]
ApiErrorClassification = Literal["retryable", "terminal"]
LlmMode = Literal["deterministic_offline", "external_llm_optional"]
ReviewRoute = Literal["remediate", "writeback"]
RemediationRoute = Literal["retry_queue", "escalate", "writeback"]
AgentKind = Literal["deterministic_skill", "llm_optional", "human_gate", "governance"]
CHECKPOINT_SCHEMA_VERSION = "langgraph-soc-checkpoint-v1"


class CallerContext(TypedDict):
    user_id: str
    email: str
    session_id: str
    roles: str
    allowed_skills: list[str]


class HarnessProfile(TypedDict, total=False):
    profile_id: str
    description: str
    allowed_skills: list[str]
    caller_context: CallerContext
    cloud_identity_hints: dict[str, str]
    llm: dict[str, str]
    approval_policy: dict[str, Any]
    model_policy: dict[str, Any]
    agent_roster: list[dict[str, Any]]
    runtime: dict[str, Any]


class ApprovalContext(TypedDict):
    approver_id: str
    ticket_id: str
    approval_timestamp: str


class Finding(TypedDict, total=False):
    uid: str
    title: str
    severity: str
    rule_id: str
    resource_uid: str


class Enrichment(TypedDict):
    osv_ids: list[str]
    nvd_ids: list[str]
    epss_percentile: float
    kev_listed: bool


class Correlation(TypedDict):
    finding_uid: str
    resource_uid: str
    actor_uid: str
    tool_name: str
    window_minutes: int


class ConfidenceScore(TypedDict):
    finding_uid: str
    score: float
    reason_codes: list[str]


class FrameworkMap(TypedDict):
    finding_uid: str
    mitre_attack: list[str]
    mitre_atlas: list[str]
    cvss: dict[str, Any]
    epss_percentile: float
    kev_listed: bool
    controls: list[str]


class AgentHarnessConfig(TypedDict):
    mode: LlmMode
    provider: str
    model: str
    allowed_outputs: list[str]
    prompt_hash: str
    token_budget: dict[str, Any]
    model_policy: dict[str, Any]


class AgentDefinition(TypedDict):
    agent_id: str
    kind: AgentKind
    owns: list[WorkflowStage]
    authority: str
    privilege_boundary: str
    skill_scope: list[str]
    model_tier: str
    requires_human_approval: bool
    failure_route: str
    allowed_outputs: list[str]
    forbidden_outputs: list[str]


class PipelineNodeContract(TypedDict):
    node: WorkflowStage
    agent_id: str
    skills: list[str]
    inputs: list[str]
    outputs: list[str]
    guardrails: list[str]


class PipelineEdgeContract(TypedDict):
    source: WorkflowStage
    target: WorkflowStage
    condition: str


class AgentRunRecord(TypedDict, total=False):
    run_id: str
    agent_id: str
    stage: WorkflowStage
    authority: str
    input_hash: str
    output_hash: str
    token_budget: dict[str, Any]


class AgentPolicyEntry(TypedDict):
    agent_id: str
    kind: AgentKind
    privilege_boundary: str
    owns: list[WorkflowStage]
    requested_skill_scope: list[str]
    effective_skill_grants: list[str]
    denied_skill_scope: list[str]
    model_tier: str
    model_policy_tier: str
    requires_human_approval: bool
    approval_satisfied: bool
    write_policy: str
    decision: str


class AgentRecommendation(TypedDict):
    finding_uid: str
    priority: Literal["critical", "high", "medium", "low"]
    recommended_action: Literal["request_approval", "investigate", "close"]
    rationale: str
    generated_by: str
    output_hash: str


class LlmValidationRecord(TypedDict):
    finding_uid: str
    adapter: str
    status: Literal["accepted", "fallback", "rejected"]
    reason: str
    output_hash: str


class ReviewDecision(TypedDict):
    status: Literal["approved", "blocked"]
    reason: str
    approval: ApprovalContext | None


class RemediationResult(TypedDict, total=False):
    status: Literal["skipped", "dry_run"]
    skill: str
    reason: str
    dry_run: bool
    planned_steps: list[str]
    idempotency_key: str
    retry_decision: dict[str, Any]
    approval: ApprovalContext


class IntegrityRecord(TypedDict, total=False):
    evidence_hash: str
    approved_payload_hash: str | None
    state_hash: str


class IdempotencyRecord(TypedDict, total=False):
    workflow_key: str
    remediation_key: str | None
    duplicate_write_suppressed: bool


class ApiErrorRecord(TypedDict):
    stage: WorkflowStage
    status_code: int
    classification: ApiErrorClassification
    code: str
    message: str
    retry_after_seconds: int | None


class EvalRecord(TypedDict):
    dataset_version: str
    model_policy: str
    prompt_hash: str
    cases: list[str]
    status: Literal["pass", "blocked"]


class GraphState(TypedDict, total=False):
    caller_context: CallerContext
    approval_context: ApprovalContext
    harness_profile: HarnessProfile
    effective_allowed_skills: list[str]
    raw_events: list[dict[str, Any]]
    ocsf_events: list[dict[str, Any]]
    findings: list[Finding]
    enrichments: dict[str, Enrichment]
    correlations: list[Correlation]
    confidence_scores: list[ConfidenceScore]
    framework_maps: list[FrameworkMap]
    harness_config: AgentHarnessConfig
    agent_manifest: list[AgentDefinition]
    agent_policy: dict[str, Any]
    agent_runs: list[AgentRunRecord]
    agent_recommendations: list[AgentRecommendation]
    llm_validation: list[LlmValidationRecord]
    review_decision: ReviewDecision
    remediation_result: RemediationResult
    retry_record: dict[str, Any]
    escalation_record: dict[str, Any]
    integrity: IntegrityRecord
    idempotency: IdempotencyRecord
    api_errors: list[ApiErrorRecord]
    seen_idempotency_keys: list[str]
    llm_evidence_cards: list[dict[str, Any]]
    token_budget_usage: dict[str, Any]
    data_source_decision: dict[str, Any]
    mcp_call_plan: list[dict[str, Any]]
    mcp_execution: dict[str, Any]
    audit_record: dict[str, Any]
    eval_record: EvalRecord
    trace: list[WorkflowStage]


def _emit_node(stage: WorkflowStage, **payload: Any) -> None:
    """Emit an audit-style JSON line without pretending to be the MCP server."""
    sys.stderr.write(json.dumps({"node": stage, **payload}, sort_keys=True) + "\n")


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


DEFAULT_TOKEN_BUDGET = {
    "policy_version": "langgraph-token-budget-v1",
    "task_class": "triage_summary",
    "model_tier": "tiny",
    "max_input_tokens": 1200,
    "max_output_tokens": 256,
    "max_total_tokens": 1600,
    "max_findings_per_call": 5,
    "max_evidence_chars": 1800,
    "compression_required": True,
    "fallback_on_budget_exceeded": True,
}


DEFAULT_MODEL_POLICY = {
    "policy_version": "langgraph-model-policy-v1",
    "task_class": "triage_summary",
    "selection_strategy": "smallest_sufficient",
    "default_model_tier": "tiny",
    "allowed_model_tiers": ["tiny", "small"],
    "models": {
        "tiny": {
            "provider": "deterministic-local",
            "model": "policy-bounded-triage-v1",
        },
        "small": {
            "provider": "openai",
            "model": "gpt-4.1-mini",
        },
        "large": {
            "provider": "external-approved",
            "model": "operator-approved-large-model",
        },
    },
    "fallback": {
        "provider": "deterministic-local",
        "model": "policy-bounded-triage-v1",
    },
}

DEFAULT_AGENT_ROSTER: list[AgentDefinition] = [
    {
        "agent_id": "evidence-agent",
        "kind": "deterministic_skill",
        "owns": ["ingest", "normalize", "enrich", "correlate"],
        "authority": "read_only_evidence_collection",
        "privilege_boundary": "read_only",
        "skill_scope": [
            "ingest-cloudtrail-ocsf",
            "source-snowflake-query",
            "detect-lateral-movement",
            "discover-control-evidence",
        ],
        "model_tier": "none",
        "requires_human_approval": False,
        "failure_route": "writeback",
        "allowed_outputs": ["raw_events", "ocsf_events", "findings", "correlations"],
        "forbidden_outputs": ["approval", "write_intent", "policy_override"],
    },
    {
        "agent_id": "risk-map-agent",
        "kind": "deterministic_skill",
        "owns": ["confidence", "map"],
        "authority": "deterministic_security_facts",
        "privilege_boundary": "read_only",
        "skill_scope": ["detect-lateral-movement", "cspm-aws-cis-benchmark"],
        "model_tier": "none",
        "requires_human_approval": False,
        "failure_route": "writeback",
        "allowed_outputs": ["confidence_scores", "framework_maps"],
        "forbidden_outputs": ["approval", "write_intent", "audit_chain_mutation"],
    },
    {
        "agent_id": "triage-agent",
        "kind": "llm_optional",
        "owns": ["llm_triage"],
        "authority": "rank_summarize_draft_only",
        "privilege_boundary": "no_tool_writes",
        "skill_scope": [],
        "model_tier": "tiny",
        "requires_human_approval": False,
        "failure_route": "deterministic_fallback",
        "allowed_outputs": [
            "rank_findings",
            "summarize_evidence",
            "draft_analyst_note",
            "request_human_review",
        ],
        "forbidden_outputs": [
            "approval",
            "cvss",
            "mitre",
            "epss",
            "kev",
            "write_intent",
            "audit_chain_mutation",
        ],
    },
    {
        "agent_id": "review-gate",
        "kind": "human_gate",
        "owns": ["review"],
        "authority": "operator_attested_approval_only",
        "privilege_boundary": "approval_context_only",
        "skill_scope": [],
        "model_tier": "none",
        "requires_human_approval": True,
        "failure_route": "writeback",
        "allowed_outputs": ["approved", "blocked", "approval_context"],
        "forbidden_outputs": ["synthetic_approval", "model_attested_approval"],
    },
    {
        "agent_id": "remediation-planner",
        "kind": "deterministic_skill",
        "owns": ["remediate"],
        "authority": "dry_run_after_hitl_only",
        "privilege_boundary": "dry_run_write_planning",
        "skill_scope": [ALLOWED_SKILLS_REMEDIATION],
        "model_tier": "none",
        "requires_human_approval": True,
        "failure_route": "retry_or_escalate",
        "allowed_outputs": ["dry_run_plan", "idempotency_key", "retry_decision"],
        "forbidden_outputs": ["apply", "ungated_write", "new_idempotency_key_on_retry"],
    },
    {
        "agent_id": "retry-coordinator",
        "kind": "governance",
        "owns": ["retry_queue"],
        "authority": "bounded_retry_same_idempotency_key",
        "privilege_boundary": "retry_metadata_only",
        "skill_scope": [],
        "model_tier": "none",
        "requires_human_approval": True,
        "failure_route": "writeback",
        "allowed_outputs": ["retry_record"],
        "forbidden_outputs": ["new_write_intent", "approval_bypass"],
    },
    {
        "agent_id": "escalation-agent",
        "kind": "governance",
        "owns": ["escalate"],
        "authority": "terminal_error_human_queue",
        "privilege_boundary": "queue_metadata_only",
        "skill_scope": [],
        "model_tier": "none",
        "requires_human_approval": True,
        "failure_route": "writeback",
        "allowed_outputs": ["escalation_record"],
        "forbidden_outputs": ["auto_apply", "silent_drop"],
    },
    {
        "agent_id": "audit-writer",
        "kind": "deterministic_skill",
        "owns": ["writeback"],
        "authority": "append_only_audit_eval",
        "privilege_boundary": "append_only",
        "skill_scope": ["convert-ocsf-to-sarif"],
        "model_tier": "none",
        "requires_human_approval": False,
        "failure_route": "fail_closed",
        "allowed_outputs": ["audit_record", "eval_record", "state_hash"],
        "forbidden_outputs": ["overwrite_history", "remove_agent_run"],
    },
]


def _default_harness_profile() -> HarnessProfile:
    return {
        "profile_id": "inline-default",
        "description": "Dependency-light local demo profile.",
        "allowed_skills": ALLOWED_SKILLS_READ_ONLY_LIST,
        "caller_context": {
            "user_id": "graph-demo-operator",
            "email": "graph-demo@example.com",
            "session_id": "graph-demo-1",
            "roles": "security_engineer",
            "allowed_skills": ALLOWED_SKILLS_READ_ONLY_LIST,
        },
        "cloud_identity_hints": {
            "aws": "AWS_PROFILE=prod-readonly",
            "snowflake": "snowflake-cli auth login --authenticator externalbrowser",
        },
        "llm": {
            "mode": "deterministic_offline",
            "provider": "deterministic-local",
            "model": "policy-bounded-triage-v1",
        },
        "token_budget": DEFAULT_TOKEN_BUDGET,
        "model_policy": DEFAULT_MODEL_POLICY,
        "agent_roster": DEFAULT_AGENT_ROSTER,
        "approval_policy": {
            "remediation_requires_approval_context": True,
            "approval_source": "operator_idp_or_ticketing_system",
        },
        "runtime": {
            "langgraph_runtime_optional": True,
            "dry_run_default": True,
            "security_data_source": {
                "mode": "raw_ingest",
                "backend": "inline_events",
                "source_skill": "ingest-cloudtrail-ocsf",
                "records_format": "raw_vendor",
                "query": "",
            },
            "mcp_execution": {
                "mode": "plan_only",
                "transport": "mcp_stdio_jsonrpc",
                "execute_planned_calls": False,
                "allow_write_calls": False,
                "max_calls": 0,
            },
        },
    }


def _merge_agent_roster(profile_roster: list[dict[str, Any]] | None) -> list[AgentDefinition]:
    if not profile_roster:
        return [dict(agent) for agent in DEFAULT_AGENT_ROSTER]
    merged: list[AgentDefinition] = []
    for default in DEFAULT_AGENT_ROSTER:
        override = next(
            (agent for agent in profile_roster if agent.get("agent_id") == default["agent_id"]),
            {},
        )
        candidate = {**default, **override}
        if candidate["agent_id"] != default["agent_id"]:
            candidate["agent_id"] = default["agent_id"]
        if candidate["kind"] != default["kind"]:
            candidate["kind"] = default["kind"]
        if candidate["owns"] != default["owns"]:
            candidate["owns"] = default["owns"]
        if candidate["authority"] != default["authority"]:
            candidate["authority"] = default["authority"]
        if candidate["agent_id"] == "triage-agent":
            candidate["privilege_boundary"] = "no_tool_writes"
            candidate["skill_scope"] = []
            candidate["requires_human_approval"] = False
            candidate["forbidden_outputs"] = sorted(
                {
                    *default["forbidden_outputs"],
                    *candidate.get("forbidden_outputs", []),
                    "approval",
                    "write_intent",
                    "audit_chain_mutation",
                }
            )
        if candidate["agent_id"] == "remediation-planner":
            candidate["requires_human_approval"] = True
            candidate["privilege_boundary"] = "dry_run_write_planning"
            candidate["skill_scope"] = [ALLOWED_SKILLS_REMEDIATION]
            candidate["forbidden_outputs"] = sorted(
                {
                    *default["forbidden_outputs"],
                    *candidate.get("forbidden_outputs", []),
                    "apply",
                    "ungated_write",
                }
            )
        merged.append(candidate)  # type: ignore[arg-type]
    return merged


def load_harness_profile(path_text: str | None = None) -> HarnessProfile:
    """Load operator profile metadata without reading credentials or secrets."""
    selected = (
        path_text
        or os.environ.get("CLOUD_SECURITY_HARNESS_PROFILE")
        or os.environ.get("DEMO_HARNESS_PROFILE")
    )
    if not selected:
        return _default_harness_profile()
    payload = json.loads(Path(selected).read_text(encoding="utf-8"))
    default = _default_harness_profile()
    profile: HarnessProfile = {**default, **payload}
    profile["caller_context"] = {
        **default["caller_context"],
        **payload.get("caller_context", {}),
    }
    profile["llm"] = {
        **default["llm"],
        **payload.get("llm", {}),
    }
    profile["token_budget"] = {
        **default["token_budget"],
        **payload.get("token_budget", {}),
    }
    profile["model_policy"] = {
        **default["model_policy"],
        **payload.get("model_policy", {}),
    }
    profile["model_policy"]["models"] = {
        **default["model_policy"]["models"],
        **payload.get("model_policy", {}).get("models", {}),
    }
    profile["model_policy"]["fallback"] = {
        **default["model_policy"]["fallback"],
        **payload.get("model_policy", {}).get("fallback", {}),
    }
    profile["runtime"] = {
        **default["runtime"],
        **payload.get("runtime", {}),
    }
    profile["runtime"]["security_data_source"] = {
        **default["runtime"]["security_data_source"],
        **payload.get("runtime", {}).get("security_data_source", {}),
    }
    profile["runtime"]["mcp_execution"] = {
        **default["runtime"]["mcp_execution"],
        **payload.get("runtime", {}).get("mcp_execution", {}),
    }
    profile["agent_roster"] = _merge_agent_roster(payload.get("agent_roster"))
    return profile


def _effective_allowed_skills(profile: HarnessProfile) -> list[str]:
    requested = profile.get("allowed_skills") or ALLOWED_SKILLS_READ_ONLY_LIST
    safe_surface = {*ALLOWED_SKILLS_READ_ONLY_LIST, ALLOWED_SKILLS_REMEDIATION}
    return [skill for skill in requested if skill in safe_surface]


def _data_source_decision(profile: HarnessProfile) -> dict[str, Any]:
    source = (profile.get("runtime") or {}).get("security_data_source") or {}
    mode = source.get("mode") or "raw_ingest"
    backend = source.get("backend") or "inline_events"
    source_skill = source.get("source_skill") or (
        "ingest-cloudtrail-ocsf" if mode == "raw_ingest" else "source-snowflake-query"
    )
    return {
        "schema_version": "langgraph-security-data-source-v1",
        "mode": mode,
        "backend": backend,
        "source_skill": source_skill,
        "records_format": source.get("records_format")
        or ("raw_vendor" if mode == "raw_ingest" else "ocsf"),
        "query": source.get("query") or "",
        "raw_ingest_required": mode == "raw_ingest",
        "security_lake_replay": mode == "security_lake_replay",
        "decision_source": "harness_profile.runtime.security_data_source",
    }


def _agent_manifest(state: GraphState | None = None) -> list[AgentDefinition]:
    profile = (state or {}).get("harness_profile") if state else None
    if profile and profile.get("agent_roster"):
        return _merge_agent_roster(profile.get("agent_roster"))
    return [dict(agent) for agent in DEFAULT_AGENT_ROSTER]


def _pipeline_node_contracts(state: GraphState | None = None) -> list[PipelineNodeContract]:
    agent_by_id = {agent["agent_id"]: agent for agent in _agent_manifest(state)}
    return [
        {
            "node": "ingest",
            "agent_id": "evidence-agent",
            "skills": [
                "ingest-cloudtrail-ocsf",
                "source-snowflake-query",
                "source-clickhouse-query",
                "source-databricks-query",
            ],
            "inputs": ["harness_profile", "caller_context", "raw_events"],
            "outputs": ["effective_allowed_skills", "raw_events"],
            "guardrails": ["allowlist_intersection", "no_credentials_in_profile"],
        },
        {
            "node": "normalize",
            "agent_id": "evidence-agent",
            "skills": ["ingest-cloudtrail-ocsf"],
            "inputs": ["raw_events"],
            "outputs": ["ocsf_events", "integrity.evidence_hash", "idempotency.workflow_key"],
            "guardrails": ["ocsf_1_8_shape", "stable_event_uid", "state_hash_input"],
        },
        {
            "node": "enrich",
            "agent_id": "evidence-agent",
            "skills": ["detect-lateral-movement"],
            "inputs": ["ocsf_events"],
            "outputs": ["findings", "enrichments"],
            "guardrails": ["deterministic_finding_uid", "no_llm_security_facts"],
        },
        {
            "node": "correlate",
            "agent_id": "evidence-agent",
            "skills": ["discover-control-evidence"],
            "inputs": ["raw_events", "ocsf_events", "findings"],
            "outputs": ["correlations", "agent_runs"],
            "guardrails": ["identity_resource_join", "agent_run_hashes"],
        },
        {
            "node": "confidence",
            "agent_id": "risk-map-agent",
            "skills": ["detect-lateral-movement"],
            "inputs": ["findings", "enrichments"],
            "outputs": ["confidence_scores"],
            "guardrails": ["deterministic_reason_codes", "no_model_belief_score"],
        },
        {
            "node": "map",
            "agent_id": "risk-map-agent",
            "skills": ["cspm-aws-cis-benchmark"],
            "inputs": ["findings", "enrichments"],
            "outputs": ["framework_maps"],
            "guardrails": ["mitre_cvss_epss_kev_from_rules", "no_llm_mapping_mutation"],
        },
        {
            "node": "llm_triage",
            "agent_id": "triage-agent",
            "skills": [],
            "inputs": [
                "framework_maps",
                "confidence_scores",
                "harness_profile.llm",
                "token_budget",
            ],
            "outputs": [
                "agent_recommendations",
                "llm_validation",
                "agent_runs",
                "token_budget_usage",
            ],
            "guardrails": [
                "closed_adapter_schema",
                "rank_summarize_draft_only",
                "compact_evidence_only",
                "token_budget_enforced",
                "fallback_closed",
            ],
        },
        {
            "node": "review",
            "agent_id": "review-gate",
            "skills": [],
            "inputs": ["agent_recommendations", "approval_context"],
            "outputs": ["review_decision"],
            "guardrails": ["human_gate_required", "no_model_attested_approval"],
        },
        {
            "node": "remediate",
            "agent_id": "remediation-planner",
            "skills": agent_by_id["remediation-planner"]["skill_scope"],
            "inputs": ["review_decision", "framework_maps", "confidence_scores", "idempotency"],
            "outputs": ["remediation_result", "api_errors", "idempotency.remediation_key"],
            "guardrails": [
                "dry_run_default",
                "approval_context_required",
                "stable_idempotency_key",
            ],
        },
        {
            "node": "retry_queue",
            "agent_id": "retry-coordinator",
            "skills": [],
            "inputs": ["api_errors", "remediation_result"],
            "outputs": ["retry_record", "agent_runs"],
            "guardrails": ["bounded_retries", "reuse_idempotency_key", "retryable_errors_only"],
        },
        {
            "node": "escalate",
            "agent_id": "escalation-agent",
            "skills": [],
            "inputs": ["api_errors", "remediation_result"],
            "outputs": ["escalation_record", "agent_runs"],
            "guardrails": ["terminal_errors_to_human_queue", "no_auto_apply"],
        },
        {
            "node": "writeback",
            "agent_id": "audit-writer",
            "skills": ["convert-ocsf-to-sarif"],
            "inputs": ["trace", "agent_runs", "integrity", "idempotency", "api_errors"],
            "outputs": ["audit_record", "eval_record", "integrity.state_hash"],
            "guardrails": ["append_only_audit", "state_hash", "eval_writeback"],
        },
    ]


def _pipeline_edge_contracts() -> list[PipelineEdgeContract]:
    return [
        {"source": "ingest", "target": "normalize", "condition": "always"},
        {"source": "normalize", "target": "enrich", "condition": "always"},
        {"source": "enrich", "target": "correlate", "condition": "always"},
        {"source": "correlate", "target": "confidence", "condition": "always"},
        {"source": "confidence", "target": "map", "condition": "always"},
        {"source": "map", "target": "llm_triage", "condition": "always"},
        {"source": "llm_triage", "target": "review", "condition": "always"},
        {"source": "review", "target": "remediate", "condition": "route_after_review == remediate"},
        {"source": "review", "target": "writeback", "condition": "route_after_review == writeback"},
        {
            "source": "remediate",
            "target": "retry_queue",
            "condition": "route_after_remediation == retry_queue",
        },
        {
            "source": "remediate",
            "target": "escalate",
            "condition": "route_after_remediation == escalate",
        },
        {
            "source": "remediate",
            "target": "writeback",
            "condition": "route_after_remediation == writeback",
        },
        {"source": "retry_queue", "target": "writeback", "condition": "always"},
        {"source": "escalate", "target": "writeback", "condition": "always"},
    ]


def pipeline_contract(state: GraphState | None = None) -> dict[str, Any]:
    return {
        "schema_version": "langgraph-soc-pipeline-contract-v1",
        "description": "Code-backed LangGraph SOC workflow contract for nodes, edges, skills, and guardrails.",
        "nodes": _pipeline_node_contracts(state),
        "edges": _pipeline_edge_contracts(),
        "invariants": [
            "skills own facts; LangGraph owns routing and state",
            "LLM adapters can rank, summarize, draft, or request review only",
            "remediation is dry-run-only and requires human approval context",
            "API errors route to retry_queue only when classified retryable",
            "audit/eval writeback records state_hash and idempotency keys",
        ],
    }


def _agent_write_policy(agent: AgentDefinition) -> str:
    if agent["agent_id"] == "remediation-planner":
        return "dry_run_only_after_hitl"
    if agent["agent_id"] == "audit-writer":
        return "append_only_audit_eval"
    return "none"


def _agent_policy_decision(
    *,
    agent: AgentDefinition,
    effective_grants: list[str],
    denied_scope: list[str],
    approval_satisfied: bool,
) -> str:
    if agent["agent_id"] == "triage-agent":
        return "no_direct_tools"
    if denied_scope:
        return "blocked_by_allowlist"
    if agent["requires_human_approval"] and not approval_satisfied:
        return "requires_human_approval"
    if effective_grants or agent["kind"] in {"human_gate", "governance"}:
        return "ready"
    return "metadata_only"


def effective_agent_policy(state: GraphState) -> dict[str, Any]:
    """Compile profile, roster, and allowlist into per-agent grants."""
    profile = state.get("harness_profile") or {}
    effective_allowed = list(
        state.get("effective_allowed_skills") or _effective_allowed_skills(profile)
    )
    allowed_set = set(effective_allowed)
    harness_config = state.get("harness_config") or _agent_harness_config(state)
    selected_model_tier = (harness_config.get("model_policy") or {}).get("selected_model_tier")
    review_status = (state.get("review_decision") or {}).get("status")
    entries: list[AgentPolicyEntry] = []
    for agent in state.get("agent_manifest") or _agent_manifest(state):
        requested_scope = list(agent["skill_scope"])
        effective_grants = [skill for skill in requested_scope if skill in allowed_set]
        denied_scope = [skill for skill in requested_scope if skill not in allowed_set]
        approval_satisfied = not agent["requires_human_approval"] or review_status == "approved"
        model_policy_tier = selected_model_tier if agent["kind"] == "llm_optional" else "none"
        entries.append(
            {
                "agent_id": agent["agent_id"],
                "kind": agent["kind"],
                "privilege_boundary": agent["privilege_boundary"],
                "owns": list(agent["owns"]),
                "requested_skill_scope": requested_scope,
                "effective_skill_grants": effective_grants,
                "denied_skill_scope": denied_scope,
                "model_tier": agent["model_tier"],
                "model_policy_tier": model_policy_tier,
                "requires_human_approval": agent["requires_human_approval"],
                "approval_satisfied": approval_satisfied,
                "write_policy": _agent_write_policy(agent),
                "decision": _agent_policy_decision(
                    agent=agent,
                    effective_grants=effective_grants,
                    denied_scope=denied_scope,
                    approval_satisfied=approval_satisfied,
                ),
            }
        )
    payload = {
        "schema_version": "langgraph-agent-policy-v1",
        "profile_id": profile.get("profile_id"),
        "effective_allowed_skills": effective_allowed,
        "entries": entries,
    }
    return {
        **payload,
        "policy_hash": _stable_hash(payload)[:16],
    }


def preview_agent_policy(
    profile: HarnessProfile,
    *,
    approval_context_present: bool = False,
) -> dict[str, Any]:
    """Build a metadata-only policy preview without running graph nodes."""
    state: GraphState = {
        "harness_profile": profile,
        "caller_context": profile["caller_context"],
        "raw_events": [],
    }
    state["effective_allowed_skills"] = _effective_allowed_skills(profile)
    state["agent_manifest"] = _agent_manifest(state)
    state["harness_config"] = _agent_harness_config(state)
    if approval_context_present:
        state["review_decision"] = {
            "status": "approved",
            "reason": "preflight approval context supplied",
            "approval": {
                "approver_id": "preflight",
                "ticket_id": "PREFLIGHT",
                "approval_timestamp": "1970-01-01T00:00:00+00:00",
            },
        }
    else:
        state["review_decision"] = {
            "status": "blocked",
            "reason": "preflight only; approval context not supplied",
            "approval": None,
        }
    agent_policy = effective_agent_policy(state)
    remediation_entry = next(
        entry for entry in agent_policy["entries"] if entry["agent_id"] == "remediation-planner"
    )
    remediation_skill_granted = (
        ALLOWED_SKILLS_REMEDIATION in remediation_entry["effective_skill_grants"]
    )
    return {
        "schema_version": "langgraph-harness-preflight-v1",
        "profile_id": profile["profile_id"],
        "secrets_loaded": False,
        "cloud_calls_made": False,
        "approval_context_present": approval_context_present,
        "harness": state["harness_config"],
        "effective_allowed_skills": state["effective_allowed_skills"],
        "agent_policy": agent_policy,
        "remediation_preflight": {
            "skill": ALLOWED_SKILLS_REMEDIATION,
            "skill_granted": remediation_skill_granted,
            "approval_satisfied": remediation_entry["approval_satisfied"],
            "decision": remediation_entry["decision"],
            "write_policy": remediation_entry["write_policy"],
            "would_plan_dry_run": remediation_skill_granted and approval_context_present,
            "apply_supported": False,
        },
    }


def _record_agent_run(
    state: GraphState,
    *,
    agent_id: str,
    stage: WorkflowStage,
    inputs: Any,
    outputs: Any,
    token_budget: dict[str, Any] | None = None,
) -> None:
    state.setdefault("agent_manifest", _agent_manifest(state))
    agent_by_id = {agent["agent_id"]: agent for agent in state["agent_manifest"]}
    agent = agent_by_id[agent_id]
    runs = state.setdefault("agent_runs", [])
    record: AgentRunRecord = {
        "run_id": f"run-{len(runs) + 1:02d}-{agent_id}",
        "agent_id": agent_id,
        "stage": stage,
        "authority": agent["authority"],
        "input_hash": _stable_hash(inputs)[:16],
        "output_hash": _stable_hash(outputs)[:16],
    }
    if token_budget is not None:
        record["token_budget"] = token_budget
    runs.append(record)


def _agent_harness_config(state: GraphState) -> AgentHarnessConfig:
    """Describe the LLM/agent harness without requiring a live model."""
    profile = state.get("harness_profile") or {}
    profile_llm = profile.get("llm", {})
    return build_harness_config(
        profile_llm=profile_llm,
        profile_token_budget=profile.get("token_budget", DEFAULT_TOKEN_BUDGET),
        profile_model_policy=profile.get("model_policy", DEFAULT_MODEL_POLICY),
        environ=os.environ,
    )


def _estimate_tokens(payload: Any) -> int:
    """Cheap deterministic estimate: compact JSON chars divided by four."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return max(1, math.ceil(len(encoded) / 4))


def _compact_json_chars(payload: Any) -> int:
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _compact_evidence_cards(state: GraphState, budget: dict[str, Any]) -> list[dict[str, Any]]:
    confidence_by_uid = {
        score["finding_uid"]: score for score in state.get("confidence_scores") or []
    }
    findings_by_uid = {finding["uid"]: finding for finding in state.get("findings") or []}
    cards = []
    max_cards = int(budget["max_findings_per_call"])
    max_card_chars = max(160, int(budget["max_evidence_chars"]) // max_cards)
    for mapped in (state.get("framework_maps") or [])[:max_cards]:
        finding_uid = mapped["finding_uid"]
        finding = findings_by_uid.get(finding_uid, {})
        confidence = confidence_by_uid.get(finding_uid, {})
        cards.append(
            {
                "finding_uid": finding_uid,
                "title": str(finding.get("title", "security finding"))[:max_card_chars],
                "severity": finding.get("severity", mapped["cvss"]["severity"]),
                "confidence": confidence.get("score", 0.0),
                "reason_codes": [
                    str(reason)[:80] for reason in confidence.get("reason_codes", [])[:6]
                ],
                "mitre_attack": mapped["mitre_attack"],
                "mitre_atlas": mapped["mitre_atlas"],
                "cvss": {
                    "base_score": mapped["cvss"]["base_score"],
                    "severity": mapped["cvss"]["severity"],
                },
                "epss_percentile": mapped["epss_percentile"],
                "kev_listed": mapped["kev_listed"],
                "evidence_refs": [
                    f"finding_uid:{finding_uid}",
                    f"resource_uid:{finding.get('resource_uid', 'unknown')}",
                ],
            }
        )
    return cards


def _token_budget_usage(
    *,
    state: GraphState,
    harness_config: AgentHarnessConfig,
    evidence_cards: list[dict[str, Any]],
    recommendations: list[AgentRecommendation] | None = None,
) -> dict[str, Any]:
    budget = harness_config["token_budget"]
    raw_payload = {
        "raw_events": state.get("raw_events") or [],
        "ocsf_events": state.get("ocsf_events") or [],
        "framework_maps": state.get("framework_maps") or [],
        "confidence_scores": state.get("confidence_scores") or [],
    }
    raw_tokens = _estimate_tokens(raw_payload)
    compact_tokens = _estimate_tokens(evidence_cards)
    output_tokens = _estimate_tokens(recommendations or [])
    compact_chars = _compact_json_chars(evidence_cards)
    over_budget = (
        compact_tokens > budget["max_input_tokens"]
        or output_tokens > budget["max_output_tokens"]
        or compact_tokens + output_tokens > budget["max_total_tokens"]
        or compact_chars > budget["max_evidence_chars"]
    )
    return {
        "policy_version": budget["policy_version"],
        "task_class": budget["task_class"],
        "model_tier": budget["model_tier"],
        "model": harness_config["model"],
        "raw_input_tokens_estimate": raw_tokens,
        "compact_input_tokens_estimate": compact_tokens,
        "output_tokens_estimate": output_tokens,
        "max_input_tokens": budget["max_input_tokens"],
        "max_output_tokens": budget["max_output_tokens"],
        "max_total_tokens": budget["max_total_tokens"],
        "compact_evidence_chars": compact_chars,
        "max_evidence_chars": budget["max_evidence_chars"],
        "compression_required": budget["compression_required"],
        "compression_ratio": round(raw_tokens / compact_tokens, 2) if compact_tokens else 1.0,
        "cache_key": f"triage-{_stable_hash({'model': harness_config['model'], 'evidence': evidence_cards})[:16]}",
        "status": "fallback"
        if over_budget and budget["fallback_on_budget_exceeded"]
        else "within_budget",
        "fallback_reason": "token_budget_exceeded" if over_budget else None,
    }


def _classify_api_error(status_code: int) -> ApiErrorClassification:
    if status_code in {408, 409, 425, 429, 500, 502, 503, 504}:
        return "retryable"
    return "terminal"


def _simulated_api_error(stage: WorkflowStage) -> ApiErrorRecord | None:
    """Optional test hook for proving error classification without cloud calls."""
    if os.environ.get("DEMO_API_ERROR_STAGE", "remediate") != stage:
        return None
    status_text = os.environ.get("DEMO_API_ERROR_STATUS")
    if not status_text:
        return None
    try:
        status_code = int(status_text)
    except ValueError:
        status_code = 500
    classification = _classify_api_error(status_code)
    return {
        "stage": stage,
        "status_code": status_code,
        "classification": classification,
        "code": os.environ.get("DEMO_API_ERROR_CODE", f"HTTP_{status_code}"),
        "message": f"simulated upstream API status {status_code}",
        "retry_after_seconds": 30 if classification == "retryable" else None,
    }


def _append_trace(state: GraphState, stage: WorkflowStage) -> None:
    state.setdefault("trace", []).append(stage)


def route_after_review(state: GraphState) -> ReviewRoute:
    decision = state.get("review_decision") or {}
    return "remediate" if decision.get("status") == "approved" else "writeback"


def route_after_remediation(state: GraphState) -> RemediationRoute:
    result = state.get("remediation_result") or {}
    reason = result.get("reason")
    if reason == "retryable_api_error":
        return "retry_queue"
    if reason == "terminal_api_error":
        return "escalate"
    return "writeback"


def ingest_node(state: GraphState) -> GraphState:
    """Collect raw evidence from an approved source surface."""
    _append_trace(state, "ingest")
    profile = state.setdefault("harness_profile", _default_harness_profile())
    state["agent_manifest"] = _agent_manifest(state)
    effective_skills = _effective_allowed_skills(profile)
    state["effective_allowed_skills"] = effective_skills
    state["data_source_decision"] = _data_source_decision(profile)
    raw_events = state.get("raw_events") or [
        {
            "source": "cloudtrail",
            "event_name": "CreateAccessKey",
            "actor_uid": "AIDAEXAMPLE",
            "resource_uid": "arn:aws:iam::111122223333:user/build-bot",
        }
    ]
    state["raw_events"] = raw_events
    _emit_node(
        "ingest",
        allowlist=",".join(effective_skills),
        profile=profile["profile_id"],
        records=len(raw_events),
        data_source_mode=state["data_source_decision"]["mode"],
        source_skill=state["data_source_decision"]["source_skill"],
    )
    return state


def normalize_node(state: GraphState) -> GraphState:
    """Normalize raw events into deterministic OCSF-shaped records."""
    _append_trace(state, "normalize")
    normalized = []
    for index, event in enumerate(state.get("raw_events") or []):
        event_uid = f"evt-{_stable_hash(event)[:12]}"
        normalized.append(
            {
                "class_uid": 6003,
                "activity_name": event.get("event_name", "unknown"),
                "metadata": {"uid": event_uid, "version": "1.8.0"},
                "actor": {"uid": event.get("actor_uid", "unknown")},
                "resource": {"uid": event.get("resource_uid", f"resource-{index}")},
            }
        )
    state["ocsf_events"] = normalized
    evidence_hash = _stable_hash(normalized)
    workflow_key = _stable_hash(
        {
            "caller": state.get("caller_context", {}).get("session_id", "graph-demo-1"),
            "evidence_hash": evidence_hash,
        }
    )[:16]
    state["integrity"] = {
        "evidence_hash": evidence_hash,
        "approved_payload_hash": None,
    }
    state["idempotency"] = {
        "workflow_key": f"wf-{workflow_key}",
        "remediation_key": None,
        "duplicate_write_suppressed": False,
    }
    _emit_node("normalize", schema="OCSF 1.8", records=len(normalized))
    return state


def enrich_node(state: GraphState) -> GraphState:
    """Attach deterministic vulnerability and threat-intel context."""
    _append_trace(state, "enrich")
    enrichments: dict[str, Enrichment] = {}
    findings: list[Finding] = []
    for event in state.get("ocsf_events") or []:
        finding_uid = f"det-{event['metadata']['uid']}"
        findings.append(
            {
                "uid": finding_uid,
                "title": "High-risk access key creation",
                "severity": "high",
                "rule_id": "detect-aws-access-key-creation",
                "resource_uid": event["resource"]["uid"],
            }
        )
        enrichments[finding_uid] = {
            "osv_ids": [],
            "nvd_ids": ["CVE-2024-DEMO"],
            "epss_percentile": 0.91,
            "kev_listed": False,
        }
    state["findings"] = findings
    state["enrichments"] = enrichments
    _emit_node("enrich", providers=["OSV", "NVD", "EPSS", "KEV"], findings=len(findings))
    return state


def correlate_node(state: GraphState) -> GraphState:
    """Join findings to actor, tool, and resource lineage."""
    _append_trace(state, "correlate")
    events_by_resource = {
        event["resource"]["uid"]: event for event in state.get("ocsf_events") or []
    }
    correlations = []
    for finding in state.get("findings") or []:
        event = events_by_resource.get(finding.get("resource_uid", ""))
        correlations.append(
            {
                "finding_uid": finding["uid"],
                "resource_uid": finding.get("resource_uid", "unknown"),
                "actor_uid": (event or {}).get("actor", {}).get("uid", "unknown"),
                "tool_name": "cloud-ai-security-skills",
                "window_minutes": 15,
            }
        )
    state["correlations"] = correlations
    _record_agent_run(
        state,
        agent_id="evidence-agent",
        stage="correlate",
        inputs={
            "raw_events": state.get("raw_events"),
            "ocsf_events": state.get("ocsf_events"),
        },
        outputs={
            "findings": state.get("findings"),
            "correlations": correlations,
        },
    )
    _emit_node("correlate", joins=["identity", "resource", "tool"], correlations=len(correlations))
    return state


def confidence_node(state: GraphState) -> GraphState:
    """Score confidence using deterministic reason codes, not LLM belief."""
    _append_trace(state, "confidence")
    scores = []
    for finding in state.get("findings") or []:
        enrichment = state.get("enrichments", {}).get(finding["uid"])
        reason_codes = ["rule_match", "stable_resource_uid", "identity_correlation"]
        score = 0.86
        if enrichment and enrichment["epss_percentile"] >= 0.90:
            reason_codes.append("high_epss")
            score = 0.91
        scores.append({"finding_uid": finding["uid"], "score": score, "reason_codes": reason_codes})
    state["confidence_scores"] = scores
    _emit_node("confidence", scoring="deterministic_reason_codes", scores=len(scores))
    return state


def map_node(state: GraphState) -> GraphState:
    """Map to MITRE, CVSS, EPSS, KEV, and control frameworks."""
    _append_trace(state, "map")
    maps = []
    for finding in state.get("findings") or []:
        enrichment = state.get("enrichments", {}).get(
            finding["uid"],
            {
                "epss_percentile": 0.0,
                "kev_listed": False,
            },
        )
        maps.append(
            {
                "finding_uid": finding["uid"],
                "mitre_attack": ["T1098"],
                "mitre_atlas": ["AML.TA0000"],
                "cvss": {
                    "base_score": 8.1,
                    "severity": "high",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                },
                "epss_percentile": enrichment["epss_percentile"],
                "kev_listed": enrichment["kev_listed"],
                "controls": ["CIS-1.4", "NIST-CSF-PR.AA"],
            }
        )
    state["framework_maps"] = maps
    _record_agent_run(
        state,
        agent_id="risk-map-agent",
        stage="map",
        inputs={
            "findings": state.get("findings"),
            "enrichments": state.get("enrichments"),
            "confidence_scores": state.get("confidence_scores"),
        },
        outputs={"framework_maps": maps},
    )
    _emit_node(
        "map", frameworks=["MITRE", "CVSS", "EPSS", "KEV", "CIS", "NIST"], mappings=len(maps)
    )
    return state


def llm_triage_node(state: GraphState) -> GraphState:
    """Bounded agent layer: rank and summarize only, never decide facts."""
    _append_trace(state, "llm_triage")
    harness_config = _agent_harness_config(state)
    evidence_cards = _compact_evidence_cards(state, harness_config["token_budget"])
    initial_budget_usage = _token_budget_usage(
        state=state,
        harness_config=harness_config,
        evidence_cards=evidence_cards,
    )
    adapter = select_triage_adapter(harness_config=harness_config, environ=os.environ)
    adapter_recommendations = {}
    if initial_budget_usage["status"] != "fallback":
        adapter_recommendations = {
            recommendation.get("finding_uid"): recommendation
            for recommendation in adapter.recommendations()
            if isinstance(recommendation, dict)
        }
    confidence_by_uid = {
        score["finding_uid"]: score["score"] for score in state.get("confidence_scores") or []
    }
    recommendations = []
    validation_records = []
    for mapped in state.get("framework_maps") or []:
        finding_uid = mapped["finding_uid"]
        confidence = confidence_by_uid.get(finding_uid, 0.0)
        fallback = deterministic_triage_recommendation(
            finding_uid=finding_uid,
            mapped=mapped,
            confidence=confidence,
            harness_config=harness_config,
        )
        recommendation, validation = validate_adapter_recommendation(
            candidate=adapter_recommendations.get(finding_uid),
            fallback=fallback,
            finding_uid=finding_uid,
            harness_config=harness_config,
            adapter_id=adapter.adapter_id,
        )
        if initial_budget_usage["status"] == "fallback":
            validation = {
                "finding_uid": finding_uid,
                "adapter": "deterministic_fallback",
                "status": "fallback",
                "reason": initial_budget_usage["fallback_reason"],
                "output_hash": fallback["output_hash"],
            }
        recommendations.append(recommendation)
        validation_records.append(validation)
    budget_usage = _token_budget_usage(
        state=state,
        harness_config=harness_config,
        evidence_cards=evidence_cards,
        recommendations=recommendations,
    )
    state["harness_config"] = harness_config
    state["llm_evidence_cards"] = evidence_cards
    state["token_budget_usage"] = budget_usage
    state["agent_recommendations"] = recommendations
    state["llm_validation"] = validation_records
    _record_agent_run(
        state,
        agent_id="triage-agent",
        stage="llm_triage",
        inputs={
            "compact_evidence_cards": evidence_cards,
            "harness_config": harness_config,
        },
        outputs={
            "agent_recommendations": recommendations,
            "llm_validation": validation_records,
        },
        token_budget=budget_usage,
    )
    _emit_node(
        "llm_triage",
        mode=harness_config["mode"],
        provider=harness_config["provider"],
        model=harness_config["model"],
        recommendations=len(recommendations),
        accepted=sum(1 for record in validation_records if record["status"] == "accepted"),
        rejected=sum(1 for record in validation_records if record["status"] == "rejected"),
        token_status=budget_usage["status"],
        input_tokens=budget_usage["compact_input_tokens_estimate"],
        authority="rank_summarize_draft_only",
    )
    return state


def analyst_review_node(state: GraphState) -> GraphState:
    """Hard pause. No auto-approval and no hallucinated approval context."""
    _append_trace(state, "review")
    approval: ApprovalContext | None = state.get("approval_context")
    if approval:
        decision: ReviewDecision = {
            "status": "approved",
            "reason": "operator approval context present",
            "approval": approval,
        }
    elif os.environ.get("DEMO_APPROVE") == "yes":
        approval = {
            "approver_id": os.environ.get("DEMO_APPROVER", "operator@example.com"),
            "ticket_id": os.environ.get("DEMO_TICKET", "SEC-GRAPH-1"),
            "approval_timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
        decision: ReviewDecision = {
            "status": "approved",
            "reason": "operator approval env present",
            "approval": approval,
        }
    else:
        decision = {
            "status": "blocked",
            "reason": "missing approval_context",
            "approval": None,
        }
        state["remediation_result"] = {
            "status": "skipped",
            "skill": ALLOWED_SKILLS_REMEDIATION,
            "reason": "review blocked; remediation node not routed",
        }
    state["review_decision"] = decision
    _record_agent_run(
        state,
        agent_id="review-gate",
        stage="review",
        inputs={"agent_recommendations": state.get("agent_recommendations")},
        outputs=decision,
    )
    _emit_node("review", status=decision["status"], reason=decision["reason"])
    return state


def dry_run_remediation_node(state: GraphState) -> GraphState:
    """Plan remediation only after the review node supplies approval."""
    _append_trace(state, "remediate")
    decision = state.get("review_decision")
    approval = decision.get("approval") if decision else None
    if not approval:
        state["remediation_result"] = {
            "status": "skipped",
            "skill": ALLOWED_SKILLS_REMEDIATION,
            "reason": "no approval_context; HITL gate blocked remediation",
        }
        _record_agent_run(
            state,
            agent_id="remediation-planner",
            stage="remediate",
            inputs={"review_decision": decision},
            outputs=state["remediation_result"],
        )
        _emit_node("remediate", status="skipped", reason="hitl_not_approved")
        return state

    if ALLOWED_SKILLS_REMEDIATION not in set(state.get("effective_allowed_skills") or []):
        state["remediation_result"] = {
            "status": "skipped",
            "skill": ALLOWED_SKILLS_REMEDIATION,
            "reason": "remediation skill not in effective allowlist",
            "approval": approval,
        }
        _record_agent_run(
            state,
            agent_id="remediation-planner",
            stage="remediate",
            inputs={
                "review_decision": decision,
                "effective_allowed_skills": state.get("effective_allowed_skills"),
            },
            outputs=state["remediation_result"],
        )
        _emit_node("remediate", status="skipped", reason="skill_not_allowed")
        return state

    finding_uids = sorted(finding["uid"] for finding in state.get("findings") or [])
    approved_payload = {
        "approval_ticket": approval["ticket_id"],
        "dry_run": True,
        "finding_uids": finding_uids,
        "skill": ALLOWED_SKILLS_REMEDIATION,
    }
    approved_payload_hash = _stable_hash(approved_payload)
    remediation_key = f"rem-{approved_payload_hash[:16]}"
    integrity = dict(state.get("integrity") or {})
    integrity["approved_payload_hash"] = approved_payload_hash
    state["integrity"] = integrity
    idempotency = dict(state.get("idempotency") or {})
    idempotency["remediation_key"] = remediation_key
    state["idempotency"] = idempotency

    seen_keys = set(state.get("seen_idempotency_keys") or [])
    seen_keys.update(
        key.strip()
        for key in os.environ.get("DEMO_SEEN_IDEMPOTENCY_KEYS", "").split(",")
        if key.strip()
    )
    if remediation_key in seen_keys:
        idempotency["duplicate_write_suppressed"] = True
        state["idempotency"] = idempotency
        state["remediation_result"] = {
            "status": "skipped",
            "skill": ALLOWED_SKILLS_REMEDIATION,
            "reason": "duplicate idempotency key; write intent suppressed",
            "idempotency_key": remediation_key,
            "approval": approval,
        }
        _record_agent_run(
            state,
            agent_id="remediation-planner",
            stage="remediate",
            inputs=approved_payload,
            outputs=state["remediation_result"],
        )
        _emit_node(
            "remediate",
            status="skipped",
            reason="duplicate_idempotency_key",
            idempotency_key=remediation_key,
        )
        return state

    api_error = _simulated_api_error("remediate")
    if api_error:
        state.setdefault("api_errors", []).append(api_error)
        retry_decision = {
            "classification": api_error["classification"],
            "idempotency_key": remediation_key,
            "max_attempts": 3 if api_error["classification"] == "retryable" else 0,
            "retry_after_seconds": api_error["retry_after_seconds"],
        }
        state["remediation_result"] = {
            "status": "skipped",
            "skill": ALLOWED_SKILLS_REMEDIATION,
            "reason": f"{api_error['classification']}_api_error",
            "idempotency_key": remediation_key,
            "retry_decision": retry_decision,
            "approval": approval,
        }
        _record_agent_run(
            state,
            agent_id="remediation-planner",
            stage="remediate",
            inputs={**approved_payload, "api_error": api_error},
            outputs=state["remediation_result"],
        )
        _emit_node(
            "remediate",
            status="skipped",
            reason=f"{api_error['classification']}_api_error",
            idempotency_key=remediation_key,
            status_code=api_error["status_code"],
        )
        return state

    result: RemediationResult = {
        "status": "dry_run",
        "skill": ALLOWED_SKILLS_REMEDIATION,
        "dry_run": True,
        "planned_steps": [
            "disable_access_key",
            "tag_principal_for_review",
            "write_evidence_bundle",
        ],
        "idempotency_key": remediation_key,
        "approval": approval,
    }
    state["remediation_result"] = result
    _record_agent_run(
        state,
        agent_id="remediation-planner",
        stage="remediate",
        inputs=approved_payload,
        outputs=result,
    )
    _emit_node(
        "remediate",
        status="dry_run",
        allowlist=ALLOWED_SKILLS_REMEDIATION,
        dry_run=True,
        idempotency_key=remediation_key,
    )
    return state


def retry_queue_node(state: GraphState) -> GraphState:
    """Schedule a bounded retry without minting a new write intent."""
    _append_trace(state, "retry_queue")
    result = state.get("remediation_result") or {}
    retry_decision = result.get("retry_decision") or {}
    retry_record = {
        "status": "scheduled",
        "idempotency_key": retry_decision.get("idempotency_key"),
        "max_attempts": retry_decision.get("max_attempts", 0),
        "retry_after_seconds": retry_decision.get("retry_after_seconds"),
        "policy": "bounded_retry_same_idempotency_key",
    }
    state["retry_record"] = retry_record
    _record_agent_run(
        state,
        agent_id="retry-coordinator",
        stage="retry_queue",
        inputs={"remediation_result": result},
        outputs=retry_record,
    )
    _emit_node(
        "retry_queue",
        status=retry_record["status"],
        idempotency_key=retry_record["idempotency_key"],
        max_attempts=retry_record["max_attempts"],
    )
    return state


def escalation_node(state: GraphState) -> GraphState:
    """Escalate terminal API failures to a human queue."""
    _append_trace(state, "escalate")
    result = state.get("remediation_result") or {}
    escalation_record = {
        "status": "queued",
        "reason": result.get("reason", "manual_review_required"),
        "idempotency_key": result.get("idempotency_key"),
        "queue": "security-operations-review",
    }
    state["escalation_record"] = escalation_record
    _record_agent_run(
        state,
        agent_id="escalation-agent",
        stage="escalate",
        inputs={"remediation_result": result},
        outputs=escalation_record,
    )
    _emit_node(
        "escalate",
        status=escalation_record["status"],
        reason=escalation_record["reason"],
        queue=escalation_record["queue"],
    )
    return state


def audit_eval_writeback_node(state: GraphState) -> GraphState:
    """Emit deterministic audit and eval records for the workflow run."""
    _append_trace(state, "writeback")
    _record_agent_run(
        state,
        agent_id="audit-writer",
        stage="writeback",
        inputs={
            "trace": state.get("trace"),
            "review_decision": state.get("review_decision"),
            "remediation_result": state.get("remediation_result"),
            "retry_record": state.get("retry_record"),
            "escalation_record": state.get("escalation_record"),
        },
        outputs={"writeback": "audit_eval_pending"},
    )
    state["agent_policy"] = effective_agent_policy(state)
    state["mcp_call_plan"] = build_mcp_call_plan(
        state=state,
        pipeline_contract=pipeline_contract(state),
    )
    state["mcp_execution"] = execute_mcp_call_plan(
        call_plan=state["mcp_call_plan"],
        profile=state.get("harness_profile"),
    )
    summary_payload = {
        "caller_context": state.get("caller_context"),
        "harness_profile": {
            "profile_id": (state.get("harness_profile") or {}).get("profile_id"),
            "allowed_skills": (state.get("harness_profile") or {}).get("allowed_skills"),
            "cloud_identity_hints": (state.get("harness_profile") or {}).get(
                "cloud_identity_hints"
            ),
            "approval_policy": (state.get("harness_profile") or {}).get("approval_policy"),
        },
        "effective_allowed_skills": state.get("effective_allowed_skills"),
        "data_source_decision": state.get("data_source_decision"),
        "trace": state.get("trace"),
        "findings": state.get("findings"),
        "harness_config": state.get("harness_config"),
        "token_budget_usage": state.get("token_budget_usage"),
        "agent_manifest": state.get("agent_manifest"),
        "agent_policy": state.get("agent_policy"),
        "agent_runs": state.get("agent_runs"),
        "agent_recommendations": state.get("agent_recommendations"),
        "llm_validation": state.get("llm_validation"),
        "mcp_call_plan": state.get("mcp_call_plan"),
        "mcp_execution": state.get("mcp_execution"),
        "integrity": {
            key: value
            for key, value in (state.get("integrity") or {}).items()
            if key != "state_hash"
        },
        "idempotency": state.get("idempotency"),
        "api_errors": state.get("api_errors") or [],
        "review_decision": state.get("review_decision"),
        "remediation_result": state.get("remediation_result"),
        "retry_record": state.get("retry_record"),
        "escalation_record": state.get("escalation_record"),
    }
    state_hash = _stable_hash(summary_payload)
    integrity = dict(state.get("integrity") or {})
    integrity["state_hash"] = state_hash
    state["integrity"] = integrity
    idempotency = state.get("idempotency") or {}
    api_errors = state.get("api_errors") or []
    llm_validation = state.get("llm_validation") or []
    audit_record = {
        "event": "agentic_soc_workflow",
        "correlation_id": state.get("caller_context", {}).get("session_id", "graph-demo-1"),
        "profile_id": (state.get("harness_profile") or {}).get("profile_id"),
        "chain_hash": state_hash,
        "evidence_hash": integrity.get("evidence_hash"),
        "state_hash": state_hash,
        "idempotency_key": idempotency.get("remediation_key") or idempotency.get("workflow_key"),
        "api_error_count": len(api_errors),
        "agent_run_count": len(state.get("agent_runs") or []),
        "agent_policy_hash": (state.get("agent_policy") or {}).get("policy_hash"),
        "mcp_planned_call_count": sum(
            1 for call in state.get("mcp_call_plan") or [] if call.get("status") == "planned"
        ),
        "mcp_blocked_call_count": sum(
            1
            for call in state.get("mcp_call_plan") or []
            if str(call.get("status", "")).startswith("blocked_")
        ),
        "mcp_executed_call_count": (state.get("mcp_execution") or {}).get("executed_call_count", 0),
        "mcp_write_executed_count": (state.get("mcp_execution") or {}).get(
            "write_executed_count", 0
        ),
        "llm_adapter_accepted": sum(
            1 for record in llm_validation if record["status"] == "accepted"
        ),
        "llm_adapter_rejected": sum(
            1 for record in llm_validation if record["status"] == "rejected"
        ),
        "llm_token_budget_status": (state.get("token_budget_usage") or {}).get("status"),
        "llm_compact_input_tokens": (state.get("token_budget_usage") or {}).get(
            "compact_input_tokens_estimate"
        ),
        "retryable_api_error_count": sum(
            1 for error in api_errors if error["classification"] == "retryable"
        ),
        "remediation_status": state.get("remediation_result", {}).get("status"),
        "route": {
            "after_review": route_after_review(state),
            "after_remediation": route_after_remediation(state),
        },
    }
    eval_status: Literal["pass", "blocked"] = (
        "pass" if state.get("remediation_result", {}).get("status") == "dry_run" else "blocked"
    )
    eval_record: EvalRecord = {
        "dataset_version": "agentic-soc-demo-v1",
        "model_policy": "llm_may_rank_summarize_draft_only",
        "prompt_hash": _stable_hash({"policy": "no_llm_authoritative_security_facts"})[:16],
        "cases": [
            "hitl_gate",
            "dry_run_required",
            "mapping_trace_present",
            "integrity_hash_present",
            "idempotency_key_stable",
            "api_error_classification",
            "llm_harness_bounded",
            "llm_adapter_schema_gate",
            "llm_token_budget_gate",
            "multi_agent_ledger",
            "mcp_call_plan",
            "mcp_execution_policy",
            "conditional_edges",
        ],
        "status": eval_status,
    }
    state["audit_record"] = audit_record
    state["eval_record"] = eval_record
    _emit_node("writeback", audit=True, eval_status=eval_status)
    return state


NODES = (
    ingest_node,
    normalize_node,
    enrich_node,
    correlate_node,
    confidence_node,
    map_node,
    llm_triage_node,
    analyst_review_node,
)


def run_graph(initial: GraphState) -> GraphState:
    """Deterministic execution that mirrors the StateGraph route decisions."""
    state: GraphState = dict(initial)
    for node in NODES:
        state = node(state)
    if route_after_review(state) == "remediate":
        state = dry_run_remediation_node(state)
        remediation_route = route_after_remediation(state)
        if remediation_route == "retry_queue":
            state = retry_queue_node(state)
        elif remediation_route == "escalate":
            state = escalation_node(state)
    else:
        state.setdefault(
            "remediation_result",
            {
                "status": "skipped",
                "skill": ALLOWED_SKILLS_REMEDIATION,
                "reason": "review blocked; remediation node not routed",
            },
        )
    state = audit_eval_writeback_node(state)
    return state


def build_langgraph_app() -> Any:
    """Compile the real LangGraph app.

    Kept behind an optional import so the repository can run the deterministic
    example without pulling LangGraph into the base environment.
    """
    try:
        from langgraph.graph import END, START, StateGraph
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised by CLI path
        raise RuntimeError(
            "LangGraph is not installed. Run `uv sync --group dev --group langgraph` "
            "or use the default deterministic trace runner."
        ) from exc

    graph = StateGraph(GraphState)
    graph.add_node("ingest", ingest_node)
    graph.add_node("normalize", normalize_node)
    graph.add_node("enrich", enrich_node)
    graph.add_node("correlate", correlate_node)
    graph.add_node("confidence", confidence_node)
    graph.add_node("map", map_node)
    graph.add_node("llm_triage", llm_triage_node)
    graph.add_node("review", analyst_review_node)
    graph.add_node("remediate", dry_run_remediation_node)
    graph.add_node("retry_queue", retry_queue_node)
    graph.add_node("escalate", escalation_node)
    graph.add_node("writeback", audit_eval_writeback_node)
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
        {
            "remediate": "remediate",
            "writeback": "writeback",
        },
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
    return graph.compile()


def run_langgraph(initial: GraphState) -> GraphState:
    """Run the workflow through a compiled LangGraph StateGraph."""
    return dict(build_langgraph_app().invoke(dict(initial)))


def summarize(final: GraphState) -> dict[str, Any]:
    """Strip state to a stable operator-facing summary."""
    return {
        "caller_context": final.get("caller_context"),
        "approval_context_present": bool(
            final.get("approval_context") or (final.get("review_decision") or {}).get("approval")
        ),
        "profile": final.get("harness_profile"),
        "effective_allowed_skills": final.get("effective_allowed_skills"),
        "data_source": final.get("data_source_decision"),
        "trace": final.get("trace"),
        "findings_count": len(final.get("findings") or []),
        "confidence_scores": final.get("confidence_scores"),
        "framework_maps": final.get("framework_maps"),
        "harness": final.get("harness_config"),
        "pipeline_contract": pipeline_contract(final),
        "agents": final.get("agent_manifest"),
        "agent_policy": final.get("agent_policy"),
        "agent_runs": final.get("agent_runs"),
        "agent_recommendations": final.get("agent_recommendations"),
        "llm_validation": final.get("llm_validation"),
        "mcp_call_plan": final.get("mcp_call_plan"),
        "mcp_execution": final.get("mcp_execution"),
        "llm_evidence_cards": final.get("llm_evidence_cards"),
        "token_budget_usage": final.get("token_budget_usage"),
        "review": final.get("review_decision"),
        "remediation": final.get("remediation_result"),
        "retry": final.get("retry_record"),
        "escalation": final.get("escalation_record"),
        "integrity": final.get("integrity"),
        "idempotency": final.get("idempotency"),
        "api_errors": final.get("api_errors") or [],
        "audit": final.get("audit_record"),
        "eval": final.get("eval_record"),
    }


def _checkpoint_payload(final: GraphState) -> dict[str, Any]:
    """Build a replayable state artifact with stable hashes."""
    summary = summarize(final)
    state = dict(final)
    payload = {
        "event": "langgraph_soc_checkpoint",
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "profile_id": (final.get("harness_profile") or {}).get("profile_id"),
        "trace": final.get("trace"),
        "state_hash": (final.get("integrity") or {}).get("state_hash"),
        "summary_hash": _stable_hash(summary),
        "state": state,
    }
    payload["checkpoint_hash"] = _stable_hash(payload)
    return payload


def write_checkpoint(final: GraphState, checkpoint_path: Path) -> dict[str, Any]:
    """Persist a replay artifact for offline audit and regression checks."""
    payload = _checkpoint_payload(final)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "path": str(checkpoint_path),
        "checkpoint_hash": payload["checkpoint_hash"],
        "state_hash": payload["state_hash"],
        "summary_hash": payload["summary_hash"],
    }


def load_checkpoint(checkpoint_path: Path) -> GraphState:
    """Load and verify a checkpoint artifact without re-running graph nodes."""
    payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    expected_hash = payload.get("checkpoint_hash")
    unsigned_payload = dict(payload)
    unsigned_payload.pop("checkpoint_hash", None)
    if payload.get("event") != "langgraph_soc_checkpoint":
        raise ValueError("checkpoint event must be langgraph_soc_checkpoint")
    if payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise ValueError(f"unsupported checkpoint schema: {payload.get('schema_version')}")
    if _stable_hash(unsigned_payload) != expected_hash:
        raise ValueError("checkpoint_hash mismatch")
    state = payload.get("state")
    if not isinstance(state, dict):
        raise ValueError("checkpoint state must be an object")
    summary_hash = _stable_hash(summarize(state))
    if summary_hash != payload.get("summary_hash"):
        raise ValueError("checkpoint summary_hash mismatch")
    state_hash = (state.get("integrity") or {}).get("state_hash")
    if state_hash != payload.get("state_hash"):
        raise ValueError("checkpoint state_hash mismatch")
    return state


def main() -> int:
    replay_path = os.environ.get("DEMO_REPLAY_CHECKPOINT")
    if replay_path:
        final = load_checkpoint(Path(replay_path))
    else:
        profile = load_harness_profile()
        initial: GraphState = {
            "harness_profile": profile,
            "caller_context": profile["caller_context"],
            "raw_events": [{"source": "demo"}],
        }
        if os.environ.get("DEMO_LANGGRAPH_RUNTIME") == "yes":
            final = run_langgraph(initial)
        else:
            final = run_graph(initial)
        if checkpoint_path := os.environ.get("DEMO_CHECKPOINT_PATH"):
            write_checkpoint(final, Path(checkpoint_path))
    print(json.dumps(summarize(final), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
