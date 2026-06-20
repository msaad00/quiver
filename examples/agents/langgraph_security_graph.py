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
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypedDict

ALLOWED_SKILLS_READ_ONLY_LIST = [
    "ingest-cloudtrail-ocsf",
    "source-snowflake-query",
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


class AgentDefinition(TypedDict):
    agent_id: str
    kind: AgentKind
    owns: list[WorkflowStage]
    authority: str
    allowed_outputs: list[str]
    forbidden_outputs: list[str]


class AgentRunRecord(TypedDict):
    run_id: str
    agent_id: str
    stage: WorkflowStage
    authority: str
    input_hash: str
    output_hash: str


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
    audit_record: dict[str, Any]
    eval_record: EvalRecord
    trace: list[WorkflowStage]


def _emit_node(stage: WorkflowStage, **payload: Any) -> None:
    """Emit an audit-style JSON line without pretending to be the MCP server."""
    sys.stderr.write(json.dumps({"node": stage, **payload}, sort_keys=True) + "\n")


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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
        "approval_policy": {
            "remediation_requires_approval_context": True,
            "approval_source": "operator_idp_or_ticketing_system",
        },
        "runtime": {
            "langgraph_runtime_optional": True,
            "dry_run_default": True,
        },
    }


def load_harness_profile(path_text: str | None = None) -> HarnessProfile:
    """Load operator profile metadata without reading credentials or secrets."""
    selected = path_text or os.environ.get("CLOUD_SECURITY_HARNESS_PROFILE") or os.environ.get("DEMO_HARNESS_PROFILE")
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
    return profile


def _effective_allowed_skills(profile: HarnessProfile) -> list[str]:
    requested = profile.get("allowed_skills") or ALLOWED_SKILLS_READ_ONLY_LIST
    safe_surface = {*ALLOWED_SKILLS_READ_ONLY_LIST, ALLOWED_SKILLS_REMEDIATION}
    return [skill for skill in requested if skill in safe_surface]


def _agent_manifest() -> list[AgentDefinition]:
    return [
        {
            "agent_id": "evidence-agent",
            "kind": "deterministic_skill",
            "owns": ["ingest", "normalize", "enrich", "correlate"],
            "authority": "read_only_evidence_collection",
            "allowed_outputs": ["raw_events", "ocsf_events", "findings", "correlations"],
            "forbidden_outputs": ["approval", "write_intent", "policy_override"],
        },
        {
            "agent_id": "risk-map-agent",
            "kind": "deterministic_skill",
            "owns": ["confidence", "map"],
            "authority": "deterministic_security_facts",
            "allowed_outputs": ["confidence_scores", "framework_maps"],
            "forbidden_outputs": ["approval", "write_intent", "audit_chain_mutation"],
        },
        {
            "agent_id": "triage-agent",
            "kind": "llm_optional",
            "owns": ["llm_triage"],
            "authority": "rank_summarize_draft_only",
            "allowed_outputs": ["rank_findings", "summarize_evidence", "draft_analyst_note", "request_human_review"],
            "forbidden_outputs": ["approval", "cvss", "mitre", "epss", "kev", "write_intent", "audit_chain_mutation"],
        },
        {
            "agent_id": "review-gate",
            "kind": "human_gate",
            "owns": ["review"],
            "authority": "operator_attested_approval_only",
            "allowed_outputs": ["approved", "blocked", "approval_context"],
            "forbidden_outputs": ["synthetic_approval", "model_attested_approval"],
        },
        {
            "agent_id": "remediation-planner",
            "kind": "deterministic_skill",
            "owns": ["remediate"],
            "authority": "dry_run_after_hitl_only",
            "allowed_outputs": ["dry_run_plan", "idempotency_key", "retry_decision"],
            "forbidden_outputs": ["apply", "ungated_write", "new_idempotency_key_on_retry"],
        },
        {
            "agent_id": "retry-coordinator",
            "kind": "governance",
            "owns": ["retry_queue"],
            "authority": "bounded_retry_same_idempotency_key",
            "allowed_outputs": ["retry_record"],
            "forbidden_outputs": ["new_write_intent", "approval_bypass"],
        },
        {
            "agent_id": "escalation-agent",
            "kind": "governance",
            "owns": ["escalate"],
            "authority": "terminal_error_human_queue",
            "allowed_outputs": ["escalation_record"],
            "forbidden_outputs": ["auto_apply", "silent_drop"],
        },
        {
            "agent_id": "audit-writer",
            "kind": "deterministic_skill",
            "owns": ["writeback"],
            "authority": "append_only_audit_eval",
            "allowed_outputs": ["audit_record", "eval_record", "state_hash"],
            "forbidden_outputs": ["overwrite_history", "remove_agent_run"],
        },
    ]


def _agent_by_id(agent_id: str) -> AgentDefinition:
    for agent in _agent_manifest():
        if agent["agent_id"] == agent_id:
            return agent
    raise KeyError(agent_id)


def _record_agent_run(
    state: GraphState,
    *,
    agent_id: str,
    stage: WorkflowStage,
    inputs: Any,
    outputs: Any,
) -> None:
    state.setdefault("agent_manifest", _agent_manifest())
    agent = _agent_by_id(agent_id)
    runs = state.setdefault("agent_runs", [])
    runs.append({
        "run_id": f"run-{len(runs) + 1:02d}-{agent_id}",
        "agent_id": agent_id,
        "stage": stage,
        "authority": agent["authority"],
        "input_hash": _stable_hash(inputs)[:16],
        "output_hash": _stable_hash(outputs)[:16],
    })


def _agent_harness_config(state: GraphState) -> AgentHarnessConfig:
    """Describe the LLM/agent harness without requiring a live model."""
    profile_llm = (state.get("harness_profile") or {}).get("llm", {})
    mode: LlmMode = (
        "external_llm_optional"
        if os.environ.get("DEMO_EXTERNAL_LLM_ALLOWED") == "yes"
        or profile_llm.get("mode") == "external_llm_optional"
        else "deterministic_offline"
    )
    provider = os.environ.get("DEMO_LLM_PROVIDER") or profile_llm.get("provider", "deterministic-local")
    model = os.environ.get("DEMO_LLM_MODEL") or profile_llm.get("model", "policy-bounded-triage-v1")
    allowed_outputs = [
        "rank_findings",
        "summarize_evidence",
        "draft_analyst_note",
        "request_human_review",
    ]
    return {
        "mode": mode,
        "provider": provider,
        "model": model,
        "allowed_outputs": allowed_outputs,
        "prompt_hash": _stable_hash({
            "system": "llm may rank, summarize, and draft only",
            "forbidden": [
                "approve",
                "set_security_facts",
                "change_cvss_mitre_epss_kev",
                "call_write_tools",
                "write_audit",
            ],
            "allowed_outputs": allowed_outputs,
        })[:16],
    }


LLM_ADAPTER_ALLOWED_KEYS = {"finding_uid", "priority", "recommended_action", "rationale"}
LLM_ADAPTER_FORBIDDEN_KEYS = {
    "approval",
    "audit_chain_mutation",
    "cvss",
    "epss",
    "idempotency_key",
    "kev",
    "mitre",
    "tenant_scope",
    "write_intent",
}
LLM_ADAPTER_PRIORITIES = {"critical", "high", "medium", "low"}
LLM_ADAPTER_ACTIONS = {"request_approval", "investigate", "close"}


def _load_llm_adapter_recommendations() -> list[dict[str, Any]]:
    """Load an optional model-output fixture without requiring a live model."""
    fixture_path = os.environ.get("DEMO_LLM_ADAPTER_FIXTURE")
    if not fixture_path:
        return []
    payload = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        recommendations = payload.get("recommendations", [])
        return recommendations if isinstance(recommendations, list) else []
    return []


def _deterministic_triage_recommendation(
    *,
    finding_uid: str,
    mapped: FrameworkMap,
    confidence: float,
    harness_config: AgentHarnessConfig,
) -> AgentRecommendation:
    recommended_action: Literal["request_approval", "investigate", "close"] = (
        "request_approval" if confidence >= 0.90 else "investigate"
    )
    priority: Literal["critical", "high", "medium", "low"] = (
        "high" if mapped["cvss"]["base_score"] >= 7.0 else "medium"
    )
    recommendation_payload = {
        "finding_uid": finding_uid,
        "priority": priority,
        "recommended_action": recommended_action,
        "confidence": confidence,
        "provider": harness_config["provider"],
        "model": harness_config["model"],
    }
    return {
        "finding_uid": finding_uid,
        "priority": priority,
        "recommended_action": recommended_action,
        "rationale": "Deterministic triage from rule confidence, CVSS, EPSS, and mapping coverage.",
        "generated_by": f"{harness_config['provider']}:{harness_config['model']}",
        "output_hash": _stable_hash(recommendation_payload)[:16],
    }


def _validate_llm_adapter_recommendation(
    *,
    candidate: dict[str, Any] | None,
    fallback: AgentRecommendation,
    finding_uid: str,
    harness_config: AgentHarnessConfig,
) -> tuple[AgentRecommendation, LlmValidationRecord]:
    if not candidate:
        return fallback, {
            "finding_uid": finding_uid,
            "adapter": "deterministic_fallback",
            "status": "fallback",
            "reason": "no_adapter_output",
            "output_hash": fallback["output_hash"],
        }

    output_hash = _stable_hash(candidate)[:16]
    forbidden = sorted(key for key in candidate if key in LLM_ADAPTER_FORBIDDEN_KEYS)
    extra = sorted(key for key in candidate if key not in LLM_ADAPTER_ALLOWED_KEYS)
    if forbidden:
        return fallback, {
            "finding_uid": finding_uid,
            "adapter": "fixture_llm_adapter",
            "status": "rejected",
            "reason": f"forbidden_output:{','.join(forbidden)}",
            "output_hash": output_hash,
        }
    if extra:
        return fallback, {
            "finding_uid": finding_uid,
            "adapter": "fixture_llm_adapter",
            "status": "rejected",
            "reason": f"unknown_output:{','.join(extra)}",
            "output_hash": output_hash,
        }
    if candidate.get("finding_uid") != finding_uid:
        return fallback, {
            "finding_uid": finding_uid,
            "adapter": "fixture_llm_adapter",
            "status": "rejected",
            "reason": "finding_uid_mismatch",
            "output_hash": output_hash,
        }
    if candidate.get("priority") not in LLM_ADAPTER_PRIORITIES:
        return fallback, {
            "finding_uid": finding_uid,
            "adapter": "fixture_llm_adapter",
            "status": "rejected",
            "reason": "invalid_priority",
            "output_hash": output_hash,
        }
    if candidate.get("recommended_action") not in LLM_ADAPTER_ACTIONS:
        return fallback, {
            "finding_uid": finding_uid,
            "adapter": "fixture_llm_adapter",
            "status": "rejected",
            "reason": "invalid_recommended_action",
            "output_hash": output_hash,
        }

    rationale = str(candidate.get("rationale") or "").strip()
    if not rationale:
        return fallback, {
            "finding_uid": finding_uid,
            "adapter": "fixture_llm_adapter",
            "status": "rejected",
            "reason": "missing_rationale",
            "output_hash": output_hash,
        }

    recommendation_payload = {
        "finding_uid": finding_uid,
        "priority": candidate["priority"],
        "recommended_action": candidate["recommended_action"],
        "rationale": rationale,
        "provider": harness_config["provider"],
        "model": harness_config["model"],
    }
    accepted: AgentRecommendation = {
        "finding_uid": finding_uid,
        "priority": candidate["priority"],
        "recommended_action": candidate["recommended_action"],
        "rationale": rationale,
        "generated_by": f"{harness_config['provider']}:{harness_config['model']}",
        "output_hash": _stable_hash(recommendation_payload)[:16],
    }
    return accepted, {
        "finding_uid": finding_uid,
        "adapter": "fixture_llm_adapter",
        "status": "accepted",
        "reason": "schema_valid",
        "output_hash": output_hash,
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
    state.setdefault("agent_manifest", _agent_manifest())
    profile = state.setdefault("harness_profile", _default_harness_profile())
    effective_skills = _effective_allowed_skills(profile)
    state["effective_allowed_skills"] = effective_skills
    raw_events = state.get("raw_events") or [{
        "source": "cloudtrail",
        "event_name": "CreateAccessKey",
        "actor_uid": "AIDAEXAMPLE",
        "resource_uid": "arn:aws:iam::111122223333:user/build-bot",
    }]
    state["raw_events"] = raw_events
    _emit_node("ingest", allowlist=",".join(effective_skills), profile=profile["profile_id"], records=len(raw_events))
    return state


def normalize_node(state: GraphState) -> GraphState:
    """Normalize raw events into deterministic OCSF-shaped records."""
    _append_trace(state, "normalize")
    normalized = []
    for index, event in enumerate(state.get("raw_events") or []):
        event_uid = f"evt-{_stable_hash(event)[:12]}"
        normalized.append({
            "class_uid": 6003,
            "activity_name": event.get("event_name", "unknown"),
            "metadata": {"uid": event_uid, "version": "1.8.0"},
            "actor": {"uid": event.get("actor_uid", "unknown")},
            "resource": {"uid": event.get("resource_uid", f"resource-{index}")},
        })
    state["ocsf_events"] = normalized
    evidence_hash = _stable_hash(normalized)
    workflow_key = _stable_hash({
        "caller": state.get("caller_context", {}).get("session_id", "graph-demo-1"),
        "evidence_hash": evidence_hash,
    })[:16]
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
        findings.append({
            "uid": finding_uid,
            "title": "High-risk access key creation",
            "severity": "high",
            "rule_id": "detect-aws-access-key-creation",
            "resource_uid": event["resource"]["uid"],
        })
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
        event["resource"]["uid"]: event
        for event in state.get("ocsf_events") or []
    }
    correlations = []
    for finding in state.get("findings") or []:
        event = events_by_resource.get(finding.get("resource_uid", ""))
        correlations.append({
            "finding_uid": finding["uid"],
            "resource_uid": finding.get("resource_uid", "unknown"),
            "actor_uid": (event or {}).get("actor", {}).get("uid", "unknown"),
            "tool_name": "cloud-ai-security-skills",
            "window_minutes": 15,
        })
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
        enrichment = state.get("enrichments", {}).get(finding["uid"], {
            "epss_percentile": 0.0,
            "kev_listed": False,
        })
        maps.append({
            "finding_uid": finding["uid"],
            "mitre_attack": ["T1098"],
            "mitre_atlas": ["AML.TA0000"],
            "cvss": {"base_score": 8.1, "severity": "high", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"},
            "epss_percentile": enrichment["epss_percentile"],
            "kev_listed": enrichment["kev_listed"],
            "controls": ["CIS-1.4", "NIST-CSF-PR.AA"],
        })
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
    _emit_node("map", frameworks=["MITRE", "CVSS", "EPSS", "KEV", "CIS", "NIST"], mappings=len(maps))
    return state


def llm_triage_node(state: GraphState) -> GraphState:
    """Bounded agent layer: rank and summarize only, never decide facts."""
    _append_trace(state, "llm_triage")
    harness_config = _agent_harness_config(state)
    adapter_recommendations = {
        recommendation.get("finding_uid"): recommendation
        for recommendation in _load_llm_adapter_recommendations()
        if isinstance(recommendation, dict)
    }
    confidence_by_uid = {
        score["finding_uid"]: score["score"]
        for score in state.get("confidence_scores") or []
    }
    recommendations = []
    validation_records = []
    for mapped in state.get("framework_maps") or []:
        finding_uid = mapped["finding_uid"]
        confidence = confidence_by_uid.get(finding_uid, 0.0)
        fallback = _deterministic_triage_recommendation(
            finding_uid=finding_uid,
            mapped=mapped,
            confidence=confidence,
            harness_config=harness_config,
        )
        recommendation, validation = _validate_llm_adapter_recommendation(
            candidate=adapter_recommendations.get(finding_uid),
            fallback=fallback,
            finding_uid=finding_uid,
            harness_config=harness_config,
        )
        recommendations.append(recommendation)
        validation_records.append(validation)
    state["harness_config"] = harness_config
    state["agent_recommendations"] = recommendations
    state["llm_validation"] = validation_records
    _record_agent_run(
        state,
        agent_id="triage-agent",
        stage="llm_triage",
        inputs={
            "confidence_scores": state.get("confidence_scores"),
            "framework_maps": state.get("framework_maps"),
            "harness_config": harness_config,
        },
        outputs={
            "agent_recommendations": recommendations,
            "llm_validation": validation_records,
        },
    )
    _emit_node(
        "llm_triage",
        mode=harness_config["mode"],
        provider=harness_config["provider"],
        model=harness_config["model"],
        recommendations=len(recommendations),
        accepted=sum(1 for record in validation_records if record["status"] == "accepted"),
        rejected=sum(1 for record in validation_records if record["status"] == "rejected"),
        authority="rank_summarize_draft_only",
    )
    return state


def analyst_review_node(state: GraphState) -> GraphState:
    """Hard pause. No auto-approval and no hallucinated approval context."""
    _append_trace(state, "review")
    if os.environ.get("DEMO_APPROVE") == "yes":
        approval: ApprovalContext | None = {
            "approver_id": os.environ.get("DEMO_APPROVER", "operator@example.com"),
            "ticket_id": os.environ.get("DEMO_TICKET", "SEC-GRAPH-1"),
            "approval_timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
        decision: ReviewDecision = {
            "status": "approved",
            "reason": "operator approval present",
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
        _emit_node("remediate", status="skipped", reason="duplicate_idempotency_key", idempotency_key=remediation_key)
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
        "planned_steps": ["disable_access_key", "tag_principal_for_review", "write_evidence_bundle"],
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
    summary_payload = {
        "caller_context": state.get("caller_context"),
        "harness_profile": {
            "profile_id": (state.get("harness_profile") or {}).get("profile_id"),
            "allowed_skills": (state.get("harness_profile") or {}).get("allowed_skills"),
            "cloud_identity_hints": (state.get("harness_profile") or {}).get("cloud_identity_hints"),
            "approval_policy": (state.get("harness_profile") or {}).get("approval_policy"),
        },
        "effective_allowed_skills": state.get("effective_allowed_skills"),
        "trace": state.get("trace"),
        "findings": state.get("findings"),
        "harness_config": state.get("harness_config"),
        "agent_manifest": state.get("agent_manifest"),
        "agent_runs": state.get("agent_runs"),
        "agent_recommendations": state.get("agent_recommendations"),
        "llm_validation": state.get("llm_validation"),
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
        "llm_adapter_accepted": sum(1 for record in llm_validation if record["status"] == "accepted"),
        "llm_adapter_rejected": sum(1 for record in llm_validation if record["status"] == "rejected"),
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
            "multi_agent_ledger",
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
        state.setdefault("remediation_result", {
            "status": "skipped",
            "skill": ALLOWED_SKILLS_REMEDIATION,
            "reason": "review blocked; remediation node not routed",
        })
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
        "profile": final.get("harness_profile"),
        "effective_allowed_skills": final.get("effective_allowed_skills"),
        "trace": final.get("trace"),
        "findings_count": len(final.get("findings") or []),
        "confidence_scores": final.get("confidence_scores"),
        "framework_maps": final.get("framework_maps"),
        "harness": final.get("harness_config"),
        "agents": final.get("agent_manifest"),
        "agent_runs": final.get("agent_runs"),
        "agent_recommendations": final.get("agent_recommendations"),
        "llm_validation": final.get("llm_validation"),
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


def main() -> int:
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
    print(json.dumps(summarize(final), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
