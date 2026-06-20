"""LangGraph-style SOC workflow with deterministic skill boundaries.

The production shape this models is:

    ingest -> normalize -> enrich -> correlate -> confidence score
    -> MITRE/CVSS/EPSS/KEV map -> analyst review -> dry-run remediation
    -> audit/eval writeback

Each node is intentionally a thin, deterministic wrapper around what a real
LangGraph node would call through MCP, CLI, CI, runner, or library surfaces.
LangGraph owns state, branches, retries, and checkpointing. The skill bundles
still own facts, schemas, scores, mappings, dry-run behavior, HITL gates, and
audit/eval artifacts.

The LangGraph SDK is not pinned as a repo dependency. This module stays
runnable offline and emits the same deterministic trace a graph runner would
produce. Real code would replace `run_graph` with `StateGraph` assembly and
keep these node functions as graph nodes.

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
from typing import Any, Literal, TypedDict

ALLOWED_SKILLS_READ_ONLY = ",".join([
    "ingest-cloudtrail-ocsf",
    "source-snowflake-query",
    "detect-lateral-movement",
    "cspm-aws-cis-benchmark",
    "discover-control-evidence",
    "convert-ocsf-to-sarif",
])
ALLOWED_SKILLS_REMEDIATION = "iam-departures-aws"

WorkflowStage = Literal[
    "ingest",
    "normalize",
    "enrich",
    "correlate",
    "confidence",
    "map",
    "review",
    "remediate",
    "writeback",
]
ApiErrorClassification = Literal["retryable", "terminal"]


class CallerContext(TypedDict):
    user_id: str
    email: str
    session_id: str
    roles: str


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
    raw_events: list[dict[str, Any]]
    ocsf_events: list[dict[str, Any]]
    findings: list[Finding]
    enrichments: dict[str, Enrichment]
    correlations: list[Correlation]
    confidence_scores: list[ConfidenceScore]
    framework_maps: list[FrameworkMap]
    review_decision: ReviewDecision
    remediation_result: RemediationResult
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


def ingest_node(state: GraphState) -> GraphState:
    """Collect raw evidence from an approved source surface."""
    _append_trace(state, "ingest")
    raw_events = state.get("raw_events") or [{
        "source": "cloudtrail",
        "event_name": "CreateAccessKey",
        "actor_uid": "AIDAEXAMPLE",
        "resource_uid": "arn:aws:iam::111122223333:user/build-bot",
    }]
    state["raw_events"] = raw_events
    _emit_node("ingest", allowlist=ALLOWED_SKILLS_READ_ONLY, records=len(raw_events))
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
    _emit_node("map", frameworks=["MITRE", "CVSS", "EPSS", "KEV", "CIS", "NIST"], mappings=len(maps))
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
    state["review_decision"] = decision
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
    _emit_node(
        "remediate",
        status="dry_run",
        allowlist=ALLOWED_SKILLS_REMEDIATION,
        dry_run=True,
        idempotency_key=remediation_key,
    )
    return state


def audit_eval_writeback_node(state: GraphState) -> GraphState:
    """Emit deterministic audit and eval records for the workflow run."""
    _append_trace(state, "writeback")
    summary_payload = {
        "caller_context": state.get("caller_context"),
        "trace": state.get("trace"),
        "findings": state.get("findings"),
        "integrity": {
            key: value
            for key, value in (state.get("integrity") or {}).items()
            if key != "state_hash"
        },
        "idempotency": state.get("idempotency"),
        "api_errors": state.get("api_errors") or [],
        "review_decision": state.get("review_decision"),
        "remediation_result": state.get("remediation_result"),
    }
    state_hash = _stable_hash(summary_payload)
    integrity = dict(state.get("integrity") or {})
    integrity["state_hash"] = state_hash
    state["integrity"] = integrity
    idempotency = state.get("idempotency") or {}
    api_errors = state.get("api_errors") or []
    audit_record = {
        "event": "agentic_soc_workflow",
        "correlation_id": state.get("caller_context", {}).get("session_id", "graph-demo-1"),
        "chain_hash": state_hash,
        "evidence_hash": integrity.get("evidence_hash"),
        "state_hash": state_hash,
        "idempotency_key": idempotency.get("remediation_key") or idempotency.get("workflow_key"),
        "api_error_count": len(api_errors),
        "retryable_api_error_count": sum(
            1 for error in api_errors if error["classification"] == "retryable"
        ),
        "remediation_status": state.get("remediation_result", {}).get("status"),
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
    analyst_review_node,
    dry_run_remediation_node,
    audit_eval_writeback_node,
)


def run_graph(initial: GraphState) -> GraphState:
    """Deterministic linear execution.

    A real LangGraph graph would add conditional edges for retries, sandbox
    replays, escalation, and checkpointing. The security invariant stays the
    same: every write path reaches `dry_run_remediation_node` only after
    `analyst_review_node` provides an approval context.
    """
    state: GraphState = dict(initial)
    for node in NODES:
        state = node(state)
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
    graph.add_node("review", analyst_review_node)
    graph.add_node("remediate", dry_run_remediation_node)
    graph.add_node("writeback", audit_eval_writeback_node)
    graph.add_edge(START, "ingest")
    graph.add_edge("ingest", "normalize")
    graph.add_edge("normalize", "enrich")
    graph.add_edge("enrich", "correlate")
    graph.add_edge("correlate", "confidence")
    graph.add_edge("confidence", "map")
    graph.add_edge("map", "review")
    graph.add_edge("review", "remediate")
    graph.add_edge("remediate", "writeback")
    graph.add_edge("writeback", END)
    return graph.compile()


def run_langgraph(initial: GraphState) -> GraphState:
    """Run the workflow through a compiled LangGraph StateGraph."""
    return dict(build_langgraph_app().invoke(dict(initial)))


def summarize(final: GraphState) -> dict[str, Any]:
    """Strip state to a stable operator-facing summary."""
    return {
        "caller_context": final.get("caller_context"),
        "trace": final.get("trace"),
        "findings_count": len(final.get("findings") or []),
        "confidence_scores": final.get("confidence_scores"),
        "framework_maps": final.get("framework_maps"),
        "review": final.get("review_decision"),
        "remediation": final.get("remediation_result"),
        "integrity": final.get("integrity"),
        "idempotency": final.get("idempotency"),
        "api_errors": final.get("api_errors") or [],
        "audit": final.get("audit_record"),
        "eval": final.get("eval_record"),
    }


def main() -> int:
    initial: GraphState = {
        "caller_context": {
            "user_id": "graph-demo-operator",
            "email": "graph-demo@example.com",
            "session_id": "graph-demo-1",
            "roles": "security_engineer",
        },
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
