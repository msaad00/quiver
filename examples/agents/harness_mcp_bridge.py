"""MCP call planner for the LangGraph SOC harness example.

The live MCP wrapper owns execution, subprocess sandboxing, timeouts, HMAC
audit, and dry-run/HITL enforcement. This module keeps the LangGraph example
aligned to that wrapper by building the exact `tools/call` JSON-RPC payloads
the graph would send, while staying offline for tests and docs.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

CALLER_CONTEXT_KEYS = frozenset({
    "user_id",
    "email",
    "session_id",
    "roles",
    "allowed_skills",
})

APPROVAL_CONTEXT_KEYS = frozenset({
    "approver_id",
    "approver_email",
    "ticket_id",
    "approval_timestamp",
    "approver_ids",
    "approver_emails",
})

READ_ONLY_SKILLS = {
    "ingest-cloudtrail-ocsf",
    "source-snowflake-query",
    "source-clickhouse-query",
    "source-databricks-query",
    "detect-lateral-movement",
    "cspm-aws-cis-benchmark",
    "discover-control-evidence",
    "convert-ocsf-to-sarif",
}

REMEDIATION_SKILLS = {"iam-departures-aws"}
SOURCE_SKILLS = {
    "ingest-cloudtrail-ocsf",
    "source-snowflake-query",
    "source-clickhouse-query",
    "source-databricks-query",
}


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _validate_context(
    context: Mapping[str, Any] | None,
    *,
    allowed_keys: frozenset[str],
    label: str,
) -> dict[str, Any] | None:
    if context is None:
        return None
    validated: dict[str, Any] = {}
    for key, value in context.items():
        if key not in allowed_keys:
            raise ValueError(f"{label}.{key} is not accepted by the MCP wrapper")
        if isinstance(value, str):
            validated[key] = value
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            validated[key] = list(value)
        else:
            raise ValueError(f"{label}.{key} must be a string or array of strings")
    return validated


def _caller_context(raw: Mapping[str, Any] | None, allowed_skills: list[str]) -> dict[str, Any]:
    caller = _validate_context(raw, allowed_keys=CALLER_CONTEXT_KEYS, label="_caller_context") or {}
    profile_allowed = {skill for skill in allowed_skills if isinstance(skill, str) and skill.strip()}
    raw_caller_allowed = caller.get("allowed_skills")
    if isinstance(raw_caller_allowed, str):
        caller_allowed = {part.strip() for part in raw_caller_allowed.split(",") if part.strip()}
    elif isinstance(raw_caller_allowed, list):
        caller_allowed = {skill.strip() for skill in raw_caller_allowed if skill.strip()}
    else:
        caller_allowed = profile_allowed
    caller["allowed_skills"] = sorted(profile_allowed & caller_allowed)
    return caller


def _approval_context(raw: Mapping[str, Any] | None) -> dict[str, Any] | None:
    return _validate_context(raw, allowed_keys=APPROVAL_CONTEXT_KEYS, label="_approval_context")


def _cloudtrail_input(state: Mapping[str, Any]) -> str:
    rows = state.get("raw_events") or []
    return "\n".join(_stable_json(row) for row in rows if isinstance(row, dict)) + "\n"


def _ocsf_input(state: Mapping[str, Any]) -> str:
    rows = state.get("ocsf_events") or []
    return "\n".join(_stable_json(row) for row in rows if isinstance(row, dict)) + "\n"


def _finding_username(resource_uid: str) -> str:
    if "/" in resource_uid:
        return resource_uid.rsplit("/", 1)[-1] or "unknown"
    return "unknown"


def _finding_account_id(resource_uid: str) -> str:
    parts = resource_uid.split(":")
    if len(parts) > 4 and parts[4].isdigit() and len(parts[4]) == 12:
        return parts[4]
    return "111122223333"


def _remediation_manifest_input(state: Mapping[str, Any]) -> str:
    """Build a dry-run IAM departure manifest row from current findings.

    The shipped `iam-departures-aws` MCP entrypoint consumes newline-delimited
    manifest entries and is dry-run by default. The harness uses stable,
    non-secret identity fields derived from the finding resource ARN where
    available.
    """
    findings = state.get("findings") or []
    terminated_at = "2026-01-01T00:00:00+00:00"
    rows: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        resource_uid = str(finding.get("resource_uid") or "")
        username = _finding_username(resource_uid)
        rows.append({
            "email": f"{username or 'user'}@example.invalid",
            "recipient_account_id": _finding_account_id(resource_uid),
            "iam_username": username or f"user-{index}",
            "terminated_at": terminated_at,
        })
    return "\n".join(_stable_json(row) for row in rows) + ("\n" if rows else "")


def _skill_arguments(skill: str, state: Mapping[str, Any]) -> dict[str, Any]:
    source_decision = state.get("data_source_decision") or {}
    if skill == "ingest-cloudtrail-ocsf":
        return {
            "args": [],
            "input": _cloudtrail_input(state),
            "output_format": "ocsf",
        }
    if skill in {"source-snowflake-query", "source-clickhouse-query", "source-databricks-query"}:
        query = str(source_decision.get("query") or "SELECT payload FROM security.events_sink LIMIT 100")
        return {
            "args": ["--query", query],
            "input": "",
            "output_format": "raw",
        }
    if skill in {"detect-lateral-movement", "convert-ocsf-to-sarif"}:
        return {
            "args": [],
            "input": _ocsf_input(state),
            "output_format": "ocsf",
        }
    if skill == "iam-departures-aws":
        return {
            "args": [],
            "input": _remediation_manifest_input(state),
        }
    return {
        "args": [],
        "input": "",
    }


def build_tools_call(
    *,
    skill: str,
    state: Mapping[str, Any],
    request_id: str,
    caller_context: Mapping[str, Any],
    approval_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    arguments = _skill_arguments(skill, state)
    arguments["_caller_context"] = dict(caller_context)
    if approval_context:
        arguments["_approval_context"] = dict(approval_context)
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": skill,
            "arguments": arguments,
        },
    }


def _request_id(state: Mapping[str, Any], node: str, skill: str) -> str:
    idempotency = state.get("idempotency") or {}
    workflow_key = idempotency.get("workflow_key") or "wf-preview"
    return f"{workflow_key}:{node}:{skill}"


def build_mcp_call_plan(
    *,
    state: Mapping[str, Any],
    pipeline_contract: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Return planned MCP calls for skill-backed graph nodes.

    The plan is not an execution result. It lets operators and CI verify that
    LangGraph node ownership, caller scope, approval context, and dry-run write
    posture line up with the repo MCP wrapper before any stdio transport is
    invoked.
    """
    effective_allowed = list(state.get("effective_allowed_skills") or [])
    effective_allowed_set = set(effective_allowed)
    source_decision = state.get("data_source_decision") or {}
    selected_source_skill = source_decision.get("source_skill") or "ingest-cloudtrail-ocsf"
    records_format = source_decision.get("records_format") or "raw_vendor"
    caller = _caller_context(state.get("caller_context"), effective_allowed)
    caller_allowed_set = set(caller.get("allowed_skills") or [])
    approval = _approval_context(
        state.get("approval_context")
        or (state.get("review_decision") or {}).get("approval")
    )
    plan: list[dict[str, Any]] = []
    for node in pipeline_contract.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        node_name = str(node.get("node") or "")
        for skill in node.get("skills") or []:
            if node_name == "ingest" and skill in SOURCE_SKILLS and skill != selected_source_skill:
                status = "not_required"
                reason = f"data source mode selected {selected_source_skill}"
                request = None
            elif (
                skill == "ingest-cloudtrail-ocsf"
                and source_decision.get("mode") == "security_lake_replay"
                and records_format == "ocsf"
            ):
                status = "not_required"
                reason = "security data lake rows are already OCSF"
                request = None
            elif skill not in effective_allowed_set or skill not in caller_allowed_set:
                status = "blocked_by_allowlist"
                reason = "skill is outside effective profile/caller allowlist"
                request = None
            elif skill in REMEDIATION_SKILLS and approval is None:
                status = "blocked_by_hitl"
                reason = "write-capable skill requires approval context"
                request = None
            else:
                status = "planned"
                reason = "ready for MCP wrapper dry-run gate"
                request = build_tools_call(
                    skill=skill,
                    state=state,
                    request_id=_request_id(state, node_name, skill),
                    caller_context=caller,
                    approval_context=approval if skill in REMEDIATION_SKILLS else None,
                )
            plan.append({
                "node": node_name,
                "agent_id": node.get("agent_id"),
                "skill": skill,
                "status": status,
                "reason": reason,
                "read_only": skill in READ_ONLY_SKILLS,
                "write_capable": skill in REMEDIATION_SKILLS,
                "requires_approval_context": skill in REMEDIATION_SKILLS,
                "approval_context_attached": bool(request and skill in REMEDIATION_SKILLS),
                "caller_allowed_skill_count": len(caller.get("allowed_skills") or []),
                "transport": "mcp_stdio_jsonrpc",
                "request": request,
            })
    return plan
