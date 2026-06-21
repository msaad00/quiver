"""Bounded model adapters for the LangGraph SOC harness example.

Adapters may rank, summarize, and draft triage recommendations. They do not
own security facts, mappings, approval, idempotency, or audit state.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol

LlmMode = Literal["deterministic_offline", "external_llm_optional"]
Priority = Literal["critical", "high", "medium", "low"]
RecommendedAction = Literal["request_approval", "investigate", "close"]

ADAPTER_ALLOWED_KEYS = {"finding_uid", "priority", "recommended_action", "rationale"}
ADAPTER_FORBIDDEN_KEYS = {
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
ADAPTER_PRIORITIES = {"critical", "high", "medium", "low"}
ADAPTER_ACTIONS = {"request_approval", "investigate", "close"}


class TriageAdapter(Protocol):
    """Adapter contract for optional model-backed triage."""

    adapter_id: str

    def recommendations(self) -> list[dict[str, Any]]:
        """Return untrusted candidate recommendations."""


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_harness_config(
    *,
    profile_llm: Mapping[str, str] | None,
    environ: Mapping[str, str] = os.environ,
) -> dict[str, Any]:
    """Describe the LLM/agent harness without requiring a live model."""
    profile_llm = profile_llm or {}
    mode: LlmMode = (
        "external_llm_optional"
        if environ.get("DEMO_EXTERNAL_LLM_ALLOWED") == "yes"
        or profile_llm.get("mode") == "external_llm_optional"
        else "deterministic_offline"
    )
    provider = environ.get("DEMO_LLM_PROVIDER") or profile_llm.get("provider", "deterministic-local")
    model = environ.get("DEMO_LLM_MODEL") or profile_llm.get("model", "policy-bounded-triage-v1")
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
        "prompt_hash": stable_hash({
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


class DeterministicFallbackAdapter:
    adapter_id = "deterministic_fallback"

    def recommendations(self) -> list[dict[str, Any]]:
        return []


class FixtureTriageAdapter:
    adapter_id = "fixture_llm_adapter"

    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path

    def recommendations(self) -> list[dict[str, Any]]:
        payload = json.loads(self.fixture_path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            recommendations = payload.get("recommendations", [])
            return [item for item in recommendations if isinstance(item, dict)]
        return []


class LangChainChatFixtureAdapter:
    """Parse a LangChain chat-message fixture without calling a live model."""

    adapter_id = "langchain_chat_adapter"

    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path

    def recommendations(self) -> list[dict[str, Any]]:
        try:
            from langchain_core.messages import AIMessage
        except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional group
            raise RuntimeError(
                "LangChain adapter requires `uv sync --group langgraph` "
                "so langchain-core is available."
            ) from exc

        message = AIMessage(content=self.fixture_path.read_text(encoding="utf-8"))
        payload = json.loads(str(message.content))
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            recommendations = payload.get("recommendations", [])
            return [item for item in recommendations if isinstance(item, dict)]
        return []


def select_triage_adapter(
    *,
    harness_config: Mapping[str, Any],
    environ: Mapping[str, str] = os.environ,
) -> TriageAdapter:
    """Select the optional adapter without granting it extra authority."""
    langchain_fixture = environ.get("DEMO_LANGCHAIN_ADAPTER_FIXTURE")
    if langchain_fixture:
        return LangChainChatFixtureAdapter(Path(langchain_fixture))

    fixture_path = environ.get("DEMO_LLM_ADAPTER_FIXTURE")
    if fixture_path:
        return FixtureTriageAdapter(Path(fixture_path))

    if harness_config.get("provider") == "langchain":
        return DeterministicFallbackAdapter()

    return DeterministicFallbackAdapter()


def deterministic_triage_recommendation(
    *,
    finding_uid: str,
    mapped: Mapping[str, Any],
    confidence: float,
    harness_config: Mapping[str, Any],
) -> dict[str, Any]:
    recommended_action: RecommendedAction = (
        "request_approval" if confidence >= 0.90 else "investigate"
    )
    priority: Priority = "high" if mapped["cvss"]["base_score"] >= 7.0 else "medium"
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
        "output_hash": stable_hash(recommendation_payload)[:16],
    }


def validate_adapter_recommendation(
    *,
    candidate: Mapping[str, Any] | None,
    fallback: Mapping[str, Any],
    finding_uid: str,
    harness_config: Mapping[str, Any],
    adapter_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not candidate:
        return dict(fallback), {
            "finding_uid": finding_uid,
            "adapter": "deterministic_fallback",
            "status": "fallback",
            "reason": "no_adapter_output",
            "output_hash": fallback["output_hash"],
        }

    output_hash = stable_hash(candidate)[:16]
    forbidden = sorted(key for key in candidate if key in ADAPTER_FORBIDDEN_KEYS)
    extra = sorted(key for key in candidate if key not in ADAPTER_ALLOWED_KEYS)
    if forbidden:
        return dict(fallback), {
            "finding_uid": finding_uid,
            "adapter": adapter_id,
            "status": "rejected",
            "reason": f"forbidden_output:{','.join(forbidden)}",
            "output_hash": output_hash,
        }
    if extra:
        return dict(fallback), {
            "finding_uid": finding_uid,
            "adapter": adapter_id,
            "status": "rejected",
            "reason": f"unknown_output:{','.join(extra)}",
            "output_hash": output_hash,
        }
    if candidate.get("finding_uid") != finding_uid:
        return dict(fallback), {
            "finding_uid": finding_uid,
            "adapter": adapter_id,
            "status": "rejected",
            "reason": "finding_uid_mismatch",
            "output_hash": output_hash,
        }
    if candidate.get("priority") not in ADAPTER_PRIORITIES:
        return dict(fallback), {
            "finding_uid": finding_uid,
            "adapter": adapter_id,
            "status": "rejected",
            "reason": "invalid_priority",
            "output_hash": output_hash,
        }
    if candidate.get("recommended_action") not in ADAPTER_ACTIONS:
        return dict(fallback), {
            "finding_uid": finding_uid,
            "adapter": adapter_id,
            "status": "rejected",
            "reason": "invalid_recommended_action",
            "output_hash": output_hash,
        }

    rationale = str(candidate.get("rationale") or "").strip()
    if not rationale:
        return dict(fallback), {
            "finding_uid": finding_uid,
            "adapter": adapter_id,
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
    accepted = {
        "finding_uid": finding_uid,
        "priority": candidate["priority"],
        "recommended_action": candidate["recommended_action"],
        "rationale": rationale,
        "generated_by": f"{harness_config['provider']}:{harness_config['model']}",
        "output_hash": stable_hash(recommendation_payload)[:16],
    }
    return accepted, {
        "finding_uid": finding_uid,
        "adapter": adapter_id,
        "status": "accepted",
        "reason": "schema_valid",
        "output_hash": output_hash,
    }
