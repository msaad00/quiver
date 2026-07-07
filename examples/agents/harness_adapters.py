"""Bounded model adapters for the LangGraph SOC harness example.

Adapters may rank, summarize, and draft triage recommendations. They do not
own security facts, mappings, approval, idempotency, or audit state.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
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
    profile_token_budget: Mapping[str, Any] | None = None,
    profile_model_policy: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] = os.environ,
) -> dict[str, Any]:
    """Describe the LLM/agent harness without requiring a live model."""
    profile_llm = profile_llm or {}
    token_budget = dict(profile_token_budget or {})
    model_policy = dict(profile_model_policy or {})
    model_tier = str(
        token_budget.get("model_tier") or model_policy.get("default_model_tier") or "tiny"
    )
    allowed_tiers = set(model_policy.get("allowed_model_tiers") or [model_tier])
    if model_tier not in allowed_tiers:
        model_tier = str(model_policy.get("default_model_tier") or "tiny")
        token_budget["model_tier"] = model_tier
    model_by_tier = dict((model_policy.get("models") or {}).get(model_tier) or {})
    fallback_model = dict(model_policy.get("fallback") or {})
    mode: LlmMode = (
        "external_llm_optional"
        if environ.get("DEMO_EXTERNAL_LLM_ALLOWED") == "yes"
        or profile_llm.get("mode") == "external_llm_optional"
        or model_by_tier.get("provider") not in {None, "deterministic-local"}
        else "deterministic_offline"
    )
    env_override = bool(environ.get("DEMO_LLM_PROVIDER") or environ.get("DEMO_LLM_MODEL"))
    provider = (
        environ.get("DEMO_LLM_PROVIDER")
        or model_by_tier.get("provider")
        or profile_llm.get("provider")
        or fallback_model.get("provider")
        or "deterministic-local"
    )
    model = (
        environ.get("DEMO_LLM_MODEL")
        or model_by_tier.get("model")
        or profile_llm.get("model")
        or fallback_model.get("model")
        or "policy-bounded-triage-v1"
    )
    if environ.get("DEMO_TOKEN_MAX_INPUT_TOKENS"):
        token_budget["max_input_tokens"] = int(environ["DEMO_TOKEN_MAX_INPUT_TOKENS"])
    if environ.get("DEMO_TOKEN_MAX_TOTAL_TOKENS"):
        token_budget["max_total_tokens"] = int(environ["DEMO_TOKEN_MAX_TOTAL_TOKENS"])
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
        "token_budget": token_budget,
        "model_policy": {
            "policy_version": model_policy.get("policy_version", "langgraph-model-policy-v1"),
            "task_class": model_policy.get(
                "task_class", token_budget.get("task_class", "triage_summary")
            ),
            "selection_strategy": model_policy.get("selection_strategy", "smallest_sufficient"),
            "selected_model_tier": model_tier,
            "allowed_model_tiers": sorted(allowed_tiers),
            "selection_source": "env_override" if env_override else "profile_model_policy",
        },
        "allowed_outputs": allowed_outputs,
        "prompt_hash": stable_hash(
            {
                "system": "llm may rank, summarize, and draft only",
                "forbidden": [
                    "approve",
                    "set_security_facts",
                    "change_cvss_mitre_epss_kev",
                    "call_write_tools",
                    "write_audit",
                ],
                "allowed_outputs": allowed_outputs,
                "model_policy": model_policy.get("policy_version", "langgraph-model-policy-v1"),
            }
        )[:16],
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


_DEFAULT_LIVE_TIMEOUT_SECONDS = 30
_MAX_LIVE_TIMEOUT_SECONDS = 120
_MAX_LIVE_OUTPUT_TOKENS = 1024
_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

_LIVE_SYSTEM_PROMPT = (
    "You are a bounded SOC triage assistant. You may rank, summarize, and "
    "draft only. You never approve actions, never set CVSS/MITRE/EPSS/KEV "
    "facts, never set tenant scope or write intent, and never mutate audit "
    "state. For each evidence card, reply with STRICT JSON only: an array of "
    'objects with exactly these keys: "finding_uid" (copy it verbatim), '
    '"priority" (one of critical|high|medium|low), "recommended_action" '
    '(one of request_approval|investigate|close), and "rationale" (one or '
    "two sentences). No prose outside the JSON."
)


def _parse_adapter_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        recommendations = payload.get("recommendations", [])
        return [item for item in recommendations if isinstance(item, dict)]
    return []


class OpenAICompatTriageAdapter:
    """Live BYOM adapter for any OpenAI-compatible chat-completions endpoint.

    One adapter covers OpenAI, Azure OpenAI, Ollama, vLLM, LiteLLM, and any
    other server that speaks `POST {base_url}/chat/completions`. It holds no
    authority: outputs are untrusted candidates and every recommendation
    still passes ``validate_adapter_recommendation`` before use. Failures
    (network, HTTP, bad JSON) degrade to the deterministic fallback by
    returning no candidates; the reason is kept on ``last_error`` for the
    caller's telemetry. Single attempt, bounded timeout, no retries.
    """

    adapter_id = "openai_compat_adapter"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        evidence_cards: list[dict[str, Any]],
        api_key: str | None = None,
        timeout_seconds: int = _DEFAULT_LIVE_TIMEOUT_SECONDS,
        max_output_tokens: int = _MAX_LIVE_OUTPUT_TOKENS,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.evidence_cards = evidence_cards
        self.api_key = api_key
        self.timeout_seconds = max(1, min(int(timeout_seconds), _MAX_LIVE_TIMEOUT_SECONDS))
        self.max_output_tokens = max(64, min(int(max_output_tokens), _MAX_LIVE_OUTPUT_TOKENS))
        self.last_error: str | None = None

    def _request(self) -> urllib.request.Request:
        body = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": self.max_output_tokens,
            "messages": [
                {"role": "system", "content": _LIVE_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps({"evidence_cards": self.evidence_cards}, sort_keys=True),
                },
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return urllib.request.Request(  # noqa: S310 - operator-configured HTTPS/local endpoint
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )

    def _extract_content(self, response_payload: Mapping[str, Any]) -> str:
        choices = response_payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("response has no choices")
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ValueError("response has no message content")
        return content

    def recommendations(self) -> list[dict[str, Any]]:
        self.last_error = None
        if not self.evidence_cards:
            return []
        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310 - operator-configured HTTPS/local endpoint; see _request
                self._request(), timeout=self.timeout_seconds
            ) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
            content = self._extract_content(response_payload).strip()
            fenced = _JSON_FENCE.search(content)
            if fenced:
                content = fenced.group(1).strip()
            return _parse_adapter_payload(json.loads(content))
        except (
            urllib.error.URLError,
            TimeoutError,
            ValueError,
            json.JSONDecodeError,
            OSError,
        ) as exc:
            # Degrade to the deterministic fallback instead of failing the
            # graph; the schema gate reports fallback per finding.
            self.last_error = f"{type(exc).__name__}: {exc}"
            return []


def _live_adapter_from_env(
    *,
    harness_config: Mapping[str, Any],
    environ: Mapping[str, str],
    evidence_cards: list[dict[str, Any]] | None,
) -> OpenAICompatTriageAdapter | None:
    base_url = (environ.get("DEMO_OPENAI_BASE_URL") or "").strip()
    if not base_url:
        return None
    if harness_config.get("mode") != "external_llm_optional":
        # Profiles stay authoritative: a live endpoint never activates in
        # deterministic_offline mode.
        return None
    # Workload-identity-first: the key itself is never in the profile; the
    # operator names the env var that holds it (keyless is fine for local
    # Ollama / vLLM endpoints).
    key_env = environ.get("DEMO_OPENAI_API_KEY_ENV", "OPENAI_API_KEY")
    timeout_raw = (environ.get("DEMO_OPENAI_TIMEOUT_SECONDS") or "").strip()
    timeout_seconds = int(timeout_raw) if timeout_raw.isdigit() else _DEFAULT_LIVE_TIMEOUT_SECONDS
    return OpenAICompatTriageAdapter(
        base_url=base_url,
        model=str(harness_config.get("model") or "policy-bounded-triage-v1"),
        evidence_cards=list(evidence_cards or []),
        api_key=environ.get(key_env) or None,
        timeout_seconds=timeout_seconds,
    )


def select_triage_adapter(
    *,
    harness_config: Mapping[str, Any],
    environ: Mapping[str, str] = os.environ,
    evidence_cards: list[dict[str, Any]] | None = None,
) -> TriageAdapter:
    """Select the optional adapter without granting it extra authority."""
    langchain_fixture = environ.get("DEMO_LANGCHAIN_ADAPTER_FIXTURE")
    if langchain_fixture:
        return LangChainChatFixtureAdapter(Path(langchain_fixture))

    fixture_path = environ.get("DEMO_LLM_ADAPTER_FIXTURE")
    if fixture_path:
        return FixtureTriageAdapter(Path(fixture_path))

    live_adapter = _live_adapter_from_env(
        harness_config=harness_config,
        environ=environ,
        evidence_cards=evidence_cards,
    )
    if live_adapter is not None:
        return live_adapter

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
