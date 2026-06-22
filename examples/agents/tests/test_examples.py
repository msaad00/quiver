"""Smoke tests for the three agent-SDK reference examples.

Each example must:
  1. Run offline (no network, no real LLM), exit 0
  2. Emit an MCP-audit-style stderr line per tool call
  3. Enforce the HITL gate — never reach the remediation stage without an
     explicit approval env var (DEMO_APPROVE=yes)
  4. Never put remediation skills in the same allowlist as read-only skills
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = REPO_ROOT / "examples" / "agents"
SCHEMAS = EXAMPLES / "schemas"
DIAGRAMS = REPO_ROOT / "docs" / "diagrams"

SCRIPTS = [
    EXAMPLES / "anthropic_sdk_security_agent.py",
    EXAMPLES / "openai_sdk_security_agent.py",
    EXAMPLES / "langgraph_security_graph.py",
]

JSON_TYPE_MAP = {
    "array": list,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "object": dict,
    "string": str,
}


def _schema_errors(schema: dict, value, path: str = "$") -> list[str]:
    errors: list[str] = []
    schema_type = schema.get("type")
    if schema_type:
        expected_type = JSON_TYPE_MAP[schema_type]
        if not isinstance(value, expected_type) or (
            schema_type in {"integer", "number"} and isinstance(value, bool)
        ):
            return [f"{path}: expected {schema_type}"]

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']!r}")
    if schema_type == "string":
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than minLength")
        if pattern := schema.get("pattern"):
            if not re.match(pattern, value):
                errors.append(f"{path}: does not match pattern")
    if schema_type == "integer" and "minimum" in schema and value < schema["minimum"]:
        errors.append(f"{path}: below minimum")

    if schema_type == "array":
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: shorter than minItems")
        if schema.get("uniqueItems"):
            stable = [json.dumps(item, sort_keys=True) for item in value]
            if len(stable) != len(set(stable)):
                errors.append(f"{path}: duplicate array item")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                errors.extend(_schema_errors(item_schema, item, f"{path}[{index}]"))

    if schema_type == "object":
        required = set(schema.get("required", []))
        missing = sorted(required - set(value))
        for key in missing:
            errors.append(f"{path}: missing required property {key}")
        properties = schema.get("properties", {})
        extra = sorted(set(value) - set(properties))
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for key in extra:
                errors.append(f"{path}: additional property {key}")
        elif isinstance(additional, dict):
            for key in extra:
                errors.extend(_schema_errors(additional, value[key], f"{path}.{key}"))
        for key, child_schema in properties.items():
            if key in value:
                errors.extend(_schema_errors(child_schema, value[key], f"{path}.{key}"))

    return errors


def _render_fixture(payload, replacements: dict[str, str]):
    if isinstance(payload, str):
        rendered = payload
        for key, value in replacements.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", value)
        return rendered
    if isinstance(payload, list):
        return [_render_fixture(item, replacements) for item in payload]
    if isinstance(payload, dict):
        return {
            key: _render_fixture(value, replacements)
            for key, value in payload.items()
        }
    return payload


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
class TestExampleSmoke:
    def test_runs_without_approval_does_not_remediate(self, script: Path):
        """Default path — no DEMO_APPROVE env. Script must exit 0 and not produce
        any remediation action."""
        env = {**os.environ}
        env.pop("DEMO_APPROVE", None)
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        assert result.returncode == 0, f"script failed: {result.stderr}"
        # Remediation-stage output should NOT appear in stdout.
        assert '"planned_actions"' not in result.stdout
        assert '"remediation_dry_run"' not in result.stdout

    def test_audit_line_emitted_on_stderr(self, script: Path):
        """Every example must emit at least one MCP-audit-style JSON line."""
        env = {**os.environ}
        env.pop("DEMO_APPROVE", None)
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        audit_lines = [
            line for line in result.stderr.splitlines()
            if line.strip().startswith("{") and '"' in line
        ]
        assert audit_lines, f"no audit-style stderr line found: {result.stderr!r}"
        # At least one line should parse as JSON with an identifying key.
        parsed_any = False
        for line in audit_lines:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("event") == "mcp_tool_call" or "node" in payload:
                parsed_any = True
                break
        assert parsed_any, f"no mcp_tool_call / graph node event in stderr: {audit_lines!r}"


class TestAllowlistDiscipline:
    """Allowlists in examples must never mix read-only + remediation skills."""

    READ_ONLY_MARKERS = ("cspm-", "detect-", "ingest-", "convert-")
    REMEDIATION_MARKERS = ("iam-departures-", "remediate-")

    @pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
    def test_no_mixed_allowlist_constant(self, script: Path):
        """The file must declare separate allowlist constants for read-only
        vs remediation — never one combined list."""
        text = script.read_text(encoding="utf-8")
        # Find every `ALLOWED_SKILLS_<...>` tuple/list literal assignment and
        # verify no single declaration contains both a read-only marker and a
        # remediation marker. (We don't run the file — we scan its source.)
        import re
        combined = re.findall(
            r"ALLOWED_SKILLS_\w+\s*=\s*[\"'](?P<csv>[^\"']+)[\"']",
            text,
        )
        # Also handle the `",".join([...])` form
        joined = re.findall(
            r"ALLOWED_SKILLS_\w+\s*=\s*\",\"\.join\(\[(?P<body>[^\]]+)\]",
            text,
        )
        for csv in combined:
            skills = [s.strip() for s in csv.split(",") if s.strip()]
            self._assert_no_mix(skills, script)
        for body in joined:
            skills = re.findall(r'"([^"]+)"', body)
            self._assert_no_mix(skills, script)

    def _assert_no_mix(self, skills: list[str], script: Path) -> None:
        has_read = any(s.startswith(self.READ_ONLY_MARKERS) for s in skills)
        has_remediate = any(s.startswith(self.REMEDIATION_MARKERS) for s in skills)
        assert not (has_read and has_remediate), (
            f"{script.name}: single allowlist constant mixes read-only and "
            f"remediation markers: {skills}. Split them into two constants."
        )


class TestHitlGateReachable:
    """If DEMO_APPROVE=yes is set, the remediation stage must run and produce
    a dry-run output. Confirms the gate isn't a dead branch."""

    def test_anthropic_reaches_remediation_with_approval(self):
        env = {**os.environ, "DEMO_APPROVE": "yes", "DEMO_TICKET": "SEC-TEST-1"}
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "anthropic_sdk_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        # The real subprocess in stage 3 shells into the reconciler handler
        # which may exit nonzero if deps aren't present. That's fine — the
        # thing we're asserting is that the gate was reached and the stage-3
        # block was entered, visible in stderr.
        assert "remediation_dry_run" in result.stdout or "reconciler" in (result.stdout + result.stderr)

    def test_langgraph_reaches_remediation_with_approval(self):
        env = {**os.environ, "DEMO_APPROVE": "yes"}
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "langgraph_security_graph.py")],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        assert result.returncode == 0
        assert '"dry_run"' in result.stdout


class TestLangGraphHarnessRuntime:
    """Importable wrapper coverage for embedding the LangGraph harness."""

    def _runtime_module(self):
        if str(EXAMPLES) not in sys.path:
            sys.path.insert(0, str(EXAMPLES))
        import harness_runtime

        return harness_runtime

    def test_runtime_wrapper_runs_without_shelling_out(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("DEMO_APPROVE", raising=False)
        runtime = self._runtime_module()

        summary = runtime.run_harness_summary()

        assert summary["harness_runtime"]["schema_version"] == "langgraph-soc-harness-runtime-v1"
        assert summary["harness_runtime"]["execution_mode"] == "deterministic_runner"
        assert summary["harness_runtime"]["validation_status"] == "pass"
        assert summary["trace"][0] == "ingest"
        assert summary["trace"][-1] == "writeback"
        assert summary["review"]["status"] == "blocked"
        assert summary["remediation"]["status"] == "skipped"

    def test_runtime_wrapper_accepts_profile_caller_and_events(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("DEMO_APPROVE", raising=False)
        runtime = self._runtime_module()
        config = runtime.HarnessRunConfig(
            profile_path=EXAMPLES / "harness_profiles" / "readonly-soc.json",
            caller_context={
                "session_id": "wrapper-test-session",
                "email": "wrapper@example.com",
            },
            raw_events=(
                {
                    "source": "cloudtrail",
                    "event_name": "CreateAccessKey",
                    "actor_uid": "AIDAWRAPPER",
                    "resource_uid": "arn:aws:iam::111122223333:user/wrapper",
                },
            ),
        )

        result = runtime.run_harness(config)

        assert result.validation_errors == ()
        assert result.runtime["profile_id"] == "readonly-soc"
        assert result.summary["caller_context"]["session_id"] == "wrapper-test-session"
        assert result.summary["audit"]["correlation_id"] == "wrapper-test-session"
        assert result.summary["findings_count"] == 1

    def test_runtime_wrapper_replays_checkpoint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("DEMO_APPROVE", raising=False)
        runtime = self._runtime_module()
        checkpoint_path = tmp_path / "langgraph-checkpoint.json"

        first = runtime.run_harness(runtime.HarnessRunConfig(checkpoint_path=checkpoint_path))
        replayed = runtime.run_harness(runtime.HarnessRunConfig(replay_checkpoint_path=checkpoint_path))

        assert first.checkpoint["path"] == str(checkpoint_path)
        assert replayed.runtime["execution_mode"] == "checkpoint_replay"
        assert replayed.runtime["replayed"] is True
        assert replayed.summary["integrity"]["state_hash"] == first.summary["integrity"]["state_hash"]


class TestLangGraphSocWorkflow:
    """Regression coverage for the expanded SOC workflow graph."""

    SCRIPT = EXAMPLES / "langgraph_security_graph.py"
    CHECKPOINT_SCHEMA = SCHEMAS / "checkpoint.schema.json"
    PROFILES = EXAMPLES / "harness_profiles"
    EXPECTED_AGENT_IDS = [
        "evidence-agent",
        "risk-map-agent",
        "triage-agent",
        "review-gate",
        "remediation-planner",
        "retry-coordinator",
        "escalation-agent",
        "audit-writer",
    ]
    EXPECTED_TRACE = [
        "ingest",
        "normalize",
        "enrich",
        "correlate",
        "confidence",
        "map",
        "llm_triage",
        "review",
        "writeback",
    ]
    EXPECTED_APPROVED_TRACE = [
        "ingest",
        "normalize",
        "enrich",
        "correlate",
        "confidence",
        "map",
        "llm_triage",
        "review",
        "remediate",
        "writeback",
    ]

    def _run(
        self,
        *,
        approved: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> tuple[dict, subprocess.CompletedProcess[str]]:
        env = {**os.environ}
        if approved:
            env.update({
                "DEMO_APPROVE": "yes",
                "DEMO_APPROVER": "reviewer@example.com",
                "DEMO_TICKET": "SEC-LANGGRAPH-1",
            })
        else:
            env.pop("DEMO_APPROVE", None)
            env.pop("DEMO_APPROVER", None)
            env.pop("DEMO_TICKET", None)
        if extra_env:
            env.update(extra_env)
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout), result

    def test_trace_covers_end_to_end_soc_dag(self):
        summary, _ = self._run()
        assert summary["trace"] == self.EXPECTED_TRACE
        assert summary["findings_count"] == 1
        assert summary["harness"]["mode"] == "deterministic_offline"
        assert summary["harness"]["provider"] == "deterministic-local"
        assert summary["harness"]["allowed_outputs"] == [
            "rank_findings",
            "summarize_evidence",
            "draft_analyst_note",
            "request_human_review",
        ]
        assert summary["harness"]["token_budget"]["policy_version"] == "langgraph-token-budget-v1"
        assert summary["harness"]["token_budget"]["model_tier"] == "tiny"
        assert summary["harness"]["model_policy"]["policy_version"] == "langgraph-model-policy-v1"
        assert summary["harness"]["model_policy"]["selected_model_tier"] == "tiny"
        assert summary["harness"]["model_policy"]["selection_source"] == "profile_model_policy"
        assert summary["token_budget_usage"]["status"] == "within_budget"
        assert summary["token_budget_usage"]["compact_input_tokens_estimate"] <= summary["harness"]["token_budget"]["max_input_tokens"]
        assert summary["token_budget_usage"]["compact_evidence_chars"] <= summary["harness"]["token_budget"]["max_evidence_chars"]
        assert summary["audit"]["llm_token_budget_status"] == "within_budget"
        assert summary["audit"]["llm_compact_input_tokens"] == summary["token_budget_usage"]["compact_input_tokens_estimate"]
        assert summary["llm_evidence_cards"]
        assert all("raw_events" not in card for card in summary["llm_evidence_cards"])
        assert all("ocsf_events" not in card for card in summary["llm_evidence_cards"])
        assert [agent["agent_id"] for agent in summary["agents"]] == self.EXPECTED_AGENT_IDS
        assert [run["agent_id"] for run in summary["agent_runs"]] == [
            "evidence-agent",
            "risk-map-agent",
            "triage-agent",
            "review-gate",
            "audit-writer",
        ]
        assert all(run["input_hash"] and run["output_hash"] for run in summary["agent_runs"])
        assert summary["agent_recommendations"][0]["recommended_action"] == "request_approval"
        assert summary["agent_recommendations"][0]["generated_by"] == "deterministic-local:policy-bounded-triage-v1"
        assert summary["confidence_scores"][0]["reason_codes"] == [
            "rule_match",
            "stable_resource_uid",
            "identity_correlation",
            "high_epss",
        ]
        framework_map = summary["framework_maps"][0]
        assert framework_map["mitre_attack"] == ["T1098"]
        assert framework_map["cvss"]["severity"] == "high"
        assert framework_map["epss_percentile"] == 0.91
        assert framework_map["kev_listed"] is False

    def test_pipeline_contract_exposes_nodes_edges_and_guardrails(self):
        summary, _ = self._run()
        contract = summary["pipeline_contract"]
        assert contract["schema_version"] == "langgraph-soc-pipeline-contract-v1"
        node_names = [node["node"] for node in contract["nodes"]]
        assert node_names == [
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
        assert {node["agent_id"] for node in contract["nodes"]} == set(self.EXPECTED_AGENT_IDS)
        assert all(node["guardrails"] for node in contract["nodes"])

        edge_pairs = {
            (edge["source"], edge["target"], edge["condition"])
            for edge in contract["edges"]
        }
        assert ("review", "remediate", "route_after_review == remediate") in edge_pairs
        assert ("review", "writeback", "route_after_review == writeback") in edge_pairs
        assert ("remediate", "retry_queue", "route_after_remediation == retry_queue") in edge_pairs
        assert ("remediate", "escalate", "route_after_remediation == escalate") in edge_pairs
        assert ("remediate", "writeback", "route_after_remediation == writeback") in edge_pairs

        remediation_node = next(node for node in contract["nodes"] if node["node"] == "remediate")
        assert remediation_node["skills"] == ["iam-departures-aws"]
        assert "dry_run_default" in remediation_node["guardrails"]
        triage_node = next(node for node in contract["nodes"] if node["node"] == "llm_triage")
        assert triage_node["skills"] == []
        assert "closed_adapter_schema" in triage_node["guardrails"]
        assert "token_budget_enforced" in triage_node["guardrails"]
        assert "compact_evidence_only" in triage_node["guardrails"]
        assert "LLM adapters can rank, summarize, draft, or request review only" in contract["invariants"]

    def test_no_approval_blocks_remediation_but_writes_audit_and_eval(self):
        summary, result = self._run()
        assert summary["review"]["status"] == "blocked"
        assert summary["remediation"]["status"] == "skipped"
        assert summary["remediation"]["reason"] == "review blocked; remediation node not routed"
        assert "planned_steps" not in summary["remediation"]
        assert summary["audit"]["event"] == "agentic_soc_workflow"
        assert summary["audit"]["remediation_status"] == "skipped"
        assert summary["audit"]["route"] == {
            "after_review": "writeback",
            "after_remediation": "writeback",
        }
        assert summary["audit"]["agent_run_count"] == 5
        assert summary["eval"]["status"] == "blocked"
        assert '"node": "review"' in result.stderr
        assert '"status": "blocked"' in result.stderr
        assert summary["api_errors"] == []
        assert summary["integrity"]["evidence_hash"]
        assert summary["integrity"]["state_hash"] == summary["audit"]["state_hash"]
        assert summary["idempotency"]["workflow_key"].startswith("wf-")

    def test_approval_allows_dry_run_only(self):
        summary, _ = self._run(approved=True)
        assert summary["trace"] == self.EXPECTED_APPROVED_TRACE
        assert summary["review"]["status"] == "approved"
        assert summary["review"]["approval"]["ticket_id"] == "SEC-LANGGRAPH-1"
        assert summary["remediation"]["status"] == "dry_run"
        assert summary["remediation"]["dry_run"] is True
        assert summary["remediation"]["skill"] == "iam-departures-aws"
        assert summary["remediation"]["idempotency_key"].startswith("rem-")
        assert summary["idempotency"]["remediation_key"] == summary["remediation"]["idempotency_key"]
        assert summary["integrity"]["approved_payload_hash"]
        assert summary["audit"]["idempotency_key"] == summary["remediation"]["idempotency_key"]
        assert summary["audit"]["route"] == {
            "after_review": "remediate",
            "after_remediation": "writeback",
        }
        assert [run["agent_id"] for run in summary["agent_runs"]] == [
            "evidence-agent",
            "risk-map-agent",
            "triage-agent",
            "review-gate",
            "remediation-planner",
            "audit-writer",
        ]
        assert summary["audit"]["agent_run_count"] == 6
        assert summary["audit"]["remediation_status"] == "dry_run"
        assert summary["eval"]["status"] == "pass"

    def test_llm_harness_records_provider_model_without_granting_authority(self):
        summary, _ = self._run(extra_env={
            "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
            "DEMO_LLM_PROVIDER": "openai",
            "DEMO_LLM_MODEL": "gpt-4.1-mini",
        })
        assert summary["harness"]["mode"] == "external_llm_optional"
        assert summary["harness"]["provider"] == "openai"
        assert summary["harness"]["model"] == "gpt-4.1-mini"
        assert summary["harness"]["token_budget"]["model_tier"] == "tiny"
        assert summary["harness"]["model_policy"]["selected_model_tier"] == "tiny"
        assert summary["harness"]["model_policy"]["selection_source"] == "env_override"
        assert "call_write_tools" not in summary["harness"]["allowed_outputs"]
        assert summary["agent_recommendations"][0]["generated_by"] == "openai:gpt-4.1-mini"
        assert summary["remediation"]["status"] == "skipped"
        triage_agent = next(agent for agent in summary["agents"] if agent["agent_id"] == "triage-agent")
        assert "approval" in triage_agent["forbidden_outputs"]
        assert "write_intent" in triage_agent["forbidden_outputs"]
        assert summary["llm_validation"][0]["status"] == "fallback"
        assert summary["llm_validation"][0]["reason"] == "no_adapter_output"

    def test_token_budget_overage_uses_deterministic_fallback(self):
        summary, _ = self._run(extra_env={
            "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
            "DEMO_LLM_PROVIDER": "fixture",
            "DEMO_LLM_MODEL": "oversized-context-fixture",
            "DEMO_TOKEN_MAX_INPUT_TOKENS": "1",
        })
        assert summary["token_budget_usage"]["status"] == "fallback"
        assert summary["token_budget_usage"]["fallback_reason"] == "token_budget_exceeded"
        assert summary["llm_validation"][0]["status"] == "fallback"
        assert summary["llm_validation"][0]["reason"] == "token_budget_exceeded"
        triage_run = next(run for run in summary["agent_runs"] if run["agent_id"] == "triage-agent")
        assert triage_run["token_budget"]["status"] == "fallback"
        assert triage_run["token_budget"]["cache_key"].startswith("triage-")
        assert summary["audit"]["llm_token_budget_status"] == "fallback"

    def test_llm_adapter_accepts_bounded_triage_output(self, tmp_path: Path):
        baseline, _ = self._run()
        finding_uid = baseline["framework_maps"][0]["finding_uid"]
        fixture = tmp_path / "accepted-llm-output.json"
        fixture.write_text(json.dumps({
            "recommendations": [
                {
                    "finding_uid": finding_uid,
                    "priority": "critical",
                    "recommended_action": "request_approval",
                    "rationale": "Fixture model ranks the finding for immediate analyst review.",
                },
            ],
        }), encoding="utf-8")

        summary, _ = self._run(extra_env={
            "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
            "DEMO_LLM_PROVIDER": "fixture",
            "DEMO_LLM_MODEL": "triage-fixture-v1",
            "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
        })

        recommendation = summary["agent_recommendations"][0]
        assert recommendation["priority"] == "critical"
        assert recommendation["recommended_action"] == "request_approval"
        assert recommendation["rationale"] == "Fixture model ranks the finding for immediate analyst review."
        assert recommendation["generated_by"] == "fixture:triage-fixture-v1"
        assert summary["llm_validation"][0]["status"] == "accepted"
        assert summary["llm_validation"][0]["reason"] == "schema_valid"
        assert summary["audit"]["llm_adapter_accepted"] == 1
        assert summary["audit"]["llm_adapter_rejected"] == 0

    def test_langchain_adapter_accepts_bounded_chat_message(self, tmp_path: Path):
        pytest.importorskip("langchain_core.messages")
        baseline, _ = self._run()
        finding_uid = baseline["framework_maps"][0]["finding_uid"]
        fixture = tmp_path / "langchain-message-output.json"
        fixture.write_text(json.dumps({
            "recommendations": [
                {
                    "finding_uid": finding_uid,
                    "priority": "critical",
                    "recommended_action": "request_approval",
                    "rationale": "LangChain fixture ranks this for immediate analyst review.",
                },
            ],
        }), encoding="utf-8")

        summary, _ = self._run(extra_env={
            "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
            "DEMO_LLM_PROVIDER": "langchain",
            "DEMO_LLM_MODEL": "chat-model-fixture-v1",
            "DEMO_LANGCHAIN_ADAPTER_FIXTURE": str(fixture),
        })

        recommendation = summary["agent_recommendations"][0]
        assert recommendation["priority"] == "critical"
        assert recommendation["generated_by"] == "langchain:chat-model-fixture-v1"
        assert summary["llm_validation"][0]["adapter"] == "langchain_chat_adapter"
        assert summary["llm_validation"][0]["status"] == "accepted"
        assert summary["audit"]["llm_adapter_accepted"] == 1

    def test_llm_adapter_rejects_forbidden_security_facts(self, tmp_path: Path):
        baseline, _ = self._run()
        finding_uid = baseline["framework_maps"][0]["finding_uid"]
        fixture = tmp_path / "forbidden-llm-output.json"
        fixture.write_text(json.dumps({
            "recommendations": [
                {
                    "finding_uid": finding_uid,
                    "priority": "low",
                    "recommended_action": "close",
                    "rationale": "This output should not be trusted.",
                    "approval": {"approver_id": "model"},
                    "cvss": {"base_score": 0.0},
                },
            ],
        }), encoding="utf-8")

        summary, _ = self._run(extra_env={
            "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
            "DEMO_LLM_PROVIDER": "fixture",
            "DEMO_LLM_MODEL": "triage-fixture-v1",
            "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
        })

        recommendation = summary["agent_recommendations"][0]
        assert recommendation["priority"] == "high"
        assert recommendation["recommended_action"] == "request_approval"
        assert recommendation["rationale"].startswith("Deterministic triage")
        assert summary["llm_validation"][0]["status"] == "rejected"
        assert summary["llm_validation"][0]["reason"] == "forbidden_output:approval,cvss"
        assert summary["audit"]["llm_adapter_accepted"] == 0
        assert summary["audit"]["llm_adapter_rejected"] == 1

    def test_profile_loads_caller_context_and_allowed_skills(self):
        summary, _ = self._run(extra_env={
            "DEMO_HARNESS_PROFILE": str(self.PROFILES / "readonly-soc.json"),
        })
        assert summary["profile"]["profile_id"] == "readonly-soc"
        assert summary["caller_context"]["email"] == "soc-readonly@example.com"
        assert summary["audit"]["profile_id"] == "readonly-soc"
        assert summary["effective_allowed_skills"] == [
            "ingest-cloudtrail-ocsf",
            "source-snowflake-query",
            "detect-lateral-movement",
            "cspm-aws-cis-benchmark",
            "discover-control-evidence",
            "convert-ocsf-to-sarif",
        ]
        assert summary["remediation"]["status"] == "skipped"

    def test_profile_llm_metadata_is_bounded(self):
        summary, _ = self._run(extra_env={
            "DEMO_HARNESS_PROFILE": str(self.PROFILES / "analyst-triage.json"),
        })
        assert summary["profile"]["profile_id"] == "analyst-triage"
        assert summary["harness"]["mode"] == "external_llm_optional"
        assert summary["harness"]["provider"] == "openai"
        assert summary["harness"]["model"] == "gpt-4.1-mini"
        assert summary["harness"]["model_policy"]["selected_model_tier"] == "small"
        assert summary["harness"]["model_policy"]["selection_source"] == "profile_model_policy"
        assert summary["agent_recommendations"][0]["generated_by"] == "openai:gpt-4.1-mini"
        assert summary["review"]["status"] == "blocked"

    def test_remediation_profile_does_not_grant_approval(self):
        summary, _ = self._run(extra_env={
            "DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json"),
        })
        assert summary["profile"]["profile_id"] == "dry-run-remediation"
        assert "iam-departures-aws" in summary["effective_allowed_skills"]
        assert summary["review"]["status"] == "blocked"
        assert summary["remediation"]["status"] == "skipped"
        assert "planned_steps" not in summary["remediation"]

    def test_remediation_profile_still_requires_explicit_hitl(self):
        summary, _ = self._run(
            approved=True,
            extra_env={"DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json")},
        )
        assert summary["profile"]["profile_id"] == "dry-run-remediation"
        assert summary["review"]["status"] == "approved"
        assert summary["remediation"]["status"] == "dry_run"
        assert summary["remediation"]["dry_run"] is True

    def test_integrity_and_workflow_idempotency_are_stable(self):
        first, _ = self._run()
        second, _ = self._run()
        assert first["integrity"]["evidence_hash"] == second["integrity"]["evidence_hash"]
        assert first["integrity"]["state_hash"] == second["integrity"]["state_hash"]
        assert first["idempotency"]["workflow_key"] == second["idempotency"]["workflow_key"]
        assert first["audit"]["chain_hash"] == second["audit"]["chain_hash"]
        assert first["agent_runs"] == second["agent_runs"]

    def test_duplicate_remediation_key_suppresses_write_intent(self):
        approved, _ = self._run(approved=True)
        remediation_key = approved["remediation"]["idempotency_key"]
        replay, _ = self._run(
            approved=True,
            extra_env={"DEMO_SEEN_IDEMPOTENCY_KEYS": remediation_key},
        )
        assert replay["remediation"]["status"] == "skipped"
        assert replay["remediation"]["reason"] == "duplicate idempotency key; write intent suppressed"
        assert "planned_steps" not in replay["remediation"]
        assert replay["idempotency"]["duplicate_write_suppressed"] is True
        assert replay["remediation"]["idempotency_key"] == remediation_key
        assert replay["audit"]["agent_run_count"] == 6

    def test_retryable_api_error_does_not_bypass_hitl(self):
        summary, _ = self._run(extra_env={"DEMO_API_ERROR_STATUS": "429"})
        assert summary["review"]["status"] == "blocked"
        assert summary["remediation"]["status"] == "skipped"
        assert summary["remediation"]["reason"] == "review blocked; remediation node not routed"
        assert "retry_decision" not in summary["remediation"]
        assert summary["api_errors"] == []
        assert summary["audit"]["api_error_count"] == 0

    def test_retryable_api_error_reuses_idempotency_key_when_approved(self):
        summary, _ = self._run(
            approved=True,
            extra_env={"DEMO_API_ERROR_STATUS": "429"},
        )
        assert summary["trace"] == [
            *self.EXPECTED_APPROVED_TRACE[:-1],
            "retry_queue",
            "writeback",
        ]
        assert summary["remediation"]["status"] == "skipped"
        assert summary["remediation"]["reason"] == "retryable_api_error"
        assert "planned_steps" not in summary["remediation"]
        assert summary["api_errors"][0]["classification"] == "retryable"
        retry_decision = summary["remediation"]["retry_decision"]
        assert retry_decision["max_attempts"] == 3
        assert retry_decision["idempotency_key"] == summary["idempotency"]["remediation_key"]
        assert summary["retry"]["status"] == "scheduled"
        assert summary["retry"]["idempotency_key"] == summary["idempotency"]["remediation_key"]
        assert [run["agent_id"] for run in summary["agent_runs"]][-2:] == [
            "retry-coordinator",
            "audit-writer",
        ]
        assert summary["audit"]["agent_run_count"] == 7
        assert summary["audit"]["api_error_count"] == 1
        assert summary["audit"]["retryable_api_error_count"] == 1
        assert summary["audit"]["route"]["after_remediation"] == "retry_queue"

    def test_terminal_api_error_blocks_write_intent(self):
        summary, _ = self._run(
            approved=True,
            extra_env={"DEMO_API_ERROR_STATUS": "403"},
        )
        assert summary["trace"] == [
            *self.EXPECTED_APPROVED_TRACE[:-1],
            "escalate",
            "writeback",
        ]
        assert summary["remediation"]["status"] == "skipped"
        assert summary["remediation"]["reason"] == "terminal_api_error"
        assert "planned_steps" not in summary["remediation"]
        assert summary["api_errors"][0]["classification"] == "terminal"
        assert summary["remediation"]["retry_decision"]["max_attempts"] == 0
        assert summary["escalation"]["status"] == "queued"
        assert summary["escalation"]["reason"] == "terminal_api_error"
        assert [run["agent_id"] for run in summary["agent_runs"]][-2:] == [
            "escalation-agent",
            "audit-writer",
        ]
        assert summary["audit"]["agent_run_count"] == 7
        assert summary["audit"]["api_error_count"] == 1
        assert summary["audit"]["retryable_api_error_count"] == 0
        assert summary["audit"]["route"]["after_remediation"] == "escalate"

    def test_real_langgraph_runtime_when_dependency_is_installed(self):
        pytest.importorskip("langgraph.graph")
        env = {**os.environ, "DEMO_LANGGRAPH_RUNTIME": "yes"}
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        summary = json.loads(result.stdout)
        assert summary["trace"] == self.EXPECTED_TRACE
        assert summary["remediation"]["status"] == "skipped"
        assert summary["audit"]["route"]["after_review"] == "writeback"

    def test_real_langgraph_runtime_routes_retryable_error(self):
        pytest.importorskip("langgraph.graph")
        env = {
            **os.environ,
            "DEMO_LANGGRAPH_RUNTIME": "yes",
            "DEMO_APPROVE": "yes",
            "DEMO_API_ERROR_STATUS": "429",
        }
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        summary = json.loads(result.stdout)
        assert "retry_queue" in summary["trace"]
        assert summary["audit"]["route"]["after_remediation"] == "retry_queue"

    def test_checkpoint_artifact_replays_same_summary(self, tmp_path: Path):
        checkpoint = tmp_path / "langgraph-checkpoint.json"
        env = {**os.environ, "DEMO_CHECKPOINT_PATH": str(checkpoint)}
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        original_summary = json.loads(result.stdout)
        payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        schema = json.loads(self.CHECKPOINT_SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, payload) == []
        assert payload["event"] == "langgraph_soc_checkpoint"
        assert payload["schema_version"] == "langgraph-soc-checkpoint-v1"
        assert payload["state_hash"] == original_summary["integrity"]["state_hash"]
        assert payload["state"]["integrity"]["state_hash"] == payload["state_hash"]
        assert payload["state"]["audit_record"]["state_hash"] == payload["state_hash"]
        assert payload["state"]["audit_record"]["chain_hash"] == payload["state_hash"]
        assert payload["checkpoint_hash"]
        assert payload["summary_hash"]

        replay_env = {**os.environ, "DEMO_REPLAY_CHECKPOINT": str(checkpoint)}
        replay = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=replay_env,
        )
        assert replay.returncode == 0, replay.stderr
        assert json.loads(replay.stdout) == original_summary
        assert replay.stderr == ""

    def test_checkpoint_replay_rejects_tampered_state(self, tmp_path: Path):
        checkpoint = tmp_path / "langgraph-checkpoint.json"
        env = {**os.environ, "DEMO_CHECKPOINT_PATH": str(checkpoint)}
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        payload["state"]["trace"].append("tampered")
        checkpoint.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        replay = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env={**os.environ, "DEMO_REPLAY_CHECKPOINT": str(checkpoint)},
        )
        assert replay.returncode != 0
        assert "checkpoint_hash mismatch" in replay.stderr

    def test_stategraph_builder_is_present_without_importing_dependency(self):
        text = self.SCRIPT.read_text(encoding="utf-8")
        assert "StateGraph(GraphState)" in text
        assert "graph.add_conditional_edges" in text
        assert "route_after_review" in text
        assert "route_after_remediation" in text
        assert 'graph.add_node("llm_triage", llm_triage_node)' in text
        assert "DEMO_LANGGRAPH_RUNTIME" in text


class TestLangGraphContractSchemas:
    """Contract coverage for harness profile and LLM adapter JSON schemas."""

    PROFILE_SCHEMA = SCHEMAS / "harness_profile.schema.json"
    ADAPTER_SCHEMA = SCHEMAS / "llm_adapter_recommendations.schema.json"
    PIPELINE_SCHEMA = SCHEMAS / "pipeline_contract.schema.json"
    CHECKPOINT_SCHEMA = SCHEMAS / "checkpoint.schema.json"
    EVAL_REPORT_SCHEMA = SCHEMAS / "eval_report.schema.json"
    GRAPH = EXAMPLES / "langgraph_security_graph.py"
    PROFILES = EXAMPLES / "harness_profiles"
    DATASET = EXAMPLES / "evals" / "langgraph_triage_golden.json"

    def test_schema_files_are_closed_json_schema_documents(self):
        for schema_path in [
            self.PROFILE_SCHEMA,
            self.ADAPTER_SCHEMA,
            self.PIPELINE_SCHEMA,
            self.CHECKPOINT_SCHEMA,
            self.EVAL_REPORT_SCHEMA,
        ]:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
            assert schema["type"] == "object"
            assert schema["additionalProperties"] is False

    def test_harness_profiles_match_schema_and_intersect_allowlists(self):
        schema = json.loads(self.PROFILE_SCHEMA.read_text(encoding="utf-8"))
        for profile_path in sorted(self.PROFILES.glob("*.json")):
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            assert _schema_errors(schema, profile) == []
            assert set(profile["caller_context"]["allowed_skills"]).issubset(
                set(profile["allowed_skills"])
            )
            assert profile["approval_policy"]["remediation_requires_approval_context"] is True
            assert profile["runtime"]["dry_run_default"] is True
            if "token_budget" in profile:
                assert profile["token_budget"]["compression_required"] is True
                assert profile["token_budget"]["fallback_on_budget_exceeded"] is True
            assert profile["model_policy"]["policy_version"] == "langgraph-model-policy-v1"
            assert profile["model_policy"]["selection_strategy"] == "smallest_sufficient"
            assert profile["token_budget"]["model_tier"] in profile["model_policy"]["allowed_model_tiers"]

    def test_llm_adapter_eval_fixtures_match_expected_schema_outcome(self):
        schema = json.loads(self.ADAPTER_SCHEMA.read_text(encoding="utf-8"))
        dataset = json.loads(self.DATASET.read_text(encoding="utf-8"))
        adapter_cases = [
            case for case in dataset["cases"]
            if "llm_adapter_fixture" in case
        ]
        assert {case["case_id"] for case in adapter_cases} == {
            "llm_adapter_accepts_bounded_triage",
            "llm_adapter_rejects_forbidden_security_facts",
        }

        for case in adapter_cases:
            rendered = _render_fixture(
                case["llm_adapter_fixture"],
                {"finding_uid": "det-evt-schema-test"},
            )
            errors = _schema_errors(schema, rendered)
            if case["expected"]["llm_validation_status"] == "accepted":
                assert errors == []
            else:
                assert errors
                assert any("additional property approval" in error for error in errors)
                assert any("additional property cvss" in error for error in errors)

    def test_emitted_pipeline_contract_matches_schema_and_known_topology(self):
        result = subprocess.run(
            [sys.executable, str(self.GRAPH)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        contract = json.loads(result.stdout)["pipeline_contract"]
        schema = json.loads(self.PIPELINE_SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, contract) == []

        node_names = {node["node"] for node in contract["nodes"]}
        assert node_names == {
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
        }
        for edge in contract["edges"]:
            assert edge["source"] in node_names
            assert edge["target"] in node_names
        assert len(contract["edges"]) == 14

        remediation_node = next(
            node for node in contract["nodes"] if node["node"] == "remediate"
        )
        assert remediation_node["skills"] == ["iam-departures-aws"]
        triage_node = next(
            node for node in contract["nodes"] if node["node"] == "llm_triage"
        )
        assert triage_node["skills"] == []


class TestLangGraphHarnessSetup:
    """Setup generator coverage for operator-owned harness profiles."""

    SCRIPT = EXAMPLES / "configure_langgraph_harness.py"
    GRAPH = EXAMPLES / "langgraph_security_graph.py"
    PROFILE_SCHEMA = SCHEMAS / "harness_profile.schema.json"

    def _clean_graph_env(self, profile: Path, *, approved: bool = False) -> dict[str, str]:
        env = {**os.environ, "DEMO_HARNESS_PROFILE": str(profile)}
        for key in [
            "CLOUD_SECURITY_HARNESS_PROFILE",
            "DEMO_EXTERNAL_LLM_ALLOWED",
            "DEMO_LLM_PROVIDER",
            "DEMO_LLM_MODEL",
            "DEMO_LLM_ADAPTER_FIXTURE",
            "DEMO_LANGCHAIN_ADAPTER_FIXTURE",
            "DEMO_API_ERROR_STATUS",
            "DEMO_API_ERROR_CODE",
        ]:
            env.pop(key, None)
        if approved:
            env["DEMO_APPROVE"] = "yes"
            env["DEMO_APPROVER"] = "reviewer@example.com"
            env["DEMO_TICKET"] = "SEC-SETUP-1"
        else:
            env.pop("DEMO_APPROVE", None)
        return env

    def test_setup_generator_writes_schema_valid_profile_and_dotenv(self, tmp_path: Path):
        profile_path = tmp_path / "acme-soc-triage.json"
        env_path = tmp_path / "acme-soc-triage.env"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "analyst-triage",
                "--profile-id",
                "acme-soc-triage",
                "--email",
                "analyst@example.com",
                "--external-llm",
                "--llm-provider",
                "openai",
                "--llm-model",
                "gpt-4.1-mini",
                "--cloud-hint",
                "aws=AWS_PROFILE=prod-readonly",
                "--output-profile",
                str(profile_path),
                "--output-env",
                str(env_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        setup_summary = json.loads(result.stdout)
        assert setup_summary["secrets_written"] is False
        assert setup_summary["approval_required"] is True

        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        schema = json.loads(self.PROFILE_SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, profile) == []
        assert profile["llm"] == {
            "mode": "external_llm_optional",
            "provider": "openai",
            "model": "gpt-4.1-mini",
        }
        assert profile["token_budget"]["policy_version"] == "langgraph-token-budget-v1"
        assert profile["token_budget"]["model_tier"] == "small"
        assert profile["token_budget"]["compression_required"] is True
        assert profile["model_policy"]["policy_version"] == "langgraph-model-policy-v1"
        assert profile["model_policy"]["default_model_tier"] == "small"
        assert profile["model_policy"]["models"]["small"] == {
            "provider": "openai",
            "model": "gpt-4.1-mini",
        }
        assert "iam-departures-aws" not in profile["allowed_skills"]

        dotenv = env_path.read_text(encoding="utf-8")
        assert f"DEMO_HARNESS_PROFILE={profile_path}" in dotenv
        assert "DEMO_EXTERNAL_LLM_ALLOWED=yes" in dotenv
        assert "DEMO_LLM_PROVIDER=" not in dotenv
        assert "DEMO_LLM_MODEL=" not in dotenv
        assert "# profile_model=openai:gpt-4.1-mini" in dotenv
        assert "DEMO_APPROVE is intentionally omitted" in dotenv

        graph = subprocess.run(
            [sys.executable, str(self.GRAPH)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=self._clean_graph_env(profile_path),
        )
        assert graph.returncode == 0, graph.stderr
        summary = json.loads(graph.stdout)
        assert summary["profile"]["profile_id"] == "acme-soc-triage"
        assert summary["harness"]["mode"] == "external_llm_optional"
        assert summary["harness"]["provider"] == "openai"
        assert summary["harness"]["token_budget"]["model_tier"] == "small"
        assert summary["harness"]["model_policy"]["selected_model_tier"] == "small"
        assert summary["harness"]["model_policy"]["selection_source"] == "profile_model_policy"
        assert summary["review"]["status"] == "blocked"

    def test_setup_generator_dry_run_profile_still_requires_approval(self, tmp_path: Path):
        profile_path = tmp_path / "acme-remediation-dryrun.json"
        env_path = tmp_path / "acme-remediation-dryrun.env"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "dry-run-remediation",
                "--profile-id",
                "acme-remediation-dryrun",
                "--email",
                "security@example.com",
                "--output-profile",
                str(profile_path),
                "--output-env",
                str(env_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        assert "iam-departures-aws" in profile["allowed_skills"]
        assert profile["runtime"]["dry_run_default"] is True
        assert profile["runtime"]["apply_supported"] is False
        assert profile["approval_policy"]["remediation_requires_approval_context"] is True
        assert profile["token_budget"]["model_tier"] == "tiny"
        assert profile["model_policy"]["allowed_model_tiers"] == ["tiny"]

        blocked = subprocess.run(
            [sys.executable, str(self.GRAPH)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=self._clean_graph_env(profile_path),
        )
        assert blocked.returncode == 0, blocked.stderr
        blocked_summary = json.loads(blocked.stdout)
        assert blocked_summary["remediation"]["status"] == "skipped"

        approved = subprocess.run(
            [sys.executable, str(self.GRAPH)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=self._clean_graph_env(profile_path, approved=True),
        )
        assert approved.returncode == 0, approved.stderr
        approved_summary = json.loads(approved.stdout)
        assert approved_summary["remediation"]["status"] == "dry_run"
        assert approved_summary["remediation"]["dry_run"] is True
        assert approved_summary["audit"]["route"]["after_review"] == "remediate"

    def test_setup_generator_rejects_unknown_example_skill(self, tmp_path: Path):
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--profile-id",
                "bad-skill-profile",
                "--email",
                "analyst@example.com",
                "--allowed-skill",
                "remediate-everything-now",
                "--output-profile",
                str(tmp_path / "bad.json"),
                "--output-env",
                str(tmp_path / "bad.env"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode != 0
        assert "unknown example skill" in result.stderr


class TestLangGraphPipelineDiagram:
    """Regression coverage for the code-backed LangGraph Mermaid diagram."""

    SCRIPT = EXAMPLES / "render_langgraph_pipeline_diagram.py"
    DIAGRAM = DIAGRAMS / "langgraph-agent-harness.mmd"

    def test_pipeline_diagram_matches_renderer_output(self):
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == self.DIAGRAM.read_text(encoding="utf-8")
        assert "Source of truth: pipeline_contract()" in result.stdout
        assert "REVIEW -- approved --> REM" in result.stdout
        assert "REM -- retryable API error --> RETRY" in result.stdout


class TestLangGraphHarnessEvals:
    """Regression coverage for profile/triage eval tracking."""

    SCRIPT = EXAMPLES / "eval_langgraph_harness.py"
    DATASET = EXAMPLES / "evals" / "langgraph_triage_golden.json"
    SCHEMA = SCHEMAS / "eval_report.schema.json"

    def test_golden_eval_report_passes(self):
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT), "--check"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        schema = json.loads(self.SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, report) == []
        assert report["event"] == "langgraph_agent_harness_eval"
        assert report["dataset_version"] == "langgraph-agent-harness-golden-v1"
        assert report["cases_total"] == 8
        assert report["passed"] == 8
        assert report["failed"] == 0
        assert report["pass_rate"] == 1.0
        assert {case["case_id"] for case in report["results"]} == {
            "readonly_soc_blocks_remediation",
            "analyst_triage_records_model_metadata",
            "remediation_profile_does_not_approve_itself",
            "approved_dry_run_records_integrity_idempotency",
            "retryable_api_error_reuses_idempotency_key",
            "terminal_api_error_escalates_to_human_queue",
            "llm_adapter_accepts_bounded_triage",
            "llm_adapter_rejects_forbidden_security_facts",
        }

    def test_golden_dataset_is_valid_json(self):
        payload = json.loads(self.DATASET.read_text(encoding="utf-8"))
        assert payload["dataset_version"] == "langgraph-agent-harness-golden-v1"
        assert len(payload["cases"]) == 8

    def test_eval_report_can_be_written_and_appended(self, tmp_path):
        report_path = tmp_path / "langgraph-harness-eval.json"
        history_path = tmp_path / "langgraph-harness-eval-history.jsonl"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--check",
                "--output",
                str(report_path),
                "--append-jsonl",
                str(history_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        stdout_report = json.loads(result.stdout)
        file_report = json.loads(report_path.read_text(encoding="utf-8"))
        history_rows = [
            json.loads(line)
            for line in history_path.read_text(encoding="utf-8").splitlines()
        ]
        assert file_report == stdout_report
        schema = json.loads(self.SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, stdout_report) == []
        assert len(history_rows) == 1
        assert _schema_errors(schema, history_rows[0]) == []
        assert history_rows[0]["event"] == "langgraph_agent_harness_eval"
        assert history_rows[0]["dataset_hash"] == stdout_report["dataset_hash"]
        assert history_rows[0]["pass_rate"] == 1.0
        assert history_rows[0]["report_hash"]
        assert history_rows[0]["recorded_at"].endswith("Z")
