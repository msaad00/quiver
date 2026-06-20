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
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = REPO_ROOT / "examples" / "agents"

SCRIPTS = [
    EXAMPLES / "anthropic_sdk_security_agent.py",
    EXAMPLES / "openai_sdk_security_agent.py",
    EXAMPLES / "langgraph_security_graph.py",
]


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


class TestLangGraphSocWorkflow:
    """Regression coverage for the expanded SOC workflow graph."""

    SCRIPT = EXAMPLES / "langgraph_security_graph.py"
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
        assert "call_write_tools" not in summary["harness"]["allowed_outputs"]
        assert summary["agent_recommendations"][0]["generated_by"] == "openai:gpt-4.1-mini"
        assert summary["remediation"]["status"] == "skipped"
        triage_agent = next(agent for agent in summary["agents"] if agent["agent_id"] == "triage-agent")
        assert "approval" in triage_agent["forbidden_outputs"]
        assert "write_intent" in triage_agent["forbidden_outputs"]

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

    def test_stategraph_builder_is_present_without_importing_dependency(self):
        text = self.SCRIPT.read_text(encoding="utf-8")
        assert "StateGraph(GraphState)" in text
        assert "graph.add_conditional_edges" in text
        assert "route_after_review" in text
        assert "route_after_remediation" in text
        assert 'graph.add_node("llm_triage", llm_triage_node)' in text
        assert "DEMO_LANGGRAPH_RUNTIME" in text


class TestLangGraphHarnessEvals:
    """Regression coverage for profile/triage eval tracking."""

    SCRIPT = EXAMPLES / "eval_langgraph_harness.py"
    DATASET = EXAMPLES / "evals" / "langgraph_triage_golden.json"

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
        assert report["event"] == "langgraph_agent_harness_eval"
        assert report["dataset_version"] == "langgraph-agent-harness-golden-v1"
        assert report["cases_total"] == 3
        assert report["passed"] == 3
        assert report["failed"] == 0
        assert report["pass_rate"] == 1.0
        assert {case["case_id"] for case in report["results"]} == {
            "readonly_soc_blocks_remediation",
            "analyst_triage_records_model_metadata",
            "remediation_profile_does_not_approve_itself",
        }

    def test_golden_dataset_is_valid_json(self):
        payload = json.loads(self.DATASET.read_text(encoding="utf-8"))
        assert payload["dataset_version"] == "langgraph-agent-harness-golden-v1"
        assert len(payload["cases"]) == 3
