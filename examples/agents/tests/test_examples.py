"""Smoke tests for the agent MCP and LangGraph reference examples.

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
    EXAMPLES / "langchain_mcp_security_agent.py",
    EXAMPLES / "cursor_mcp_security_agent.py",
    EXAMPLES / "windsurf_mcp_security_agent.py",
    EXAMPLES / "cortex_mcp_security_agent.py",
    EXAMPLES / "codex_mcp_security_agent.py",
    EXAMPLES / "zed_mcp_security_agent.py",
    EXAMPLES / "langgraph_security_graph.py",
    EXAMPLES / "run_langgraph_harness.py",
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
        return {key: _render_fixture(value, replacements) for key, value in payload.items()}
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
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
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
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env=env,
        )
        audit_lines = [
            line
            for line in result.stderr.splitlines()
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
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env=env,
        )
        # The real subprocess in stage 3 shells into the reconciler handler
        # which may exit nonzero if deps aren't present. That's fine — the
        # thing we're asserting is that the gate was reached and the stage-3
        # block was entered, visible in stderr.
        assert "remediation_dry_run" in result.stdout or "reconciler" in (
            result.stdout + result.stderr
        )

    def test_openai_reaches_remediation_with_approval(self):
        env = {
            **os.environ,
            "DEMO_APPROVE": "yes",
            "DEMO_TICKET": "SEC-TEST-2",
        }
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "openai_sdk_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env=env,
        )
        assert "remediation_dry_run" in result.stdout or "reconciler" in (
            result.stdout + result.stderr
        )

    def test_langchain_mcp_binding_documents_stdio_transport(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "langchain_mcp_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["langchain_binding"]
        assert binding["integration"] == "mcp_stdio_jsonrpc"
        assert binding["anti_pattern"] == "do_not_wrap_skill_clis_as_langchain_tools"
        assert "cloud-ai-security-skills" in binding["mcp_servers"]
        assert payload["mcp_tools_discovered"]

    def test_cursor_mcp_binding_documents_project_config(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "cursor_mcp_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["cursor_binding"]
        assert binding["integration"] == "cursor_mcp_json"
        assert binding["config_path"] == ".cursor/mcp.json"
        assert "cloud-ai-security-skills" in binding["mcp_config"]["mcpServers"]
        assert payload["mcp_tools_discovered"]

    def test_windsurf_mcp_binding_documents_absolute_path_config(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "windsurf_mcp_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["windsurf_binding"]
        assert binding["integration"] == "windsurf_mcp_config_json"
        assert binding["config_path"] == "~/.codeium/windsurf/mcp_config.json"
        assert "cloud-ai-security-skills" in binding["mcp_config"]["mcpServers"]
        assert binding["mcp_config"]["mcpServers"]["cloud-ai-security-skills"]["args"][0].endswith(
            "mcp-server/src/server.py"
        )
        assert payload["mcp_tools_discovered"]

    def test_cortex_mcp_binding_documents_project_config(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "cortex_mcp_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["cortex_binding"]
        assert binding["integration"] == "cortex_mcp_json"
        assert binding["config_path"] == ".cortex/mcp.json"
        assert (
            "${workspaceFolder}"
            in binding["mcp_config"]["mcpServers"]["cloud-ai-security-skills"]["args"][0]
        )
        assert payload["mcp_tools_discovered"]

    def test_codex_mcp_binding_documents_toml_config(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "codex_mcp_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["codex_binding"]
        assert binding["integration"] == "codex_config_toml"
        assert binding["config_path"] == "~/.codex/config.toml"
        assert "[mcp_servers.cloud-ai-security-skills]" in binding["mcp_toml"]
        assert "mcp-server/src/server.py" in binding["mcp_toml"]
        assert payload["mcp_tools_discovered"]

    def test_zed_mcp_binding_documents_context_servers(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "zed_mcp_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["zed_binding"]
        assert binding["integration"] == "zed_context_servers_json"
        assert binding["config_path"] == "~/.config/zed/settings.json"
        servers = binding["context_servers"]["context_servers"]
        assert "cloud-ai-security-skills" in servers
        assert servers["cloud-ai-security-skills"]["command"]["args"][0].endswith(
            "mcp-server/src/server.py"
        )
        assert payload["mcp_tools_discovered"]

    def test_anthropic_binding_documents_mcp_config(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "anthropic_sdk_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["anthropic_binding"]
        assert binding["integration"] == "anthropic_mcp_json"
        assert "mcp_config" in binding
        assert payload["mcp_tools_discovered"]

    def test_openai_binding_documents_mcp_server(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "openai_sdk_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["openai_binding"]
        assert binding["integration"] == "openai_agents_mcp_server"
        assert binding["mcp_server"]["name"] == "cloud-ai-security-skills"
        assert payload["mcp_tools_discovered"]

    def test_langgraph_reaches_remediation_with_approval(self):
        env = {
            **os.environ,
            "DEMO_APPROVE": "yes",
            "DEMO_HARNESS_PROFILE": str(EXAMPLES / "harness_profiles" / "dry-run-remediation.json"),
        }
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


class TestIdeMcpBindings:
    PROFILE = EXAMPLES / "harness_profiles" / "sdk-cspm-agent.json"

    def _bindings_module(self):
        if str(EXAMPLES) not in sys.path:
            sys.path.insert(0, str(EXAMPLES))
        import ide_mcp_bindings

        return ide_mcp_bindings

    def test_all_clients_share_mcp_policy_env(self):
        ide_mcp_bindings = self._bindings_module()

        profile = json.loads(self.PROFILE.read_text(encoding="utf-8"))
        expected = ide_mcp_bindings.mcp_policy_env(profile)

        cursor_env = ide_mcp_bindings.build_cursor_mcp_config(profile)["mcpServers"][
            "cloud-ai-security-skills"
        ]["env"]
        windsurf_env = ide_mcp_bindings.build_windsurf_mcp_config(profile)["mcpServers"][
            "cloud-ai-security-skills"
        ]["env"]
        zed_env = ide_mcp_bindings.build_zed_context_servers(profile)["context_servers"][
            "cloud-ai-security-skills"
        ]["command"]["env"]
        langchain_env = ide_mcp_bindings.build_langchain_mcp_servers(profile)[
            "cloud-ai-security-skills"
        ]["env"]
        anthropic_env = ide_mcp_bindings.build_anthropic_mcp_config(profile)["mcpServers"][
            "cloud-ai-security-skills"
        ]["env"]
        openai_env = ide_mcp_bindings.build_openai_agents_mcp_server(profile)["env"]

        assert cursor_env == expected
        assert windsurf_env == expected
        assert zed_env == expected
        assert langchain_env == expected
        assert anthropic_env == expected
        assert openai_env == expected
        assert expected["CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS"] == "true"
        assert "cspm-aws-cis-benchmark" in expected["CLOUD_SECURITY_MCP_ALLOWED_SKILLS"]

    def test_workspace_clients_use_workspace_folder_arg(self):
        ide_mcp_bindings = self._bindings_module()

        profile = json.loads(self.PROFILE.read_text(encoding="utf-8"))
        cursor_args = ide_mcp_bindings.build_cursor_mcp_config(profile)["mcpServers"][
            "cloud-ai-security-skills"
        ]["args"]
        cortex_args = ide_mcp_bindings.build_cortex_mcp_config(profile)["mcpServers"][
            "cloud-ai-security-skills"
        ]["args"]
        assert cursor_args == [ide_mcp_bindings.WORKSPACE_SERVER_ARG]
        assert cortex_args == [ide_mcp_bindings.WORKSPACE_SERVER_ARG]


class TestEmitMcpClientConfigs:
    SCRIPT = EXAMPLES / "emit_mcp_client_configs.py"

    def test_emits_all_clients_offline(self):
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["schema_version"] == "mcp-client-config-bundle-v1"
        assert set(payload["clients"]) == {
            "cursor",
            "cortex",
            "windsurf",
            "codex",
            "zed",
            "langchain",
            "anthropic",
            "openai",
        }
        assert "mcp_config" in payload["clients"]["cursor"]
        assert "mcp_toml" in payload["clients"]["codex"]
        assert "context_servers" in payload["clients"]["zed"]
        assert "mcp_servers" in payload["clients"]["langchain"]
        assert "mcp_server" in payload["clients"]["openai"]

    def test_single_client_filter(self):
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT), "--client", "cursor"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert set(payload["clients"]) == {"cursor"}

    def test_emit_bundle_matches_schema(self):
        schema = json.loads(
            (SCHEMAS / "mcp_client_config_bundle.schema.json").read_text(encoding="utf-8")
        )
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert _schema_errors(schema, payload) == []


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

    def test_runtime_wrapper_accepts_profile_caller_and_events(
        self, monkeypatch: pytest.MonkeyPatch
    ):
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

    def test_runtime_wrapper_replays_checkpoint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.delenv("DEMO_APPROVE", raising=False)
        runtime = self._runtime_module()
        checkpoint_path = tmp_path / "langgraph-checkpoint.json"

        first = runtime.run_harness(runtime.HarnessRunConfig(checkpoint_path=checkpoint_path))
        replayed = runtime.run_harness(
            runtime.HarnessRunConfig(replay_checkpoint_path=checkpoint_path)
        )

        assert first.checkpoint["path"] == str(checkpoint_path)
        assert replayed.runtime["execution_mode"] == "checkpoint_replay"
        assert replayed.runtime["replayed"] is True
        assert (
            replayed.summary["integrity"]["state_hash"] == first.summary["integrity"]["state_hash"]
        )

    def test_runtime_wrapper_accepts_stateful_approval_context(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.delenv("DEMO_APPROVE", raising=False)
        runtime = self._runtime_module()
        config = runtime.HarnessRunConfig(
            profile_path=EXAMPLES / "harness_profiles" / "dry-run-remediation.json",
            approval_context={
                "approver_id": "reviewer@example.com",
                "ticket_id": "SEC-RUNTIME-1",
                "approval_timestamp": "2026-06-23T00:00:00+00:00",
            },
        )

        result = runtime.run_harness(config)

        assert result.validation_errors == ()
        assert result.summary["approval_context_present"] is True
        assert result.summary["review"]["status"] == "approved"
        assert result.summary["review"]["reason"] == "operator approval context present"
        assert result.summary["remediation"]["status"] == "dry_run"


class TestLangGraphHarnessRunner:
    """CLI coverage for the operator-facing harness runner."""

    SCRIPT = EXAMPLES / "run_langgraph_harness.py"

    def _run(
        self,
        *args: str,
        env: dict[str, str] | None = None,
    ) -> tuple[dict, subprocess.CompletedProcess[str]]:
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env={**os.environ, **(env or {})},
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout), result

    def test_runner_executes_readonly_profile(self):
        summary, result = self._run(
            "--profile",
            str(EXAMPLES / "harness_profiles" / "readonly-soc.json"),
            "--clear-approval-env",
        )

        assert summary["harness_runtime"]["schema_version"] == "langgraph-soc-harness-runtime-v1"
        assert summary["harness_runtime"]["execution_mode"] == "deterministic_runner"
        assert summary["harness_runtime"]["validation_status"] == "pass"
        assert summary["profile"]["profile_id"] == "readonly-soc"
        assert summary["review"]["status"] == "blocked"
        assert summary["remediation"]["status"] == "skipped"
        assert '"node": "ingest"' in result.stderr

    def test_runner_accepts_raw_events_and_caller_context(self, tmp_path: Path):
        raw_events = tmp_path / "events.jsonl"
        raw_events.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "source": "cloudtrail",
                            "event_name": "CreateAccessKey",
                            "actor_uid": "AIDARUNNER",
                            "resource_uid": "arn:aws:iam::111122223333:user/runner",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        caller_context = {
            "email": "runner@example.com",
            "session_id": "runner-session",
        }

        summary, _ = self._run(
            "--profile",
            str(EXAMPLES / "harness_profiles" / "readonly-soc.json"),
            "--raw-events",
            str(raw_events),
            "--caller-context",
            json.dumps(caller_context),
            "--clear-approval-env",
        )

        assert summary["caller_context"]["email"] == "runner@example.com"
        assert summary["audit"]["correlation_id"] == "runner-session"
        assert summary["findings_count"] == 1

    def test_runner_approval_reaches_dry_run_only(self):
        summary, _ = self._run(
            "--profile",
            str(EXAMPLES / "harness_profiles" / "dry-run-remediation.json"),
            "--approve",
            "--approver",
            "reviewer@example.com",
            "--ticket",
            "SEC-RUNNER-1",
        )

        assert summary["review"]["status"] == "approved"
        assert summary["approval_context_present"] is True
        assert summary["review"]["reason"] == "operator approval context present"
        assert summary["review"]["approval"]["ticket_id"] == "SEC-RUNNER-1"
        assert summary["remediation"]["status"] == "dry_run"
        assert summary["remediation"]["dry_run"] is True

    def test_runner_accepts_explicit_approval_context_file(self, tmp_path: Path):
        approval_context = tmp_path / "approval.json"
        approval_context.write_text(
            json.dumps(
                {
                    "approver_id": "reviewer@example.com",
                    "ticket_id": "SEC-RUNNER-FILE-1",
                    "approval_timestamp": "2026-06-23T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )

        summary, _ = self._run(
            "--profile",
            str(EXAMPLES / "harness_profiles" / "dry-run-remediation.json"),
            "--approval-context",
            str(approval_context),
            "--clear-approval-env",
        )

        assert summary["approval_context_present"] is True
        assert summary["review"]["approval"]["ticket_id"] == "SEC-RUNNER-FILE-1"
        assert summary["remediation"]["status"] == "dry_run"

    def test_runner_writes_output_and_replays_checkpoint(self, tmp_path: Path):
        checkpoint = tmp_path / "checkpoint.json"
        output = tmp_path / "summary.json"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--checkpoint",
                str(checkpoint),
                "--output",
                str(output),
                "--clear-approval-env",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        original = json.loads(output.read_text(encoding="utf-8"))
        assert checkpoint.exists()

        replayed, _ = self._run("--replay-checkpoint", str(checkpoint))

        assert replayed["harness_runtime"]["execution_mode"] == "checkpoint_replay"
        assert replayed["harness_runtime"]["replayed"] is True
        assert replayed["integrity"]["state_hash"] == original["integrity"]["state_hash"]

    def test_runner_rejects_secret_material_in_approval_context(self, tmp_path: Path):
        approval_context = tmp_path / "approval.json"
        synthetic_pat = "ghp_" + ("a" * 36)
        approval_context.write_text(
            json.dumps(
                {
                    "approver_id": "reviewer@example.com",
                    "ticket_id": "SEC-RUNNER-SECRET-1",
                    "approval_timestamp": "2026-06-23T00:00:00+00:00",
                    "notes": synthetic_pat,
                }
            ),
            encoding="utf-8",
        )

        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--profile",
                str(EXAMPLES / "harness_profiles" / "dry-run-remediation.json"),
                "--approval-context",
                str(approval_context),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        assert result.returncode == 1
        assert "must not contain password, PAT, token, or secret material" in result.stderr

    def test_runner_fails_closed_on_invalid_raw_event_shape(self, tmp_path: Path):
        raw_events = tmp_path / "bad-events.json"
        raw_events.write_text(json.dumps(["not-an-object"]), encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--raw-events",
                str(raw_events),
                "--clear-approval-env",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        assert result.returncode == 1
        assert "langgraph harness run failed" in result.stderr
        assert "--raw-events must be a JSON object" in result.stderr


class TestLangGraphMcpPlanExecutor:
    """Coverage for executing MCP call plans as a separate harness artifact."""

    SCRIPT = EXAMPLES / "execute_langgraph_mcp_plan.py"

    @staticmethod
    def _summary(mode: str = "plan_only") -> dict:
        return {
            "profile": {
                "runtime": {
                    "mcp_execution": {
                        "mode": mode,
                        "transport": "mcp_stdio_jsonrpc",
                        "execute_planned_calls": mode == "operator_stdio",
                        "allow_write_calls": False,
                        "max_calls": 5,
                    }
                }
            },
            "effective_allowed_skills": ["source-snowflake-query"],
            "mcp_call_plan": [
                {
                    "node": "ingest",
                    "skill": "source-snowflake-query",
                    "status": "planned",
                    "write_capable": False,
                    "request": {
                        "jsonrpc": "2.0",
                        "id": "wf:ingest:source-snowflake-query",
                        "method": "tools/call",
                        "params": {
                            "name": "source-snowflake-query",
                            "arguments": {
                                "args": [
                                    "--query",
                                    "SELECT payload FROM security.events_sink LIMIT 1",
                                ],
                                "input": "",
                                "_caller_context": {
                                    "allowed_skills": ["source-snowflake-query"],
                                },
                            },
                        },
                    },
                }
            ],
        }

    def test_executor_replays_plan_only_summary_without_transport(self, tmp_path: Path):
        summary_path = tmp_path / "summary.json"
        summary_path.write_text(json.dumps(self._summary(), sort_keys=True), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT), "--summary", str(summary_path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["mode"] == "plan_only"
        assert report["executed_call_count"] == 0
        assert report["status_counts"] == {"skipped_plan_only": 1}

    def test_executor_runs_operator_stdio_with_local_fake_server(self, tmp_path: Path):
        summary_path = tmp_path / "summary.json"
        summary_path.write_text(
            json.dumps(self._summary("operator_stdio"), sort_keys=True), encoding="utf-8"
        )
        fake_server = tmp_path / "fake_mcp_server.py"
        fake_server.write_text(
            """
import json
import sys


def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\\r\\n", b"\\n"):
            break
        key, value = line.decode("utf-8").split(":", 1)
        headers[key.strip().lower()] = value.strip()
    payload = sys.stdin.buffer.read(int(headers["content-length"]))
    return json.loads(payload.decode("utf-8"))


def write_message(message):
    payload = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(payload)}\\r\\n\\r\\n".encode("utf-8"))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


while True:
    request = read_message()
    if request is None:
        break
    write_message({
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {"ok": True, "tool": request.get("params", {}).get("name")},
    })
""",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--summary",
                str(summary_path),
                "--allow-operator-stdio",
                "--mcp-server-command",
                sys.executable,
                "--mcp-server-arg",
                str(fake_server),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["mode"] == "operator_stdio"
        assert report["executed_call_count"] == 1
        assert report["write_executed_count"] == 0
        assert report["status_counts"] == {"executed": 1}

    def test_safe_mcp_env_does_not_forward_api_keys(self, monkeypatch: pytest.MonkeyPatch):
        sys.path.insert(0, str(EXAMPLES))
        try:
            from harness_mcp_transport import safe_mcp_env
        finally:
            sys.path.pop(0)
        monkeypatch.setenv("OPENAI_API_KEY", "redacted-test-value")
        monkeypatch.setenv("CLOUD_SECURITY_MCP_TIMEOUT_SECONDS", "5")
        env = safe_mcp_env(allowed_skills=["source-snowflake-query"])
        assert "OPENAI_API_KEY" not in env
        assert env["CLOUD_SECURITY_MCP_TIMEOUT_SECONDS"] == "5"
        assert env["CLOUD_SECURITY_MCP_ALLOWED_SKILLS"] == "source-snowflake-query"


class TestSdkPresetOverlay:
    """Harness profile ∩ workflow preset intersection for SDK examples."""

    def test_preset_intersects_harness_profile(self, monkeypatch: pytest.MonkeyPatch):
        sys.path.insert(0, str(EXAMPLES))
        try:
            from sdk_agent_common import load_sdk_profile, read_allowlist
        finally:
            sys.path.pop(0)
        monkeypatch.setenv(
            "CLOUD_SECURITY_MCP_PRESET",
            "presets/preset-cspm-readonly.json",
        )
        profile = load_sdk_profile()
        assert profile["preset_applied"] == "cspm-readonly"
        skills = read_allowlist(profile)
        assert "detect-lateral-movement" not in skills
        assert "cspm-aws-cis-benchmark" in skills
        assert "convert-ocsf-to-sarif" in skills
        caller = profile["caller_context"]["allowed_skills"]
        assert "detect-lateral-movement" not in caller
        assert "cspm-aws-cis-benchmark" in caller

    def test_empty_intersection_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ):
        sys.path.insert(0, str(EXAMPLES))
        try:
            from sdk_agent_common import load_sdk_profile
        finally:
            sys.path.pop(0)
        preset_path = tmp_path / "no-overlap.json"
        preset_path.write_text(
            json.dumps(
                {
                    "name": "no-overlap",
                    "allowed_skills": ["ingest-cloudtrail-ocsf"],
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CLOUD_SECURITY_MCP_PRESET", str(preset_path))
        with pytest.raises(ValueError, match="empty"):
            load_sdk_profile()


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
            env.update(
                {
                    "DEMO_APPROVE": "yes",
                    "DEMO_APPROVER": "reviewer@example.com",
                    "DEMO_TICKET": "SEC-LANGGRAPH-1",
                }
            )
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
        assert (
            summary["token_budget_usage"]["compact_input_tokens_estimate"]
            <= summary["harness"]["token_budget"]["max_input_tokens"]
        )
        assert (
            summary["token_budget_usage"]["compact_evidence_chars"]
            <= summary["harness"]["token_budget"]["max_evidence_chars"]
        )
        assert summary["audit"]["llm_token_budget_status"] == "within_budget"
        assert (
            summary["audit"]["llm_compact_input_tokens"]
            == summary["token_budget_usage"]["compact_input_tokens_estimate"]
        )
        assert summary["llm_evidence_cards"]
        assert all("raw_events" not in card for card in summary["llm_evidence_cards"])
        assert all("ocsf_events" not in card for card in summary["llm_evidence_cards"])
        assert [agent["agent_id"] for agent in summary["agents"]] == self.EXPECTED_AGENT_IDS
        triage_agent = next(
            agent for agent in summary["agents"] if agent["agent_id"] == "triage-agent"
        )
        assert triage_agent["privilege_boundary"] == "no_tool_writes"
        assert triage_agent["skill_scope"] == []
        assert triage_agent["model_tier"] == "tiny"
        assert "approval" in triage_agent["forbidden_outputs"]
        remediation_agent = next(
            agent for agent in summary["agents"] if agent["agent_id"] == "remediation-planner"
        )
        assert remediation_agent["requires_human_approval"] is True
        assert remediation_agent["privilege_boundary"] == "dry_run_write_planning"
        assert summary["agent_policy"]["schema_version"] == "langgraph-agent-policy-v1"
        assert summary["agent_policy"]["policy_hash"] == summary["audit"]["agent_policy_hash"]
        policy_entries = {entry["agent_id"]: entry for entry in summary["agent_policy"]["entries"]}
        assert policy_entries["triage-agent"]["decision"] == "no_direct_tools"
        assert policy_entries["triage-agent"]["effective_skill_grants"] == []
        assert policy_entries["remediation-planner"]["denied_skill_scope"] == ["iam-departures-aws"]
        assert policy_entries["remediation-planner"]["decision"] == "blocked_by_allowlist"
        assert [run["agent_id"] for run in summary["agent_runs"]] == [
            "evidence-agent",
            "risk-map-agent",
            "triage-agent",
            "review-gate",
            "audit-writer",
        ]
        assert all(run["input_hash"] and run["output_hash"] for run in summary["agent_runs"])
        assert summary["agent_recommendations"][0]["recommended_action"] == "request_approval"
        assert (
            summary["agent_recommendations"][0]["generated_by"]
            == "deterministic-local:policy-bounded-triage-v1"
        )
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
            (edge["source"], edge["target"], edge["condition"]) for edge in contract["edges"]
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
        assert (
            "LLM adapters can rank, summarize, draft, or request review only"
            in contract["invariants"]
        )

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

    def test_approval_without_remediation_skill_does_not_create_write_intent(self):
        summary, _ = self._run(approved=True)
        assert summary["trace"] == self.EXPECTED_APPROVED_TRACE
        assert summary["review"]["status"] == "approved"
        assert summary["remediation"]["status"] == "skipped"
        assert summary["remediation"]["reason"] == "remediation skill not in effective allowlist"
        assert "planned_steps" not in summary["remediation"]
        remediation_policy = next(
            entry
            for entry in summary["agent_policy"]["entries"]
            if entry["agent_id"] == "remediation-planner"
        )
        assert remediation_policy["denied_skill_scope"] == ["iam-departures-aws"]
        assert remediation_policy["decision"] == "blocked_by_allowlist"

    def test_approval_allows_dry_run_only(self):
        summary, _ = self._run(
            approved=True,
            extra_env={"DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json")},
        )
        assert summary["trace"] == self.EXPECTED_APPROVED_TRACE
        assert summary["review"]["status"] == "approved"
        assert summary["review"]["approval"]["ticket_id"] == "SEC-LANGGRAPH-1"
        assert summary["remediation"]["status"] == "dry_run"
        assert summary["remediation"]["dry_run"] is True
        assert summary["remediation"]["skill"] == "iam-departures-aws"
        assert summary["data_source"]["mode"] == "raw_ingest"
        assert summary["data_source"]["source_skill"] == "ingest-cloudtrail-ocsf"
        assert summary["remediation"]["idempotency_key"].startswith("rem-")
        planned_remediation_call = next(
            call for call in summary["mcp_call_plan"] if call["skill"] == "iam-departures-aws"
        )
        assert planned_remediation_call["status"] == "planned"
        assert planned_remediation_call["request"]["method"] == "tools/call"
        assert (
            planned_remediation_call["request"]["params"]["arguments"]["_approval_context"][
                "ticket_id"
            ]
            == "SEC-LANGGRAPH-1"
        )
        assert "--apply" not in planned_remediation_call["request"]["params"]["arguments"]["args"]
        assert summary["mcp_execution"]["schema_version"] == "langgraph-mcp-execution-v1"
        assert summary["mcp_execution"]["mode"] == "plan_only"
        assert (
            summary["mcp_execution"]["planned_call_count"]
            == summary["audit"]["mcp_planned_call_count"]
        )
        assert summary["mcp_execution"]["executed_call_count"] == 0
        assert summary["mcp_execution"]["write_executed_count"] == 0
        assert (
            summary["mcp_execution"]["status_counts"]["skipped_plan_only"]
            == summary["audit"]["mcp_planned_call_count"]
        )
        assert (
            summary["idempotency"]["remediation_key"] == summary["remediation"]["idempotency_key"]
        )
        assert summary["integrity"]["approved_payload_hash"]
        assert summary["audit"]["idempotency_key"] == summary["remediation"]["idempotency_key"]
        assert summary["audit"]["route"] == {
            "after_review": "remediate",
            "after_remediation": "writeback",
        }
        policy_entries = {entry["agent_id"]: entry for entry in summary["agent_policy"]["entries"]}
        assert policy_entries["remediation-planner"]["effective_skill_grants"] == [
            "iam-departures-aws"
        ]
        assert policy_entries["remediation-planner"]["denied_skill_scope"] == []
        assert policy_entries["remediation-planner"]["decision"] == "ready"
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
        summary, _ = self._run(
            extra_env={
                "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
                "DEMO_LLM_PROVIDER": "openai",
                "DEMO_LLM_MODEL": "gpt-4.1-mini",
            }
        )
        assert summary["harness"]["mode"] == "external_llm_optional"
        assert summary["harness"]["provider"] == "openai"
        assert summary["harness"]["model"] == "gpt-4.1-mini"
        assert summary["harness"]["token_budget"]["model_tier"] == "tiny"
        assert summary["harness"]["model_policy"]["selected_model_tier"] == "tiny"
        assert summary["harness"]["model_policy"]["selection_source"] == "env_override"
        assert "call_write_tools" not in summary["harness"]["allowed_outputs"]
        assert summary["agent_recommendations"][0]["generated_by"] == "openai:gpt-4.1-mini"
        assert summary["remediation"]["status"] == "skipped"
        triage_agent = next(
            agent for agent in summary["agents"] if agent["agent_id"] == "triage-agent"
        )
        assert "approval" in triage_agent["forbidden_outputs"]
        assert "write_intent" in triage_agent["forbidden_outputs"]
        assert summary["llm_validation"][0]["status"] == "fallback"
        assert summary["llm_validation"][0]["reason"] == "no_adapter_output"

    def test_mcp_execution_bridge_executes_readonly_and_blocks_writes(self):
        sys.path.insert(0, str(EXAMPLES))
        try:
            from harness_mcp_bridge import execute_mcp_call_plan
        finally:
            sys.path.pop(0)

        call_plan = [
            {
                "node": "ingest",
                "skill": "source-snowflake-query",
                "status": "planned",
                "write_capable": False,
                "request": {
                    "jsonrpc": "2.0",
                    "id": "wf:ingest:source-snowflake-query",
                    "method": "tools/call",
                    "params": {"name": "source-snowflake-query", "arguments": {}},
                },
            },
            {
                "node": "remediate",
                "skill": "iam-departures-aws",
                "status": "planned",
                "write_capable": True,
                "request": {
                    "jsonrpc": "2.0",
                    "id": "wf:remediate:iam-departures-aws",
                    "method": "tools/call",
                    "params": {"name": "iam-departures-aws", "arguments": {}},
                },
            },
        ]
        profile = {
            "runtime": {
                "mcp_execution": {
                    "mode": "operator_stdio",
                    "transport": "mcp_stdio_jsonrpc",
                    "execute_planned_calls": True,
                    "allow_write_calls": False,
                    "max_calls": 10,
                }
            }
        }

        def fake_transport(request: dict) -> dict:
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"ok": True}}

        report = execute_mcp_call_plan(
            call_plan=call_plan,
            profile=profile,
            transport=fake_transport,
        )
        assert report["executed_call_count"] == 1
        assert report["write_executed_count"] == 0
        assert report["status_counts"] == {"executed": 1, "blocked_write_execution": 1}
        assert report["results"][1]["skill"] == "iam-departures-aws"

    def test_token_budget_overage_uses_deterministic_fallback(self):
        summary, _ = self._run(
            extra_env={
                "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
                "DEMO_LLM_PROVIDER": "fixture",
                "DEMO_LLM_MODEL": "oversized-context-fixture",
                "DEMO_TOKEN_MAX_INPUT_TOKENS": "1",
            }
        )
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
        fixture.write_text(
            json.dumps(
                {
                    "recommendations": [
                        {
                            "finding_uid": finding_uid,
                            "priority": "critical",
                            "recommended_action": "request_approval",
                            "rationale": "Fixture model ranks the finding for immediate analyst review.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        summary, _ = self._run(
            extra_env={
                "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
                "DEMO_LLM_PROVIDER": "fixture",
                "DEMO_LLM_MODEL": "triage-fixture-v1",
                "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
            }
        )

        recommendation = summary["agent_recommendations"][0]
        assert recommendation["priority"] == "critical"
        assert recommendation["recommended_action"] == "request_approval"
        assert (
            recommendation["rationale"]
            == "Fixture model ranks the finding for immediate analyst review."
        )
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
        fixture.write_text(
            json.dumps(
                {
                    "recommendations": [
                        {
                            "finding_uid": finding_uid,
                            "priority": "critical",
                            "recommended_action": "request_approval",
                            "rationale": "LangChain fixture ranks this for immediate analyst review.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        summary, _ = self._run(
            extra_env={
                "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
                "DEMO_LLM_PROVIDER": "langchain",
                "DEMO_LLM_MODEL": "chat-model-fixture-v1",
                "DEMO_LANGCHAIN_ADAPTER_FIXTURE": str(fixture),
            }
        )

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
        fixture.write_text(
            json.dumps(
                {
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
                }
            ),
            encoding="utf-8",
        )

        summary, _ = self._run(
            extra_env={
                "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
                "DEMO_LLM_PROVIDER": "fixture",
                "DEMO_LLM_MODEL": "triage-fixture-v1",
                "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
            }
        )

        recommendation = summary["agent_recommendations"][0]
        assert recommendation["priority"] == "high"
        assert recommendation["recommended_action"] == "request_approval"
        assert recommendation["rationale"].startswith("Deterministic triage")
        assert summary["llm_validation"][0]["status"] == "rejected"
        assert summary["llm_validation"][0]["reason"] == "forbidden_output:approval,cvss"
        assert summary["audit"]["llm_adapter_accepted"] == 0
        assert summary["audit"]["llm_adapter_rejected"] == 1

    def test_profile_loads_caller_context_and_allowed_skills(self):
        summary, _ = self._run(
            extra_env={
                "DEMO_HARNESS_PROFILE": str(self.PROFILES / "readonly-soc.json"),
            }
        )
        assert summary["profile"]["profile_id"] == "readonly-soc"
        assert summary["caller_context"]["email"] == "soc-readonly@example.com"
        assert summary["audit"]["profile_id"] == "readonly-soc"
        assert summary["data_source"]["mode"] == "security_lake_replay"
        assert summary["data_source"]["backend"] == "snowflake"
        assert summary["data_source"]["source_skill"] == "source-snowflake-query"
        assert summary["effective_allowed_skills"] == [
            "ingest-cloudtrail-ocsf",
            "source-snowflake-query",
            "detect-lateral-movement",
            "cspm-aws-cis-benchmark",
            "discover-control-evidence",
            "convert-ocsf-to-sarif",
        ]
        ingest_source_calls = [
            call
            for call in summary["mcp_call_plan"]
            if call["node"] == "ingest" and call["skill"].startswith("source-")
        ]
        assert [(call["skill"], call["status"]) for call in ingest_source_calls] == [
            ("source-snowflake-query", "planned"),
            ("source-clickhouse-query", "not_required"),
            ("source-databricks-query", "not_required"),
        ]
        normalize_ingest = next(
            call
            for call in summary["mcp_call_plan"]
            if call["node"] == "normalize" and call["skill"] == "ingest-cloudtrail-ocsf"
        )
        assert normalize_ingest["status"] == "not_required"
        assert "already OCSF" in normalize_ingest["reason"]
        assert summary["remediation"]["status"] == "skipped"

    def test_profile_llm_metadata_is_bounded(self):
        summary, _ = self._run(
            extra_env={
                "DEMO_HARNESS_PROFILE": str(self.PROFILES / "analyst-triage.json"),
            }
        )
        assert summary["profile"]["profile_id"] == "analyst-triage"
        assert summary["harness"]["mode"] == "external_llm_optional"
        assert summary["harness"]["provider"] == "openai"
        assert summary["harness"]["model"] == "gpt-4.1-mini"
        assert summary["harness"]["model_policy"]["selected_model_tier"] == "small"
        assert summary["harness"]["model_policy"]["selection_source"] == "profile_model_policy"
        triage_agent = next(
            agent for agent in summary["agents"] if agent["agent_id"] == "triage-agent"
        )
        assert triage_agent["model_tier"] == "small"
        assert triage_agent["privilege_boundary"] == "no_tool_writes"
        assert triage_agent["skill_scope"] == []
        assert summary["agent_recommendations"][0]["generated_by"] == "openai:gpt-4.1-mini"
        assert summary["review"]["status"] == "blocked"

    def test_remediation_profile_does_not_grant_approval(self):
        summary, _ = self._run(
            extra_env={
                "DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json"),
            }
        )
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
        approved, _ = self._run(
            approved=True,
            extra_env={"DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json")},
        )
        remediation_key = approved["remediation"]["idempotency_key"]
        replay, _ = self._run(
            approved=True,
            extra_env={
                "DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json"),
                "DEMO_SEEN_IDEMPOTENCY_KEYS": remediation_key,
            },
        )
        assert replay["remediation"]["status"] == "skipped"
        assert (
            replay["remediation"]["reason"] == "duplicate idempotency key; write intent suppressed"
        )
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
            extra_env={
                "DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json"),
                "DEMO_API_ERROR_STATUS": "429",
            },
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
            extra_env={
                "DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json"),
                "DEMO_API_ERROR_STATUS": "403",
            },
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
            "DEMO_HARNESS_PROFILE": str(self.PROFILES / "dry-run-remediation.json"),
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


class TestLangGraphHitlInterrupt:
    """LangGraph native interrupt/resume at the analyst review gate."""

    SCRIPT = EXAMPLES / "langgraph_hitl_interrupt_resume.py"

    def test_interrupt_resume_reaches_dry_run_remediation(self):
        pytest.importorskip("langgraph.graph")
        env = {
            **os.environ,
            "PYTHONPATH": str(EXAMPLES),
            "CLOUD_SECURITY_HARNESS_PROFILE": str(
                EXAMPLES / "harness_profiles" / "dry-run-remediation.json"
            ),
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
        payload = json.loads(result.stdout)
        assert payload["schema_version"] == "langgraph-hitl-interrupt-resume-v1"
        assert payload["interrupt_before"] == "review"
        assert payload["phases"]["paused_at_review"] is True
        assert payload["review_decision"]["status"] == "approved"
        assert payload["remediation_result"]["status"] == "dry_run"
        assert payload["remediation_result"]["dry_run"] is True

    def test_skips_gracefully_when_langgraph_is_missing(self, monkeypatch):
        monkeypatch.delenv("PYTHONPATH", raising=False)
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env={
                k: v
                for k, v in os.environ.items()
                if k not in {"VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT"}
            },
        )
        if result.returncode == 0 and '"status": "skipped"' in result.stdout:
            return
        pytest.importorskip("langgraph.graph")
        assert result.returncode == 0, result.stderr


class TestLangGraphContractSchemas:
    """Contract coverage for harness profile and LLM adapter JSON schemas."""

    PROFILE_SCHEMA = SCHEMAS / "harness_profile.schema.json"
    ADAPTER_SCHEMA = SCHEMAS / "llm_adapter_recommendations.schema.json"
    PIPELINE_SCHEMA = SCHEMAS / "pipeline_contract.schema.json"
    AGENT_POLICY_SCHEMA = SCHEMAS / "agent_policy.schema.json"
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
            self.AGENT_POLICY_SCHEMA,
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
            data_source = profile["runtime"].get("security_data_source") or {}
            assert data_source.get("mode") in {"raw_ingest", "security_lake_replay"}
            if data_source.get("mode") == "raw_ingest":
                assert data_source.get("source_skill") == "ingest-cloudtrail-ocsf"
                assert data_source.get("records_format") == "raw_vendor"
            if data_source.get("mode") == "security_lake_replay":
                assert data_source.get("source_skill", "").startswith("source-")
                assert data_source.get("backend") in {"snowflake", "clickhouse", "databricks"}
            mcp_execution = profile["runtime"].get("mcp_execution") or {}
            assert mcp_execution["transport"] == "mcp_stdio_jsonrpc"
            assert mcp_execution["allow_write_calls"] is False
            if mcp_execution["mode"] == "plan_only":
                assert mcp_execution["execute_planned_calls"] is False
            if "token_budget" in profile:
                assert profile["token_budget"]["compression_required"] is True
                assert profile["token_budget"]["fallback_on_budget_exceeded"] is True
            assert profile["model_policy"]["policy_version"] == "langgraph-model-policy-v1"
            assert profile["model_policy"]["selection_strategy"] == "smallest_sufficient"
            assert (
                profile["token_budget"]["model_tier"]
                in profile["model_policy"]["allowed_model_tiers"]
            )
            if profile.get("agent_roster"):
                roster = {agent["agent_id"]: agent for agent in profile["agent_roster"]}
                if "triage-agent" in roster:
                    assert roster["triage-agent"]["privilege_boundary"] == "no_tool_writes"
                    assert roster["triage-agent"]["skill_scope"] == []
                if "remediation-planner" in roster:
                    assert roster["remediation-planner"]["requires_human_approval"] is True

    def test_llm_adapter_eval_fixtures_match_expected_schema_outcome(self):
        schema = json.loads(self.ADAPTER_SCHEMA.read_text(encoding="utf-8"))
        dataset = json.loads(self.DATASET.read_text(encoding="utf-8"))
        adapter_cases = [case for case in dataset["cases"] if "llm_adapter_fixture" in case]
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

        remediation_node = next(node for node in contract["nodes"] if node["node"] == "remediate")
        assert remediation_node["skills"] == ["iam-departures-aws"]
        triage_node = next(node for node in contract["nodes"] if node["node"] == "llm_triage")
        assert triage_node["skills"] == []

    def test_emitted_agent_policy_matches_schema_and_known_boundaries(self):
        result = subprocess.run(
            [sys.executable, str(self.GRAPH)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        summary = json.loads(result.stdout)
        agent_policy = summary["agent_policy"]
        schema = json.loads(self.AGENT_POLICY_SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, agent_policy) == []
        assert agent_policy["policy_hash"] == summary["audit"]["agent_policy_hash"]

        entries = {entry["agent_id"]: entry for entry in agent_policy["entries"]}
        assert entries["triage-agent"]["effective_skill_grants"] == []
        assert entries["triage-agent"]["decision"] == "no_direct_tools"
        assert entries["remediation-planner"]["write_policy"] == "dry_run_only_after_hitl"
        assert entries["remediation-planner"]["denied_skill_scope"] == ["iam-departures-aws"]


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
                "--data-source-mode",
                "security-lake-replay",
                "--lake-backend",
                "clickhouse",
                "--lake-query",
                "SELECT payload FROM security.events_sink LIMIT 50",
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
        assert profile["runtime"]["security_data_source"] == {
            "mode": "security_lake_replay",
            "backend": "clickhouse",
            "source_skill": "source-clickhouse-query",
            "records_format": "ocsf",
            "query": "SELECT payload FROM security.events_sink LIMIT 50",
        }
        assert profile["runtime"]["mcp_execution"] == {
            "mode": "plan_only",
            "transport": "mcp_stdio_jsonrpc",
            "execute_planned_calls": False,
            "allow_write_calls": False,
            "max_calls": 0,
        }
        roster = {agent["agent_id"]: agent for agent in profile["agent_roster"]}
        assert roster["triage-agent"] == {
            "agent_id": "triage-agent",
            "model_tier": "small",
            "privilege_boundary": "no_tool_writes",
            "skill_scope": [],
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
        assert summary["data_source"]["mode"] == "security_lake_replay"
        assert summary["data_source"]["backend"] == "clickhouse"
        clickhouse_source_call = next(
            call
            for call in summary["mcp_call_plan"]
            if call["node"] == "ingest" and call["skill"] == "source-clickhouse-query"
        )
        assert clickhouse_source_call["status"] == "planned"
        assert clickhouse_source_call["request"]["params"]["arguments"]["args"] == [
            "--query",
            "SELECT payload FROM security.events_sink LIMIT 50",
        ]
        assert summary["mcp_execution"]["mode"] == "plan_only"
        assert summary["mcp_execution"]["executed_call_count"] == 0
        triage_agent = next(
            agent for agent in summary["agents"] if agent["agent_id"] == "triage-agent"
        )
        assert triage_agent["model_tier"] == "small"
        assert triage_agent["skill_scope"] == []
        assert summary["review"]["status"] == "blocked"

    def test_sdk_cspm_role_matches_shipped_sdk_profile_shape(self, tmp_path: Path):
        profile_path = tmp_path / "acme-sdk-cspm.json"
        env_path = tmp_path / "acme-sdk-cspm.env"
        shipped = json.loads(
            (EXAMPLES / "harness_profiles" / "sdk-cspm-agent.json").read_text(encoding="utf-8")
        )
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "sdk-cspm",
                "--profile-id",
                "acme-sdk-cspm",
                "--email",
                "sdk-agent@example.com",
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
        schema = json.loads(self.PROFILE_SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, profile) == []
        assert profile["allowed_skills"] == shipped["allowed_skills"]
        assert (
            profile["caller_context"]["allowed_skills"]
            == shipped["caller_context"]["allowed_skills"]
        )
        assert profile["cloud_identity_hints"] == shipped["cloud_identity_hints"]
        assert profile["runtime"]["mcp_execution"] == shipped["runtime"]["mcp_execution"]
        assert len(profile["agent_roster"]) == 1
        assert profile["agent_roster"][0]["agent_id"] == "triage-agent"
        assert "iam-departures-aws" not in profile["allowed_skills"]

    def test_setup_generator_intersects_workflow_preset(self, tmp_path: Path):
        profile_path = tmp_path / "acme-sdk-cspm-preset.json"
        env_path = tmp_path / "acme-sdk-cspm-preset.env"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "sdk-cspm",
                "--preset",
                "presets/preset-cspm-readonly.json",
                "--profile-id",
                "acme-sdk-cspm-preset",
                "--email",
                "sdk-agent@example.com",
                "--output-profile",
                str(profile_path),
                "--output-env",
                str(env_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stderr
        setup_summary = json.loads(result.stdout)
        assert setup_summary["preset_applied"] == "cspm-readonly"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        assert profile["preset_applied"] == "cspm-readonly"
        assert "detect-lateral-movement" not in profile["allowed_skills"]
        assert "cspm-aws-cis-benchmark" in profile["allowed_skills"]

    def test_setup_generator_emits_mcp_client_configs(self, tmp_path: Path):
        profile_path = tmp_path / "acme-sdk-cspm.json"
        env_path = tmp_path / "acme-sdk-cspm.env"
        mcp_path = tmp_path / "mcp-client-configs.json"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "sdk-cspm",
                "--profile-id",
                "acme-sdk-cspm",
                "--email",
                "sdk-agent@example.com",
                "--output-profile",
                str(profile_path),
                "--output-env",
                str(env_path),
                "--emit-mcp-configs",
                str(mcp_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stderr
        summary = json.loads(result.stdout)
        assert summary["mcp_client_configs"] == str(mcp_path)
        bundle = json.loads(mcp_path.read_text(encoding="utf-8"))
        assert bundle["schema_version"] == "mcp-client-config-bundle-v1"
        assert set(bundle["clients"]) == {
            "cursor",
            "cortex",
            "windsurf",
            "codex",
            "zed",
            "langchain",
            "anthropic",
            "openai",
        }

    def test_setup_generator_rejects_missing_preset(self, tmp_path: Path):
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "sdk-cspm",
                "--preset",
                "presets/does-not-exist.json",
                "--profile-id",
                "acme-bad-preset",
                "--email",
                "sdk-agent@example.com",
                "--output-profile",
                str(tmp_path / "bad.json"),
                "--output-env",
                str(tmp_path / "bad.env"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 2
        assert "preset not found" in result.stderr

    def test_setup_generator_can_mark_readonly_mcp_stdio_execution(self, tmp_path: Path):
        profile_path = tmp_path / "acme-readonly-stdio.json"
        env_path = tmp_path / "acme-readonly-stdio.env"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "readonly-soc",
                "--profile-id",
                "acme-readonly-stdio",
                "--email",
                "analyst@example.com",
                "--mcp-execution-mode",
                "operator_stdio",
                "--mcp-max-calls",
                "2",
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
        assert profile["runtime"]["mcp_execution"] == {
            "mode": "operator_stdio",
            "transport": "mcp_stdio_jsonrpc",
            "execute_planned_calls": True,
            "allow_write_calls": False,
            "max_calls": 2,
        }
        schema = json.loads(self.PROFILE_SCHEMA.read_text(encoding="utf-8"))
        assert _schema_errors(schema, profile) == []

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
        assert profile["runtime"]["security_data_source"]["mode"] == "raw_ingest"
        assert (
            profile["runtime"]["security_data_source"]["source_skill"] == "ingest-cloudtrail-ocsf"
        )
        assert profile["approval_policy"]["remediation_requires_approval_context"] is True
        assert profile["token_budget"]["model_tier"] == "tiny"
        assert profile["model_policy"]["allowed_model_tiers"] == ["tiny"]
        roster = {agent["agent_id"]: agent for agent in profile["agent_roster"]}
        assert roster["remediation-planner"]["requires_human_approval"] is True
        assert roster["remediation-planner"]["privilege_boundary"] == "dry_run_write_planning"

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

    def test_setup_generator_rejects_secret_material_in_cloud_hints(self, tmp_path: Path):
        profile_path = tmp_path / "bad-profile.json"
        env_path = tmp_path / "bad.env"
        credential_hint = "SNOWFLAKE_" + "PASSWORD=not-for-profile"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--role",
                "readonly-soc",
                "--profile-id",
                "bad-secret-profile",
                "--email",
                "analyst@example.com",
                "--cloud-hint",
                f"snowflake={credential_hint}",
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

        assert result.returncode == 2
        assert "must not contain password, PAT, token, or secret material" in result.stderr
        assert not profile_path.exists()
        assert not env_path.exists()

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


class TestLangGraphHarnessPreflight:
    """Preflight inspector coverage for profile grants before graph execution."""

    SCRIPT = EXAMPLES / "inspect_langgraph_harness.py"
    PROFILES = EXAMPLES / "harness_profiles"

    def test_readonly_profile_reports_denied_remediation_without_cloud_calls(self):
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--profile",
                str(self.PROFILES / "readonly-soc.json"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["schema_version"] == "langgraph-harness-preflight-v1"
        assert report["secrets_loaded"] is False
        assert report["cloud_calls_made"] is False
        assert report["remediation_preflight"]["would_plan_dry_run"] is False
        assert report["remediation_preflight"]["skill_granted"] is False

        entries = {entry["agent_id"]: entry for entry in report["agent_policy"]["entries"]}
        assert entries["triage-agent"]["decision"] == "no_direct_tools"
        assert entries["remediation-planner"]["denied_skill_scope"] == ["iam-departures-aws"]
        assert entries["remediation-planner"]["decision"] == "blocked_by_allowlist"

    def test_dry_run_profile_can_require_remediation_ready(self, tmp_path: Path):
        output = tmp_path / "preflight.json"
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--profile",
                str(self.PROFILES / "dry-run-remediation.json"),
                "--approval-context-present",
                "--require-remediation-ready",
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == ""
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["approval_context_present"] is True
        assert report["remediation_preflight"]["skill_granted"] is True
        assert report["remediation_preflight"]["would_plan_dry_run"] is True
        assert report["remediation_preflight"]["apply_supported"] is False

    def test_require_remediation_ready_fails_closed_for_readonly_profile(self):
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--profile",
                str(self.PROFILES / "readonly-soc.json"),
                "--approval-context-present",
                "--require-remediation-ready",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 3
        assert "remediation preflight is not ready" in result.stderr
        report = json.loads(result.stdout)
        assert report["remediation_preflight"]["skill_granted"] is False


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


class TestLangGraphHarnessDriftCheck:
    """Regression coverage for the operator-facing harness drift checker."""

    SCRIPT = EXAMPLES / "check_langgraph_harness_drift.py"

    def test_harness_drift_check_passes(self):
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["event"] == "langgraph_harness_drift_check"
        assert report["schema_version"] == "langgraph-harness-drift-check-v1"
        assert report["status"] == "pass"
        assert report["failed"] == 0
        check_names = {check["name"] for check in report["checks"]}
        assert "pipeline_diagram_generated" in check_names
        assert "preflight_policy_safe" in check_names
        assert "harness_docs_have_no_secret_literals" in check_names
        assert "mcp_client_bundle_schema" in check_names


class TestOpenAICompatAdapter:
    """Live BYOM adapter: bounded request shape, tolerant parsing, safe failure."""

    @staticmethod
    def _adapters():
        sys.path.insert(0, str(EXAMPLES))
        try:
            import harness_adapters
        finally:
            sys.path.pop(0)
        return harness_adapters

    @staticmethod
    def _cards():
        return [{"finding_uid": "det-1", "title": "access key created", "severity": "high"}]

    def _response(self, content: str) -> bytes:
        return json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")

    def _fake_urlopen(self, monkeypatch, adapters, body: bytes, capture: dict):
        import contextlib
        import io

        @contextlib.contextmanager
        def fake_urlopen(request, timeout=None):
            capture["url"] = request.full_url
            capture["headers"] = dict(request.header_items())
            capture["body"] = json.loads(request.data.decode("utf-8"))
            capture["timeout"] = timeout
            yield io.BytesIO(body)

        monkeypatch.setattr(adapters.urllib.request, "urlopen", fake_urlopen)

    def test_sends_bounded_openai_request(self, monkeypatch):
        adapters = self._adapters()
        capture: dict = {}
        content = json.dumps(
            [
                {
                    "finding_uid": "det-1",
                    "priority": "high",
                    "recommended_action": "investigate",
                    "rationale": "new key on a build principal",
                }
            ]
        )
        self._fake_urlopen(monkeypatch, adapters, self._response(content), capture)

        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1/",
            model="gpt-4.1-mini",
            evidence_cards=self._cards(),
            api_key="test-key",
            timeout_seconds=999,
        )
        recommendations = adapter.recommendations()

        assert capture["url"] == "https://llm.example/v1/chat/completions"
        assert capture["headers"].get("Authorization") == "Bearer test-key"
        assert capture["body"]["model"] == "gpt-4.1-mini"
        assert capture["body"]["temperature"] == 0
        assert capture["timeout"] == 120  # clamped to the bounded maximum
        system_prompt = capture["body"]["messages"][0]["content"]
        assert "rank, summarize, and draft only" in system_prompt
        assert "never approve" in system_prompt
        assert recommendations == [
            {
                "finding_uid": "det-1",
                "priority": "high",
                "recommended_action": "investigate",
                "rationale": "new key on a build principal",
            }
        ]
        assert adapter.last_error is None

    def test_parses_fenced_json_and_recommendations_object(self, monkeypatch):
        adapters = self._adapters()
        payload = {
            "recommendations": [
                {
                    "finding_uid": "det-1",
                    "priority": "medium",
                    "recommended_action": "close",
                    "rationale": "benign automation",
                }
            ]
        }
        content = "```json\n" + json.dumps(payload) + "\n```"
        self._fake_urlopen(monkeypatch, adapters, self._response(content), {})

        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        assert adapter.recommendations() == payload["recommendations"]

    def test_keyless_endpoint_sends_no_auth_header(self, monkeypatch):
        adapters = self._adapters()
        capture: dict = {}
        self._fake_urlopen(monkeypatch, adapters, self._response("[]"), capture)

        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="http://127.0.0.1:11434/v1",
            model="llama3",
            evidence_cards=self._cards(),
        )
        adapter.recommendations()
        assert "Authorization" not in capture["headers"]

    def test_network_failure_degrades_to_no_candidates(self, monkeypatch):
        adapters = self._adapters()

        def fail_urlopen(request, timeout=None):
            raise adapters.urllib.error.URLError("connection refused")

        monkeypatch.setattr(adapters.urllib.request, "urlopen", fail_urlopen)
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        assert adapter.recommendations() == []
        assert "URLError" in (adapter.last_error or "")

    def test_non_json_content_degrades_to_no_candidates(self, monkeypatch):
        adapters = self._adapters()
        self._fake_urlopen(monkeypatch, adapters, self._response("I think this looks fine."), {})
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        assert adapter.recommendations() == []
        assert adapter.last_error is not None

    def test_empty_evidence_skips_the_network_entirely(self, monkeypatch):
        adapters = self._adapters()

        def explode(request, timeout=None):  # pragma: no cover - must not run
            raise AssertionError("no network call expected without evidence")

        monkeypatch.setattr(adapters.urllib.request, "urlopen", explode)
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=[],
        )
        assert adapter.recommendations() == []

    def test_selection_requires_external_mode_and_base_url(self, monkeypatch):
        adapters = self._adapters()

        offline = adapters.select_triage_adapter(
            harness_config={"mode": "deterministic_offline", "model": "m"},
            environ={"DEMO_OPENAI_BASE_URL": "https://llm.example/v1"},
            evidence_cards=self._cards(),
        )
        assert offline.adapter_id == "deterministic_fallback"

        no_url = adapters.select_triage_adapter(
            harness_config={"mode": "external_llm_optional", "model": "m"},
            environ={},
            evidence_cards=self._cards(),
        )
        assert no_url.adapter_id == "deterministic_fallback"

        live = adapters.select_triage_adapter(
            harness_config={"mode": "external_llm_optional", "model": "gpt-4.1-mini"},
            environ={
                "DEMO_OPENAI_BASE_URL": "https://llm.example/v1",
                "DEMO_OPENAI_API_KEY_ENV": "MY_KEY",
                "MY_KEY": "secret",
                "DEMO_OPENAI_TIMEOUT_SECONDS": "5",
            },
            evidence_cards=self._cards(),
        )
        assert live.adapter_id == "openai_compat_adapter"
        assert live.model == "gpt-4.1-mini"
        assert live.api_key == "secret"
        assert live.timeout_seconds == 5

    def test_fixture_adapter_still_beats_live_endpoint(self, tmp_path, monkeypatch):
        adapters = self._adapters()
        fixture = tmp_path / "fixture.json"
        fixture.write_text("[]", encoding="utf-8")
        selected = adapters.select_triage_adapter(
            harness_config={"mode": "external_llm_optional", "model": "m"},
            environ={
                "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
                "DEMO_OPENAI_BASE_URL": "https://llm.example/v1",
            },
            evidence_cards=self._cards(),
        )
        assert selected.adapter_id == "fixture_llm_adapter"

    def test_live_output_still_passes_the_schema_gate(self, monkeypatch):
        """A live adapter that emits forbidden keys is rejected downstream."""
        adapters = self._adapters()
        content = json.dumps(
            [
                {
                    "finding_uid": "det-1",
                    "priority": "high",
                    "recommended_action": "request_approval",
                    "rationale": "looks bad",
                    "approval": {"approved": True},
                }
            ]
        )
        self._fake_urlopen(monkeypatch, adapters, self._response(content), {})
        adapter = adapters.OpenAICompatTriageAdapter(
            base_url="https://llm.example/v1",
            model="m",
            evidence_cards=self._cards(),
        )
        candidate = adapter.recommendations()[0]
        fallback = {"finding_uid": "det-1", "output_hash": "abc"}
        accepted, validation = adapters.validate_adapter_recommendation(
            candidate=candidate,
            fallback=fallback,
            finding_uid="det-1",
            harness_config={"provider": "openai", "model": "m"},
            adapter_id=adapter.adapter_id,
        )
        assert validation["status"] == "rejected"
        assert validation["reason"].startswith("forbidden_output:approval")
        assert accepted == fallback


class TestModelQualityEval:
    """Model-quality mode scores adapter agreement against the golden dataset."""

    SCRIPT = EXAMPLES / "eval_langgraph_harness.py"

    def _run(self, tmp_path, env=None, extra_args=()):
        report_path = tmp_path / "model-quality.json"
        run_env = {key: value for key, value in os.environ.items() if not key.startswith("DEMO_")}
        run_env.update(env or {})
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                "--model-quality",
                "--check",
                "--output",
                str(report_path),
                *extra_args,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=run_env,
        )
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
        return result, report

    def test_default_run_agrees_with_golden_dataset(self, tmp_path):
        result, report = self._run(tmp_path)
        assert result.returncode == 0, result.stderr
        assert report["event"] == "langgraph_model_quality_eval"
        assert report["cases_total"] == 8
        assert report["agreement_rate"] == 1.0
        assert report["adapter_accepted"] >= 1
        assert report["adapter_env"] == {
            "fixture": False,
            "langchain_fixture": False,
            "live_openai_compat": False,
        }

    def test_low_quality_adapter_fails_the_gate(self, tmp_path):
        import hashlib

        # Same uid derivation the harness uses for the golden CreateAccessKey
        # event, so the schema gate accepts this low-quality recommendation.
        golden_event = {
            "source": "cloudtrail",
            "event_name": "CreateAccessKey",
            "actor_uid": "AIDAEXAMPLE",
            "resource_uid": "arn:aws:iam::111122223333:user/build-bot",
        }
        encoded = json.dumps(golden_event, sort_keys=True, separators=(",", ":")).encode()
        finding_uid = f"det-evt-{hashlib.sha256(encoded).hexdigest()[:12]}"

        fixture = tmp_path / "bad-adapter.json"
        # Valid schema, wrong triage: the gate accepts it, agreement drops.
        fixture.write_text(
            json.dumps(
                [
                    {
                        "finding_uid": finding_uid,
                        "priority": "low",
                        "recommended_action": "close",
                        "rationale": "nothing to see here",
                    }
                ]
            ),
            encoding="utf-8",
        )
        result, report = self._run(
            tmp_path,
            env={
                "DEMO_LLM_ADAPTER_FIXTURE": str(fixture),
                "DEMO_EXTERNAL_LLM_ALLOWED": "yes",
            },
        )
        assert result.returncode == 1
        assert report["adapter_env"]["fixture"] is True
        assert report["agreement_rate"] < 1.0


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
            json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()
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
