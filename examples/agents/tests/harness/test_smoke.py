"""Agent harness tests."""

from __future__ import annotations

import sys
from pathlib import Path

_AGENTS_DIR = Path(__file__).resolve().parents[2]
if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))

import json
import os
import subprocess
import sys

import pytest
from harness_shared import (
    EXAMPLES,
    REPO_ROOT,
    SCRIPTS,
)


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

    def test_claude_desktop_mcp_binding_documents_config(self):
        result = subprocess.run(
            [sys.executable, str(EXAMPLES / "claude_desktop_mcp_security_agent.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=REPO_ROOT,
            env={**os.environ},
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        binding = payload["claude_desktop_binding"]
        assert binding["integration"] == "claude_desktop_mcp_json"
        assert "claude_desktop_config.json" in binding["config_path"]
        assert "cloud-ai-security-skills" in binding["mcp_config"]["mcpServers"]
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
