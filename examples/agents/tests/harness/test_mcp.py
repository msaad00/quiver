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
    SCHEMAS,
    schema_errors,
)


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
            "claude-desktop",
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
        assert schema_errors(schema, payload) == []


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
