from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "mcp-server" / "src" / "tool_registry.py"
SPEC = importlib.util.spec_from_file_location("cloud_security_tool_registry", REGISTRY_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

build_command = MODULE.build_command
discover_skills = MODULE.discover_skills
supported_skills = MODULE.supported_skills
tool_definition = MODULE.tool_definition
tool_map = MODULE.tool_map


class TestDiscovery:
    def test_discovers_all_skills(self):
        skills = discover_skills(REPO_ROOT)
        assert len(skills) >= 35
        assert {skill.name for skill in skills} >= {
            "source-s3-select",
            "source-databricks-query",
            "source-snowflake-query",
            "sink-s3-jsonl",
            "sink-snowflake-jsonl",
            "sink-clickhouse-jsonl",
            "ingest-cloudtrail-ocsf",
            "ingest-entra-directory-audit-ocsf",
            "ingest-okta-system-log-ocsf",
            "ingest-google-workspace-login-ocsf",
            "detect-lateral-movement",
            "detect-okta-mfa-fatigue",
            "detect-entra-credential-addition",
            "detect-entra-role-grant-escalation",
            "detect-google-workspace-suspicious-login",
            "cspm-aws-cis-benchmark",
            "iam-departures-aws",
            "ingest-vpc-flow-logs-gcp-ocsf",
            "ingest-nsg-flow-logs-azure-ocsf",
            "ingest-gcp-scc-ocsf",
            "ingest-azure-defender-for-cloud-ocsf",
            "discover-ai-bom",
            "discover-control-evidence",
            "discover-cloud-control-evidence",
        }

    def test_marks_remediation_skill_without_cli_entrypoint_as_unsupported(self):
        skills = {skill.name: skill for skill in discover_skills(REPO_ROOT)}
        assert skills["iam-departures-aws"].supported is False
        assert skills["iam-departures-aws"].capability == "write-remediation"

    def test_supports_standalone_handler_based_remediation_skill(self):
        skills = {skill.name: skill for skill in discover_skills(REPO_ROOT)}
        assert skills["remediate-mcp-tool-quarantine"].supported is True
        assert skills["remediate-mcp-tool-quarantine"].entrypoint is not None
        assert skills["remediate-mcp-tool-quarantine"].entrypoint.name == "handler.py"

    def test_supported_tools_include_ingest_detect_and_evaluate(self):
        tools = tool_map(REPO_ROOT)
        assert "source-s3-select" in tools
        assert "source-databricks-query" in tools
        assert "source-snowflake-query" in tools
        assert "sink-s3-jsonl" in tools
        assert "sink-snowflake-jsonl" in tools
        assert "sink-clickhouse-jsonl" in tools
        assert "ingest-cloudtrail-ocsf" in tools
        assert "ingest-entra-directory-audit-ocsf" in tools
        assert "ingest-okta-system-log-ocsf" in tools
        assert "ingest-google-workspace-login-ocsf" in tools
        assert "detect-lateral-movement" in tools
        assert "detect-okta-mfa-fatigue" in tools
        assert "detect-entra-credential-addition" in tools
        assert "detect-entra-role-grant-escalation" in tools
        assert "detect-google-workspace-suspicious-login" in tools
        assert "model-serving-security" in tools
        assert "discover-ai-bom" in tools
        assert "discover-control-evidence" in tools
        assert "discover-cloud-control-evidence" in tools
        assert "remediate-mcp-tool-quarantine" in tools
        assert "iam-departures-aws" not in tools


class TestToolDefinition:
    def test_tool_definition_comes_from_skill_metadata(self):
        skill = tool_map(REPO_ROOT)["ingest-cloudtrail-ocsf"]
        tool = tool_definition(skill)
        assert tool["name"] == "ingest-cloudtrail-ocsf"
        assert "CloudTrail" in tool["description"]
        assert tool["annotations"]["readOnlyHint"] is True
        assert tool["inputSchema"]["properties"]["args"]["type"] == "array"
        assert tool["inputSchema"]["properties"]["output_format"]["enum"] == ["ocsf", "native"]
        assert "Approval model: none." in tool["description"]
        assert "Execution modes: jit, ci, mcp, persistent." in tool["description"]
        assert "Side effects: none." in tool["description"]
        assert "Network egress: none." in tool["description"]
        assert "Caller roles: unspecified." in tool["description"]
        assert "Approver roles: unspecified." in tool["description"]
        assert "Min approvers: unspecified." in tool["description"]
        assert skill.input_formats == ("raw",)
        assert skill.output_formats == ("ocsf", "native")
        assert skill.approval_model == "none"
        assert skill.execution_modes == ("jit", "ci", "mcp", "persistent")
        assert skill.side_effects == ("none",)
        assert skill.network_egress == ()
        assert skill.caller_roles == ()
        assert skill.approver_roles == ()
        assert skill.min_approvers is None

    def test_unsupported_write_skill_rbac_metadata_is_parsed(self):
        remediation = next(skill for skill in discover_skills(REPO_ROOT) if skill.name == "iam-departures-aws")
        assert remediation.network_egress == (
            "api.workday.com",
            "*.snowflakecomputing.com",
            "*.databricks.com",
            "*.clickhouse.cloud",
        )
        assert remediation.caller_roles == ("security_engineer", "incident_responder")
        assert remediation.approver_roles == ("security_lead", "cis_officer")
        assert remediation.min_approvers == 1

    def test_tool_input_schema_exposes_wrapper_context_fields(self):
        skill = tool_map(REPO_ROOT)["ingest-cloudtrail-ocsf"]
        schema = tool_definition(skill)["inputSchema"]
        assert "_caller_context" in schema["properties"]
        assert "allowed_skills" in schema["properties"]["_caller_context"]["properties"]
        assert "_approval_context" in schema["properties"]

    def test_mcp_tool_quarantine_requires_two_approvers_in_metadata(self):
        remediation = next(
            skill for skill in discover_skills(REPO_ROOT) if skill.name == "remediate-mcp-tool-quarantine"
        )
        assert remediation.min_approvers == 2

    def test_source_snowflake_query_exposes_raw_output(self):
        skill = tool_map(REPO_ROOT)["source-snowflake-query"]
        tool = tool_definition(skill)
        assert tool["inputSchema"]["properties"]["output_format"]["enum"] == ["raw"]
        assert skill.output_formats == ("raw",)
        assert skill.network_egress == ("*.snowflakecomputing.com",)

    def test_source_s3_select_exposes_raw_output(self):
        skill = tool_map(REPO_ROOT)["source-s3-select"]
        tool = tool_definition(skill)
        assert tool["inputSchema"]["properties"]["output_format"]["enum"] == ["raw"]
        assert skill.output_formats == ("raw",)
        assert skill.network_egress == ("*.amazonaws.com",)

    def test_source_databricks_query_exposes_raw_output(self):
        skill = tool_map(REPO_ROOT)["source-databricks-query"]
        tool = tool_definition(skill)
        assert tool["inputSchema"]["properties"]["output_format"]["enum"] == ["raw"]
        assert skill.output_formats == ("raw",)
        assert skill.network_egress == ("*.databricks.com",)

    def test_sink_snowflake_jsonl_exposes_write_metadata(self):
        skill = tool_map(REPO_ROOT)["sink-snowflake-jsonl"]
        tool = tool_definition(skill)
        assert tool["annotations"]["readOnlyHint"] is False
        assert tool["annotations"]["destructiveHint"] is True
        assert tool["inputSchema"]["properties"]["output_format"]["enum"] == ["native"]
        assert skill.output_formats == ("native",)
        assert skill.capability == "write-sink"
        assert skill.approver_roles == ("security_lead", "data_platform_owner")

    def test_sink_s3_jsonl_exposes_write_metadata(self):
        skill = tool_map(REPO_ROOT)["sink-s3-jsonl"]
        tool = tool_definition(skill)
        assert tool["annotations"]["readOnlyHint"] is False
        assert tool["annotations"]["destructiveHint"] is True
        assert tool["inputSchema"]["properties"]["output_format"]["enum"] == ["native"]
        assert skill.output_formats == ("native",)
        assert skill.capability == "write-sink"
        assert skill.network_egress == ("*.amazonaws.com",)

    def test_sink_clickhouse_jsonl_exposes_write_metadata(self):
        skill = tool_map(REPO_ROOT)["sink-clickhouse-jsonl"]
        tool = tool_definition(skill)
        assert tool["annotations"]["readOnlyHint"] is False
        assert tool["annotations"]["destructiveHint"] is True
        assert tool["inputSchema"]["properties"]["output_format"]["enum"] == ["native"]
        assert skill.output_formats == ("native",)
        assert skill.capability == "write-sink"
        assert skill.network_egress == ("*.clickhouse.cloud",)

    def test_build_command_uses_fixed_entrypoint(self):
        skill = tool_map(REPO_ROOT)["detect-lateral-movement"]
        command = build_command(skill, ["--output", "findings.jsonl"])
        assert command[1].endswith("skills/detection/detect-lateral-movement/src/detect.py")
        assert command[-2:] == ["--output", "findings.jsonl"]

    def test_build_command_appends_output_format_when_requested(self):
        skill = tool_map(REPO_ROOT)["ingest-cloudtrail-ocsf"]
        command = build_command(skill, [], output_format="native")
        assert command[-2:] == ["--output-format", "native"]


class TestMcpTimeoutParsing:
    def test_missing_value_returns_none(self):
        assert MODULE._parse_mcp_timeout(None, Path("/fake")) is None

    def test_empty_value_returns_none(self):
        assert MODULE._parse_mcp_timeout("", Path("/fake")) is None
        assert MODULE._parse_mcp_timeout("   ", Path("/fake")) is None

    def test_integer_value_parses(self):
        assert MODULE._parse_mcp_timeout("120", Path("/fake")) == 120

    def test_non_integer_value_errors(self):
        try:
            MODULE._parse_mcp_timeout("forever", Path("/fake"))
        except ValueError as exc:
            assert "must be an integer" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_out_of_range_value_errors(self):
        try:
            MODULE._parse_mcp_timeout("0", Path("/fake"))
        except ValueError as exc:
            assert "between 1 and 900" in str(exc)
        else:
            raise AssertionError("expected ValueError")

        try:
            MODULE._parse_mcp_timeout("9999", Path("/fake"))
        except ValueError as exc:
            assert "between 1 and 900" in str(exc)
        else:
            raise AssertionError("expected ValueError")

    def test_default_shipped_skills_have_no_override(self):
        for skill in discover_skills(REPO_ROOT):
            assert skill.mcp_timeout_seconds is None, (
                f"{skill.name} ships an mcp_timeout_seconds override; "
                "make sure its SKILL.md declares the value explicitly and "
                "that this test is updated to allowlist it"
            )


class TestFrontmatterParsing:
    def test_parses_quoted_value_with_colon(self):
        frontmatter = (
            'name: example-skill\n'
            'description: "Detect: suspicious behavior in foo:bar streams"\n'
            'license: Apache-2.0\n'
        )
        data = MODULE._parse_frontmatter(frontmatter)
        assert data["description"] == "Detect: suspicious behavior in foo:bar streams"
        assert data["name"] == "example-skill"

    def test_parses_block_scalar_description(self):
        frontmatter = (
            'name: block-scalar-skill\n'
            'description: >-\n'
            '  this description spans\n'
            '  multiple wrapped lines\n'
            'license: Apache-2.0\n'
        )
        data = MODULE._parse_frontmatter(frontmatter)
        assert "multiple wrapped lines" in data["description"]
        assert data["name"] == "block-scalar-skill"

    def test_parses_list_value_into_comma_string(self):
        frontmatter = (
            'name: list-skill\n'
            'execution_modes:\n'
            '  - jit\n'
            '  - mcp\n'
            '  - ci\n'
        )
        data = MODULE._parse_frontmatter(frontmatter)
        assert data["execution_modes"] == "jit, mcp, ci"

    def test_rejects_non_mapping_frontmatter(self):
        try:
            MODULE._parse_frontmatter("- just\n- a\n- list\n")
        except ValueError as exc:
            assert "must parse to a mapping" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestMinApproversParsing:
    def test_missing_value_returns_none(self):
        assert MODULE._parse_min_approvers(None, Path("/fake")) is None

    def test_empty_value_returns_none(self):
        assert MODULE._parse_min_approvers("", Path("/fake")) is None
        assert MODULE._parse_min_approvers("   ", Path("/fake")) is None

    def test_integer_value_parses(self):
        assert MODULE._parse_min_approvers("2", Path("/fake")) == 2
        assert MODULE._parse_min_approvers("0", Path("/fake")) == 0

    def test_non_integer_value_errors_with_skill_path(self):
        try:
            MODULE._parse_min_approvers("two", Path("/fake/skill"))
        except ValueError as exc:
            assert "min_approvers must be an integer" in str(exc)
            assert "/fake/skill" in str(exc)
        else:
            raise AssertionError("expected ValueError")
