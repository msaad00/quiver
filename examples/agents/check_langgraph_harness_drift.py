"""Check that the LangGraph SOC harness docs and contracts match the code.

This command is intentionally offline. It does not load credentials, call a
model, execute cloud APIs, or run remediation. It compares generated artifacts
and profile/schema contracts against the runnable harness surfaces.

Run:

    python examples/agents/check_langgraph_harness_drift.py
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness_runtime import HarnessRunConfig, run_harness_summary
from langgraph_security_graph import load_harness_profile, pipeline_contract, preview_agent_policy
from render_langgraph_pipeline_diagram import render_mermaid

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = REPO_ROOT / "examples" / "agents"
SCHEMAS = EXAMPLES / "schemas"
PROFILES = EXAMPLES / "harness_profiles"
DIAGRAM = REPO_ROOT / "docs" / "diagrams" / "langgraph-agent-harness.mmd"
HARNESS_DOC = REPO_ROOT / "docs" / "HARNESS.md"
EXAMPLES_README = EXAMPLES / "README.md"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

EXPECTED_SCHEMAS = [
    SCHEMAS / "harness_profile.schema.json",
    SCHEMAS / "llm_adapter_recommendations.schema.json",
    SCHEMAS / "pipeline_contract.schema.json",
    SCHEMAS / "agent_policy.schema.json",
    SCHEMAS / "checkpoint.schema.json",
    SCHEMAS / "eval_report.schema.json",
]

REQUIRED_DOC_TOKENS = [
    "inspect_langgraph_harness.py",
    "run_langgraph_harness.py",
    "execute_langgraph_mcp_plan.py",
    "eval_langgraph_harness.py --check",
    "render_langgraph_pipeline_diagram.py",
    "check_langgraph_harness_drift.py",
]

SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9_]{36,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(
        r"(?i)\b(?:openai_api_key|anthropic_api_key|github_token|"
        r"snowflake_password|secret_access_key)\b\s*[:=]\s*[\"'][^\"']{4,}[\"']"
    ),
]

JSON_TYPE_MAP = {
    "array": list,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "object": dict,
    "string": str,
}


@dataclass(frozen=True)
class DriftCheck:
    name: str
    passed: bool
    details: Any

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": "pass" if self.passed else "fail",
            "details": self.details,
        }


def _schema_errors(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
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
        for key in sorted(required - set(value)):
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


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _check_schema_documents() -> DriftCheck:
    failures: list[str] = []
    for schema_path in EXPECTED_SCHEMAS:
        if not schema_path.exists():
            failures.append(f"{schema_path.relative_to(REPO_ROOT)} missing")
            continue
        schema = _load_json(schema_path)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            failures.append(f"{schema_path.name}: unsupported $schema")
        if schema.get("type") != "object":
            failures.append(f"{schema_path.name}: root type must be object")
        if schema.get("additionalProperties") is not False:
            failures.append(f"{schema_path.name}: root must be closed")
    return DriftCheck(
        "schema_documents_closed",
        not failures,
        "all expected schemas are closed draft 2020-12 objects" if not failures else failures,
    )


def _check_pipeline_contract() -> DriftCheck:
    schema = _load_json(SCHEMAS / "pipeline_contract.schema.json")
    contract = pipeline_contract()
    errors = _schema_errors(schema, contract)
    node_names = {node["node"] for node in contract.get("nodes", [])}
    for edge in contract.get("edges", []):
        if edge.get("source") not in node_names or edge.get("target") not in node_names:
            errors.append(f"edge references unknown node: {edge}")
    return DriftCheck(
        "pipeline_contract_schema",
        not errors,
        {
            "nodes": len(contract.get("nodes", [])),
            "edges": len(contract.get("edges", [])),
            "errors": errors,
        },
    )


def _check_diagram(update_diagram: bool) -> DriftCheck:
    rendered = render_mermaid() + "\n"
    existing = DIAGRAM.read_text(encoding="utf-8") if DIAGRAM.exists() else ""
    if existing != rendered and update_diagram:
        DIAGRAM.parent.mkdir(parents=True, exist_ok=True)
        DIAGRAM.write_text(rendered, encoding="utf-8")
        existing = rendered
    return DriftCheck(
        "pipeline_diagram_generated",
        existing == rendered,
        {
            "path": str(DIAGRAM.relative_to(REPO_ROOT)),
            "source": "pipeline_contract()",
            "updated": update_diagram and existing == rendered,
        },
    )


def _check_profiles() -> DriftCheck:
    schema = _load_json(SCHEMAS / "harness_profile.schema.json")
    failures: list[str] = []
    profile_names: list[str] = []
    for profile_path in sorted(PROFILES.glob("*.json")):
        profile_names.append(profile_path.name)
        profile = _load_json(profile_path)
        errors = _schema_errors(schema, profile)
        if errors:
            failures.extend(f"{profile_path.name}: {error}" for error in errors)
            continue
        if not set(profile["caller_context"]["allowed_skills"]).issubset(profile["allowed_skills"]):
            failures.append(f"{profile_path.name}: caller_context skills exceed profile allowlist")
        if profile["runtime"].get("dry_run_default") is not True:
            failures.append(f"{profile_path.name}: dry_run_default must stay true")
        if profile["runtime"].get("apply_supported", False) is not False:
            failures.append(f"{profile_path.name}: apply_supported must stay false")
        data_source = profile["runtime"].get("security_data_source") or {}
        if data_source.get("mode") not in {"raw_ingest", "security_lake_replay"}:
            failures.append(f"{profile_path.name}: security_data_source mode is invalid")
        if (
            data_source.get("mode") == "raw_ingest"
            and data_source.get("source_skill") != "ingest-cloudtrail-ocsf"
        ):
            failures.append(f"{profile_path.name}: raw_ingest must use ingest-cloudtrail-ocsf")
        if data_source.get("mode") == "security_lake_replay":
            if not str(data_source.get("source_skill", "")).startswith("source-"):
                failures.append(f"{profile_path.name}: lake replay must use a source-* query skill")
            if data_source.get("backend") not in {"snowflake", "clickhouse", "databricks"}:
                failures.append(
                    f"{profile_path.name}: lake replay backend must be a shipped warehouse source"
                )
        mcp_execution = profile["runtime"].get("mcp_execution") or {}
        if mcp_execution.get("transport") != "mcp_stdio_jsonrpc":
            failures.append(f"{profile_path.name}: MCP execution transport must be stdio JSON-RPC")
        if (
            mcp_execution.get("mode") == "plan_only"
            and mcp_execution.get("execute_planned_calls") is not False
        ):
            failures.append(f"{profile_path.name}: plan_only must not execute planned MCP calls")
        if mcp_execution.get("allow_write_calls") is not False:
            failures.append(f"{profile_path.name}: write-capable MCP execution must stay disabled")
        if mcp_execution.get("max_calls", 0) < 0:
            failures.append(f"{profile_path.name}: MCP max_calls must be non-negative")
        if profile["approval_policy"].get("remediation_requires_approval_context") is not True:
            failures.append(f"{profile_path.name}: remediation must require approval context")
        if profile["token_budget"].get("fallback_on_budget_exceeded") is not True:
            failures.append(f"{profile_path.name}: token overage must fall back closed")
        if profile["token_budget"].get("model_tier") not in profile["model_policy"].get(
            "allowed_model_tiers",
            [],
        ):
            failures.append(f"{profile_path.name}: token model tier not allowed by model policy")
    return DriftCheck(
        "harness_profiles_safe",
        not failures,
        {"profiles": profile_names, "errors": failures},
    )


def _check_preflight_policy() -> DriftCheck:
    failures: list[str] = []
    for profile_path in sorted(PROFILES.glob("*.json")):
        profile = load_harness_profile(str(profile_path))
        without_approval = preview_agent_policy(profile, approval_context_present=False)
        with_approval = preview_agent_policy(profile, approval_context_present=True)
        for report in [without_approval, with_approval]:
            if report.get("secrets_loaded") is not False:
                failures.append(f"{profile_path.name}: preflight loaded secrets")
            if report.get("cloud_calls_made") is not False:
                failures.append(f"{profile_path.name}: preflight made cloud calls")
            if report["remediation_preflight"].get("apply_supported") is not False:
                failures.append(f"{profile_path.name}: preflight reports apply support")
            triage = next(
                entry
                for entry in report["agent_policy"]["entries"]
                if entry["agent_id"] == "triage-agent"
            )
            if triage.get("effective_skill_grants") != []:
                failures.append(f"{profile_path.name}: triage-agent has tool grants")
        if without_approval["remediation_preflight"].get("would_plan_dry_run") is not False:
            failures.append(f"{profile_path.name}: remediation ready without approval context")
    return DriftCheck(
        "preflight_policy_safe",
        not failures,
        "preflight stays metadata-only and approval-gated" if not failures else failures,
    )


def _check_runtime_wrapper() -> DriftCheck:
    summary = run_harness_summary(
        HarnessRunConfig(profile_path=PROFILES / "readonly-soc.json"),
    )
    errors: list[str] = []
    if summary["harness_runtime"]["validation_status"] != "pass":
        errors.append("runtime wrapper validation did not pass")
    if summary["trace"][0] != "ingest" or summary["trace"][-1] != "writeback":
        errors.append("runtime trace must start at ingest and end at writeback")
    if summary["harness"].get("mode") not in {
        "deterministic_offline",
        "external_llm_metadata",
    }:
        errors.append("unexpected harness mode")
    return DriftCheck(
        "runtime_wrapper_validates",
        not errors,
        {
            "profile_id": summary["profile"]["profile_id"],
            "execution_mode": summary["harness_runtime"]["execution_mode"],
            "errors": errors,
        },
    )


def _check_docs_wired() -> DriftCheck:
    docs = {
        str(HARNESS_DOC.relative_to(REPO_ROOT)): HARNESS_DOC.read_text(encoding="utf-8"),
        str(EXAMPLES_README.relative_to(REPO_ROOT)): EXAMPLES_README.read_text(encoding="utf-8"),
        str(CI_WORKFLOW.relative_to(REPO_ROOT)): CI_WORKFLOW.read_text(encoding="utf-8"),
    }
    failures: list[str] = []
    for token in REQUIRED_DOC_TOKENS:
        if not any(token in text for text in docs.values()):
            failures.append(f"missing reference: {token}")
    return DriftCheck(
        "docs_and_ci_reference_harness_commands",
        not failures,
        "docs and CI reference harness commands" if not failures else failures,
    )


def _harness_secret_scan_paths() -> list[Path]:
    paths = [
        HARNESS_DOC,
        EXAMPLES_README,
        REPO_ROOT / "docs" / "AGENT_QUICKSTART.md",
        EXAMPLES / "configure_langgraph_harness.py",
        EXAMPLES / "inspect_langgraph_harness.py",
        EXAMPLES / "run_langgraph_harness.py",
        EXAMPLES / "execute_langgraph_mcp_plan.py",
        EXAMPLES / "sdk_agent_common.py",
        EXAMPLES / "anthropic_sdk_security_agent.py",
        EXAMPLES / "openai_sdk_security_agent.py",
        EXAMPLES / "langchain_mcp_security_agent.py",
        EXAMPLES / "cursor_mcp_security_agent.py",
        EXAMPLES / "windsurf_mcp_security_agent.py",
        EXAMPLES / "cortex_mcp_security_agent.py",
        EXAMPLES / "harness_adapters.py",
        EXAMPLES / "harness_mcp_transport.py",
        *sorted(PROFILES.glob("*.json")),
        *sorted((REPO_ROOT / "presets").glob("*.json")),
    ]
    return [path for path in paths if path.is_file()]


def _check_no_harness_secret_literals() -> DriftCheck:
    findings: list[str] = []
    for path in _harness_secret_scan_paths():
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "re.compile(" in line or "SECRET_PATTERNS" in line:
                continue
            for pattern in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    findings.append(
                        f"{path.relative_to(REPO_ROOT)}:{line_no}: {match.group(0)[:32]}"
                    )
    return DriftCheck(
        "harness_docs_have_no_secret_literals",
        not findings,
        "no PAT/API-key/password literals in harness docs, profiles, or presets"
        if not findings
        else findings,
    )


def run_checks(*, update_diagram: bool = False) -> list[DriftCheck]:
    return [
        _check_schema_documents(),
        _check_pipeline_contract(),
        _check_diagram(update_diagram),
        _check_profiles(),
        _check_preflight_policy(),
        _check_runtime_wrapper(),
        _check_docs_wired(),
        _check_no_harness_secret_literals(),
    ]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update-diagram",
        action="store_true",
        help="Rewrite docs/diagrams/langgraph-agent-harness.mmd if it drifted.",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    checks = run_checks(update_diagram=args.update_diagram)
    failed = [check for check in checks if not check.passed]
    report = {
        "event": "langgraph_harness_drift_check",
        "schema_version": "langgraph-harness-drift-check-v1",
        "status": "fail" if failed else "pass",
        "checks_total": len(checks),
        "passed": len(checks) - len(failed),
        "failed": len(failed),
        "checks": [check.to_json() for check in checks],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
