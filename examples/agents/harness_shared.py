"""Shared fixtures and helpers for agent harness tests."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
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
    EXAMPLES / "claude_desktop_mcp_security_agent.py",
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


def schema_errors(schema: dict, value, path: str = "$") -> list[str]:
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
                errors.extend(schema_errors(item_schema, item, f"{path}[{index}]"))

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
                errors.extend(schema_errors(additional, value[key], f"{path}.{key}"))
        for key, child_schema in properties.items():
            if key in value:
                errors.extend(schema_errors(child_schema, value[key], f"{path}.{key}"))

    return errors


def render_fixture(payload, replacements: dict[str, str]):
    if isinstance(payload, str):
        rendered = payload
        for key, value in replacements.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", value)
        return rendered
    if isinstance(payload, list):
        return [render_fixture(item, replacements) for item in payload]
    if isinstance(payload, dict):
        return {key: render_fixture(value, replacements) for key, value in payload.items()}
    return payload
