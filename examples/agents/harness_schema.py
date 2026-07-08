"""Shared JSON-schema validation helpers for harness artifacts."""

from __future__ import annotations

import json
import re
from typing import Any

JSON_TYPE_MAP = {
    "array": list,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "object": dict,
    "string": str,
}


def schema_errors(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        type_errors = [schema_errors({**schema, "type": item}, value, path) for item in schema_type]
        if any(not item for item in type_errors):
            return []
        return type_errors[0]
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
