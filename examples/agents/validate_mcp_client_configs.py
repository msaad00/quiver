"""Validate an emitted MCP client config bundle against the repo schema.

Offline operator tool — does not spawn MCP or call cloud APIs.

Run:

    python examples/agents/validate_mcp_client_configs.py artifacts/mcp-client-configs.json
    python examples/agents/emit_mcp_client_configs.py | python examples/agents/validate_mcp_client_configs.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from harness_schema import schema_errors

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "mcp_client_config_bundle.schema.json"

SECRET_MARKERS = (
    "ghp_",
    "github_pat_",
    "sk-",
    "AKIA",
    "-----BEGIN",
)


def _load_bundle(path: Path | None) -> dict[str, Any]:
    raw = sys.stdin.read() if path is None else path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("bundle must be a JSON object")
    return payload


def validate_bundle(payload: dict[str, Any], *, schema_path: Path = SCHEMA_PATH) -> list[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return schema_errors(schema, payload)


def _secret_literal_errors(payload: dict[str, Any]) -> list[str]:
    text = json.dumps(payload)
    findings: list[str] = []
    for marker in SECRET_MARKERS:
        if marker in text:
            findings.append(f"bundle text contains suspicious marker: {marker}")
    return findings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bundle",
        nargs="?",
        type=Path,
        help="Bundle JSON path (stdin when omitted)",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=SCHEMA_PATH,
        help="Schema path (default: examples/agents/schemas/mcp_client_config_bundle.schema.json)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        bundle = _load_bundle(args.bundle)
        errors = validate_bundle(bundle, schema_path=args.schema)
        errors.extend(_secret_literal_errors(bundle))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    if errors:
        for error in errors:
            sys.stderr.write(f"{error}\n")
        return 1
    print(
        json.dumps(
            {
                "schema_version": bundle.get("schema_version"),
                "profile_id": bundle.get("profile_id"),
                "clients": sorted((bundle.get("clients") or {}).keys()),
                "status": "valid",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
