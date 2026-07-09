from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)

ENTRYPOINT_CANDIDATES = (
    "src/ingest.py",
    "src/detect.py",
    "src/convert.py",
    "src/checks.py",
    "src/discover.py",
    "src/handler.py",
    "src/sink.py",
)


MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 900

MCP_TOOL_SCHEMA_FILENAME = "mcp_tool_schema.json"
WRAPPER_SCHEMA_PROPERTY_KEYS = frozenset(
    {"input", "args", "output_format", "_caller_context", "_approval_context"}
)


@dataclass(frozen=True)
class SkillSpec:
    name: str
    description: str
    category: str
    capability: str
    skill_dir: Path
    entrypoint: Path | None
    approval_model: str
    execution_modes: tuple[str, ...]
    side_effects: tuple[str, ...]
    input_formats: tuple[str, ...]
    output_formats: tuple[str, ...]
    network_egress: tuple[str, ...]
    caller_roles: tuple[str, ...]
    approver_roles: tuple[str, ...]
    min_approvers: int | None
    mcp_timeout_seconds: int | None
    worker_mode: bool = False

    @property
    def supported(self) -> bool:
        return self.entrypoint is not None

    @property
    def read_only(self) -> bool:
        return self.capability == "read-only"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def iter_skill_dirs(root: Path | None = None) -> list[Path]:
    base = (root or repo_root()) / "skills"
    return sorted(path.parent for path in base.glob("*/*/SKILL.md"))


def _extract_frontmatter(skill_md: Path) -> str:
    text = skill_md.read_text()
    match = FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError(f"{skill_md} missing YAML frontmatter")
    return match.group(1)


def _flatten_value(value: Any) -> str:
    """Render a YAML scalar/list/dict back into the string shape the rest of the
    registry consumes. Lists are joined with commas (matches `_parse_modes`),
    folded multi-line scalars collapse into a single space-separated string.
    """
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_flatten_value(item) for item in value if item not in (None, ""))
    if isinstance(value, dict):
        return ", ".join(f"{k}={_flatten_value(v)}" for k, v in value.items())
    if isinstance(value, bool):
        return "true" if value else "false"
    return " ".join(str(value).split())


def _parse_frontmatter(frontmatter: str) -> dict[str, str]:
    """Parse SKILL.md frontmatter using PyYAML.

    Historically this was a hand-rolled splitter that failed on quoted values
    containing colons and on standard YAML constructs. `yaml.safe_load` handles
    the full subset we use; `_flatten_value` collapses scalars/lists into the
    string shape the rest of the registry already expects.
    """
    raw = yaml.safe_load(frontmatter)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"SKILL.md frontmatter must parse to a mapping, got {type(raw).__name__}")
    return {str(key): _flatten_value(value) for key, value in raw.items()}


# Agent-bom trust-axis "capability" values are layer verbs (ingest,
# detect, ...). They are unrelated to the read/write axis the MCP tool
# registry historically used, so when the SKILL.md value is a verb we
# fall back to the path-derived heuristic instead of treating it as a
# write hint.
_TRUST_CAPABILITY_VERBS = frozenset(
    {"ingest", "detect", "discover", "evaluate", "view", "output", "remediate", "source"}
)


def _derive_capability(skill_dir: Path, metadata: dict[str, str]) -> str:
    declared = metadata.get("capability") or ""
    if declared and declared not in _TRUST_CAPABILITY_VERBS:
        return declared
    category = skill_dir.parent.name
    if category == "remediation" or skill_dir.name.startswith("remediate-"):
        return "write-remediation"
    if skill_dir.name.startswith("sink-"):
        return "write-sink"
    if skill_dir.name.startswith("runner-"):
        return "write-runner"
    return "read-only"


def _parse_modes(raw_value: str | None) -> tuple[str, ...]:
    if not raw_value:
        return ()
    return tuple(part.strip() for part in raw_value.split(",") if part.strip())


def _resolve_entrypoint(skill_dir: Path) -> Path | None:
    for candidate in ENTRYPOINT_CANDIDATES:
        path = skill_dir / candidate
        if path.exists():
            return path
    return None


def discover_skills(root: Path | None = None) -> list[SkillSpec]:
    base = root or repo_root()
    specs: list[SkillSpec] = []
    for skill_dir in iter_skill_dirs(base):
        metadata = _parse_frontmatter(_extract_frontmatter(skill_dir / "SKILL.md"))
        specs.append(
            SkillSpec(
                name=metadata["name"],
                description=metadata["description"],
                category=skill_dir.parent.name,
                capability=_derive_capability(skill_dir, metadata),
                skill_dir=skill_dir,
                entrypoint=_resolve_entrypoint(skill_dir),
                approval_model=metadata.get("approval_model", ""),
                execution_modes=_parse_modes(metadata.get("execution_modes")),
                side_effects=_parse_modes(metadata.get("side_effects")),
                input_formats=_parse_modes(metadata.get("input_formats")),
                output_formats=_parse_modes(metadata.get("output_formats")),
                network_egress=_parse_modes(metadata.get("network_egress")),
                caller_roles=_parse_modes(metadata.get("caller_roles")),
                approver_roles=_parse_modes(metadata.get("approver_roles")),
                min_approvers=_parse_min_approvers(metadata.get("min_approvers"), skill_dir),
                mcp_timeout_seconds=_parse_mcp_timeout(
                    metadata.get("mcp_timeout_seconds"), skill_dir
                ),
                worker_mode=_parse_bool(metadata.get("worker_mode")),
            )
        )
    return specs


def _parse_bool(raw: str | None) -> bool:
    if raw is None:
        return False
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


# Hard-coded list of evaluation-layer skills wired to the worker
# harness today. Kept in sync with `worker_pool.SUPPORTED_SKILL_NAMES`
# and the `__main__` blocks in each skill's `checks.py`.
WORKER_MODE_SKILL_NAMES: frozenset[str] = frozenset(
    {
        "cspm-aws-cis-benchmark",
        "cspm-gcp-cis-benchmark",
        "cspm-azure-cis-benchmark",
        "k8s-security-benchmark",
        "container-security",
    }
)


def supports_worker_mode(skill: SkillSpec) -> bool:
    """A skill supports the persistent-worker pool when its frontmatter
    declares `worker_mode: true` OR its name is on the hard-coded list
    of evaluation-layer skills wired to `_shared/worker_harness.py`.

    Both are required to land safely — the registry-level flag and the
    in-tree harness wiring move in lockstep, so a typo in one place
    can't silently disable warming."""
    if skill.entrypoint is None:
        return False
    if getattr(skill, "worker_mode", False):
        return True
    return skill.name in WORKER_MODE_SKILL_NAMES


def _parse_min_approvers(raw: str | None, skill_dir: Path) -> int | None:
    """Defensive parse for `min_approvers`. Missing / empty -> None.

    Surfaces a clear error if a SKILL.md author writes a non-integer value.
    Without this, a malformed value crashed `discover_skills` at import time
    and made the whole MCP server fail to start.
    """
    if raw is None or not str(raw).strip():
        return None
    try:
        return int(str(raw).strip())
    except ValueError as exc:
        raise ValueError(
            f"{skill_dir}/SKILL.md: min_approvers must be an integer, got {raw!r}"
        ) from exc


def _parse_mcp_timeout(raw: str | None, skill_dir: Path) -> int | None:
    if raw is None or not raw.strip():
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{skill_dir}/SKILL.md: mcp_timeout_seconds must be an integer, got {raw!r}"
        ) from exc
    if value < MIN_TIMEOUT_SECONDS or value > MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"{skill_dir}/SKILL.md: mcp_timeout_seconds must be between "
            f"{MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}, got {value}"
        )
    return value


def supported_skills(root: Path | None = None) -> list[SkillSpec]:
    return [skill for skill in discover_skills(root) if skill.supported]


def skill_mcp_schema_path(skill_dir: Path) -> Path:
    return skill_dir / MCP_TOOL_SCHEMA_FILENAME


def load_skill_mcp_schema(skill_dir: Path) -> dict[str, object] | None:
    path = skill_mcp_schema_path(skill_dir)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: mcp_tool_schema.json must be a JSON object")
    return payload


def _merge_schema_properties(
    base_properties: dict[str, object],
    overlay_properties: dict[str, object],
) -> dict[str, object]:
    merged = dict(base_properties)
    for key, spec in overlay_properties.items():
        if key in WRAPPER_SCHEMA_PROPERTY_KEYS:
            continue
        merged[key] = spec
    return merged


def merge_tool_input_schema(
    base: dict[str, object],
    overlay: dict[str, object] | None,
) -> dict[str, object]:
    if not overlay:
        return base
    merged: dict[str, object] = dict(base)
    overlay_props = overlay.get("properties")
    if isinstance(overlay_props, dict) and overlay_props:
        base_props = merged.get("properties")
        if not isinstance(base_props, dict):
            base_props = {}
        merged["properties"] = _merge_schema_properties(base_props, overlay_props)
    if "examples" in overlay:
        merged["examples"] = overlay["examples"]
    if "description" in overlay and overlay["description"]:
        merged["description"] = overlay["description"]
    return merged


def _cli_args_for_property(value: object, prop_schema: dict[str, object]) -> list[str]:
    cli_flag = prop_schema.get("x-cli-flag")
    cli_style = prop_schema.get("x-cli-style", "flag")
    prop_type = prop_schema.get("type")

    if cli_style == "positional":
        if value is None:
            return []
        return [str(value)]

    if prop_type == "boolean":
        if value is True:
            if cli_flag:
                cli_value = prop_schema.get("x-cli-value")
                if cli_value is not None:
                    return [str(cli_flag), str(cli_value)]
                return [str(cli_flag)]
        return []

    if cli_flag and value is not None:
        return [str(cli_flag), str(value)]
    return []


def expand_skill_parameters(
    skill: SkillSpec,
    request_args: dict[str, object],
) -> tuple[dict[str, object], list[str]]:
    """Translate typed per-skill schema properties into CLI args.

    Skills may ship ``mcp_tool_schema.json`` with ``x-cli-flag`` /
    ``x-cli-style`` hints. Wrapper-reserved keys are left untouched.
    """
    overlay = load_skill_mcp_schema(skill.skill_dir)
    if not overlay:
        return request_args, []

    overlay_props = overlay.get("properties")
    if not isinstance(overlay_props, dict):
        return request_args, []

    remaining = dict(request_args)
    extra_args: list[str] = []
    positional_args: list[str] = []

    for key, prop_schema in overlay_props.items():
        if key in WRAPPER_SCHEMA_PROPERTY_KEYS or key not in remaining:
            continue
        if not isinstance(prop_schema, dict):
            continue
        value = remaining.pop(key)
        cli_args = _cli_args_for_property(value, prop_schema)
        if prop_schema.get("x-cli-style") == "positional":
            positional_args.extend(cli_args)
        else:
            extra_args.extend(cli_args)

    return remaining, positional_args + extra_args


def tool_input_schema(skill: SkillSpec) -> dict[str, object]:
    description = "Inline stdin payload for the skill. Use this for JSON or JSONL filters."
    if skill.entrypoint and skill.entrypoint.name == "checks.py":
        description = (
            "Optional stdin payload. Most benchmark/check skills use explicit CLI args instead."
        )
    properties: dict[str, object] = {
        "input": {
            "type": "string",
            "description": description,
        },
        "args": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Explicit CLI arguments forwarded to the fixed skill entrypoint.",
        },
        "_caller_context": {
            "type": "object",
            "description": "Optional wrapper-supplied caller identity context for audit propagation.",
            "properties": {
                "user_id": {"type": "string"},
                "email": {"type": "string"},
                "session_id": {"type": "string"},
                "roles": {"type": "array", "items": {"type": "string"}},
                "allowed_skills": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional per-caller skill allowlist; intersects with operator allowlists.",
                },
            },
            # Strict: a typo on `approver_email` -> `approver_emial` lands in
            # the audit event as an empty approver list and the wrapper still
            # computes min_approvers against the typo'd field. Reject unknown
            # keys at the schema boundary instead.
            "additionalProperties": False,
        },
        "_approval_context": {
            "type": "object",
            "description": (
                "Optional wrapper-supplied approval context for HITL-gated tools. "
                "For multi-approver actions, populate `approver_ids` or `approver_emails` "
                "with one entry per distinct approver."
            ),
            "properties": {
                "approver_id": {"type": "string"},
                "approver_email": {"type": "string"},
                "ticket_id": {"type": "string"},
                "approval_timestamp": {"type": "string"},
                "approver_ids": {"type": "array", "items": {"type": "string"}},
                "approver_emails": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        },
    }
    if skill.output_formats:
        properties["output_format"] = {
            "type": "string",
            "enum": list(skill.output_formats),
            "description": "Optional output rendering mode supported by this skill.",
        }
    base_schema = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    return merge_tool_input_schema(base_schema, load_skill_mcp_schema(skill.skill_dir))


def tool_definition(skill: SkillSpec) -> dict[str, object]:
    """Build a tool definition for `tools/list`.

    The MCP spec lets servers attach arbitrary keys under `annotations`. The
    SKILL.md frontmatter carries structured fields (approval model, execution
    modes, side effects, network egress, caller / approver roles, min
    approvers) that an agent should be able to filter on programmatically
    rather than parse out of a free-text description. Those fields live in
    `annotations` from this PR forward; the description stays short. Legacy
    `readOnlyHint` / `destructiveHint` / `idempotentHint` are kept for
    spec-compliant clients that already read them.
    """
    description = (
        skill.description.strip()
        if skill.description
        else f"Skill `{skill.name}` ({skill.category} layer)."
    )
    tool: dict[str, object] = {
        "name": skill.name,
        "description": description,
        "inputSchema": tool_input_schema(skill),
        "annotations": {
            # Spec-defined hints — kept for clients that already filter on them.
            "readOnlyHint": skill.read_only,
            "destructiveHint": not skill.read_only,
            "idempotentHint": skill.read_only,
            # Repo-defined structured metadata. Documented in
            # docs/MCP_AUDIT_CONTRACT.md so tool-using clients can filter
            # without reading prose.
            "category": skill.category,
            "capability": skill.capability,
            "approvalModel": skill.approval_model or "none",
            "executionModes": list(skill.execution_modes),
            "sideEffects": list(skill.side_effects),
            "inputFormats": list(skill.input_formats),
            "outputFormats": list(skill.output_formats),
            "networkEgress": list(skill.network_egress),
            "callerRoles": list(skill.caller_roles),
            "approverRoles": list(skill.approver_roles),
            "minApprovers": skill.min_approvers if skill.min_approvers is not None else 0,
        },
    }
    return tool


def tool_map(root: Path | None = None) -> dict[str, SkillSpec]:
    return {skill.name: skill for skill in supported_skills(root)}


def build_command(skill: SkillSpec, args: list[str], output_format: str | None = None) -> list[str]:
    if not skill.entrypoint:
        raise ValueError(f"skill {skill.name} has no supported entrypoint")
    command = [sys.executable, str(skill.entrypoint), *args]
    if output_format:
        if output_format not in skill.output_formats:
            raise ValueError(
                f"skill `{skill.name}` does not support output_format `{output_format}`"
            )
        if "--output-format" not in args:
            command.extend(["--output-format", output_format])
    return command
