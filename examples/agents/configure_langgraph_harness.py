"""Generate an operator-owned LangGraph SOC harness profile.

The generator writes configuration only. It does not collect credentials,
approval tokens, OAuth callbacks, or cloud secrets.

Run:

    python examples/agents/configure_langgraph_harness.py \
      --role sdk-cspm \
      --preset presets/preset-cspm-readonly.json \
      --profile-id acme-sdk-cspm \
      --email sdk-agent@example.com \
      --output-profile artifacts/acme-sdk-cspm.json \
      --output-env artifacts/acme-sdk-cspm.env \
      --emit-mcp-configs artifacts/mcp-client-configs.json

    python examples/agents/configure_langgraph_harness.py \
      --role analyst-triage \
      --profile-id acme-soc-triage \
      --email analyst@example.com \
      --output-profile artifacts/acme-soc-triage.json \
      --output-env artifacts/acme-soc-triage.env
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Literal

from emit_mcp_client_configs import emit_client_configs
from langgraph_security_graph import (
    ALLOWED_SKILLS_READ_ONLY_LIST,
    ALLOWED_SKILLS_REMEDIATION,
    DEFAULT_MODEL_POLICY,
    DEFAULT_TOKEN_BUDGET,
)
from sdk_agent_common import apply_preset_to_profile, load_preset

HarnessRole = Literal["readonly-soc", "analyst-triage", "dry-run-remediation", "sdk-cspm"]
LAKE_SOURCE_SKILLS = {
    "snowflake": "source-snowflake-query",
    "clickhouse": "source-clickhouse-query",
    "databricks": "source-databricks-query",
}

SDK_CSPM_ALLOWED_SKILLS = [
    "cspm-aws-cis-benchmark",
    "cspm-gcp-cis-benchmark",
    "cspm-azure-cis-benchmark",
    "detect-lateral-movement",
    "detect-privilege-escalation-k8s",
    "convert-ocsf-to-sarif",
]
SDK_CSPM_CALLER_SKILLS = [
    "cspm-aws-cis-benchmark",
    "detect-lateral-movement",
    "convert-ocsf-to-sarif",
]

ROLE_DEFAULTS: dict[HarnessRole, dict[str, Any]] = {
    "readonly-soc": {
        "description": "Read-only SOC replay and triage profile.",
        "roles": "soc_analyst",
        "include_remediation": False,
    },
    "analyst-triage": {
        "description": "SOC analyst triage profile with bounded optional model drafting.",
        "roles": "security_analyst",
        "include_remediation": False,
    },
    "dry-run-remediation": {
        "description": "HITL-gated dry-run remediation planning profile.",
        "roles": "security_engineer",
        "include_remediation": True,
    },
    "sdk-cspm": {
        "description": (
            "Anthropic, OpenAI, LangChain, and IDE MCP examples (Cursor, Windsurf, "
            "Cortex, Codex, Zed): read-only CSPM + detect triage via MCP stdio."
        ),
        "roles": "security_engineer",
        "include_remediation": False,
        "allowed_skills": SDK_CSPM_ALLOWED_SKILLS,
        "caller_allowed_skills": SDK_CSPM_CALLER_SKILLS,
        "cloud_identity_hints": {
            "aws": "AWS_PROFILE=prod-readonly",
            "gcp": "gcloud auth login",
            "azure": "az login",
        },
        "mcp_execution_mode": "operator_stdio",
        "mcp_max_calls": 4,
        "agent_roster_only_triage": True,
    },
}

PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
SECRET_FIELD_RE = re.compile(
    r"(?i)(password|passwd|pwd|pat|personal[_-]?access[_-]?token|api[_-]?key|"
    r"secret|private[_-]?key|access[_-]?key|session[_-]?token|bearer)"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|"
    r"sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def _assert_no_secret_material(payload: Any, *, path: str) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(key)
            if SECRET_FIELD_RE.search(key_text):
                raise ValueError(
                    f"{path}.{key_text} must not contain passwords, PATs, tokens, or secrets"
                )
            _assert_no_secret_material(value, path=f"{path}.{key_text}")
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            _assert_no_secret_material(value, path=f"{path}[{index}]")
    elif isinstance(payload, str) and (
        SECRET_FIELD_RE.search(payload) or SECRET_VALUE_RE.search(payload)
    ):
        raise ValueError(f"{path} must not contain password, PAT, token, or secret material")


def _parse_cloud_hint(values: list[str], *, role: HarnessRole) -> dict[str, str]:
    hints: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("cloud hints must use provider=hint")
        provider, hint = value.split("=", 1)
        provider = provider.strip().lower()
        hint = hint.strip()
        if not provider or not hint:
            raise ValueError("cloud hints require a provider and hint")
        _assert_no_secret_material({provider: hint}, path="cloud_identity_hints")
        hints[provider] = hint
    if hints:
        return hints
    role_hints = ROLE_DEFAULTS[role].get("cloud_identity_hints")
    if isinstance(role_hints, dict):
        return dict(role_hints)
    return {
        "aws": "AWS_PROFILE=prod-readonly",
        "snowflake": "snowflake-cli auth login --authenticator externalbrowser",
    }


def _profile_allowed_skills(role: HarnessRole, extra_skills: list[str]) -> list[str]:
    role_skills = ROLE_DEFAULTS[role].get("allowed_skills")
    allowed = list(role_skills) if role_skills else list(ALLOWED_SKILLS_READ_ONLY_LIST)
    known = {*ALLOWED_SKILLS_READ_ONLY_LIST, ALLOWED_SKILLS_REMEDIATION, *SDK_CSPM_ALLOWED_SKILLS}
    include_remediation = bool(ROLE_DEFAULTS[role]["include_remediation"])
    if include_remediation and ALLOWED_SKILLS_REMEDIATION not in allowed:
        allowed.append(ALLOWED_SKILLS_REMEDIATION)
    for skill in extra_skills:
        if skill not in known:
            raise ValueError(f"unknown example skill: {skill}")
        if skill not in allowed:
            allowed.append(skill)
    return allowed


def _caller_allowed_skills(role: HarnessRole, allowed_skills: list[str]) -> list[str]:
    role_caller = ROLE_DEFAULTS[role].get("caller_allowed_skills")
    if not role_caller:
        return list(allowed_skills)
    allowed_set = set(allowed_skills)
    return [skill for skill in role_caller if skill in allowed_set]


def _security_data_source(args: argparse.Namespace) -> dict[str, str]:
    if args.data_source_mode == "raw-ingest":
        return {
            "mode": "raw_ingest",
            "backend": "inline_events",
            "source_skill": "ingest-cloudtrail-ocsf",
            "records_format": "raw_vendor",
            "query": "",
        }
    source_skill = LAKE_SOURCE_SKILLS[args.lake_backend]
    query = args.lake_query or "SELECT payload FROM security.events_sink LIMIT 100"
    _assert_no_secret_material({"lake_query": query}, path="runtime.security_data_source")
    return {
        "mode": "security_lake_replay",
        "backend": args.lake_backend,
        "source_skill": source_skill,
        "records_format": args.lake_records_format,
        "query": query,
    }


def build_profile(args: argparse.Namespace) -> dict[str, Any]:
    role: HarnessRole = args.role
    if not PROFILE_ID_RE.match(args.profile_id):
        raise ValueError("profile_id must match ^[a-z0-9][a-z0-9-]{1,63}$")
    role_defaults = ROLE_DEFAULTS[role]
    mcp_execution_mode = args.mcp_execution_mode
    mcp_max_calls = args.mcp_max_calls
    if mcp_execution_mode == "plan_only" and role_defaults.get("mcp_execution_mode"):
        mcp_execution_mode = str(role_defaults["mcp_execution_mode"])
    if mcp_max_calls == 0 and role_defaults.get("mcp_max_calls") is not None:
        mcp_max_calls = int(role_defaults["mcp_max_calls"])
    if mcp_max_calls < 0:
        raise ValueError("--mcp-max-calls must be 0 or greater")
    allowed_skills = _profile_allowed_skills(role, args.allowed_skill)
    caller_skills = _caller_allowed_skills(role, allowed_skills)
    llm_mode = "external_llm_optional" if args.external_llm else "deterministic_offline"
    session_id = args.session_id or f"{args.profile_id}-session"
    user_id = args.user_id or args.email.split("@", 1)[0]
    model_tier = "small" if args.external_llm else "tiny"
    agent_roster = [
        {
            "agent_id": "triage-agent",
            "model_tier": model_tier,
            "privilege_boundary": "no_tool_writes",
            "skill_scope": [],
        },
    ]
    if not role_defaults.get("agent_roster_only_triage"):
        agent_roster.append(
            {
                "agent_id": "remediation-planner",
                "requires_human_approval": True,
                "privilege_boundary": "dry_run_write_planning",
                "skill_scope": [ALLOWED_SKILLS_REMEDIATION]
                if role_defaults["include_remediation"]
                else [],
            }
        )
    profile = {
        "profile_id": args.profile_id,
        "description": args.description or role_defaults["description"],
        "allowed_skills": allowed_skills,
        "caller_context": {
            "user_id": user_id,
            "email": args.email,
            "session_id": session_id,
            "roles": args.roles or role_defaults["roles"],
            "allowed_skills": caller_skills,
        },
        "cloud_identity_hints": _parse_cloud_hint(args.cloud_hint, role=role),
        "llm": {
            "mode": llm_mode,
            "provider": args.llm_provider,
            "model": args.llm_model,
        },
        "token_budget": {
            **DEFAULT_TOKEN_BUDGET,
            "model_tier": model_tier,
        },
        "model_policy": {
            **DEFAULT_MODEL_POLICY,
            "default_model_tier": model_tier,
            "allowed_model_tiers": ["tiny", "small"] if args.external_llm else ["tiny"],
            "models": {
                **DEFAULT_MODEL_POLICY["models"],
                model_tier: {
                    "provider": args.llm_provider,
                    "model": args.llm_model,
                },
            },
        },
        "agent_roster": agent_roster,
        "approval_policy": {
            "remediation_requires_approval_context": True,
            "approval_source": args.approval_source,
            "min_approvers": args.min_approvers,
        },
        "runtime": {
            "langgraph_runtime_optional": True,
            "dry_run_default": True,
            "apply_supported": False,
            "security_data_source": _security_data_source(args),
            "mcp_execution": {
                "mode": mcp_execution_mode,
                "transport": "mcp_stdio_jsonrpc",
                "execute_planned_calls": mcp_execution_mode == "operator_stdio",
                "allow_write_calls": False,
                "max_calls": mcp_max_calls,
            },
        },
    }
    _assert_no_secret_material(profile, path="profile")
    return profile


def write_dotenv(
    *,
    profile_path: Path,
    env_path: Path,
    external_llm: bool,
    provider: str,
    model: str,
) -> None:
    lines = [
        "# Generated by examples/agents/configure_langgraph_harness.py.",
        "# This file points at the operator-owned profile; provider/model policy lives in JSON.",
        f"CLOUD_SECURITY_HARNESS_PROFILE={profile_path}",
        f"DEMO_HARNESS_PROFILE={profile_path}",
        f"DEMO_EXTERNAL_LLM_ALLOWED={'yes' if external_llm else 'no'}",
        f"# profile_model={provider}:{model}",
        "# DEMO_APPROVE is intentionally omitted; set it only after human approval.",
    ]
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=sorted(ROLE_DEFAULTS), default="readonly-soc")
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--description")
    parser.add_argument("--email", required=True)
    parser.add_argument("--user-id")
    parser.add_argument("--session-id")
    parser.add_argument("--roles")
    parser.add_argument(
        "--cloud-hint", action="append", default=[], help="provider=credential-hint"
    )
    parser.add_argument(
        "--allowed-skill", action="append", default=[], help="additional known example skill"
    )
    parser.add_argument(
        "--preset",
        help="workflow preset JSON path (intersects role allowlist; fail closed on empty)",
    )
    parser.add_argument(
        "--data-source-mode",
        choices=["raw-ingest", "security-lake-replay"],
        default="raw-ingest",
        help="Whether this harness should ingest raw events or replay an existing security data lake",
    )
    parser.add_argument(
        "--lake-backend",
        choices=sorted(LAKE_SOURCE_SKILLS),
        default="snowflake",
        help="Security lake backend when --data-source-mode=security-lake-replay",
    )
    parser.add_argument(
        "--lake-records-format",
        choices=["raw_vendor", "ocsf"],
        default="ocsf",
        help="Shape returned by the lake replay query",
    )
    parser.add_argument(
        "--lake-query", help="Read-only SELECT/WITH/SHOW/DESCRIBE query for lake replay"
    )
    parser.add_argument(
        "--mcp-execution-mode",
        choices=["plan_only", "operator_stdio"],
        default="plan_only",
        help="Plan MCP calls only, or mark planned read-only calls eligible for an operator-owned stdio transport",
    )
    parser.add_argument(
        "--mcp-max-calls",
        type=int,
        default=0,
        help="Maximum planned MCP calls an operator-owned transport may execute; 0 means no harness cap",
    )
    parser.add_argument("--external-llm", action="store_true")
    parser.add_argument("--llm-provider", default="deterministic-local")
    parser.add_argument("--llm-model", default="policy-bounded-triage-v1")
    parser.add_argument("--approval-source", default="operator_idp_or_ticketing_system")
    parser.add_argument("--min-approvers", type=int, default=1)
    parser.add_argument("--output-profile", type=Path, required=True)
    parser.add_argument("--output-env", type=Path, required=True)
    parser.add_argument(
        "--emit-mcp-configs",
        type=Path,
        help="Optional path to write IDE MCP client config bundle JSON (sdk-cspm and other roles)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        profile = build_profile(args)
        if args.preset:
            preset = load_preset(args.preset)
            if preset is None:
                raise ValueError("preset path must be non-empty")
            profile = apply_preset_to_profile(profile, preset)
            _assert_no_secret_material(profile, path="profile")
    except (ValueError, FileNotFoundError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    args.output_profile.parent.mkdir(parents=True, exist_ok=True)
    args.output_profile.write_text(
        json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_dotenv(
        profile_path=args.output_profile,
        env_path=args.output_env,
        external_llm=args.external_llm,
        provider=args.llm_provider,
        model=args.llm_model,
    )
    mcp_configs_path = None
    if args.emit_mcp_configs:
        bundle = {
            "schema_version": "mcp-client-config-bundle-v1",
            "profile_id": profile["profile_id"],
            "clients": emit_client_configs(profile),
        }
        args.emit_mcp_configs.parent.mkdir(parents=True, exist_ok=True)
        args.emit_mcp_configs.write_text(
            json.dumps(bundle, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        mcp_configs_path = str(args.emit_mcp_configs)
    print(
        json.dumps(
            {
                "profile": str(args.output_profile),
                "env": str(args.output_env),
                "mcp_client_configs": mcp_configs_path,
                "profile_id": profile["profile_id"],
                "role": args.role,
                "allowed_skills": profile["allowed_skills"],
                "preset_applied": profile.get("preset_applied"),
                "approval_required": True,
                "secrets_written": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
