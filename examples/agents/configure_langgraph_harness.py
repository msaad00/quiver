"""Generate an operator-owned LangGraph SOC harness profile.

The generator writes configuration only. It does not collect credentials,
approval tokens, OAuth callbacks, or cloud secrets.

Run:

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

from langgraph_security_graph import (
    ALLOWED_SKILLS_READ_ONLY_LIST,
    ALLOWED_SKILLS_REMEDIATION,
    DEFAULT_MODEL_POLICY,
    DEFAULT_TOKEN_BUDGET,
)

HarnessRole = Literal["readonly-soc", "analyst-triage", "dry-run-remediation"]

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
}

PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")


def _parse_cloud_hint(values: list[str]) -> dict[str, str]:
    hints: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("cloud hints must use provider=hint")
        provider, hint = value.split("=", 1)
        provider = provider.strip().lower()
        hint = hint.strip()
        if not provider or not hint:
            raise ValueError("cloud hints require a provider and hint")
        hints[provider] = hint
    if hints:
        return hints
    return {
        "aws": "AWS_PROFILE=prod-readonly",
        "snowflake": "snowflake-cli auth login --authenticator externalbrowser",
    }


def _profile_allowed_skills(role: HarnessRole, extra_skills: list[str]) -> list[str]:
    allowed = list(ALLOWED_SKILLS_READ_ONLY_LIST)
    known = {*ALLOWED_SKILLS_READ_ONLY_LIST, ALLOWED_SKILLS_REMEDIATION}
    include_remediation = bool(ROLE_DEFAULTS[role]["include_remediation"])
    if include_remediation:
        allowed.append(ALLOWED_SKILLS_REMEDIATION)
    for skill in extra_skills:
        if skill not in known:
            raise ValueError(f"unknown example skill: {skill}")
        if skill not in allowed:
            allowed.append(skill)
    return allowed


def build_profile(args: argparse.Namespace) -> dict[str, Any]:
    role: HarnessRole = args.role
    if not PROFILE_ID_RE.match(args.profile_id):
        raise ValueError("profile_id must match ^[a-z0-9][a-z0-9-]{1,63}$")
    allowed_skills = _profile_allowed_skills(role, args.allowed_skill)
    llm_mode = "external_llm_optional" if args.external_llm else "deterministic_offline"
    session_id = args.session_id or f"{args.profile_id}-session"
    user_id = args.user_id or args.email.split("@", 1)[0]
    model_tier = "small" if args.external_llm else "tiny"
    return {
        "profile_id": args.profile_id,
        "description": args.description or ROLE_DEFAULTS[role]["description"],
        "allowed_skills": allowed_skills,
        "caller_context": {
            "user_id": user_id,
            "email": args.email,
            "session_id": session_id,
            "roles": args.roles or ROLE_DEFAULTS[role]["roles"],
            "allowed_skills": allowed_skills,
        },
        "cloud_identity_hints": _parse_cloud_hint(args.cloud_hint),
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
        "approval_policy": {
            "remediation_requires_approval_context": True,
            "approval_source": args.approval_source,
            "min_approvers": args.min_approvers,
        },
        "runtime": {
            "langgraph_runtime_optional": True,
            "dry_run_default": True,
            "apply_supported": False,
        },
    }


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
    parser.add_argument("--cloud-hint", action="append", default=[], help="provider=credential-hint")
    parser.add_argument("--allowed-skill", action="append", default=[], help="additional known example skill")
    parser.add_argument("--external-llm", action="store_true")
    parser.add_argument("--llm-provider", default="deterministic-local")
    parser.add_argument("--llm-model", default="policy-bounded-triage-v1")
    parser.add_argument("--approval-source", default="operator_idp_or_ticketing_system")
    parser.add_argument("--min-approvers", type=int, default=1)
    parser.add_argument("--output-profile", type=Path, required=True)
    parser.add_argument("--output-env", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        profile = build_profile(args)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    args.output_profile.parent.mkdir(parents=True, exist_ok=True)
    args.output_profile.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_dotenv(
        profile_path=args.output_profile,
        env_path=args.output_env,
        external_llm=args.external_llm,
        provider=args.llm_provider,
        model=args.llm_model,
    )
    print(json.dumps({
        "profile": str(args.output_profile),
        "env": str(args.output_env),
        "profile_id": profile["profile_id"],
        "role": args.role,
        "allowed_skills": profile["allowed_skills"],
        "approval_required": True,
        "secrets_written": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
