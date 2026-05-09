"""Skill-name → atomic ingest skill resolver.

Same shipped tool registry the MCP wrapper uses. The router never spawns
a skill that is not in `WEBHOOK_ALLOWED_SKILLS`, even if the registry
knows about it. Default-deny so a fresh deployment can't accidentally
expose every ingest skill.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
_MCP_SRC = REPO_ROOT / "mcp-server" / "src"
if str(_MCP_SRC) not in sys.path:
    sys.path.insert(0, str(_MCP_SRC))

from tool_registry import SkillSpec, tool_map  # noqa: E402  pylint: disable=wrong-import-position


@dataclass(frozen=True)
class RouteResolution:
    found: bool
    allowed: bool
    skill: SkillSpec | None
    reason: str = ""


def _allowlist(env: dict[str, str] | None = None) -> set[str]:
    src = os.environ if env is None else env
    raw = (src.get("WEBHOOK_ALLOWED_SKILLS") or "").strip()
    if not raw:
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def resolve(
    skill_name: str,
    *,
    env: dict[str, str] | None = None,
) -> RouteResolution:
    tools = tool_map(REPO_ROOT)
    skill = tools.get(skill_name)
    if skill is None:
        return RouteResolution(
            found=False,
            allowed=False,
            skill=None,
            reason=f"unknown skill `{skill_name}`",
        )
    if skill.category != "ingestion":
        # The receiver only accepts ingest skills. Detect / remediate /
        # evaluate on a webhook surface would either skip the OCSF wire
        # contract (detect / evaluate consume OCSF, not raw webhooks) or
        # bypass HITL (remediate). Refuse explicitly.
        return RouteResolution(
            found=True,
            allowed=False,
            skill=skill,
            reason=f"skill `{skill_name}` is in category `{skill.category}`; only `ingestion` skills are routable on this surface",
        )
    if skill_name not in _allowlist(env):
        return RouteResolution(
            found=True,
            allowed=False,
            skill=skill,
            reason=f"skill `{skill_name}` is not in WEBHOOK_ALLOWED_SKILLS",
        )
    return RouteResolution(found=True, allowed=True, skill=skill)
