"""Lock-in test: the three iam-departures remediation skills ship with
top-level entrypoints so the MCP registry sees them.

History: between the 04-28 audit and 05-09 audit the registry returned
73/76 supported skills because `iam-departures-{aws,azure-entra,gcp}` had
no entrypoint matching `tool_registry.ENTRYPOINT_CANDIDATES`. The
README's "76 shipped skills" was inaccurate against the MCP surface.

This test fails closed if any iam-departures skill regresses to that
state.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TR_PATH = REPO_ROOT / "mcp-server" / "src" / "tool_registry.py"
spec = importlib.util.spec_from_file_location("cloud_security_tool_registry_test", TR_PATH)
assert spec and spec.loader
TR = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = TR
spec.loader.exec_module(TR)


_IAM_DEPARTURE_REMEDIATIONS = (
    "iam-departures-aws",
    "iam-departures-azure-entra",
    "iam-departures-gcp",
)


def test_all_iam_departures_skills_are_supported():
    tools = TR.tool_map()
    for name in _IAM_DEPARTURE_REMEDIATIONS:
        assert name in tools, f"{name} missing from MCP tool map"
        assert tools[name].entrypoint is not None
        assert tools[name].entrypoint.name == "handler.py"


def test_total_supported_count_matches_discovered():
    """The repo invariant: every shipped SKILL.md must resolve to an
    entrypoint. If `discover_skills` ever exceeds `supported_skills` the
    README count is overstating what the MCP surface can call."""
    discovered = TR.discover_skills()
    supported = TR.supported_skills()
    assert len(discovered) == len(supported), (
        f"{len(discovered) - len(supported)} skill(s) ship SKILL.md but no "
        f"recognised entrypoint: "
        f"{sorted(s.name for s in discovered if not s.supported)}"
    )


def test_iam_departures_skills_advertise_mcp_execution_mode():
    """SKILL.md frontmatter is the source of truth for execution surfaces.
    All three remediation skills now have a top-level CLI entrypoint, so
    `mcp` belongs in `execution_modes`."""
    tools = TR.tool_map()
    for name in _IAM_DEPARTURE_REMEDIATIONS:
        assert "mcp" in tools[name].execution_modes, (
            f"{name}: execution_modes={tools[name].execution_modes!r} should include 'mcp'"
        )
