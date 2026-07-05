"""Top-level CLI / MCP entrypoint for `iam-departures-gcp`.

The skill's destructive path lives in the deployed Cloud Function pipeline
(`runners/`). This module re-exports the parser's CLI `main()` so the same
skill is callable from MCP, the CLI, and CI without code changes — but
only in plan-only / dry-run mode (the parser sets
`IAM_DEPARTURES_GCP_SKIP_EXISTENCE_CHECK` when `--dry-run` is passed). The
GCP IAM mutations are the worker function's responsibility.

Why this shim: `mcp-server/src/tool_registry.ENTRYPOINT_CANDIDATES` resolves
the first known filename under `src/`; without this top-level handler, the
registry did not see the skill, and the SKILL.md frontmatter that already
listed `mcp` in `execution_modes` was a half-truth.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_PARSER_PATH = Path(__file__).resolve().parent / "cloud_function_parser" / "handler.py"
_spec = importlib.util.spec_from_file_location("iam_departures_gcp_parser", _PARSER_PATH)
assert _spec and _spec.loader, f"could not load {_PARSER_PATH}"
_parser_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("iam_departures_gcp_parser", _parser_mod)
_spec.loader.exec_module(_parser_mod)


def main(argv: list[str] | None = None) -> int:
    return int(_parser_mod.main(argv))


__all__ = ["main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
