"""Top-level CLI / MCP entrypoint for `iam-departures-azure-entra`.

The skill's destructive path lives in the deployed Function App
(`runners/`). This module re-exports the parser's CLI `main()` so the same
skill is callable from MCP, the CLI, and CI without code changes — but
only in plan-only / dry-run mode. The Microsoft Graph `disable user` call
is the function worker's responsibility; the MCP/CLI surface stays
read-only and consults only the static decision tree.

Why this shim: `mcp-server/src/tool_registry.ENTRYPOINT_CANDIDATES` resolves
the first known filename under `src/`; without this top-level handler, the
registry did not see the skill, and the README's "76 shipped skills"
silently dropped to 73 callable through MCP.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PARSER_DIR = Path(__file__).resolve().parent / "function_parser"
if str(_PARSER_DIR) not in sys.path:
    sys.path.insert(0, str(_PARSER_DIR))

from handler import main  # noqa: E402  pylint: disable=import-error,wrong-import-position

__all__ = ["main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
