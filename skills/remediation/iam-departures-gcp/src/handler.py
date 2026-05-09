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

import sys
from pathlib import Path

_PARSER_DIR = Path(__file__).resolve().parent / "cloud_function_parser"
if str(_PARSER_DIR) not in sys.path:
    sys.path.insert(0, str(_PARSER_DIR))

from handler import main  # noqa: E402  pylint: disable=import-error,wrong-import-position

__all__ = ["main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
