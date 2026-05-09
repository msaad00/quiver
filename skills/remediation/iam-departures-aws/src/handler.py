"""Top-level CLI / MCP entrypoint for `iam-departures-aws`.

The skill's destructive path lives in the deployed Step Function pipeline
(`runners/`). This module re-exports the parser's CLI `main()` so the same
skill is callable from MCP, the CLI, and CI without code changes — but
only in plan-only / dry-run mode. `--apply` is refused at the parser
boundary; deletion happens only inside the deployed runner.

Why this shim: `mcp-server/src/tool_registry.ENTRYPOINT_CANDIDATES` resolves
the first known filename under `src/`; without this top-level handler, the
registry does not see the skill, and the README's "76 shipped skills"
silently dropped to 73 callable through MCP.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The parser sub-module owns the actual CLI logic. We append its directory
# to `sys.path` rather than restructure the package: the Step Function
# deployment already imports `lambda_parser.handler` by that path, and we
# do not want to break that.
_PARSER_DIR = Path(__file__).resolve().parent / "lambda_parser"
if str(_PARSER_DIR) not in sys.path:
    sys.path.insert(0, str(_PARSER_DIR))

from handler import main  # noqa: E402  pylint: disable=import-error,wrong-import-position

__all__ = ["main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
