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

import importlib.util
import sys
from pathlib import Path

# The parser sub-module owns the actual CLI logic. We load it via
# importlib.util by absolute path rather than restructure the package: the
# Step Function deployment already imports `lambda_parser.handler` by that
# path, and we do not want to break that.
_PARSER_PATH = Path(__file__).resolve().parent / "lambda_parser" / "handler.py"
_spec = importlib.util.spec_from_file_location("iam_departures_aws_parser", _PARSER_PATH)
assert _spec and _spec.loader, f"could not load {_PARSER_PATH}"
_parser_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("iam_departures_aws_parser", _parser_mod)
_spec.loader.exec_module(_parser_mod)


def main(argv: list[str] | None = None) -> int:
    return int(_parser_mod.main(argv))


__all__ = ["main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
