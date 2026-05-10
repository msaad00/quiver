"""Per-skill pytest conftest: isolate this skill's src/ from sibling skills."""

from __future__ import annotations

import sys
from pathlib import Path

_SIBLING_MODULE_NAMES = ("ingest", "detect", "checks", "convert", "discover", "handler")

_TESTS_DIR = Path(__file__).resolve().parent
_SRC_DIR = _TESTS_DIR.parent / "src"

for _name in _SIBLING_MODULE_NAMES:
    sys.modules.pop(_name, None)

sys.path[:] = [p for p in sys.path if not p.endswith("/src")]
sys.path.insert(0, str(_SRC_DIR))
