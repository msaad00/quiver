"""Behavioral validator: import every skill entrypoint and check `main()`.

The structural validators (`validate_skill_contract.py`, `validate_skill_integrity.py`,
etc.) only check files exist and frontmatter parses. They do not catch:

  - syntax errors in entrypoints that no test imports
  - `ImportError` for a skill module that depends on a freshly-renamed shared util
  - missing `main()` function that the SKILL.md docs claim exists
  - top-level side effects that crash on import (rare but they happen)

This validator imports every supported skill entrypoint via `importlib.util`
with a unique module name (so duplicate `detect`/`ingest` filenames don't
collide), then verifies the conventional `main()` callable is present.

Run via CI on every PR. Fails closed if anything can't import.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = REPO_ROOT / "skills"

ENTRYPOINT_NAMES = (
    "ingest.py",
    "detect.py",
    "convert.py",
    "checks.py",
    "discover.py",
    "handler.py",
    "sink.py",
)


def _iter_skill_entrypoints() -> list[Path]:
    """Yield every `skills/<layer>/<name>/src/<entrypoint>.py` that exists."""
    paths: list[Path] = []
    for skill_dir in sorted(SKILLS_DIR.glob("*/*")):
        src = skill_dir / "src"
        if not src.is_dir():
            continue
        for name in ENTRYPOINT_NAMES:
            path = src / name
            if path.is_file():
                paths.append(path)
    return paths


def _module_name_for(path: Path) -> str:
    """Generate a unique module name from the skill path so multiple skills
    can each have their own `detect.py` without colliding in `sys.modules`."""
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    return "cloud_security_runtime__" + "_".join(rel.parts)


def _import_entrypoint(path: Path) -> tuple[bool, str | None]:
    name = _module_name_for(path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return False, "could not build importlib spec"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - any import-time failure is a finding
        return False, f"{type(exc).__name__}: {exc}"

    if not hasattr(module, "main"):
        return False, "entrypoint exposes no `main()` function"
    if not callable(module.main):
        return False, "`main` exists but is not callable"
    return True, None


def main() -> int:
    entrypoints = _iter_skill_entrypoints()
    if not entrypoints:
        print("Skill runtime validation failed: no entrypoints discovered", file=sys.stderr)
        return 1

    # Make `from skills._shared.* import ...` resolvable for skills that rely
    # on it. Mirrors the per-skill `sys.path.insert(REPO_ROOT, ...)` block.
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    failures: list[tuple[Path, str]] = []
    for path in entrypoints:
        ok, error = _import_entrypoint(path)
        if not ok:
            failures.append((path, error or "unknown"))

    if failures:
        print("Skill runtime validation failed:", file=sys.stderr)
        for path, error in failures:
            rel = path.relative_to(REPO_ROOT)
            print(f"  - {rel}: {error}", file=sys.stderr)
        return 1

    print(f"Skill runtime validation passed: imported {len(entrypoints)} entrypoints.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
