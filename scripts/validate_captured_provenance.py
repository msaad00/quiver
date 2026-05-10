"""CI: enforce the provenance contract for captured fixtures.

Sibling of `validate_golden_ocsf.py`. Where that validator proves the OCSF
schema is honoured, this one proves the *origin* is honoured: every file
under `skills/detection-engineering/captured/` must be (a) listed in the
manifest, (b) under a permissive licence, (c) flagged as a real capture
(`synthetic_seeded: false`), and (d) consumed by an existing detector skill.

Synthetic files belong under `skills/detection-engineering/golden/`. The
captured/ contract is intentionally narrow so PR descriptions and release
notes can keep "captured" and "synthetic" claims separable.

Invoked from CI as:

    python scripts/validate_captured_provenance.py

Exit code:
    0 — every captured fixture is fully provenanced
    1 — at least one provenance rule is violated; offending entries listed
        on stderr.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).resolve().parent.parent
CAPTURED_DIR = ROOT / "skills" / "detection-engineering" / "captured"
DETECTOR_DIR = ROOT / "skills" / "detection"
MANIFEST_PATH = CAPTURED_DIR / "MANIFEST.yaml"

# README.md and MANIFEST.yaml are the only non-fixture files allowed to live
# in the captured/ directory.
NON_FIXTURE_FILES = frozenset({"README.md", "MANIFEST.yaml"})

# License allowlist. Permissive only; copyleft (GPL/AGPL/LGPL) and
# proprietary/unknown licences are rejected by design.
ALLOWED_LICENSES = frozenset(
    {
        "Apache-2.0",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC0-1.0",
        "CC-BY-4.0",
    }
)

REQUIRED_KEYS = (
    "path",
    "origin",
    "license",
    "capture_window_utc",
    "attack_pattern",
    "consuming_detector",
    "synthetic_seeded",
)


def _iter_fixture_files() -> Iterable[Path]:
    if not CAPTURED_DIR.is_dir():
        return []
    return sorted(
        p
        for p in CAPTURED_DIR.iterdir()
        if p.is_file() and p.name not in NON_FIXTURE_FILES and not p.name.startswith(".")
    )


def _load_manifest() -> list[dict[str, Any]]:
    if not MANIFEST_PATH.is_file():
        raise FileNotFoundError(
            f"captured/MANIFEST.yaml is missing at {MANIFEST_PATH}. "
            "Every captured fixture must be declared there."
        )
    with MANIFEST_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    fixtures = data.get("fixtures") or []
    if not isinstance(fixtures, list):
        raise ValueError(
            "captured/MANIFEST.yaml: top-level `fixtures` must be a list."
        )
    return fixtures


def _validate_entry(entry: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    path = entry.get("path", "<missing path>")

    for key in REQUIRED_KEYS:
        if key not in entry:
            violations.append(f"{path}: missing required key `{key}`")

    license_value = entry.get("license")
    if license_value is not None and license_value not in ALLOWED_LICENSES:
        violations.append(
            f"{path}: license `{license_value}` is not in the permissive "
            f"allowlist {sorted(ALLOWED_LICENSES)}. Copyleft, proprietary, and "
            "unknown licences are rejected on purpose."
        )

    synthetic = entry.get("synthetic_seeded")
    if synthetic is True:
        violations.append(
            f"{path}: synthetic_seeded=true is not allowed under captured/. "
            "Move this fixture to skills/detection-engineering/golden/."
        )
    elif synthetic is None:
        # already captured by REQUIRED_KEYS check; do not double-report.
        pass
    elif not isinstance(synthetic, bool):
        violations.append(
            f"{path}: synthetic_seeded must be a boolean, got "
            f"{type(synthetic).__name__}."
        )

    detector = entry.get("consuming_detector")
    if detector:
        detector_path = DETECTOR_DIR / str(detector)
        if not (detector_path / "SKILL.md").is_file():
            violations.append(
                f"{path}: consuming_detector `{detector}` does not exist at "
                f"skills/detection/{detector}/. Captured fixtures must be "
                "wired to a real shipped detector."
            )

    origin = entry.get("origin")
    if origin is not None and not (
        isinstance(origin, str)
        and (
            origin.startswith("http://")
            or origin.startswith("https://")
            or origin.startswith("CITATION:")
        )
    ):
        violations.append(
            f"{path}: origin must be an http(s) URL or `CITATION:<paper>`. "
            "An origin no one can open today is not a citation."
        )

    return violations


def main() -> int:
    violations: list[str] = []

    try:
        manifest_entries = _load_manifest()
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    declared_paths: set[str] = set()
    for entry in manifest_entries:
        if not isinstance(entry, dict):
            violations.append(
                f"manifest entry is not a mapping: {entry!r}"
            )
            continue
        path = entry.get("path")
        if isinstance(path, str):
            declared_paths.add(path)
        violations.extend(_validate_entry(entry))

    fixture_files = list(_iter_fixture_files())
    fixture_names = {p.name for p in fixture_files}

    for fname in sorted(fixture_names - declared_paths):
        violations.append(
            f"{fname}: file present under captured/ but not in MANIFEST.yaml. "
            "Every fixture must be declared."
        )
    for declared in sorted(declared_paths - fixture_names):
        violations.append(
            f"{declared}: declared in MANIFEST.yaml but not present under "
            "captured/."
        )

    if not fixture_files:
        # Empty directories defeat the point of the contract — fail loudly.
        violations.append(
            "captured/ contains no fixture files. The directory exists to "
            "host real public traces; ship at least one or remove the gate."
        )

    if violations:
        print(
            "Captured-fixture provenance violations:\n  - "
            + "\n  - ".join(violations),
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(fixture_files)} captured fixture(s) validated under "
        f"{CAPTURED_DIR.relative_to(ROOT)}/."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
