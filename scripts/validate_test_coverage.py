from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

try:
    from defusedxml import ElementTree as ET
except ModuleNotFoundError:  # pragma: no cover - exercised when dev deps not installed
    sys.stderr.write(
        "error: validate_test_coverage.py requires `defusedxml` "
        "(listed in pyproject.toml `[dependency-groups].dev`). "
        "Install dev dependencies: `uv sync --group dev` or `pip install defusedxml`.\n"
    )
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_XML = ROOT / "coverage.xml"
OVERALL_FLOOR = 80.0
# Per-layer floors set ~5pp below observed coverage on 2026-04-28 so honest
# refactors have headroom without leaking real regressions. Bump these as
# coverage climbs; never lower without an issue documenting why.
LAYER_FLOORS = {
    "_shared": 90.0,
    "detection": 80.0,
    "discovery": 80.0,
    "evaluation": 80.0,
    "ingestion": 80.0,
    "output": 80.0,
    "remediation": 70.0,
    "view": 80.0,
}


def _read_coverage_xml(path: Path) -> ET.Element:
    try:
        return ET.parse(path).getroot()
    except FileNotFoundError:
        print(f"Coverage validation failed: missing report `{path}`", file=sys.stderr)
        raise SystemExit(1)


def _collect_layer_stats(root: ET.Element) -> dict[str, tuple[int, int]]:
    by_layer: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for cls in root.findall(".//class"):
        filename = cls.get("filename", "")
        parts = filename.split("/")
        if parts[0] == "skills":
            parts = parts[1:]
        if len(parts) < 2:
            continue
        layer = parts[0]
        lines = cls.findall("./lines/line")
        total = len(lines)
        hit = sum(1 for line in lines if int(line.get("hits", "0")) > 0)
        by_layer[layer][0] += hit
        by_layer[layer][1] += total
    return {layer: (stats[0], stats[1]) for layer, stats in by_layer.items()}


def _coverage_percent(hit: int, total: int) -> float:
    return (100.0 * hit / total) if total else 0.0


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    xml_path = Path(args[0]) if args else DEFAULT_XML

    root = _read_coverage_xml(xml_path)
    line_rate = float(root.get("line-rate", "0.0")) * 100.0
    errors: list[str] = []
    if line_rate < OVERALL_FLOOR:
        errors.append(
            f"overall coverage {line_rate:.2f}% is below required floor {OVERALL_FLOOR:.0f}%"
        )

    layer_stats = _collect_layer_stats(root)
    for layer, floor in LAYER_FLOORS.items():
        hit, total = layer_stats.get(layer, (0, 0))
        pct = _coverage_percent(hit, total)
        if pct < floor:
            errors.append(f"{layer} coverage {pct:.2f}% is below required floor {floor:.0f}%")

    if errors:
        print("Coverage validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(
        "Coverage validation passed: "
        f"overall={line_rate:.2f}% "
        + " ".join(
            f"{layer}={_coverage_percent(*layer_stats[layer]):.2f}%"
            for layer in sorted(LAYER_FLOORS)
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
