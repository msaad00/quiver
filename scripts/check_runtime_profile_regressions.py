#!/usr/bin/env python3
"""Compare runtime benchmark scaling behavior against a checked-in baseline."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CaseMetrics:
    wall_multiplier: float
    throughput_multiplier: float
    rss_multiplier: float


def _load_snapshot(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path} did not contain a JSON object")
    return raw


def _case_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = snapshot.get("cases")
    if not isinstance(cases, list):
        raise ValueError("snapshot missing `cases` list")
    mapped: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("snapshot case entry was not an object")
        name = case.get("name")
        if not isinstance(name, str):
            raise ValueError("snapshot case missing string `name`")
        mapped[name] = case
    return mapped


def _metric(load: dict[str, Any], name: str) -> float:
    value = load.get(name)
    if not isinstance(value, (int, float)):
        raise ValueError(f"load entry missing numeric `{name}`")
    return float(value)


def _case_metrics(case: dict[str, Any]) -> CaseMetrics:
    loads = case.get("loads")
    if not isinstance(loads, dict):
        raise ValueError("case missing `loads` object")
    typical = loads.get("typical")
    ten_x = loads.get("10x")
    if not isinstance(typical, dict) or not isinstance(ten_x, dict):
        raise ValueError("case must include `typical` and `10x` loads")
    typical_wall = _metric(typical, "avg_wall_ms")
    ten_x_wall = _metric(ten_x, "avg_wall_ms")
    typical_throughput = _metric(typical, "approx_throughput_rps")
    ten_x_throughput = _metric(ten_x, "approx_throughput_rps")
    typical_rss = _metric(typical, "peak_rss_mib")
    ten_x_rss = _metric(ten_x, "peak_rss_mib")
    return CaseMetrics(
        wall_multiplier=ten_x_wall / typical_wall,
        throughput_multiplier=ten_x_throughput / typical_throughput,
        rss_multiplier=ten_x_rss / typical_rss,
    )


def _format_ratio(value: float) -> str:
    return f"{value:.2f}x"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check runtime benchmark scaling against a baseline snapshot."
    )
    parser.add_argument(
        "--baseline", type=Path, required=True, help="Checked-in baseline snapshot JSON."
    )
    parser.add_argument(
        "--candidate", type=Path, required=True, help="Freshly-generated benchmark snapshot JSON."
    )
    parser.add_argument(
        "--max-wall-multiplier-regression",
        type=float,
        default=0.5,
        help="Fail if candidate wall multiplier exceeds baseline by more than this fraction. Default: 0.5 (50%%).",
    )
    parser.add_argument(
        "--max-throughput-multiplier-drop",
        type=float,
        default=0.4,
        help="Fail if candidate throughput multiplier drops below baseline by more than this fraction. Default: 0.4 (40%%).",
    )
    parser.add_argument(
        "--max-rss-multiplier-regression",
        type=float,
        default=0.5,
        help="Fail if candidate RSS multiplier exceeds baseline by more than this fraction. Default: 0.5 (50%%).",
    )
    args = parser.parse_args(argv)

    baseline_cases = _case_map(_load_snapshot(args.baseline))
    candidate_cases = _case_map(_load_snapshot(args.candidate))

    failures: list[str] = []
    for case_name, baseline_case in baseline_cases.items():
        candidate_case = candidate_cases.get(case_name)
        if candidate_case is None:
            failures.append(f"{case_name}: missing from candidate snapshot")
            continue

        baseline = _case_metrics(baseline_case)
        candidate = _case_metrics(candidate_case)

        max_wall = baseline.wall_multiplier * (1 + args.max_wall_multiplier_regression)
        min_throughput = baseline.throughput_multiplier * (1 - args.max_throughput_multiplier_drop)
        max_rss = baseline.rss_multiplier * (1 + args.max_rss_multiplier_regression)

        if candidate.wall_multiplier > max_wall:
            failures.append(
                f"{case_name}: wall scaling regressed from {_format_ratio(baseline.wall_multiplier)} "
                f"to {_format_ratio(candidate.wall_multiplier)} (limit {_format_ratio(max_wall)})"
            )
        if candidate.throughput_multiplier < min_throughput:
            failures.append(
                f"{case_name}: throughput scaling regressed from {_format_ratio(baseline.throughput_multiplier)} "
                f"to {_format_ratio(candidate.throughput_multiplier)} (floor {_format_ratio(min_throughput)})"
            )
        if candidate.rss_multiplier > max_rss:
            failures.append(
                f"{case_name}: RSS scaling regressed from {_format_ratio(baseline.rss_multiplier)} "
                f"to {_format_ratio(candidate.rss_multiplier)} (limit {_format_ratio(max_rss)})"
            )

        print(
            f"{case_name}: wall {_format_ratio(candidate.wall_multiplier)} "
            f"(baseline {_format_ratio(baseline.wall_multiplier)}), "
            f"throughput {_format_ratio(candidate.throughput_multiplier)} "
            f"(baseline {_format_ratio(baseline.throughput_multiplier)}), "
            f"rss {_format_ratio(candidate.rss_multiplier)} "
            f"(baseline {_format_ratio(baseline.rss_multiplier)})"
        )

    for case_name in sorted(set(candidate_cases) - set(baseline_cases)):
        print(f"{case_name}: present only in candidate snapshot")

    if failures:
        for failure in failures:
            print(f"REGRESSION: {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
