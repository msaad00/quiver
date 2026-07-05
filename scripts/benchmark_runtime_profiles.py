#!/usr/bin/env python3
"""Benchmark representative runtime profiles for shipped skills."""

from __future__ import annotations

import argparse
import json
import resource
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import cycle, islice
from pathlib import Path
from typing import Any, Literal, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
RUNS = 3


LoadName = Literal["typical", "10x"]
InputMode = Literal["path", "stdin"]


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    fixture_path: Path
    fixture_shape: list[str]
    loads: dict[LoadName, int]
    input_mode: InputMode
    command_prefix: tuple[str, ...]


CASES: tuple[BenchmarkCase, ...] = (
    BenchmarkCase(
        name="ingest-cloudtrail-ocsf",
        fixture_path=REPO_ROOT / "skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl",
        fixture_shape=[
            "raw CloudTrail JSONL",
            "repeated to 1,000 and 10,000 input records",
        ],
        loads={"typical": 1_000, "10x": 10_000},
        input_mode="path",
        command_prefix=(
            PYTHON,
            str(REPO_ROOT / "skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py"),
        ),
    ),
    BenchmarkCase(
        name="detect-lateral-movement",
        fixture_path=REPO_ROOT
        / "skills/detection-engineering/golden/lateral_movement_input.ocsf.jsonl",
        fixture_shape=[
            "mixed OCSF API Activity and Network Activity rows",
            "repeated to 1,000 and 10,000 input records",
        ],
        loads={"typical": 1_000, "10x": 10_000},
        input_mode="path",
        command_prefix=(
            PYTHON,
            str(REPO_ROOT / "skills/detection/detect-lateral-movement/src/detect.py"),
        ),
    ),
    BenchmarkCase(
        name="sink-snowflake-jsonl",
        fixture_path=REPO_ROOT
        / "skills/detection-engineering/golden/lateral_movement_findings.ocsf.jsonl",
        fixture_shape=[
            "OCSF finding JSONL",
            "measured in --dry-run mode only",
            "repeated to 500 and 5,000 input records",
        ],
        loads={"typical": 500, "10x": 5_000},
        input_mode="stdin",
        command_prefix=(
            PYTHON,
            str(REPO_ROOT / "skills/output/sink-snowflake-jsonl/src/sink.py"),
            "--dry-run",
            "--table",
            "BENCH.RUNTIME_PROFILES",
        ),
    ),
)


def _case_by_name(name: str) -> BenchmarkCase:
    for case in CASES:
        if case.name == name:
            return case
    valid = ", ".join(case.name for case in CASES)
    raise ValueError(f"unknown case `{name}`; choose from: {valid}")


def _normalize_ru_maxrss(raw_value: int) -> float:
    if sys.platform == "darwin":
        return raw_value / (1024 * 1024)
    return (raw_value * 1024) / (1024 * 1024)


def _load_fixture_lines(path: Path) -> list[str]:
    lines = [
        line.rstrip("\n") for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if not lines:
        raise ValueError(f"fixture `{path}` did not contain any non-empty lines")
    return lines


def _write_repeated_fixture(source_path: Path, target_records: int, output_path: Path) -> None:
    lines = _load_fixture_lines(source_path)
    repeated = list(islice(cycle(lines), target_records))
    output_path.write_text("".join(f"{line}\n" for line in repeated), encoding="utf-8")


def _round_ms(value: float) -> float:
    return round(value * 1000, 2)


def _measure_child_once(
    input_path: Path, input_mode: InputMode, command: Sequence[str]
) -> dict[str, float]:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    with (
        input_path.open("rb") if input_mode == "stdin" else open("/dev/null", "rb") as stdin_handle
    ):
        stdin = stdin_handle if input_mode == "stdin" else None
        completed = subprocess.run(
            list(command),
            stdin=stdin,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=False,
            check=False,
        )
    end = time.perf_counter()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if completed.returncode != 0:
        stderr_text = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"child command failed with exit {completed.returncode}: {stderr_text}")
    return {
        "wall_seconds": end - start,
        "cpu_user_seconds": after.ru_utime - before.ru_utime,
        "cpu_sys_seconds": after.ru_stime - before.ru_stime,
        "peak_rss_mib": _normalize_ru_maxrss(after.ru_maxrss),
    }


def _run_helper(
    input_path: Path, input_mode: InputMode, command: Sequence[str]
) -> dict[str, float]:
    helper_command = [
        PYTHON,
        str(REPO_ROOT / "scripts/benchmark_runtime_profiles.py"),
        "_measure-one",
        "--input-path",
        str(input_path),
        "--input-mode",
        input_mode,
        "--",
        *command,
    ]
    completed = subprocess.run(helper_command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip() or completed.stdout.strip() or "benchmark helper failed"
        )
    raw_result = json.loads(completed.stdout)
    if not isinstance(raw_result, dict):
        raise RuntimeError("benchmark helper did not return a JSON object")
    return cast(dict[str, float], raw_result)


def _average(values: list[float]) -> float:
    return sum(values) / len(values)


def _summarize_case(case: BenchmarkCase, load_name: LoadName, input_path: Path) -> dict[str, Any]:
    command = list(case.command_prefix)
    if case.input_mode == "path":
        command.append(str(input_path))

    samples = [_run_helper(input_path, case.input_mode, command) for _ in range(RUNS)]
    avg_wall_seconds = _average([sample["wall_seconds"] for sample in samples])
    input_records = case.loads[load_name]
    return {
        "load_level": load_name,
        "input_records": input_records,
        "avg_wall_ms": round(
            _average([_round_ms(sample["wall_seconds"]) for sample in samples]), 2
        ),
        "avg_cpu_user_ms": round(
            _average([_round_ms(sample["cpu_user_seconds"]) for sample in samples]), 2
        ),
        "avg_cpu_sys_ms": round(
            _average([_round_ms(sample["cpu_sys_seconds"]) for sample in samples]), 2
        ),
        "peak_rss_mib": round(max(sample["peak_rss_mib"] for sample in samples), 1),
        "approx_throughput_rps": round(input_records / avg_wall_seconds, 1),
        "runs": samples,
    }


def _benchmark_case(case: BenchmarkCase) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"{case.name}-bench-") as temp_dir:
        temp_root = Path(temp_dir)
        loads: dict[str, Any] = {}
        for load_name, input_records in case.loads.items():
            input_path = temp_root / f"{case.name}-{load_name}.jsonl"
            _write_repeated_fixture(case.fixture_path, input_records, input_path)
            loads[load_name] = _summarize_case(case, load_name, input_path)
    return {
        "name": case.name,
        "fixture_path": str(case.fixture_path.relative_to(REPO_ROOT)),
        "fixture_shape": case.fixture_shape,
        "loads": loads,
    }


def _build_snapshot(selected_cases: Sequence[BenchmarkCase]) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runs_per_case": RUNS,
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "measurement_method": {
            "wall_clock": "process start to exit",
            "cpu_time": "resource.getrusage(RUSAGE_CHILDREN) in a fresh helper process per run",
            "peak_rss": "ru_maxrss from the fresh helper process, normalized to MiB",
            "stdout": "discarded to avoid terminal rendering cost",
        },
        "cases": [_benchmark_case(case) for case in selected_cases],
    }


def _main_measure_one(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Internal helper: measure one child process.")
    parser.add_argument("--input-path", required=True)
    parser.add_argument("--input-mode", choices=("path", "stdin"), required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("missing child command after `--`")
    result = _measure_child_once(Path(args.input_path), args.input_mode, command)
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args_list = list(argv or sys.argv[1:])
    if args_list and args_list[0] == "_measure-one":
        return _main_measure_one(args_list[1:])

    parser = argparse.ArgumentParser(
        description="Benchmark representative runtime profiles for shipped skills."
    )
    parser.add_argument(
        "--case",
        action="append",
        choices=[case.name for case in CASES],
        help="Benchmark only the named case. Repeat to select multiple cases.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the benchmark snapshot JSON to this path as well as stdout.",
    )
    parsed = parser.parse_args(args_list)

    selected_cases = (
        CASES if not parsed.case else tuple(_case_by_name(name) for name in parsed.case)
    )
    snapshot = _build_snapshot(selected_cases)
    rendered = json.dumps(snapshot, indent=2, sort_keys=False) + "\n"
    if parsed.output:
        parsed.output.parent.mkdir(parents=True, exist_ok=True)
        parsed.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
