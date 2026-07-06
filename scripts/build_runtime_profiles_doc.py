#!/usr/bin/env python3
"""Generate `docs/RUNTIME_PROFILES.md` from `runtime-profile-results.jsonl`.

The harness in `scripts/runner_e2e.sh` writes one JSONL record per
(runner, scenario). This script reads that file and renders a
human-readable Markdown report.

It is intentionally deterministic: the only inputs are the JSONL
records, the renderer is sort-stable, and the auto-generated banner
makes it clear the doc is machine-output. `--check` mode regenerates
the doc in-memory and diffs it against the on-disk copy so CI can
detect when a regenerator was skipped after a results refresh.

Honest-gaps section lists every record where `status == "gap"` so
readers see scenarios that don't yet have automated coverage. We do
not fabricate p50/p95/throughput for those rows.

Usage
-----

    python scripts/build_runtime_profiles_doc.py \
        --results runtime-profile-results.jsonl \
        --output docs/RUNTIME_PROFILES.md

    # CI parity check (exit 1 when the doc drifted out of sync):
    python scripts/build_runtime_profiles_doc.py --check
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Per-row dynamics that change between runs but do not represent a
# generator-shape change. `--check` strips these before diffing.
_DYNAMIC_PATTERNS: tuple[re.Pattern[str], ...] = (
    # ISO-8601 timestamp with 'Z' suffix (captured_at column).
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"),
    # ms timings rendered as "12.34 ms".
    re.compile(r"\d+\.\d{2} ms"),
)


def _structural_canonical(text: str) -> str:
    """Return a structure-only canonicalization of the rendered doc.

    Drops timestamps + numeric latency cells so a re-run with identical
    scenario shape but different numbers compares equal. Keeps the
    table layout, scenario names, gap reasons, and prose intact.
    """
    canonical = text
    for pattern in _DYNAMIC_PATTERNS:
        canonical = pattern.sub("<dynamic>", canonical)
    return canonical


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO_ROOT / "runtime-profile-results.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "RUNTIME_PROFILES.md"

BANNER = (
    "<!-- AUTO-GENERATED — do not hand-edit. Source: "
    "runtime-profile-results.jsonl, regenerator: "
    "scripts/build_runtime_profiles_doc.py. -->"
)


def _load_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(
            f"results file not found: {path}. Run `bash scripts/runner_e2e.sh` first."
        )
    records: list[dict[str, Any]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
    return records


def _fmt_ms(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (int, float)):
        return f"{value:.2f} ms"
    return str(value)


def _fmt_int(value: Any) -> str:
    if value is None:
        return "—"
    return str(value)


def _fmt_bool(value: Any) -> str:
    if value is None:
        return "n/a"
    return "yes" if value else "no"


def _render_measured_table(records: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    rows.append(
        "| Runner | Scenario | Samples | p50 | p95 | Mean | Sink arrival | Audit chain | Captured |"
    )
    rows.append("|---|---|---:|---:|---:|---:|---:|:---:|---|")
    for rec in records:
        runner = rec.get("runner", "?")
        scenario = rec.get("scenario", "?")
        samples = _fmt_int(rec.get("samples"))
        p50 = _fmt_ms(rec.get("p50_ms"))
        p95 = _fmt_ms(rec.get("p95_ms"))
        mean = _fmt_ms(rec.get("mean_ms"))
        sink = _fmt_int(rec.get("sink_arrival_count"))
        chain = _fmt_bool(rec.get("audit_chain_verified"))
        captured = rec.get("captured_at", "—")
        rows.append(
            f"| `{runner}` | `{scenario}` | {samples} | {p50} | {p95} | {mean} | "
            f"{sink} | {chain} | {captured} |"
        )
    return "\n".join(rows)


def _render_gap_section(records: list[dict[str, Any]]) -> str:
    """Render the honest-gaps section for status=gap rows AND surfaces
    where the per-record `*_status` field calls out an in-flight gap.
    """
    if not records:
        return "_None._"
    lines: list[str] = []
    for rec in records:
        runner = rec.get("runner", "?")
        scenario = rec.get("scenario", "?")
        reason = rec.get("gap_reason") or rec.get("error") or "(no reason recorded)"
        lines.append(f"- `{runner}` — `{scenario}`: {reason}")
    return "\n".join(lines)


def _render_subgaps(records: list[dict[str, Any]]) -> str:
    """Per-runner gaps surfaced via `*_status` fields (chain, sink) so
    a reader of the doc can see that even scenarios marked `ok` have
    bounded coverage."""
    notes: list[str] = []
    for rec in records:
        runner = rec.get("runner", "?")
        scenario = rec.get("scenario", "?")
        for field in ("audit_chain_status", "sink_status"):
            value = rec.get(field)
            if isinstance(value, str) and value.startswith("gap"):
                notes.append(f"- `{runner}` / `{scenario}` — {field}: `{value}`")
    if not notes:
        return "_All ok-status scenarios cover both audit + sink assertions._"
    return "\n".join(notes)


def render_doc(records: list[dict[str, Any]]) -> str:
    measured = [rec for rec in records if rec.get("status") == "ok" or rec.get("status") == "fail"]
    gaps = [rec for rec in records if rec.get("status") == "gap"]
    errors = [rec for rec in records if rec.get("status") == "error"]

    measured_sorted = sorted(measured, key=lambda r: (r.get("runner", ""), r.get("scenario", "")))
    gaps_sorted = sorted(gaps, key=lambda r: (r.get("runner", ""), r.get("scenario", "")))

    parts: list[str] = []
    parts.append(BANNER)
    parts.append("")
    parts.append("# Runtime Profiles — Runner Templates")
    parts.append("")
    parts.append(
        "This document is regenerated from `runtime-profile-results.jsonl` "
        "every time the harness runs. It is intentionally light on prose: the "
        "point is to detect **regressions** between CI runs, not to advertise "
        "raw numbers."
    )
    parts.append("")
    parts.append("Closes:")
    parts.append(
        "- [#198](https://github.com/msaad00/cloud-ai-security-skills/issues/198) — "
        "deploy and verify all three runner templates end to end (CI surface)."
    )
    parts.append(
        "- [#199](https://github.com/msaad00/cloud-ai-security-skills/issues/199) — "
        "benchmark runtime profiles at representative scale (CI cadence)."
    )
    parts.append("")
    parts.append("## What this is")
    parts.append("")
    parts.append(
        "Every record below comes from `scripts/runner_e2e.sh`, which spins "
        "each runner template up against an ephemeral local backend, sends "
        "**N synthetic events matched to that runner's real contract**, and "
        "asserts both **audit-log capture** and **sink arrival** before "
        "reporting timings."
    )
    parts.append("")
    parts.append(
        "Sample size defaults to **N = 20** per scenario. These are CI-runner "
        "numbers on a free-tier executor. Do **not** quote these p50/p95s as "
        "customer-scale numbers — they exist to flag a regression, not to "
        "advertise throughput."
    )
    parts.append("")
    parts.append("## Measured runs")
    parts.append("")
    if measured_sorted:
        parts.append(_render_measured_table(measured_sorted))
    else:
        parts.append("_No measured records — run the harness first._")
    parts.append("")
    parts.append("### Per-scenario assertions")
    parts.append("")
    parts.append("Each `ok` record above means **all** of the following held for the run:")
    parts.append("")
    parts.append("- the runner accepted every one of the N requests with no failures;")
    parts.append(
        "- the audit assertion for that runner passed (the receiver writes a "
        "single-line JSONL audit; the SSE runner writes an HMAC-chained log and "
        "`scripts/verify_audit_chain.py` returned exit 0; the AWS runner has no "
        "in-process audit chain — its audit gap is documented below);"
    )
    parts.append(
        "- the **sink-arrival assertion** for that runner held (webhook receiver "
        "currently does not fan out — gap below; SSE response payload shape was "
        "verified for every reply; AWS scenario asserts exact SQS message count "
        "= N)."
    )
    parts.append("")
    parts.append("## Honest gaps")
    parts.append("")
    parts.append(
        "Scenarios in this section have **no automated coverage in this PR**. "
        "The doc lists them so readers can see the coverage boundary without "
        "having to grep the harness source."
    )
    parts.append("")
    parts.append(_render_gap_section(gaps_sorted))
    parts.append("")
    parts.append("### Sub-gaps inside ok-status scenarios")
    parts.append("")
    parts.append(
        "Even `ok` scenarios have bounded coverage — the harness records the "
        "boundary on each row's `audit_chain_status` and `sink_status` so this "
        "doc never claims more than was tested."
    )
    parts.append("")
    parts.append(_render_subgaps(measured_sorted))
    parts.append("")
    if errors:
        parts.append("## Errors in the latest run")
        parts.append("")
        for rec in errors:
            parts.append(
                f"- `{rec.get('runner', '?')}` / `{rec.get('scenario', '?')}`: "
                f"{rec.get('error', '(no detail)')}"
            )
        parts.append("")
    parts.append("## How to run")
    parts.append("")
    parts.append("Locally:")
    parts.append("")
    parts.append("```bash")
    parts.append("uv sync --group dev --group webhook --group mcp-sse --group http-runtime")
    parts.append("bash scripts/runner_e2e.sh")
    parts.append("python scripts/build_runtime_profiles_doc.py")
    parts.append("```")
    parts.append("")
    parts.append(
        "In CI the workflow `.github/workflows/runner-e2e.yml` runs the harness "
        "on every PR that touches `runners/**`, `mcp-server/**`, "
        "`skills/_shared/**`, the harness itself, or the workflow file, plus "
        "once a day at 02:00 UTC. The workflow also runs "
        "`build_runtime_profiles_doc.py --check` so a PR that updates the "
        "harness but not the doc fails immediately."
    )
    parts.append("")
    parts.append("## Tooling notes")
    parts.append("")
    parts.append(
        "- `helm lint` / `docker build` for the runner templates run in "
        "`.github/workflows/runner-templates.yml`, not this harness. The "
        "harness assumes the templates render — it does not re-validate them."
    )
    parts.append(
        "- GCP and Azure cloud-runner end-to-end coverage is still gap (see "
        "above). The real-cloud deploy proof requested by #198 stays the "
        "responsibility of an operator running the templates against a real "
        "account; this harness only covers what can be exercised locally."
    )
    parts.append("")
    return "\n".join(parts) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Render to memory and diff against the on-disk doc. Exit 1 on drift.",
    )
    args = parser.parse_args(argv)

    records = _load_records(args.results)
    rendered = render_doc(records)

    if args.check:
        if not args.output.exists():
            sys.stderr.write(f"error: {args.output} does not exist — run without --check first\n")
            return 1
        current = args.output.read_text(encoding="utf-8")
        # Structural comparison — strip the per-row `Captured` ISO
        # timestamp + the numeric latency/sample cells so a re-run that
        # only moved the numbers does not register as a drift. The
        # purpose of --check is to catch "generator output shape
        # changed but the committed doc wasn't refreshed", not "p50
        # moved 0.2 ms".
        if _structural_canonical(current) != _structural_canonical(rendered):
            sys.stderr.write(
                f"error: {args.output} is structurally out of sync with "
                f"{args.results}.\n"
                "Run `python scripts/build_runtime_profiles_doc.py` and commit "
                "the result.\n"
            )
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(f"wrote {args.output} ({len(rendered)} bytes)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
