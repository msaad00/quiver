"""NIST AI RMF 1.0 — GOVERN function evaluation.

Implements 10 of the GOVERN function's ~25 documented subcategories as a
manifest-completeness + freshness audit. The manifest is YAML/JSON keyed
by subcategory ID (``GOVERN-1.1`` ... ``GOVERN-6.2``); each entry must
declare ``documented``, ``review_cadence_days``, ``last_reviewed``, and
``coverage`` so the check can return PASS / PARTIAL / FAIL / NA.

This is NOT a substitute for the qualitative org-level assessment
NIST AI RMF requires. It validates that the manifest exists, is current,
and covers the populations the framework asks for. The narrative the
program owner attaches to the manifest is what the assessment grades.

Read-only — consumes one local manifest file. No cloud SDKs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skills._shared.evaluation_ocsf import findings_to_native, findings_to_ocsf  # noqa: E402

SKILL_NAME = "evaluate-nist-ai-rmf-govern"
BENCHMARK_NAME = "NIST AI RMF 1.0 — GOVERN"
PROVIDER_NAME = "Multi"
FUNCTION = "GOVERN"
OUTPUT_FORMATS = ("native", "ocsf")
MANIFEST_ENV = "NIST_AI_RMF_GOVERN_MANIFEST"
FRAMEWORKS = ("NIST AI RMF 1.0", "OCSF 1.8", "NIST CSF 2.0")

STATUS_PASS = "PASS"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAIL = "FAIL"
STATUS_NA = "NOT_APPLICABLE"
STATUS_ERROR = "ERROR"

# Curated subset of NIST AI RMF 1.0 GOVERN subcategories — 10 of ~25.
# Source: NIST AI RMF 1.0 Core (Section 5.1, table of subcategories).
IMPLEMENTED_SUBCATEGORIES: tuple[tuple[str, str, str, str], ...] = (
    (
        "GOVERN-1.1",
        "AI risk management documented and reviewed",
        "policies",
        "HIGH",
    ),
    (
        "GOVERN-1.2",
        "Roles, responsibilities, and lines of authority defined",
        "roles",
        "HIGH",
    ),
    (
        "GOVERN-1.4",
        "AI risk management integrated with enterprise risk",
        "policies",
        "MEDIUM",
    ),
    (
        "GOVERN-1.6",
        "Mechanisms to inventory AI systems",
        "inventory",
        "HIGH",
    ),
    (
        "GOVERN-2.1",
        "Workforce trained on AI risk",
        "training",
        "MEDIUM",
    ),
    (
        "GOVERN-3.1",
        "Policies for impacted communities",
        "policies",
        "MEDIUM",
    ),
    (
        "GOVERN-4.1",
        "Organizational practices documented for AI development",
        "policies",
        "MEDIUM",
    ),
    (
        "GOVERN-5.1",
        "Policies for third-party AI input",
        "third_party",
        "HIGH",
    ),
    (
        "GOVERN-6.1",
        "AI risk decisions communicated upward",
        "communication",
        "MEDIUM",
    ),
    (
        "GOVERN-6.2",
        "Mechanisms to address AI risk in third-party transactions",
        "third_party",
        "HIGH",
    ),
)

# Subcategories the framework documents but this skill does NOT implement.
# Surface honest scope; do not silently claim 100% function coverage.
DOCUMENTED_NOT_IMPLEMENTED: tuple[str, ...] = (
    "GOVERN-1.3",
    "GOVERN-1.5",
    "GOVERN-1.7",
    "GOVERN-2.2",
    "GOVERN-2.3",
    "GOVERN-3.2",
    "GOVERN-4.2",
    "GOVERN-4.3",
    "GOVERN-5.2",
    "GOVERN-6.3",
    # Plus additional subcategories the AI RMF 1.0 publication lists; this
    # set is the documented-but-deferred subset and is not exhaustive.
)


@dataclass
class Finding:
    control_id: str
    title: str
    section: str
    severity: str
    status: str
    detail: str = ""
    remediation: str = ""
    nist_ai_rmf: str = ""
    nist_csf: str = ""
    resources: list[str] = field(default_factory=list)


def benchmark_metadata() -> dict[str, Any]:
    """Return machine-readable scope for wrappers and docs."""
    return {
        "frameworks": list(FRAMEWORKS),
        "function": FUNCTION,
        "implemented_subcategories": [sub[0] for sub in IMPLEMENTED_SUBCATEGORIES],
        "implemented_count": len(IMPLEMENTED_SUBCATEGORIES),
        "documented_not_implemented": list(DOCUMENTED_NOT_IMPLEMENTED),
        "manifest_env": MANIFEST_ENV,
    }


# ---------------------------------------------------------------------------
# Manifest loading & evaluation
# ---------------------------------------------------------------------------


def load_manifest(path: str | Path | None) -> dict[str, Any]:
    """Load a JSON/YAML manifest. Empty/missing path returns ``{}``."""
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Manifest not found: {p}")
    text = p.read_text(encoding="utf-8")
    if not text.strip():
        return {}
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - import guard
            raise RuntimeError(
                "PyYAML required for YAML manifests; install with `pip install pyyaml`."
            ) from exc
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Manifest must be a mapping, got {type(data).__name__}")
    return data


def _parse_date(raw: Any) -> datetime | None:
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if not isinstance(raw, str):
        return None
    try:
        # Accept date or datetime ISO strings.
        if "T" in raw:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _evaluate_entry(
    subcat_id: str,
    title: str,
    section: str,
    severity: str,
    entry: dict[str, Any] | None,
    *,
    now: datetime,
) -> Finding:
    """Evaluate one subcategory entry against the freshness + completeness contract."""
    if entry is None:
        return Finding(
            control_id=subcat_id,
            title=title,
            section=section,
            severity=severity,
            status=STATUS_FAIL,
            detail=f"No manifest entry for {subcat_id}",
            remediation=(
                f"Add a `{subcat_id}` entry to the manifest with `documented: true`, "
                "`review_cadence_days`, `last_reviewed`, and `coverage`."
            ),
            nist_ai_rmf=f"{FUNCTION}: {subcat_id}",
            nist_csf="GV.RM-1",
        )

    if not isinstance(entry, dict):
        return Finding(
            control_id=subcat_id,
            title=title,
            section=section,
            severity=severity,
            status=STATUS_ERROR,
            detail=f"Manifest entry for {subcat_id} must be a mapping",
            nist_ai_rmf=f"{FUNCTION}: {subcat_id}",
            nist_csf="GV.RM-1",
        )

    if entry.get("not_applicable") is True:
        return Finding(
            control_id=subcat_id,
            title=title,
            section=section,
            severity=severity,
            status=STATUS_NA,
            detail=str(entry.get("not_applicable_reason") or "Marked not applicable"),
            nist_ai_rmf=f"{FUNCTION}: {subcat_id}",
            nist_csf="GV.RM-1",
        )

    documented = bool(entry.get("documented"))
    coverage_raw = entry.get("coverage")
    coverage = float(coverage_raw) if isinstance(coverage_raw, (int, float)) else 0.0
    review_cadence_days = entry.get("review_cadence_days")
    last_reviewed = _parse_date(entry.get("last_reviewed"))
    evidence_uri = entry.get("evidence_uri") or entry.get("evidence")
    resources_field = entry.get("resources") or []
    resources = [str(r) for r in resources_field if isinstance(r, str)]

    issues: list[str] = []

    if not documented:
        issues.append("not documented")

    if review_cadence_days is None or not isinstance(review_cadence_days, (int, float)):
        issues.append("missing review_cadence_days")
    elif last_reviewed is None:
        issues.append("missing last_reviewed")
    else:
        max_age = timedelta(days=float(review_cadence_days))
        if now - last_reviewed > max_age:
            issues.append(
                f"stale: last reviewed {(now - last_reviewed).days}d ago "
                f"vs cadence {int(review_cadence_days)}d"
            )

    if not evidence_uri:
        issues.append("no evidence_uri")

    if coverage <= 0:
        issues.append("coverage 0%")
    elif coverage < 0.5:
        issues.append(f"coverage low ({coverage:.0%})")

    if not issues:
        return Finding(
            control_id=subcat_id,
            title=title,
            section=section,
            severity=severity,
            status=STATUS_PASS,
            detail=(
                f"Documented; reviewed within {int(review_cadence_days or 0)}d cadence; "
                f"coverage {coverage:.0%}"
            ),
            nist_ai_rmf=f"{FUNCTION}: {subcat_id}",
            nist_csf="GV.RM-1",
            resources=resources,
        )

    if documented and coverage >= 0.5 and last_reviewed is not None:
        return Finding(
            control_id=subcat_id,
            title=title,
            section=section,
            severity=severity,
            status=STATUS_PARTIAL,
            detail="; ".join(issues),
            remediation=(
                "Close the gaps listed in `detail`. Manifest contract: documented=true, "
                "review_cadence_days, last_reviewed within cadence, evidence_uri, "
                "coverage >= 0.5."
            ),
            nist_ai_rmf=f"{FUNCTION}: {subcat_id}",
            nist_csf="GV.RM-1",
            resources=resources,
        )

    return Finding(
        control_id=subcat_id,
        title=title,
        section=section,
        severity=severity,
        status=STATUS_FAIL,
        detail="; ".join(issues),
        remediation=(
            "Fix the issues in `detail`. Manifest entry must declare documented=true, "
            "set review_cadence_days, last_reviewed within cadence, evidence_uri, "
            "and coverage >= 0.5."
        ),
        nist_ai_rmf=f"{FUNCTION}: {subcat_id}",
        nist_csf="GV.RM-1",
        resources=resources,
    )


def run_benchmark(
    manifest: dict[str, Any],
    *,
    subcategory: str | None = None,
    now: datetime | None = None,
) -> list[Finding]:
    """Evaluate the configured subcategories against the manifest."""
    when = now if now is not None else datetime.now(UTC)
    entries = manifest.get("subcategories", manifest) if isinstance(manifest, dict) else {}
    if not isinstance(entries, dict):
        entries = {}

    findings: list[Finding] = []
    for sub_id, title, section, severity in IMPLEMENTED_SUBCATEGORIES:
        if subcategory and sub_id != subcategory:
            continue
        entry = entries.get(sub_id)
        findings.append(_evaluate_entry(sub_id, title, section, severity, entry, now=when))
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def print_summary(findings: list[Finding]) -> None:
    total = len(findings)
    counts = {STATUS_PASS: 0, STATUS_PARTIAL: 0, STATUS_FAIL: 0, STATUS_NA: 0, STATUS_ERROR: 0}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1

    print(f"\n{'=' * 64}")
    print(f"  {BENCHMARK_NAME}")
    print(f"  Implements {len(IMPLEMENTED_SUBCATEGORIES)} subcategories")
    print(f"{'=' * 64}\n")
    icon = {
        STATUS_PASS: "+",
        STATUS_PARTIAL: "~",
        STATUS_FAIL: "x",
        STATUS_NA: "-",
        STATUS_ERROR: "?",
    }
    for f in findings:
        print(f"  [{icon.get(f.status, '?')}] {f.control_id:14s} [{f.severity:6s}] {f.title}")
        if f.status in (STATUS_FAIL, STATUS_PARTIAL):
            print(f"      {f.detail}")
            if f.remediation:
                print(f"      FIX: {f.remediation}")
    print(f"\n  {'-' * 60}")
    print(
        f"  Total: {total} | PASS {counts[STATUS_PASS]} | PARTIAL "
        f"{counts[STATUS_PARTIAL]} | FAIL {counts[STATUS_FAIL]} | "
        f"NA {counts[STATUS_NA]}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=f"{BENCHMARK_NAME} — manifest-completeness evaluator"
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        help=(f"Path to manifest (JSON/YAML). Defaults to ${MANIFEST_ENV} env var."),
    )
    parser.add_argument(
        "--subcategory",
        help="Run a single subcategory (e.g. GOVERN-1.1).",
    )
    parser.add_argument("--output", choices=["console", "json"], default="console")
    parser.add_argument("--output-format", choices=list(OUTPUT_FORMATS), default="native")
    args = parser.parse_args(argv)

    manifest_path = args.manifest or os.environ.get(MANIFEST_ENV) or ""
    try:
        manifest = load_manifest(manifest_path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    findings = run_benchmark(manifest, subcategory=args.subcategory)

    if args.output == "json":
        rendered: list[dict[str, Any]] = (
            findings_to_ocsf(
                findings,
                skill_name=SKILL_NAME,
                benchmark_name=BENCHMARK_NAME,
                provider=PROVIDER_NAME,
                frameworks=list(FRAMEWORKS),
            )
            if args.output_format == "ocsf"
            else findings_to_native(findings)
        )
        print(json.dumps(rendered, indent=2))
    else:
        print_summary(findings)

    critical_or_high_fails = sum(
        1 for f in findings if f.status == STATUS_FAIL and f.severity in ("HIGH", "CRITICAL")
    )
    return 1 if critical_or_high_fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
