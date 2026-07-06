"""CI: replay every OCSF golden fixture through the schema validator.

Zero tolerance for malformed events in the frozen fixtures. If a fixture fails,
either the fixture or the emitting skill has drifted from OCSF_CONTRACT.md —
both are regressions worth the build break.

Invoked from CI as:

    uv run python scripts/validate_golden_ocsf.py

Exit code:
    0 — every fixture line is a valid OCSF 1.8 event
    1 — at least one fixture has a validation error
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "skills" / "detection-engineering" / "golden"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills._shared.ocsf_validator import validate_event  # noqa: E402


def main() -> int:
    fixtures = sorted(GOLDEN.glob("*.ocsf.jsonl"))
    if not fixtures:
        print(f"No OCSF fixtures found under {GOLDEN.relative_to(ROOT)}", file=sys.stderr)
        return 1

    errors: list[str] = []
    total_events = 0
    total_fixtures = 0

    for path in fixtures:
        total_fixtures += 1
        for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{path.relative_to(ROOT)}:{lineno}: JSON parse failed: {exc}")
                continue
            if not isinstance(event, dict):
                errors.append(
                    f"{path.relative_to(ROOT)}:{lineno}: expected a JSON object, got {type(event).__name__}"
                )
                continue
            total_events += 1
            violations = validate_event(event)
            for violation in violations:
                errors.append(f"{path.relative_to(ROOT)}:{lineno}: {violation}")

    if errors:
        print("OCSF golden-fixture validation FAILED:", file=sys.stderr)
        for err in errors:
            print(f" - {err}", file=sys.stderr)
        print(
            f"\n{len(errors)} violation(s) across {total_fixtures} fixture(s) / {total_events} events",
            file=sys.stderr,
        )
        return 1

    print(
        f"OCSF golden-fixture validation passed: {total_events} events across {total_fixtures} fixtures"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
