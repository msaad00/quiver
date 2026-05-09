"""End-to-end tests for the new top-level CLI / MCP shim
(`src/handler.py`) and the underlying parser `main()` entrypoint.

The parser already had unit-level tests for `_validate_entry` (see
`test_parser_lambda.py`); these tests cover the *boundary* the MCP server
sees: subprocess invocation, stdin manifest, --apply refusal, and exit
codes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1]
HANDLER = SKILL_ROOT / "src" / "handler.py"


def _well_outside_grace_iso() -> str:
    """A timestamp well past the 7-day default grace window."""
    return (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()


def _run(stdin: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HANDLER), *args],
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )


def test_dry_run_default_emits_plan_for_actionable_entry():
    entry = {
        "email": "alice@example.com",
        "recipient_account_id": "123456789012",
        "iam_username": "alice",
        "terminated_at": _well_outside_grace_iso(),
    }
    result = _run(json.dumps(entry) + "\n")
    assert result.returncode == 0, result.stderr

    plan = json.loads(result.stdout.strip().splitlines()[0])
    assert plan["action"] == "remediate"
    assert plan["entry"]["iam_username"] == "alice"

    summary = json.loads(result.stderr.strip().splitlines()[-1])
    assert summary == {
        "event": "plan_summary",
        "actions": 1,
        "skips": 0,
        "dry_run": True,
    }


def test_apply_is_refused_with_exit_2():
    result = _run("{}\n", "--apply")
    assert result.returncode == 2
    payload = json.loads(result.stderr.strip().splitlines()[-1])
    assert payload["event"] == "apply_refused"
    assert "Step Function" in payload["reason"]


def test_dry_run_skips_within_grace_period():
    entry = {
        "email": "bob@example.com",
        "recipient_account_id": "123456789012",
        "iam_username": "bob",
        "terminated_at": datetime.now(timezone.utc).isoformat(),
    }
    result = _run(json.dumps(entry) + "\n")
    assert result.returncode == 0
    plan = json.loads(result.stdout.strip().splitlines()[0])
    assert plan["action"] == "skip"
    assert "grace period" in plan["reason"]


def test_dry_run_skips_invalid_account_id():
    entry = {
        "email": "carol@example.com",
        "recipient_account_id": "not-an-id",
        "iam_username": "carol",
        "terminated_at": _well_outside_grace_iso(),
    }
    result = _run(json.dumps(entry) + "\n")
    assert result.returncode == 0
    plan = json.loads(result.stdout.strip().splitlines()[0])
    assert plan["action"] == "skip"
    assert "Invalid recipient_account_id" in plan["reason"]


def test_dry_run_redacts_unknown_fields():
    """Plan output should only carry the known schema. HR-side noise
    (employee_id, manager, salary_band, etc.) must not surface in the
    audited plan."""
    entry = {
        "email": "dave@example.com",
        "recipient_account_id": "123456789012",
        "iam_username": "dave",
        "terminated_at": _well_outside_grace_iso(),
        "salary_band": "L7",
        "manager_email": "boss@example.com",
        "ssn_last4": "1234",
    }
    result = _run(json.dumps(entry) + "\n")
    assert result.returncode == 0
    plan = json.loads(result.stdout.strip().splitlines()[0])
    assert "salary_band" not in plan["entry"]
    assert "manager_email" not in plan["entry"]
    assert "ssn_last4" not in plan["entry"]


def test_dry_run_handles_blank_lines():
    entry = {
        "email": "ed@example.com",
        "recipient_account_id": "123456789012",
        "iam_username": "ed",
        "terminated_at": _well_outside_grace_iso(),
    }
    stdin = "\n" + json.dumps(entry) + "\n\n"
    result = _run(stdin)
    assert result.returncode == 0
    summary = json.loads(result.stderr.strip().splitlines()[-1])
    assert summary["actions"] == 1
