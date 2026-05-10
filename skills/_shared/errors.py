"""SkillError hierarchy + structured error envelope.

Every shipped skill — and every runner / wrapper that hosts skills —
emits errors in one shape so SIEMs and reviewers don't need a
per-skill parser. The shape mirrors the wrapper's audit envelope:
correlation_id, error_class (bucketed for routing), error_type
(specific exception name), retryable, and a redacted message.

The hierarchy is deliberately small:

    SkillError                       # base; catch this in callers
    ├── ConfigError                  # missing env / bad SKILL.md / bad CLI args
    ├── AuthError                    # 401 / 403 / no creds / bad role
    ├── PermanentError               # 4xx that retries cannot fix
    ├── TransientError               # rate-limited / 5xx / network blip
    └── ContractError                # caller violated the skill contract
                                     # (e.g. mismatched OCSF class, wrong CLI
                                     # entrypoint invocation)

Use `emit_error(...)` from a skill's `__main__` to write a single
JSON object on stdout AND a parallel record on stderr so the OCSF
output stream stays clean while operators still see the failure.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from typing import Any


class SkillError(Exception):
    """Base for every error a skill emits programmatically.

    Subclass attributes:
      retryable: whether the caller should rerun the skill on the same
        input (only `TransientError` is True).
      error_class: bucket the SIEM filters on. Aligns with the
        SkillError subclass.
    """

    retryable: bool = False
    error_class: str = "skill_error"

    def __init__(self, message: str, *, redacted: str | None = None, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.redacted = redacted or message
        self.hint = hint or ""


class ConfigError(SkillError):
    retryable = False
    error_class = "config"


class AuthError(SkillError):
    retryable = False
    error_class = "auth"


class PermanentError(SkillError):
    retryable = False
    error_class = "permanent"


class TransientError(SkillError):
    retryable = True
    error_class = "transient"


class ContractError(SkillError):
    retryable = False
    error_class = "contract"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _correlation_id() -> str:
    return os.environ.get("SKILL_CORRELATION_ID", "")


def emit_error(
    skill_name: str,
    exc: BaseException,
    *,
    correlation_id: str | None = None,
    extra: dict[str, Any] | None = None,
    stdout: Any | None = None,
    stderr: Any | None = None,
) -> int:
    """Write one structured error record per emit. Returns the exit code
    the caller should use:

      - 1 for `ConfigError` / `PermanentError` / `ContractError`
      - 2 for `AuthError`
      - 75 (`EX_TEMPFAIL`) for `TransientError`
      - 1 for unknown exceptions

    Stdout gets a single JSON object so the rest of the pipeline (which
    expects JSONL) parses it normally. Stderr gets the same record so a
    human tail-reader sees it.
    """
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    if isinstance(exc, SkillError):
        error_class = exc.error_class
        retryable = exc.retryable
        redacted = exc.redacted
        hint = exc.hint
    else:
        error_class = "unhandled"
        retryable = False
        redacted = type(exc).__name__
        hint = ""

    record = {
        "event": "skill_error",
        "timestamp": _now_iso(),
        "skill": skill_name,
        "correlation_id": correlation_id or _correlation_id(),
        "error_class": error_class,
        "error_type": type(exc).__name__,
        "retryable": retryable,
        "message": redacted,
        "hint": hint,
    }
    if extra:
        # Operator-supplied annotations (region, account_id, account_count,
        # etc). Refused if they collide with reserved keys to keep the
        # SIEM contract stable.
        reserved = set(record)
        for key, value in extra.items():
            if key in reserved:
                raise ValueError(f"`extra` key `{key}` collides with the reserved error envelope")
            record[key] = value

    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    out.write(line)
    out.flush()
    err.write(line)
    err.flush()

    if isinstance(exc, AuthError):
        return 2
    if isinstance(exc, TransientError):
        return 75  # EX_TEMPFAIL — the runner / wrapper retries the call
    return 1
