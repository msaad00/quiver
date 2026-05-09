"""Defensive env-var parsing helpers.

Skills tune behavior via env vars (window sizes, thresholds, milliseconds).
The historical pattern was a per-skill `_env_int` that silently fell back to
the default when the value didn't parse — operators thought they tuned the
skill, but a typo silently kept the original behavior.

These helpers fall back to the default *and* emit a structured warning so the
fallback is visible in stderr telemetry. Setting `CLOUD_SECURITY_STRICT_ENV=1`
makes parse failures fatal for environments that prefer fail-closed.
"""

from __future__ import annotations

import os

from skills._shared.runtime_telemetry import emit_stderr_event

STRICT_ENV_VAR = "CLOUD_SECURITY_STRICT_ENV"


def _strict() -> bool:
    return os.environ.get(STRICT_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def _emit_parse_failure(skill_name: str, name: str, raw: str, default: object) -> None:
    emit_stderr_event(
        skill_name,
        level="warning",
        event="env_parse_failed",
        message=(
            f"env var {name}={raw!r} did not parse; falling back to default {default!r}. "
            "Set CLOUD_SECURITY_STRICT_ENV=1 to fail closed instead."
        ),
        env=name,
        raw=raw,
        default=default,
    )


def env_int(name: str, default: int, *, skill_name: str) -> int:
    """Parse an integer env var, warn on failure, fall back to default."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        if _strict():
            raise
        _emit_parse_failure(skill_name, name, raw, default)
        return default


def env_float(name: str, default: float, *, skill_name: str) -> float:
    """Parse a float env var, warn on failure, fall back to default."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        if _strict():
            raise
        _emit_parse_failure(skill_name, name, raw, default)
        return default


def env_ms(name: str, default_ms: int, *, skill_name: str) -> int:
    """Parse a millisecond env var as int. Same semantics as `env_int`."""
    return env_int(name, default_ms, skill_name=skill_name)
