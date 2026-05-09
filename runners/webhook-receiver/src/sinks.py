"""Sink fan-out — pipe each ingest output line through every configured
shipped sink skill. Sinks are subprocesses (matching the MCP wrapper
contract); each one gets its own correlation_id so the audit chain
joins back to the originating webhook request.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

# Map of operator-friendly sink name -> shipped skill entrypoint.
_SINK_SKILL_NAMES: dict[str, str] = {
    "s3": "sink-s3-jsonl",
    "snowflake": "sink-snowflake-jsonl",
    "clickhouse": "sink-clickhouse-jsonl",
}


@dataclass(frozen=True)
class SinkResult:
    target: str
    ok: bool
    exit_code: int
    correlation_id: str
    error: str = ""


def _sink_targets(env: dict[str, str] | None = None) -> list[str]:
    src = os.environ if env is None else env
    raw = (src.get("WEBHOOK_SINK_TARGETS") or "").strip()
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def _sink_entrypoint(skill_name: str) -> Path | None:
    """Resolve a sink skill name to its `src/sink.py` entrypoint.

    We don't go through `tool_registry` here because the receiver wants a
    deterministic path and a sink skill's entrypoint name is fixed by
    convention.
    """
    candidate = REPO_ROOT / "skills" / "output" / skill_name / "src" / "sink.py"
    return candidate if candidate.is_file() else None


def fan_out(
    body: bytes,
    parent_correlation_id: str,
    *,
    env: dict[str, str] | None = None,
) -> list[SinkResult]:
    """Stream `body` (the ingest skill's stdout JSONL) through each
    configured sink. Returns one `SinkResult` per target so the response
    payload and audit record can surface partial failures.
    """
    src = os.environ if env is None else env
    results: list[SinkResult] = []
    for target in _sink_targets(env):
        skill_name = _SINK_SKILL_NAMES.get(target)
        if skill_name is None:
            results.append(
                SinkResult(
                    target=target,
                    ok=False,
                    exit_code=-1,
                    correlation_id="",
                    error=f"unknown sink target `{target}`",
                )
            )
            continue
        entry = _sink_entrypoint(skill_name)
        if entry is None:
            results.append(
                SinkResult(
                    target=target,
                    ok=False,
                    exit_code=-1,
                    correlation_id="",
                    error=f"entrypoint missing for `{skill_name}`",
                )
            )
            continue
        cid = f"{parent_correlation_id}.{target}"
        sink_env = _build_child_env(src, cid)
        try:
            completed = subprocess.run(
                [sys.executable, str(entry)],
                input=body,
                capture_output=True,
                cwd=REPO_ROOT,
                env=sink_env,
                check=False,
                timeout=120,
            )
            results.append(
                SinkResult(
                    target=target,
                    ok=completed.returncode == 0,
                    exit_code=completed.returncode,
                    correlation_id=cid,
                    error=(completed.stderr or b"").decode("utf-8", errors="replace")[-512:]
                    if completed.returncode != 0
                    else "",
                )
            )
        except subprocess.TimeoutExpired as exc:
            results.append(
                SinkResult(
                    target=target,
                    ok=False,
                    exit_code=-1,
                    correlation_id=cid,
                    error=f"timeout after {exc.timeout}s",
                )
            )
    return results


_SAFE_CHILD_ENV_VARS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "PYTHONHOME",
    "PYTHONPATH",
    "TZ",
    "USER",
    "VIRTUAL_ENV",
)


def _build_child_env(src: dict[str, str], correlation_id: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for key in _SAFE_CHILD_ENV_VARS:
        value = src.get(key)
        if value:
            env[key] = value
    for key, raw_value in src.items():
        if not key.startswith("CLOUD_SECURITY_"):
            continue
        value = raw_value.strip()
        if value:
            env[key] = value
    env["PYTHONUNBUFFERED"] = "1"
    env["SKILL_CORRELATION_ID"] = correlation_id
    return env


def new_correlation_id() -> str:
    return str(uuid.uuid4())
