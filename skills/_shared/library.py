"""Python SDK shim — call shipped skills as library functions.

Today every skill runs as a subprocess (CLI / CI / MCP / runner). For
external applications that already live in a Python process, spawning
a fresh interpreter per call is overkill — the SDK shim wraps the same
shipped tool registry behind a clean callable surface:

    from skills._shared.library import SkillsClient

    client = SkillsClient(allowed_skills=["ingest-cloudtrail-ocsf",
                                          "detect-aws-access-key-creation"])

    # ingest+detect a captured fixture, fan-out free
    raw = open("cloudtrail.jsonl", "rb").read()
    result = client.invoke("ingest-cloudtrail-ocsf", stdin=raw)
    findings = client.invoke(
        "detect-aws-access-key-creation",
        stdin=result.stdout,
    )

The client honours the same trust controls the MCP wrapper enforces:

  - operator allowlist (`allowed_skills` arg or `CLOUD_SECURITY_MCP_ALLOWED_SKILLS`)
  - caller allowlist intersection
  - read-only / dry-run / HITL gates (writes refused unless --dry-run
    or --apply with `_approval_context`)
  - SAFE_CHILD_ENV_VARS scrub on every subprocess
  - audit envelope on every call (same shape as MCP)
  - RLIMIT_AS / FSIZE / CPU caps via the existing resource_limits module

The shim does not bypass the subprocess boundary — that boundary is
where every guardrail lives. It just hides the JSON-RPC framing so a
calling Python program does not have to assemble Content-Length
headers.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[2]
_MCP_SRC = REPO_ROOT / "mcp-server" / "src"
if str(_MCP_SRC) not in sys.path:
    sys.path.insert(0, str(_MCP_SRC))

import sandbox as _sandbox  # noqa: E402
from resource_limits import from_env as _resource_limits_from_env  # noqa: E402
from resource_limits import make_preexec as _make_preexec  # noqa: E402
from tool_registry import (  # noqa: E402
    SkillSpec,
    build_command,
    repo_root,
    tool_map,
)

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


@dataclass(frozen=True)
class SkillResult:
    """Return shape from `SkillsClient.invoke`. Matches the MCP wrapper's
    `structuredContent` so the same audit-log analysis code works."""

    skill: str
    correlation_id: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class SkillNotAllowed(Exception):
    """The requested skill is unknown, in the wrong category, or outside
    the configured allowlist."""


class SkillCallRefused(Exception):
    """A guard rejected the call (write-without-dry-run, missing approval,
    not enough approvers)."""


@dataclass
class SkillsClient:
    """Library entrypoint to the same tool registry the MCP wrapper uses.

    `allowed_skills` is the *operator-level* allowlist. External callers
    pass the smallest set their workflow needs. The constructor refuses
    skill names that aren't on disk, so a typo fails at construction
    instead of on the first invocation.
    """

    allowed_skills: tuple[str, ...] = ()
    timeout_seconds: int = 60
    audit_writer: Any | None = None  # callable: (event_dict) -> None

    _tool_map: dict[str, SkillSpec] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._tool_map = tool_map(repo_root())
        unknown = [s for s in self.allowed_skills if s not in self._tool_map]
        if unknown:
            raise SkillNotAllowed(
                f"unknown skill(s): {sorted(unknown)}. Pass only names that ship in `skills/`."
            )

    def list_skills(self) -> list[str]:
        """Return the effective tool surface — operator allowlist applied."""
        if not self.allowed_skills:
            return sorted(self._tool_map.keys())
        return sorted(self.allowed_skills)

    def invoke(
        self,
        skill_name: str,
        *,
        args: list[str] | None = None,
        stdin: bytes | str | None = None,
        approval_context: dict[str, Any] | None = None,
    ) -> SkillResult:
        """Call one skill and return its `SkillResult`.

        Refuses unknown skills, write-capable skills without `--dry-run`,
        and write-capable skills missing required `approval_context`.
        Same guardrails the MCP wrapper enforces; same audit shape.
        """
        if self.allowed_skills and skill_name not in self.allowed_skills:
            raise SkillNotAllowed(
                f"skill `{skill_name}` is not in the configured allowlist"
            )
        skill = self._tool_map.get(skill_name)
        if skill is None:
            raise SkillNotAllowed(f"unknown skill `{skill_name}`")
        args = list(args or [])

        if not self._is_safe_write(skill, args):
            raise SkillCallRefused(
                f"skill `{skill_name}` is write-capable; library callers must "
                f"pass `--dry-run` (or omit `--apply` for handler/checks entrypoints)"
            )
        if self._needs_approval(skill, args):
            if approval_context is None:
                raise SkillCallRefused(
                    f"skill `{skill_name}` requires an approval_context dict"
                )
            min_approvers = skill.min_approvers or 0
            if min_approvers > _approval_count(approval_context):
                raise SkillCallRefused(
                    f"skill `{skill_name}` requires at least {min_approvers} approver(s)"
                )

        correlation_id = str(uuid4())
        env = self._build_child_env(correlation_id, approval_context)
        if isinstance(stdin, str):
            stdin_bytes = stdin.encode("utf-8")
        elif stdin is None:
            stdin_bytes = b""
        else:
            stdin_bytes = stdin

        limits = _resource_limits_from_env(self.timeout_seconds)
        command = build_command(skill, args)
        sandbox_active = _sandbox.is_enabled()
        if sandbox_active:
            command = _sandbox.wrap_command(command, skill)
        sandboxed = bool(
            sandbox_active and command and command[0] in {"bwrap", "sandbox-exec"}
        )
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                input=stdin_bytes,
                capture_output=True,
                cwd=repo_root(),
                env=env,
                timeout=self.timeout_seconds,
                check=False,
                preexec_fn=_make_preexec(limits) if os.name == "posix" else None,
            )
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)

        result = SkillResult(
            skill=skill_name,
            correlation_id=correlation_id,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_ms=duration_ms,
        )
        self._emit_audit(skill, result, sandboxed=sandboxed)
        return result

    # ── internals ───────────────────────────────────────────────────

    def _is_safe_write(self, skill: SkillSpec, args: list[str]) -> bool:
        if skill.read_only:
            return True
        if skill.category == "remediation" and skill.entrypoint and skill.entrypoint.name == "handler.py":
            return "--apply" not in args
        if skill.category == "evaluation" and skill.entrypoint and skill.entrypoint.name == "checks.py":
            return "--apply" not in args
        return "--dry-run" in args

    def _needs_approval(self, skill: SkillSpec, args: list[str]) -> bool:
        if skill.read_only or not skill.approver_roles:
            return False
        if skill.category == "evaluation" and skill.entrypoint and skill.entrypoint.name == "checks.py":
            return "--apply" in args
        return True

    def _build_child_env(
        self,
        correlation_id: str,
        approval_context: dict[str, Any] | None,
    ) -> dict[str, str]:
        env: dict[str, str] = {}
        for key in _SAFE_CHILD_ENV_VARS:
            value = os.environ.get(key)
            if value:
                env[key] = value
        for key, raw_value in os.environ.items():
            if not key.startswith("CLOUD_SECURITY_"):
                continue
            value = raw_value.strip()
            if value:
                env[key] = value
        env["PYTHONUNBUFFERED"] = "1"
        env["SKILL_CORRELATION_ID"] = correlation_id
        if approval_context:
            for src_key, dst_key in (
                ("approver_id", "SKILL_APPROVER_ID"),
                ("approver_email", "SKILL_APPROVER_EMAIL"),
                ("ticket_id", "SKILL_APPROVAL_TICKET"),
                ("approval_timestamp", "SKILL_APPROVAL_TIMESTAMP"),
            ):
                v = approval_context.get(src_key)
                if isinstance(v, str) and v:
                    env[dst_key] = v
        return env

    def _emit_audit(self, skill: SkillSpec, result: SkillResult, *, sandboxed: bool = False) -> None:
        record = {
            "event": "skills_library_call",
            "timestamp": datetime.now(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "correlation_id": result.correlation_id,
            "skill": skill.name,
            "category": skill.category,
            "capability": skill.capability,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "stdout_length": len(result.stdout),
            "stderr_length": len(result.stderr),
            "result": "success" if result.ok else "error",
            "sandboxed": sandboxed,
        }
        if self.audit_writer is not None:
            try:
                self.audit_writer(record)
            except Exception:  # pragma: no cover - audit must never crash the call
                pass
        else:
            sys.stderr.write(json.dumps(record, sort_keys=True) + "\n")
            sys.stderr.flush()


def _approval_count(approval_context: dict[str, Any] | None) -> int:
    if not approval_context:
        return 0
    seen: set[str] = set()
    for key in ("approver_emails", "approver_ids"):
        values = approval_context.get(key) or []
        if isinstance(values, list):
            for v in values:
                if isinstance(v, str) and v.strip():
                    seen.add(v.strip())
    if seen:
        return len(seen)
    for key in ("approver_email", "approver_id"):
        v = approval_context.get(key)
        if isinstance(v, str) and v.strip():
            return 1
    return 0
