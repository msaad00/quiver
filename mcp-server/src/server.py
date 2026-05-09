from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, cast
from uuid import uuid4

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from tool_registry import (  # noqa: E402
    SkillSpec,
    build_command,
    repo_root,
    tool_definition,
    tool_map,
)

SERVER_NAME = "cloud-ai-security-skills"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2025-06-18"
DEFAULT_TIMEOUT_SECONDS = 60
ALLOWED_SKILLS_ENV = "CLOUD_SECURITY_MCP_ALLOWED_SKILLS"
REQUIRE_CALLER_ALLOWED_SKILLS_ENV = "CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS"

# Server-defined JSON-RPC error codes (reserved range -32000..-32099 per spec).
# Documented in docs/MCP_AUDIT_CONTRACT.md so clients can distinguish causes.
ERROR_TOOL_TIMEOUT = -32001
ERROR_TOOL_NOT_ALLOWED = -32002
ERROR_APPROVAL_REQUIRED = -32003
ERROR_TOOL_CRASHED = -32004
SAFE_CHILD_ENV_VARS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "PATH",
    "PATHEXT",
    "PYTHONHOME",
    "PYTHONPATH",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
    "VIRTUAL_ENV",
    "WINDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
)


def _skill_name_set(raw: str) -> set[str]:
    return {part.strip() for part in raw.split(",") if part.strip()}


def _allowed_skills_filter() -> set[str] | None:
    """Return the set of skill names the current process is allowed to expose.

    `None` = no filter (default, all skills exposed). A non-empty comma-separated
    `CLOUD_SECURITY_MCP_ALLOWED_SKILLS` value restricts both `tools/list` and
    `tools/call` to the named skills — the model cannot call what isn't listed.
    Whitespace around names is tolerated; an empty string is treated as unset.
    """
    raw = os.environ.get(ALLOWED_SKILLS_ENV, "").strip()
    if not raw:
        return None
    return _skill_name_set(raw)


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _caller_allowed_skills_filter(caller_context: dict[str, Any] | None) -> set[str] | None:
    if caller_context is None or "allowed_skills" not in caller_context:
        return None
    raw_allowed = caller_context["allowed_skills"]
    if isinstance(raw_allowed, str):
        return _skill_name_set(raw_allowed)
    return {name.strip() for name in cast(list[str], raw_allowed) if name.strip()}


def _effective_allowed_skills(caller_context: dict[str, Any] | None) -> set[str] | None:
    process_allowed = _allowed_skills_filter()
    caller_allowed = _caller_allowed_skills_filter(caller_context)
    if _truthy_env(REQUIRE_CALLER_ALLOWED_SKILLS_ENV) and caller_allowed is None:
        return set()
    if process_allowed is None:
        return caller_allowed
    if caller_allowed is None:
        return process_allowed
    return process_allowed & caller_allowed


def _filtered_tool_map() -> dict[str, SkillSpec]:
    """`tool_map()` plus the operator-scoped allowlist, if any."""
    return _scoped_tool_map()


def _scoped_tool_map(
    caller_context: dict[str, Any] | None = None,
    tools: dict[str, SkillSpec] | None = None,
) -> dict[str, SkillSpec]:
    """`tool_map()` plus operator and caller-scoped allowlists, if any."""
    tools = tool_map() if tools is None else tools
    allowed = _effective_allowed_skills(caller_context)
    if allowed is None:
        return tools
    return {name: spec for name, spec in tools.items() if name in allowed}


def _resolve_timeout(skill: SkillSpec, env: dict[str, str]) -> int:
    """Resolve the per-call subprocess timeout.

    Priority: env override > skill-declared timeout > global default. The env
    override is kept at the top so operators can widen or tighten the window
    without editing every SKILL.md.
    """
    override = env.get("CLOUD_SECURITY_MCP_TIMEOUT_SECONDS", "").strip()
    if override:
        return int(override)
    if skill.mcp_timeout_seconds is not None:
        return skill.mcp_timeout_seconds
    return DEFAULT_TIMEOUT_SECONDS


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stable_hash(payload: Any) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _emit_audit_event(event: dict[str, Any]) -> None:
    sys.stderr.write(json.dumps(event, sort_keys=True) + "\n")
    sys.stderr.flush()


def _error_response(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def _result_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _read_message(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        name, value = line.decode("utf-8").split(":", 1)
        headers[name.strip().lower()] = value.strip()

    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    payload = stream.read(length)
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("JSON-RPC message payload must be an object")
    return cast(dict[str, Any], decoded)


def _write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    payload = json.dumps(message).encode("utf-8")
    stream.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8"))
    stream.write(payload)
    stream.flush()


def _validate_args(raw_args: Any) -> list[str]:
    if raw_args is None:
        return []
    if not isinstance(raw_args, list) or not all(isinstance(arg, str) for arg in raw_args):
        raise ValueError("`args` must be an array of strings")
    return raw_args


def _validate_input(raw_input: Any) -> str:
    if raw_input is None:
        return ""
    if not isinstance(raw_input, str):
        raise ValueError("`input` must be a string")
    return raw_input


def _validate_output_format(raw_output_format: Any) -> str | None:
    if raw_output_format is None:
        return None
    if not isinstance(raw_output_format, str):
        raise ValueError("`output_format` must be a string")
    return raw_output_format


def _validate_context(raw_context: Any, field_name: str) -> dict[str, Any] | None:
    if raw_context is None:
        return None
    if not isinstance(raw_context, dict):
        raise ValueError(f"`{field_name}` must be an object")
    validated: dict[str, Any] = {}
    for key, value in raw_context.items():
        if not isinstance(key, str):
            raise ValueError(f"`{field_name}` keys must be strings")
        if isinstance(value, str):
            validated[key] = value
            continue
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            validated[key] = cast(list[str], value)
            continue
        raise ValueError(f"`{field_name}.{key}` must be a string or array of strings")
    return validated


def _unique_nonempty_strings(raw_values: Any) -> list[str]:
    if not isinstance(raw_values, list):
        return []
    values: list[str] = []
    seen: set[str] = set()
    for item in raw_values:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        values.append(normalized)
    return values


def _distinct_approvers(approval_context: dict[str, Any] | None) -> list[str]:
    if not approval_context:
        return []
    approver_ids = _unique_nonempty_strings(approval_context.get("approver_ids"))
    approver_emails = _unique_nonempty_strings(approval_context.get("approver_emails"))
    if len(approver_emails) >= len(approver_ids) and approver_emails:
        return approver_emails
    if approver_ids:
        return approver_ids

    approver_id = str(approval_context.get("approver_id") or "").strip()
    approver_email = str(approval_context.get("approver_email") or "").strip()
    if approver_id or approver_email:
        return [approver_email or approver_id]
    return []


def _approval_count(approval_context: dict[str, Any] | None) -> int:
    return len(_distinct_approvers(approval_context))


def _caller_scope_audit_fields(caller_context: dict[str, Any] | None) -> dict[str, Any]:
    allowed = _caller_allowed_skills_filter(caller_context)
    if allowed is None:
        return {
            "caller_skill_scope_provided": False,
            "caller_skill_scope_count": 0,
            "caller_skill_scope_hash": "",
        }
    sorted_allowed = sorted(allowed)
    return {
        "caller_skill_scope_provided": True,
        "caller_skill_scope_count": len(sorted_allowed),
        "caller_skill_scope_hash": _stable_hash(sorted_allowed),
    }


def _build_child_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in SAFE_CHILD_ENV_VARS:
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
    return env


def _is_safe_write_invocation(skill: SkillSpec, args: list[str]) -> bool:
    """Return True when the requested invocation is dry-run/read-only at the
    wrapper boundary.

    Remediation `handler.py` and evaluation `checks.py` entrypoints can be
    dry-run by default and only write when `--apply` is present, so allow those
    tools to run as long as `--apply` is absent. Other write-capable categories
    keep the stricter explicit `--dry-run` requirement.
    """
    if skill.read_only:
        return True
    if skill.category == "remediation" and skill.entrypoint and skill.entrypoint.name == "handler.py":
        return "--apply" not in args
    if skill.category == "evaluation" and skill.entrypoint and skill.entrypoint.name == "checks.py":
        return "--apply" not in args
    return "--dry-run" in args


def _requires_approval_context(skill: SkillSpec, args: list[str]) -> bool:
    if skill.read_only or not skill.approver_roles:
        return False
    if skill.category == "evaluation" and skill.entrypoint and skill.entrypoint.name == "checks.py":
        return "--apply" in args
    return True


def _call_tool(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    request_args = arguments or {}
    caller_context = _validate_context(request_args.get("_caller_context"), "_caller_context")
    tools = tool_map()
    if name not in tools:
        raise KeyError(f"unknown tool `{name}`")

    skill = tools[name]
    args = _validate_args(request_args.get("args"))
    stdin_text = _validate_input(request_args.get("input"))
    output_format = _validate_output_format(request_args.get("output_format"))
    approval_context = _validate_context(request_args.get("_approval_context"), "_approval_context")
    correlation_id = str(uuid4())
    started = time.monotonic()
    audit_event: dict[str, Any] = {
        "event": "mcp_tool_call",
        "timestamp": _now_iso(),
        "correlation_id": correlation_id,
        "tool": name,
        "category": skill.category,
        "capability": skill.capability,
        "read_only": skill.read_only,
        "output_format": output_format or "default",
        "args_hash": _stable_hash(args),
        "args_count": len(args),
        "input_sha256": hashlib.sha256(stdin_text.encode("utf-8")).hexdigest() if stdin_text else "",
        "input_length": len(stdin_text),
        "caller_context_provided": caller_context is not None,
        "approval_context_provided": approval_context is not None,
        "approval_count": _approval_count(approval_context),
        "caller_id": caller_context.get("user_id", "") if caller_context else "",
        "caller_session_id": caller_context.get("session_id", "") if caller_context else "",
        "approval_ticket": approval_context.get("ticket_id", "") if approval_context else "",
        "result": "pending",
    }
    audit_event.update(_caller_scope_audit_fields(caller_context))

    try:
        if name not in _scoped_tool_map(caller_context, tools):
            raise KeyError(f"unknown tool `{name}`")
        if not _is_safe_write_invocation(skill, args):
            raise ValueError(
                "write-capable tools must stay in dry-run/read-only mode under MCP "
                "(`--dry-run`, or no `--apply` for dry-run-default handler/checks entrypoints)"
            )
        if _requires_approval_context(skill, args) and approval_context is None:
            raise ValueError("write-capable tools with approver_roles require `_approval_context`")
        if _requires_approval_context(skill, args) and (skill.min_approvers or 0) > _approval_count(approval_context):
            raise ValueError(
                f"tool `{skill.name}` requires at least {skill.min_approvers} approver(s) in `_approval_context`"
            )

        env = _build_child_env()
        env["SKILL_CORRELATION_ID"] = correlation_id
        if caller_context:
            if "user_id" in caller_context:
                env["SKILL_CALLER_ID"] = caller_context["user_id"]
            if "email" in caller_context:
                env["SKILL_CALLER_EMAIL"] = caller_context["email"]
            if "session_id" in caller_context:
                env["SKILL_SESSION_ID"] = caller_context["session_id"]
            if "roles" in caller_context:
                env["SKILL_CALLER_ROLES"] = ",".join(caller_context["roles"])
            allowed_skills = _caller_allowed_skills_filter(caller_context)
            if allowed_skills is not None:
                env["SKILL_CALLER_ALLOWED_SKILLS"] = ",".join(sorted(allowed_skills))
        if approval_context:
            if "approver_id" in approval_context:
                env["SKILL_APPROVER_ID"] = approval_context["approver_id"]
            if "approver_email" in approval_context:
                env["SKILL_APPROVER_EMAIL"] = approval_context["approver_email"]
            approver_ids = _unique_nonempty_strings(approval_context.get("approver_ids"))
            approver_emails = _unique_nonempty_strings(approval_context.get("approver_emails"))
            if approver_ids:
                env["SKILL_APPROVER_IDS"] = ",".join(approver_ids)
            if approver_emails:
                env["SKILL_APPROVER_EMAILS"] = ",".join(approver_emails)
            if "ticket_id" in approval_context:
                env["SKILL_APPROVAL_TICKET"] = approval_context["ticket_id"]
            if "approval_timestamp" in approval_context:
                env["SKILL_APPROVAL_TIMESTAMP"] = approval_context["approval_timestamp"]
        timeout_seconds = _resolve_timeout(skill, env)
        audit_event["timeout_seconds"] = timeout_seconds
        completed = subprocess.run(
            build_command(skill, args, output_format=output_format),
            input=stdin_text,
            text=True,
            capture_output=True,
            cwd=repo_root(),
            env=env,
            timeout=timeout_seconds,
            check=False,
        )

        audit_event["result"] = "error" if completed.returncode != 0 else "success"
        audit_event["exit_code"] = completed.returncode
        output_text = completed.stdout or completed.stderr or ""
        return {
            "content": [{"type": "text", "text": output_text}],
            "structuredContent": {
                "skill": skill.name,
                "category": skill.category,
                "capability": skill.capability,
                "correlation_id": correlation_id,
                "output_format": output_format or "default",
                "caller_context_provided": caller_context is not None,
                "approval_context_provided": approval_context is not None,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "exit_code": completed.returncode,
            },
            "isError": completed.returncode != 0,
        }
    except Exception as exc:
        audit_event["result"] = "error"
        audit_event["error_type"] = type(exc).__name__
        audit_event["error_message"] = str(exc)
        raise
    finally:
        audit_event["duration_ms"] = int((time.monotonic() - started) * 1000)
        _emit_audit_event(audit_event)


def _handle_request(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return _result_response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )

    if method == "ping":
        return _result_response(request_id, {})

    if method == "tools/list":
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return _error_response(request_id, -32602, "`tools/list` params must be an object when present")
        try:
            caller_context = _validate_context(params.get("_caller_context"), "_caller_context")
        except ValueError as exc:
            return _error_response(request_id, -32602, str(exc))
        tools = [tool_definition(skill) for skill in _scoped_tool_map(caller_context).values()]
        return _result_response(request_id, {"tools": tools})

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        if not isinstance(name, str):
            return _error_response(request_id, -32602, "`tools/call` requires a string `name`")
        try:
            return _result_response(request_id, _call_tool(name, params.get("arguments")))
        except KeyError as exc:
            return _error_response(request_id, -32601, str(exc))
        except ValueError as exc:
            return _error_response(request_id, -32602, str(exc))
        except subprocess.TimeoutExpired as exc:
            return _error_response(
                request_id, ERROR_TOOL_TIMEOUT, f"tool timed out after {exc.timeout}s"
            )

    return _error_response(request_id, -32601, f"method not found: {method}")


def serve() -> int:
    while True:
        message = _read_message(sys.stdin.buffer)
        if message is None:
            return 0
        response = _handle_request(message)
        if response is not None:
            _write_message(sys.stdout.buffer, response)


if __name__ == "__main__":
    raise SystemExit(serve())
