"""FastAPI receiver — wires HTTP POST → atomic ingest skill → sink fan-out.

Single endpoint shape: `POST /webhook/<skill-name>`. Defaults are
default-deny so a fresh deployment cannot route any payload until
`WEBHOOK_ALLOWED_SKILLS` opts a skill in.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# FastAPI is intentionally an extras-only dependency. Importing this
# module without FastAPI installed surfaces a clear error so operators
# know which extras to add.
try:  # pragma: no cover - exercised only when extra is missing
    from fastapi import FastAPI, HTTPException, Request, Response
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "runners.webhook-receiver requires `fastapi`. Install with "
        "`uv sync --group dev --extra webhook` (or pin fastapi in your "
        "deployment image)."
    ) from exc

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from auth import verify_bearer, verify_hmac  # noqa: E402  pylint: disable=wrong-import-position
from router import REPO_ROOT, resolve  # noqa: E402  pylint: disable=wrong-import-position
from sinks import (  # noqa: E402  pylint: disable=wrong-import-position
    SinkResult,
    fan_out,
    new_correlation_id,
)

app = FastAPI(
    title="cloud-ai-security-skills · webhook receiver",
    docs_url=None,
    redoc_url=None,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _emit_audit(event: dict[str, Any]) -> None:
    """Best-effort audit emit — same shape as the MCP wrapper.

    stderr is the always-on sink; if `CLOUD_SECURITY_MCP_AUDIT_LOG` is
    set the receiver appends one line per resolved request to that
    file with `os.fsync()`.
    """
    line = json.dumps(event, sort_keys=True) + "\n"
    sys.stderr.write(line)
    sys.stderr.flush()
    log_path = (os.environ.get("CLOUD_SECURITY_MCP_AUDIT_LOG") or "").strip()
    if not log_path:
        return
    try:
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:  # pragma: no cover - audit best-effort
        pass


def _sink_results_to_dict(results: list[SinkResult]) -> list[dict[str, Any]]:
    return [
        {
            "target": r.target,
            "ok": r.ok,
            "exit_code": r.exit_code,
            "correlation_id": r.correlation_id,
            "error": r.error,
        }
        for r in results
    ]


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "webhook-receiver"}


@app.post("/webhook/{skill_name}")
async def webhook(skill_name: str, request: Request) -> Response:
    started = time.monotonic()
    correlation_id = new_correlation_id()
    body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    audit_event: dict[str, Any] = {
        "event": "webhook_request",
        "timestamp": _now_iso(),
        "correlation_id": correlation_id,
        "skill": skill_name,
        "payload_sha256": hashlib.sha256(body).hexdigest() if body else "",
        "payload_length": len(body),
        "result": "pending",
    }

    try:
        # 1) Routing — closed-set: unknown / wrong-category / not allowlisted.
        resolution = resolve(skill_name)
        if not resolution.found:
            audit_event["result"] = "error"
            audit_event["error_type"] = "skill_not_found"
            audit_event["error_message"] = resolution.reason
            raise HTTPException(status_code=404, detail=resolution.reason)
        if not resolution.allowed:
            audit_event["result"] = "error"
            audit_event["error_type"] = "skill_not_allowed"
            audit_event["error_message"] = resolution.reason
            raise HTTPException(status_code=403, detail=resolution.reason)

        # 2) Auth — HMAC then bearer; either failure aborts before subprocess.
        hmac_result = verify_hmac(skill_name, headers, body)
        if not hmac_result.ok:
            audit_event["result"] = "error"
            audit_event["error_type"] = hmac_result.reason
            raise HTTPException(status_code=401, detail=hmac_result.reason)
        bearer_result = verify_bearer(headers)
        if not bearer_result.ok:
            audit_event["result"] = "error"
            audit_event["error_type"] = bearer_result.reason
            raise HTTPException(status_code=401, detail=bearer_result.reason)

        # 3) Skill execution — feed the raw body to stdin, capture OCSF JSONL.
        skill = resolution.skill
        assert skill is not None and skill.entrypoint is not None
        completed = subprocess.run(
            [sys.executable, str(skill.entrypoint)],
            input=body,
            capture_output=True,
            cwd=REPO_ROOT,
            env={
                **{k: v for k, v in os.environ.items() if k.startswith("CLOUD_SECURITY_")},
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                "PYTHONUNBUFFERED": "1",
                "SKILL_CORRELATION_ID": correlation_id,
            },
            check=False,
            timeout=120,
        )
        audit_event["skill_exit_code"] = completed.returncode
        audit_event["stdout_length"] = len(completed.stdout)
        if completed.returncode != 0:
            audit_event["result"] = "error"
            audit_event["error_type"] = "skill_failed"
            audit_event["error_message"] = (completed.stderr or b"").decode(
                "utf-8", errors="replace"
            )[-512:]
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "skill_failed",
                    "exit_code": completed.returncode,
                    "stderr": (completed.stderr or b"").decode("utf-8", errors="replace")[-512:],
                },
            )

        # 4) Sink fan-out — best effort, surface per-target results.
        sink_results = fan_out(completed.stdout, correlation_id)
        audit_event["sink_results"] = _sink_results_to_dict(sink_results)
        audit_event["result"] = "success"
        return Response(
            content=json.dumps(
                {
                    "correlation_id": correlation_id,
                    "skill": skill_name,
                    "skill_exit_code": completed.returncode,
                    "stdout_length": len(completed.stdout),
                    "sink_results": _sink_results_to_dict(sink_results),
                }
            ),
            media_type="application/json",
            status_code=200,
        )
    except HTTPException:
        raise
    except subprocess.TimeoutExpired as exc:
        audit_event["result"] = "error"
        audit_event["error_type"] = "skill_timeout"
        audit_event["error_message"] = f"skill timed out after {exc.timeout}s"
        raise HTTPException(status_code=504, detail="skill timed out") from exc
    except Exception as exc:  # pragma: no cover - last-resort safety net
        audit_event["result"] = "error"
        audit_event["error_type"] = type(exc).__name__
        audit_event["error_message"] = str(exc)
        raise
    finally:
        audit_event["duration_ms"] = int((time.monotonic() - started) * 1000)
        _emit_audit(audit_event)
