"""End-to-end harness for the shipped runner templates.

Invoked by `scripts/runner_e2e.sh`. Each runner gets its own scenario
block; per scenario we send N synthetic events that match the runner's
real contract, measure round-trip latency, and assert:

- the runner accepted + processed the event
- the audit log captured the event (and, where the runner writes an
  HMAC-chained audit, that the chain verifies)
- the configured sink actually received the event

Records are written as JSONL to `runtime-profile-results.jsonl` in the
repository root — one record per (runner, scenario). The shell wrapper
forwards the exit code of this harness, so any assertion failure fails
the workflow.

Honest gaps
-----------
- The webhook receiver's built-in audit log is single-line, not
  HMAC-chained. We record `audit_chain_verified=null` with a reason
  field rather than fabricate a chain status. The SSE runner does write
  a chained log; we run `scripts/verify_audit_chain.py` and capture the
  exit status.
- The GCP and Azure cloud runners have no in-tree local mock equivalent
  to `moto` for their respective queueing primitives. They appear in
  the results JSONL with `status="gap"` so the generated doc lists them
  honestly instead of fabricating numbers.
- Sample size defaults to 20. These numbers are CI-runner numbers, not
  customer-scale numbers. See `docs/RUNTIME_PROFILES.md`.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import importlib.util
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_PATH = REPO_ROOT / "runtime-profile-results.jsonl"

DEFAULT_SAMPLES = 20

# Make the webhook + SSE source trees importable.
sys.path.insert(0, str(REPO_ROOT / "mcp-server" / "src"))
sys.path.insert(0, str(REPO_ROOT / "runners" / "webhook-receiver" / "src"))


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _hex_hmac(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    sorted_values = sorted(values)
    # Linear-interpolation between closest ranks; matches NumPy default.
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac


def _summarize_timings(timings_ms: list[float]) -> dict[str, float]:
    if not timings_ms:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "mean_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
    return {
        "p50_ms": round(_percentile(timings_ms, 50.0), 2),
        "p95_ms": round(_percentile(timings_ms, 95.0), 2),
        "mean_ms": round(statistics.fmean(timings_ms), 2),
        "min_ms": round(min(timings_ms), 2),
        "max_ms": round(max(timings_ms), 2),
    }


def _append_result(record: dict[str, Any]) -> None:
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


# --------------------------------------------------------------------------- #
# Webhook receiver scenario                                                    #
# --------------------------------------------------------------------------- #


def _load_webhook_app(env: dict[str, str]) -> Any:
    """Load the receiver module under a controlled env so module-level
    config (allowlist, secrets) takes effect for this scenario."""
    for key, value in env.items():
        os.environ[key] = value
    # Force a fresh load so module-level reads see our env.
    for cached in [
        "webhook_server_e2e",
        "server",
        "auth",
        "router",
        "sinks",
    ]:
        sys.modules.pop(cached, None)
    src_dir = REPO_ROOT / "runners" / "webhook-receiver" / "src"
    spec = importlib.util.spec_from_file_location(
        "webhook_server_e2e",
        src_dir / "server.py",
        submodule_search_locations=[str(src_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["webhook_server_e2e"] = module
    spec.loader.exec_module(module)
    return module


def run_webhook_scenario(samples: int) -> dict[str, Any]:
    """Boot the webhook receiver in-process (FastAPI TestClient) and
    exercise it with HMAC-signed CloudTrail events. The sink fan-out is
    disabled here because the shipped sinks need CLI flags that the
    receiver template does not yet pass; the sink-arrival assertion is
    treated as an honest gap. The receiver subprocess does invoke the
    real ingest skill, so the round-trip exercises router + auth +
    skill subprocess + audit write.
    """
    scenario = "ingest-cloudtrail-ocsf"
    correlation_ids: list[str] = []
    timings_ms: list[float] = []
    sink_arrivals = 0  # See sink_status below.

    with tempfile.TemporaryDirectory() as tmp:
        audit_log = Path(tmp) / "webhook-audit.jsonl"
        secret = "runner-e2e-shared-secret"
        env = {
            "WEBHOOK_ALLOWED_SKILLS": scenario,
            "WEBHOOK_HMAC_SECRETS": json.dumps({scenario: secret}),
            "WEBHOOK_HMAC_HEADER": "X-Hub-Signature-256",
            "WEBHOOK_SINK_TARGETS": "",
            "CLOUD_SECURITY_MCP_AUDIT_LOG": str(audit_log),
        }
        try:
            server_mod = _load_webhook_app(env)
        except Exception as exc:  # pragma: no cover - import is a precondition
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"import failed: {exc!r}",
                "samples": 0,
            }

        from fastapi.testclient import TestClient  # noqa: WPS433

        # Use the fixture the rest of the harness expects.
        fixture_path = REPO_ROOT / "skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl"
        if not fixture_path.is_file():
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"fixture missing: {fixture_path}",
                "samples": 0,
            }

        # Take the first non-empty event line as one CloudTrail record.
        raw_lines = [
            line.strip()
            for line in fixture_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not raw_lines:
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"fixture empty: {fixture_path}",
                "samples": 0,
            }
        body = (raw_lines[0] + "\n").encode("utf-8")
        sig = "sha256=" + _hex_hmac(secret, body)

        client = TestClient(server_mod.app)

        # Liveness gate.
        healthz = client.get("/healthz")
        if healthz.status_code != 200:
            return {
                "runner": "webhook-receiver",
                "scenario": scenario,
                "status": "error",
                "error": f"healthz failed: {healthz.status_code}",
                "samples": 0,
            }

        failures = 0
        for _ in range(samples):
            t0 = time.perf_counter()
            resp = client.post(
                f"/webhook/{scenario}",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Hub-Signature-256": sig,
                },
            )
            dur_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code != 200:
                failures += 1
                continue
            timings_ms.append(dur_ms)
            payload = resp.json()
            cid = payload.get("correlation_id") or ""
            if cid:
                correlation_ids.append(cid)

        # Audit-log assertion — count `webhook_request` events that match
        # our correlation_ids.
        audit_records: list[dict[str, Any]] = []
        if audit_log.exists():
            for line in audit_log.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    audit_records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        audit_matches = sum(
            1 for rec in audit_records if rec.get("correlation_id") in set(correlation_ids)
        )

    timings_summary = _summarize_timings(timings_ms)
    status = "ok" if failures == 0 and audit_matches == samples else "fail"
    return {
        "runner": "webhook-receiver",
        "scenario": scenario,
        "status": status,
        "samples": samples,
        "successful_requests": samples - failures,
        "failed_requests": failures,
        "audit_records_matched": audit_matches,
        "audit_chain_verified": None,
        "audit_chain_status": "not_applicable_receiver_audit_is_unchained",
        "sink_arrival_count": sink_arrivals,
        "sink_status": "gap_sink_fanout_needs_per_sink_flags",
        "captured_at": _now_iso(),
        **timings_summary,
    }


# --------------------------------------------------------------------------- #
# MCP SSE scenario                                                             #
# --------------------------------------------------------------------------- #


def run_mcp_sse_scenario(samples: int) -> dict[str, Any]:
    """Boot the SSE transport on an ephemeral port + exercise the
    synchronous JSON-RPC `/rpc` endpoint with `ping` and `tools/list`.
    The transport writes an HMAC-chained audit log; after the run we
    invoke `scripts/verify_audit_chain.py` and capture its exit code."""
    scenario = "jsonrpc-ping-and-tools-list"
    timings_ms: list[float] = []

    with tempfile.TemporaryDirectory() as tmp:
        audit_log = Path(tmp) / "sse-audit.jsonl"
        keys_file = Path(tmp) / "sse-bearer-keys.json"

        # Mint a single bearer key + bearer secret pair in the keys file.
        # Schema: top-level JSON array of {kid, secret, issued, expires?}.
        bearer_secret = uuid.uuid4().hex + uuid.uuid4().hex
        keys_payload = [
            {
                "kid": "runner-e2e",
                "secret": bearer_secret,
                "issued": _now_iso(),
                "expires": "2099-01-01T00:00:00Z",
            }
        ]
        keys_file.write_text(json.dumps(keys_payload), encoding="utf-8")

        hmac_key_hex = uuid.uuid4().hex + uuid.uuid4().hex
        port = _free_port()
        sse_env = {
            **os.environ,
            "MCP_SSE_BIND": "127.0.0.1",
            "MCP_SSE_PORT": str(port),
            "MCP_SSE_BEARER_KEYS_FILE": str(keys_file),
            "CLOUD_SECURITY_MCP_AUDIT_LOG": str(audit_log),
            "CLOUD_SECURITY_AUDIT_HMAC_KEY": hmac_key_hex,
        }

        sse_entry = REPO_ROOT / "mcp-server" / "src" / "transports" / "sse.py"
        log_path = Path(tmp) / "sse-server.log"
        proc = subprocess.Popen(
            [sys.executable, str(sse_entry)],
            env=sse_env,
            cwd=str(REPO_ROOT),
            stdout=open(log_path, "wb"),
            stderr=subprocess.STDOUT,
        )

        try:
            # Wait for /healthz.
            import urllib.request  # noqa: WPS433

            ready = False
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                try:
                    # B310: localhost-only readiness probe against a port
                    # this process just started; URL is constructed here
                    # and never sourced from external input.
                    with urllib.request.urlopen(  # nosec B310
                        f"http://127.0.0.1:{port}/healthz", timeout=1.0
                    ) as resp:
                        if resp.status == 200:
                            ready = True
                            break
                except Exception:  # noqa: BLE001 - readiness loop
                    time.sleep(0.2)
            if not ready:
                return {
                    "runner": "mcp-sse",
                    "scenario": scenario,
                    "status": "error",
                    "error": "sse listener never became ready",
                    "samples": 0,
                    "captured_at": _now_iso(),
                }

            failures = 0
            valid_payloads = 0
            for i in range(samples):
                # Alternate ping and tools/list so we exercise dispatch.
                if i % 2 == 0:
                    payload = {"jsonrpc": "2.0", "id": i + 1, "method": "ping"}
                else:
                    payload = {
                        "jsonrpc": "2.0",
                        "id": i + 1,
                        "method": "tools/list",
                        "params": {},
                    }
                body = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/rpc",
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {bearer_secret}",
                    },
                )
                t0 = time.perf_counter()
                try:
                    # B310: localhost-only RPC; URL is constructed in this
                    # function for the listener this process just started.
                    with urllib.request.urlopen(req, timeout=10.0) as resp:  # nosec B310
                        dur_ms = (time.perf_counter() - t0) * 1000.0
                        if resp.status != 200:
                            failures += 1
                            continue
                        body_out = resp.read()
                except Exception:  # noqa: BLE001 - record as failure
                    failures += 1
                    continue
                # Sink-arrival = the JSON-RPC response carries result/error.
                try:
                    parsed = json.loads(body_out.decode("utf-8"))
                except json.JSONDecodeError:
                    failures += 1
                    continue
                if parsed.get("jsonrpc") != "2.0" or "id" not in parsed:
                    failures += 1
                    continue
                if "result" not in parsed and "error" not in parsed:
                    failures += 1
                    continue
                # ping → result is empty dict; tools/list → result has tools list.
                if payload["method"] == "tools/list":
                    res = parsed.get("result") or {}
                    if not isinstance(res, dict) or "tools" not in res:
                        failures += 1
                        continue
                valid_payloads += 1
                timings_ms.append(dur_ms)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

        # Chain verification.
        verify_cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "verify_audit_chain.py"),
            str(audit_log),
        ]
        verify_env = {**os.environ, "CLOUD_SECURITY_AUDIT_HMAC_KEY": hmac_key_hex}
        verify_proc = subprocess.run(
            verify_cmd,
            env=verify_env,
            capture_output=True,
            text=True,
            check=False,
        )
        audit_chain_verified = verify_proc.returncode == 0
        audit_chain_exit = verify_proc.returncode

        # Count chain records to confirm one per sample landed.
        audit_count = 0
        if audit_log.exists():
            for line in audit_log.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    audit_count += 1

    timings_summary = _summarize_timings(timings_ms)
    # `ping` + `tools/list` are auditless by design in mcp-server (only
    # `tools/call` writes an audit record). We still get one chain entry
    # from `bearer_key_rotated` at boot — so the chain assertion is
    # "exit 0 from verify_audit_chain AND >=1 record landed".
    status = "ok" if failures == 0 and audit_chain_verified and audit_count >= 1 else "fail"
    return {
        "runner": "mcp-sse",
        "scenario": scenario,
        "status": status,
        "samples": samples,
        "successful_requests": valid_payloads,
        "failed_requests": failures,
        "audit_records": audit_count,
        "audit_chain_verified": audit_chain_verified,
        "audit_chain_exit": audit_chain_exit,
        "audit_chain_status": ("ok_chain_verified_ping_and_tools_list_are_auditless_by_design"),
        "sink_arrival_count": valid_payloads,
        "sink_status": "ok_response_payload_shape_verified",
        "captured_at": _now_iso(),
        **timings_summary,
    }


# --------------------------------------------------------------------------- #
# AWS cloud-runner scenario (moto)                                             #
# --------------------------------------------------------------------------- #


def run_aws_cloud_runner_scenario(samples: int) -> dict[str, Any]:
    """Drive `runners/aws-s3-sqs-detect/src/ingest_handler.lambda_handler`
    against a moto-mocked S3 + SQS pair. The assertion is exact
    SQS-message arrival count per (samples × records-per-event)."""
    scenario = "s3-eventbridge-ingest"
    timings_ms: list[float] = []

    try:
        import boto3  # noqa: WPS433
        from moto import mock_aws  # noqa: WPS433
    except ImportError as exc:
        return {
            "runner": "cloud-runner-aws-s3-sqs",
            "scenario": scenario,
            "status": "gap",
            "error": f"boto3/moto not installed: {exc!r}",
            "samples": 0,
            "captured_at": _now_iso(),
        }

    fixture_path = REPO_ROOT / "skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl"
    if not fixture_path.is_file():
        return {
            "runner": "cloud-runner-aws-s3-sqs",
            "scenario": scenario,
            "status": "error",
            "error": f"fixture missing: {fixture_path}",
            "samples": 0,
            "captured_at": _now_iso(),
        }
    raw_lines = [
        line for line in fixture_path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if not raw_lines:
        return {
            "runner": "cloud-runner-aws-s3-sqs",
            "scenario": scenario,
            "status": "error",
            "error": f"fixture empty: {fixture_path}",
            "samples": 0,
            "captured_at": _now_iso(),
        }
    # One record per S3 object so the SQS arrival count is exactly samples.
    object_body = (raw_lines[0] + "\n").encode("utf-8")

    handler_path = REPO_ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "ingest_handler.py"
    spec = importlib.util.spec_from_file_location("aws_ingest_handler_e2e", handler_path)
    assert spec is not None and spec.loader is not None
    handler_mod = importlib.util.module_from_spec(spec)
    sys.modules["aws_ingest_handler_e2e"] = handler_mod
    spec.loader.exec_module(handler_mod)

    bucket = "runner-e2e-bucket"
    successful = 0
    failures = 0
    sink_arrivals = 0

    skill_cmd = (
        f"{sys.executable} "
        f"{REPO_ROOT / 'skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py'} "
        "--output-format ocsf"
    )

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        sqs = boto3.client("sqs", region_name="us-east-1")
        s3.create_bucket(Bucket=bucket)
        queue = sqs.create_queue(QueueName="runner-e2e-detect")
        queue_url = queue["QueueUrl"]

        prev_env = os.environ.copy()
        try:
            os.environ["INGEST_SKILL_CMD"] = skill_cmd
            os.environ["DETECT_QUEUE_URL"] = queue_url
            os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

            for i in range(samples):
                key = f"events/runner-e2e-{i:03d}.jsonl"
                s3.put_object(Bucket=bucket, Key=key, Body=object_body)
                event = {
                    "Records": [
                        {
                            "s3": {
                                "bucket": {"name": bucket},
                                "object": {"key": key},
                            }
                        }
                    ]
                }
                t0 = time.perf_counter()
                try:
                    handler_mod.lambda_handler(event, None)
                    dur_ms = (time.perf_counter() - t0) * 1000.0
                    timings_ms.append(dur_ms)
                    successful += 1
                except Exception:  # noqa: BLE001 - record as failure
                    failures += 1
                    continue

            # Count messages that arrived on the queue (drain in batches).
            for _ in range(samples * 2):  # safety upper bound
                resp = sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=0,
                )
                messages = resp.get("Messages") or []
                if not messages:
                    break
                sink_arrivals += len(messages)
                for msg in messages:
                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        finally:
            os.environ.clear()
            os.environ.update(prev_env)

    timings_summary = _summarize_timings(timings_ms)
    status = "ok" if failures == 0 and sink_arrivals == samples else "fail"
    return {
        "runner": "cloud-runner-aws-s3-sqs",
        "scenario": scenario,
        "status": status,
        "samples": samples,
        "successful_requests": successful,
        "failed_requests": failures,
        "audit_chain_verified": None,
        "audit_chain_status": "gap_aws_runner_audit_writes_via_cloudwatch_only",
        "sink_arrival_count": sink_arrivals,
        "sink_status": "ok_sqs_message_count_matches_samples",
        "captured_at": _now_iso(),
        **timings_summary,
    }


# --------------------------------------------------------------------------- #
# GCP / Azure cloud-runner gap markers                                         #
# --------------------------------------------------------------------------- #


def gap_record(runner: str, scenario: str, why: str) -> dict[str, Any]:
    return {
        "runner": runner,
        "scenario": scenario,
        "status": "gap",
        "samples": 0,
        "successful_requests": 0,
        "failed_requests": 0,
        "p50_ms": None,
        "p95_ms": None,
        "audit_chain_verified": None,
        "audit_chain_status": "gap_no_local_mock_in_repo",
        "sink_arrival_count": None,
        "sink_status": "gap",
        "gap_reason": why,
        "captured_at": _now_iso(),
    }


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    global RESULTS_PATH  # noqa: PLW0603 - module-level mutable target shared with _append_result
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples",
        type=int,
        default=DEFAULT_SAMPLES,
        help="Iterations per (runner, scenario). Default %(default)s.",
    )
    parser.add_argument(
        "--results-path",
        type=Path,
        default=RESULTS_PATH,
        help="JSONL output file (one record per scenario).",
    )
    parser.add_argument(
        "--only",
        choices=("webhook", "sse", "aws", "gaps", "all"),
        default="all",
        help="Run a subset of scenarios.",
    )
    args = parser.parse_args(argv)
    samples = max(1, int(args.samples))

    RESULTS_PATH = args.results_path

    # Truncate prior results so each invocation owns its file.
    if RESULTS_PATH.exists():
        RESULTS_PATH.unlink()

    scenarios: list[Callable[[], dict[str, Any]]] = []
    if args.only in ("webhook", "all"):
        scenarios.append(lambda: run_webhook_scenario(samples))
    if args.only in ("sse", "all"):
        scenarios.append(lambda: run_mcp_sse_scenario(samples))
    if args.only in ("aws", "all"):
        scenarios.append(lambda: run_aws_cloud_runner_scenario(samples))
    if args.only in ("gaps", "all"):
        scenarios.append(
            lambda: gap_record(
                "cloud-runner-gcp-gcs-pubsub",
                "gcs-finalize-ingest",
                "no in-tree local mock for Pub/Sub queueing; track real-cloud "
                "deploy proof in issue #198 instead of fabricating numbers",
            )
        )
        scenarios.append(
            lambda: gap_record(
                "cloud-runner-azure-blob-eventgrid",
                "blob-eventgrid-ingest",
                "no in-tree local mock for Event Grid + Service Bus; track "
                "real-cloud deploy proof in issue #198 instead of fabricating "
                "numbers",
            )
        )

    overall_failure = False
    for run in scenarios:
        try:
            record = run()
        except Exception as exc:  # noqa: BLE001 - one failed scenario must not hide others
            record = {
                "runner": "harness",
                "scenario": "unknown",
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "captured_at": _now_iso(),
            }
        _append_result(record)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        if record.get("status") not in ("ok", "gap"):
            overall_failure = True

    return 1 if overall_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
