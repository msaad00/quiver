#!/usr/bin/env bash
#
# runner_e2e.sh — end-to-end harness for the shipped runner templates.
#
# Each runner template gets a real round-trip exercise against an
# ephemeral local backend:
#
#   webhook-receiver     -> in-process FastAPI client + HMAC-signed POST
#   mcp-sse              -> subprocess uvicorn + bearer-key JSON-RPC /rpc
#   cloud-runner-aws     -> moto-mocked S3 + SQS, real lambda_handler
#   cloud-runner-gcp     -> recorded as honest gap (no local mock today)
#   cloud-runner-azure   -> recorded as honest gap (no local mock today)
#
# Output:
#   runtime-profile-results.jsonl   one JSONL record per (runner, scenario)
#
# Exit codes:
#   0   every scenario either status=ok or status=gap
#   non-zero   one or more scenarios reported a failure
#
# Sample-size knob:
#   RUNNER_E2E_SAMPLES (default 20). Documented intentionally low; these
#   are CI-runner regression-detection numbers, not customer-scale
#   numbers. See docs/RUNTIME_PROFILES.md.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

SAMPLES="${RUNNER_E2E_SAMPLES:-20}"
RESULTS_PATH="${RUNNER_E2E_RESULTS:-${REPO_ROOT}/runtime-profile-results.jsonl}"
ONLY="${RUNNER_E2E_ONLY:-all}"

PYTHON_BIN="${PYTHON:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if command -v uv >/dev/null 2>&1 && [[ -f "${REPO_ROOT}/pyproject.toml" ]]; then
    PYTHON_BIN="uv run python"
  else
    PYTHON_BIN="python3"
  fi
fi

echo "[runner-e2e] python  : ${PYTHON_BIN}"
echo "[runner-e2e] samples : ${SAMPLES}"
echo "[runner-e2e] results : ${RESULTS_PATH}"
echo "[runner-e2e] only    : ${ONLY}"

set -x
exec ${PYTHON_BIN} "${REPO_ROOT}/scripts/_runner_e2e_harness.py" \
  --samples "${SAMPLES}" \
  --results-path "${RESULTS_PATH}" \
  --only "${ONLY}"
