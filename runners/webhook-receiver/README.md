# Webhook receiver — any-source → ingest → S3 / Snowflake / ClickHouse

A vendor-neutral HTTP receiver that turns any webhook into the same
shipped pipeline the other reference runners use.

```
HTTP POST                                                shipped sinks
─────────                                                ─────────────
                                                       ┌── sink-s3-jsonl
vendor webhook ─► /webhook/<ingest-skill> ─► ingest ──┼── sink-snowflake-jsonl
S3 EventBridge ─►                            skill   └── sink-clickhouse-jsonl
generic POST  ─►                                ▼
                                          OCSF JSONL
                                          (fan-out)
```

Read next:

- [`../README.md`](../README.md) — how shipped runners relate to atomic
  skills.
- [`../../docs/RUNNER_CONTRACT.md`](../../docs/RUNNER_CONTRACT.md) — the
  contract every runner satisfies.
- [`../../docs/MCP_AUDIT_CONTRACT.md`](../../docs/MCP_AUDIT_CONTRACT.md)
  — same audit shape this receiver writes.

## Why

The other reference runners (`aws-s3-sqs-detect`, `gcp-gcs-pubsub-detect`,
`azure-blob-eventgrid-detect`) are pinned to one cloud's primitives. A
SaaS webhook callback, a vendor signing receipt, or an internal HTTP
gateway have no out-of-the-box landing pad in the repo today. This
receiver fills that gap without forking the skill model — every
webhook payload is dispatched to a **named atomic ingest skill**, the
output is routed to the operator's choice of shipped sinks, and one
audit record is emitted per request.

## What it is, exactly

- **One process.** A FastAPI app under `src/server.py`. Stateless. Deploy
  on AWS App Runner / Lambda Function URL, GCP Cloud Run, Azure Container
  Apps, or any container runtime.
- **Closed-set routing.** `POST /webhook/<skill-name>` resolves
  `<skill-name>` against the shipped tool registry. Unknown skill →
  `404`. Skill outside `WEBHOOK_ALLOWED_SKILLS` → `403`.
- **Signature verification first.** Per-route HMAC-SHA-256 on the raw
  body, or bearer-token, or both. Missing signature → `401`. Invalid
  signature → `401`. The body is verified before the skill is invoked.
- **Sink fan-out.** Each emitted OCSF event is written to every sink in
  `WEBHOOK_SINK_TARGETS` (`s3,snowflake,clickhouse`). Sinks are the
  shipped `skills/output/sink-*-jsonl` skills — same dual-audit, same
  idempotent semantics.
- **One audit record per request.** Same JSON shape as
  `mcp_tool_call`: route, payload SHA-256, sink fan-out targets, the
  outbound `correlation_id`, and the wrapped skill exit code.

## Configuration

| Env var | Purpose |
|---|---|
| `WEBHOOK_ALLOWED_SKILLS` | Comma-separated allowlist. Any other skill name returns `403`. Defaults to **none** (locked-down by default). |
| `WEBHOOK_HMAC_SECRETS` | JSON object: `{"<skill-name>": "shared-secret"}`. Per-skill secret used for HMAC-SHA-256 verification of `X-Hub-Signature-256` (or the configurable header). |
| `WEBHOOK_HMAC_HEADER` | Header carrying the signature. Defaults to `X-Hub-Signature-256`. |
| `WEBHOOK_BEARER_TOKEN` | Optional bearer token. When set, `Authorization: Bearer <token>` is required on every route. Combine with HMAC for two-factor request auth. |
| `WEBHOOK_SINK_TARGETS` | Comma-separated subset of `s3`, `snowflake`, `clickhouse`. Empty means no sink fan-out (response payload only). |
| `CLOUD_SECURITY_MCP_AUDIT_LOG` | Same env as the MCP wrapper — durable JSONL audit file with HMAC chain when `CLOUD_SECURITY_AUDIT_HMAC_KEY` is set. |

## Deployment templates

The `templates/` directory ships reference manifests for:

- AWS App Runner via container image
- AWS Lambda Function URL via container image (zero-cold-start at low volume)
- GCP Cloud Run
- Azure Container Apps
- Helm chart for self-hosted Kubernetes

Each template surfaces the env vars above and wires the audit log to a
mounted volume / managed secret store as appropriate. Adapting one for
a different runtime is a 10-line config change.

## Local quickstart

```bash
uv sync --group dev --extra webhook
export WEBHOOK_ALLOWED_SKILLS=ingest-cloudtrail-ocsf
export WEBHOOK_HMAC_SECRETS='{"ingest-cloudtrail-ocsf":"local-dev-secret"}'
export WEBHOOK_SINK_TARGETS=
uvicorn runners.webhook-receiver.src.server:app --port 8080

# In another shell:
BODY='[{"eventVersion":"1.08","eventSource":"signin.amazonaws.com",…}]'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac local-dev-secret -hex | sed 's/^.* //')
curl -sS -X POST localhost:8080/webhook/ingest-cloudtrail-ocsf \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIG" \
  --data "$BODY" | jq
```

## What it is not

- Not a managed multi-tenant SaaS — operators run this themselves, same
  line as the other reference runners.
- Not an authentication service. HMAC + bearer cover the request-auth
  surface; identity federation, OIDC, mTLS belong upstream of the
  receiver.
- Not a scheduler. One request → one skill → one fan-out. Recurring or
  buffered ingestion belongs in the existing event-driven runners.

## Trust model

- **Default-deny on routing.** `WEBHOOK_ALLOWED_SKILLS` is empty by
  default; the receiver returns `403` until an operator opts a skill
  in.
- **Request body verified before skill invocation.** Invalid signature
  never reaches the skill subprocess; the audit record still fires
  with `result: error` and `error_type: signature_invalid`.
- **Skills inherit the existing safe-env contract.** The receiver
  spawns the skill with the same `SAFE_CHILD_ENV_VARS` whitelist the
  MCP wrapper uses. No ambient secret leaks into the skill process.
- **Sink fan-out is best-effort, never silent.** Sink failures are
  logged into the audit record per-target. The webhook response
  surfaces `"sink_results": [{"target": "s3", "ok": true}, ...]` so
  the caller can tell.
