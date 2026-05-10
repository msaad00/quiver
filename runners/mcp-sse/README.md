# MCP SSE / streamable-HTTP runner

Hardened cloud runner for the MCP wrapper's SSE transport (slice 1 of
issue #415 ships the listener; this directory ships the deployable
surface — slice 2). One process exposes:

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/healthz` | `GET` | open | liveness probe |
| `/sse` | `GET` | `Bearer` | open the long-lived event stream |
| `/messages?session=<token>` | `POST` | `Bearer` | submit one JSON-RPC message |
| `/rpc` | `POST` | `Bearer` | synchronous JSON-RPC convenience endpoint |

The full transport contract — endpoints, environment variables,
audit-record shape — lives in
[`docs/MCP_TRANSPORT.md`](../../docs/MCP_TRANSPORT.md). The audit-chain
contract is in
[`docs/MCP_AUDIT_CONTRACT.md`](../../docs/MCP_AUDIT_CONTRACT.md).

## Security posture

* Non-root container (UID 65532, matches Google distroless `nonroot`).
* Read-only root filesystem; only `/tmp` (memory tmpfs) and the
  configurable audit-log mount are writable.
* `--cap-drop=ALL`, `--security-opt=no-new-privileges`, default seccomp.
* No public bind by default. The transport refuses to start on a
  non-loopback address unless both `MCP_SSE_ALLOW_PUBLIC_BIND=1` and
  at least one bearer key are configured.
* Helm chart ships a default-deny `NetworkPolicy` that only allows
  ingress from a configurable namespace selector. ClusterIP service by
  default — exposing publicly is explicit opt-in (Ingress + values
  override).

## Local quickstart — Docker

```bash
docker build -t cloud-security-mcp-sse -f runners/mcp-sse/Dockerfile .

mkdir -p $PWD/keys $PWD/audit
python scripts/rotate_mcp_sse_bearer_key.py \
    --file $PWD/keys/sse-bearer-keys.json \
    --kid initial \
    --ttl-days 7 \
    > $PWD/keys/.first-secret

docker run --rm -p 8765:8765 \
  --read-only \
  --tmpfs /tmp \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user 65532:65532 \
  --memory=512m --cpus=1.0 --pids-limit=128 \
  -e MCP_SSE_BIND=0.0.0.0 \
  -e MCP_SSE_PORT=8765 \
  -e MCP_SSE_ALLOW_PUBLIC_BIND=1 \
  -e MCP_SSE_BEARER_KEYS_FILE=/etc/cloud-security/sse-bearer-keys.json \
  -e CLOUD_SECURITY_MCP_AUDIT_LOG=/var/log/cloud-security/audit.jsonl \
  -e CLOUD_SECURITY_AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
  -v $PWD/keys:/etc/cloud-security:ro \
  -v $PWD/audit:/var/log/cloud-security:rw \
  cloud-security-mcp-sse
```

Or with the bundled Compose file:

```bash
docker compose -f runners/mcp-sse/templates/docker-compose.yml up
```

## Local quickstart — Helm

```bash
helm install mcp-sse runners/mcp-sse/templates/helm \
  --set image.repository=ghcr.io/your-org/cloud-security-mcp-sse \
  --set image.tag=$(git rev-parse --short HEAD) \
  --set-file secrets.bearerKeysJson=$PWD/keys/sse-bearer-keys.json \
  --set existingAuditHmacSecret=mcp-audit-hmac \
  --set networkPolicy.allowedNamespaceSelector.matchLabels."kubernetes\.io/metadata\.name"=agents
```

The chart creates:

* `Deployment` — non-root, read-only rootfs, dropped caps, seccomp default.
* `Service` (ClusterIP).
* `ConfigMap` — non-secret env (bind, port, audit log path).
* `Secret` — bearer-keys JSON + audit HMAC key (operator may use
  `existingSecret` instead).
* `NetworkPolicy` — default-deny ingress, allow only from the
  configured namespace selector.
* `PersistentVolumeClaim` for the audit log (when
  `volumes.audit.storageClass` is set).

## Environment reference

| Variable | Default | Effect |
|---|---|---|
| `MCP_SSE_BIND` | `127.0.0.1` | bind address |
| `MCP_SSE_PORT` | `8765` | TCP port |
| `MCP_SSE_BEARER_KEYS_FILE` | _(unset)_ | path to the JSON keys file (preferred) |
| `MCP_SSE_BEARER_KEYS` | _(unset)_ | comma-separated env fallback (slice-1 contract) |
| `MCP_SSE_ALLOW_PUBLIC_BIND` | _(unset)_ | required for non-loopback binds |
| `CLOUD_SECURITY_MCP_AUDIT_LOG` | _(unset)_ | path to the JSONL audit log |
| `CLOUD_SECURITY_AUDIT_HMAC_KEY` | _(unset)_ | HMAC key for the tamper-evident chain |

## Bearer-key rotation

Generate a new key and append it to the keys file:

```bash
python scripts/rotate_mcp_sse_bearer_key.py \
  --file /etc/cloud-security/sse-bearer-keys.json \
  --ttl-days 90
```

The script writes the new entry atomically (tmp + fsync + rename) and
prints the new secret to stdout once. Reload a running listener
without bouncing it:

```bash
kill -HUP $(pgrep -f transports/sse.py)
```

The `KeyStore` accepts BOTH the old and the new secret until the old
key's `expires` ticks past, so clients have an overlap window to roll
forward. Every reload emits one `bearer_key_rotated` audit record on
the same HMAC chain as the tool-call records (kid in/out only — never
the secret). See
[`docs/MCP_TRANSPORT.md`](../../docs/MCP_TRANSPORT.md) for the full
contract.
