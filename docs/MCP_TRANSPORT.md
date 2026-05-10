# MCP Transport

This document describes the transports the MCP wrapper exposes — the
ways an MCP client can reach the same JSON-RPC dispatch + audit
contract.

The contract itself lives in
[`MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md). Every transport must
preserve every field, every guard, and every chain-hash link. The only
difference between transports on the audit record is the `transport`
field.

## Transports

| Transport | Default | Status | Use when |
|---|---|---|---|
| `stdio` | yes | shipping | a local MCP client owns the wrapper subprocess |
| `sse` (streamable HTTP) | no | slice 1 of #415 | a remote MCP client (or the cloud runner) needs network access |

`stdio` is still the default. SSE is opt-in and never enabled by
turning a single boolean on — the operator must configure bearer keys
and (for non-loopback binds) acknowledge the public exposure.

## stdio

```bash
python mcp-server/src/server.py < requests > responses
```

The framing is `Content-Length`-prefixed JSON-RPC, identical to the
LSP-style MCP framing. One process, one supervisor (the MCP client),
one audit chain on stderr / the optional file sink.

Audit records on this transport carry `transport: "stdio"`.

## SSE / streamable HTTP

```bash
# Install:
uv sync --group dev --group mcp-sse --group http-runtime

# Run:
MCP_SSE_BEARER_KEYS="key1,key2" \
MCP_SSE_BIND=127.0.0.1 \
MCP_SSE_PORT=8765 \
python mcp-server/src/transports/sse.py
```

The SSE transport relies on two extras: `mcp-sse` (sse-starlette + starlette
for the listener) and `http-runtime` (uvicorn for the server driver).
`http-runtime` is shared with the webhook receiver so the same server stack
isn't declared in two extras.

### Endpoints

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/healthz` | `GET` | open | liveness probe (no secrets, no chain effect) |
| `/sse` | `GET` | `Bearer` | open the long-lived event stream; first event is `endpoint` carrying the per-session `/messages` URL |
| `/messages?session=<token>` | `POST` | `Bearer` | submit one JSON-RPC message; response is queued onto the matching SSE stream |
| `/rpc` | `POST` | `Bearer` | synchronous JSON-RPC convenience endpoint — body in, JSON response out, same audit emission as the streaming pair |

Both `/messages` and `/rpc` go through the shared
`dispatch.handle_request(transport="sse")`, so every guard
(`tools/list` filter, write-mode check, approver context, sandbox,
worker pool, resource limits) fires identically to stdio.

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `MCP_SSE_BIND` | `127.0.0.1` | bind address; non-loopback values trigger the public-bind guard |
| `MCP_SSE_PORT` | `8765` | TCP port |
| `MCP_SSE_BEARER_KEYS_FILE` | _(unset)_ | absolute path to a JSON keys file (preferred for production, see "Bearer-key rotation contract" below) |
| `MCP_SSE_BEARER_KEYS` | _(unset)_ | comma-separated env fallback (slice-1 contract); ignored when the file env is set |
| `MCP_SSE_ALLOW_PUBLIC_BIND` | _(unset)_ | required when `MCP_SSE_BIND` is non-loopback; together with at least one bearer key, this opts the operator into network exposure |

The audit-log envs documented in
[`MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md)
(`CLOUD_SECURITY_MCP_AUDIT_LOG`, `CLOUD_SECURITY_AUDIT_HMAC_KEY`) work
unchanged here — both transports share one process-local sink.

### Bind safety

The SSE listener refuses to start when:

- `MCP_SSE_BIND` is non-loopback and `MCP_SSE_ALLOW_PUBLIC_BIND` is not
  truthy, OR
- `MCP_SSE_ALLOW_PUBLIC_BIND` is truthy but `MCP_SSE_BEARER_KEYS` is
  empty.

In both cases the process writes a one-line rationale to stderr and
exits with code `2`. There is no soft-fail / unauthenticated mode —
the MCP wrapper holds an arbitrary-tool execution surface, so an open
bind is never the right default.

### Auth model

Bearer tokens come from `MCP_SSE_BEARER_KEYS`, comma-separated. Every
request to `/sse`, `/messages`, and `/rpc` MUST carry
`Authorization: Bearer <key>` matching one of the configured values
(constant-time compared with `hmac.compare_digest`).

Two key-source modes are supported (slice 2 of #415 wired in the file
form; the env form was the slice-1 contract and stays as a fallback):

- **File** (`MCP_SSE_BEARER_KEYS_FILE`): a JSON array. Each entry is
  `{ "kid": "...", "secret": "...", "issued": "...", "expires": "..." }`
  with `expires` optional. The listener reloads the file on `SIGHUP`.
- **Env** (`MCP_SSE_BEARER_KEYS`): the original comma-separated form.
  Each token is treated as a non-expiring synthetic key with kid
  `env-<index>`. Only used when the file env is unset.

### Audit guarantees

Every JSON-RPC message dispatched on the SSE transport produces one
audit record with `transport: "sse"`, written through the same
`audit_sink.AuditSink` that stdio uses. The HMAC chain
(`CLOUD_SECURITY_AUDIT_HMAC_KEY`) is unbroken across transports — a
log file containing both `transport: "stdio"` and `transport: "sse"`
records replays cleanly under
`scripts/verify_audit_chain.py`.

The shared sink is guarded by a process-wide lock so concurrent SSE
clients cannot interleave their chain links. stdio is single-threaded
and so the lock is uncontended on that path.

Privacy rules from
[`MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md) apply unchanged: the
audit record never echoes raw stdin, secrets, approval tokens, or
caller credentials.

## Deployment (Docker / Helm)

Slice 2 of #415 ships a hardened cloud runner under
[`runners/mcp-sse/`](../runners/mcp-sse/). The directory mirrors the
shape of `runners/webhook-receiver/` so operators get a consistent
deployment story across runners.

### Docker

```bash
docker build -t cloud-security-mcp-sse -f runners/mcp-sse/Dockerfile .
docker run --rm -p 8765:8765 \
  --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 \
  --memory=512m --cpus=1.0 --pids-limit=128 \
  -e MCP_SSE_BIND=0.0.0.0 \
  -e MCP_SSE_ALLOW_PUBLIC_BIND=1 \
  -e MCP_SSE_BEARER_KEYS_FILE=/etc/cloud-security/sse-bearer-keys.json \
  -v $PWD/keys:/etc/cloud-security:ro \
  cloud-security-mcp-sse
```

The image is multi-stage (build deps → distroless-friendly runtime),
runs as UID 65532, drops all Linux capabilities, and is
read-only-rootfs friendly. The supplied
[`templates/docker-compose.yml`](../runners/mcp-sse/templates/docker-compose.yml)
wires the same flags for local end-to-end tests.

### Helm

```bash
helm install mcp-sse runners/mcp-sse/templates/helm \
  --set image.repository=ghcr.io/your-org/cloud-security-mcp-sse \
  --set image.tag=$(git rev-parse --short HEAD) \
  --set-file secrets.bearerKeysJson=$PWD/keys/sse-bearer-keys.json \
  --set secrets.auditHmacKey=$(openssl rand -hex 32) \
  --set networkPolicy.allowedNamespaceSelector.matchLabels."kubernetes\.io/metadata\.name"=agents
```

The chart creates:

- `Deployment` — non-root, read-only rootfs, dropped caps, seccomp
  default, audit-log mount, bearer-keys mounted from a Secret with
  mode `0400`.
- `Service` (ClusterIP). Exposing publicly is opt-in via Ingress.
- `ConfigMap` — non-secret env (bind, port, audit log path).
- `Secret` — bearer-keys JSON + audit HMAC key. Operators can point at
  an existing Secret instead with `secrets.existingSecret`.
- `NetworkPolicy` — default-deny ingress except from a configurable
  namespace + pod selector. With no selector configured the policy
  selects the pod and writes no `ingress` rules — the canonical
  Kubernetes shape for "deny all ingress to the selected pods".
- `PersistentVolumeClaim` for the audit log when
  `volumes.audit.storageClass` is set; an in-memory `emptyDir` is the
  fallback for local testing.

The `Deployment` carries `checksum/secret` and `checksum/configmap`
annotations so a `helm upgrade` that mutates the Secret rolls the
pod automatically. SIGHUP-driven in-place reloads (see below) are the
no-restart path.

## Bearer-key rotation contract

Slice 2 of #415 added a key-rotation contract so operators can rotate
without bouncing the listener.

### File shape

```json
[
  {
    "kid": "2026-04-01-abcd",
    "secret": "old-secret",
    "issued":  "2026-04-01T00:00:00Z",
    "expires": "2026-05-15T00:00:00Z"
  },
  {
    "kid": "2026-05-10-ef12",
    "secret": "new-secret",
    "issued":  "2026-05-10T00:00:00Z",
    "expires": "2026-08-08T00:00:00Z"
  }
]
```

* `kid`, `secret` are required; `kid` must be unique within the file.
* `issued`, `expires` are optional UTC ISO-8601 timestamps. An entry
  with no `expires` never expires (matches the env-fallback contract).
* Unknown fields are ignored (forward-compat for future metadata such
  as `purpose` or `subject`).
* The listener refuses to start when the file resolves to **zero**
  usable keys (parse error, schema mismatch, every entry expired) —
  an open-door deploy is never the right default.

### Lifecycle

1. **Cut a new key.** The shipped helper writes the new entry
   atomically and prints the secret to stdout once:

   ```bash
   python scripts/rotate_mcp_sse_bearer_key.py \
     --file /etc/cloud-security/sse-bearer-keys.json \
     --ttl-days 90
   ```

   The script writes via `tempfile + fsync + os.replace + dir-fsync`,
   so a crash mid-write leaves the previous file untouched. Exit
   codes: `0` success, `1` IO/parse failure, `2` refusal (would write
   an empty keyset).

2. **Reload the listener.** SIGHUP triggers a synchronous reload:

   ```bash
   kill -HUP $(pgrep -f transports/sse.py)
   ```

   Kubernetes operators can pair this with `kubectl rollout restart`
   for a belt-and-braces redeploy; SIGHUP is the no-downtime path.

3. **Overlap window.** Validation accepts ANY non-expired secret in
   the store. Both old and new bearers authenticate until the old
   key's `expires` ticks past — clients roll forward on their own
   schedule. After expiry the old secret returns `401`.

4. **Retire.** Either let the file's `expires` field do the work
   (next reload drops it from `kids_active`), or pass
   `--retire-oldest-expired` to the rotation script to physically
   prune the entry.

### Audit-record shape

Every successful reload emits ONE `bearer_key_rotated` record through
the same `audit_sink.AuditSink` as the tool-call records. The HMAC
chain stays unbroken across record types — `verify_audit_chain.py`
replays a mixed log without any flag changes.

```json
{
  "event": "bearer_key_rotated",
  "transport": "sse",
  "timestamp": "2026-05-10T12:34:56.789Z",
  "reason": "boot" | "sighup" | "manual",
  "source": "file",
  "kids_added":   ["2026-05-10-ef12"],
  "kids_removed": ["2026-04-01-abcd"],
  "kids_active":  ["2026-05-10-ef12"]
}
```

Privacy is identical to the rest of
[`MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md): the record carries
only `kid` values, never `secret`. A SIEM that already ingests
`mcp_tool_call` events gets `bearer_key_rotated` for free — same
chain, same line format.

## Why SSE here, not raw HTTP

The MCP ecosystem standardises on the SSE / streamable-HTTP shape for
remote transports — every conformant client knows how to open `GET
/sse` + post to the session URL. Implementing that shape (rather than
a bespoke JSON-RPC-over-HTTP) keeps the wrapper interoperable with the
common MCP client libraries. The synchronous `/rpc` endpoint is an
audited convenience for programmatic callers and tests; it does not
replace the SSE pair.
