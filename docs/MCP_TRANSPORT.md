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
MCP_SSE_BEARER_KEYS="key1,key2" \
MCP_SSE_BIND=127.0.0.1 \
MCP_SSE_PORT=8765 \
python mcp-server/src/transports/sse.py
```

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
| `MCP_SSE_BEARER_KEYS` | _(unset)_ | comma-separated set of accepted bearer tokens; constant-time compared |
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

Slice 1 (this PR) treats keys as static configuration. Slice 2 (deferred
follow-up PR per #415) wires:

- key rotation on the cloud-runner Helm chart,
- the per-tenant key-issuance workflow,
- the Docker image entrypoint variants for the SSE transport.

Until slice 2 ships, operators set keys via env / sealed-secret and
restart to rotate.

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

## Why SSE here, not raw HTTP

The MCP ecosystem standardises on the SSE / streamable-HTTP shape for
remote transports — every conformant client knows how to open `GET
/sse` + post to the session URL. Implementing that shape (rather than
a bespoke JSON-RPC-over-HTTP) keeps the wrapper interoperable with the
common MCP client libraries. The synchronous `/rpc` endpoint is an
audited convenience for programmatic callers and tests; it does not
replace the SSE pair.
