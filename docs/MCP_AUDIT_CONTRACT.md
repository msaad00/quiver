# MCP Audit Contract

This document defines the audit record emitted by `mcp-server/src/server.py`
for each resolved `tools/call` invocation.

The goal is to make the wrapper's runtime behavior explicit:

- operators can tell what was invoked
- callers and approvers can be traced when the runtime provides context
- failures are still audited
- secrets and raw stdin are not echoed into the audit trail

Trust boundary at a glance: [`diagrams/mcp-trust-boundary.mmd`](diagrams/mcp-trust-boundary.mmd) — the same lifecycle this doc describes, rendered as a sequence diagram (every guard, every short-circuit, the audit emission point).

Read next:

- [RUNTIME_ISOLATION.md](RUNTIME_ISOLATION.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [ERROR_CODES.md](ERROR_CODES.md)
- [../AGENTS.md](../AGENTS.md)

## Scope

This contract covers the wrapper audit event, not the wrapped skill's own
stdout, stderr, or domain-specific logs.

It applies when the MCP server:

- resolves a supported tool name
- validates the incoming `arguments`
- emits the `mcp_tool_call` audit record in `_call_tool`

It does not cover:

- unknown tool names rejected before `_call_tool` runs
- client-side tracing outside this repo
- HTTP transports other than the SSE / streamable-HTTP listener documented in [MCP_TRANSPORT.md](MCP_TRANSPORT.md)

## Emission Point

`mcp-server/src/server.py` emits one audit event per tool invocation from the
`finally` block in `_call_tool()`.

That means the event is emitted for:

- successful skill execution
- non-zero skill exit codes
- validation failures in the wrapper
- approval precondition failures in the wrapper
- subprocess timeouts
- other exceptions raised while the wrapper is preparing or running the tool

The event is written as a single JSON object to `stderr` and terminated by a
newline. When a durable file sink is configured (see *Durable file sink*
below), the same event — augmented with chain-hash fields — is also appended
to the configured JSONL file with a per-event `fsync()`.

## Durable file sink (optional)

`stderr` is the always-on sink, but supervising stdio MCP clients can
silently swallow it. When operators need a record they can audit
post-hoc, set:

| Variable | Effect |
|---|---|
| `CLOUD_SECURITY_MCP_AUDIT_LOG` | Absolute path to a JSONL file. Each `mcp_tool_call` event is appended with a per-event `fsync()`. The file is created with mode `0600`; parent directories are created if needed. |
| `CLOUD_SECURITY_AUDIT_HMAC_KEY` | When set, every event carries `prev_hash` and `chain_hash` fields, computed as `HMAC-SHA-256(key, prev_hash \|\| canonical_event_json)`. The chain seeds from `0` * 64 on first start and resumes from the last persisted `chain_hash` across restarts. |

Verify a chain post-hoc:

```bash
CLOUD_SECURITY_AUDIT_HMAC_KEY=... \
  python scripts/verify_audit_chain.py /var/log/cloud-security-mcp/audit.jsonl
```

The verifier exits `0` when every event matches its expected chain hash,
`1` when any event was edited / dropped / re-keyed, and `2` on
configuration errors. It prints the offending line numbers to stderr so a
SIEM can ingest the failure trace directly.

## Event Shape

Required top-level fields:

| Field | Type | Meaning |
|---|---|---|
| `event` | string | fixed value `mcp_tool_call` |
| `timestamp` | string | UTC ISO-8601 timestamp with millisecond precision |
| `correlation_id` | string | wrapper-generated stable ID for this tool invocation, also forwarded to the skill runtime |
| `transport` | string | which surface delivered the request — `stdio` or `sse` (see [MCP_TRANSPORT.md](MCP_TRANSPORT.md)) |
| `tool` | string | resolved MCP tool name |
| `category` | string | skill category from the contract metadata |
| `capability` | string | skill capability from the contract metadata |
| `read_only` | boolean | whether the wrapped skill is read-only |
| `output_format` | string | requested output format, or `default` |
| `args_hash` | string | SHA-256 of the validated `args` array after stable JSON normalization |
| `args_count` | integer | number of validated arguments |
| `input_sha256` | string | SHA-256 of stdin input text, or empty string when no input was provided |
| `input_length` | integer | byte length of the stdin text as passed to the subprocess |
| `caller_context_provided` | boolean | whether `_caller_context` was supplied |
| `caller_skill_scope_provided` | boolean | whether `_caller_context.allowed_skills` was supplied |
| `caller_skill_scope_count` | integer | number of distinct non-empty skills in the caller scope |
| `caller_skill_scope_hash` | string | SHA-256 of the sorted caller skill scope, or empty string when absent |
| `approval_context_provided` | boolean | whether `_approval_context` was supplied |
| `caller_id` | string | `user_id` from `_caller_context`, or empty string |
| `caller_session_id` | string | `session_id` from `_caller_context`, or empty string |
| `approval_ticket` | string | `ticket_id` from `_approval_context`, or empty string |
| `result` | string | `pending`, `success`, or `error` |
| `duration_ms` | integer | wall-clock duration of the wrapper invocation |

Conditionally present fields:

| Field | Present when | Meaning |
|---|---|---|
| `exit_code` | the subprocess completed and returned a code | wrapped skill exit status |
| `error_type` | an exception was raised before the wrapper could finish normally | Python exception class name |
| `error_message` | an exception was raised before the wrapper could finish normally | stringified exception message |

## Field Semantics

### `args_hash`

The wrapper computes the hash from the validated `args` list using a stable JSON
encoding:

- keys are sorted
- separators are compact
- the hash is SHA-256

This is meant to support audit correlation without storing the raw argument
payload.

### `input_sha256`

The wrapper hashes the exact stdin text passed to the subprocess.

If no input was provided, the field is the empty string, not a hash of an empty
payload.

### Caller and approval context

The wrapper preserves only the fields it knows about:

- `_caller_context.user_id` -> `caller_id`
- `_caller_context.session_id` -> `caller_session_id`
- `_caller_context.allowed_skills` -> counted and hashed as caller skill scope
- `_approval_context.ticket_id` -> `approval_ticket`

Presence is tracked separately from value so operators can tell the difference
between "not supplied" and "supplied but empty".

### `correlation_id`

The wrapper generates one UUID per resolved tool invocation.

It is used in three places:

- the MCP audit event on `stderr`
- the `structuredContent` response returned to the MCP client
- the subprocess environment as `SKILL_CORRELATION_ID`

That lets operators correlate:

- wrapper audit records
- structured skill `stderr`
- client-visible tool-call metadata

### `result`

`result` starts as `pending` and is updated to one of:

- `success` when the subprocess returns exit code `0`
- `error` when the subprocess returns a non-zero exit code
- `error` when the wrapper raises an exception

The audit event is still emitted on exceptions because the wrapper records the
error fields in the `except` block and writes the event in `finally`.

## Validation And Gating

Before the subprocess runs, the wrapper enforces:

- `args` must be an array of strings
- `input` must be a string
- `output_format` must be a string when present
- `_caller_context` and `_approval_context` must be objects with string values
  or string arrays
- `_caller_context.allowed_skills`, when supplied, is intersected with
  `CLOUD_SECURITY_MCP_ALLOWED_SKILLS`; setting
  `CLOUD_SECURITY_MCP_REQUIRE_CALLER_ALLOWED_SKILLS=1` rejects calls without a
  caller skill scope by exposing no callable tools
- write-capable tools must stay in safe mode at the wrapper boundary:
  `--dry-run` for generic write tools, or no `--apply` for dry-run-default
  `handler.py` / `checks.py` entrypoints
- write-capable tools with `approver_roles` must receive `_approval_context`

These checks are part of the audited lifecycle. A failure here still produces an
audit record with `result: "error"`.

## Privacy And Logging Rules

The audit trail must not expose:

- raw stdin content
- raw secrets
- raw approval tokens
- raw caller credentials

The wrapper only emits hashes and context identifiers.

Operationally, this means:

- `stderr` is the audit channel for the wrapper
- `stdout` remains the wrapped skill's result channel
- operator-facing diagnostics should stay out of the audit record unless they
  are already safe to publish as metadata

## Tool annotation contract

`tools/list` returns each tool with a short description and a structured
`annotations` object. Agentic clients should filter on `annotations`
rather than parse the description.

| Annotation key | Type | Source | Meaning |
|---|---|---|---|
| `readOnlyHint` | bool | derived | matches MCP spec — true when the skill never writes |
| `destructiveHint` | bool | derived | inverse of `readOnlyHint` |
| `idempotentHint` | bool | derived | matches MCP spec — true when re-running converges |
| `category` | string | SKILL.md path | one of `ingestion`, `discovery`, `detection`, `evaluation`, `remediation`, `view`, `output` |
| `capability` | string | frontmatter | `read-only`, `write-remediation`, `write-sink`, `write-runner` |
| `approvalModel` | string | frontmatter | `none`, `human_required`, etc. |
| `executionModes` | string[] | frontmatter | `jit`, `ci`, `mcp`, `persistent`, … |
| `sideEffects` | string[] | frontmatter | `none`, `writes-cloud`, `writes-identity`, `writes-database`, `writes-storage`, `writes-audit` |
| `inputFormats` / `outputFormats` | string[] | frontmatter | `raw`, `canonical`, `ocsf`, `native`, `bridge` |
| `networkEgress` | string[] | frontmatter | hostnames or `*.glob.example` patterns the skill is allowed to reach |
| `callerRoles` / `approverRoles` | string[] | frontmatter | RBAC vocabulary |
| `minApprovers` | int | frontmatter | 0 when not set; > 0 enforces `_approval_context` |

`additionalProperties: false` on `_caller_context` and `_approval_context`
in the input schema; the wrapper enforces the same closed key set on
`tools/call` so a typo on `approver_email` -> `approver_emial` is rejected
with `-32602` instead of silently dropping into an empty approver list.

## Reliability Expectations

The wrapper should preserve this audit contract across supported tool calls:

- one event per resolved tool invocation
- newline-delimited JSON for easy collection
- stable field names for downstream parsers
- no hidden second audit channel

If the audit shape changes, update this document and the relevant wrapper tests
in the same change.

## JSON-RPC Error Codes

The wrapper uses the server-defined range (-32000..-32099) so clients can tell
operational failures apart from each other. Standard JSON-RPC codes (-32600
parse error, -32601 method/tool not found, -32602 invalid params) keep their
spec meaning.

| Code | Constant | Cause |
|------|----------|-------|
| `-32001` | `ERROR_TOOL_TIMEOUT` | skill subprocess exceeded the resolved timeout |
| `-32002` | `ERROR_TOOL_NOT_ALLOWED` | reserved for future explicit allowlist denials |
| `-32003` | `ERROR_APPROVAL_REQUIRED` | reserved for future approval-context errors |
| `-32004` | `ERROR_TOOL_CRASHED` | reserved for future non-timeout subprocess failures |

Constants live in `mcp-server/src/server.py`. Update this table whenever a new
code is reserved or a placeholder is wired in.
