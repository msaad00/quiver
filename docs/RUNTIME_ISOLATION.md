# Runtime Isolation

This repo ships security skills, not a shared trusted runtime. Isolation is
part of the product contract.

The rule is simple:
- read-only skills run with the smallest possible local and cloud trust surface
- write-capable skills run in tighter, separate execution boundaries
- transport, storage, and audit controls are explicit, not assumed

Each shipped `SKILL.md` now declares:
- `approval_model`
- `execution_modes`
- `side_effects`
- optional `network_egress`

Agents and wrappers should treat those fields as part of the runtime contract, not optional documentation.

Important meaning:
- `execution_modes: persistent` means the skill is compatible with a persistent runner or serverless loop
- it does **not** mean the repo already ships a dedicated daemon, queue worker, sink, or Lambda wrapper for that skill
- today, most skills are persistent-compatible but still run as stateless CLI tools; the repo ships a small number of persistent code paths, including `iam-departures-aws` and the reference runner under `runners/aws-s3-sqs-detect/`

## Modes

| Mode | Best for | Isolation posture | Human approval |
|---|---|---|---|
| CLI / just-in-time | local triage, one-off conversions, fixture checks | local venv or container, scoped files, least-privilege creds | only for write-capable skills |
| CI | regression testing, policy checks, snapshots | ephemeral runner, short-lived creds, no write skills in normal PR lanes | never for read-only skills |
| MCP | local agent tool calling | stdio-only wrapper, fixed tool surface, timeouts, no generic shell tool | inherited from the wrapped skill |
| Persistent / serverless | continuous detection, sinks, remediation | isolated runner or cloud service boundary, checkpointing, egress controls, idempotent writes | required for destructive actions |

Persistent mode should be read as:
- the skill stays stateless and deterministic
- a separate runner or serverless wrapper owns checkpoints, retries, queue offsets, and sink writes
- operators still need to provide the surrounding runtime unless the skill explicitly ships one

## Sandboxing layers

The MCP wrapper and the Python SDK shim spawn every skill in a child
subprocess. Three layers of isolation can stack on that boundary; the
operator opts in to as many as their host supports.

### Layer 1 — container hardening (default in shipped image)

The shipped image runs as non-root, with a read-only root filesystem,
`no-new-privileges`, dropped Linux capabilities, and a writable
`/tmp` tmpfs. Operators who run the wrapper outside the image are
responsible for re-creating equivalent controls.

### Layer 2 — opt-in OS sandbox (this layer)

Operators set `CLOUD_SECURITY_MCP_SANDBOX=on` to wrap each skill
subprocess under the platform's namespace / sandbox tooling:

- **Linux (`bwrap`)** — read-only binds for `/usr`, `/etc`, `/lib`,
  `/lib64`; the repo bound at its real path so the cwd keeps working;
  `--tmpfs /tmp`; `--proc /proc`; `--dev /dev`; `--unshare-all` to
  drop pid / ipc / mount / uts / cgroup namespaces; `--die-with-parent`
  so the child exits when the wrapper does. Network stays on by
  default (cloud SDKs need it) — only skills whose `SKILL.md`
  declares `network_egress: []` get `--unshare-net`.
- **macOS (`sandbox-exec`)** — the wrapper writes a per-call deny-by-
  default `.sb` profile to `/tmp/`, allowing `file-read*`,
  `file-write*` under `/tmp/` and the repo root, `process*`, and
  `network*` (toggled to `(deny network*)` when `network_egress: []`).
- **Other platforms** — no-op fallback. The wrapper logs a one-shot
  stderr warning and proceeds unwrapped.

Off by default; off behaviour is byte-identical to pre-layer-2. When
the env var is on but the wrapper binary (`bwrap` / `sandbox-exec`)
isn't installed, the wrapper falls back to the unsandboxed command
and emits an `mcp_sandbox_fallback` event on stderr so the operator
notices their opt-in didn't take. The audit envelope carries a new
`sandboxed: bool` field on every call, so SOC tooling can prove
which calls actually ran wrapped.

Network policy is binary, not per-host, in this layer. The repo's
`network_egress` field is advisory and may list hostnames; layer 2
only enforces "all or nothing" — per-host iptables / pf rules are
out of scope until a future PR.

### Layer 3 — `RLIMIT_*` enforcement (always on, POSIX)

`mcp-server/src/resource_limits.py` clamps `RLIMIT_AS`, `RLIMIT_FSIZE`,
optionally `RLIMIT_NPROC`, and `RLIMIT_CPU` in a `preexec_fn` before
`exec()`. Tunable via `CLOUD_SECURITY_SKILL_MAX_BYTES` /
`MAX_FILE_BYTES` / `MAX_PROCESSES`. Windows has no `resource` module;
this layer is a documented no-op there.

## Read-only skills

These layers should stay read-only unless the skill contract says otherwise:
- `ingestion/`
- `discovery/`
- `detection/`
- `evaluation/`
- `view/`

Expected controls:
- no arbitrary shell passthrough
- no hidden writes
- no broad network egress outside documented API use
- deterministic `stdout` output
- warnings and skips only on `stderr`
- optional structured `stderr` telemetry via `SKILL_LOG_FORMAT=json` or `AGENT_TELEMETRY=1` for wrappers and operators that need machine-readable runtime hints; see [STDERR_TELEMETRY_CONTRACT.md](STDERR_TELEMETRY_CONTRACT.md)
- strict input validation before parse, convert, or cloud calls

Current pilots:
- `ingest-cloudtrail-ocsf`
- `detect-lateral-movement`
- `ingest-k8s-audit-ocsf`
- `detect-privilege-escalation-k8s`
- `ingest-okta-system-log-ocsf`
- `detect-okta-mfa-fatigue`
- `ingest-google-workspace-login-ocsf`
- `detect-google-workspace-suspicious-login`

## Write-capable skills and edge components

These are the only places where side effects should happen:
- `remediation/`
- future `sinks/`
- `runners/`

Current shipped exceptions:
- `iam-departures-aws` includes repo-owned Lambda handlers and infrastructure for its event-driven persistent path
- `runners/aws-s3-sqs-detect` ships a generic AWS reference runner for S3 → ingest → SQS → detect → DynamoDB dedupe → SNS

Required controls:
- `--dry-run` support
- explicit blast-radius docs
- approval gates for destructive actions
- dedicated credentials, separate from read-only analysis paths
- idempotency keys or merge-on-UID behavior
- immutable or append-only audit trail where feasible

Where the runtime supports it, write-capable skills should also preserve:
- caller identity
- approver identity
- session or request identifiers
- execution principal details
- change-control or ticket references

Those fields are part of the audit contract, not optional debug noise.

## Credentials and cloud access

Best practice for operators:
- use dedicated dev or sandbox accounts, subscriptions, or projects for local testing
- prefer short-lived credentials and workload identity over static secrets
- do not expose production credentials to agent sessions unless the task truly requires them
- keep remediation credentials separate from read-only discovery and detection credentials

Best practice for this repo:
- cloud SDK default chains are preferred over ad hoc token plumbing
- secrets come from secret stores or the execution environment, never hardcoded
- logs must not echo secrets, tokens, or connection strings

## Data in transit and at rest

Transport expectations:
- TLS for external API calls and remote sinks
- local MCP uses stdio, not an unauthenticated network listener
- MCP wrappers should emit invocation audit events that identify the tool, caller context presence, approval context presence, exit code, and a hashed argument payload without echoing secrets or raw stdin
- any network MCP transport must add explicit authentication, integrity, and timeout controls; the shipped opt-in SSE / streamable HTTP transport uses bearer keys, public-bind refusal, shared audit-chain integrity, and the same per-call timeout path as stdio

Storage expectations:
- findings, evidence, and inventories should be encrypted at rest in the chosen sink
- retention should be minimal and documented
- raw high-risk payloads should be retained only when justified by audit or replay needs

## Integrity, drift, and indexing

Threats to defend against:
- code drift
- skill poisoning
- prompt injection through untrusted logs or findings
- hidden write behavior in a read-only skill
- schema drift and deprecated vendor APIs
- dependency and supply-chain drift

Repo controls already in place:
- skill contract validation
- integrity validation
- dependency consistency validation
- framework coverage validation
- safe-skill bar checks

Operational guidance:
- use only official references in `REFERENCES.md`
- treat scanner output and upstream findings as untrusted input until validated
- keep deterministic identifiers for replay-sensitive artifacts
- prefer UTC epoch-millisecond timestamps in wire outputs
- index persistent stores on stable provider, account, region, resource, framework, and severity fields before free-form text

## Compatibility note

Some repo-local bridge and profile identifiers still use older names:
- `cloud_security_mcp`
- `cloud-security.environment-graph.v1`
- `cloud-security:*` CycloneDX property keys

Those names remain stable for compatibility with downstream readers. Public repo
identity and emitted OCSF `metadata.product` identity should still use
`cloud-ai-security-skills`.
