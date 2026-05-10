# Performance — cold-start vs warm-pool

Most skills shipped here are short-lived CLIs. The MCP wrapper spawns one
fresh `python` process per `tools/call`, the skill imports its cloud SDK,
does its work, and exits. That model is the right default — it keeps the
trust envelope tight (RLIMIT, env scrub, optional sandbox wrap re-apply
to every call) and stateless.

It also has one ugly tail: a benchmark that walks 60+ controls in
sequence pays the full cold-import cost on each call, and on a typical
audit machine that's 12-18 seconds of `boto3` / `google-cloud-*` /
`azure-mgmt-*` import latency before any work runs.

## Opt-in persistent-worker pool

Operators who run the evaluation-layer benchmarks in a hot loop can opt
in to a process-local pool that keeps one interpreter warm per skill
name and pipes JSON-RPC `tools/call` messages over stdin/stdout per
invocation:

```bash
export CLOUD_SECURITY_MCP_WORKER_POOL=on
```

The pool is **off by default**. Operators who don't set the env var see
no behavioural change — the wrapper still spawns one fresh subprocess
per call.

### What's wired today

The pool currently warms five evaluation-layer skills:

- `cspm-aws-cis-benchmark`
- `cspm-gcp-cis-benchmark`
- `cspm-azure-cis-benchmark`
- `k8s-security-benchmark`
- `container-security`

These are the obvious hot loops: each iterates dozens of CIS controls
and re-pays the SDK import on every one. Other skills can opt in later
by adding a `worker_mode: true` line to their `SKILL.md` frontmatter
and the four-line `--worker` block to their entrypoint (see
`skills/_shared/worker_harness.py`).

### Latency expectations

CSPM walks dominate cold-import wall time. Local hands-on against
`cspm-aws-cis-benchmark` on the audit machine (no AWS credentials, so
the workload short-circuits early — wall time is mostly process spin-up
plus `boto3` import):

| Scenario | Wall time |
|---|---|
| Fresh process per call (current default) | ~12-18s with credentials, ~0.27s without |
| Warm pool — first call | same as cold (one-time spawn) |
| Warm pool — subsequent calls | ~1-2s with credentials, ~0.10s without |

The numbers depend heavily on what your skill imports and how many AWS
calls each control issues. The shape (subsequent calls dominated by
work, not import) is consistent.

### Knobs

| Env var | Default | What |
|---|---|---|
| `CLOUD_SECURITY_MCP_WORKER_POOL` | unset (off) | Truthy values: `1`, `true`, `yes`, `on`. |
| `CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS` | 300 | A worker idle longer than this is killed on the next dispatch and re-spawned cold next call. |
| `CLOUD_SECURITY_MCP_WORKER_MAX_BYTES` | 10485760 (10 MB) | Single-call stdout cap. A worker that exceeds it is killed; the call returns exit 1 with a diagnostic. |

### What the pool does NOT change

- **Trust envelope.** RLIMIT_AS / FSIZE / NPROC / CPU still apply — the
  worker process is the one that hits them. Env scrubbing is applied at
  spawn time. Sandbox wrap (`bwrap` / `sandbox-exec`) composes by
  construction; the worker is launched inside the wrapper just like a
  one-shot call.
- **Audit envelope.** One `mcp_tool_call` audit event per resolved tool
  call, identical fields to the one-shot path. The new
  `worker_mode_used: bool` field marks calls that took the warm path.
- **Cross-call state.** The worker is reused as a latency optimisation,
  not a contract for cross-call state. Skills that mutate module-level
  state between calls do so at their own contract risk and should not
  opt in.

### Failure modes

- **Output overflow.** A single call producing more than
  `CLOUD_SECURITY_MCP_WORKER_MAX_BYTES` of stdout kills the worker. The
  current call returns exit 1 with stderr explaining the cap; the next
  call re-spawns cold.
- **Worker crash.** A worker that exits between calls is detected on
  the next dispatch — the pool reaps the corpse, returns the call as
  exit 1, and the call after that re-spawns fresh.
- **Idle TTL.** Workers with no recent calls are killed on the next
  dispatch. Tune `CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS` for tighter
  or looser holds.
- **Process exit.** An `atexit` hook reaps every warm worker on normal
  interpreter shutdown so the wrapper does not leak warmed
  interpreters.
