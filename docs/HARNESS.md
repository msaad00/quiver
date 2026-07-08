# Harness — surfaces, customization knobs, scope boundary

One page that answers two questions:

1. **How do operators run, embed, and customize the shipped skills?**
2. **What does the repo NOT handle, on purpose?**

Read next:

- [`SKILL_CONTRACT.md`](SKILL_CONTRACT.md) — the per-skill bar
- [`SKILL_COMPOSITION.md`](SKILL_COMPOSITION.md) — workflows + presets
- [`MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md) — audit envelope
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — adversaries + mitigations

Visuals: [`diagrams/agent-topology.mmd`](diagrams/agent-topology.mmd) renders the full surface set; [`diagrams/mcp-trust-boundary.mmd`](diagrams/mcp-trust-boundary.mmd) traces the wrapper lifecycle; [`diagrams/pipeline-blast-radius.mmd`](diagrams/pipeline-blast-radius.mmd) colour-codes each layer by capability.

## Six surfaces, one bundle

The same `SKILL.md + src/ + tests/` runs unchanged behind all six
surfaces. None of them forks the skill model:

| Surface | Where | Use when |
|---|---|---|
| **CLI / pipes** | `python skills/<x>/<y>/src/<entry>.py` | quick local triage; CI scripts; ops one-liners |
| **CI** | `.github/workflows/ci.yml` lanes | gate a PR against a captured fixture |
| **MCP** | [`mcp-server/src/server.py`](../mcp-server/src/server.py) | any agentic client (Claude Code/Desktop, Cursor, Codex, Cortex, Windsurf, Zed) — stdio JSON-RPC |
| **Webhook** | [`runners/webhook-receiver/`](../runners/webhook-receiver/) | route a vendor callback / API gateway POST through ingest → sink |
| **Library SDK** | [`skills/_shared/library.py`](../skills/_shared/library.py) | external Python apps that want to call skills as functions |
| **Persistent runners** | [`runners/{aws-s3-sqs,gcp-gcs-pubsub,azure-blob-eventgrid}-detect/`](../runners/) | event-driven detection at cloud scale |

## Optional agentic SOC harness

LangGraph / LangChain / SOAR sit above the six skill surfaces. They may own
workflow state, model choice, routing, retries, checkpointing, escalation, and
analyst-note drafting, but they do not own security facts or write authority.

The reference implementation is
[`examples/agents/langgraph_security_graph.py`](../examples/agents/langgraph_security_graph.py):

```text
ingest -> normalize -> enrich -> correlate -> confidence -> map
-> bounded LLM triage -> analyst review
   approved -> dry-run remediation -> retry/escalate/writeback
   blocked  -> writeback
```

The importable wrapper is
[`examples/agents/harness_runtime.py`](../examples/agents/harness_runtime.py).
Use it when another runner wants the harness as code instead of shelling out
to the demo script:

```bash
PYTHONPATH=examples/agents python - <<'PY'
from harness_runtime import HarnessRunConfig, run_harness_summary

summary = run_harness_summary(HarnessRunConfig(
    profile_path="examples/agents/harness_profiles/readonly-soc.json",
    raw_events=({"source": "cloudtrail", "event_name": "CreateAccessKey"},),
))
print(summary["harness_runtime"]["validation_status"])
PY
```

Inspect a profile before running the graph:

```bash
python examples/agents/inspect_langgraph_harness.py \
  --profile examples/agents/harness_profiles/readonly-soc.json

python examples/agents/inspect_langgraph_harness.py \
  --profile examples/agents/harness_profiles/dry-run-remediation.json \
  --approval-context-present \
  --require-remediation-ready
```

The preflight inspector emits the same `agent_policy` effective-grants report
without replaying evidence, calling a model, reading credentials, or executing
remediation. `--require-remediation-ready` fails closed unless the remediation
skill is granted and an approval context is represented.

Run the executable harness wrapper:

```bash
python examples/agents/run_langgraph_harness.py \
  --profile examples/agents/harness_profiles/readonly-soc.json \
  --raw-events artifacts/events.jsonl \
  --caller-context '{"email":"analyst@example.com","session_id":"SEC-123"}'

python examples/agents/run_langgraph_harness.py \
  --profile examples/agents/harness_profiles/dry-run-remediation.json \
  --approve \
  --approver reviewer@example.com \
  --ticket SEC-123 \
  --checkpoint artifacts/langgraph-checkpoint.json

python examples/agents/run_langgraph_harness.py \
  --profile examples/agents/harness_profiles/dry-run-remediation.json \
  --approval-context artifacts/approval-context.json

python examples/agents/run_langgraph_harness.py \
  --replay-checkpoint artifacts/langgraph-checkpoint.json
```

LangGraph native interrupt/resume at the analyst HITL gate (separate from the
JSON checkpoint artifact above — this uses LangGraph's built-in checkpointer):

```bash
uv sync --group dev --group langgraph

PYTHONPATH=examples/agents python examples/agents/langgraph_hitl_interrupt_resume.py

CLOUD_SECURITY_HARNESS_PROFILE=examples/agents/harness_profiles/dry-run-remediation.json \\
  PYTHONPATH=examples/agents python examples/agents/langgraph_hitl_interrupt_resume.py
```

The demo pauses before ``review``, injects operator ``approval_context`` via
``update_state``, then resumes into dry-run remediation planning.

## Agent + AI pluggability — MCP first, not LCEL wrappers

Frameworks (LangChain, LangGraph, OpenAI Agents SDK, Anthropic Agent SDK, Cursor,
Codex) should bind the **repo MCP server** as their tool surface. Skills stay
behind one audited contract: allowlists, HITL gates, dry-run defaults, and
HMAC audit chains do not fork per framework.

| Do | Don't |
|---|---|
| Spawn `mcp-server/src/server.py` over stdio JSON-RPC | Wrap `python skills/.../detect.py` as `@tool` / LCEL chains |
| Load a harness profile for allowlists + caller context | Hard-code skill names in agent source |
| Keep remediation on a **separate** loop after human approval | Register `remediate-*` beside `detect-*` in one tool set |
| Pick model adapters inside the harness triage node only | Let the model invent CVSS/MITRE/approval facts |

Reference examples:

- [`examples/agents/sdk_agent_common.py`](../examples/agents/sdk_agent_common.py) — shared profile + live `tools/list` discovery
- [`examples/agents/anthropic_sdk_security_agent.py`](../examples/agents/anthropic_sdk_security_agent.py)
- [`examples/agents/openai_sdk_security_agent.py`](../examples/agents/openai_sdk_security_agent.py)
- [`examples/agents/langchain_mcp_security_agent.py`](../examples/agents/langchain_mcp_security_agent.py) — MCP stdio config block + anti-LCEL guidance (offline runnable; `langchain-mcp-adapters` when installed)
- [`examples/agents/cursor_mcp_security_agent.py`](../examples/agents/cursor_mcp_security_agent.py) — project `.cursor/mcp.json` block
- [`examples/agents/windsurf_mcp_security_agent.py`](../examples/agents/windsurf_mcp_security_agent.py) — Windsurf `mcp_config.json` block
- [`examples/agents/cortex_mcp_security_agent.py`](../examples/agents/cortex_mcp_security_agent.py) — Cortex `.cortex/mcp.json` block
- [`examples/agents/codex_mcp_security_agent.py`](../examples/agents/codex_mcp_security_agent.py) — Codex `config.toml` fragment
- [`examples/agents/zed_mcp_security_agent.py`](../examples/agents/zed_mcp_security_agent.py) — Zed `context_servers` block

Generate a profile with a workflow preset baked in:

```bash
python examples/agents/configure_langgraph_harness.py \
  --role sdk-cspm \
  --preset presets/preset-cspm-readonly.json \
  --profile-id acme-sdk-cspm \
  --email sdk-agent@example.com \
  --output-profile artifacts/acme-sdk-cspm.json \
  --output-env artifacts/acme-sdk-cspm.env
```

```bash
python examples/agents/langchain_mcp_security_agent.py

CLOUD_SECURITY_HARNESS_PROFILE=examples/agents/harness_profiles/sdk-cspm-agent.json \\
  DEMO_APPROVE=yes python examples/agents/langchain_mcp_security_agent.py
```

Bounded LLM triage inside the LangGraph harness uses pluggable adapters
(`harness_adapters.py`): deterministic offline, JSON fixture, OpenAI-compatible
HTTP, or LangChain chat-message fixtures — all validated before they touch
workflow state.

Execute or re-evaluate the emitted MCP plan as a separate artifact:

```bash
python examples/agents/run_langgraph_harness.py \
  --profile examples/agents/harness_profiles/readonly-soc.json \
  --output artifacts/harness-summary.json

python examples/agents/execute_langgraph_mcp_plan.py \
  --summary artifacts/harness-summary.json \
  --output artifacts/harness-mcp-execution.json
```

The runner calls the same importable wrapper used by CI or SOAR integrations,
keeps validation on by default, and accepts `--langgraph-runtime` when the
optional LangGraph dependency is installed. `--approve` only supplies demo
HITL metadata; remediation still requires the profile allowlist and remains
dry-run only. Embedded callers should pass `approval_context` directly to
`HarnessRunConfig`; the older `DEMO_APPROVE` environment variables remain a
compatibility path for the original example script.

Each profile also declares `runtime.security_data_source`, so the harness does
not guess whether a tenant/account needs raw ingest or security-lake replay.
Use `mode=raw_ingest` with `source_skill=ingest-cloudtrail-ocsf` when evidence
arrives as raw vendor events. Use `mode=security_lake_replay` with
`source-snowflake-query`, `source-clickhouse-query`, or
`source-databricks-query` when OCSF or raw rows already live in the customer
lake. `records_format=ocsf` tells the MCP call planner to skip the raw
normalizer; `records_format=raw_vendor` keeps the source query followed by the
ingest/normalize skill. Queries stay read-only and credentials remain outside
the profile.

Profiles also declare `runtime.mcp_execution`. The shipped profiles use
`mode=plan_only`, `transport=mcp_stdio_jsonrpc`,
`execute_planned_calls=false`, and `allow_write_calls=false`. The graph still
builds exact MCP `tools/call` JSON-RPC payloads, but the harness emits a
separate `mcp_execution` ledger showing those planned calls were skipped by
policy. Operator-owned integrations can opt a generated profile into
`mode=operator_stdio` for read-only call execution through their own MCP
transport. The standalone `execute_langgraph_mcp_plan.py` utility consumes an
existing harness summary and emits a second execution report, so live transport
attempts do not mutate the graph's state hash. It uses a credential-scrubbed
subprocess environment for the bundled stdio helper; write-capable execution
remains disabled in the example schema.

`HARNESS.md` is therefore the readable operator contract; the graph nodes,
adapter gates, runtime wrapper, schemas, checkpoint replay, and eval runner are
the executable harness.

Diagram source:
[`docs/diagrams/langgraph-agent-harness.mmd`](diagrams/langgraph-agent-harness.mmd).
It is generated from the code-backed `pipeline_contract()`:

```bash
python examples/agents/render_langgraph_pipeline_diagram.py \
  --output docs/diagrams/langgraph-agent-harness.mmd
```

Drift check:

```bash
python examples/agents/check_langgraph_harness_drift.py
```

The drift checker regenerates the diagram from `pipeline_contract()` in memory,
validates closed schemas and stock profiles, verifies metadata-only preflight
policy, runs the importable wrapper validation path, checks harness docs/CI
references, and scans the harness docs/profiles for PAT/API-key/password
literals. It also verifies that stock profiles declare MCP execution policy and
do not enable write-capable execution. It remains offline: no cloud
credentials, model calls, approval tokens, cloud APIs, or remediation
execution.

The LLM/agent harness records provider/model/mode, model-policy selection, and
token-budget policy in state and audit output. `model_policy` selects the
configured provider/model tier for the triage task; `token_budget` caps input,
output, finding count, and compact evidence size. Its allowed outputs
are intentionally narrow: rank findings, summarize evidence, draft analyst
notes, and request human review. It cannot set CVSS, MITRE, EPSS, KEV, tenant
scope, idempotency keys, HITL approval, dry-run state, or audit-chain facts.
The compiled LangGraph path uses conditional edges for HITL, retryable API
errors, terminal API errors, duplicate write suppression, and audit/eval
writeback; the offline runner mirrors those routes for tests.

Model-backed triage plugs in through a bounded adapter contract in
[`examples/agents/harness_adapters.py`](../examples/agents/harness_adapters.py).
The graph can select deterministic fallback, a JSON fixture, or an optional
LangChain chat-message fixture, then accepts only `finding_uid`, `priority`,
`recommended_action`, and `rationale`; forbidden fields such as `approval`,
`cvss`, `mitre`, `epss`, `kev`, `tenant_scope`, `idempotency_key`, or
`write_intent` are rejected and replaced by deterministic fallback. The summary
and audit record expose `llm_validation` plus accepted/rejected counts so
operators can see whether model output influenced triage without letting it
mutate facts.
Before an optional adapter sees anything, the graph compacts deterministic
findings, confidence, framework mappings, and evidence references into small
cards. The run ledger records estimated raw input tokens, compact input tokens,
output tokens, compression ratio, model tier, cache key, and deterministic
fallback when the budget is exceeded.

The example exposes a concrete `agents` manifest and `agent_runs` ledger:
`evidence-agent`, `risk-map-agent`, `triage-agent`, `review-gate`,
`remediation-planner`, `retry-coordinator`, `escalation-agent`, and
`audit-writer`. Profiles can declare concise `agent_roster` overrides for
model tier, privilege boundary, skill scope, and HITL posture. Runtime loading
then re-applies fixed graph ownership and safety boundaries: the LLM triage
agent keeps `no_tool_writes` with an empty skill scope, while remediation
planning keeps `dry_run_write_planning` and requires human approval. Each run
carries an authority label plus input/output hashes so replay can detect drift
without trusting prompt text.
The summary also emits `agent_policy`, a compiled effective-grants report that
intersects each agent's roster skill scope with the profile allowlist. It shows
granted skills, denied skills, model tier, write policy, approval satisfaction,
and a stable `policy_hash` copied into audit.
The operator-facing summary also emits `pipeline_contract`, a code-backed list
of nodes, edges, route conditions, skills, input/output state keys, and
guardrails for approval, dry-run remediation, retries, idempotency, and audit
writeback.

The same example can persist a checkpoint artifact after writeback:

```bash
DEMO_CHECKPOINT_PATH=artifacts/langgraph-checkpoint.json \
python examples/agents/langgraph_security_graph.py

DEMO_REPLAY_CHECKPOINT=artifacts/langgraph-checkpoint.json \
python examples/agents/langgraph_security_graph.py
```

The artifact stores `schema_version=langgraph-soc-checkpoint-v1`, final graph
state, `state_hash`, `summary_hash`, and `checkpoint_hash`, and matches a
closed schema envelope. Replay verifies those hashes before returning the
operator-facing summary and does not re-run graph nodes or tool calls.

Eval fixtures live under
[`examples/agents/evals/`](../examples/agents/evals/). The offline gate
replays golden profile and triage cases through the same graph, checks bounded
recommendation shape, HITL routing, allowlist intersection, and remediation
blocking, and covers both accepted and rejected LLM adapter output. It also
checks integrity hashes, remediation idempotency keys, retryable API errors,
terminal API errors, retry queue routing, and human escalation routing, then
emits a pass-rate report:

```bash
python examples/agents/eval_langgraph_harness.py --check

python examples/agents/eval_langgraph_harness.py --check \
  --output artifacts/langgraph-harness-eval.json \
  --append-jsonl artifacts/langgraph-harness-eval-history.jsonl
```

This is regression tracking for orchestrator behavior, not an LLM-as-judge.
It does not call a live model; live model quality checks can be layered on top
later with the same dataset/version/report contract. The JSON report captures
the latest run, while the JSONL history gives CI, release checks, or customer
forks an append-only pass-rate trail for harness drift. Both output forms
share a closed eval-report schema.

Operator profiles live under
[`examples/agents/harness_profiles/`](../examples/agents/harness_profiles/).
They are JSON metadata only: allowed skills, caller context, identity hints,
LLM provider/model metadata, model-policy selection, token-budget limits,
agent-roster overrides, and approval-policy documentation. They do not store
cloud secrets and they do not grant approval. A remediation profile can make a
dry-run skill visible, but the graph still needs `_approval_context` from the
operator's IDP or ticketing workflow before routing to remediation. Profiles
can declare `model_policy`, `token_budget`, and `agent_roster` together so
small triage tasks stay on tiny/small model tiers, oversized context falls back
deterministically, and write-capable stages remain deterministic plus HITL.
Closed JSON Schema contracts live under
[`examples/agents/schemas/`](../examples/agents/schemas/) for harness
profiles, LLM adapter recommendation payloads, emitted `agent_policy`, and the
emitted `pipeline_contract` topology. Checkpoint artifacts have a closed schema
envelope for replay persistence, and eval reports use a shared schema for
both JSON output and JSONL history rows.

## Customization knobs

Five tiers of override. Outer wins:

```
CLOUD_SECURITY_*  env  >  caller_context  >  preset.json  >  SKILL.md frontmatter  >  defaults
```

| Knob | Where | What |
|---|---|---|
| Tool surface | `CLOUD_SECURITY_MCP_ALLOWED_SKILLS` env | comma-separated allowlist; default = all skills |
| Per-caller surface | `_caller_context.allowed_skills` JSON field on every call | intersects with the operator allowlist |
| Workflow surface | [`presets/*.json`](../presets/) | named allowlists tied to a workflow doc |
| Audit destination | `CLOUD_SECURITY_MCP_AUDIT_LOG` + `CLOUD_SECURITY_AUDIT_HMAC_KEY` | durable JSONL + HMAC chain |
| Per-call timeout | `mcp_timeout_seconds` in SKILL.md, or `CLOUD_SECURITY_MCP_TIMEOUT_SECONDS` env | wall-clock cap |
| Resource caps | `CLOUD_SECURITY_SKILL_MAX_BYTES` / `MAX_FILE_BYTES` / `MAX_PROCESSES` | RLIMIT enforcement |
| OS sandbox (opt-in) | `CLOUD_SECURITY_MCP_SANDBOX=on` | wrap each skill subprocess under `bwrap` (Linux) / `sandbox-exec` (macOS); fs/pid/ipc isolation; network dropped only when `network_egress: []` declared; no-op fallback if wrapper binary absent |
| Persistent worker pool (opt-in) | `CLOUD_SECURITY_MCP_WORKER_POOL=on` | keep one warm interpreter per evaluation skill (`cspm-{aws,gcp,azure}-cis-benchmark`, `k8s-security-benchmark`, `container-security`); JSON-RPC over stdin/stdout per call; idle-TTL killed via `CLOUD_SECURITY_MCP_WORKER_IDLE_SECONDS` (default 300s); hard-kill on stdout > `CLOUD_SECURITY_MCP_WORKER_MAX_BYTES` (default 10 MB); same env scrub + RLIMIT + sandbox wrap as the one-shot path; no cross-call state |
| Retry policy | `CLOUD_SECURITY_RETRY_MAX_ATTEMPTS` / `BASE_SECONDS` / `CAP_SECONDS` / `TOTAL_BUDGET_SECONDS` | bounded by construction |
| Webhook auth | `WEBHOOK_HMAC_SECRETS` / `WEBHOOK_HMAC_HEADER` / `WEBHOOK_BEARER_TOKEN` | per-skill HMAC + bearer |
| Webhook routing | `WEBHOOK_ALLOWED_SKILLS` / `WEBHOOK_SINK_TARGETS` | default-deny |
| Helm | [`runners/webhook-receiver/templates/helm/values.yaml`](../runners/webhook-receiver/templates/helm/values.yaml) | resource limits, security context, audit volume |

## Authentication — what the repo does and doesn't do

**The repo does not authenticate end users.** That's the cloud CLI's
job and the operator's IDP's job. We never see passwords, never store
tokens, never cache credentials, never speak SAML / OIDC / SCIM as a
client.

What the repo does:

1. **Reads the cloud SDK default credential chain.** `boto3` /
   `google.cloud.*` / `azure-identity` / `snowflake-connector` all
   look up credentials in the same order they always do — env var,
   shared file, instance metadata, workload identity, federated SSO
   token. The skill only calls `boto3.client(...)` and trusts the
   chain.
2. **Surfaces a structured `ConfigError` when creds are missing.**
   The error envelope (`skills/_shared/errors.py`) carries a `hint`
   field telling the caller exactly what to run (e.g.
   `aws sso login --profile prod-readonly`). The agent (Claude Code /
   Cortex / etc.) can pattern-match on the hint and prompt the user.
3. **Forwards `SKILL_CALLER_*` audit metadata.** The MCP wrapper
   passes the caller's identity into the skill subprocess so audit
   logs can attribute actions to a real human, not just to the
   ambient cred. The actual *authentication* of that human happens
   upstream of the wrapper.

### Worked example: Snowflake employee, Claude + Cortex, company SSO

```text
1. Employee runs `snowflake-cli auth login --authenticator externalbrowser`
   once per shift (their company's SSO flow opens a browser, returns
   an MFA-stamped token, caches it under ~/.snowflake/).
2. Employee opens Claude Code (or Cortex) — the agent is configured
   to load the repo's MCP server.
3. Agent calls `tools/call source-snowflake-query`. The MCP wrapper
   invokes the skill subprocess; the skill calls
   `snowflake.connector.connect()` with no creds in args; the
   connector reads ~/.snowflake/ and uses the cached SSO token.
4. If the token has expired, the skill returns:
     {"event":"skill_error","error_class":"auth","retryable":false,
      "hint":"snowflake-cli auth login --authenticator externalbrowser"}
   The agent surfaces the hint to the human, who refreshes once.
5. Audit log carries `caller_email` from `_caller_context` so the
   query is attributed to the human, not to the SSO service principal.
```

The same pattern works for AWS IAM Identity Center, Microsoft Entra,
GCP Workforce Identity. **The operator's IDP integration is upstream
of the repo.** We delegate, we don't re-implement.

## Scope boundary — what we handle vs delegate

To stop redundancy creep, we draw the line clearly.

| Concern | Repo's job | Delegated to |
|---|---|---|
| Skill contract + lifecycle | ✓ | — |
| Trust controls (allowlist, dry-run, HITL, audit, RLIMIT, env scrub) | ✓ | — |
| Wire format (OCSF / native / bridge) | ✓ | — |
| Per-skill retry / error / log envelope | ✓ | — |
| **Cloud authentication** | error-fast with hint | cloud CLI / SDK credential chain (`aws sso login`, `gcloud auth login`, etc.) |
| **Identity federation (SSO)** | propagate `caller_id` | operator's IDP (Okta / Entra / Workforce) |
| **TLS termination** | speak HTTP behind a WAF | operator's API gateway / WAF |
| **Multi-tenancy** | one process = one tenant | operator routes per-tenant via separate processes / containers |
| **Secret management** | read env vars | operator's KMS / Vault / sealed-secrets |
| **Workflow orchestration** | reference harness in `examples/agents/` plus specs in `examples/workflows/` | operator's production SOAR / Step Function / LangGraph |
| **State persistence (dedupe, checkpoint)** | reference checkpoint artifacts only | runners own production state, skills are stateless |
| **Rate limiting incoming traffic** | — | operator's API gateway |
| **Authorization to remediate** | enforce HITL gate | operator's IDP attests `_approval_context` |

### Anti-redundancy rules

These rules exist so a future PR doesn't accidentally re-implement
something the SDK / IDP / WAF / agent already does:

- **Never store passwords or tokens.** If the repo would need a
  database table to hold them, that work belongs upstream of the
  wrapper.
- **Never speak SAML / OIDC as a client.** The cloud CLI does that.
- **Never ship a hosted workflow engine by default.** Reference harnesses can
  show LangGraph/SOAR composition, but production orchestration remains
  operator-owned.
- **Never proxy traffic to the cloud.** The skill calls the cloud SDK
  directly; latency, retries, and TLS are the SDK's concern.
- **Never persist user state between calls.** Skills are pure
  functions over inputs. State lives in runners or operator
  databases.

## Surface comparison cheat-sheet

```
                     CLI    CI    MCP   Webhook   Library
read-only skills      ✓      ✓     ✓      ✓         ✓
write skills (HITL)   ✓      ✓     ✓      ✗         ✓
audit envelope        stderr ✓     ✓      ✓         ✓
RLIMIT enforced       ✗      ✗     ✓      ✓         ✓
default-deny routing  n/a    n/a   opt-in opt-in    opt-in
allowlist tiers       1      1     3      2         1
```

`MCP` and `Library` go through the registry's gate. `CLI` skips it
because the local user is trusted; CI skips it because the CI runner
is trusted. `Webhook` adds an HMAC + default-deny layer because the
ingress is not trusted.

## Login / privileges / roles — what the best practice actually is

The instinct is to pick one of {standard, customizable, prompted}. The
right answer is **all three, in layers**, because each solves a
different problem:

```
                   identity   privileges   UX
─────────────────  ────────   ──────────   ──────────────────────────
Standard           ✓ delegated to IDP
Customizable                  ✓ via env vars + SKILL.md frontmatter
Prompted                                   ✓ via agent surfacing hints
```

### 1. Standard — the always-on baseline

Skills use the cloud SDK's default credential chain. **Don't reimplement
SSO.** The chain already handles:

- Workload identity (EKS IRSA, GKE Workload Identity, AKS Pod Identity)
- IDC / SSO-cached tokens (`aws sso login`, `gcloud auth login`,
  `az login`, `snowflake-cli auth login --authenticator externalbrowser`)
- Federated tokens (OIDC → STS:AssumeRoleWithWebIdentity, Workforce
  Federation, Azure App Registration)
- Static credentials (only when an operator explicitly opts in)

**Best practice:** every shipped skill uses the SDK default chain.
Zero config in the common case.

### 2. Customizable — pinning an identity per deployment

Operators with multiple cloud accounts / projects / tenants need to
pin which identity each skill assumes. The repo exposes this via:

- **Env vars** the SDK already honours: `AWS_PROFILE`, `AWS_ROLE_ARN`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_CLIENT_ID`,
  `SNOWFLAKE_ACCOUNT` / `SNOWFLAKE_USER` / `SNOWFLAKE_AUTHENTICATOR`,
  `OKTA_DOMAIN` + `OKTA_API_TOKEN`. Pass-through via the wrapper's
  `CLOUD_SECURITY_*` namespace OR the SDK's own variable name.
- **SKILL.md frontmatter** declares `caller_roles` + `approver_roles`
  (vocabulary the operator's IDP attests).
- **Per-skill IAM policies** under `skills/<x>/<y>/infra/iam_policies/`
  ship the *minimum* permission set; CI rejects wildcard actions
  without a `WILDCARD_OK` justification.

**Best practice:** operators pin identity via SDK env vars at
deployment, not in code. Skills never embed account IDs / role ARNs.

### 3. Prompted — the agent surfaces, the skill detects

Skills are **non-interactive by design**. They never prompt.

When credentials are missing or expired, the skill emits a structured
error (the `skills/_shared/errors.py` envelope) with three machine-
readable hooks the agent uses:

- `error_class: "auth"` — the agent knows this is recoverable by user
  action, not a bug.
- `retryable: false` — the agent doesn't auto-retry; the user has to
  do something.
- `hint: "aws sso login --profile prod-readonly"` — the literal command
  the user runs to fix it.

The agent (Claude Code / Claude Desktop / Cursor / Codex / Cortex)
pattern-matches on `error_class == "auth"` and surfaces the `hint` to
the user. The agent **does not** capture the user's password / MFA
code / OAuth callback. The cloud CLI does that.

**Best practice:** skill detects + reports, agent surfaces, user runs
the cloud CLI. Three roles, three boundaries, no overlap.

### When is "prompted" the wrong answer?

When the calling surface is non-interactive: CI, runners, server-side
agent loops on a schedule. There is no human to prompt. In those
contexts:

- The skill must fail closed with the same structured error.
- The runner / scheduler emits the error to the operator's alerting
  pipeline (`error_class: "auth"` is a routable severity).
- Workload identity should be in place before the workflow ships, so
  this branch should never fire in production.

### Bottom line

Skills delegate identity. Skills check authorization. Skills detect
expired creds and surface a hint. **The agent and the cloud CLI do
the rest.** That's the smallest contract that doesn't redundantly
re-implement SSO, IDP, or the cloud SDK's credential chain.

## What Anthropic suggests, and how the repo aligns

Anthropic publishes guidance on tool design, MCP servers, Claude Agent SDK
patterns, and sandbox posture. The repo intentionally tracks those
recommendations — the alignment is documented here so future PRs can
check against the platform's bar instead of re-deriving it.

| Anthropic recommendation | Where it appears | Repo alignment |
|---|---|---|
| **SKILL.md frontmatter format** (Claude Skills) | [Anthropic Skills overview](https://docs.claude.com/en/docs/claude-code/skills) | ✓ every shipped skill carries the same shape (`name`, `description`, `Use when` / `Do NOT use`, capability metadata). Validator: `scripts/validate_skill_contract.py` |
| **MCP `tools/list` returns names + structured annotations** | [MCP spec 2025-06-18](https://modelcontextprotocol.io/) | ✓ structured `annotations` (category, capability, approvalModel, executionModes, sideEffects, callerRoles, approverRoles, networkEgress, minApprovers) replaced the legacy description blob in #424 |
| **`readOnlyHint` / `destructiveHint` / `idempotentHint`** | MCP spec | ✓ shipped on every tool; derived from SKILL.md frontmatter |
| **Closed-set input schemas (`additionalProperties: false`)** | MCP spec | ✓ enforced for `_caller_context` + `_approval_context` (#413/#424). Unknown keys → `-32602 Invalid params` |
| **Subagent + least-privilege tool surface** | [Claude Agent SDK](https://docs.claude.com/en/api/agent-sdk) | ✓ caller-allowlist intersection (`_caller_context.allowed_skills`) lets a parent agent restrict what a sub-agent can call. See [`presets/`](../presets/) for named bundles |
| **Lifecycle hooks for guardrails** | [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks) | ✓ matches the wrapper's `_call_tool` lifecycle: pre-call validation (allowlist + schema), pre-call gate (dry-run + HITL), post-call audit |
| **Structured tool-output JSON** | tool-design guidance | ✓ every skill emits OCSF / native JSONL on stdout; errors use the `SkillError` envelope (#437) |
| **MCP server runs sandboxed** | [Anthropic security guidance](https://www.anthropic.com/news/agent-capabilities-api) | ✓ #428 adds RLIMIT enforcement; #438 adds container hardening (non-root, read-only, cap-drop, seccomp) |
| **Bounded retries — never infinite** | tool-design guidance | ✓ `skills/_shared/retry.py` is bounded by construction: floor 1, ceiling 10 attempts, ceiling 600 s wall-clock, permanent-error short-circuit, no recursive retries (#437) |
| **Authentication delegated to the platform / cloud CLI** | [Claude Desktop config docs](https://docs.claude.com/en/docs/claude-code/mcp) | ✓ skills use the cloud SDK default credential chain. Repo never sees passwords or tokens |
| **OAuth via MCP for vendor APIs** | MCP spec 2025-06-18 | ⏳ not yet — we delegate to the cloud CLI. A follow-up could orchestrate an MCP-side OAuth dance for SaaS APIs (Workday, Okta) where the cloud-CLI pattern doesn't fit |
| **Plain-text agent file format (`AGENTS.md`)** | [Anthropic docs](https://docs.claude.com/en/docs/claude-code/memory) | ✓ shipped at repo root; tells the agent the repo's guardrails before any tool call |
| **Workflow composition by transcript, not inheritance** | Claude Agent SDK pattern | ✓ atomic skills + workflow markdown specs + presets (no nested sub-skills). [`SKILL_COMPOSITION.md`](SKILL_COMPOSITION.md) |
| **Observability — one record per tool call** | tool-design guidance | ✓ exceeded — durable JSONL audit + HMAC-SHA-256 chain + tamper-evident verifier (#410) |

### Where we go beyond Anthropic's baseline

These aren't in Anthropic's published guidance because they're
operator-side, not platform-side, but they fit naturally with the
agent model:

- **HITL gate at the wrapper.** Anthropic's tool-design guidance calls
  for human approval on destructive actions; we *enforce* it via the
  `min_approvers` count rather than relying on the agent to ask.
- **Tamper-evident audit chain.** HMAC-SHA-256 over `prev_hash + event`
  makes the audit log a usable forensic artifact, not just a stream.
- **Closed-set workflow surfaces.** `presets/*.json` with CI validation
  (`scripts/validate_presets.py`) so a renamed skill cannot silently
  break a deployed allowlist.
- **Coverage as code.** `docs/COVERAGE_SNAPSHOT.md` is regenerable from
  `framework-coverage.json` with a CI gate; the README's progress
  numbers stop drifting.

### Where the repo deliberately differs

- **No agent-side prompting from inside a skill.** Skills are
  non-interactive; the agent surfaces auth hints. Anthropic's tool
  pattern allows interactive tools, but for cloud + AI security work
  determinism beats interactivity.
- **No managed multi-tenant runtime.** Anthropic's hosted Skills are
  multi-tenant; this repo ships single-tenant primitives operators
  run themselves. The trust contract stays in the operator's hands.

### Reading list (Anthropic primary sources)

- `https://docs.claude.com/en/docs/claude-code/skills` — Claude Skills format
- `https://docs.claude.com/en/api/agent-sdk` — Claude Agent SDK reference
- `https://modelcontextprotocol.io/` — MCP spec
- `https://docs.claude.com/en/docs/claude-code/hooks` — lifecycle hooks
- `https://docs.claude.com/en/docs/claude-code/memory` — `AGENTS.md` / `CLAUDE.md`
- `https://docs.claude.com/en/docs/claude-code/mcp` — MCP server config in Claude Code
