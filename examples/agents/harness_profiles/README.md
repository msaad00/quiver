# LangGraph harness profiles

Profiles are operator-owned configuration for the example harness. They do not
store secrets, credentials, OAuth callbacks, passwords, or approval tokens.

Use a profile with:

```bash
DEMO_HARNESS_PROFILE=examples/agents/harness_profiles/readonly-soc.json \
python examples/agents/langgraph_security_graph.py
```

Generate a custom profile with:

```bash
python examples/agents/configure_langgraph_harness.py \
  --role dry-run-remediation \
  --profile-id acme-remediation-dryrun \
  --email security@example.com \
  --cloud-hint aws=AWS_PROFILE=prod-readonly \
  --output-profile artifacts/acme-remediation-dryrun.json \
  --output-env artifacts/acme-remediation-dryrun.env
```

## Setup choices

The generator asks for metadata, not secrets. Pick the smallest role, the data
source mode, the model policy, and whether MCP calls should only be planned or
eligible for an operator-owned stdio transport.

| Decision | Generator flags | Effect |
|---|---|---|
| Role / privilege boundary | `--role readonly-soc`, `--role analyst-triage`, `--role dry-run-remediation`, or `--role sdk-cspm` | chooses read-only skills by default; only the dry-run role makes the remediation planner visible; `sdk-cspm` matches the shipped SDK agent profile |
| Caller identity | `--email`, optional `--user-id`, `--session-id`, `--roles` | audit attribution and IDP/ticketing context; not authentication |
| Cloud identity hint | `--cloud-hint provider=hint` | command or env hint the agent can show a human; credentials stay in the cloud CLI/SDK chain |
| Evidence source | `--data-source-mode raw-ingest` or `--data-source-mode security-lake-replay` | raw vendor events go through ingest; existing warehouse rows go through a read-only source query |
| Lake backend | `--lake-backend snowflake`, `clickhouse`, or `databricks` | selects `source-snowflake-query`, `source-clickhouse-query`, or `source-databricks-query` |
| Lake row shape | `--lake-records-format ocsf` or `raw_vendor` | OCSF rows skip raw normalization; raw rows keep source query followed by ingest |
| Model use | default deterministic mode, or `--external-llm --llm-provider ... --llm-model ...` | records provider/model metadata and bounded routing; model output cannot set facts, approval, or write intent |
| MCP execution | default `--mcp-execution-mode plan_only`, or `operator_stdio` with `--mcp-max-calls` | shipped default records the plan only; operator stdio mode can execute read-only calls through a separate transport |
| Approval source | `--approval-source`, `--min-approvers` | documents the HITL authority; the profile still cannot self-approve |

Security-lake replay profile:

```bash
python examples/agents/configure_langgraph_harness.py \
  --role analyst-triage \
  --profile-id acme-snowflake-replay \
  --email analyst@example.com \
  --data-source-mode security-lake-replay \
  --lake-backend snowflake \
  --lake-records-format ocsf \
  --lake-query "SELECT payload FROM security.events_sink LIMIT 100" \
  --output-profile artifacts/acme-snowflake-replay.json \
  --output-env artifacts/acme-snowflake-replay.env
```

Bounded external-model metadata:

```bash
python examples/agents/configure_langgraph_harness.py \
  --role analyst-triage \
  --profile-id acme-triage-drafting \
  --email analyst@example.com \
  --external-llm \
  --llm-provider openai \
  --llm-model gpt-4.1-mini \
  --output-profile artifacts/acme-triage-drafting.json \
  --output-env artifacts/acme-triage-drafting.env
```

Operator stdio planning for read-only MCP calls:

```bash
python examples/agents/configure_langgraph_harness.py \
  --role readonly-soc \
  --profile-id acme-readonly-stdio \
  --email analyst@example.com \
  --mcp-execution-mode operator_stdio \
  --mcp-max-calls 25 \
  --output-profile artifacts/acme-readonly-stdio.json \
  --output-env artifacts/acme-readonly-stdio.env
```

Inspect a profile before running the graph:

```bash
python examples/agents/inspect_langgraph_harness.py \
  --profile examples/agents/harness_profiles/readonly-soc.json
```

The generated dotenv file points `CLOUD_SECURITY_HARNESS_PROFILE` and
`DEMO_HARNESS_PROFILE` at the profile. It does not duplicate provider/model as
env overrides, and it intentionally omits `DEMO_APPROVE`; approval still has
to come from an explicit human approval context at runtime.

Profiles control:

- `allowed_skills`: operator-chosen skill surface; the example intersects it
  with the repo's known read/write skill set.
- `caller_context`: stable human or agent identity metadata for audit.
- `cloud_identity_hints`: commands or env hints the agent can surface to a
  human; credentials stay in the provider CLI/SDK chain.
- `llm`: provider/model metadata for bounded triage; model output can only
  rank, summarize, draft, or request human review.
- `model_policy`: task-to-tier routing for model selection; profiles choose
  the configured provider/model tier before env overrides are applied.
- `token_budget`: model tier and hard estimated token caps; the harness sends
  compact evidence cards only and falls back deterministically when a request
  would exceed budget.
- `agent_roster`: concise per-agent overrides for model tier, privilege
  boundary, skill scope, and HITL posture. The loader keeps the graph topology
  fixed and re-applies no-write/HITL guardrails.
- `approval_policy`: documentation of the HITL source; profiles never grant
  approval by themselves.
- `runtime.security_data_source`: whether the run ingests raw events or
  replays an existing Snowflake/ClickHouse/Databricks security lake.
- `runtime.mcp_execution`: whether planned MCP calls are only recorded
  (`plan_only`, the shipped default) or eligible for an operator-owned stdio
  transport. Example profiles keep `allow_write_calls=false`.

At runtime the harness emits `agent_policy`, which intersects the roster skill
scope with `allowed_skills`. Approval alone is not enough to reach dry-run
remediation; the remediation skill must also be present in the effective
allowlist. It also emits `mcp_call_plan` and `mcp_execution` separately, so
operators can distinguish intended MCP calls from calls actually executed by a
live transport.

Included profiles:

| Profile | Use |
|---|---|
| `readonly-soc.json` | SOC replay and triage without remediation tools |
| `analyst-triage.json` | Optional external-model metadata for analyst drafting |
| `dry-run-remediation.json` | HITL-gated dry-run remediation planning |
| `sdk-cspm-agent.json` | Anthropic, OpenAI, LangChain, and Cursor SDK MCP examples |
