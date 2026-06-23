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
