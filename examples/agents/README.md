# Agent-SDK integration examples

Reference implementations showing how to load `cloud-ai-security-skills`
via MCP from inside an agent-framework loop, while keeping **every guardrail
intact**. The same MCP wrapper enforces HITL, dry-run, audit, and the skill
allowlist regardless of which SDK is driving the loop.

| Example | Framework | What it shows |
|---|---|---|
| [`anthropic_sdk_security_agent.py`](anthropic_sdk_security_agent.py) | Anthropic Python SDK (Managed Agent) | CSPM scan → triage loop with HITL gate on remediation |
| [`openai_sdk_security_agent.py`](openai_sdk_security_agent.py) | OpenAI Agents SDK | Parallel port of the Anthropic example for portability |
| [`langchain_mcp_security_agent.py`](langchain_mcp_security_agent.py) | LangChain | MCP-first stdio pattern; `langchain-mcp-adapters` config when installed — not LCEL skill wrappers |
| [`cursor_mcp_security_agent.py`](cursor_mcp_security_agent.py) | Cursor | Project-scoped `.cursor/mcp.json` + harness profile; same MCP audit/HITL contract |
| [`windsurf_mcp_security_agent.py`](windsurf_mcp_security_agent.py) | Windsurf | `~/.codeium/windsurf/mcp_config.json` + harness profile; absolute-path MCP stdio |
| [`cortex_mcp_security_agent.py`](cortex_mcp_security_agent.py) | Cortex Code CLI | Project-scoped `.cortex/mcp.json` + harness profile; `${workspaceFolder}` MCP stdio |
| [`codex_mcp_security_agent.py`](codex_mcp_security_agent.py) | Codex | `~/.codex/config.toml` fragment + harness profile; absolute-path MCP stdio |
| [`zed_mcp_security_agent.py`](zed_mcp_security_agent.py) | Zed | `~/.config/zed/settings.json` `context_servers` block + harness profile; absolute-path MCP stdio |
| [`emit_mcp_client_configs.py`](emit_mcp_client_configs.py) | All IDE clients | Offline bundle of Cursor/Cortex/Windsurf/Codex/Zed MCP blocks from one harness profile |
| [`langgraph_security_graph.py`](langgraph_security_graph.py) | LangGraph | SOC workflow DAG: ingest → normalize → enrich → correlate → confidence → MITRE/CVSS/EPSS/KEV map → HITL → dry-run remediation → audit/eval writeback |
| [`langgraph_hitl_interrupt_resume.py`](langgraph_hitl_interrupt_resume.py) | LangGraph | Native `interrupt_before` + checkpointer at the analyst review gate; operator resumes with `approval_context` |

Anthropic and OpenAI examples load [`harness_profiles/sdk-cspm-agent.json`](harness_profiles/sdk-cspm-agent.json) by default so allowlists, caller context, and MCP execution policy stay customizable without editing Python.

Optional workflow preset overlay (intersects with the harness profile — fail closed on empty):

```bash
CLOUD_SECURITY_MCP_PRESET=presets/preset-cspm-readonly.json \
  python examples/agents/anthropic_sdk_security_agent.py
```

See [`../../presets/README.md`](../../presets/README.md) for shipped presets.

Generate a matching harness profile (same allowlist shape as
[`harness_profiles/sdk-cspm-agent.json`](harness_profiles/sdk-cspm-agent.json)):

```bash
python examples/agents/configure_langgraph_harness.py \
  --role sdk-cspm \
  --preset presets/preset-cspm-readonly.json \
  --profile-id acme-sdk-cspm \
  --email sdk-agent@example.com \
  --output-profile artifacts/acme-sdk-cspm.json \
  --output-env artifacts/acme-sdk-cspm.env \
  --emit-mcp-configs artifacts/mcp-client-configs.json
```

Or emit IDE MCP blocks from an existing profile:

```bash
python examples/agents/emit_mcp_client_configs.py \
  --profile artifacts/acme-sdk-cspm.json \
  --output artifacts/mcp-client-configs.json
```

## Safety posture — every example enforces the same invariants

1. **Read-only skill allowlist.** MCP SDK and IDE reference examples set
   `CLOUD_SECURITY_MCP_ALLOWED_SKILLS=<comma-separated read-only skills>` on
   the MCP server subprocess. Remediation skills are **not** registered as
   tools. An agent loop cannot call what isn't on the list.
2. **HITL gate before remediation is added to the tool registry.** The
   "correct pattern" demos never put `remediate-*` skills in the model's
   tool set in the first place. A second chain — gated by a human operator
   passing `_approval_context` — is required to reach remediation.
3. **Dry-run default.** If a write-capable skill is ever added to the
   allowlist, the MCP wrapper refuses any call that doesn't include
   `--dry-run`. Examples demonstrate this with an explicit assertion.
4. **Audit record per tool call.** Each example prints the MCP audit line
   (`{event: mcp_tool_call, correlation_id, ...}`) so an operator running
   the example can see the forensic trail land.
5. **Explicit `caller_context`.** Each example passes a stable
   `caller_context` (user_id, session_id) so the audit record ties the
   agent invocation to the operator — not to a headless session.

## Anti-pattern called out — agent-loop exploitation

This README includes a `DONT_DO_THIS` section below showing a naive loop that
chains `detect → remediate` without a human gate:

```python
# ❌ NEVER — the loop discovers a finding, picks `remediate-*` from its tools,
#    runs `--dry-run`, hallucinates an approval, and re-runs without it.
#    The MCP wrapper still refuses, but the pattern is close to right-of-boom.
tools = [*detect_tools, *remediate_tools]  # remediate-* in the same tool set

for step in agent.run_until_done():
    # hallucinated approval_context is rejected by the wrapper, but the model
    # has been told these tools exist — that's the wrong default.
```

The correct pattern:

```python
# ✅ Detection chain with read-only tools only
detection_tools = scan_and_triage_tools(allowed="cspm-*,detect-*")
findings = run_agent_loop(tools=detection_tools)

# ✅ Human-gated remediation chain — runs only AFTER an operator approves
if operator_approved(findings):
    remediation_tools = scoped_remediation_tools(allowed="iam-departures-aws")
    remediation_result = run_agent_loop(
        tools=remediation_tools,
        caller_context={...},
        approval_context={"approver_id": "...", "ticket_id": "SEC-123"},
    )
```

The MCP server enforces this server-side — the client code is just the
operator-visible contract.

## Running the examples

The examples are runnable against **moto fixtures**, so no real cloud
credentials are needed for the CSPM scan demo. The remediation demo is
dry-run only — it prints the Step Function input it *would* produce
without actually starting an execution.

```bash
uv sync --group dev --extra aws
python examples/agents/anthropic_sdk_security_agent.py
```

The LangGraph reference is dependency-light by default but also includes a
real optional `StateGraph` runtime. The graph keeps security facts in
deterministic skill nodes, adds a bounded multi-agent harness with an
auditable `agent_runs` ledger, and uses conditional edges for HITL, retry,
terminal-error escalation, duplicate suppression, and writeback.

```bash
# Generate an operator-owned profile and dotenv file. The generator writes
# metadata only: no cloud credentials, approval tokens, or secrets.
python examples/agents/configure_langgraph_harness.py \
  --role analyst-triage \
  --profile-id acme-soc-triage \
  --email analyst@example.com \
  --external-llm \
  --llm-provider openai \
  --llm-model gpt-4.1-mini \
  --output-profile artifacts/acme-soc-triage.json \
  --output-env artifacts/acme-soc-triage.env

# Existing security lake: replay read-only rows instead of raw ingest.
python examples/agents/configure_langgraph_harness.py \
  --role readonly-soc \
  --profile-id acme-clickhouse-replay \
  --email analyst@example.com \
  --data-source-mode security-lake-replay \
  --lake-backend clickhouse \
  --lake-query "SELECT payload FROM security.events_sink LIMIT 100" \
  --output-profile artifacts/acme-clickhouse-replay.json \
  --output-env artifacts/acme-clickhouse-replay.env

# Blocked path: no approval context, no remediation action.
python examples/agents/langgraph_security_graph.py

# Profile path: operator-owned roles, allowlists, identity hints, and model metadata.
DEMO_HARNESS_PROFILE=examples/agents/harness_profiles/readonly-soc.json \
python examples/agents/langgraph_security_graph.py

# Preflight profile grants before graph execution.
python examples/agents/inspect_langgraph_harness.py \
  --profile examples/agents/harness_profiles/readonly-soc.json
python examples/agents/inspect_langgraph_harness.py \
  --profile examples/agents/harness_profiles/dry-run-remediation.json \
  --approval-context-present \
  --require-remediation-ready

# Operator-facing harness runner: profile + optional evidence fixture
# through the importable runtime wrapper, with validation enabled by default.
python examples/agents/run_langgraph_harness.py \
  --profile examples/agents/harness_profiles/readonly-soc.json \
  --raw-events /path/to/events.jsonl \
  --caller-context '{"email":"analyst@example.com","session_id":"SEC-123"}'

# HITL-gated dry-run planning through the same runner.
python examples/agents/run_langgraph_harness.py \
  --profile examples/agents/harness_profiles/dry-run-remediation.json \
  --approve \
  --approver reviewer@example.com \
  --ticket SEC-LANGGRAPH-1

# Embedded/SOAR-style approval metadata can also come from JSON, not env vars.
python examples/agents/run_langgraph_harness.py \
  --profile examples/agents/harness_profiles/dry-run-remediation.json \
  --approval-context /path/to/approval-context.json

# MCP execution is explicit. Shipped profiles emit mcp_call_plan plus
# mcp_execution=plan_only; generated profiles can mark read-only calls eligible
# for an operator-owned stdio transport without enabling write execution.
python examples/agents/configure_langgraph_harness.py \
  --role readonly-soc \
  --profile-id acme-readonly-stdio \
  --email analyst@example.com \
  --mcp-execution-mode operator_stdio \
  --mcp-max-calls 3 \
  --output-profile artifacts/acme-readonly-stdio.json \
  --output-env artifacts/acme-readonly-stdio.env

python examples/agents/run_langgraph_harness.py \
  --profile artifacts/acme-readonly-stdio.json \
  --output artifacts/acme-readonly-stdio-summary.json

python examples/agents/execute_langgraph_mcp_plan.py \
  --summary artifacts/acme-readonly-stdio-summary.json \
  --output artifacts/acme-readonly-stdio-mcp-execution.json

# Approved path: remediation reaches dry-run only and writes audit/eval output.
DEMO_HARNESS_PROFILE=examples/agents/harness_profiles/dry-run-remediation.json \
DEMO_APPROVE=yes \
DEMO_APPROVER=reviewer@example.com \
DEMO_TICKET=SEC-LANGGRAPH-1 \
python examples/agents/langgraph_security_graph.py

# Real LangGraph runtime: compiles the same nodes into StateGraph.
uv sync --group dev --group langgraph
DEMO_LANGGRAPH_RUNTIME=yes \
python examples/agents/langgraph_security_graph.py

# Optional LLM/agent harness override: provider/model are recorded in audit,
# but profile model_policy remains the normal configuration path and LLM
# output is still limited to rank/summarize/draft/request-review.
DEMO_EXTERNAL_LLM_ALLOWED=yes \
DEMO_LLM_PROVIDER=openai \
DEMO_LLM_MODEL=gpt-4.1-mini \
python examples/agents/langgraph_security_graph.py

# Optional adapter fixture: accepts only finding_uid, priority,
# recommended_action, and rationale; forbidden security facts fall back closed.
DEMO_EXTERNAL_LLM_ALLOWED=yes \
DEMO_LLM_PROVIDER=fixture \
DEMO_LLM_MODEL=triage-fixture-v1 \
DEMO_LLM_ADAPTER_FIXTURE=/path/to/recommendations.json \
python examples/agents/langgraph_security_graph.py

# Optional LangChain adapter fixture: parses a LangChain AIMessage payload,
# then applies the same bounded recommendation schema gate.
uv sync --group dev --group langgraph
DEMO_EXTERNAL_LLM_ALLOWED=yes \
DEMO_LLM_PROVIDER=langchain \
DEMO_LLM_MODEL=chat-model-fixture-v1 \
DEMO_LANGCHAIN_ADAPTER_FIXTURE=/path/to/langchain-message.json \
python examples/agents/langgraph_security_graph.py

# Live BYOM adapter: one OpenAI-compatible client covers OpenAI, Azure
# OpenAI, Ollama, vLLM, and LiteLLM. Activates only in
# external_llm_optional mode; stdlib-only; single bounded call, no retries.
# The API key is never in a profile — name the env var that holds it
# (default OPENAI_API_KEY; keyless is fine for local Ollama/vLLM).
# Model output still passes the same closed schema gate; any network or
# parse failure falls back to deterministic triage.
DEMO_EXTERNAL_LLM_ALLOWED=yes \
DEMO_LLM_PROVIDER=openai \
DEMO_LLM_MODEL=gpt-4.1-mini \
DEMO_OPENAI_BASE_URL=https://api.openai.com/v1 \
DEMO_OPENAI_API_KEY_ENV=OPENAI_API_KEY \
python examples/agents/langgraph_security_graph.py

# Same adapter against a local Ollama endpoint (no key):
DEMO_EXTERNAL_LLM_ALLOWED=yes \
DEMO_LLM_PROVIDER=ollama \
DEMO_LLM_MODEL=llama3.1 \
DEMO_OPENAI_BASE_URL=http://127.0.0.1:11434/v1 \
python examples/agents/langgraph_security_graph.py

# Retryable API error path: no write intent is created without approval;
# approved retries reuse the same remediation idempotency key.
DEMO_APPROVE=yes \
DEMO_API_ERROR_STATUS=429 \
python examples/agents/langgraph_security_graph.py

# Checkpoint artifact: persist the final graph state with stable hashes,
# then replay the same summary offline without re-running graph nodes.
DEMO_CHECKPOINT_PATH=artifacts/langgraph-checkpoint.json \
python examples/agents/langgraph_security_graph.py
DEMO_REPLAY_CHECKPOINT=artifacts/langgraph-checkpoint.json \
python examples/agents/langgraph_security_graph.py

# Offline eval gate: replay golden profile, triage, integrity,
# idempotency, and API-error cases and fail on drift.
python examples/agents/eval_langgraph_harness.py --check

# Eval artifact store: keep the latest JSON report and append pass-rate history.
python examples/agents/eval_langgraph_harness.py --check \
  --output artifacts/langgraph-harness-eval.json \
  --append-jsonl artifacts/langgraph-harness-eval-history.jsonl

# Model-quality mode: score the configured triage adapter (fixture or live
# OpenAI-compatible endpoint) against the golden priorities/actions. With no
# adapter configured it scores the deterministic path (agreement 1.0), so the
# same command works offline in CI and against a live model for BYOM drift.
DEMO_OPENAI_BASE_URL=http://127.0.0.1:11434/v1 \
python examples/agents/eval_langgraph_harness.py --model-quality --check \
  --min-agreement 0.75 \
  --output artifacts/langgraph-model-quality.json \
  --append-jsonl artifacts/langgraph-model-quality-history.jsonl

# Diagram artifact: render docs/diagrams/langgraph-agent-harness.mmd
# from the code-backed pipeline_contract().
python examples/agents/render_langgraph_pipeline_diagram.py \
  --output docs/diagrams/langgraph-agent-harness.mmd

# Drift doctor: verify schemas, profiles, generated diagram, docs/CI
# references, preflight safety, and wrapper validation stay aligned.
python examples/agents/check_langgraph_harness_drift.py
```

The LangGraph summary includes `integrity.evidence_hash`,
`integrity.state_hash`, stable workflow/remediation idempotency keys, and
retryable-vs-terminal API error classification. It also includes the
`profile`, `effective_allowed_skills`, `data_source`, `harness`
provider/model/mode/model policy/token budget, `agents` manifest,
`pipeline_contract`, `mcp_call_plan`, `agent_runs`
ledger, `agent_policy` effective grants report, compact LLM evidence cards,
token budget usage, and bounded
`agent_recommendations` so
operators can see which role and model would have drafted the analyst note
without letting that model set policy, mappings, approvals, or audit facts. Use
`DEMO_API_ERROR_STATUS=429` for retryable errors or `403` for terminal errors.
`llm_validation` records whether an adapter output was accepted, rejected, or
replaced by deterministic fallback. The eval runner can write a point-in-time
JSON report and append timestamped JSONL rows so CI or operators can track
pass-rate drift across harness, profile, and adapter changes. Both report
forms share a closed schema contract under [`schemas/`](schemas/).
`pipeline_contract` is code-backed topology metadata: node ownership, skills,
input/output state keys, conditional edges, and guardrails for dry-run,
approval, retries, idempotency, and audit writeback.
Profiles can also carry concise `agent_roster` overrides. The loader preserves
fixed graph ownership and re-applies safety boundaries, so an operator can set
the triage model tier or document remediation posture without granting the LLM
agent tool-write scope or bypassing HITL.
`agent_policy` is the compiled view of those choices: per-agent requested
skills, effective grants, denied skills, model tier, write policy, approval
state, and decision.
`inspect_langgraph_harness.py` emits that policy without running graph nodes,
calling a model, reading credentials, or executing remediation.
Importable harness wrapper:

```bash
PYTHONPATH=examples/agents python - <<'PY'
from harness_runtime import HarnessRunConfig, run_harness

result = run_harness(HarnessRunConfig(
    profile_path="examples/agents/harness_profiles/readonly-soc.json",
    raw_events=({"source": "cloudtrail", "event_name": "CreateAccessKey"},),
))
assert result.runtime["validation_status"] == "pass"
PY
```

Use this wrapper from CI, MCP, SOAR, or a customer-owned LangGraph app when
the workflow should run as code. `docs/HARNESS.md` remains the readable
operator contract, not the implementation body.
`run_langgraph_harness.py` is the CLI over that wrapper: it accepts profile
paths, raw-event fixtures, caller-context overrides, LangGraph runtime
selection, checkpoint write/replay, JSON output, and explicit demo approval
metadata without duplicating graph logic. `HarnessRunConfig` also accepts
stateful `approval_context`, so CI, SOAR, ticketing, or MCP wrappers do not
need to rely on process-wide approval env vars.
Adapter plumbing lives in [`harness_adapters.py`](harness_adapters.py): the
graph selects deterministic fallback, JSON fixture, optional LangChain chat
fixture, or the live OpenAI-compatible BYOM adapter, then applies one closed
schema gate before any recommendation enters graph state. The live adapter
(`OpenAICompatTriageAdapter`) speaks the `chat/completions` wire format, so a
single client covers OpenAI, Azure OpenAI, Ollama, vLLM, and LiteLLM; it makes
one bounded call (clamped timeout, capped output tokens, no retries) and any
failure degrades to deterministic triage with the reason recorded in node
telemetry.
The graph sends compact finding cards to the optional adapter, not raw events
or full OCSF payloads. Each triage run records estimated raw and compact input
tokens, output tokens, compression ratio, cache key, model tier, and fallback
reason when a budget is exceeded.
Checkpoint artifacts use `langgraph-soc-checkpoint-v1`, include the final
state, `state_hash`, `summary_hash`, and `checkpoint_hash`, match a closed
schema envelope, and replay only after those hashes verify.

Profile examples live under
[`harness_profiles/`](harness_profiles/):

| Profile | Behavior |
|---|---|
| `readonly-soc.json` | read-only SOC replay and triage |
| `analyst-triage.json` | optional external-model metadata for bounded drafting |
| `dry-run-remediation.json` | exposes remediation planning, but still requires `DEMO_APPROVE=yes` / approval context |

Contract schemas live under [`schemas/`](schemas/). They define the closed
shape for harness profiles, the LLM adapter recommendation payload accepted by
the reference graph, the emitted `pipeline_contract` topology, and checkpoint
artifact and eval-report envelopes.
Use [`check_langgraph_harness_drift.py`](check_langgraph_harness_drift.py) to
fail closed when the generated diagram, profiles, schemas, docs, CI command
references, metadata-only preflight, or wrapper validation drift away from the
code-backed harness.

Use [`configure_langgraph_harness.py`](configure_langgraph_harness.py) when
customizing the harness for a buyer or internal environment. It asks for role,
operator identity, cloud identity hints, allowed example skills, and
provider/model policy metadata, then writes a schema-shaped profile plus a
dotenv file that points at the profile without duplicating provider/model
override env vars.
The generated runtime keeps `dry_run_default=true`, `apply_supported=false`,
`remediation_requires_approval_context=true`, a model policy, and a token
budget policy; setting a remediation-capable role exposes dry-run planning
only, not approval.

Eval fixtures live under [`evals/`](evals/). The eval runner is deterministic:
it replays profile/triage cases, checks recommendation shape, HITL routing,
allowlist behavior, LLM adapter schema acceptance/rejection, and remediation
blocking, then emits a pass-rate report. It does not call a live model and
does not use an LLM-as-judge.

See each example file's module-level docstring for framework-specific
prerequisites.

## What's NOT in these examples

- **Production-grade API operations.** These are reference loops; API error
  classes, retry decisions, and idempotency keys are modeled deterministically,
  but a real stack would connect them to durable queues, circuit breakers,
  backoff timers, and structured observability.
- **Multi-tenancy.** Each example runs in a single operator context.
- **Cloud credential brokering.** Examples rely on the shell environment
  (moto for tests, AWS profile for local runs).
- **Claude.ai / Claude Desktop integration.** Those are MCP clients, not
  agent SDKs — see [`../../docs/integrations/`](../../docs/integrations/).

## Open-model integration (Ollama, etc.)

See [`../../docs/integrations/ollama.md`](../../docs/integrations/ollama.md)
for the explicit posture on running these skills from open models. **Short
version:** the server-side guards (HITL, allowlist, dry-run, audit) are
model-agnostic and still hold. Open-model accuracy and prompt-injection
resistance are weaker, so start with read-only skills and never put
remediation tools in an open-model agent loop without a hard human gate.
