# Agent-SDK integration examples

Three reference implementations showing how to load `cloud-ai-security-skills`
via MCP from inside an agent-framework loop, while keeping **every guardrail
intact**. The same MCP wrapper enforces HITL, dry-run, audit, and the skill
allowlist regardless of which SDK is driving the loop.

| Example | Framework | What it shows |
|---|---|---|
| [`anthropic_sdk_security_agent.py`](anthropic_sdk_security_agent.py) | Anthropic Python SDK (Managed Agent) | CSPM scan → triage loop with HITL gate on remediation |
| [`openai_sdk_security_agent.py`](openai_sdk_security_agent.py) | OpenAI Agents SDK | Parallel port of the Anthropic example for portability |
| [`langgraph_security_graph.py`](langgraph_security_graph.py) | LangGraph | SOC workflow DAG: ingest → normalize → enrich → correlate → confidence → MITRE/CVSS/EPSS/KEV map → HITL → dry-run remediation → audit/eval writeback |

## Safety posture — every example enforces the same invariants

1. **Read-only skill allowlist.** Every example sets
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

Each example includes a `DONT_DO_THIS` section showing a naive loop that
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

# Blocked path: no approval context, no remediation action.
python examples/agents/langgraph_security_graph.py

# Profile path: operator-owned roles, allowlists, identity hints, and model metadata.
DEMO_HARNESS_PROFILE=examples/agents/harness_profiles/readonly-soc.json \
python examples/agents/langgraph_security_graph.py

# Approved path: remediation reaches dry-run only and writes audit/eval output.
DEMO_APPROVE=yes \
DEMO_APPROVER=reviewer@example.com \
DEMO_TICKET=SEC-LANGGRAPH-1 \
python examples/agents/langgraph_security_graph.py

# Real LangGraph runtime: compiles the same nodes into StateGraph.
uv sync --group dev --group langgraph
DEMO_LANGGRAPH_RUNTIME=yes \
python examples/agents/langgraph_security_graph.py

# Optional LLM/agent harness metadata: provider/model are recorded in audit,
# but LLM output is still limited to rank/summarize/draft/request-review.
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

# Diagram artifact: render docs/diagrams/langgraph-agent-harness.mmd
# from the code-backed pipeline_contract().
python examples/agents/render_langgraph_pipeline_diagram.py \
  --output docs/diagrams/langgraph-agent-harness.mmd
```

The LangGraph summary includes `integrity.evidence_hash`,
`integrity.state_hash`, stable workflow/remediation idempotency keys, and
retryable-vs-terminal API error classification. It also includes the
`profile`, `effective_allowed_skills`, `harness` provider/model/mode, `agents`
manifest, `pipeline_contract`, `agent_runs` ledger, and bounded
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
Adapter plumbing lives in [`harness_adapters.py`](harness_adapters.py): the
graph selects deterministic fallback, JSON fixture, or optional LangChain chat
fixture adapters, then applies one closed schema gate before any recommendation
enters graph state.
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

Use [`configure_langgraph_harness.py`](configure_langgraph_harness.py) when
customizing the harness for a buyer or internal environment. It asks for role,
operator identity, cloud identity hints, allowed example skills, and
provider/model metadata, then writes a schema-shaped profile plus a dotenv file.
The generated runtime keeps `dry_run_default=true`, `apply_supported=false`,
and `remediation_requires_approval_context=true`; setting a remediation-capable
role exposes dry-run planning only, not approval.

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
