# Ollama (and other open-model runtimes)

You can drive `cloud-ai-security-skills` from an agent backed by Ollama-hosted
open models (Llama, Mistral, Qwen, etc.) — **the MCP server's guardrails are
model-agnostic and still hold**. But open-model accuracy and prompt-injection
resistance are meaningfully worse than frontier closed models. This doc
spells out the safe default.

## Bridge options

Ollama itself is not an MCP client. Bridge it via one of:

1. **openai-agents SDK → Ollama via OpenAI-compatible endpoint** (recommended)
2. **LangGraph → Ollama model node → MCP tool node**
3. **LiteLLM proxy → any agent framework that speaks MCP**

Example (openai-agents, pseudocode):

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:11434/v1",  # Ollama's OpenAI-compatible endpoint
    api_key="ollama",  # ignored by Ollama but required by client
)

# Configure the MCP bridge as you would with any OpenAI-compat agent:
mcp_server = {
    "command": "python3",
    "args": ["/abs/path/to/mcp-server/src/server.py"],
    "env": {
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "cspm-aws-cis-benchmark,detect-lateral-movement,convert-ocsf-to-sarif",
        # ^ READ-ONLY ONLY. Never list remediate-* here for open models.
    },
}
```

## Guardrails — what still works, what to strengthen

### What the MCP server enforces (model-agnostic — open models cannot bypass)

| Guardrail | Where enforced | What an open model cannot do |
|---|---|---|
| Skill allowlist | `mcp-server/src/server.py` `_filtered_tool_map` | Call a skill not in `CLOUD_SECURITY_MCP_ALLOWED_SKILLS` |
| HITL gate | wrapper refuses if `approval_model=human_required` and `_approval_context` is absent | Run remediation without an operator-provided approval context |
| Dry-run default | wrapper refuses write-capable tools without `--dry-run` | Hit a real cloud API with mutations |
| IaC deny list | cross-account IAM policy | Touch `root` / `break-glass-*` / `emergency-*` regardless of any hallucinated argument |
| Arg/input validation | wrapper validates JSON-RPC params | Send malformed arguments; they're rejected before any skill runs |
| Audit record per call | wrapper emits `{event: mcp_tool_call, correlation_id, ...}` to stderr | Evade the forensic trail |

A jailbroken Llama 3.3 running under Ollama **cannot bypass any of these** —
they execute before the skill runs.

### What gets worse with open models (and how to compensate)

| Risk | Why it gets worse | Compensating control |
|---|---|---|
| Wrong tool selection | Open models have ~10–30% worse tool-call accuracy than Claude 4 / GPT-5 on structured tool-use benchmarks | Keep the allowlist small. If the loop only needs CSPM + SARIF conversion, list exactly those two. |
| Prompt injection from ingested data | Open models are more susceptible to embedded instructions in logs/findings ("ignore previous instructions and ...") | Never let an open-model agent write its own approval_context. HITL must come from a human-driven external system. |
| Hallucinated tool args | More likely to invent fake `_approval_context` or pass invalid resource names | Wrapper's JSON-RPC validation rejects these; nothing reaches the skill. |
| Output verbosity / format drift | Models may wrap OCSF in prose, markdown, etc. | Downstream skills already treat stdin as untrusted and validate shape. |

## Recommended starting posture for open-model deployments

```json
{
  "mcpServers": {
    "cloud-ai-security-skills": {
      "command": "python3",
      "args": ["/abs/path/.../mcp-server/src/server.py"],
      "env": {
        "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "cspm-aws-cis-benchmark,cspm-gcp-cis-benchmark,cspm-azure-cis-benchmark,detect-lateral-movement,detect-privilege-escalation-k8s,ingest-cloudtrail-ocsf,convert-ocsf-to-sarif"
      }
    }
  }
}
```

**Rules:**

- **Read-only skills only.** Absolutely no `iam-departures-aws` or
  `remediate-okta-session-kill` in the allowlist. Even with HITL gates, the
  affordance is wrong for an autonomous open-model loop.
- **Separate agent for HITL-gated remediation.** If you want open-model
  remediation, build a *separate* agent loop where the model receives a
  pre-approved, human-curated finding as input (not a tool-selection choice)
  and emits a structured "remediate this specific ARN" request that goes
  through your ticketing system before anything runs.
- **Log every MCP audit line to a SIEM.** Open-model agents produce more
  noise (retries, wrong-tool-call attempts). Keep the forensic trail.

## Where the audit trail lands

The MCP server writes one JSON line per tool call to stderr:

```json
{
  "event": "mcp_tool_call",
  "timestamp": "2026-04-18T12:00:00.000Z",
  "correlation_id": "<uuid>",
  "tool": "cspm-aws-cis-benchmark",
  "caller_id": "<set by caller_context>",
  "caller_session_id": "<>",
  "read_only": true,
  "timeout_seconds": 60,
  "result": "success",
  "exit_code": 0
}
```

For open-model deployments, capture stderr and forward to Splunk / Sentinel /
Chronicle. The `caller_session_id` + `correlation_id` pair gives you the
forensic trail per tool call, per operator session, even when the model driving
the loop is untrusted.

## See also

- [`README.md`](README.md) — full per-client integrations index
- [`../../CLAUDE.md`](../../CLAUDE.md) — agent guardrails required before invoking any skill
- [`../../examples/agents/README.md`](../../examples/agents/README.md) — runnable SDK examples
- [`../HITL_POLICY.md`](../HITL_POLICY.md) — when human approval is required
- [`../MCP_AUDIT_CONTRACT.md`](../MCP_AUDIT_CONTRACT.md) — audit record schema
