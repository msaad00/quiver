# Presets — named MCP tool allowlists

Presets are JSON files listing the **atomic skills** an agent loop is
authorized to call for a specific operational use-case. Loading a preset
into `CLOUD_SECURITY_MCP_ALLOWED_SKILLS` (or an MCP wrapper's
`_caller_context.allowed_skills`) gives the agent the *minimum* tool
surface for the job — and nothing else.

## Why presets exist

The MCP wrapper supports three levels of allowlist:

1. **Process-level** (`CLOUD_SECURITY_MCP_ALLOWED_SKILLS`) — set by the
   operator at server start.
2. **Caller-level** (`_caller_context.allowed_skills`) — set by the
   wrapping client per request.
3. **Workflow-level** (this directory) — the named set the workflow
   authorizes.

The effective tool set is the **intersection** of all three. Presets
make level 3 explicit and reusable across clients so a CSPM-only agent
in Claude Code, Cursor, and Codex all load the same surface, scoped the
same way.

See [`../docs/SKILL_COMPOSITION.md`](../docs/SKILL_COMPOSITION.md) for the
broader composition model.

## Shipped presets

| Preset | Use case | Atoms | Write paths? |
|---|---|---|---|
| [`preset-cspm-readonly.json`](preset-cspm-readonly.json) | continuous CSPM scanning + posture review | the three `cspm-*-cis-benchmark` skills, K8s + container + GPU + model-serving evaluation, `convert-ocsf-to-sarif` | none |
| [`preset-detection-only.json`](preset-detection-only.json) | feed raw logs through ingest + detect, hand findings to a SIEM | a curated 15-ingest / 32-detect subset plus both view skills (the JSON is authoritative) | none |
| [`preset-incident-response.json`](preset-incident-response.json) | the workflow at [`../examples/workflows/incident-response-okta-mfa-fatigue.md`](../examples/workflows/incident-response-okta-mfa-fatigue.md) | one detector + one discover + one remediate | one HITL-gated session kill |
| [`preset-ai-runtime.json`](preset-ai-runtime.json) | runtime guardrails for an AI agent platform — detect prompt injection, tool drift, exfiltration | MCP-proxy ingest, the AI-runtime detectors, MCP tool quarantine | one HITL-gated tool quarantine |

## Loading a preset

### Process-wide

```bash
export CLOUD_SECURITY_MCP_ALLOWED_SKILLS="$(jq -r '.allowed_skills | join(",")' presets/preset-cspm-readonly.json)"
python mcp-server/src/server.py
```

### Per-call (caller-level)

```jsonc
// MCP tools/call params
{
  "_caller_context": {
    "user_id": "alice@example.com",
    "session_id": "sess-123",
    "allowed_skills": [/* the array from presets/preset-incident-response.json */]
  },
  /* ... */
}
```

### SDK harness examples

The Anthropic, OpenAI, and LangChain reference agents accept
`CLOUD_SECURITY_MCP_PRESET` to intersect a harness profile with a preset
without hand-editing JSON:

```bash
CLOUD_SECURITY_MCP_PRESET=preset-cspm-readonly.json \
  python examples/agents/openai_sdk_security_agent.py
```

The effective allowlist is **profile ∩ preset ∩ caller** (empty intersection
raises at load time).

Generate a harness profile with the preset baked in:

```bash
python examples/agents/configure_langgraph_harness.py \
  --role sdk-cspm \
  --preset preset-cspm-readonly.json \
  --profile-id acme-sdk-cspm \
  --email sdk-agent@example.com \
  --output-profile artifacts/acme-sdk-cspm.json \
  --output-env artifacts/acme-sdk-cspm.env
```

The wrapper records `caller_skill_scope_count` and
`caller_skill_scope_hash` in the audit event so the same preset across
runs is recognisable in post-hoc analysis.

## Authoring a new preset

1. **Name it after the use case**, not the skill set. `preset-pci-evidence-export.json`,
   not `preset-cspm-aws-and-azure-only.json`.
2. **Smallest blast radius wins.** If a workflow can run with three
   atoms, the preset gets three atoms — never broader.
3. **Bind it to a workflow doc.** Every preset that authorizes a write
   path must reference a workflow under `examples/workflows/` that
   describes when and why the write fires.
4. **Validate it.** The preset is a JSON file with a single key,
   `allowed_skills` (array of strings). Skill names must match the
   shipped `SKILL.md` `name:` field exactly.
