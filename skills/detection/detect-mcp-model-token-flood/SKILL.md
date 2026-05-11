---
name: detect-mcp-model-token-flood
description: >-
  Detect unbounded prompt-token consumption against a model endpoint over MCP.
  Reads OCSF 1.8 Application Activity (class 6002) records produced by
  ingest-mcp-proxy-ocsf that carry unmapped.mcp.prompt_tokens and
  unmapped.mcp.model_name, accumulates prompt tokens per
  (actor.user.uid, model_name) within a sliding window, and fires one
  Detection Finding when an individual user exceeds the budget on the same
  model. Maps to OWASP LLM04 Model Denial of Service and OWASP LLM10
  Unbounded Consumption. Use when the user mentions model DoS, prompt-token
  exhaustion, MCP model quotas, or LLM cost-bombing. Do NOT use on raw MCP
  proxy logs — feed them through ingest-mcp-proxy-ocsf first. Do NOT use as a
  rate limiter; thresholds here are detection-side and complement, not
  replace, the wrapper rate-limit RLIMITs.
purpose: Detect prompt-token flooding against a model endpoint over MCP (OWASP LLM04 · LLM10).
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: canonical, native, ocsf
output_formats: native, ocsf
concurrency_safety: stateless
---

# detect-mcp-model-token-flood

## Attack pattern

An agent or adversary aimed at a model endpoint over MCP can drive a denial-
of-service or cost-amplification attack by submitting an unbounded stream of
prompt tokens against the same model identity. The wrapper's per-call RLIMIT
caps a single request but does **not** cap cumulative consumption across
calls inside a short window — a 200k-token flood from one user against the
same model often shows up as 4 × 50k requests, all well under the per-call
ceiling, all from the same actor, all within minutes.

This maps to OWASP LLM Top 10 **LLM04 Model Denial of Service** and **LLM10
Unbounded Consumption**.

## Detection logic

Walk MCP Application Activity events from `ingest-mcp-proxy-ocsf`. Each event
contributes its `unmapped.mcp.prompt_tokens` value to a sliding-window total
keyed by `(actor.user.uid, model_name)`. When the cumulative window total
crosses `MCP_PROMPT_TOKEN_BUDGET` (default `200000`) inside
`MCP_PROMPT_TOKEN_WINDOW_MIN` (default `5`), fire **one** Detection Finding.

```
window = events within MCP_PROMPT_TOKEN_WINDOW_MIN minutes
total  = sum(prompt_tokens) over window keyed by (user_uid, model_name)
fire if total > MCP_PROMPT_TOKEN_BUDGET
```

- Single user · same model · accumulated tokens cross budget → fire once per
  flooding window. The window slides forward; subsequent budget crossings
  outside the original window fire again.
- Different user, same model → counted separately.
- Same user, different model → counted separately.

Use when the user mentions model DoS, prompt-token flooding, OWASP LLM04, or
OWASP LLM10. Do NOT use as a request-level rate limiter — that belongs to the
MCP proxy's RLIMIT contract.

## Output contract

One OCSF 1.8 Detection Finding (class 2004) per flooding window. With
`--output-format native` the skill emits the repo-owned native projection.

OCSF output populates:

- `finding_info.types[] = ["mcp-model-token-flood", "llm-model-dos"]`
- `finding_info.attacks[]` — MITRE ATLAS `AML.T0034` Cost Harvesting where
  applicable; the LLM Top 10 mapping is the primary one.
- deterministic `finding_info.uid`.
- `observables[]` — user uid, model name, total tokens, window start/end.

## Usage

```bash
python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > token-flood-findings.ocsf.jsonl

# Tighten thresholds for tighter detection
MCP_PROMPT_TOKEN_BUDGET=100000 MCP_PROMPT_TOKEN_WINDOW_MIN=2 \
  python src/detect.py mcp-proxy.ocsf.jsonl
```
