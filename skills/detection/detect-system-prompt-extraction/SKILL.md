---
name: detect-system-prompt-extraction
description: >-
  Detect MCP tool-call responses that look like leaked system-prompt or hidden
  instruction material from native or OCSF Application Activity records emitted
  by ingest-mcp-proxy-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004)
  tagged with MITRE ATLAS AML.T0004 / AML.T0041 when a `tools/call` response
  contains explicit system-prompt markers such as `<system_prompt>`,
  "You are ChatGPT", "developer message", or "hidden instructions". Use when
  the user mentions "system prompt leakage", "prompt extraction", "hidden
  instructions exposed", or "LLM07 via MCP". Do NOT use for generic jailbreak
  language, semantic prompt leakage claims, or tool-description inspection.
purpose: Detect MCP tool-call responses that look like leaked system-prompt or hidden instruction material from native or OCSF Application Activity records emitted by ingest-mcp-proxy-ocsf.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: native, ocsf
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. Read-only — consumes MCP application-activity records
  from stdin/file and emits OCSF 1.8 Detection Finding 2004 to stdout. No
  network calls; pairs with ingest-mcp-proxy-ocsf upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-system-prompt-extraction
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATLAS
    - OWASP LLM Top 10
  cloud: mcp
  capability: read-only
---

# detect-system-prompt-extraction

Streaming detector for explicit system-prompt leakage in MCP tool-call
responses. This is the next honest AI-native slice after MCP credential-leak
detection, and it stays intentionally narrow so the repo does not over-claim
semantic prompt extraction.

## Use when

- You ingest MCP proxy activity and want a deterministic detector for leaked system prompts or hidden instructions
- You want a read-only AI-native detector aligned to MITRE ATLAS prompt extraction and OWASP LLM system-prompt leakage concerns
- You need a narrow `#255` slice that does not depend on model-specific embedding or semantic similarity systems

## Do NOT use

- For suspicious tool descriptions; use [`detect-prompt-injection-mcp-proxy`](../detect-prompt-injection-mcp-proxy/)
- For generic jailbreak or override language in user text alone
- To claim full semantic prompt extraction coverage; this first slice is explicit marker-based only

## Rule

A finding fires on every `tools/call` response from `ingest-mcp-proxy-ocsf`
whose response body contains one or more explicit system-prompt leakage markers
such as:

- `<system_prompt>` / `</system_prompt>`
- `system prompt`
- `developer message`
- `hidden instructions`
- role-style lead-ins like `You are ChatGPT`, `You are Claude`, or `You are an AI assistant`

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[]` carrying MITRE ATLAS prompt-extraction identifiers
- `observables[]` including session, tool, matched signal list, and a SHA-256 fingerprint of the leaked excerpt

The native projection (`--output-format native`) keeps only a short excerpt,
matched signal names, and a fingerprint — never the full leaked body.

## Run

```bash
# MCP proxy -> ingest native -> detect
python skills/ingestion/ingest-mcp-proxy-ocsf/src/ingest.py raw.jsonl --output-format native \
  | python skills/detection/detect-system-prompt-extraction/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-system-prompt-extraction/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-mcp-proxy-ocsf`](../../ingestion/ingest-mcp-proxy-ocsf/) — upstream ingester
- [`detect-agent-credential-leak-mcp`](../detect-agent-credential-leak-mcp/) — MCP credential-exposure depth
- [`detect-prompt-injection-mcp-proxy`](../detect-prompt-injection-mcp-proxy/) — suspicious MCP tool-description detection
