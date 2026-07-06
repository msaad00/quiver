---
name: detect-tool-output-exfiltration-instructions
description: >-
  Detect MCP tool-call responses that explicitly instruct an agent to exfiltrate
  conversation history, prompts, files, or secrets. Consumes native or OCSF
  Application Activity records from ingest-mcp-proxy-ocsf and emits OCSF 1.8
  Detection Finding (class 2004) when a `tools/call` response contains
  high-confidence exfiltration language such as "send the conversation
  history", "upload local files", or "exfiltrate secrets". Use when the user
  mentions "tool-result exfiltration prompt injection", "response-layer data
  exfil instructions", or "MCP output says to upload secrets". Do NOT use for
  leaked credential material itself, tool descriptions, or semantic jailbreak
  claims.
purpose: Detect MCP tool-call responses that explicitly instruct an agent to exfiltrate conversation history, prompts, files, or secrets.
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-tool-output-exfiltration-instructions
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATLAS
    - OWASP LLM Top 10
    - OWASP MCP Top 10
  cloud: mcp
  capability: read-only
---

# detect-tool-output-exfiltration-instructions

Streaming detector for explicit exfiltration instructions embedded in MCP
`tools/call` responses. This is the response-layer version of "send data out"
prompt injection: the tool output itself tells the agent to upload
conversation history, prompts, files, or secrets elsewhere.

## Use when

- You ingest MCP proxy activity and want a deterministic detector for exfiltration instructions in tool results
- You want a read-only AI-native detector aligned to response-layer prompt injection without an LLM in the loop
- You need the next narrow `#255` slice after credential leakage and system-prompt extraction

## Do NOT use

- For leaked credentials already present in the body; use [`detect-agent-credential-leak-mcp`](../detect-agent-credential-leak-mcp/)
- For suspicious tool descriptions; use [`detect-prompt-injection-mcp-proxy`](../detect-prompt-injection-mcp-proxy/)
- For generic moderation or semantic exfiltration claims

## Rule

A finding fires on every `tools/call` response from `ingest-mcp-proxy-ocsf`
whose response body contains one or more explicit exfiltration instruction
markers such as:

- `send` / `upload` / `exfiltrate` + `conversation history`, `chat history`, `messages`, or `transcript`
- `upload` / `copy` / `send` + `local files`, `workspace files`, or `attached documents`
- `send` / `export` / `post` + `tokens`, `credentials`, `api keys`, `secrets`, or `system prompt`

The scope is intentionally narrow and phrase-driven. It does not attempt to
classify every possible indirect prompt injection variant.

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[]` carrying MITRE ATLAS `AML.T0051` Prompt Injection
- `observables[]` including session, tool, matched signal list, and a SHA-256
  fingerprint of the excerpt

The native projection (`--output-format native`) keeps only a short excerpt,
matched signal names, and a fingerprint — never the full body.

## Run

```bash
python skills/ingestion/ingest-mcp-proxy-ocsf/src/ingest.py raw.jsonl --output-format native \
  | python skills/detection/detect-tool-output-exfiltration-instructions/src/detect.py \
  > findings.ocsf.jsonl

python skills/detection/detect-tool-output-exfiltration-instructions/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-mcp-proxy-ocsf`](../../ingestion/ingest-mcp-proxy-ocsf/) — upstream ingester
- [`detect-prompt-injection-mcp-proxy`](../detect-prompt-injection-mcp-proxy/) — description-layer prompt injection
- [`detect-system-prompt-extraction`](../detect-system-prompt-extraction/) — explicit prompt leakage
- [`detect-agent-credential-leak-mcp`](../detect-agent-credential-leak-mcp/) — credential leakage in tool-call responses
