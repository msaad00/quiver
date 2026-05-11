---
name: detect-agent-credential-leak-mcp
description: >-
  Detect credential-looking material leaked in MCP tool-call responses. Consumes
  the native/canonical application-activity projection from
  ingest-mcp-proxy-ocsf, scans `tools/call` response bodies for high-confidence
  token patterns (AWS access keys, GitHub tokens, OpenAI keys, Slack tokens),
  and emits an OCSF Detection Finding (class 2004) without echoing the raw
  secret back out. Use when the user mentions MCP credential exposure, leaked
  tool results, agent secret leakage, or OWASP MCP credential exposure in tool
  responses. Do NOT use on `tools/list` metadata, non-MCP logs, or as a
  semantic prompt-injection classifier. This first slice is a deterministic
  regex detector on native MCP response bodies.
purpose: Detect credential-looking material leaked in MCP tool-call responses.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, persistent
side_effects: none
input_formats: native
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. Read-only — consumes the native/canonical MCP
  application-activity stream from ingest-mcp-proxy-ocsf and emits OCSF 1.8
  Detection Finding 2004 to stdout. No network egress, no cloud SDK.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-agent-credential-leak-mcp
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - OWASP MCP Top 10
    - OWASP LLM Top 10
  cloud: mcp
  capability: read-only
---

# detect-agent-credential-leak-mcp

Deterministic MCP detector for credential exposure in tool results.

## Use when

- You run `ingest-mcp-proxy-ocsf --output-format native` and want to scan tool responses for leaked secrets
- You want a high-confidence MCP/agent credential exposure detector without an LLM in the loop
- You are expanding issue `#255` with AI-native detection before remediation

## Do NOT use

- On OCSF-only MCP activity that does not carry response bodies
- For prompt-injection in tool descriptions; use [`detect-prompt-injection-mcp-proxy`](../detect-prompt-injection-mcp-proxy/)
- For schema drift; use [`detect-mcp-tool-drift`](../detect-mcp-tool-drift/)

## Rule

A finding fires when:

1. `source_skill == ingest-mcp-proxy-ocsf`
2. event is a native/canonical `application_activity`
3. `method == "tools/call"` and `direction == "response"`
4. the response `body` contains high-confidence credential patterns

This first slice matches:

- AWS access key IDs
- GitHub tokens
- OpenAI API keys
- Slack tokens

## Guardrails

- Read-only detector: stdin JSONL -> stdout findings
- No raw secrets echoed in findings; only masked previews and SHA-256 fingerprints
- Deterministic finding IDs for replay-safe dedupe
- Fail-closed on malformed input: skip and warn, never crash the stream

## Run

```bash
agent-bom proxy "<server cmd>" --log-format jsonl \
  | python skills/ingestion/ingest-mcp-proxy-ocsf/src/ingest.py --output-format native \
  | python skills/detection/detect-agent-credential-leak-mcp/src/detect.py \
  > findings.ocsf.jsonl
```

## See also

- [`ingest-mcp-proxy-ocsf`](../../ingestion/ingest-mcp-proxy-ocsf/) — upstream MCP ingester
- [`detect-prompt-injection-mcp-proxy`](../detect-prompt-injection-mcp-proxy/) — prompt-injection sibling
- [`detect-mcp-tool-drift`](../detect-mcp-tool-drift/) — tool-drift sibling
