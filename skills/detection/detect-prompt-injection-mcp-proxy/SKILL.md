---
name: detect-prompt-injection-mcp-proxy
description: >-
  Detect suspicious prompt-injection and instruction-smuggling language in MCP
  tool descriptions from ingest-mcp-proxy-ocsf. Reads OCSF 1.8 Application
  Activity (class 6002) or the native application-activity projection, keeps a
  narrow high-signal scope, and flags `tools/list` responses whose tool
  descriptions explicitly tell an agent to ignore prior instructions, reveal a
  system or developer prompt, bypass guardrails, or exfiltrate secrets or
  conversation history. Emits OCSF 1.8 Detection Finding (class 2004) with
  MITRE ATLAS AML.T0051 Prompt Injection. Use when the user mentions MCP
  prompt injection, instruction smuggling in tool metadata, malicious tool
  descriptions, or AI-agent tool poisoning beyond simple schema drift. Do NOT
  use on raw MCP proxy logs — normalize them through ingest-mcp-proxy-ocsf
  first. Do NOT use as a general content-moderation classifier or on tool-call
  results; this slice only covers suspicious tool declarations in `tools/list`
  responses.
purpose: Detect suspicious prompt-injection and instruction-smuggling language in MCP tool descriptions from ingest-mcp-proxy-ocsf.
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
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-prompt-injection-mcp-proxy
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATLAS
    - OWASP LLM Top 10
    - OWASP MCP Top 10
  cloud:
    - mcp
    - multi
---

# detect-prompt-injection-mcp-proxy

## Attack pattern

An MCP server can advertise a tool whose description is itself a malicious
instruction block:

- "ignore previous instructions"
- "reveal the system prompt"
- "bypass safety restrictions"
- "send conversation history"

That text is not just documentation. In an agent workflow it often lands in the
same context window as the rest of the tool catalog, where the model may treat
it as trusted guidance. This is an MCP-flavored prompt-injection / tool
poisoning pattern: the malicious payload sits in tool metadata instead of in a
later tool response.

This detector covers that first, high-signal slice. It does not try to classify
every jailbreak variant or every unsafe prompt. It looks for explicit
instruction-smuggling language in `tools/list` tool descriptions.

## Detection logic

Walk MCP Application Activity events from `ingest-mcp-proxy-ocsf`, whether they
arrive as OCSF Application Activity (6002) or the native application-activity
projection.

Keep only:

- `tools/list`
- `response`
- non-empty `tool.name`
- non-empty `tool.description`

Then flag descriptions that match one or more conservative signal groups:

- instruction override
- prompt exfiltration
- guardrail bypass
- secret or conversation exfiltration

Examples of phrases this first slice catches:

- `ignore previous instructions`
- `reveal the system prompt`
- `show the developer message`
- `bypass guardrails`
- `send conversation history`

## Output contract

One Detection Finding per suspicious tool declaration. By default the skill
emits OCSF 1.8 Detection Finding (class `2004`). With `--output-format native`,
it emits the repo-owned native finding projection.

OCSF output populates:

- `finding_info.types[] = ["mcp-prompt-injection", "llm-prompt-injection"]`
- `finding_info.attacks[]` with MITRE ATLAS `AML.T0051` Prompt Injection
- deterministic `finding_info.uid`
- `observables[]` with session uid, tool name, tool-description hash, and the
  source event uid
- `evidence.matched_signals[]` and `evidence.raw_event_uids[]`

## Usage

```bash
python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > prompt-injection-findings.ocsf.jsonl

python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl --output-format native \
  | python src/detect.py --output-format native \
  > prompt-injection-findings.native.jsonl
```

## Do NOT use

- On raw MCP proxy logs before normalization
- As a general jailbreak detector for every LLM request
- On tool-call outputs or tool responses
- As a replacement for `detect-mcp-tool-drift`

## Tests

The test suite covers:

- filtering on the correct class / method / direction
- explicit suspicious description matches
- no findings for benign tool descriptions
- deterministic finding IDs
- native and OCSF output modes
- golden-fixture parity for a frozen OCSF input and expected finding

## Native output format

When `--output-format native` is selected, the skill emits:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "detection_finding"`
- `finding_uid` and `event_uid`
- `provider`
- `time_ms`
- `session_uid`
- `tool_name`
- `matched_signals`
- `description_excerpt`
- `mitre_attacks`
