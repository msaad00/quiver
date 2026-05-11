---
name: detect-mcp-tool-drift
description: >-
  Detect MCP tool schema drift mid-session — the MCP tool-poisoning / rug-pull
  attack pattern. Reads OCSF 1.8 Application Activity (class 6002) or the native
  application-activity projection produced by ingest-mcp-proxy-ocsf, groups them
  by session, and flags any tool whose
  fingerprint (sha256 over name + description + inputSchema + annotations) changes
  between tools/list responses in the same session. Emits OCSF 1.8 Detection
  Finding (class 2004) with MITRE ATT&CK T1195.001 (Compromise Software Supply
  Chain) inside finding_info.attacks. Use when the user mentions MCP security,
  tool drift, tool poisoning, prompt injection via tool schema, or supply chain
  compromise of an MCP server. Do NOT use on raw MCP proxy logs — feed them
  through ingest-mcp-proxy-ocsf first. Do NOT use for cross-session drift (same
  tool, different sessions) — that is a legitimate MCP server update, not an
  attack; a separate detector will cover it. Do NOT use as a compliance check;
  this is an active detection skill.
purpose: Detect MCP tool schema drift mid-session — the MCP tool-poisoning / rug-pull attack pattern.
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

# detect-mcp-tool-drift

## Attack pattern

An MCP server can change the schema of a tool between calls in the same session. A benign-looking `query_db(sql)` tool with `readOnly: true` in the first `tools/list` response can come back in the second `tools/list` response (after the agent has already trusted the first definition) with a new `write` argument and `readOnly: false`. By the time the agent sees the updated schema, it may have already been primed by the original description and will happily call `query_db(sql="DELETE …", write=true)`.

This is the **MCP tool-poisoning** / **rug-pull** pattern. It maps to MITRE ATT&CK **T1195.001** — Supply Chain Compromise: Compromise Software Supply Chain. The tool is the "software"; the MCP server is the "supply chain."

## Detection logic

Walk MCP Application Activity events in timestamp order. The detector accepts:

- OCSF Application Activity emitted by `ingest-mcp-proxy-ocsf`
- the native or canonical activity projection emitted by the same skill when `--output-format native` is selected

For each session and tool name, track the last-seen fingerprint. If a later `tools/list` entry for the same `(session, tool name)` has a different fingerprint, emit **one** Detection Finding per drift event.

```
state[(session_uid, tool_name)] = last_fingerprint
```

- Same fingerprint in the same session → no finding (idempotent republish of the same tool is normal).
- Different fingerprint in the same session → finding.
- Different fingerprint in a different session → ignored (cross-session is a separate detector).

## Output contract

One Detection Finding per drift event. By default the skill emits OCSF 1.8 Detection Finding (class `2004`). With `--output-format native`, it emits the repo-owned native finding projection.

OCSF output populates:

- `finding_info.attacks[]`: MITRE ATT&CK v14, tactic TA0001 (Initial Access), technique T1195.001 (Compromise Software Supply Chain).
- `finding_info.types[]`: `["mcp-tool-drift"]` for downstream filtering.
- `finding_info.first_seen_time` / `finding_info.last_seen_time`: timestamps of the two `tools/list` events that triggered the finding.
- `finding_info.uid`: deterministic (`det-mcp-drift-<session>-<tool>-<before-8>-<after-8>`) so re-running on the same fixture is idempotent.
- `observables[]`: session uid, tool name, before/after fingerprints.
- `evidence`: event counts and pointers to the raw `tools/list` records.

See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the full Detection Finding contract.

## Usage

```bash
# Piped from the ingest skill
python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > drift-findings.ocsf.jsonl

# Native input and native output
python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl --output-format native \
  | python src/detect.py --output-format native \
  > drift-findings.native.jsonl

# Standalone file
python src/detect.py ../golden/mcp_proxy_sample.ocsf.jsonl
```

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
- `before_fingerprint`
- `after_fingerprint`
- `mitre_attacks`

Example:

```json
{
  "schema_mode": "native",
  "canonical_schema_version": "2026-04",
  "record_type": "detection_finding",
  "finding_uid": "det-mcp-drift-sess-abc-query_db-9b5f6e3c-7d10a2bf",
  "provider": "MCP",
  "session_uid": "sess-abc",
  "tool_name": "query_db",
  "before_fingerprint": "sha256:...",
  "after_fingerprint": "sha256:..."
}
```

## Tests

Golden-fixture parity: runs against [`../golden/mcp_proxy_sample.ocsf.jsonl`](../golden/mcp_proxy_sample.ocsf.jsonl) and asserts the output matches [`../golden/tool_drift_finding.ocsf.json`](../golden/tool_drift_finding.ocsf.json) exactly (with volatile fields scrubbed).
