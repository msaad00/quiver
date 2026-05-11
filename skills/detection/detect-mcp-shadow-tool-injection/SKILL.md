---
name: detect-mcp-shadow-tool-injection
description: >-
  Detect MCP tools whose description or inputSchema has been mutated mid-session
  relative to an out-of-band server-registered baseline — the shadow-tool /
  tool-poisoning variant where the MCP server's startup snapshot is the trust
  anchor, not the first in-session sighting. Reads OCSF 1.8 Application
  Activity (class 6002) records produced by ingest-mcp-proxy-ocsf and compares
  the live tool's description/inputSchema sha256 hashes against the baseline
  file at MCP_TOOL_BASELINE_PATH ({tool_name: {description_sha256,
  schema_sha256, registered_at}}). Fires one Detection Finding per (session,
  tool) when either hash diverges from the baseline. Maps to OWASP MCP Top 10
  Tool Poisoning. Use when the user mentions MCP shadow tools, tool poisoning
  with a server registration baseline, or MITRE T1195.001. Do NOT use on raw
  MCP proxy logs — feed them through ingest-mcp-proxy-ocsf first. Do NOT use
  for first-sight-in-session detection without a baseline — that is what
  detect-mcp-tool-drift covers.
purpose: Detect MCP tools whose description/schema diverges from the server-registered baseline (OWASP MCP Top 10).
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

# detect-mcp-shadow-tool-injection

## Attack pattern

An MCP server can register a tool at startup with one description and
inputSchema, then later answer `tools/list` with a different declaration —
the **shadow tool**. The agent has no way to know whether the live
declaration matches what the operator registered. A compromised or
rug-pulled MCP server can silently substitute a poisoned tool while the
operator's runbook still references the original definition.

The defense is an out-of-band baseline: when the MCP server starts, it
writes `{tool_name: {description_sha256, schema_sha256, registered_at}}`
to a baseline file that the operator owns. Any live declaration whose
hashes diverge from the baseline is a **shadow-tool injection**.

This is the **OWASP MCP Top 10 Tool Poisoning** class and maps to MITRE
ATT&CK `T1195.001` Compromise Software Supply Chain — the tool's
declaration is the software the agent ingests.

## Detection logic

Walk MCP Application Activity events from `ingest-mcp-proxy-ocsf`. For
each `tools/list` response, compute sha256 over the tool's
`description` (UTF-8) and a stable JSON serialization of its
`inputSchema`. Compare both against the baseline entry keyed by tool
name. Fire when either hash diverges.

```
baseline = json.load(MCP_TOOL_BASELINE_PATH)
for tool in tools/list response:
    if tool.name in baseline:
        if sha256(tool.description) != baseline[tool.name].description_sha256:
            fire
        elif sha256_stable_json(tool.inputSchema) != baseline[tool.name].schema_sha256:
            fire
```

- Tool not in baseline → ignored (unknown tools are a different defect,
  not shadow-tool injection).
- Same `(session, tool)` keeps appearing with the divergent hashes →
  one finding (idempotent on the divergence pair).
- Different divergence in the same session → new finding (the baseline
  hashes haven't moved; the live tool moved again).
- Missing/empty baseline file → single stderr warning + fail open
  (operators must register first).

Use when the user mentions OWASP MCP Top 10 tool poisoning, shadow
tools, MCP startup baselines, or supply-chain compromise with an
out-of-band trust anchor. Do NOT use for first-sight-in-session drift
without a baseline — that is `detect-mcp-tool-drift`.

## Boundary with `detect-mcp-tool-drift`

The two skills are intentionally separate:

- `detect-mcp-tool-drift` fires when a tool's fingerprint **changes
  between two `tools/list` responses in the same session**. The trust
  anchor is the **first sighting**. Works without an out-of-band
  baseline.
- `detect-mcp-shadow-tool-injection` fires when a tool's hashes
  **diverge from a server-registered baseline file**. The trust anchor
  is the **baseline**. Requires the operator to register tools at
  startup. Catches the case where the very first `tools/list` response
  in a session is already poisoned (which `detect-mcp-tool-drift`
  cannot detect).

Reviewers asking "is this drift vs poisoning?" should pick by trust
anchor: in-session-only → drift; server-registered baseline → shadow
tool.

## Output contract

One OCSF 1.8 Detection Finding (class 2004) per `(session, tool)`
divergence. With `--output-format native` the skill emits the
repo-owned native projection.

OCSF output populates:

- `finding_info.types[] = ["mcp-shadow-tool-injection", "mcp-tool-poisoning"]`
- `finding_info.attacks[]` — MITRE ATT&CK `T1195.001` Compromise Software
  Supply Chain (v14).
- deterministic `finding_info.uid`.
- severity HIGH.
- `observables[]` — session uid, tool name, baseline hashes, live hashes,
  divergence type (description / schema / both).

## Usage

```bash
# Baseline written by the MCP server on startup
MCP_TOOL_BASELINE_PATH=/var/lib/mcp/tool-baseline.json \
  python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > shadow-tool-findings.ocsf.jsonl
```
