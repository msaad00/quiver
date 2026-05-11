---
name: detect-mcp-adversarial-input-corpus
description: >-
  Detect MCP requests whose user prompt matches an entry in a curated
  adversarial-input fingerprint catalog. Reads OCSF 1.8 Application Activity
  (class 6002) records produced by ingest-mcp-proxy-ocsf, pattern-matches
  unmapped.mcp.prompt (or request.params.messages[].content for chat-shaped
  tool calls) against fingerprints in src/fingerprints.json, and emits one
  Detection Finding per matching request citing every matched fingerprint.
  Maps to MITRE ATLAS AML.T0043 Craft Adversarial Data plus the relevant
  OWASP LLM Top 10 entries (LLM01 prompt injection, LLM02 insecure output
  handling, LLM07 system-prompt leakage). Use when the user mentions prompt
  injection, jailbreak detection, system-prompt extraction, role-play
  hijack, or adversarial corpora. Do NOT use on raw MCP proxy logs — feed
  them through ingest-mcp-proxy-ocsf first. Do NOT use as a content
  classifier or a model-side guardrail; this is a deterministic pattern
  scanner over a frozen catalog.
purpose: Detect MCP requests matching the adversarial-input fingerprint catalog (ATLAS AML.T0043).
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

# detect-mcp-adversarial-input-corpus

## Attack pattern

Adversaries seed MCP requests with prompts crafted to override the agent's
system prompt, exfiltrate it, role-play around safety filters, or smuggle
encoded payloads through tool calls. Each of these is a well-documented
pattern with a deterministic fingerprint — the public prompt-injection
catalogs are now mature enough that a frozen regex set covers a large slice
of the in-the-wild traffic.

This is the **MITRE ATLAS AML.T0043 Craft Adversarial Data** technique on
the prompt side of the loop, with secondary mappings into OWASP LLM Top 10
entries: LLM01 (prompt injection), LLM02 (insecure output handling — when a
match prompts a downstream tool to render the payload), and LLM07
(system-prompt leakage).

## Detection logic

At import time the detector loads `src/fingerprints.json` — a frozen
catalog of `{name, mitre_id, regex_pattern, severity, source}` entries.
If the file is missing or malformed, the detector logs a single stderr
warning and **fails open** (no findings, no crash). Operators are expected
to ship the catalog alongside the skill.

For each MCP Application Activity event, the detector scans:

- `unmapped.mcp.prompt`
- `unmapped.mcp.request.params.messages[].content` (the chat-shape used by
  most LLM SDK proxies passing through MCP)

Each scanned string is matched against every fingerprint regex (case
insensitive). When a single request matches one or more fingerprints, the
detector emits **one** Detection Finding citing every matched fingerprint
name in `observables`. The finding's severity is the **maximum** severity
across the matched fingerprints.

```
fingerprints = json.load("src/fingerprints.json")
for event in events:
    matched = [fp for fp in fingerprints if regex(fp).search(prompt)]
    if matched:
        emit one finding listing every fp.name
```

- Same request, multiple fingerprints → one finding with all names.
- Different requests in the same session → one finding each.
- Empty prompt or missing `unmapped.mcp.prompt` → ignored.

Use when the user mentions prompt injection, jailbreak detection, ATLAS
AML.T0043, system-prompt extraction, or adversarial-corpus coverage. Do NOT
use as a content classifier — the catalog is deterministic, not a model.

## Output contract

One OCSF 1.8 Detection Finding (class 2004) per matched request. With
`--output-format native` the skill emits the repo-owned native projection.

OCSF output populates:

- `finding_info.types[] = ["mcp-adversarial-input", "llm-prompt-injection"]`
- `finding_info.attacks[]` — MITRE ATLAS `AML.T0043` Craft Adversarial Data.
- deterministic `finding_info.uid` derived from session + request hash.
- `observables[]` — session uid, request uid, matched fingerprint names,
  match count, and the matched prompt sources (which scan field fired).

## Usage

```bash
python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > adversarial-input-findings.ocsf.jsonl
```

## Fingerprint catalog

The catalog is `src/fingerprints.json`. Each entry must declare a
`source` field citing the public reference (OWASP, NIST, the
prompt-injection-cheat-sheet repo, etc.) — the catalog is auditable and
every entry traces back to publicly documented research. Catalog entries
are not exhaustive coverage; they are a deterministic floor for the
common cases.
