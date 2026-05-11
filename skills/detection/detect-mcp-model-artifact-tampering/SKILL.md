---
name: detect-mcp-model-artifact-tampering
description: >-
  Detect MCP tool calls whose returned model_artifact_sha256 differs from a
  known-good baseline registered at session start. Reads OCSF 1.8 Application
  Activity (class 6002) records produced by ingest-mcp-proxy-ocsf and walks
  them per session: the first event in a session that carries
  unmapped.mcp.model_artifact_sha256 establishes the baseline, and the first
  later event whose hash diverges fires one Detection Finding tagged with
  MITRE ATLAS AML.T0010 (ML Supply Chain Compromise) and OWASP LLM03 (Supply
  Chain). Use when the user mentions ML supply-chain tampering, model artifact
  drift in an agent session, OWASP LLM03, or ATLAS AML.T0010. Do NOT use on
  raw MCP proxy logs — feed them through ingest-mcp-proxy-ocsf first. Do NOT
  use for cross-session artifact drift; a model upgrade between sessions is a
  legitimate change. Do NOT use as a generic file-hash differ; the contract is
  scoped to MCP tool responses that publish a model artifact hash.
purpose: Detect MCP tool calls whose returned model artifact hash diverges from a session baseline (ATLAS AML.T0010 · OWASP LLM03).
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

# detect-mcp-model-artifact-tampering

## Attack pattern

An MCP server (or a tool it brokers) loads a model artifact when a session
starts and republishes the artifact's SHA-256 on every subsequent tool call
that touches the model. The artifact is the **supply-chain blob**: model
weights, an adapter, a tokenizer, an inference engine binary. If the artifact
is swapped mid-session — by a process restart that pulls a different artifact
from a poisoned registry, by a hot-reload that picks up a tampered file, or
by an attacker substituting weights for an already-trusted endpoint — the
SHA-256 the tool returns changes while the session keeps running. The agent
keeps calling the now-tampered tool under the trust contract established at
session start.

This is the **ML Supply Chain Compromise** pattern. It maps to MITRE ATLAS
**AML.T0010** and OWASP LLM Top 10 **LLM03 — Supply Chain**.

## Detection logic

Walk MCP Application Activity events from `ingest-mcp-proxy-ocsf` per
session, ordered by time. Filter for events with a non-empty
`unmapped.mcp.model_artifact_sha256` and `unmapped.mcp.tool_name`.

For each session, the **first** such event sets the baseline artifact hash.
Any later event in the **same session** whose hash differs from the baseline
emits **one** Detection Finding and the baseline moves forward (so a
subsequent re-tampering is reported once).

```
state[session_uid] = first_artifact_sha256
```

- First baseline-bearing event → no finding (sets baseline).
- Same artifact hash later → no finding.
- Different artifact hash later → finding; baseline updated.
- Different session → ignored (new baseline).

Use when the user mentions ML supply-chain compromise, model tampering, or
ATLAS AML.T0010. Do NOT use as a general file integrity monitor.

## Output contract

One OCSF 1.8 Detection Finding (class 2004) per divergent hash. With
`--output-format native` the skill emits the repo-owned native projection.

OCSF output populates:

- `finding_info.attacks[]` — MITRE ATLAS `AML.T0010`, tactic
  `AML.TA0000` (ML Model Access pre-attack stage), surfaced via the
  `finding_info.attacks` slot the way OWASP MCP detectors in this repo
  already do.
- `finding_info.types[] = ["mcp-model-artifact-tampering", "llm-supply-chain"]`
- `finding_info.uid` deterministic
  (`det-mcp-model-tamper-<session-8>-<tool-8>-<before-8>-<after-8>`).
- `observables[]` — session uid, tool name, before/after artifact hashes.

## Usage

```bash
python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > artifact-tamper-findings.ocsf.jsonl
```
