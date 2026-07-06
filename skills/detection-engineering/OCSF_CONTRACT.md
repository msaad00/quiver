# OCSF Contract — Detection Engineering Category

This document pins the exact OCSF fields every skill in `detection-engineering/` must read and write. It is the **only** dependency shared across skills in this category. If you are writing a new ingestion or detection skill, your tests must verify that the output matches this contract.

It also defines the repo-wide OCSF policy for adjacent layers:
- support `native`, `canonical`, `ocsf`, and `bridge` modes explicitly
- use a native OCSF class when one exists and fits the artifact cleanly
- use OCSF profiles and extensions before inventing repo-local fields
- use a deterministic bridge artifact only when OCSF does not yet model the discovery or BOM shape well enough

## OCSF version

- Base schema: **OCSF 1.8.0** (current stable — verified against [schema.ocsf.io](https://schema.ocsf.io/)).
- MCP-specific fields: **custom profile extension** `cloud_security_mcp`, bolted onto `Application Activity` (class 6002). This captures MCP tool schema, tool arguments, and proxy session ID without modifying the base OCSF schema.
- **`Security Finding` (class 2001) is NOT used.** It has been deprecated since OCSF 1.1.0. All detections in this category emit **`Detection Finding` (class 2004)** instead.
- MITRE ATT&CK v14 is pinned for this contract version. The `attacks[]` array lives inside `finding_info` (the OCSF 1.8 layout), not at the event root.

```
contract version: 1.8.0+mcp.2026.04
```

## OCSF-optional policy beyond detection

The repo is broader than event ingestion and detections, so schema usage falls into four buckets:

1. **Native source mode**
   - preserve source payload shape and source-natural identifiers
   - use when vendor fidelity matters more than standard transport

2. **Canonical repo mode**
   - normalize into the repo's stable internal model
   - use for storage, joins, metrics, state materialization, and downstream stability

3. **Native OCSF wire paths**
   - `ingest-*`
   - `detect-*`
   - `evaluate-*`
   - `convert-*`

4. **Discovery and evidence paths that should prefer native OCSF where it fits**
   - `Cloud Resources Inventory Info [5023]`
   - `Software Inventory Info [5020]`
   - `Live Evidence Info [5040]`
   - `Base Event [0]` only as a last-resort generic carrier

5. **Documented bridge artifacts**
   - environment graph snapshots
   - CycloneDX-aligned AI BOMs
   - deterministic technical-evidence JSON

Bridge artifacts are allowed only when:
- the current OCSF schema does not cleanly express the artifact
- the skill documents the gap and the intended OCSF mapping path
- the bridge format remains deterministic and validation-friendly

The direction of travel is still toward more native OCSF inventory/evidence use where it helps, but the repo must continue to function correctly without OCSF when source fidelity or canonical-state stability is the more accurate contract.

Some repo-local bridge/profile identifiers intentionally retain their older
names for compatibility:
- `cloud_security_mcp`
- `cloud-security.environment-graph.v1`
- `cloud-security:*` CycloneDX property keys in AI BOM artifacts

Those identifiers are treated as compatibility contracts, not public branding.
The emitted OCSF `metadata.product` identity and the public repo/docs surface
must still use the current repo name.

Current bridge modes shipped in-tree:
- `discover-environment --output-format ocsf-cloud-resources-inventory`
- `discover-control-evidence --output-format ocsf-live-evidence`
- `discover-cloud-control-evidence --output-format ocsf-live-evidence`

## Wire format

- All skills read and write **JSONL** (one OCSF event per line).
- UTF-8, no BOM, LF line endings.
- Skills read from `stdin` by default, write to `stdout`. A `--input` / `--output` flag is optional but must not change the default behaviour.
- Errors go to `stderr`. A malformed line is **skipped with a `stderr` warning**, never fatal — detection pipelines must not crash on one bad event.

## Required OCSF fields (every event)

Every event a skill emits MUST populate these fields at minimum. Fields marked `[req]` are required by OCSF itself; `[pin]` are pinned by this contract on top of the OCSF minimum.

| Field | Type | Notes |
|---|---|---|
| `activity_id` | int [req] | Class-specific activity enum |
| `category_uid` | int [req] | Matches the class's category |
| `category_name` | string [pin] | Human-readable category (for log grep) |
| `class_uid` | int [req] | The OCSF class number (e.g. 6002 Application Activity, 2004 Detection Finding) |
| `class_name` | string [pin] | Human-readable class (for log grep) |
| `type_uid` | int [req] | `class_uid * 100 + activity_id` |
| `severity_id` | int [req] | 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal |
| `status_id` | int [rec] | 0 Unknown, 1 Success, 2 Failure — recommended by OCSF 1.8 (not required) |
| `time` | int [req] | Unix epoch **milliseconds** (not seconds) |
| `metadata.version` | string [req] | `"1.8.0"` |
| `metadata.uid` | string [pin] | Deterministic event-level identity for SIEM dedupe and replay safety |
| `metadata.product.name` | string [pin] | `"cloud-ai-security-skills"` |
| `metadata.product.vendor_name` | string [pin] | `"msaad00/cloud-ai-security-skills"` |
| `metadata.product.feature.name` | string [pin] | Name of the emitting skill (e.g. `"detect-mcp-tool-drift"`) |

## OCSF class usage

### Ingest skills

| Source | OCSF class | `class_uid` | Why |
|---|---|---:|---|
| AWS CloudTrail | API Activity | 6003 | Control-plane API calls |
| GCP Audit | API Activity | 6003 | Same |
| Azure Activity | API Activity | 6003 | Same |
| Kubernetes audit | API Activity | 6003 | K8s API server is the control plane |
| MCP proxy | Application Activity | 6002 | MCP is an application protocol, not a cloud control plane |
| Model serving access logs | HTTP Activity | 4002 | Inference over HTTP |

### Detect skills

All detection skills in this category produce **Detection Finding** (class `2004`, `category_uid=2`). Input class varies.

> **Do not emit Security Finding (2001).** It is deprecated in OCSF ≥ 1.1. Downstream OCSF consumers (Splunk OCSF app, ClickHouse schema, Grafana dashboards) now key off `class_uid=2004`.

#### Activity IDs for Detection Finding

| `activity_id` | Meaning |
|---:|---|
| 0 | Unknown |
| **1** | **Create** — a brand-new finding (what every detector here emits) |
| 2 | Update — re-raised with new evidence |
| 3 | Close — auto-closed by expiry or correlation |
| 99 | Other |

## Required fields on a Detection Finding (2004)

```jsonc
{
  "activity_id": 1,                 // 1 = Create
  "category_uid": 2,                // Findings
  "category_name": "Findings",
  "class_uid": 2004,                // Detection Finding (Security Finding 2001 is deprecated)
  "class_name": "Detection Finding",
  "type_uid": 200401,               // 2004 * 100 + 1
  "severity_id": 4,                 // High — pinned by detection rule
  "status_id": 1,                   // 1 Success — the rule ran cleanly (recommended in 1.8)
  "time": 1775797260000,            // when the FINDING was created, not the underlying event

  "metadata": {
    "version": "1.8.0",
    "uid": "det-mcp-drift-abc123",
    "product": {
      "name": "cloud-ai-security-skills",
      "vendor_name": "msaad00/cloud-ai-security-skills",
      "feature": {"name": "detect-mcp-tool-drift"}
    },
    "labels": ["detection-engineering", "mcp", "supply-chain"]
  },

  "finding_info": {
    "uid": "det-mcp-drift-abc123",  // deterministic ID per (rule, session, tool)
    "title": "MCP tool schema drift detected mid-session",
    "desc": "Tool 'query_db' changed fingerprint after first call in session sess-abc",
    "types": ["mcp-tool-drift"],
    "first_seen_time": 1775797200000,
    "last_seen_time":  1775797260000,

    // MITRE ATT&CK lives HERE in OCSF 1.8, not at the event root.
    "attacks": [
      {
        "version": "v14",
        "tactic":    {"name": "Initial Access",                         "uid": "TA0001"},
        "technique": {"name": "Compromise Software Supply Chain",       "uid": "T1195.001"}
      }
    ]
  },

  "observables": [
    {"name": "session.uid",    "type": "Other",       "value": "sess-abc"},
    {"name": "tool.name",      "type": "Other",       "value": "query_db"},
    {"name": "tool.before",    "type": "Fingerprint", "value": "sha256:abc..."},
    {"name": "tool.after",     "type": "Fingerprint", "value": "sha256:def..."}
  ],

  "evidence": {
    "events_observed": 2,
    "before_event_time": 1775797200000,
    "after_event_time":  1775797260000,
    "raw_events": []                // pointer / rowid / S3 URI, not full bodies
  }
}
```

The point: **a downstream tool (ClickHouse, Splunk OCSF app, Grafana) can pivot on `finding_info.attacks[].technique.uid` without ever reading the rule code**. That is the whole benefit of keeping MITRE inside OCSF instead of as a sidecar mapping.

`metadata.uid` is the event-level companion to `finding_info.uid`. Use it for replay-safe SIEM dedupe and index merges; use `finding_info.uid` for finding lifecycle and sink-side upserts.

## MITRE ATT&CK version pinning

- ATT&CK version: **v14** (pinned for the 1.8.0+mcp.2026.04 contract)
- Rationale: frozen once per contract version so detections are reproducible. To bump, cut a new contract version and update every detection skill's test fixtures.

## Custom MCP profile extension

For `Application Activity` events that originate from an MCP proxy, populate these extra fields under a nested `mcp` key (non-standard, gated by `metadata.profiles: ["cloud_security_mcp"]`):

```jsonc
{
  "metadata": {
    "profiles": ["cloud_security_mcp"],
    ...
  },
  "mcp": {
    "session_uid": "sess-abc",       // agent-bom proxy session ID
    "method":      "tools/list",     // MCP JSON-RPC method
    "direction":   "response",       // request | response
    "tool": {                        // present only for tools/list and tools/call
      "name":        "query_db",
      "description": "Query database using SQL",
      "input_schema_sha256": "sha256:abc123...",
      "fingerprint":         "sha256:full_tool_fingerprint..."
    }
  }
}
```

Fingerprint definition: `sha256(json.dumps({name, description, inputSchema, annotations}, sort_keys=True))`.

When OCSF publishes an official MCP or AI-agent profile, we will migrate the `mcp` key to the official field names in one PR and bump the contract version.

## Test contract

Every detection skill ships with:
1. An **input fixture**: frozen OCSF JSONL in `golden/<source>_sample.ocsf.jsonl`
2. An **expected-output fixture**: frozen OCSF Detection Finding in `golden/<detection>_finding.ocsf.jsonl`
3. A pytest test that pipes the input fixture through the detector and asserts deep-equality against the expected output

If the skill adds a new attack scenario, add a new fixture pair, keep the old one. Never mutate an existing fixture.

## Migration notes (1.3 → 1.8)

This contract was originally drafted against OCSF 1.3 in error — 1.3 was superseded by 1.4, 1.5, 1.6, 1.7, and 1.8. The upgrade made three substantive changes:

1. **`Security Finding` (2001) → `Detection Finding` (2004).** The former is deprecated since OCSF 1.1. Code and fixtures have been updated.
2. **`attacks[]` moved inside `finding_info`.** In the deprecated Security Finding layout, `attacks[]` was at the event root. In OCSF 1.8 Detection Finding it lives at `finding_info.attacks`. All downstream SQL / Grafana queries must pivot on `finding_info.attacks[].technique.uid`.
3. **`status_id` is recommended, not required** on Detection Finding. We continue to set it to `1` (Success) for parity across skills.

Application Activity (6002) fields relevant to this category are unchanged between 1.3 and 1.8, so the ingest skill's output layout only needed a `metadata.version` bump.
