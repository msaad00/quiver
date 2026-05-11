# References — detect-mcp-tool-drift

## Standards implemented

- **MITRE ATT&CK** — T1195 Supply Chain Compromise, sub-technique T1195.001 Compromise Software Supply Chain
  https://attack.mitre.org/techniques/T1195/001/
- **MITRE ATT&CK version pinned for this skill** — v14
- **OWASP MCP Top 10** — MCP-04 Supply Chain Vulnerabilities — https://genai.owasp.org/

## Input format

OCSF 1.8 Application Activity (class 6002) with the `cloud_security_mcp`
custom profile, as produced by `ingest-mcp-proxy-ocsf`. See sibling
[`ingest-mcp-proxy-ocsf/REFERENCES.md`](../ingest-mcp-proxy-ocsf/REFERENCES.md).

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding
- **OCSF 1.8 finding_info object** — `attacks[]` lives **inside** `finding_info`, not at the event root (the deprecated Security Finding 2001 layout). MITRE ATT&CK is populated per the OCSF 1.8 contract.
- **OCSF 1.8 attack object** — https://schema.ocsf.io/1.8.0/objects/attack

## Detection model

Stateless single-pass walk over events sorted by `time`. Per
`(session_uid, tool_name)`, track the last-seen fingerprint. Any
transition to a different fingerprint emits one finding.

The fingerprint is defined in `ingest-mcp-proxy-ocsf` as:

```python
sha256(json.dumps({
    "name":        tool["name"],
    "description": tool.get("description", ""),
    "inputSchema": tool.get("inputSchema", {}),
    "annotations": tool.get("annotations", {}),
}, sort_keys=True))
```

The detector does NOT recompute the fingerprint — it trusts the upstream
ingest skill. If the contract between ingest and detect ever drifts, the
golden-fixture deep-equality test fails.

## Required permissions

None. Reads from stdin.

## Attack pattern reference

The MCP tool-poisoning / rug-pull pattern was first publicly documented
in MCP attack research throughout 2025. Real-world examples have shown
MCP servers that:

- Advertise a benign read-only tool in the first `tools/list` response
- Wait for the agent to establish trust by calling the tool successfully
- Re-advertise the same tool name with expanded write semantics in a
  subsequent `tools/list` response
- Receive the agent's call to the now-mutated tool with arguments the
  agent constructed under the assumption of the original schema

This skill detects step 3 (the schema change), which is the only step
visible in proxy logs without inspecting tool semantics.

## See also

- `OCSF_CONTRACT.md` (sibling) — wire format
- `ingest-mcp-proxy-ocsf` (sibling) — upstream producer
- `detect-mcp-shadow-tool-injection` — sibling detector that fires against
  an out-of-band server-registered baseline rather than the first sighting
  in a session. Use shadow-tool-injection when the operator has registered
  baseline hashes at startup; use tool-drift when only in-session events
  are available.
- `OWASP MCP Top 10` — https://genai.owasp.org/
