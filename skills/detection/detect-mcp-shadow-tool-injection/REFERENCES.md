# References — detect-mcp-shadow-tool-injection

## Standards implemented

- **OWASP MCP Top 10** — Tool Poisoning / Shadow Tools
  https://genai.owasp.org/
- **MITRE ATT&CK** — T1195.001 Compromise Software Supply Chain (v14)
  https://attack.mitre.org/techniques/T1195/001/
- **MITRE ATT&CK version pinned for this skill** — v14
- **OWASP LLM Top 10** — LLM05 Supply Chain (Plugins / Tools), secondary
  mapping
  https://genai.owasp.org/

## Input format

OCSF 1.8 Application Activity (class 6002) emitted by
`ingest-mcp-proxy-ocsf`. The detector consumes `tools/list` response
events and reads `mcp.tool.{name, description, inputSchema}`.

## Baseline format

A JSON file pointed to by `MCP_TOOL_BASELINE_PATH`:

```json
{
  "schema_version": "1",
  "tools": {
    "query_db": {
      "description_sha256": "<hex sha256 of the trusted description>",
      "schema_sha256": "<hex sha256 of the trusted inputSchema stable-JSON>",
      "registered_at": "2026-05-10T12:00:00Z"
    }
  }
}
```

The MCP server owns the baseline file. The detector treats the baseline
as ground truth. If the file is missing, malformed, or empty, the
detector logs a stderr warning and fails open — operators are expected
to ship the baseline alongside the MCP server's startup contract.

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** —
  https://schema.ocsf.io/1.8.0/classes/detection_finding

## Detection model

For each `tools/list` response event, the detector:

1. Looks up the tool by name in the baseline.
2. Computes sha256 over the tool's `description` (UTF-8) and over a
   stable JSON serialization of its `inputSchema` (sort_keys=True,
   separators tight).
3. Compares both hashes to the baseline values.
4. Fires when either diverges. Records which side(s) diverged in the
   finding.

One finding per `(session, tool, divergence-pair)`. Re-running on the
same input is idempotent.

## Required permissions

None. Reads from stdin. Reads the baseline file as a local resource.

## See also

- `detect-mcp-tool-drift` — first-sight-in-session schema drift (no
  baseline lookup). Shadow-tool fires against an out-of-band baseline;
  drift fires against the first sighting in a session.
- `detect-mcp-plugin-supply-chain` — orthogonal: catches tools whose
  inputSchema references a host outside the allowlist; this skill
  catches tools whose declaration as a whole diverges from a baseline.
