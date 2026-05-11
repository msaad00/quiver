# References — detect-mcp-plugin-supply-chain

## Standards implemented

- **OWASP LLM Top 10** — LLM05 Supply Chain (Plugins / Tools)
  https://genai.owasp.org/
- **MITRE ATT&CK** — T1195.001 Compromise Software Supply Chain
  https://attack.mitre.org/techniques/T1195/001/
- **MITRE ATT&CK version pinned for this skill** — v14
- **OWASP MCP Top 10** — Plugin / supply-chain class — https://genai.owasp.org/

## Input format

OCSF 1.8 Application Activity (class 6002) emitted by
`ingest-mcp-proxy-ocsf`. The detector consumes the `tools/list` response
events and walks the schema embedded under `mcp.tool.inputSchema`
(or `mcp.tool.input_schema`, surfaced verbatim).

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** —
  https://schema.ocsf.io/1.8.0/classes/detection_finding

## Detection model

Recursive schema walker. Visits `oneOf`, `anyOf`, `allOf`, `properties`,
`items`, `$ref`, `default`, `description`. Collects every `http(s)://`-shaped
string. For each URL, parses the hostname and compares against the operator
allowlist (env var `MCP_PLUGIN_ALLOWED_HOSTS`, comma-separated). One finding
per `(session_uid, host)`; idempotent on repeat events.

## Required permissions

None. Reads from stdin.

## See also

- `detect-mcp-tool-drift` — fires on tool fingerprint divergence in the same
  session; this detector fires on first sight of a tool whose schema reaches
  outside the allowlist regardless of drift.
