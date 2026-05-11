# References — detect-mcp-model-artifact-tampering

## Standards implemented

- **MITRE ATLAS** — AML.T0010 ML Supply Chain Compromise
  https://atlas.mitre.org/techniques/AML.T0010
- **OWASP LLM Top 10** — LLM03 Supply Chain
  https://genai.owasp.org/
- **OWASP MCP Top 10** — Supply-chain / tool-poisoning class
  https://genai.owasp.org/

## Input format

OCSF 1.8 Application Activity (class 6002) emitted by
`ingest-mcp-proxy-ocsf`. The detector reads
`unmapped.mcp.model_artifact_sha256` and `unmapped.mcp.tool_name`; the proxy
adapter is responsible for surfacing these fields under `unmapped` when the
MCP server publishes them.

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** —
  https://schema.ocsf.io/1.8.0/classes/detection_finding
- **OCSF 1.8 attack object** —
  https://schema.ocsf.io/1.8.0/objects/attack

## Detection model

Per-session baseline of the first observed artifact SHA-256. A second event
in the same session whose hash differs emits one finding; baseline advances
so subsequent re-tampering is reported once per transition.

## Required permissions

None. Reads from stdin.

## See also

- `detect-mcp-tool-drift` — same fingerprint-divergence shape, scoped to
  tool schemas instead of model artifacts.
- `detect-mcp-shadow-tool-injection` — divergence against an externally
  registered baseline rather than session-first.
