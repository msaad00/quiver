# References — detect-mcp-unbounded-tool-output

## Standards implemented

- **OWASP LLM Top 10** — LLM10 Unbounded Resource Consumption
  https://genai.owasp.org/
- **MITRE ATLAS** — `AML.T0034` Cost Harvesting (the cost-amplification mapping
  for the LLM10 class)
  https://atlas.mitre.org/techniques/AML.T0034
- **OWASP MCP Top 10** — Resource exhaustion class
  https://genai.owasp.org/

## Input format

OCSF 1.8 Application Activity (class 6002) emitted by `ingest-mcp-proxy-ocsf`.
The detector consumes any event carrying `unmapped.mcp.response_size_bytes` or
`unmapped.mcp.response_line_count` and aggregates breaches per
`(session_uid, tool_name)`.

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** —
  https://schema.ocsf.io/1.8.0/classes/detection_finding

## Detection model

Per-session, per-tool breach counter. A breach is recorded when EITHER
threshold is crossed by a single event. When the counter reaches the repeat
threshold, the detector fires once for the `(session, tool)` pair — chronic
behaviour, not acute spikes. The wrapper RLIMIT contract handles per-call
enforcement; this skill handles the cumulative pattern.

## Required permissions

None. Reads from stdin.

## See also

- `detect-mcp-model-token-flood` — the prompt-side mirror (input tokens
  rather than output bytes/lines).
- `detect-mcp-tool-drift` — same class of MCP tool-side defects but for
  schema mutation rather than payload volume.
