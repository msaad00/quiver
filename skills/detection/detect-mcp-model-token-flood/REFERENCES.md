# References — detect-mcp-model-token-flood

## Standards implemented

- **OWASP LLM Top 10** — LLM04 Model Denial of Service · LLM10 Unbounded
  Consumption — https://genai.owasp.org/
- **MITRE ATLAS** — AML.T0034 Cost Harvesting (where applicable)
  https://atlas.mitre.org/techniques/AML.T0034
- **OWASP MCP Top 10** — Resource-exhaustion class — https://genai.owasp.org/

## Input format

OCSF 1.8 Application Activity (class 6002) emitted by
`ingest-mcp-proxy-ocsf`. Reads `unmapped.mcp.prompt_tokens` (integer),
`unmapped.mcp.model_name` (string), and `actor.user.uid` (string).

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** —
  https://schema.ocsf.io/1.8.0/classes/detection_finding

## Detection model

Sliding window keyed by `(user_uid, model_name)`. Inside the window
(`MCP_PROMPT_TOKEN_WINDOW_MIN`, default 5 minutes), sum
`prompt_tokens`. Fire when the running sum first exceeds
`MCP_PROMPT_TOKEN_BUDGET` (default 200000). The window then slides forward
past the most recent crossing event; subsequent flooding fires a new finding.

## Required permissions

None. Reads from stdin.

## See also

- `detect-mcp-unbounded-tool-output` — sister detector for response-size /
  line-count exhaustion.
