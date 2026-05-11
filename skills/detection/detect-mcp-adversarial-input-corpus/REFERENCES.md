# References — detect-mcp-adversarial-input-corpus

## Standards implemented

- **MITRE ATLAS** — `AML.T0043` Craft Adversarial Data
  https://atlas.mitre.org/techniques/AML.T0043
- **OWASP LLM Top 10** — LLM01 Prompt Injection, LLM02 Insecure Output
  Handling, LLM07 System Prompt Leakage
  https://genai.owasp.org/
- **OWASP MCP Top 10** — Prompt-side adversarial input class
  https://genai.owasp.org/
- **NIST AI 600-1** — Adversarial Machine Learning taxonomy
  https://www.nist.gov/

## Fingerprint catalog sources

The 30+ entries in `src/fingerprints.json` are derived from publicly
documented research. Each entry carries an explicit `source` field.
Categories represented:

- **Direct prompt-injection prefixes** — "ignore all previous instructions",
  "disregard the prior", "forget everything above", etc.
  Source: OWASP LLM Top 10 LLM01 example bank, public prompt-injection
  cheat-sheets.

- **System-prompt extraction probes** — "repeat your instructions",
  "what is your system prompt", "print your initial message".
  Source: OWASP LLM07 catalog, NIST AI 600-1 adversarial ML examples.

- **Role-play hijacks** — "you are now DAN", "act as evil", "pretend to be
  an AI without restrictions".
  Source: published jailbreak corpora (DAN/STAN/DUDE families documented
  in OWASP LLM Top 10 references).

- **Tool-result injection signals** — literal `</tool_result>` and
  `</system>` close-tag smuggles intended to trick the agent into believing
  a payload was emitted by a trusted upstream.
  Source: OWASP LLM02 insecure output handling examples.

- **Encoded-payload markers** — `data:text/plain;base64,` prefixes,
  long unicode-escape runs, and other smuggle envelopes used to evade
  case-sensitive content filters.
  Source: NIST AI 600-1, OWASP LLM01 evasion examples.

## Input format

OCSF 1.8 Application Activity (class 6002) emitted by `ingest-mcp-proxy-ocsf`.
The detector scans `unmapped.mcp.prompt` and
`unmapped.mcp.request.params.messages[].content` (for chat-shape tool calls).

## Output format

- **OCSF 1.8 Detection Finding (class 2004)** —
  https://schema.ocsf.io/1.8.0/classes/detection_finding

## Detection model

Deterministic regex scan over a frozen JSON catalog. The detector loads
the catalog once at import time, validates each entry, and ignores
malformed entries with a stderr warning. Missing or unparseable catalog
file → fails open (no findings). One finding per matching request; the
emitted finding lists every fingerprint name that matched. Severity is
the max across all matched fingerprints.

## Required permissions

None. Reads from stdin.

## See also

- `detect-mcp-system-prompt-extraction` — narrower scope: only the
  system-prompt-leakage subset, fires on tool-call patterns rather than
  prompt-corpus matches.
- `detect-prompt-injection-mcp-proxy` — broader, learned-pattern detector
  for non-corpus prompt-injection signals.
