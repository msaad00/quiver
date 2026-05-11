---
name: detect-mcp-plugin-supply-chain
description: >-
  Detect MCP server tools/list responses where any tool's inputSchema references
  a hostname not in MCP_PLUGIN_ALLOWED_HOSTS. Reads OCSF 1.8 Application
  Activity (class 6002) records produced by ingest-mcp-proxy-ocsf and walks
  the tool's JSON schema (oneOf / anyOf / allOf / properties / items / $ref /
  default / description) extracting every URL-shaped string. Fires once per
  (session, host) pair when the host falls outside the allowlist. Maps to
  OWASP LLM Top 10 LLM05 Supply Chain via Plugins/Tools. Use when the user
  mentions MCP plugin supply chain, untrusted schema $ref, LLM05, or tool
  inputSchema fetching remote definitions. Do NOT use on raw MCP proxy logs —
  feed them through ingest-mcp-proxy-ocsf first. Do NOT use as a generic URL
  scanner; the contract is scoped to inputSchema URLs in tools/list responses.
purpose: Detect MCP tools/list tools whose inputSchema points at a hostname outside the operator allowlist (OWASP LLM05).
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

# detect-mcp-plugin-supply-chain

## Attack pattern

An MCP server's `tools/list` response can advertise a tool whose JSON
`inputSchema` itself reaches outside the trust boundary — a `$ref` to a
remote schema URL, a `default` value containing a remote URL, or a
`description` that promotes a remote endpoint. When the agent or its
infrastructure resolves that schema (for input validation, for documentation
rendering, for code generation, or for human review), it fetches code or
content from a host the operator never authorized.

This is the **plugin / tool supply-chain** flavour of OWASP LLM Top 10
**LLM05 Supply Chain**. The poisoned link is not the tool's
implementation — it is the tool's **declaration**.

## Detection logic

Walk MCP Application Activity events from `ingest-mcp-proxy-ocsf`. For each
`tools/list` response, recursively walk every `inputSchema` node and harvest
URL-shaped strings from `$ref`, `default`, `description`, and string values
nested inside `oneOf / anyOf / allOf / properties / items`.

Compare each URL's hostname against `MCP_PLUGIN_ALLOWED_HOSTS` (a comma-
separated list, default empty). When the env var is **empty**, the detector
fails open and prints a single stderr warning so operators notice they shipped
without an allowlist. Each `(session, host)` pair fires **once** per session.

```
allowlist = MCP_PLUGIN_ALLOWED_HOSTS (default empty → warn + fail-open)
walk(input_schema) → collected_urls
for url in collected_urls:
    host = urlparse(url).hostname
    if host and host not in allowlist:
        emit finding once per (session, host)
```

Use when the user mentions LLM05, plugin supply chain, untrusted schema, or
remote `$ref` resolution. Do NOT use as a content-security policy enforcer.

## Output contract

One OCSF 1.8 Detection Finding (class 2004) per disallowed `(session, host)`
pair. With `--output-format native` the skill emits the repo-owned native
projection.

OCSF output populates:

- `finding_info.types[] = ["mcp-plugin-supply-chain", "llm-supply-chain"]`
- `finding_info.attacks[]` — MITRE ATT&CK `T1195.001` Compromise Software
  Supply Chain (the tool's declaration is the software the agent ingests).
- deterministic `finding_info.uid`.
- `observables[]` — session uid, tool name, host, source field (`$ref` /
  `default` / `description`).

## Usage

```bash
MCP_PLUGIN_ALLOWED_HOSTS="schema.openai.com,registry.modelcontextprotocol.io" \
  python ../ingest-mcp-proxy-ocsf/src/ingest.py mcp-proxy.jsonl \
  | python src/detect.py \
  > plugin-supply-chain-findings.ocsf.jsonl
```
