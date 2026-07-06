---
name: detect-web-injection
description: >-
  Detect OWASP Top 10 A03:2021 (Injection) signals in HTTP access logs.
  Reads OCSF 1.8 HTTP Activity (class 4002) records and fires when the
  request URL query string OR request body matches one of a curated set
  of deterministic SQL / shell-command / LDAP / NoSQL / XPath /
  template injection signatures (UNION SELECT, OR 1=1, ;rm -rf,
  $(whoami), `;ls`, `(|(uid=*`, `{{ 7*7 }}`, `$ne` operator, etc.).
  Emits OCSF Detection Finding 2004 tagged OWASP A03 + MITRE ATT&CK
  T1190 (Exploit Public-Facing Application). Use when an upstream
  ingester normalizes web / WAF / API-gateway logs into OCSF 4002 and
  you want a low-false-positive lexical injection detector. Do NOT use
  as a WAF (no in-line blocking), as a SAST / DAST tool, on the WAF's
  own logs (results would be self-referential — the WAF already
  blocked them), as a substitute for parameterised queries / proper
  input validation in the application, or for large-scale ML-based
  payload classification.
purpose: "Detect OWASP Top 10 A03:2021 (Injection) signals in HTTP access logs."
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. Read-only — consumes OCSF 1.8 HTTP Activity
  records from stdin / file, emits OCSF 1.8 Detection Finding 2004 to
  stdout. No outbound network calls.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-web-injection
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud: multi
  capability: read-only
---

# detect-web-injection

Streaming detector for OWASP Top 10 A03:2021 — Injection — across
SQL, command, LDAP, NoSQL, XPath, and template variants in OCSF 1.8
HTTP Activity (class 4002) request lines and bodies.

Closes the A03 row in the repo's OWASP Top 10 coverage matrix
(gap-roadmap issue #431).

## Use when

- Your pipeline normalises web / API access logs into OCSF 4002 with
  the request query string and (when available) request body
  populated.
- You want a deterministic regex-anchored detector with a curated
  payload library — no ML, no LLM.
- You want findings tagged with the matched injection family
  (`sql`, `command`, `ldap`, `nosql`, `xpath`, `template`).

## Do NOT use

- As a WAF — this fires after the request was processed.
- On the WAF's own action logs (results would be self-referential).
- As a replacement for SAST / DAST or parameterised queries in the
  app.
- For ML-based payload classification at scale (use a dedicated WAF
  or a security-research skill).

## Rule

A finding fires when **any** of the following surfaces matches **any**
of the configured injection signatures:

- `http_request.url.query_string`
- `http_request.url.path` (path-segment injection)
- `http_request.body` (when the upstream ingester populates it; we
  also accept the OCSF unmapped form `unmapped.body`)
- `http_request.headers[name in {Referer, User-Agent, X-Forwarded-For}].value`

The signature catalogue (in `src/detect.py:INJECTION_PATTERNS`) is
deliberately small and high-precision: each pattern was extracted from
public OWASP cheat sheets / PortSwigger / CVE write-ups and chosen
for low FP. Operators can extend the list at call time via
`detect(..., extra_patterns=[(family, regex), ...])`.

The technique mapping is **T1190 (Exploit Public-Facing
Application)** under tactic **TA0001 (Initial Access)**.

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH
(`severity_id=4`), with:

- `finding_info.attacks[].technique_uid = T1190`
- `observables[]` includes `actor.user.uid`, `src.ip`,
  `http_request.url.path`, `http_request.http_method`, the matched
  `injection.family` and `injection.signature_label`, and a
  redacted-snippet `injection.payload_excerpt` (60 chars max, no full
  body).

The native projection (`--output-format native`) carries the matched
surface (query / path / body / header) and the matched signature for
forensic context.

## Run

```bash
cat web-activity.ocsf.jsonl \
  | python skills/detection/detect-web-injection/src/detect.py \
  > findings.ocsf.jsonl
```

## See also

- [`detect-web-broken-access-control`](../detect-web-broken-access-control/) — A01:2021 sibling
- [`detect-web-auth-failures`](../detect-web-auth-failures/) — A07:2021 sibling
- [`detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)
