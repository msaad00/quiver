---
name: detect-web-broken-access-control
description: >-
  Detect OWASP Top 10 A01:2021 (Broken Access Control) signals in HTTP
  access logs. Reads OCSF 1.8 HTTP Activity (class 4002) records and
  fires when one of two deterministic patterns appears: (1) the
  resource path embeds a user / account / object id that does not match
  the actor's authenticated subject claim (IDOR — horizontal privilege
  escalation), or (2) a 4XX response from one principal is followed
  inside a short window by a 2XX response on the exact same URL after
  an Authorization header swap (the "auth-swap flip" — typical
  privilege bypass via stolen / forged token). Emits OCSF Detection
  Finding 2004 tagged OWASP A01 + MITRE ATT&CK T1212. Use when an
  ingestion pipeline normalizes web-server / WAF / API-gateway logs
  into OCSF 4002 and you want a deterministic, no-LLM authz-violation
  detector. Do NOT use as a WAF, as a posture check on IAM policies
  (different surface — see CSPM benchmarks), for service-mesh L7
  authorisation (Envoy / Istio emit a different log shape), or as a
  substitute for application-layer authorization tests in CI.
purpose: "Detect OWASP Top 10 A01:2021 (Broken Access Control) signals in HTTP access logs."
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-web-broken-access-control
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud: multi
  capability: read-only
---

# detect-web-broken-access-control

Streaming detector for OWASP Top 10 A01:2021 — Broken Access Control —
across web server, API gateway, and reverse-proxy access logs that
have been normalised into OCSF 1.8 HTTP Activity (class 4002).

Closes the A01 row in the repo's OWASP Top 10 coverage matrix
(gap-roadmap issue #431).

## Use when

- Your pipeline produces OCSF 4002 records with `actor.user.uid`
  populated from a verified token claim (JWT `sub`, session principal)
  and `http_request.url.path` populated from the request line.
- You want to flag IDOR-class horizontal privilege escalation
  (`/users/42/...` accessed by user `7`) without writing per-route
  authz tests.
- You want to flag the "auth-swap flip" pattern (a 403 on a path,
  followed by a 200 on the same path from the same source IP under a
  different `Authorization` header within a short window) — a common
  signature of stolen-token replay.

## Do NOT use

- As a WAF — this detects after-the-fact, not in-line.
- For service-mesh L7 authz (Envoy / Istio access logs use a
  different OCSF mapping; pair with the matching ingester).
- As a substitute for unit / integration tests of route-level
  authorization.
- For cloud IAM posture (use the CSPM benchmarks).

## Rule

A finding fires when **either** condition is met:

1. **IDOR** — `http_request.url.path` matches one of the configured
   id-bearing patterns (default: `/users/<id>/...`,
   `/accounts/<id>/...`, `/orgs/<id>/...`, `/tenants/<id>/...`,
   `/customers/<id>/...`) AND the captured `<id>` does NOT equal the
   actor's `user.uid` (or any value in `user.groups[]` for
   group-scoped resources).

2. **Auth-swap flip** — within a configurable window (default 60s) on
   the same `(src_endpoint.ip, http_request.url.path)`, a 4XX
   (`status_code` 401 / 403) is followed by a 2XX
   (`status_code` 200 / 201 / 204) AND the
   `http_request.headers[name=Authorization]` value differs between
   the two records (compared as a redacted hash).

Both patterns map to MITRE ATT&CK **T1212 (Exploitation for
Credential Access)** when the principal is unauthenticated, and to
**T1078 (Valid Accounts)** when the principal is a different
authenticated user. The detector emits T1212 by default.

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH
(`severity_id=4`), with:

- `finding_info.attacks[].technique_uid = T1212`
- `observables[]` includes `actor.user.uid`, `target.uid` (the
  resource id from the path or the path itself for the auth-swap
  variant), `src.ip`, `http_request.url.path`,
  `http_request.http_method`, `http_response.status_code`, and
  the `rule` discriminator (`idor` or `auth-swap-flip`).

The native projection (`--output-format native`) carries the raw HTTP
record pair for forensic context.

## Run

```bash
# Web access logs → ingest → detect (default OCSF output)
cat web-activity.ocsf.jsonl \
  | python skills/detection/detect-web-broken-access-control/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-web-broken-access-control/src/detect.py \
    web-activity.ocsf.jsonl --output-format native
```

## See also

- [`detect-web-injection`](../detect-web-injection/) — A03:2021 sibling
- [`detect-web-auth-failures`](../detect-web-auth-failures/) — A07:2021 sibling
- [`detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)
