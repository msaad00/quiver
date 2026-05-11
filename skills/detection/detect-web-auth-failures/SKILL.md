---
name: detect-web-auth-failures
description: >-
  Detect OWASP Top 10 A07:2021 (Identification and Authentication
  Failures) signals in HTTP access logs. Reads OCSF 1.8 HTTP Activity
  (class 4002) records and fires on (1) repeated authentication
  failures from a single source IP within a short window — the basic
  credential-stuffing / brute-force pattern — and (2) successful
  logins flagged as weak (no MFA challenge in the same session window
  on a sensitive endpoint, or password-grant authentication on an
  admin endpoint). Emits OCSF Detection Finding 2004 tagged OWASP A07
  + MITRE ATT&CK T1110 (Brute Force) and T1078 (Valid Accounts). Use
  when an upstream ingester normalises web / SSO / API-gateway logs
  into OCSF 4002. Do NOT use as a replacement for the dedicated SSO
  detectors (`detect-okta-mfa-fatigue`, `detect-credential-stuffing-okta`,
  `detect-google-workspace-suspicious-login`), as a SSO posture check,
  or as a replacement for IdP-level rate limiting.
purpose: "Detect OWASP Top 10 A07:2021 (Identification and Authentication Failures) signals in HTTP access logs."
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-web-auth-failures
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud: multi
  capability: read-only
---

# detect-web-auth-failures

Streaming detector for OWASP Top 10 A07:2021 — Identification and
Authentication Failures — across web / API / SSO access logs in OCSF
1.8 HTTP Activity (class 4002) shape.

Closes the A07 row in the repo's OWASP Top 10 coverage matrix
(gap-roadmap issue #431).

## Use when

- Your pipeline normalises login / token-exchange / refresh-token
  endpoints into OCSF 4002 records with `http_response.status_code`
  populated and `http_request.url.path` carrying a recognisable
  login surface (`/login`, `/auth/...`, `/oauth/token`,
  `/api/login`, etc.).
- You want a deterministic burst-and-flip detector — N failures in a
  window followed (or unfollowed) by a success — to mimic the SSO
  detectors (`detect-credential-stuffing-okta`,
  `detect-okta-mfa-fatigue`) at the HTTP layer for any login
  endpoint your IdP doesn't already cover.
- You want a "weak login" flag for password-grant on a sensitive
  endpoint, or for sessions that complete without an MFA challenge
  within the same source-ip window.

## Do NOT use

- As a replacement for the dedicated Okta / Workspace / Entra
  detectors — those see structured event types your access log does
  not carry.
- As a SSO posture check.
- As a replacement for IdP-level rate limiting / IP allowlisting /
  CAPTCHAs.
- For agent-side credential leaks (use `detect-agent-credential-leak-mcp`).

## Rule

A finding fires when **any** of:

1. **Brute-force burst** — within a configurable window
   (default 60s), the same `src_endpoint.ip` produces ≥ N failed
   login attempts (`status_code` ∈ {401, 403, 429}) on
   path-matched login endpoints (default match: `/login`,
   `/auth`, `/oauth`, `/api/login`, `/api/auth`,
   `/signin`).
2. **Stuffing flip** — N failures from one IP followed inside the
   window by a 2XX success on the same login endpoint (mirrors the
   Okta detector's pattern at HTTP-layer).
3. **Weak login** — a 2XX response on `/oauth/token` carrying
   `grant_type=password` in the request body OR a 2XX login
   without an associated MFA-challenge response in the window
   from the same IP.

The first two map to **T1110 (Brute Force)**. The third maps to
**T1078 (Valid Accounts)**.

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH
(`severity_id=4`), with:

- `finding_info.attacks[].technique_uid` set to `T1110` for
  brute-force / stuffing variants and `T1078` for the weak-login
  variant.
- `observables[]` includes `actor.user.uid` (when present),
  `src.ip`, `http_request.url.path`, the matched `rule`
  (`brute-force-burst` / `stuffing-flip` / `weak-login`), and the
  per-rule counters (window start/end, failure count, unique users
  attempted).

## Run

```bash
cat web-activity.ocsf.jsonl \
  | python skills/detection/detect-web-auth-failures/src/detect.py \
  > findings.ocsf.jsonl
```

## See also

- [`detect-web-broken-access-control`](../detect-web-broken-access-control/) — A01:2021 sibling
- [`detect-web-injection`](../detect-web-injection/) — A03:2021 sibling
- [`detect-credential-stuffing-okta`](../detect-credential-stuffing-okta/) — Okta-specific equivalent
- [`detect-okta-mfa-fatigue`](../detect-okta-mfa-fatigue/) — MFA-fatigue equivalent
- [`detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)
