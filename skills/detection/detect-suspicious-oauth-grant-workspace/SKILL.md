---
name: detect-suspicious-oauth-grant-workspace
description: >-
  Detect Google Workspace OAuth token `authorize` events where a user grants a
  non-preapproved OAuth client high-risk scopes such as Gmail, Drive, Admin
  Directory, audit, Groups, Calendar, Contacts, or Cloud Platform access.
  Reads OCSF 1.8 Account Change (3001) or native events emitted by
  `ingest-workspace-admin-ocsf` with `application_name=token`, and emits OCSF
  Detection Finding (2004) tagged with MITRE ATT&CK T1550.001. Use when the
  user mentions Google Workspace OAuth grants, third-party app consent, risky
  Google scopes, or SaaS token persistence. Do NOT use on raw Admin SDK
  payloads before normalization, on non-Workspace token events, or as a
  remediation skill.
purpose: Detect non-preapproved Google Workspace OAuth clients granted high-risk scopes.
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
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-suspicious-oauth-grant-workspace
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - google-workspace
---

# detect-suspicious-oauth-grant-workspace

## Use when

- You normalized Google Workspace OAuth token audit events with `ingest-workspace-admin-ocsf`
- You need to surface third-party Google OAuth clients with risky scopes
- You want a stateless detector for Workspace SaaS token persistence

## Do NOT use

- On raw Admin SDK Reports API JSON before ingestion
- On OAuth events from Okta, Entra, Slack, or non-Google providers
- As remediation; token revocation belongs in a controlled write-capable skill

## Detection logic

One pass over OCSF Account Change events:

1. Require producer `ingest-workspace-admin-ocsf`.
2. Require `application_name=token` and `event_name=authorize`.
3. Require non-empty `client_id`.
4. Ignore clients in `WORKSPACE_PREAPPROVED_OAUTH_CLIENT_IDS`.
5. Fire when `scope` / `scope_data` contains high-risk markers for Gmail,
   Drive, Admin Directory, audit, Groups, Calendar, Contacts, or Cloud Platform.

## Output contract

Default output is OCSF Detection Finding (class `2004`) with:

- deterministic `metadata.uid`
- `finding_info.types[] = ["workspace-suspicious-oauth-grant", "OWASP-Top-10-A05"]`
- MITRE ATT&CK `T1550.001`
- `evidence.client_id`, `evidence.app_name`, and `evidence.scopes`

Severity is `HIGH`.

## Usage

```bash
export WORKSPACE_PREAPPROVED_OAUTH_CLIENT_IDS="trusted-client-1,trusted-client-2"
cat workspace-admin.ocsf.jsonl | python src/detect.py > workspace-oauth-findings.ocsf.jsonl
```

## Delivery note

Delivered as part of Google Workspace vendor story issue #32.
