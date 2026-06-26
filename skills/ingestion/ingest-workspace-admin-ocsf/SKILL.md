---
name: ingest-workspace-admin-ocsf
description: >-
  Convert verified Google Workspace Admin SDK Reports API activities into OCSF
  1.8 Identity & Access Management events. Login activities route to
  Authentication (3002); OAuth token authorize/request/deny/revoke events and
  admin role-assignment events route to Account Change (3001). Preserves
  Workspace-native fields such as id.time, id.uniqueQualifier, applicationName,
  actor, ownerDomain, token client_id, scope, app_name, and admin role
  parameters under `unmapped.google_workspace_admin.*` for downstream
  detection. Use when the user has Admin Reports API exports for login, token,
  or admin applications and needs OCSF or native JSONL. Do NOT use as a live
  collector, on Gmail/Drive content logs, or as a detector.
purpose: Convert Google Workspace Admin SDK Reports API login, token, and admin activities into OCSF Authentication and Account Change events.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No Google SDK required when Admin SDK Reports API
  payloads are already exported. Read-only normalizer; never calls Google APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-workspace-admin-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: google-workspace
  capability: read-only
---

# ingest-workspace-admin-ocsf

Normalize Google Workspace Admin SDK Reports API exports into OCSF 1.8 IAM
events with deterministic IDs and preserved vendor evidence.

## Use when

- You have `activities.list` exports for `applicationName=login`, `token`, or `admin`
- You need Workspace login, OAuth token, and admin-role events in one OCSF stream
- You want to feed Workspace OAuth or admin-role detectors without re-querying Google APIs
- You need native JSONL for a pipeline that is not OCSF-aware yet

## Do NOT use

- As a live collector; OAuth and Admin SDK API collection stay upstream
- On Gmail, Drive, Calendar, or document-content audit streams
- To infer ATT&CK findings directly
- To revoke OAuth tokens, roles, sessions, or any Workspace state

## Input contract

Accepts one of these raw Admin SDK Reports API shapes:

1. A response object with `items[]`
2. A single activity object
3. A JSON array of activity objects
4. JSONL, one activity or response object per line

Supported application/event families:

- `login`: `login_success`, `login_failure`, `logout`, `2sv_enroll`, `2sv_disable`
- `token`: `authorize`, `request`, `deny`, `revoke`
- `admin`: role-assignment events such as `ASSIGN_ROLE`, `CREATE_ROLE_ASSIGNMENT`, or events carrying `role_name` / `role_id` plus an assignee

Unsupported events are skipped with `stderr_jsonl` warnings rather than guessed.

## Output contract

Default output is OCSF 1.8 JSONL:

- **Authentication (3002)** for login and logout events
- **Account Change (3001)** for MFA changes, OAuth grants/revocations, and admin role assignments

Every event includes:

- deterministic `metadata.uid`
- epoch-ms `time`
- `actor`, `user`, `src_endpoint`, `session`, and `resources` where present
- raw Workspace parameters under `unmapped.google_workspace_admin.parameters`

With `--output-format native`, the skill emits the repo-owned canonical
projection with `schema_mode: "native"`.

## Usage

```bash
python src/ingest.py workspace-admin-reports.json > workspace-admin.ocsf.jsonl
python src/ingest.py workspace-admin-reports.json --output-format native > workspace-admin.native.jsonl
```

## Security guardrails

- Read-only only. No Google API calls and no token handling.
- Preserves native identifiers for audit correlation.
- Keeps unsupported event names visible in stderr so coverage gaps are measurable.

## Delivery note

Delivered as part of Google Workspace vendor story issue #32.
