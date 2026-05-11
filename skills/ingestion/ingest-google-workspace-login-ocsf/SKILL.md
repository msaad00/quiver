---
name: ingest-google-workspace-login-ocsf
description: >-
  Convert verified Google Workspace Admin SDK Reports API login audit events
  into OCSF 1.8 Identity & Access Management events. The first slice maps
  Google Workspace login success, login failure, logout, and 2-step
  verification enrollment-change events into Authentication (3002) and Account
  Change (3001) while preserving natural IDs such as id.time,
  id.uniqueQualifier, actor.profileId, and event parameters for SIEM-friendly
  dedupe and downstream correlation. Use when the user mentions Google
  Workspace login audit ingestion, Admin SDK Reports normalization, or feeding
  Workspace identity telemetry into an OCSF pipeline. Do NOT use for raw Google
  Cloud Audit Logs, Okta System Log, or as a detector or policy engine — this
  skill only normalizes verified Workspace login audit payloads.
purpose: Convert verified Google Workspace Admin SDK Reports API login audit events into OCSF 1.8 Identity & Access Management events. The first slice maps Google Workspace login success, login failure, logout, and 2-step veri...
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
  Requires Python 3.11+. No Google SDK required when Admin SDK Reports payloads
  are already exported. Read-only — validates raw Workspace audit shape and
  emits OCSF or native JSONL. Never calls write APIs.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/ingestion/ingest-google-workspace-login-ocsf
  version: 0.1.0
  frameworks:
    - OCSF 1.8
  cloud: google-workspace
  capability: read-only
---

# ingest-google-workspace-login-ocsf

Convert verified Google Workspace Admin SDK Reports login audit payloads into
OCSF 1.8 IAM records by default, or the repo-owned native IAM projection when
`--output-format native` is selected.

## Use when

- You have Admin SDK Reports `activities.list` exports for `applicationName=login` and need OCSF output
- You want to normalize Google Workspace login and 2-step-verification telemetry for SIEM, lake, MCP, or downstream detection use
- You need a portable identity event stream that preserves Workspace `id.time`, `id.uniqueQualifier`, actor IDs, and raw login parameters
- You want Workspace identity events represented as OCSF before feeding them into cross-vendor detections or evidence flows

## Do NOT use

- On Google Cloud Audit Logs, Cloud Identity logs, or raw Entra / Okta payloads
- To collect live Workspace audit data by itself — upstream collection and auth stay outside this skill
- To infer ATT&CK techniques or create findings directly
- To mutate Workspace users, sessions, or 2-step settings

## Input + output contract

Accepts three raw Admin SDK Reports shapes (activities list, single activity, JSONL stream) and supports a narrow, verified event family: `login_success`, `login_failure`, `logout`, `2sv_enroll`, `2sv_disable`. Unsupported event names are skipped with a warning to `stderr`.

Emits OCSF 1.8 JSONL with verified class mappings: **Authentication (3002)** for login/logout events, **Account Change (3001)** for 2sv enroll/disable. Records carry deterministic `metadata.uid`, epoch-ms `time`, actor + session IDs, and raw `parameters[]` preserved under `unmapped.google_workspace_login`.

Full input shapes, the supported event-family table, and the output guarantees live in [`references/event-types.md`](references/event-types.md) — kept out of `SKILL.md` per progressive disclosure ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)).

## Usage

```bash
# activities.list export, OCSF default
python src/ingest.py workspace-login.json > workspace-login.ocsf.jsonl

# JSONL stream from stdin
cat workspace-login.jsonl | python src/ingest.py > workspace-login.ocsf.jsonl

# Native projection
python src/ingest.py workspace-login.json --output-format native > workspace-login.native.jsonl

# explicit output file
python src/ingest.py workspace-login.json --output workspace-login.ocsf.jsonl
```

## Native output format

When `--output-format native` is selected, the skill emits the canonical
projection with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "authentication"` or `"account_change"`
- `event_uid`
- `provider`
- `time_ms`
- `event_name`
- `parameters`
- preserved `actor`, `user`, `src_endpoint`, and `session` blocks

## Security guardrails

- Read-only only. No Google Workspace writes. No subprocesses.
- Keeps Workspace natural IDs for dedupe and correlation instead of inventing random IDs.
- Uses verified raw fields from official Google Workspace docs only; unsupported event names are skipped rather than guessed.
- Normalizes into OCSF only where the class fit is explicit. Unmapped vendor-specific detail stays under `unmapped`.

## See also

- [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) — shared OCSF wire contract and version pinning
- [`../ingest-gcp-audit-ocsf/SKILL.md`](../ingest-gcp-audit-ocsf/SKILL.md) — Google Cloud API audit equivalent
- [`../ingest-okta-system-log-ocsf/SKILL.md`](../ingest-okta-system-log-ocsf/SKILL.md) — external identity-vendor ingestion peer
