---
name: detect-gcp-service-account-token-minting
description: >-
  Detect successful GCP IAM Credentials API token minting for service accounts
  from OCSF 1.8 API Activity records emitted by ingest-gcp-audit-ocsf. Emits
  an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK
  T1098.001 when a principal successfully calls GenerateAccessToken or
  GenerateIdToken for a service account. Use when the user mentions GCP
  service-account token minting, IAM Credentials API abuse, GenerateAccessToken,
  GenerateIdToken, or short-lived service-account impersonation tokens. Do NOT
  use for service-account key creation, workload-identity federation
  configuration, or generic IAM policy changes.
purpose: Detect successful GCP IAM Credentials API token minting for service accounts from OCSF 1.8 API Activity records emitted by ingest-gcp-audit-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&...
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
  Requires Python 3.11+. Read-only — consumes OCSF 1.8 API Activity records
  from stdin/file and emits OCSF 1.8 Detection Finding 2004 to stdout. No GCP
  SDK; pairs with ingest-gcp-audit-ocsf upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-gcp-service-account-token-minting
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: gcp
  capability: read-only
---

# detect-gcp-service-account-token-minting

Streaming detector for GCP service-account token minting through Cloud Audit
Logs. This complements `detect-gcp-service-account-key-creation`: key creation
finds long-lived credential material, while this detector finds short-lived
impersonation tokens minted through the IAM Credentials API.

## Use when

- You stream Cloud Audit Logs through `ingest-gcp-audit-ocsf`
- You want a high-confidence finding for service-account impersonation token minting
- You need coverage for `GenerateAccessToken` and `GenerateIdToken` events

## Do NOT use

- To detect user-managed service-account key creation; use
  [`detect-gcp-service-account-key-creation`](../detect-gcp-service-account-key-creation/)
- To infer workload-identity federation configuration changes
- To claim all GCP service-account abuse paths; this slice covers only
  successful IAM Credentials token generation

## Rule

A finding fires on every successful Cloud Audit event from
`ingest-gcp-audit-ocsf` where:

1. `api.service.name` is `iamcredentials.googleapis.com`
2. `api.operation` is one of:
   - `google.iam.credentials.v1.GenerateAccessToken`
   - `google.iam.credentials.v1.GenerateIdToken`
3. `status_id == 1`
4. `resources[]` resolve a target service-account resource

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0003` (Persistence)
- `finding_info.attacks[].technique_uid = T1098` (Account Manipulation)
- `finding_info.attacks[].sub_technique_uid = T1098.001` (Additional Cloud Credentials)
- `observables[]` including `target.name`, `project.uid`, `actor.name`, and `api.operation`

The native projection (`--output-format native`) keeps the target service
account and actor/project context in a flatter shape.

## Run

```bash
python skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-gcp-service-account-token-minting/src/detect.py \
  > findings.ocsf.jsonl

python skills/detection/detect-gcp-service-account-token-minting/src/detect.py findings-input.jsonl --output-format native
```

