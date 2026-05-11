---
name: detect-entra-credential-addition
description: >-
  Detect successful Microsoft Entra application or service-principal credential
  additions from OCSF 1.8 API Activity (6003) events or the native API
  activity projection produced by ingest-entra-directory-audit-ocsf. The first
  slice stays intentionally narrow: it fires on successful Entra
  service-principal credential adds, application certificate-secret management,
  and federated identity credential creation, then emits OCSF 1.8 Detection
  Finding (class 2004) with MITRE ATT&CK T1098.001 Additional Cloud
  Credentials. Use when the user mentions Entra app secrets, service-principal
  credential additions, federated identity credentials, or workload-identity
  persistence. Do NOT use on raw Graph directoryAudit payloads — normalize them
  through ingest-entra-directory-audit-ocsf first. Do NOT use as a generic
  Entra app-role escalation or administrative drift detector.
purpose: Detect successful Microsoft Entra application or service-principal credential additions from OCSF 1.8 API Activity (6003) events or the native API activity projection produced by ingest-entra-directory-audit-ocsf. The...
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
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-entra-credential-addition
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud:
    - azure
    - entra
    - microsoft-graph
---

# detect-entra-credential-addition

## Attack pattern

This detector covers one narrow Entra persistence slice:

- `Add service principal credentials`
- `Update application - Certificates and secrets management`
- `Create federated identity credential`
- `Add federated identity credential`

All of these actions create or rotate credential material or trust paths for an
application or service principal. In ATT&CK terms, that maps cleanly to
`T1098.001` Additional Cloud Credentials.

This first slice intentionally does **not** cover:

- app-role grants
- directory role assignments
- Conditional Access changes
- every Entra administrative mutation

Those remain separate follow-up detections so this rule stays precise.

## Detection logic

One pass over Entra identity-management events from
`ingest-entra-directory-audit-ocsf`, whether they arrive as OCSF API Activity
records or the native API-activity projection:

1. Keep only events emitted by `ingest-entra-directory-audit-ocsf`
2. Require a successful Entra credential or federated-credential operation
3. Deduplicate by the original Entra event UID
4. Emit one finding per matching event

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[]`:
  - `entra-credential-addition`
  - or `entra-federated-credential-addition`
- `finding_info.attacks[]` populated with MITRE ATT&CK:
  - `T1098` Account Manipulation
  - `T1098.001` Additional Cloud Credentials
- `evidence.raw_event_uids[]`
- `observables[]` carrying the actor, target, operation, and correlation UID

## Usage

```bash
python ../ingest-entra-directory-audit-ocsf/src/ingest.py entra-directory-audit.json \
  | python src/detect.py \
  > entra-credential-findings.ocsf.jsonl

python ../ingest-entra-directory-audit-ocsf/src/ingest.py entra-directory-audit.json --output-format native \
  | python src/detect.py --output-format native \
  > entra-credential-findings.native.jsonl
```

## Do NOT use

- On raw Graph `directoryAudit` JSON before normalization
- As a generic Entra role-assignment or app-role escalation detector
- For Okta, Google Workspace, CloudTrail, or Azure Activity logs
- To infer every possible Entra persistence path from a single event family

## Tests

The test suite covers:

- OCSF and native input paths
- duplicate event suppression by Entra event UID
- failed federated credential creation being skipped
- golden fixture parity for the shipped sample

## Native output format

When `--output-format native` is selected, the skill emits:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "detection_finding"`
- `finding_uid` and `event_uid`
- `provider`
- `time_ms`
- `actor_name`
- `target_name` / `target_uid`
- `mitre_attacks`
- `evidence`
