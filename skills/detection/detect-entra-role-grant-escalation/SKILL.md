---
name: detect-entra-role-grant-escalation
description: >-
  Detect successful Microsoft Entra app-role grants to service principals from
  OCSF 1.8 API Activity (6003) events or the native API activity projection
  produced by ingest-entra-directory-audit-ocsf. This slice stays intentionally
  narrow: it fires on successful `Add app role assignment to service principal`
  events and emits OCSF 1.8 Detection Finding (class 2004) with MITRE ATT&CK
  T1098.003 Additional Cloud Roles. Use when the user mentions Entra app-role
  assignments, application-permission grants, service-principal privilege
  escalation, or Microsoft Graph app-role assignment drift. Do NOT use on raw
  Graph directoryAudit payloads — normalize them through
  ingest-entra-directory-audit-ocsf first. Do NOT use as a generic Entra
  credential-addition, Conditional Access, or directory-role-assignment
  detector.
purpose: Detect successful Microsoft Entra app-role grants to service principals from OCSF 1.8 API Activity (6003) events or the native API activity projection produced by ingest-entra-directory-audit-ocsf. This slice stays in...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-entra-role-grant-escalation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud:
    - azure
    - entra
    - microsoft-graph
---

# detect-entra-role-grant-escalation

## Attack pattern

This detector covers one narrow Entra privilege-escalation slice:

- `Add app role assignment to service principal`

That event family represents granting an application permission / app role to a
service principal. In ATT&CK terms, that maps cleanly to `T1098.003`
Additional Cloud Roles.

This slice intentionally does **not** cover:

- service-principal credential additions
- federated identity credentials
- directory role assignments
- Conditional Access changes
- every Entra administrative mutation

Those remain separate follow-up detections so this rule stays precise.

## Detection logic

One pass over Entra identity-management events from
`ingest-entra-directory-audit-ocsf`, whether they arrive as OCSF API Activity
records or the native API-activity projection:

1. Keep only events emitted by `ingest-entra-directory-audit-ocsf`
2. Require a successful Entra app-role assignment to a service principal
3. Deduplicate by the original Entra event UID
4. Emit one finding per matching event

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["entra-role-grant-escalation"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK:
  - `T1098` Account Manipulation
  - `T1098.003` Additional Cloud Roles
- `evidence.raw_event_uids[]`
- `observables[]` carrying the actor, target, operation, and correlation UID

## Usage

```bash
python ../ingest-entra-directory-audit-ocsf/src/ingest.py entra-directory-audit.json \
  | python src/detect.py \
  > entra-role-grant-findings.ocsf.jsonl

python ../ingest-entra-directory-audit-ocsf/src/ingest.py entra-directory-audit.json --output-format native \
  | python src/detect.py --output-format native \
  > entra-role-grant-findings.native.jsonl
```

## Do NOT use

- On raw Graph `directoryAudit` JSON before normalization
- As a generic Entra credential-addition detector
- For directory-role or subscription-role assignments from Azure Activity
- For Okta, Google Workspace, CloudTrail, or Azure Activity logs

## Tests

The test suite covers:

- OCSF and native input paths
- duplicate event suppression by Entra event UID
- failed app-role assignments being skipped
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
