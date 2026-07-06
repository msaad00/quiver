---
name: detect-gcp-service-account-key-creation
description: >-
  Detect successful GCP IAM `CreateServiceAccountKey` API calls against service
  accounts from OCSF 1.8 API Activity records emitted by
  ingest-gcp-audit-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004)
  tagged with MITRE ATT&CK T1098.001 (Additional Cloud Credentials) when a
  principal creates a user-managed key for a service account. Use when the
  user mentions "GCP service account key created", "additional cloud
  credentials in GCP", or "T1098.001 via Cloud Audit Logs". Do NOT use for
  posture-at-rest key inventory, workload-identity federation coverage, or
  generic IAM policy changes. This first slice only covers successful
  `CreateServiceAccountKey` operations.
purpose: Detect successful GCP IAM `CreateServiceAccountKey` API calls against service accounts from OCSF 1.8 API Activity records emitted by ingest-gcp-audit-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-gcp-service-account-key-creation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: gcp
  capability: read-only
---

# detect-gcp-service-account-key-creation

Streaming detector for new GCP service-account keys created through Cloud Audit
Logs. This is the first honest shipped GCP service-account key persistence
slice after the broader service-account and IAM Credentials anchors already
tracked in `detect-lateral-movement`.

## Use when

- You stream Cloud Audit Logs through `ingest-gcp-audit-ocsf` and want near-real-time findings on new service-account keys
- You want a narrow, high-confidence GCP persistence detector for additional cloud credentials
- You are closing the first GCP service-account key gap under the ATT&CK roadmap without over-claiming workload-identity federation or token-minting coverage

## Do NOT use

- As a posture-at-rest service-account key inventory or age check; use [`cspm-gcp-cis-benchmark`](../../evaluation/cspm-gcp-cis-benchmark/)
- To infer workload-identity federation abuse or IAM Credentials token generation; those are separate follow-on detections
- To claim every GCP service-account pivot path; this first slice is only `CreateServiceAccountKey`

## Rule

A finding fires on every successful Cloud Audit event from
`ingest-gcp-audit-ocsf` where:

1. `api.service.name` is `iam.googleapis.com`
2. `api.operation` is `google.iam.admin.v1.CreateServiceAccountKey`
3. `status_id == 1`
4. `resources[]` resolve a target service-account resource

When upstream `ingest-gcp-audit-ocsf` receives a sanitized
`protoPayload.response.name` for the created key, the detector also emits the
exact `target_key_resource` and `target_key_id` as evidence. It does not retain
private key material.

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0003` (Persistence)
- `finding_info.attacks[].technique_uid = T1098` (Account Manipulation)
- `finding_info.attacks[].sub_technique_uid = T1098.001` (Additional Cloud Credentials)
- `observables[]` including `target.name`, `project.uid`, `actor.name`, and `api.operation`
- `evidence.target_key_resource` / `evidence.target_key_id` when the upstream audit event includes the created key resource name

The native projection (`--output-format native`) keeps the target service
account, created key resource, and actor/project context in a flatter shape.

## Run

```bash
# Cloud Audit Logs -> ingest -> detect (default OCSF output)
python skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-gcp-service-account-key-creation/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-gcp-service-account-key-creation/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-gcp-audit-ocsf`](../../ingestion/ingest-gcp-audit-ocsf/) — upstream ingester
- [`detect-lateral-movement`](../detect-lateral-movement/) — broader GCP service-account pivot anchors
- [`cspm-gcp-cis-benchmark`](../../evaluation/cspm-gcp-cis-benchmark/) — posture-at-rest GCP service-account key hygiene
