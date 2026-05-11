---
name: detect-aws-access-key-creation
description: >-
  Detect successful AWS IAM `CreateAccessKey` API calls against IAM users from
  OCSF 1.8 API Activity records emitted by ingest-cloudtrail-ocsf. Emits an
  OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1098.001
  (Additional Cloud Credentials) when a principal creates an access key for an
  IAM user. Use when the user mentions "AWS access key created", "IAM user key
  issuance", "additional cloud credentials in AWS", or "T1098.001 via
  CloudTrail". Do NOT use as a posture-at-rest access-key inventory check, to
  infer console-password or login-profile creation, or to claim every AWS
  identity-pivot path. This first slice only covers successful
  `CreateAccessKey` operations.
purpose: Detect successful AWS IAM `CreateAccessKey` API calls against IAM users from OCSF 1.8 API Activity records emitted by ingest-cloudtrail-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T...
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
  from stdin/file and emits OCSF 1.8 Detection Finding 2004 to stdout. No AWS
  SDK; pairs with ingest-cloudtrail-ocsf upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-aws-access-key-creation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: aws
  capability: read-only
---

# detect-aws-access-key-creation

Streaming detector for new AWS IAM user access keys created through CloudTrail.
This is the first honest shipped AWS IAM-user persistence slice after the
role-session-centric depth in `detect-lateral-movement`.

## Use when

- You stream CloudTrail through `ingest-cloudtrail-ocsf` and want near-real-time findings on new IAM user access keys
- You want a narrow, high-confidence AWS persistence detector for additional cloud credentials
- You are closing the first AWS IAM-user / access-key gap under the ATT&CK roadmap without over-claiming login-profile or temporary-credential coverage

## Do NOT use

- As a posture-at-rest access-key inventory or age check; use [`cspm-aws-cis-benchmark`](../../evaluation/cspm-aws-cis-benchmark/)
- To infer console-password creation or login-profile changes; that is a separate follow-on detector
- To claim every AWS temporary-credential or IAM-user pivot path; this first slice is only `CreateAccessKey`

## Rule

A finding fires on every successful CloudTrail event from `ingest-cloudtrail-ocsf` where:

1. `api.operation` is `CreateAccessKey`
2. `status_id == 1`
3. request parameters resolve a target IAM username

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0003` (Persistence)
- `finding_info.attacks[].technique_uid = T1098` (Account Manipulation)
- `finding_info.attacks[].sub_technique_uid = T1098.001` (Additional Cloud Credentials)
- `observables[]` including `target.name`, `account.uid`, `region`, `actor.name`, and `api.operation`

The native projection (`--output-format native`) keeps the target IAM user and
actor/account context in a flatter shape.

## Run

```bash
# CloudTrail -> ingest -> detect (default OCSF output)
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-aws-access-key-creation/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-aws-access-key-creation/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-cloudtrail-ocsf`](../../ingestion/ingest-cloudtrail-ocsf/) — upstream ingester
- [`detect-lateral-movement`](../detect-lateral-movement/) — AWS role-session pivot coverage
- [`cspm-aws-cis-benchmark`](../../evaluation/cspm-aws-cis-benchmark/) — posture-at-rest AWS credential hygiene
