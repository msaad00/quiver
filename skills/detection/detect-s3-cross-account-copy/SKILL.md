---
name: detect-s3-cross-account-copy
description: >-
  Detect successful AWS S3 cross-account object copies from OCSF 1.8 API
  Activity records emitted by ingest-cloudtrail-ocsf. Emits an OCSF 1.8
  Detection Finding (class 2004) tagged with MITRE ATT&CK T1537 (Transfer Data
  to Cloud Account) when a principal from one AWS account performs a successful
  S3 `CopyObject` into a bucket owned by another account. Use when the user
  mentions "S3 cross-account copy", "cross-account CopyObject", "AWS exfil to
  another cloud account", or "T1537 via CloudTrail". Do NOT use as a generic
  S3 object-write detector, to infer every exfiltration path, or to claim all
  cross-account storage movement is covered.
purpose: Detect successful AWS S3 cross-account object copies from OCSF 1.8 API Activity records emitted by ingest-cloudtrail-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1537 (Transfer Data...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-s3-cross-account-copy
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: aws
  capability: read-only
---

# detect-s3-cross-account-copy

Streaming detector for AWS S3 object copies into a different AWS account. This
is the first honest shipped AWS exfiltration-to-cloud-account slice under the
ATT&CK roadmap, and it stays intentionally narrow.

## Use when

- You stream CloudTrail through `ingest-cloudtrail-ocsf` and want near-real-time findings on suspicious cross-account S3 copies
- You want a deterministic, read-only AWS exfiltration detector aligned to ATT&CK `T1537`
- You need a narrow follow-on slice after the shipped AWS discovery and IAM-user persistence detectors

## Do NOT use

- As a generic S3 object-write detector for same-account operations
- To infer every exfiltration path; this slice only covers successful cross-account `CopyObject`
- To claim all cross-account storage movement is covered; multipart, replication, and non-S3 destinations remain separate follow-on work

## Rule

A finding fires on every successful CloudTrail event from `ingest-cloudtrail-ocsf` where:

1. `api.service.name` is `s3.amazonaws.com`
2. `api.operation` is `CopyObject`
3. `status_id == 1`
4. request parameters resolve `bucketName`, `key`, and `x-amz-copy-source`
5. the actor account differs from the recipient / bucket-owner account

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0010` (Exfiltration)
- `finding_info.attacks[].technique_uid = T1537` (Transfer Data to Cloud Account)
- `observables[]` including actor, actor account, target account, destination bucket/key, and source copy path

The native projection (`--output-format native`) keeps the same copy summary in
a flatter shape.

## Run

```bash
# CloudTrail -> ingest -> detect (default OCSF output)
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-s3-cross-account-copy/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-s3-cross-account-copy/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-cloudtrail-ocsf`](../../ingestion/ingest-cloudtrail-ocsf/) — upstream ingester
- [`detect-aws-enumeration-burst`](../detect-aws-enumeration-burst/) — AWS discovery depth
- [`detect-lateral-movement`](../detect-lateral-movement/) — cross-cloud movement after successful pivots
