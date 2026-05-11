---
name: detect-aws-enumeration-burst
description: >-
  Detect short-window bursts of high-signal AWS discovery APIs from OCSF 1.8
  API Activity records emitted by ingest-cloudtrail-ocsf. Emits an OCSF 1.8
  Detection Finding (class 2004) tagged with MITRE ATT&CK T1526 (Cloud Service
  Discovery) when one principal rapidly calls a narrow allow-list of CloudTrail
  discovery APIs across IAM, EC2, S3, KMS, Lambda, EKS, CloudTrail, and
  Organizations. Use when the user mentions "AWS discovery burst", "CloudTrail
  enumeration spree", "rapid Describe/List calls", or "T1526 via CloudTrail".
  Do NOT use as a generic anomaly detector for every read API, to claim all AWS
  discovery paths, or to infer exfiltration from read-only control-plane calls.
purpose: Detect short-window bursts of high-signal AWS discovery APIs from OCSF 1.8 API Activity records emitted by ingest-cloudtrail-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK T1526 (Cloud...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-aws-enumeration-burst
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: aws
  capability: read-only
---

# detect-aws-enumeration-burst

Streaming detector for rapid AWS discovery bursts in CloudTrail. This is the
first shipped AWS cloud-discovery slice under the ATT&CK roadmap, and it stays
intentionally narrow so the repo does not over-claim generic discovery coverage.

## Use when

- You stream CloudTrail through `ingest-cloudtrail-ocsf` and want near-real-time findings on suspicious enumeration bursts
- You want a deterministic, read-only AWS discovery detector aligned to ATT&CK `T1526`
- You need a narrow follow-on slice after the shipped AWS IAM-user access-key and login-profile persistence detectors

## Do NOT use

- As a generic anomaly detector for every `Describe*`, `Get*`, or `List*` call in AWS
- To infer exfiltration or data access; use a dedicated egress or data-transfer detector
- To claim every AWS discovery path is covered; this first slice is only a curated allow-list of high-signal control-plane APIs

## Rule

A finding fires when one AWS principal, within a rolling five-minute window:

1. emits at least `6` successful CloudTrail events from `ingest-cloudtrail-ocsf`
2. across at least `5` distinct allow-listed discovery API calls
3. against the same account / region / principal key

Today the allow-list covers high-signal AWS discovery APIs such as:

- IAM: `ListUsers`, `ListRoles`, `ListPolicies`, `GetAccountAuthorizationDetails`
- EC2: `DescribeInstances`, `DescribeSecurityGroups`, `DescribeSubnets`, `DescribeVpcs`
- S3: `ListBuckets`
- Organizations: `DescribeOrganization`, `ListAccounts`
- KMS: `ListKeys`
- Lambda: `ListFunctions`
- EKS: `ListClusters`
- CloudTrail: `DescribeTrails`

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity MEDIUM (`severity_id=3`), with:

- `finding_info.attacks[].tactic_uid = TA0007` (Discovery)
- `finding_info.attacks[].technique_uid = T1526` (Cloud Service Discovery)
- `observables[]` including actor, account, region, source IP, total event count, distinct API count, and the concrete API set seen in the burst

The native projection (`--output-format native`) keeps the same burst summary in
a flatter shape.

## Run

```bash
# CloudTrail -> ingest -> detect (default OCSF output)
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-aws-enumeration-burst/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-aws-enumeration-burst/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-cloudtrail-ocsf`](../../ingestion/ingest-cloudtrail-ocsf/) — upstream ingester
- [`detect-lateral-movement`](../detect-lateral-movement/) — cross-cloud movement after successful pivots
- [`detect-cloudtrail-disabled`](../detect-cloudtrail-disabled/) — AWS defense-evasion depth
