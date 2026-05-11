---
name: detect-cloudtrail-disabled
description: >-
  Detect successful AWS CloudTrail `StopLogging` and `DeleteTrail` API calls
  from OCSF 1.8 API Activity records emitted by ingest-cloudtrail-ocsf. Emits
  an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&CK
  T1562.001 (Disable or Modify Tools) when a trail is explicitly stopped or
  deleted. Use when the user mentions "CloudTrail disabled," "trail
  deletion," "defense evasion in AWS logging," or "T1562.001 CloudTrail."
  Do NOT use as a posture-at-rest check (use the CSPM AWS CIS skill), for GCP
  or Azure audit logging changes, or to infer every possible logging
  impairment path. This first slice only covers successful `StopLogging` and
  `DeleteTrail` events.
purpose: Detect successful AWS CloudTrail `StopLogging` and `DeleteTrail` API calls from OCSF 1.8 API Activity records emitted by ingest-cloudtrail-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged with MITRE ATT&C...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-cloudtrail-disabled
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - CIS AWS Foundations
  cloud: aws
  capability: read-only
---

# detect-cloudtrail-disabled

Streaming detector for successful CloudTrail disable/delete operations in AWS. This is the first concrete slice under issue `#253`: it keeps the rule narrow and high-confidence instead of over-claiming every possible logging impairment path.

## Use when

- You stream CloudTrail through `ingest-cloudtrail-ocsf` and want near-real-time defense-evasion findings
- You want to catch explicit trail shutdown or deletion events the moment they happen
- You are closing ATT&CK T1562.001 coverage with a read-only detector

## Do NOT use

- As a posture-at-rest logging check; use [`cspm-aws-cis-benchmark`](../../evaluation/cspm-aws-cis-benchmark/)
- For GCP or Azure audit-log disablement; those are separate detectors
- To infer missing trails, missing data events, or KMS drift; those belong in CSPM and follow-on detectors

## Rule

A finding fires on every successful CloudTrail event from `ingest-cloudtrail-ocsf` where:

1. `api.operation` is `StopLogging` or `DeleteTrail`
2. `status_id == 1`
3. request parameters resolve a trail name or trail ARN

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[].tactic_uid = TA0005` (Defense Evasion)
- `finding_info.attacks[].technique_uid = T1562.001` (Disable or Modify Tools)
- `observables[]` including `target.name`, `trail.arn` when present, `account.uid`, `region`, `actor.name`, and `api.operation`

The native projection (`--output-format native`) keeps the trail identity and actor/account context in a flatter shape.

## Run

```bash
# CloudTrail -> ingest -> detect (default OCSF output)
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-cloudtrail-disabled/src/detect.py \
  > findings.ocsf.jsonl

# Native projection
python skills/detection/detect-cloudtrail-disabled/src/detect.py findings-input.jsonl --output-format native
```

## See also

- [`ingest-cloudtrail-ocsf`](../../ingestion/ingest-cloudtrail-ocsf/) — upstream ingester
- [`cspm-aws-cis-benchmark`](../../evaluation/cspm-aws-cis-benchmark/) — posture-at-rest logging coverage
- [`detect-aws-open-security-group`](../detect-aws-open-security-group/) — sibling AWS CloudTrail detector
