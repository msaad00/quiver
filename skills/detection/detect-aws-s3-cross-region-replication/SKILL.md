---
name: detect-aws-s3-cross-region-replication
description: >-
  Detect AWS S3 `PutBucketReplication` calls that ship objects to a
  destination bucket in a different region OR a different account than the
  source bucket. Reads OCSF 1.8 API Activity (class 6003) records produced
  by `ingest-cloudtrail-ocsf`, walks each replication rule's destination
  block (`bucket`, `account`, `region`), and emits an OCSF 1.8 Detection
  Finding (class 2004) tagged with MITRE ATT&CK T1537 (Transfer Data to
  Cloud Account) and T1567 (Exfiltration Over Web Service) when the
  destination crosses a region or account boundary AND the destination
  bucket is not on the `AWS_REPLICATION_AUTHORIZED_BUCKETS` allow-list.
  Use when the user mentions "S3 replication exfil", "PutBucketReplication
  to another account", "S3 cross-region replication anomaly", or
  "T1537 in AWS via S3". Do NOT use as a posture-at-rest replication
  inventory, for cross-account `CopyObject` (use detect-s3-cross-account-copy),
  or on raw CloudTrail JSON before OCSF normalization.
purpose: Detect AWS S3 cross-region or cross-account replication-rule creation as a T1537 / T1567 exfiltration vector.
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
  Requires Python 3.11+. Read-only — consumes OCSF 1.8 API Activity 6003
  records from stdin/file and emits OCSF 1.8 Detection Finding 2004 to
  stdout. No AWS SDK; pairs with `ingest-cloudtrail-ocsf` upstream.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-aws-s3-cross-region-replication
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
  cloud: aws
  capability: read-only
---

# detect-aws-s3-cross-region-replication

## Attack pattern

S3 cross-region replication is a documented data-pipeline feature: an
operator creates a replication rule and every object written to the
source bucket is asynchronously copied to the destination. A persistent
attacker who lands `s3:PutReplicationConfiguration` can lay down a rule
whose destination is **an attacker-controlled bucket in a different
account or region** and quietly drain the source bucket as new objects
land — no `GetObject` call ever shows up in CloudTrail, only the rule
creation.

This is the same idiom as `T1537 Transfer Data to Cloud Account` and
`T1567 Exfiltration Over Web Service`: the data path is the cloud
provider's own replication machinery, fully encrypted, fully native.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose producer
is `ingest-cloudtrail-ocsf`:

1. Filter to `api.operation == "PutBucketReplication"`.
2. Require `status_id == 1` (success).
3. Walk `unmapped.cloudtrail.request_parameters.replicationConfiguration.rules[]`.
4. For each rule destination, classify the boundary:
   - `cross-region` if the destination region != source region
   - `cross-account` if the destination account != source account
   - `cross-account-and-region` if both
   - `same-region-and-account` → skip
5. **Fail-open allow-list**: if `AWS_REPLICATION_AUTHORIZED_BUCKETS` is
   empty, fire on every cross-boundary rule (with
   `evidence.allowlist_mode = "fail-open"`). Operators must set the
   allow-list explicitly in prod; the warning is emitted to stderr.
6. When the allow-list is set, fire only when the destination bucket is
   **not** on it.

The detector is stateless — one finding per (source-bucket, rule)
pair, deduplicated on `metadata.uid`.

Operators tune the policy at runtime:

- `AWS_REPLICATION_AUTHORIZED_BUCKETS` — comma-separated bucket names or
  ARNs (default empty = fail-open).

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["aws-s3-cross-region-replication", "boundary-<...>"]`
- `finding_info.attacks[]` carries MITRE ATT&CK `T1537` and `T1567`
  (tactic `TA0010 Exfiltration`)
- `observables[]` for source / destination bucket, account, region, actor
- `evidence` carries `boundary`, `allowlist_mode`, `rule_id`

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
export AWS_REPLICATION_AUTHORIZED_BUCKETS="prod-dr-replica-us-west-2,analytics-archive"
cat cloudtrail.ocsf.jsonl \
  | python src/detect.py \
  > aws_s3_cross_region_replication_findings.ocsf.jsonl
```

## Do NOT use

- On raw CloudTrail JSON before OCSF normalization (use
  `ingest-cloudtrail-ocsf` first).
- As a posture-at-rest replication-rule inventory (this is event-based).
- For cross-account `CopyObject` events (use
  `detect-s3-cross-account-copy`).
- As a remediation skill — replication-rule revocation lives in the
  remediation layer.

## Tests

The test suite covers:

- positive: cross-region replication to unauthorized bucket fires (enforced)
- positive: cross-account replication fires
- negative: same-region same-account rule does NOT fire
- negative: cross-region rule whose destination is on the allow-list does NOT fire
- malformed: missing replication rules → no fire, stderr warning
- threshold edge: cross-region + cross-account combined boundary classified correctly
- multi-event idempotence: duplicate `metadata.uid` does not inflate counts
- vendor-name: events from a non-cloudtrail producer are ignored
- env-override: `AWS_REPLICATION_AUTHORIZED_BUCKETS` honored
- golden fixture: input / output round-trip

## Roadmap

First slice of the cloud exfiltration + defense-evasion expansion under
issue `#253` (MITRE ATT&CK coverage to 50%).
