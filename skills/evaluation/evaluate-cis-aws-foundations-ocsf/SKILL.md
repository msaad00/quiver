---
name: evaluate-cis-aws-foundations-ocsf
description: >-
  Evaluate AWS Config OCSF evidence against the Config-backed slice of CIS AWS
  Foundations Benchmark v3.0. Reads OCSF 1.8 API Activity (6003) configuration
  item records and AWS Config Compliance Finding (2003) records emitted by
  ingest-aws-config-ocsf, then emits one OCSF Compliance Finding (2003) per
  implemented CIS control. Covers 12 read-only controls across S3, CloudTrail,
  security groups, VPC flow logs, GuardDuty, and Security Hub. Use when the user
  wants CIS AWS evaluation from already-collected AWS Config evidence without
  live AWS API calls. Do NOT use as a full replacement for
  cspm-aws-cis-benchmark IAM/live-account checks yet; IAM and CloudWatch alarm
  controls remain intentionally out of scope for this decoupled slice.
purpose: Evaluate AWS Config OCSF evidence against the Config-backed slice of CIS AWS Foundations Benchmark v3.0.
capability: evaluate
persistence: none
telemetry: stderr_jsonl
privilege_escalation: read
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf, native
output_formats: native, ocsf
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. No cloud SDKs, credentials, or network egress needed.
  Reads local JSON/JSONL evidence produced by ingest-aws-config-ocsf.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/evaluation/evaluate-cis-aws-foundations-ocsf
  version: 0.1.0
  frameworks:
    - CIS AWS Foundations v3.0
    - OCSF 1.8
    - NIST CSF 2.0
    - ISO 27001:2022
    - SOC 2 TSC
  cloud: aws
---

# Evaluate — CIS AWS Foundations over AWS Config OCSF

Read-only evaluator for the decoupled AWS posture path:

```text
AWS Config export -> ingest-aws-config-ocsf -> evaluate-cis-aws-foundations-ocsf
```

The skill does not call AWS. It evaluates already-collected configuration item
and Config rule evidence and emits one native or OCSF Compliance Finding per
implemented control.

## Use When

- You already collect AWS Config configuration item history or snapshots.
- You need CIS AWS posture findings in OCSF without live AWS credentials.
- You want to prove the ingest-decouples-from-evaluate architecture before
  retiring legacy live-account checks.

## Do Not Use

- As a full replacement for `cspm-aws-cis-benchmark` yet.
- For IAM controls that require credential report or account password policy
  evidence.
- For CloudWatch alarm controls unless that evidence has been modeled into AWS
  Config records.

## Implemented Controls

| ID | Control | Evidence |
|---|---|---|
| 2.1 | S3 default encryption | `AWS::S3::Bucket` configuration or AWS Config rule |
| 2.2 | S3 server access logging | `AWS::S3::Bucket` configuration or AWS Config rule |
| 2.3 | S3 public access blocked | `AWS::S3::Bucket` configuration or AWS Config rule |
| 2.4 | S3 versioning enabled | `AWS::S3::Bucket` configuration or AWS Config rule |
| 3.1 | CloudTrail multi-region | `AWS::CloudTrail::Trail` configuration or AWS Config rule |
| 3.2 | CloudTrail log validation | `AWS::CloudTrail::Trail` configuration or AWS Config rule |
| 3.5 | CloudTrail KMS encryption | `AWS::CloudTrail::Trail` configuration or AWS Config rule |
| 4.1 | No unrestricted SSH | `AWS::EC2::SecurityGroup` ingress or AWS Config rule |
| 4.2 | No unrestricted RDP | `AWS::EC2::SecurityGroup` ingress or AWS Config rule |
| 4.3 | VPC flow logs enabled | `AWS::EC2::VPC` + `AWS::EC2::FlowLog` evidence |
| 6.1 | GuardDuty enabled | `AWS::GuardDuty::Detector` evidence or AWS Config rule |
| 6.2 | Security Hub enabled | `AWS::SecurityHub::Hub` evidence or AWS Config rule |

## Roadmap

The following CIS AWS v3.0 controls remain in the legacy live-account evaluator
until equivalent evidence is available in the decoupled pipeline:

- IAM controls: 1.1 through 1.7
- CloudTrail S3 bucket public access: 3.3
- CloudWatch alarms: 3.4
- CloudTrail data events: 3.6

## Usage

```bash
# OCSF JSONL from the ingester
python skills/ingestion/ingest-aws-config-ocsf/src/ingest.py aws-config.json \
  | python skills/evaluation/evaluate-cis-aws-foundations-ocsf/src/checks.py

# Native JSON array
python src/checks.py aws-config.ocsf.jsonl --output json

# OCSF Compliance Finding output
python src/checks.py aws-config.ocsf.jsonl --output json --output-format ocsf

# Single control
python src/checks.py aws-config.ocsf.jsonl --control 2.1
```

Exit code is `1` when any HIGH or CRITICAL implemented control fails, `0` when
only pass / medium fail / not-applicable results remain, and `2` for malformed
input.
