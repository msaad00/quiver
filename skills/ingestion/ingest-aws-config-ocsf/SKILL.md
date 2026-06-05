---
name: ingest-aws-config-ocsf
description: >-
  Convert AWS Config configuration-item change notifications and Config rule
  compliance changes into OCSF 1.8 events. Configuration items become API
  Activity (6003) records with resource configuration, tags, relationships, and
  change-diff context preserved under unmapped.aws_config. Compliance changes
  become Compliance Finding (2003) records with Config rule, resource, and
  status evidence. Supports SNS envelopes, EventBridge-style detail envelopes,
  raw AWS Config notification messages, configuration item snapshots, JSON
  arrays, and JSONL. Use when the user mentions AWS Config snapshots,
  configuration item history, Config rule compliance change events, or
  decoupling AWS posture ingestion from CIS evaluation. Do NOT use for
  CloudTrail audit logs, Security Hub ASFF findings, GuardDuty findings, or
  live AWS API assessment.
purpose: Convert AWS Config configuration-item and compliance-change events into OCSF 1.8 API Activity and Compliance Finding records.
capability: ingest
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: raw
output_formats: ocsf, native
concurrency_safety: stateless
---

# ingest-aws-config-ocsf

Read-only AWS Config ingestion for the posture pipeline. It normalizes recorded
configuration items and Config rule compliance changes into a stable event
stream so evaluation skills can read evidence without calling AWS live APIs.

## Use When

- You have AWS Config SNS notifications, EventBridge detail payloads, exported
  configuration item history, or Config snapshot records.
- You need AWS Config rule compliance changes as OCSF Compliance Finding (2003)
  JSONL.
- You are building the ingest-decouples-from-evaluate path for CIS AWS
  Foundations over already-collected evidence.

## Do NOT Use

- For CloudTrail management or data events; use `ingest-cloudtrail-ocsf`.
- For Security Hub ASFF findings; use `ingest-security-hub-ocsf`.
- For GuardDuty native findings; use `ingest-guardduty-ocsf`.
- As a live AWS scanner. This skill does not call AWS APIs.

## Wire Contract

Accepted input shapes:

1. SNS notification envelopes with `Message` as a JSON string or object.
2. Raw AWS Config messages with `messageType`.
3. Raw `configurationItem` or `configurationItems` objects from snapshots or
   history exports.
4. EventBridge-style objects with an AWS Config `detail` payload.
5. JSON arrays or JSONL streams containing any of the above.

Output:

- Configuration item changes and snapshots emit OCSF 1.8 API Activity (6003).
- Compliance change notifications emit OCSF 1.8 Compliance Finding (2003).
- `--output-format native` emits the same canonical records without an OCSF
  envelope for downstream evaluators that want repo-native evidence.

All original AWS Config context that is not first-class OCSF is retained under
`unmapped.aws_config` in OCSF mode and under `raw` in native mode.

## Usage

```bash
# AWS Config SNS notification or raw message
python src/ingest.py aws-config.json > aws-config.ocsf.jsonl

# Native evidence stream for a future evaluator
python src/ingest.py aws-config.json --output-format native > aws-config.native.jsonl

# JSONL export
cat config-history.jsonl | python src/ingest.py > config-history.ocsf.jsonl
```

## Tests

`tests/test_ingest.py` verifies SNS string unwrapping, raw configuration item
snapshots, compliance change mapping, native output, OCSF validator conformance,
and golden fixture parity against:

- `skills/detection-engineering/golden/aws_config_raw_sample.json`
- `skills/detection-engineering/golden/aws_config_sample.ocsf.jsonl`
