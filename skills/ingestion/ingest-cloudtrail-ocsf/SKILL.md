---
name: ingest-cloudtrail-ocsf
description: >-
  Convert raw AWS CloudTrail events (JSON or NDJSON, single events or
  CloudTrail digest files) into OCSF 1.8 API Activity events (class 6003).
  Maps userIdentity to OCSF actor, sourceIPAddress to src_endpoint, eventName
  to api.operation, eventSource to api.service.name, and infers activity_id
  (Create / Read / Update / Delete) from the event verb. Sets status_id to
  Failure when CloudTrail records an errorCode. Use when the user mentions
  CloudTrail ingestion, AWS audit log normalization, OCSF pipeline for AWS,
  or feeding CloudTrail into a SIEM. Do NOT use for GCP audit logs (use
  ingest-gcp-audit-ocsf), Azure activity logs (use
  ingest-azure-activity-ocsf), or Kubernetes audit logs (use
  ingest-k8s-audit-ocsf). Do NOT use as a detection skill — this skill only
  normalises events, it does not flag anything.
purpose: Convert raw AWS CloudTrail events (JSON or NDJSON, single events or CloudTrail digest files) into OCSF 1.8 API Activity events (class 6003). Maps userIdentity to OCSF actor, sourceIPAddress to src_endpoint, eventName...
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

# ingest-cloudtrail-ocsf

Thin, single-purpose ingestion skill: raw CloudTrail JSON in → canonical event projection → OCSF 1.8 API Activity JSONL or native enriched JSONL out. No detection logic, no side effects, no AWS API calls. Reads files or stdin; writes JSONL or stdout.

## Wire contract

Reads either of the two CloudTrail layouts that are emitted by the AWS service:

1. **Single event** — one JSON object per line (NDJSON, e.g. EventBridge → Kinesis Firehose to S3)
2. **CloudTrail digest** — top-level `{"Records": [...]}` wrapping an array of events (the format `aws s3 cp` retrieves directly from the CloudTrail bucket)

The skill auto-detects which shape it's looking at and unwraps `Records` if present.

By default it writes OCSF 1.8 **API Activity** (`class_uid: 6003`, `category_uid: 6`). See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the field-level pinning that every OCSF event matches.

When `--output-format native` is selected, it emits the same event in the repo's native enriched shape with stable `event_uid`, normalized provider/account/operation/status fields, and preserved actor/session/source context, but without the OCSF envelope fields.

## Field mapping

The native output field list, the `eventName` → `activity_id` prefix table, the `errorCode` → `status_id` rules, and the explicit "not mapped (yet)" scope live in [`references/field-map.md`](references/field-map.md). Keeping the detail there keeps this file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)) while detectors and reviewers still get the exact mapping one click away.

## Usage

```bash
# Single file
python src/ingest.py cloudtrail.json > cloudtrail.ocsf.jsonl

# Same input, native enriched output
python src/ingest.py cloudtrail.json --output-format native > cloudtrail.native.jsonl

# Piped from S3 sync
aws s3 cp s3://my-cloudtrail-bucket/AWSLogs/.../recent.json.gz - | gunzip | python src/ingest.py
```

## Tests

`tests/test_ingest.py` runs the ingester against [`../golden/cloudtrail_raw_sample.jsonl`](../golden/cloudtrail_raw_sample.jsonl) and asserts deep-equality against [`../golden/cloudtrail_sample.ocsf.jsonl`](../golden/cloudtrail_sample.ocsf.jsonl) with volatile fields scrubbed. Plus unit tests for the activity_id mapping table, status_id detection, and Records-wrapper auto-detection.
