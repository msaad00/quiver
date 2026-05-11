---
name: ingest-guardduty-ocsf
description: >-
  Convert raw AWS GuardDuty findings (native JSON finding format from the
  GuardDuty API, EventBridge, or S3 export) into OCSF 1.8 Detection Finding
  events (class 2004). Extracts MITRE ATT&CK technique and tactic from the
  GuardDuty finding Type string, maps the 1.0-8.9 severity scale to OCSF
  severity_id, preserves Resource context, and emits finding_info.attacks[]
  nested inside finding_info (OCSF 1.8 layout). Use when the user mentions
  GuardDuty ingestion, normalising AWS managed detections into OCSF, feeding
  GuardDuty into a unified finding pipeline, or chaining GuardDuty into the
  convert-ocsf-to-sarif / convert-ocsf-to-mermaid-attack-flow skills. Do NOT
  use for Security Hub ASFF (use ingest-security-hub-ocsf), CloudTrail audit
  logs (use ingest-cloudtrail-ocsf), or VPC Flow Logs (use
  ingest-vpc-flow-logs-ocsf). Do NOT use as a detection skill — GuardDuty IS
  the detector; this skill is a passthrough normaliser.
purpose: Convert raw AWS GuardDuty findings (native JSON finding format from the GuardDuty API, EventBridge, or S3 export) into OCSF 1.8 Detection Finding events (class 2004). Extracts MITRE ATT&CK technique and tactic from th...
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

# ingest-guardduty-ocsf

Thin passthrough ingestion skill: raw GuardDuty finding JSON in → canonical finding projection → OCSF 1.8 Detection Finding (2004) JSONL or native enriched finding JSONL out. GuardDuty is already a detection engine — this skill normalises its findings into the same wire format everything else in `detection-engineering/` speaks, so downstream converters (`convert-ocsf-to-sarif`, `convert-ocsf-to-mermaid-attack-flow`) and evaluators consume them uniformly alongside detections from the custom `detect-*` skills.

## Wire contract

Reads any of the three shapes the GuardDuty service emits:

1. **Single finding** — one JSON object per line (NDJSON, e.g. EventBridge → Kinesis Firehose to S3)
2. **API `ListFindings` / `GetFindings` wrapper** — top-level `{"Findings": [...]}` (the format returned by `aws guardduty get-findings`)
3. **EventBridge event envelope** — top-level `{"detail": {...}, "detail-type": "GuardDuty Finding", ...}`; the skill auto-unwraps `detail`.

Writes OCSF 1.8 **Detection Finding** (`class_uid: 2004`, `category_uid: 2`). See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the field-level pinning that every event matches.

When `--output-format native` is selected, it emits the same finding in the repo's native enriched shape with stable `event_uid`, normalized provider/account/severity fields, MITRE ATT&CK annotations, and preserved evidence/resource context, but without the OCSF envelope fields.

## Field mapping

The native output field list, the GuardDuty Type → MITRE ATT&CK tactic/technique tables, the 1.0–8.9 severity → `severity_id` ladder, the deterministic `finding_info.uid` derivation, and the explicit "not mapped (yet)" scope live in [`references/field-map.md`](references/field-map.md). Keeping the detail there keeps this file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)) while detectors and reviewers still get the exact mapping one click away.

## Usage

```bash
# Single finding
python src/ingest.py guardduty.json > guardduty.ocsf.jsonl

# Same input, native enriched output
python src/ingest.py guardduty.json --output-format native > guardduty.native.jsonl

# From EventBridge stream
aws guardduty get-findings --detector-id abc --finding-ids f1 f2 | python src/ingest.py

# Piped downstream
python src/ingest.py gd.json | python ../convert-ocsf-to-sarif/src/convert.py > gd.sarif
```

## Tests

`tests/test_ingest.py` runs the ingester against [`../golden/guardduty_raw_sample.json`](../golden/guardduty_raw_sample.json) and asserts deep-equality against [`../golden/guardduty_sample.ocsf.jsonl`](../golden/guardduty_sample.ocsf.jsonl). Plus unit tests for the Type → MITRE table, the severity scale, Findings-wrapper unwrapping, and EventBridge detail unwrapping.
