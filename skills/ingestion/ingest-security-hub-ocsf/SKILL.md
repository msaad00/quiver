---
name: ingest-security-hub-ocsf
description: >-
  Convert AWS Security Hub ASFF findings into OCSF 1.8 Detection Finding
  events. Validates the required ASFF fields, maps ASFF severity into OCSF,
  preserves aggregated resource and compliance context, and extracts MITRE
  ATT&CK hints when upstream products provide them. Supports single findings,
  `{\"Findings\": [...]}` wrappers, and EventBridge imported-finding
  envelopes. Use when the user mentions Security Hub ingestion, ASFF
  normalization, or unifying upstream AWS findings into OCSF. Do NOT use for
  GuardDuty native findings, CloudTrail audit logs, or VPC Flow Logs. Do NOT
  use as a detection skill; this is a passthrough normalizer and validator.
purpose: Convert AWS Security Hub ASFF findings into OCSF 1.8 Detection Finding events. Validates the required ASFF fields, maps ASFF severity into OCSF, preserves aggregated resource and compliance context, and extracts MITRE...
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

# ingest-security-hub-ocsf

Thin passthrough ingestion skill with ASFF validation: raw Security Hub ASFF JSON in → canonical finding projection → OCSF 1.8 Detection Finding (2004) JSONL or native enriched finding JSONL out. Security Hub is an aggregator — it already collects findings from GuardDuty, Inspector, Macie, Config, Firewall Manager, and third-party products, all normalised to the same ASFF schema. This skill does one thing: validate that the ASFF required fields are present and transform them into the repo's stable finding contract.

## Wire contract

Reads any of the three shapes Security Hub emits:

1. **Single finding** — one JSON object per line (NDJSON, e.g. EventBridge → Kinesis Firehose to S3)
2. **BatchImportFindings / GetFindings wrapper** — top-level `{"Findings": [...]}` (the format from `aws securityhub get-findings` or from `BatchImportFindings` request bodies)
3. **EventBridge event envelope** — top-level `{"detail-type": "Security Hub Findings - Imported", "detail": {"findings": [...]}, ...}`; the skill auto-unwraps `detail.findings`.

Writes OCSF 1.8 **Detection Finding** (`class_uid: 2004`, `category_uid: 2`). See [`../OCSF_CONTRACT.md`](../OCSF_CONTRACT.md) for the field-level pinning every event matches.

When `--output-format native` is selected, it emits the same finding in the repo's native enriched shape with stable `event_uid`, normalized provider/account/severity fields, MITRE ATT&CK annotations, preserved compliance/resource context, and no OCSF envelope fields.

## Field mapping

The native output field list, the ASFF required-field validation list, the `Severity.Label` / `Normalized` → `severity_id` ladder, the MITRE ATT&CK extraction rules (Types[] taxonomy + ProductFields lookup), the deterministic `finding_info.uid` derivation, and the `Compliance` block passthrough live in [`references/field-map.md`](references/field-map.md). Keeping the detail there keeps this file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)) while detectors and reviewers still get the exact mapping one click away.

## Usage

```bash
# Single finding
python src/ingest.py asff.json > asff.ocsf.jsonl

# Same input, native enriched output
python src/ingest.py asff.json --output-format native > asff.native.jsonl

# From a BatchImportFindings request body
aws securityhub get-findings --max-results 100 | python src/ingest.py

# Piped downstream to SARIF
python src/ingest.py asff.json | python ../convert-ocsf-to-sarif/src/convert.py > asff.sarif
```

## Tests

`tests/test_ingest.py` runs the ingester against [`../golden/security_hub_raw_sample.json`](../golden/security_hub_raw_sample.json) and asserts deep-equality against [`../golden/security_hub_sample.ocsf.jsonl`](../golden/security_hub_sample.ocsf.jsonl). Plus unit tests for ASFF validation (every required field), Label vs Normalized severity precedence, Types[] MITRE extraction, ProductFields MITRE extraction, BatchImport wrapper unwrapping, and EventBridge envelope unwrapping.
