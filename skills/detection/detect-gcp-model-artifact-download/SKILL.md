---
name: detect-gcp-model-artifact-download
description: >-
  Detect successful GCS object downloads that look like model-weight or
  checkpoint artifact collection. Consumes OCSF 1.8 API Activity emitted by
  ingest-gcp-audit-ocsf and fires only on successful
  storage.googleapis.com/storage.objects.get events whose object path matches
  explicit model-artifact filename or suffix heuristics. Emits OCSF Detection
  Finding 2004 by default, with a native output mode for repo-local pipelines.
  Use when the user wants to spot suspicious model artifact collection from
  Cloud Storage. Do NOT use for generic bucket access monitoring, generic data
  exfiltration, or Azure/AWS object-store reads.
purpose: Detect successful GCS object downloads that look like model-weight or checkpoint artifact collection.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf, native
output_formats: ocsf, native
concurrency_safety: stateless
compatibility: >-
  Requires Python 3.11+. Input must be the OCSF / native API Activity stream
  from ingest-gcp-audit-ocsf. The detector is read-only and deterministic.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-gcp-model-artifact-download
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - MITRE ATLAS
    - OWASP LLM Top 10
  cloud: gcp
  capability: read-only
---

# detect-gcp-model-artifact-download

## What it does

Flags successful GCS object reads that look like model weights, checkpoints, or
other ML artifact collection.

The detector is intentionally narrow:

- only `ingest-gcp-audit-ocsf` input
- only successful `storage.objects.get`
- only explicit model-artifact filename / suffix matches

It does **not** claim generic GCS exfiltration coverage.

## Mappings

- **MITRE ATT&CK**: `T1530` Data from Cloud Storage
- **MITRE ATLAS**: `AML.T0035` ML Artifact Collection

## Input contract

Reads JSONL API Activity records and expects:

- `metadata.product.feature.name = ingest-gcp-audit-ocsf`
- `api.service.name = storage.googleapis.com`
- `api.operation = storage.objects.get`
- `resources[].name` carrying a GCS-style resource path such as:
  `projects/_/buckets/<bucket>/objects/<object>`

The detector URL-decodes the object path before applying artifact matching.

## Artifact heuristics

High-confidence model artifact hits include:

- `.safetensors`, `.pt`, `.pth`, `.ckpt`, `.onnx`, `.gguf`, `.tflite`, `.keras`, `.h5`
- exact filenames like `pytorch_model.bin`, `adapter_model.bin`, `saved_model.pb`
- `.bin` only when the path also contains model hints such as `model`,
  `checkpoint`, `weights`, `vertex`, or `aiplatform`

## Output

- default: OCSF Detection Finding 2004
- optional: native repo finding via `--output-format native`

## Example

```bash
python skills/ingestion/ingest-gcp-audit-ocsf/src/ingest.py gcp-audit.jsonl \
  | python skills/detection/detect-gcp-model-artifact-download/src/detect.py
```
