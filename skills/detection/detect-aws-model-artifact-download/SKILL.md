---
name: detect-aws-model-artifact-download
description: >-
  Detect successful AWS S3 `GetObject` downloads of model-weight and
  checkpoint artifacts from OCSF 1.8 API Activity records emitted by
  ingest-cloudtrail-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004)
  tagged with MITRE ATT&CK T1530 and MITRE ATLAS AML.T0035 when an S3 object
  read matches narrow model-artifact heuristics such as `.safetensors`,
  `.pt`, `.ckpt`, `pytorch_model.bin`, or `saved_model.pb`. Use when the user
  mentions "AWS model weights downloaded", "S3 model artifact collection",
  "checkpoint read from CloudTrail", or "AML.T0035 in AWS". Do NOT use for
  generic S3 egress, cross-account copy detection, or network-only
  exfiltration claims.
purpose: Detect successful AWS S3 `GetObject` downloads of model-weight and checkpoint artifacts from OCSF 1.8 API Activity records emitted by ingest-cloudtrail-ocsf. Emits an OCSF 1.8 Detection Finding (class 2004) tagged wit...
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
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-aws-model-artifact-download
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - MITRE ATLAS
    - OWASP LLM Top 10
  cloud: aws
  capability: read-only
---

# detect-aws-model-artifact-download

Streaming detector for successful AWS S3 downloads of model-weight and
checkpoint artifacts. This is an AWS-first cloud slice under the AI-native
roadmap: it uses CloudTrail object-read telemetry instead of another MCP-only
text pattern.

## Use when

- You stream CloudTrail through `ingest-cloudtrail-ocsf` and want a narrow AI-native detector for model-artifact collection from S3
- You need AWS-first coverage for suspicious reads of `.safetensors`, `.pt`, `.pth`, `.ckpt`, `.onnx`, `pytorch_model.bin`, or similar checkpoint files
- You want an honest cloud detector that can expand to GCP and Azure later without over-claiming cross-cloud support today

## Do NOT use

- For generic S3 data-exfiltration or storage abuse; use a storage- or network-focused detector instead
- For cross-account object-copy coverage; use [`detect-s3-cross-account-copy`](../detect-s3-cross-account-copy/)
- To claim confirmed network exfiltration or model-weight transfer outside AWS; this first slice is a CloudTrail object-download detector

## Rule

A finding fires on every successful CloudTrail event from `ingest-cloudtrail-ocsf` where:

1. `api.service.name` is `s3.amazonaws.com`
2. `api.operation` is `GetObject`
3. `status_id == 1`
4. `resources[]` resolve both the bucket name and object key
5. the object key matches a narrow model-artifact heuristic:
   - strict suffixes such as `.safetensors`, `.pt`, `.pth`, `.ckpt`, `.onnx`, `.gguf`, `.tflite`
   - exact filenames such as `pytorch_model.bin`, `adapter_model.bin`, `saved_model.pb`
   - `.bin` only when the key also carries model hints such as `model`, `checkpoint`, `weights`, `sagemaker`, or `bedrock`

The detector intentionally skips `AWSService` actors so internal service reads
do not flood the signal.

## OCSF output

OCSF 1.8 Detection Finding (class 2004), severity HIGH (`severity_id=4`), with:

- `finding_info.attacks[]` carrying ATT&CK `T1530` Data from Cloud Storage
- `finding_info.attacks[]` carrying ATLAS `AML.T0035` ML Artifact Collection
- `observables[]` including bucket, key, actor identity, account, region, and source IP

The native projection (`--output-format native`) keeps the bucket, key,
artifact match, and actor/account context in a flatter shape.

## Run

```bash
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py raw.jsonl \
  | python skills/detection/detect-aws-model-artifact-download/src/detect.py
```

Native output:

```bash
python skills/detection/detect-aws-model-artifact-download/src/detect.py findings-input.jsonl --output-format native
```

## Notes

- This is detection-only today.
- The next honest expansion is provider-equivalent model-artifact download coverage on GCP and Azure, not a broader AWS over-claim.

## Related

- [`detect-s3-cross-account-copy`](../detect-s3-cross-account-copy/) — AWS storage exfiltration sibling
- [`detect-agent-credential-leak-mcp`](../detect-agent-credential-leak-mcp/) — AI-native credential leakage
- [`detect-system-prompt-extraction`](../detect-system-prompt-extraction/) — explicit prompt leakage
- [`model-serving-security`](../../evaluation/model-serving-security/) — AI-serving posture depth
