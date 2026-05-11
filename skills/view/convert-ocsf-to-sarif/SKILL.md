---
name: convert-ocsf-to-sarif
description: >-
  Convert OCSF 1.8 Detection Findings (class 2004) into SARIF 2.1.0 results
  for upload to GitHub code scanning. Maps each finding's MITRE ATT&CK
  technique to a SARIF rule (ruleId = technique.uid), maps severity_id to
  SARIF level (CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note),
  and projects observables[] into SARIF locations and properties so the
  downstream Security tab carries the actor, target resource, and evidence
  pointers. Use when the user mentions SARIF, GitHub code scanning, GitHub
  Security tab, code scanning upload, or wants detection findings to land
  alongside dependency findings in the same UI. Do NOT use for OCSF events
  that are NOT Detection Findings (class 2004) — Compliance Findings (2003)
  and Inventory Info (5001) need different mappings; a future
  convert-ocsf-compliance-to-sarif will cover those. Do NOT use as a
  detection skill — this only converts.
purpose: Convert OCSF 1.8 Detection Findings (class 2004) into SARIF 2.1.0 results for upload to GitHub code scanning. Maps each finding's MITRE ATT&CK technique to a SARIF rule (ruleId = technique.uid), maps severity_id to SA...
capability: view
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native
concurrency_safety: stateless
---

# convert-ocsf-to-sarif

Cross-vendor view-layer skill: takes OCSF 1.8 Detection Findings (class 2004) on stdin and emits a single SARIF 2.1.0 document on stdout. Built once, used by every detection-engineering pipeline that wants to surface findings in GitHub's Security tab.

## Wire contract

Input: JSONL of OCSF Detection Findings produced by any `detect-*` skill in this repo.

Output: A single SARIF 2.1.0 JSON document (one `runs[]` entry, results array containing every input finding). The document validates against [https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json).

## Field mapping

| OCSF Detection Finding (2004) field | SARIF 2.1.0 field |
|---|---|
| `finding_info.uid` | `result.guid` |
| `finding_info.title` | `result.message.text` (first line) |
| `finding_info.desc` | `result.message.text` (after the title) |
| `finding_info.attacks[0].technique.uid` | `result.ruleId` |
| `finding_info.attacks[0].technique.name` | `result.rule.shortDescription.text` (under `tool.driver.rules[]`) |
| `finding_info.attacks[0].tactic.uid` + `tactic.name` | `result.rule.properties.tags[]` (e.g. `mitre/attack/initial-access/TA0001`) |
| `finding_info.attacks[0].sub_technique.uid` (if present) | appended to `result.tags[]` |
| `severity_id` | `result.level` per the table below |
| `metadata.product.feature.name` | `result.properties.detector` (which skill emitted the finding) |
| `metadata.product.name` + `metadata.product.feature.name` | `tool.driver.name` |
| `time` | `result.properties.detected_at_ms` (ms epoch) |
| `observables[]` | `result.properties.observables[]` (verbatim, so SARIF consumers can pivot) |
| `evidence` | `result.properties.evidence` (verbatim) |
| `finding_info.types[]` | `result.properties.finding_types[]` |

## severity_id → SARIF level

| OCSF severity_id | SARIF level | Reason |
|---:|---|---|
| 0 (Unknown) | `none` | SARIF default |
| 1 (Informational) | `note` | |
| 2 (Low) | `note` | |
| 3 (Medium) | `warning` | |
| 4 (High) | `error` | GitHub Security tab shows as red |
| 5 (Critical) | `error` | |
| 6 (Fatal) | `error` | |

## Rule deduplication

Multiple findings can share a MITRE technique (e.g. several priv-esc attempts all → T1611). The skill builds a unique `tool.driver.rules[]` array keyed by technique uid so each technique appears once with its description, and each `result` references the rule by `ruleId`.

## Usage

```bash
# Single pipe step in a detection pipeline
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  | python src/convert.py \
  > findings.sarif

# Then upload to GitHub:
gh api repos/:owner/:repo/code-scanning/sarifs \
  --input findings.sarif \
  --field commit_sha=$(git rev-parse HEAD) \
  --field ref=refs/heads/main
```

Or via the GitHub Action `github/codeql-action/upload-sarif@v3` in CI — same pattern as the existing `agent-bom-iac` upload.

## Tests

Golden fixture parity: runs the K8s priv-esc golden findings (`../golden/k8s_priv_esc_findings.ocsf.jsonl`) through the converter and asserts the output matches a frozen SARIF golden (`../golden/k8s_priv_esc_findings.sarif`). Plus unit tests for severity mapping, MITRE rule deduplication, multi-finding handling, and edge cases (missing attacks, missing observables, empty input).
