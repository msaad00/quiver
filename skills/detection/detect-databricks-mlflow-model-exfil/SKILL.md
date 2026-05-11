---
name: detect-databricks-mlflow-model-exfil
description: >-
  Detect Databricks MLflow model artifacts being downloaded by an actor or
  copied to an external workspace. Reads OCSF 1.8 API Activity (class 6003)
  records normalized from Databricks audit logs whose `api.operation` matches
  `mlflow.downloadArtifact`, `mlflow.getModelVersionDownloadUri`, or
  `mlflow.transitionModelVersionStage` (when the target stage is external),
  carrying `unmapped.databricks.model_name` and the actor email under
  `actor.user.email_addr`, and emits OCSF 1.8 Detection Finding (class 2004)
  tagged with MITRE ATLAS AML.T0040 (ML Model Inference / Stealing) and
  MITRE ATT&CK T1567 (Exfiltration Over Web Service). Fires once per
  (model_name, actor) tuple per 24h window to avoid storming on legitimate
  CI pipelines that re-download model versions. Use when you suspect a
  Databricks principal is exfiltrating MLflow model artifacts (the weights
  + config bundle) outside the workspace. Do NOT use on raw Databricks
  audit JSON before OCSF normalization, as an MLflow inventory snapshot,
  or as a generic ML-pipeline performance detector.
purpose: Detect Databricks MLflow model-artifact download / cross-workspace transition.
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
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-databricks-mlflow-model-exfil
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - MITRE ATLAS
    - OWASP LLM Top 10
  cloud:
    - databricks
---

# detect-databricks-mlflow-model-exfil

## Attack pattern

Databricks MLflow tracks model artifacts (weights, config, signature
file, registered-model metadata) in a registry that can be queried via
REST. A compromised actor with `EDIT` or `READ` on a registered model
can download the artifact bundle off the workspace — equivalent to
stealing the trained model — or transition a model version to a stage
that lives in a different workspace, smuggling the artifact across the
trust boundary.

On the wire this surfaces as a Databricks audit-log entry whose
`serviceName == "mlflow"` and `actionName` in
{`downloadArtifact`, `getModelVersionDownloadUri`,
`transitionModelVersionStage`}. The first two anchor the exfiltration
directly; the third anchors a stage move that targets a workspace
outside the current trust boundary (the upstream ingester surfaces
the target stage / workspace as
`unmapped.databricks.target_workspace_id`).

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events from a
Databricks producer:

1. Match `api.operation` in the recognized MLflow anchor family
   (case-insensitive).
2. Require `status_id == 1` (success).
3. Require a non-empty `actor.user.email_addr` (or `uid`).
4. Require a non-empty `unmapped.databricks.model_name`.
5. For `mlflow.transitionModelVersionStage`: only fire when
   `unmapped.databricks.target_workspace_id` is set AND differs from
   `unmapped.databricks.workspace_id`.
6. Fire **once per (model_name, actor) tuple per 24h window** —
   legitimate CI pipelines re-download model versions on every train
   step; one finding per principal-model pair per day is enough to
   anchor the investigation.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding
projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["databricks-mlflow-model-exfil",
  "OWASP-LLM-Top-10-LLM06"]`
- `finding_info.attacks[]` populated with MITRE ATLAS `AML.T0040`
  (ML Model Inference / Stealing) plus MITRE ATT&CK `T1567`
  (Exfiltration Over Web Service)
- `observables[]` carrying the actor, model name, model version,
  workspace ID, and target workspace ID (when known)
- `evidence` carrying the raw event uid, the model name, version,
  operation, and download count in the window

Severity is `HIGH` (severity_id `4`) because a downloaded model
artifact lives outside the workspace's audit and access controls.

## Usage

```bash
cat databricks_audit.ocsf.jsonl \
  | python src/detect.py \
  > databricks_mlflow_exfil_findings.ocsf.jsonl
```

Tune the dedupe window with the `DATABRICKS_MLFLOW_DEDUPE_WINDOW_MIN`
environment variable (default `1440` minutes = 24h).

## Do NOT use

- On raw Databricks audit JSON before OCSF normalization
- As an MLflow registry inventory or model-age check
- As a generic AWS / GCP / Azure model-artifact-download detector —
  those have dedicated skills under `detect-aws-model-artifact-download`
  and `detect-gcp-model-artifact-download`

## Tests

The test suite covers:

- positive: a single `mlflow.downloadArtifact` fires exactly one
  finding with the expected ATLAS T0040 + ATT&CK T1567 mapping
- positive: a cross-workspace `transitionModelVersionStage` fires
- negative: same-workspace stage transition does NOT fire
- negative: a failed download (`status_id != 1`) does NOT fire
- edge: a multi-download burst by the same (model, actor) collapses
  to one finding within the dedupe window
- edge: a malformed JSON line is skipped with a stderr telemetry
  event, not crashed on
- edge: a non-Databricks producer is ignored

## Roadmap

Third Databricks vendor-depth detector for issue #436.
