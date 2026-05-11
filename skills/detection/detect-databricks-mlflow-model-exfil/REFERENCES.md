# References — detect-databricks-mlflow-model-exfil

## Source formats and schemas

- **Databricks audit logs overview** — https://docs.databricks.com/en/admin/account-settings/audit-logs.html
- **Databricks MLflow audit-log events** — https://docs.databricks.com/en/admin/account-settings/audit-log-events.html#mlflow-events
- **Databricks MLflow `downloadArtifact` REST API** — https://docs.databricks.com/api/workspace/mlflowartifacts/download
- **Databricks MLflow Model Registry `getModelVersionDownloadUri`** — https://docs.databricks.com/api/workspace/modelregistry/getmodelversiondownloaduri
- **Databricks MLflow `transitionModelVersionStage`** — https://docs.databricks.com/api/workspace/modelregistry/transitionmodelversionstage
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATLAS AML.T0040 ML Model Inference / Stealing** — https://atlas.mitre.org/techniques/AML.T0040
- **MITRE ATT&CK T1567 Exfiltration Over Web Service** — https://attack.mitre.org/techniques/T1567/
- **MITRE ATT&CK TA0010 Exfiltration tactic** — https://attack.mitre.org/tactics/TA0010/
- **OWASP LLM Top 10 — LLM06 Sensitive Information Disclosure (model weights)** — https://genai.owasp.org/llm-top-10/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8 API
Activity 6003 events from the upstream `ingest-databricks-audit-ocsf`
pipeline (roadmap, tracked under #436).
