# Framework Coverage

This file is **generated from [`framework-coverage.json`](framework-coverage.json)** by `scripts/generate_framework_coverage_doc.py`. Do not edit by hand — update the registry and regenerate.

- Registry version: `0.8.1`
- Registry updated: `2026-04-24`
- Total shipped skills in registry: **80**

## Roll-up

| Framework | Version | Shipped skills mapped | Coverage target |
|---|---|---|---|
| OCSF | 1.8.0 | **59** | — |
| MITRE ATT&CK | v14 | **53** | 100% mapped coverage |
| MITRE ATLAS | current | **13** | 100% mapped coverage |
| CIS AWS Foundations | v3.0 | **4** | — |
| CIS GCP Foundations | v3.0 | **5** | — |
| CIS Azure Foundations | v2.1 | **6** | — |
| CIS Kubernetes Benchmark | current | **2** | — |
| CIS Docker Benchmark | current | **1** | — |
| CIS Controls | v8 | **2** | — |
| NIST CSF | 2.0 | **20** | 100% mapped coverage |
| NIST AI RMF | current | **4** | — |
| SOC 2 TSC | current | **20** | 100% mapped coverage |
| PCI DSS | 4.0 | **4** | 100% mapped coverage |
| ISO 27001 | 2022 | **3** | — |
| OWASP Top 10 | 2021 | **4** | — |
| OWASP LLM Top 10 | current | **8** | — |
| OWASP MCP Top 10 | current | **7** | — |
| CycloneDX ML-BOM | current | **2** | — |

Shipped skills mapped counts the number of skills in the registry that declare this framework under `frameworks`. It does not claim per-control depth; see each skill's `SKILL.md` and `REFERENCES.md` for the concrete controls, techniques, or benchmarks covered.

## Per-framework skill lists

### OCSF (1.8.0)

- Registry id: `ocsf-1.8`

Shipped skills mapped: **59**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-agent-credential-leak-mcp`](../skills/detection/detect-agent-credential-leak-mcp) | detection | mcp, multi | agent-tools, tool-results, credentials |
| [`detect-aws-access-key-creation`](../skills/detection/detect-aws-access-key-creation) | detection | aws | iam-users, access-keys, credentials, cloudtrail |
| [`detect-aws-enumeration-burst`](../skills/detection/detect-aws-enumeration-burst) | detection | aws | identities, compute, storage, network, organizations, cloudtrail |
| [`detect-aws-login-profile-creation`](../skills/detection/detect-aws-login-profile-creation) | detection | aws | iam-users, login-profiles, credentials, cloudtrail |
| [`detect-aws-model-artifact-download`](../skills/detection/detect-aws-model-artifact-download) | detection | aws | object-storage, objects, model-artifacts, audit-logs |
| [`detect-aws-open-security-group`](../skills/detection/detect-aws-open-security-group) | detection | aws | security-groups, ingress-rules, cloudtrail |
| [`detect-azure-activity-logs-disabled`](../skills/detection/detect-azure-activity-logs-disabled) | detection | azure | activity-logs, diagnostic-settings, logging |
| [`detect-azure-open-nsg`](../skills/detection/detect-azure-open-nsg) | detection | azure | network-security-groups, ingress-rules, azure-activity |
| [`detect-cloudtrail-disabled`](../skills/detection/detect-cloudtrail-disabled) | detection | aws | cloudtrail, audit-trails, logging |
| [`detect-container-escape-k8s`](../skills/detection/detect-container-escape-k8s) | detection | kubernetes | clusters, containers, runtime |
| [`detect-credential-stuffing-okta`](../skills/detection/detect-credential-stuffing-okta) | detection | okta | identities, authentication, sessions |
| [`detect-entra-credential-addition`](../skills/detection/detect-entra-credential-addition) | detection | azure, entra, microsoft-graph | identities, applications, service-principals, federated-credentials |
| [`detect-entra-role-grant-escalation`](../skills/detection/detect-entra-role-grant-escalation) | detection | azure, entra, microsoft-graph | identities, applications, service-principals, app-role-assignments |
| [`detect-gcp-audit-logs-disabled`](../skills/detection/detect-gcp-audit-logs-disabled) | detection | gcp | audit-logs, logging-sinks, log-streams |
| [`detect-gcp-model-artifact-download`](../skills/detection/detect-gcp-model-artifact-download) | detection | gcp | object-storage, objects, model-artifacts, audit-logs |
| [`detect-gcp-open-firewall`](../skills/detection/detect-gcp-open-firewall) | detection | gcp | vpc-firewall-rules, ingress-rules, cloud-audit-logs |
| [`detect-gcp-service-account-key-creation`](../skills/detection/detect-gcp-service-account-key-creation) | detection | gcp | identities, service-accounts, credentials, audit-logs |
| [`detect-gcp-service-account-token-minting`](../skills/detection/detect-gcp-service-account-token-minting) | detection | gcp | identities, service-accounts, credentials, audit-logs |
| [`detect-google-workspace-suspicious-login`](../skills/detection/detect-google-workspace-suspicious-login) | detection | google-workspace | identities, authentication, sessions, mfa |
| [`detect-lateral-movement`](../skills/detection/detect-lateral-movement) | detection | aws, azure, gcp, multi | iam-roles, role-sessions, applications, service-accounts, service-account-keys, iam-credentials, service-principals, managed-identities, federated-credentials, app-role-assignments, sessions, api, network |
| [`detect-mcp-tool-drift`](../skills/detection/detect-mcp-tool-drift) | detection | mcp, multi | agent-tools, supply-chain, tool-metadata |
| [`detect-okta-mfa-fatigue`](../skills/detection/detect-okta-mfa-fatigue) | detection | okta | identities, authentication, mfa, sessions |
| [`detect-privilege-escalation-k8s`](../skills/detection/detect-privilege-escalation-k8s) | detection | kubernetes | clusters, containers, identities, secrets |
| [`detect-prompt-injection-mcp-proxy`](../skills/detection/detect-prompt-injection-mcp-proxy) | detection | mcp, multi | agent-tools, tool-metadata, guardrails |
| [`detect-s3-cross-account-copy`](../skills/detection/detect-s3-cross-account-copy) | detection | aws | storage, buckets, objects, identities, cloudtrail |
| [`detect-sensitive-secret-read-k8s`](../skills/detection/detect-sensitive-secret-read-k8s) | detection | kubernetes | clusters, secrets, identities |
| [`detect-snowflake-bulk-data-egress`](../skills/detection/detect-snowflake-bulk-data-egress) | detection | snowflake | warehouse, queries, external-stages, identities |
| [`detect-system-prompt-extraction`](../skills/detection/detect-system-prompt-extraction) | detection | mcp | agent-tools, tool-results, prompts, instructions |
| [`detect-tool-output-exfiltration-instructions`](../skills/detection/detect-tool-output-exfiltration-instructions) | detection | mcp | agent-tools, tool-results, instructions, artifacts |
| [`detect-tool-output-policy-bypass`](../skills/detection/detect-tool-output-policy-bypass) | detection | mcp | agent-tools, tool-results, instructions, approvals |
| [`detect-web-auth-failures`](../skills/detection/detect-web-auth-failures) | detection | multi | http-access-logs, authentication, sessions, mfa |
| [`detect-web-broken-access-control`](../skills/detection/detect-web-broken-access-control) | detection | multi | http-access-logs, api-gateway, web-apps, identities |
| [`detect-web-injection`](../skills/detection/detect-web-injection) | detection | multi | http-access-logs, api-gateway, web-apps, request-payloads |
| [`discover-cloud-control-evidence`](../skills/discovery/discover-cloud-control-evidence) | discovery | aws, azure, gcp, multi | evidence, inventory, network-segmentation, logging, encryption, key-management, ai-endpoints |
| [`discover-control-evidence`](../skills/discovery/discover-control-evidence) | discovery | multi | evidence, inventory, ai-endpoints |
| [`discover-environment`](../skills/discovery/discover-environment) | discovery | aws, azure, gcp, kubernetes, containers, multi | inventory, compute, storage, network, logging, clusters, ai-endpoints |
| [`ingest-azure-activity-ocsf`](../skills/ingestion/ingest-azure-activity-ocsf) | ingestion | azure | api, audit-logs |
| [`ingest-azure-defender-for-cloud-ocsf`](../skills/ingestion/ingest-azure-defender-for-cloud-ocsf) | ingestion | azure | findings, security-posture |
| [`ingest-cloudtrail-ocsf`](../skills/ingestion/ingest-cloudtrail-ocsf) | ingestion | aws | iam, api, audit-logs |
| [`ingest-entra-directory-audit-ocsf`](../skills/ingestion/ingest-entra-directory-audit-ocsf) | ingestion | azure, entra, microsoft-graph | identities, applications, service-principals, federated-credentials, audit-logs |
| [`ingest-gcp-audit-ocsf`](../skills/ingestion/ingest-gcp-audit-ocsf) | ingestion | gcp | api, audit-logs |
| [`ingest-gcp-scc-ocsf`](../skills/ingestion/ingest-gcp-scc-ocsf) | ingestion | gcp | findings, security-posture |
| [`ingest-google-workspace-login-ocsf`](../skills/ingestion/ingest-google-workspace-login-ocsf) | ingestion | google-workspace | identities, authentication, mfa, sessions, audit-logs |
| [`ingest-guardduty-ocsf`](../skills/ingestion/ingest-guardduty-ocsf) | ingestion | aws | findings, threat-detections |
| [`ingest-k8s-audit-ocsf`](../skills/ingestion/ingest-k8s-audit-ocsf) | ingestion | kubernetes | clusters, audit-logs, identities |
| [`ingest-mcp-proxy-ocsf`](../skills/ingestion/ingest-mcp-proxy-ocsf) | ingestion | mcp, multi | agent-tools, application-activity |
| [`ingest-nsg-flow-logs-azure-ocsf`](../skills/ingestion/ingest-nsg-flow-logs-azure-ocsf) | ingestion | azure | network, flow-logs |
| [`ingest-okta-system-log-ocsf`](../skills/ingestion/ingest-okta-system-log-ocsf) | ingestion | okta | identities, authentication, user-access, groups, applications, audit-logs |
| [`ingest-security-hub-ocsf`](../skills/ingestion/ingest-security-hub-ocsf) | ingestion | aws | findings, security-posture |
| [`ingest-vpc-flow-logs-gcp-ocsf`](../skills/ingestion/ingest-vpc-flow-logs-gcp-ocsf) | ingestion | gcp | network, flow-logs |
| [`ingest-vpc-flow-logs-ocsf`](../skills/ingestion/ingest-vpc-flow-logs-ocsf) | ingestion | aws | network, flow-logs |
| [`source-databricks-query`](../skills/ingestion/source-databricks-query) | ingestion | databricks | lakehouse, query-results, audit-logs |
| [`source-s3-select`](../skills/ingestion/source-s3-select) | ingestion | aws | object-storage, query-results, audit-logs |
| [`source-snowflake-query`](../skills/ingestion/source-snowflake-query) | ingestion | snowflake | lakehouse, query-results, audit-logs |
| [`sink-clickhouse-jsonl`](../skills/output/sink-clickhouse-jsonl) | output | clickhouse | findings, evidence, audit-logs, lakehouse |
| [`sink-s3-jsonl`](../skills/output/sink-s3-jsonl) | output | aws | findings, evidence, audit-logs, object-storage |
| [`sink-snowflake-jsonl`](../skills/output/sink-snowflake-jsonl) | output | snowflake | findings, evidence, audit-logs, lakehouse |
| [`convert-ocsf-to-mermaid-attack-flow`](../skills/view/convert-ocsf-to-mermaid-attack-flow) | view | multi | findings, review-output, graphs |
| [`convert-ocsf-to-sarif`](../skills/view/convert-ocsf-to-sarif) | view | multi | findings, review-output |

### MITRE ATT&CK (v14)

- Registry id: `mitre-attack-v14`
- Providers in scope: aws, azure, gcp, kubernetes, containers, mcp
- Asset classes in scope: identities, api, network, clusters, containers, findings
- Coverage target: 100% mapped coverage

Shipped skills mapped: **53**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-aws-access-key-creation`](../skills/detection/detect-aws-access-key-creation) | detection | aws | iam-users, access-keys, credentials, cloudtrail |
| [`detect-aws-enumeration-burst`](../skills/detection/detect-aws-enumeration-burst) | detection | aws | identities, compute, storage, network, organizations, cloudtrail |
| [`detect-aws-login-profile-creation`](../skills/detection/detect-aws-login-profile-creation) | detection | aws | iam-users, login-profiles, credentials, cloudtrail |
| [`detect-aws-model-artifact-download`](../skills/detection/detect-aws-model-artifact-download) | detection | aws | object-storage, objects, model-artifacts, audit-logs |
| [`detect-aws-open-security-group`](../skills/detection/detect-aws-open-security-group) | detection | aws | security-groups, ingress-rules, cloudtrail |
| [`detect-azure-activity-logs-disabled`](../skills/detection/detect-azure-activity-logs-disabled) | detection | azure | activity-logs, diagnostic-settings, logging |
| [`detect-azure-open-nsg`](../skills/detection/detect-azure-open-nsg) | detection | azure | network-security-groups, ingress-rules, azure-activity |
| [`detect-cloudtrail-disabled`](../skills/detection/detect-cloudtrail-disabled) | detection | aws | cloudtrail, audit-trails, logging |
| [`detect-container-escape-k8s`](../skills/detection/detect-container-escape-k8s) | detection | kubernetes | clusters, containers, runtime |
| [`detect-credential-stuffing-okta`](../skills/detection/detect-credential-stuffing-okta) | detection | okta | identities, authentication, sessions |
| [`detect-entra-credential-addition`](../skills/detection/detect-entra-credential-addition) | detection | azure, entra, microsoft-graph | identities, applications, service-principals, federated-credentials |
| [`detect-entra-role-grant-escalation`](../skills/detection/detect-entra-role-grant-escalation) | detection | azure, entra, microsoft-graph | identities, applications, service-principals, app-role-assignments |
| [`detect-gcp-audit-logs-disabled`](../skills/detection/detect-gcp-audit-logs-disabled) | detection | gcp | audit-logs, logging-sinks, log-streams |
| [`detect-gcp-model-artifact-download`](../skills/detection/detect-gcp-model-artifact-download) | detection | gcp | object-storage, objects, model-artifacts, audit-logs |
| [`detect-gcp-open-firewall`](../skills/detection/detect-gcp-open-firewall) | detection | gcp | vpc-firewall-rules, ingress-rules, cloud-audit-logs |
| [`detect-gcp-service-account-key-creation`](../skills/detection/detect-gcp-service-account-key-creation) | detection | gcp | identities, service-accounts, credentials, audit-logs |
| [`detect-gcp-service-account-token-minting`](../skills/detection/detect-gcp-service-account-token-minting) | detection | gcp | identities, service-accounts, credentials, audit-logs |
| [`detect-google-workspace-suspicious-login`](../skills/detection/detect-google-workspace-suspicious-login) | detection | google-workspace | identities, authentication, sessions, mfa |
| [`detect-lateral-movement`](../skills/detection/detect-lateral-movement) | detection | aws, azure, gcp, multi | iam-roles, role-sessions, applications, service-accounts, service-account-keys, iam-credentials, service-principals, managed-identities, federated-credentials, app-role-assignments, sessions, api, network |
| [`detect-mcp-tool-drift`](../skills/detection/detect-mcp-tool-drift) | detection | mcp, multi | agent-tools, supply-chain, tool-metadata |
| [`detect-okta-mfa-fatigue`](../skills/detection/detect-okta-mfa-fatigue) | detection | okta | identities, authentication, mfa, sessions |
| [`detect-privilege-escalation-k8s`](../skills/detection/detect-privilege-escalation-k8s) | detection | kubernetes | clusters, containers, identities, secrets |
| [`detect-s3-cross-account-copy`](../skills/detection/detect-s3-cross-account-copy) | detection | aws | storage, buckets, objects, identities, cloudtrail |
| [`detect-sensitive-secret-read-k8s`](../skills/detection/detect-sensitive-secret-read-k8s) | detection | kubernetes | clusters, secrets, identities |
| [`detect-snowflake-bulk-data-egress`](../skills/detection/detect-snowflake-bulk-data-egress) | detection | snowflake | warehouse, queries, external-stages, identities |
| [`detect-web-auth-failures`](../skills/detection/detect-web-auth-failures) | detection | multi | http-access-logs, authentication, sessions, mfa |
| [`detect-web-broken-access-control`](../skills/detection/detect-web-broken-access-control) | detection | multi | http-access-logs, api-gateway, web-apps, identities |
| [`detect-web-injection`](../skills/detection/detect-web-injection) | detection | multi | http-access-logs, api-gateway, web-apps, request-payloads |
| [`discover-cloud-control-evidence`](../skills/discovery/discover-cloud-control-evidence) | discovery | aws, azure, gcp, multi | evidence, inventory, network-segmentation, logging, encryption, key-management, ai-endpoints |
| [`discover-environment`](../skills/discovery/discover-environment) | discovery | aws, azure, gcp, kubernetes, containers, multi | inventory, compute, storage, network, logging, clusters, ai-endpoints |
| [`iam-departures-reconciler`](../skills/discovery/iam-departures-reconciler) | discovery | multi, snowflake, databricks, clickhouse, workday | identities, hr-events, manifests, warehouse-joins |
| [`gpu-cluster-security`](../skills/evaluation/gpu-cluster-security) | evaluation | aws, azure, gcp, kubernetes, containers, multi | gpu-fleets, clusters, containers, runtime, tenancy |
| [`ingest-azure-defender-for-cloud-ocsf`](../skills/ingestion/ingest-azure-defender-for-cloud-ocsf) | ingestion | azure | findings, security-posture |
| [`ingest-cloudtrail-ocsf`](../skills/ingestion/ingest-cloudtrail-ocsf) | ingestion | aws | iam, api, audit-logs |
| [`ingest-entra-directory-audit-ocsf`](../skills/ingestion/ingest-entra-directory-audit-ocsf) | ingestion | azure, entra, microsoft-graph | identities, applications, service-principals, federated-credentials, audit-logs |
| [`ingest-gcp-scc-ocsf`](../skills/ingestion/ingest-gcp-scc-ocsf) | ingestion | gcp | findings, security-posture |
| [`ingest-guardduty-ocsf`](../skills/ingestion/ingest-guardduty-ocsf) | ingestion | aws | findings, threat-detections |
| [`ingest-k8s-audit-ocsf`](../skills/ingestion/ingest-k8s-audit-ocsf) | ingestion | kubernetes | clusters, audit-logs, identities |
| [`ingest-security-hub-ocsf`](../skills/ingestion/ingest-security-hub-ocsf) | ingestion | aws | findings, security-posture |
| [`iam-departures-aws`](../skills/remediation/iam-departures-aws) | remediation | aws, snowflake, databricks, clickhouse | identities, access, audit, hr-events |
| [`iam-departures-azure-entra`](../skills/remediation/iam-departures-azure-entra) | remediation | azure | identities, access, audit, hr-events |
| [`iam-departures-gcp`](../skills/remediation/iam-departures-gcp) | remediation | gcp | identities, access, audit, hr-events |
| [`remediate-aws-sg-revoke`](../skills/remediation/remediate-aws-sg-revoke) | remediation | aws | security-groups, ingress-rules, audit |
| [`remediate-azure-nsg-revoke`](../skills/remediation/remediate-azure-nsg-revoke) | remediation | azure | network-security-groups, ingress-rules, audit |
| [`remediate-container-escape-k8s`](../skills/remediation/remediate-container-escape-k8s) | remediation | kubernetes | pods, workloads, networkpolicy, audit |
| [`remediate-entra-credential-revoke`](../skills/remediation/remediate-entra-credential-revoke) | remediation | azure, entra | service-principals, applications, credentials, role-assignments, audit |
| [`remediate-gcp-firewall-revoke`](../skills/remediation/remediate-gcp-firewall-revoke) | remediation | gcp | vpc-firewall-rules, ingress-rules, audit |
| [`remediate-k8s-rbac-revoke`](../skills/remediation/remediate-k8s-rbac-revoke) | remediation | kubernetes | rolebindings, clusterrolebindings, rbac, audit |
| [`remediate-mcp-tool-quarantine`](../skills/remediation/remediate-mcp-tool-quarantine) | remediation | mcp | mcp-tools, quarantine-list, audit |
| [`remediate-okta-session-kill`](../skills/remediation/remediate-okta-session-kill) | remediation | okta | identities, sessions, oauth-tokens, audit |
| [`remediate-workspace-session-kill`](../skills/remediation/remediate-workspace-session-kill) | remediation | google-workspace | users, sessions, audit |
| [`convert-ocsf-to-mermaid-attack-flow`](../skills/view/convert-ocsf-to-mermaid-attack-flow) | view | multi | findings, review-output, graphs |
| [`convert-ocsf-to-sarif`](../skills/view/convert-ocsf-to-sarif) | view | multi | findings, review-output |

### MITRE ATLAS (current)

- Registry id: `mitre-atlas`
- Providers in scope: aws, azure, gcp
- Asset classes in scope: ai-endpoints, models, datasets, vector-stores, gpu-fleets, evidence
- Coverage target: 100% mapped coverage

Shipped skills mapped: **13**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-aws-model-artifact-download`](../skills/detection/detect-aws-model-artifact-download) | detection | aws | object-storage, objects, model-artifacts, audit-logs |
| [`detect-gcp-model-artifact-download`](../skills/detection/detect-gcp-model-artifact-download) | detection | gcp | object-storage, objects, model-artifacts, audit-logs |
| [`detect-prompt-injection-mcp-proxy`](../skills/detection/detect-prompt-injection-mcp-proxy) | detection | mcp, multi | agent-tools, tool-metadata, guardrails |
| [`detect-system-prompt-extraction`](../skills/detection/detect-system-prompt-extraction) | detection | mcp | agent-tools, tool-results, prompts, instructions |
| [`detect-tool-output-exfiltration-instructions`](../skills/detection/detect-tool-output-exfiltration-instructions) | detection | mcp | agent-tools, tool-results, instructions, artifacts |
| [`detect-tool-output-policy-bypass`](../skills/detection/detect-tool-output-policy-bypass) | detection | mcp | agent-tools, tool-results, instructions, approvals |
| [`discover-ai-bom`](../skills/discovery/discover-ai-bom) | discovery | aws, azure, gcp, multi | inventory, ai-endpoints, models, datasets, vector-stores, gpu-fleets |
| [`discover-cloud-control-evidence`](../skills/discovery/discover-cloud-control-evidence) | discovery | aws, azure, gcp, multi | evidence, inventory, network-segmentation, logging, encryption, key-management, ai-endpoints |
| [`discover-control-evidence`](../skills/discovery/discover-control-evidence) | discovery | multi | evidence, inventory, ai-endpoints |
| [`discover-environment`](../skills/discovery/discover-environment) | discovery | aws, azure, gcp, kubernetes, containers, multi | inventory, compute, storage, network, logging, clusters, ai-endpoints |
| [`gpu-cluster-security`](../skills/evaluation/gpu-cluster-security) | evaluation | aws, azure, gcp, kubernetes, containers, multi | gpu-fleets, clusters, containers, runtime, tenancy |
| [`model-serving-security`](../skills/evaluation/model-serving-security) | evaluation | aws, azure, gcp, multi | ai-endpoints, models, identities, network, logging, guardrails |
| [`remediate-mcp-tool-quarantine`](../skills/remediation/remediate-mcp-tool-quarantine) | remediation | mcp | mcp-tools, quarantine-list, audit |

### CIS AWS Foundations (v3.0)

- Registry id: `cis-aws-v3`

Shipped skills mapped: **4**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-aws-open-security-group`](../skills/detection/detect-aws-open-security-group) | detection | aws | security-groups, ingress-rules, cloudtrail |
| [`detect-cloudtrail-disabled`](../skills/detection/detect-cloudtrail-disabled) | detection | aws | cloudtrail, audit-trails, logging |
| [`cspm-aws-cis-benchmark`](../skills/evaluation/cspm-aws-cis-benchmark) | evaluation | aws | identities, storage, logging, network |
| [`remediate-aws-sg-revoke`](../skills/remediation/remediate-aws-sg-revoke) | remediation | aws | security-groups, ingress-rules, audit |

### CIS GCP Foundations (v3.0)

- Registry id: `cis-gcp-v3`

Shipped skills mapped: **5**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-gcp-audit-logs-disabled`](../skills/detection/detect-gcp-audit-logs-disabled) | detection | gcp | audit-logs, logging-sinks, log-streams |
| [`detect-gcp-open-firewall`](../skills/detection/detect-gcp-open-firewall) | detection | gcp | vpc-firewall-rules, ingress-rules, cloud-audit-logs |
| [`cspm-gcp-cis-benchmark`](../skills/evaluation/cspm-gcp-cis-benchmark) | evaluation | gcp | identities, storage, logging, network |
| [`iam-departures-gcp`](../skills/remediation/iam-departures-gcp) | remediation | gcp | identities, access, audit, hr-events |
| [`remediate-gcp-firewall-revoke`](../skills/remediation/remediate-gcp-firewall-revoke) | remediation | gcp | vpc-firewall-rules, ingress-rules, audit |

### CIS Azure Foundations (v2.1)

- Registry id: `cis-azure-v2.1`

Shipped skills mapped: **6**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-azure-activity-logs-disabled`](../skills/detection/detect-azure-activity-logs-disabled) | detection | azure | activity-logs, diagnostic-settings, logging |
| [`detect-azure-open-nsg`](../skills/detection/detect-azure-open-nsg) | detection | azure | network-security-groups, ingress-rules, azure-activity |
| [`cspm-azure-cis-benchmark`](../skills/evaluation/cspm-azure-cis-benchmark) | evaluation | azure | identities, storage, logging, network |
| [`iam-departures-azure-entra`](../skills/remediation/iam-departures-azure-entra) | remediation | azure | identities, access, audit, hr-events |
| [`remediate-azure-nsg-revoke`](../skills/remediation/remediate-azure-nsg-revoke) | remediation | azure | network-security-groups, ingress-rules, audit |
| [`remediate-entra-credential-revoke`](../skills/remediation/remediate-entra-credential-revoke) | remediation | azure, entra | service-principals, applications, credentials, role-assignments, audit |

### CIS Kubernetes Benchmark (current)

- Registry id: `cis-k8s`

Shipped skills mapped: **2**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`gpu-cluster-security`](../skills/evaluation/gpu-cluster-security) | evaluation | aws, azure, gcp, kubernetes, containers, multi | gpu-fleets, clusters, containers, runtime, tenancy |
| [`k8s-security-benchmark`](../skills/evaluation/k8s-security-benchmark) | evaluation | kubernetes | clusters, identities, network, logging |

### CIS Docker Benchmark (current)

- Registry id: `cis-docker`

Shipped skills mapped: **1**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`container-security`](../skills/evaluation/container-security) | evaluation | containers | containers, runtime, images |

### CIS Controls (v8)

- Registry id: `cis-controls-v8`

Shipped skills mapped: **2**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`gpu-cluster-security`](../skills/evaluation/gpu-cluster-security) | evaluation | aws, azure, gcp, kubernetes, containers, multi | gpu-fleets, clusters, containers, runtime, tenancy |
| [`iam-departures-aws`](../skills/remediation/iam-departures-aws) | remediation | aws, snowflake, databricks, clickhouse | identities, access, audit, hr-events |

### NIST CSF (2.0)

- Registry id: `nist-csf-2.0`
- Providers in scope: aws, azure, gcp, kubernetes, containers, multi
- Asset classes in scope: identities, storage, logging, network, clusters, runtime, evidence
- Coverage target: 100% mapped coverage

Shipped skills mapped: **20**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`discover-environment`](../skills/discovery/discover-environment) | discovery | aws, azure, gcp, kubernetes, containers, multi | inventory, compute, storage, network, logging, clusters, ai-endpoints |
| [`container-security`](../skills/evaluation/container-security) | evaluation | containers | containers, runtime, images |
| [`cspm-aws-cis-benchmark`](../skills/evaluation/cspm-aws-cis-benchmark) | evaluation | aws | identities, storage, logging, network |
| [`cspm-azure-cis-benchmark`](../skills/evaluation/cspm-azure-cis-benchmark) | evaluation | azure | identities, storage, logging, network |
| [`cspm-gcp-cis-benchmark`](../skills/evaluation/cspm-gcp-cis-benchmark) | evaluation | gcp | identities, storage, logging, network |
| [`gpu-cluster-security`](../skills/evaluation/gpu-cluster-security) | evaluation | aws, azure, gcp, kubernetes, containers, multi | gpu-fleets, clusters, containers, runtime, tenancy |
| [`k8s-security-benchmark`](../skills/evaluation/k8s-security-benchmark) | evaluation | kubernetes | clusters, identities, network, logging |
| [`model-serving-security`](../skills/evaluation/model-serving-security) | evaluation | aws, azure, gcp, multi | ai-endpoints, models, identities, network, logging, guardrails |
| [`iam-departures-aws`](../skills/remediation/iam-departures-aws) | remediation | aws, snowflake, databricks, clickhouse | identities, access, audit, hr-events |
| [`iam-departures-azure-entra`](../skills/remediation/iam-departures-azure-entra) | remediation | azure | identities, access, audit, hr-events |
| [`iam-departures-gcp`](../skills/remediation/iam-departures-gcp) | remediation | gcp | identities, access, audit, hr-events |
| [`remediate-aws-sg-revoke`](../skills/remediation/remediate-aws-sg-revoke) | remediation | aws | security-groups, ingress-rules, audit |
| [`remediate-azure-nsg-revoke`](../skills/remediation/remediate-azure-nsg-revoke) | remediation | azure | network-security-groups, ingress-rules, audit |
| [`remediate-container-escape-k8s`](../skills/remediation/remediate-container-escape-k8s) | remediation | kubernetes | pods, workloads, networkpolicy, audit |
| [`remediate-entra-credential-revoke`](../skills/remediation/remediate-entra-credential-revoke) | remediation | azure, entra | service-principals, applications, credentials, role-assignments, audit |
| [`remediate-gcp-firewall-revoke`](../skills/remediation/remediate-gcp-firewall-revoke) | remediation | gcp | vpc-firewall-rules, ingress-rules, audit |
| [`remediate-k8s-rbac-revoke`](../skills/remediation/remediate-k8s-rbac-revoke) | remediation | kubernetes | rolebindings, clusterrolebindings, rbac, audit |
| [`remediate-mcp-tool-quarantine`](../skills/remediation/remediate-mcp-tool-quarantine) | remediation | mcp | mcp-tools, quarantine-list, audit |
| [`remediate-okta-session-kill`](../skills/remediation/remediate-okta-session-kill) | remediation | okta | identities, sessions, oauth-tokens, audit |
| [`remediate-workspace-session-kill`](../skills/remediation/remediate-workspace-session-kill) | remediation | google-workspace | users, sessions, audit |

### NIST AI RMF (current)

- Registry id: `nist-ai-rmf`

Shipped skills mapped: **4**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`discover-ai-bom`](../skills/discovery/discover-ai-bom) | discovery | aws, azure, gcp, multi | inventory, ai-endpoints, models, datasets, vector-stores, gpu-fleets |
| [`discover-cloud-control-evidence`](../skills/discovery/discover-cloud-control-evidence) | discovery | aws, azure, gcp, multi | evidence, inventory, network-segmentation, logging, encryption, key-management, ai-endpoints |
| [`gpu-cluster-security`](../skills/evaluation/gpu-cluster-security) | evaluation | aws, azure, gcp, kubernetes, containers, multi | gpu-fleets, clusters, containers, runtime, tenancy |
| [`model-serving-security`](../skills/evaluation/model-serving-security) | evaluation | aws, azure, gcp, multi | ai-endpoints, models, identities, network, logging, guardrails |

### SOC 2 TSC (current)

- Registry id: `soc2-tsc`
- Providers in scope: aws, azure, gcp, multi
- Asset classes in scope: access, logging, change, evidence, inventory, ai-endpoints
- Coverage target: 100% mapped coverage

Shipped skills mapped: **20**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`discover-ai-bom`](../skills/discovery/discover-ai-bom) | discovery | aws, azure, gcp, multi | inventory, ai-endpoints, models, datasets, vector-stores, gpu-fleets |
| [`discover-cloud-control-evidence`](../skills/discovery/discover-cloud-control-evidence) | discovery | aws, azure, gcp, multi | evidence, inventory, network-segmentation, logging, encryption, key-management, ai-endpoints |
| [`discover-control-evidence`](../skills/discovery/discover-control-evidence) | discovery | multi | evidence, inventory, ai-endpoints |
| [`cspm-aws-cis-benchmark`](../skills/evaluation/cspm-aws-cis-benchmark) | evaluation | aws | identities, storage, logging, network |
| [`model-serving-security`](../skills/evaluation/model-serving-security) | evaluation | aws, azure, gcp, multi | ai-endpoints, models, identities, network, logging, guardrails |
| [`sink-clickhouse-jsonl`](../skills/output/sink-clickhouse-jsonl) | output | clickhouse | findings, evidence, audit-logs, lakehouse |
| [`sink-s3-jsonl`](../skills/output/sink-s3-jsonl) | output | aws | findings, evidence, audit-logs, object-storage |
| [`sink-snowflake-jsonl`](../skills/output/sink-snowflake-jsonl) | output | snowflake | findings, evidence, audit-logs, lakehouse |
| [`iam-departures-aws`](../skills/remediation/iam-departures-aws) | remediation | aws, snowflake, databricks, clickhouse | identities, access, audit, hr-events |
| [`iam-departures-azure-entra`](../skills/remediation/iam-departures-azure-entra) | remediation | azure | identities, access, audit, hr-events |
| [`iam-departures-gcp`](../skills/remediation/iam-departures-gcp) | remediation | gcp | identities, access, audit, hr-events |
| [`remediate-aws-sg-revoke`](../skills/remediation/remediate-aws-sg-revoke) | remediation | aws | security-groups, ingress-rules, audit |
| [`remediate-azure-nsg-revoke`](../skills/remediation/remediate-azure-nsg-revoke) | remediation | azure | network-security-groups, ingress-rules, audit |
| [`remediate-container-escape-k8s`](../skills/remediation/remediate-container-escape-k8s) | remediation | kubernetes | pods, workloads, networkpolicy, audit |
| [`remediate-entra-credential-revoke`](../skills/remediation/remediate-entra-credential-revoke) | remediation | azure, entra | service-principals, applications, credentials, role-assignments, audit |
| [`remediate-gcp-firewall-revoke`](../skills/remediation/remediate-gcp-firewall-revoke) | remediation | gcp | vpc-firewall-rules, ingress-rules, audit |
| [`remediate-k8s-rbac-revoke`](../skills/remediation/remediate-k8s-rbac-revoke) | remediation | kubernetes | rolebindings, clusterrolebindings, rbac, audit |
| [`remediate-mcp-tool-quarantine`](../skills/remediation/remediate-mcp-tool-quarantine) | remediation | mcp | mcp-tools, quarantine-list, audit |
| [`remediate-okta-session-kill`](../skills/remediation/remediate-okta-session-kill) | remediation | okta | identities, sessions, oauth-tokens, audit |
| [`remediate-workspace-session-kill`](../skills/remediation/remediate-workspace-session-kill) | remediation | google-workspace | users, sessions, audit |

### PCI DSS (4.0)

- Registry id: `pci-dss-4.0`
- Providers in scope: aws, azure, gcp, multi
- Asset classes in scope: network, logging, encryption, evidence, inventory
- Coverage target: 100% mapped coverage

Shipped skills mapped: **4**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`discover-ai-bom`](../skills/discovery/discover-ai-bom) | discovery | aws, azure, gcp, multi | inventory, ai-endpoints, models, datasets, vector-stores, gpu-fleets |
| [`discover-cloud-control-evidence`](../skills/discovery/discover-cloud-control-evidence) | discovery | aws, azure, gcp, multi | evidence, inventory, network-segmentation, logging, encryption, key-management, ai-endpoints |
| [`discover-control-evidence`](../skills/discovery/discover-control-evidence) | discovery | multi | evidence, inventory, ai-endpoints |
| [`cspm-aws-cis-benchmark`](../skills/evaluation/cspm-aws-cis-benchmark) | evaluation | aws | identities, storage, logging, network |

### ISO 27001 (2022)

- Registry id: `iso-27001-2022`

Shipped skills mapped: **3**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`cspm-aws-cis-benchmark`](../skills/evaluation/cspm-aws-cis-benchmark) | evaluation | aws | identities, storage, logging, network |
| [`cspm-azure-cis-benchmark`](../skills/evaluation/cspm-azure-cis-benchmark) | evaluation | azure | identities, storage, logging, network |
| [`cspm-gcp-cis-benchmark`](../skills/evaluation/cspm-gcp-cis-benchmark) | evaluation | gcp | identities, storage, logging, network |

### OWASP Top 10 (2021)

- Registry id: `owasp-top-10`

Shipped skills mapped: **4**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-snowflake-bulk-data-egress`](../skills/detection/detect-snowflake-bulk-data-egress) | detection | snowflake | warehouse, queries, external-stages, identities |
| [`detect-web-auth-failures`](../skills/detection/detect-web-auth-failures) | detection | multi | http-access-logs, authentication, sessions, mfa |
| [`detect-web-broken-access-control`](../skills/detection/detect-web-broken-access-control) | detection | multi | http-access-logs, api-gateway, web-apps, identities |
| [`detect-web-injection`](../skills/detection/detect-web-injection) | detection | multi | http-access-logs, api-gateway, web-apps, request-payloads |

### OWASP LLM Top 10 (current)

- Registry id: `owasp-llm-top-10`

Shipped skills mapped: **8**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-agent-credential-leak-mcp`](../skills/detection/detect-agent-credential-leak-mcp) | detection | mcp, multi | agent-tools, tool-results, credentials |
| [`detect-aws-model-artifact-download`](../skills/detection/detect-aws-model-artifact-download) | detection | aws | object-storage, objects, model-artifacts, audit-logs |
| [`detect-gcp-model-artifact-download`](../skills/detection/detect-gcp-model-artifact-download) | detection | gcp | object-storage, objects, model-artifacts, audit-logs |
| [`detect-prompt-injection-mcp-proxy`](../skills/detection/detect-prompt-injection-mcp-proxy) | detection | mcp, multi | agent-tools, tool-metadata, guardrails |
| [`detect-system-prompt-extraction`](../skills/detection/detect-system-prompt-extraction) | detection | mcp | agent-tools, tool-results, prompts, instructions |
| [`detect-tool-output-exfiltration-instructions`](../skills/detection/detect-tool-output-exfiltration-instructions) | detection | mcp | agent-tools, tool-results, instructions, artifacts |
| [`detect-tool-output-policy-bypass`](../skills/detection/detect-tool-output-policy-bypass) | detection | mcp | agent-tools, tool-results, instructions, approvals |
| [`model-serving-security`](../skills/evaluation/model-serving-security) | evaluation | aws, azure, gcp, multi | ai-endpoints, models, identities, network, logging, guardrails |

### OWASP MCP Top 10 (current)

- Registry id: `owasp-mcp-top-10`

Shipped skills mapped: **7**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`detect-agent-credential-leak-mcp`](../skills/detection/detect-agent-credential-leak-mcp) | detection | mcp, multi | agent-tools, tool-results, credentials |
| [`detect-mcp-tool-drift`](../skills/detection/detect-mcp-tool-drift) | detection | mcp, multi | agent-tools, supply-chain, tool-metadata |
| [`detect-prompt-injection-mcp-proxy`](../skills/detection/detect-prompt-injection-mcp-proxy) | detection | mcp, multi | agent-tools, tool-metadata, guardrails |
| [`detect-tool-output-exfiltration-instructions`](../skills/detection/detect-tool-output-exfiltration-instructions) | detection | mcp | agent-tools, tool-results, instructions, artifacts |
| [`detect-tool-output-policy-bypass`](../skills/detection/detect-tool-output-policy-bypass) | detection | mcp | agent-tools, tool-results, instructions, approvals |
| [`ingest-mcp-proxy-ocsf`](../skills/ingestion/ingest-mcp-proxy-ocsf) | ingestion | mcp, multi | agent-tools, application-activity |
| [`remediate-mcp-tool-quarantine`](../skills/remediation/remediate-mcp-tool-quarantine) | remediation | mcp | mcp-tools, quarantine-list, audit |

### CycloneDX ML-BOM (current)

- Registry id: `cyclonedx-ml-bom`

Shipped skills mapped: **2**

| Skill | Layer | Providers | Asset classes |
|---|---|---|---|
| [`discover-ai-bom`](../skills/discovery/discover-ai-bom) | discovery | aws, azure, gcp, multi | inventory, ai-endpoints, models, datasets, vector-stores, gpu-fleets |
| [`discover-control-evidence`](../skills/discovery/discover-control-evidence) | discovery | multi | evidence, inventory, ai-endpoints |

## Skills with no framework mapping

_Every shipped skill in the registry references at least one framework._

## How to update

1. Edit [`framework-coverage.json`](framework-coverage.json) with the new framework, skill, or mapping.
2. Run `python scripts/generate_framework_coverage_doc.py` to regenerate this file.
3. Commit both `framework-coverage.json` and `FRAMEWORK_COVERAGE.md` in the same change.
4. CI runs the script in check mode and fails if the generated doc differs from the checked-in version.

