# Skills Catalog

Skills are grouped by **layered function**, not by vendor. Start with the problem you are solving, then pick the layer and skill that match it. If you want a guided entry point instead of a catalog, read [`docs/USE_CASES.md`](../docs/USE_CASES.md) first.

| Category | Question it answers | Default output format |
|---|---|---|
| [`ingestion/`](ingestion/) | "How do I normalize this raw source into a stable event stream?" | **OCSF 1.8** (native opt-in via `--output-format native`) |
| [`discovery/`](discovery/) | "What does this cloud / AI estate look like right now?" | **native / CycloneDX / bridge** (OCSF Inventory Info 5001 is too thin to force) |
| [`detection/`](detection/) | "What attack pattern does this event stream show?" | **OCSF Detection Finding 2004** (native opt-in) |
| [`evaluation/`](evaluation/) | "Does this posture or event stream meet a benchmark?" | **native** by default; OCSF Compliance Finding 2003 opt-in |
| [`view/`](view/) | "How should I render or export this OCSF output?" | **SARIF / Mermaid** — consumer of OCSF |
| [`remediation/`](remediation/) | "Something is wrong. How do I fix it safely?" | **native** (state change + audit record, not a finding) |
| [`output/`](output/) | "Where do these findings / evidence / audit rows persist?" | **pass-through** |

**OCSF is the SIEM interop wire format for ingest + detect — not the universal internal format.** See [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md#3-layer-model) §3.1 for the full applicability discussion.

Every shipped skill follows the [Anthropic skills guide](https://platform.claude.com/docs/en/build-with-claude/skills-guide): `SKILL.md`, `src/`, `tests/`, `REFERENCES.md`, and explicit `Use when...` / `Do NOT use...` routing language.

## ingestion/

Raw source formats to OCSF 1.8 JSONL.

| Skill | Scope |
|---|---|
| [`ingest-cloudtrail-ocsf`](ingestion/ingest-cloudtrail-ocsf/) | AWS CloudTrail |
| [`ingest-aws-config-ocsf`](ingestion/ingest-aws-config-ocsf/) | AWS Config configuration items and compliance changes |
| [`ingest-vpc-flow-logs-ocsf`](ingestion/ingest-vpc-flow-logs-ocsf/) | AWS VPC Flow Logs |
| [`ingest-vpc-flow-logs-gcp-ocsf`](ingestion/ingest-vpc-flow-logs-gcp-ocsf/) | GCP VPC Flow Logs |
| [`ingest-nsg-flow-logs-azure-ocsf`](ingestion/ingest-nsg-flow-logs-azure-ocsf/) | Azure NSG Flow Logs |
| [`ingest-guardduty-ocsf`](ingestion/ingest-guardduty-ocsf/) | AWS GuardDuty |
| [`ingest-security-hub-ocsf`](ingestion/ingest-security-hub-ocsf/) | AWS Security Hub |
| [`ingest-gcp-scc-ocsf`](ingestion/ingest-gcp-scc-ocsf/) | GCP Security Command Center |
| [`ingest-azure-defender-for-cloud-ocsf`](ingestion/ingest-azure-defender-for-cloud-ocsf/) | Azure Defender for Cloud |
| [`ingest-gcp-audit-ocsf`](ingestion/ingest-gcp-audit-ocsf/) | GCP Cloud Audit Logs |
| [`ingest-azure-activity-ocsf`](ingestion/ingest-azure-activity-ocsf/) | Azure Activity Logs |
| [`ingest-entra-directory-audit-ocsf`](ingestion/ingest-entra-directory-audit-ocsf/) | Microsoft Entra / Graph directory audit |
| [`ingest-okta-system-log-ocsf`](ingestion/ingest-okta-system-log-ocsf/) | Okta System Log |
| [`ingest-google-workspace-login-ocsf`](ingestion/ingest-google-workspace-login-ocsf/) | Google Workspace login audit |
| [`ingest-workspace-admin-ocsf`](ingestion/ingest-workspace-admin-ocsf/) | Google Workspace Admin SDK Reports login, token, and admin-role audit |
| [`ingest-github-audit-log-ocsf`](ingestion/ingest-github-audit-log-ocsf/) | GitHub Organization Audit Log |
| [`ingest-slack-audit-ocsf`](ingestion/ingest-slack-audit-ocsf/) | Slack Audit Logs API |
| [`ingest-workday-audit-ocsf`](ingestion/ingest-workday-audit-ocsf/) | Workday REST / RaaS audit reports |
| [`ingest-salesforce-event-mon-ocsf`](ingestion/ingest-salesforce-event-mon-ocsf/) | Salesforce Event Monitoring EventLogFile / REST exports |
| [`ingest-k8s-audit-ocsf`](ingestion/ingest-k8s-audit-ocsf/) | Kubernetes audit logs |
| [`ingest-mcp-proxy-ocsf`](ingestion/ingest-mcp-proxy-ocsf/) | MCP proxy activity |

## detection/

Deterministic OCSF-to-finding rules.

| Skill | MITRE |
|---|---|
| [`detect-lateral-movement`](detection/detect-lateral-movement/) | lateral movement / cross-cloud identity pivot + east-west traffic |
| [`detect-okta-mfa-fatigue`](detection/detect-okta-mfa-fatigue/) | Okta Verify push bombing / MFA fatigue |
| [`detect-credential-stuffing-okta`](detection/detect-credential-stuffing-okta/) | Okta credential stuffing / password spraying burst followed by successful sign-in (T1110.003) |
| [`detect-entra-credential-addition`](detection/detect-entra-credential-addition/) | successful Entra application or service-principal credential additions |
| [`detect-entra-role-grant-escalation`](detection/detect-entra-role-grant-escalation/) | successful Entra app-role grants to service principals |
| [`detect-admin-role-grant-workspace`](detection/detect-admin-role-grant-workspace/) | protected Google Workspace admin role grant outside break-glass allowlist |
| [`detect-google-workspace-suspicious-login`](detection/detect-google-workspace-suspicious-login/) | provider-marked suspicious Workspace login or repeated failures followed by success |
| [`detect-suspicious-oauth-grant-workspace`](detection/detect-suspicious-oauth-grant-workspace/) | Google Workspace OAuth client authorized with high-risk scopes |
| [`detect-mass-termination-anomaly`](detection/detect-mass-termination-anomaly/) | Workday mass-termination spike across a short HR offboarding window |
| [`detect-bulk-export-salesforce`](detection/detect-bulk-export-salesforce/) | Salesforce large export followed by session close |
| [`detect-api-anomaly-salesforce`](detection/detect-api-anomaly-salesforce/) | Salesforce API usage by a user or integration outside baseline |
| [`detect-aws-access-key-creation`](detection/detect-aws-access-key-creation/) | successful AWS IAM `CreateAccessKey` operations against IAM users (T1098.001 Additional Cloud Credentials) |
| [`detect-aws-login-profile-creation`](detection/detect-aws-login-profile-creation/) | successful AWS IAM `CreateLoginProfile` operations against IAM users (T1098.001 Additional Cloud Credentials) |
| [`detect-gcp-service-account-key-creation`](detection/detect-gcp-service-account-key-creation/) | successful GCP IAM `CreateServiceAccountKey` operations against service accounts (T1098.001 Additional Cloud Credentials) |
| [`detect-gcp-service-account-token-minting`](detection/detect-gcp-service-account-token-minting/) | successful GCP IAM Credentials `GenerateAccessToken` / `GenerateIdToken` operations against service accounts (T1098.001 Additional Cloud Credentials) |
| [`detect-aws-enumeration-burst`](detection/detect-aws-enumeration-burst/) | short-window burst of high-signal AWS discovery APIs in CloudTrail (T1526 Cloud Service Discovery) |
| [`detect-aws-model-artifact-download`](detection/detect-aws-model-artifact-download/) | successful AWS S3 `GetObject` downloads of model-weight and checkpoint artifacts (T1530, ATLAS AML.T0035) |
| [`detect-gcp-model-artifact-download`](detection/detect-gcp-model-artifact-download/) | successful GCS `storage.objects.get` downloads of model-weight and checkpoint artifacts (T1530, ATLAS AML.T0035) |
| [`detect-s3-cross-account-copy`](detection/detect-s3-cross-account-copy/) | successful AWS S3 `CopyObject` into another account's bucket-owner context (T1537 Transfer Data to Cloud Account) |
| [`detect-system-prompt-extraction`](detection/detect-system-prompt-extraction/) | explicit system-prompt or hidden-instruction leakage markers in MCP tool-call responses (ATLAS AML.T0004 / AML.T0041) |
| [`detect-tool-output-policy-bypass`](detection/detect-tool-output-policy-bypass/) | explicit policy-bypass, approval-evasion, or user-concealment instructions in MCP tool-call responses (ATLAS AML.T0051) |
| [`detect-tool-output-exfiltration-instructions`](detection/detect-tool-output-exfiltration-instructions/) | explicit exfiltration instructions for conversation history, prompts, files, or secrets in MCP tool-call responses (ATLAS AML.T0051) |
| [`detect-aws-open-security-group`](detection/detect-aws-open-security-group/) | AWS Security Group ingress opened to 0.0.0.0/0 or ::/0 on risky admin / database / cache ports (T1190 Exploit Public-Facing Application) |
| [`detect-azure-open-nsg`](detection/detect-azure-open-nsg/) | Azure NSG inbound rule opened to `*` / `Internet` / `0.0.0.0/0` / `::/0` on risky admin / database / cache ports (T1190 Exploit Public-Facing Application) |
| [`detect-gcp-open-firewall`](detection/detect-gcp-open-firewall/) | GCP VPC firewall rule opened to 0.0.0.0/0 or ::/0 on risky admin / database / cache ports via `compute.firewalls.insert` or `compute.firewalls.patch` (T1190 Exploit Public-Facing Application) |
| [`detect-prompt-injection-mcp-proxy`](detection/detect-prompt-injection-mcp-proxy/) | suspicious prompt-injection language in MCP tool descriptions |
| [`detect-mcp-tool-drift`](detection/detect-mcp-tool-drift/) | T1195.001 |
| [`detect-container-escape-k8s`](detection/detect-container-escape-k8s/) | T1611, T1610, T1613 |
| [`detect-privilege-escalation-k8s`](detection/detect-privilege-escalation-k8s/) | T1552.007, T1611, T1098, T1550.001 |
| [`detect-sensitive-secret-read-k8s`](detection/detect-sensitive-secret-read-k8s/) | secret access / K8s API misuse |

Shared wire-contract docs and frozen fixtures live under [`detection-engineering/`](detection-engineering/). That folder is a shared-assets namespace, not a skill layer.

## discovery/

Read-only inventory, graph, and AI BOM skills.

| Skill | Scope |
|---|---|
| [`discover-environment`](discovery/discover-environment/) | Multi-cloud discovery / graph overlay |
| [`discover-ai-bom`](discovery/discover-ai-bom/) | AI asset inventory → CycloneDX-aligned AI BOM |
| [`discover-control-evidence`](discovery/discover-control-evidence/) | Discovery artifact → PCI / SOC 2 technical evidence JSON |
| [`discover-cloud-control-evidence`](discovery/discover-cloud-control-evidence/) | Cross-cloud inventory → PCI / SOC 2 technical evidence JSON |

## evaluation/

Read-only posture and benchmark evaluation skills.

| Skill | Scope | Checks |
|---|---|---:|
| [`cspm-aws-cis-benchmark`](evaluation/cspm-aws-cis-benchmark/) | AWS | 18 |
| [`evaluate-cis-aws-foundations-ocsf`](evaluation/evaluate-cis-aws-foundations-ocsf/) | AWS Config OCSF | 12 |
| [`cspm-gcp-cis-benchmark`](evaluation/cspm-gcp-cis-benchmark/) | GCP | 7 |
| [`cspm-azure-cis-benchmark`](evaluation/cspm-azure-cis-benchmark/) | Azure | 6 |
| [`k8s-security-benchmark`](evaluation/k8s-security-benchmark/) | Kubernetes | 10 |
| [`container-security`](evaluation/container-security/) | Containers | 8 |
| [`model-serving-security`](evaluation/model-serving-security/) | AI model serving | 20 |
| [`gpu-cluster-security`](evaluation/gpu-cluster-security/) | GPU clusters | 13 |

## view/

OCSF outputs into review- or integration-friendly formats.

| Skill | Output |
|---|---|
| [`convert-ocsf-to-sarif`](view/convert-ocsf-to-sarif/) | SARIF |
| [`convert-ocsf-to-mermaid-attack-flow`](view/convert-ocsf-to-mermaid-attack-flow/) | Mermaid attack flow |

## remediation/

Active fix workflows with dry-run, audit, and guardrails.

| Skill | Scope |
|---|---|
| [`iam-departures-aws`](remediation/iam-departures-aws/) | AWS IAM cleanup for departed employees (per-cloud split for Azure/GCP/Snowflake/Databricks planned; library modules in `src/lambda_worker/clouds/`) |
| [`iam-departures-azure-entra`](remediation/iam-departures-azure-entra/) | Azure Entra ID cleanup for departed employees — 11-step Microsoft Graph + Azure RBAC teardown (disable, revoke sign-in sessions, delete OAuth2 grants, remove from groups + directoryRoles + appRoleAssignments, detach RBAC at subscription + management-group + resource-group scope, remove licenses, audit-tag, soft-delete by default with opt-in `--hard-delete`); 7-day grace period, rehire-aware, protected-UPN deny-list (`admin@*`, `breakglass-*`, `emergency-*`, `sync_*`), `IAM_DEPARTURES_AZURE_INCIDENT_ID` + `IAM_DEPARTURES_AZURE_APPROVER` HITL gate; dual audit (Cosmos DB + CMK-encrypted Blob Storage); orchestrated by Logic App + Function App + EventGrid (Azure-native equivalent of the AWS Step Function + EventBridge + 2-Lambda flagship) |
| [`iam-departures-gcp`](remediation/iam-departures-gcp/) | GCP / Workspace cleanup for departed employees — 11-step Admin SDK + Cloud IAM teardown (disable Workspace user or delete SA, revoke OAuth tokens, delete SSH keys across project + per-instance metadata, remove from Cloud Identity / Workspace groups, detach project + folder + org IAM, detach BigQuery dataset IAM, revoke GCS bucket IAM, audit-tag via Cloud Audit Logs, final disable/delete); `IAM_DEPARTURES_GCP_INCIDENT_ID` + `IAM_DEPARTURES_GCP_APPROVER` HITL gate; dual audit (Firestore + CMEK-encrypted GCS); orchestrated by Cloud Workflow + Cloud Functions Gen 2 + Eventarc (GCP-native equivalent of the AWS flagship) |
| [`remediate-okta-session-kill`](remediation/remediate-okta-session-kill/) | Okta containment — revoke sessions + OAuth tokens after detect-okta-mfa-fatigue or detect-credential-stuffing-okta; dual-audit, deny-list, declared-incident gate |
| [`remediate-container-escape-k8s`](remediation/remediate-container-escape-k8s/) | Kubernetes containment — default deny-all NetworkPolicy quarantine plus explicit `--approve-pod-kill` and dual-approved `--approve-node-drain` follow-ups after detect-container-escape-k8s; protected-namespace deny-list, declared-incident gate, dual audit |
| [`remediate-k8s-rbac-revoke`](remediation/remediate-k8s-rbac-revoke/) | Kubernetes RBAC revocation — delete or re-verify the offending RoleBinding / ClusterRoleBinding after detect-privilege-escalation-k8s rule r3-rbac-self-grant; protected-namespace + system:* deny-list, declared-incident gate, dual audit |
| [`remediate-mcp-tool-quarantine`](remediation/remediate-mcp-tool-quarantine/) | MCP tool quarantine — append the offending tool to a JSONL quarantine file the operator's MCP client filters its surface against, after detect-mcp-tool-drift (T1195.001) or detect-prompt-injection-mcp-proxy (ATLAS AML.T0051); protected-prefix (`mcp_`, `system_`, `internal_`) deny-list, declared-incident gate, dual audit |
| [`remediate-entra-credential-revoke`](remediation/remediate-entra-credential-revoke/) | Entra service-principal containment — disable the SP (`accountEnabled=false`) and emit a triage payload listing current credentials + role assignments for operator selective revocation, after detect-entra-credential-addition (T1098.001) or detect-entra-role-grant-escalation (T1098.003); protected name-prefix + objectId deny-list, declared-incident gate, dual audit |
| [`remediate-workspace-session-kill`](remediation/remediate-workspace-session-kill/) | Google Workspace containment — sign out the user (`Users.signOut`) + force password change (`Users.patch changePasswordAtNextLogin`) after detect-google-workspace-suspicious-login (T1110, T1078); dual-audit, deny-list (admin/break-glass/@google.com + extensible), declared-incident gate; reverify reads Admin SDK Reports for any login_success since remediation |
| [`remediate-aws-sg-revoke`](remediation/remediate-aws-sg-revoke/) | AWS Security Group surgical revoke — `RevokeSecurityGroupIngress` for the specific cidr+port flagged by detect-aws-open-security-group (T1190); deny-list (`default*` SG names + `intentionally-open` tag + env-pinned sg ids), declared-incident gate, dual audit; reverify re-reads via `DescribeSecurityGroups` and emits OCSF Detection Finding on DRIFT |
| [`remediate-azure-nsg-revoke`](remediation/remediate-azure-nsg-revoke/) | Azure NSG surgical revoke — `security_rules.begin_delete()` (default) or `--mode patch` to `access=Deny` for the specific rule flagged by detect-azure-open-nsg (T1190); deny-list (`default*`/`Default*` rule names + `*-protected` NSG names + `intentionally-open` parent-NSG tag + env-pinned rule ids), declared-incident gate, dual audit; reverify re-reads via `security_rules.get()` and emits OCSF Detection Finding on DRIFT |
| [`remediate-gcp-firewall-revoke`](remediation/remediate-gcp-firewall-revoke/) | GCP VPC firewall surgical revoke — `compute.firewalls.patch` setting `disabled: true` (default safe `--mode patch`) or `compute.firewalls.delete` (`--mode delete`) for the specific rule flagged by detect-gcp-open-firewall (T1190); deny-list (`default-*` rule names + `intentionally-open` description marker + env-pinned rule names), declared-incident gate, dual audit; reverify re-reads via `compute.firewalls.get` and emits OCSF Detection Finding on DRIFT |

## output/

Append-only persistence sinks for findings, evidence, and audit rows. Pure writers — no identity or cloud-config mutation, no re-shaping of the payload. Kept distinct from `remediation/` so the "skills are pure, edges have side effects" layering stays honest.

| Skill | Target |
|---|---|
| [`sink-s3-jsonl`](output/sink-s3-jsonl/) | Amazon S3 (immutable JSONL objects) |
| [`sink-snowflake-jsonl`](output/sink-snowflake-jsonl/) | Snowflake (staged COPY) |
| [`sink-clickhouse-jsonl`](output/sink-clickhouse-jsonl/) | ClickHouse (batched INSERT) |

## How to add a new skill

1. Pick the layer that matches the work.
2. Copy the nearest sibling in that layer as your reference layout.
3. Write `SKILL.md` with spec-compliant frontmatter. Name must be `^[a-z0-9-]+$`.
4. Lead the description with "Use when…" and close with "Do NOT use…".
5. Add tests. Detection, evaluation, and view skills should use the pinned OCSF contract and frozen fixtures where relevant.
6. Register the skill in the appropriate CI matrix and the top-level docs.
