# Skill index — find a skill fast

The same 81 skill bundles, pivoted three ways:

1. **[By environment](#by-environment)** — pick a cloud or platform, see every skill that touches it.
2. **[By purpose](#by-purpose)** — pick a layer (ingest / discover / detect / evaluate / remediate / view / output / source).
3. **[By framework](#by-framework)** — pick a control catalog (CIS / NIST / MITRE ATT&CK / ATLAS / OWASP / OCSF).

Each row is a directory under [`skills/`](../skills/). The `SKILL.md` in each
directory is the single source of truth for what the skill does, what it does
not do, and what it talks to.

> Counts are auto-validated by `scripts/validate_count_drift.sh`. If a row
> moves, the count check fails CI until this index is regenerated.

## By environment

### AWS — 14 skills

| Layer | Skill | What it does |
|---|---|---|
| Ingest | [`ingest-cloudtrail-ocsf`](../skills/ingestion/ingest-cloudtrail-ocsf/) | CloudTrail → OCSF 1.8 API Activity 6003 |
| Ingest | [`ingest-guardduty-ocsf`](../skills/ingestion/ingest-guardduty-ocsf/) | GuardDuty findings → OCSF Detection Finding 2004 |
| Ingest | [`ingest-security-hub-ocsf`](../skills/ingestion/ingest-security-hub-ocsf/) | Security Hub findings → OCSF |
| Ingest | [`ingest-vpc-flow-logs-ocsf`](../skills/ingestion/ingest-vpc-flow-logs-ocsf/) | VPC Flow Logs → OCSF Network Activity |
| Detect | [`detect-aws-access-key-creation`](../skills/detection/detect-aws-access-key-creation/) | T1098.001 — IAM CreateAccessKey on a user |
| Detect | [`detect-aws-enumeration-burst`](../skills/detection/detect-aws-enumeration-burst/) | T1087 — discovery-burst against IAM/EC2/S3 |
| Detect | [`detect-aws-login-profile-creation`](../skills/detection/detect-aws-login-profile-creation/) | T1098.001 — IAM CreateLoginProfile (console password) |
| Detect | [`detect-aws-model-artifact-download`](../skills/detection/detect-aws-model-artifact-download/) | ATLAS AML.T0040 — model exfil via S3 |
| Detect | [`detect-aws-open-security-group`](../skills/detection/detect-aws-open-security-group/) | T1190 — 0.0.0.0/0 added to a security group |
| Detect | [`detect-cloudtrail-disabled`](../skills/detection/detect-cloudtrail-disabled/) | T1562.001 — CloudTrail StopLogging / DeleteTrail |
| Detect | [`detect-s3-cross-account-copy`](../skills/detection/detect-s3-cross-account-copy/) | T1537 — S3 cross-account exfiltration |
| Evaluate | [`cspm-aws-cis-benchmark`](../skills/evaluation/cspm-aws-cis-benchmark/) | CIS AWS Foundations v3 — 50% control coverage |
| Remediate | [`iam-departures-aws`](../skills/remediation/iam-departures-aws/) | HITL — disable / delete IAM users on departure |
| Remediate | [`remediate-aws-sg-revoke`](../skills/remediation/remediate-aws-sg-revoke/) | HITL — revoke open SG ingress, dry-run-first |

### GCP — 11 skills

| Layer | Skill | What it does |
|---|---|---|
| Ingest | [`ingest-gcp-audit-ocsf`](../skills/ingestion/ingest-gcp-audit-ocsf/) | GCP Cloud Audit → OCSF API Activity 6003 |
| Ingest | [`ingest-gcp-scc-ocsf`](../skills/ingestion/ingest-gcp-scc-ocsf/) | Security Command Center findings → OCSF |
| Ingest | [`ingest-vpc-flow-logs-gcp-ocsf`](../skills/ingestion/ingest-vpc-flow-logs-gcp-ocsf/) | GCP VPC Flow Logs → OCSF Network Activity |
| Detect | [`detect-gcp-audit-logs-disabled`](../skills/detection/detect-gcp-audit-logs-disabled/) | T1562.001 — `_Default` sink disable / IAM exemption |
| Detect | [`detect-gcp-model-artifact-download`](../skills/detection/detect-gcp-model-artifact-download/) | ATLAS AML.T0040 — Vertex / GCS model exfil |
| Detect | [`detect-gcp-open-firewall`](../skills/detection/detect-gcp-open-firewall/) | T1190 — 0.0.0.0/0 firewall ingress |
| Detect | [`detect-gcp-service-account-key-creation`](../skills/detection/detect-gcp-service-account-key-creation/) | T1098.001 — user-managed SA key issuance |
| Detect | [`detect-gcp-service-account-token-minting`](../skills/detection/detect-gcp-service-account-token-minting/) | T1098.001 — `signJwt` / `generateAccessToken` abuse |
| Evaluate | [`cspm-gcp-cis-benchmark`](../skills/evaluation/cspm-gcp-cis-benchmark/) | CIS GCP Foundations v3 — 30 of 60 controls (50%) |
| Remediate | [`iam-departures-gcp`](../skills/remediation/iam-departures-gcp/) | HITL — remove principals on departure |
| Remediate | [`remediate-gcp-firewall-revoke`](../skills/remediation/remediate-gcp-firewall-revoke/) | HITL — close open firewall ingress |

### Azure · Entra — 12 skills

| Layer | Skill | What it does |
|---|---|---|
| Ingest | [`ingest-azure-activity-ocsf`](../skills/ingestion/ingest-azure-activity-ocsf/) | Azure Activity → OCSF API Activity |
| Ingest | [`ingest-azure-defender-for-cloud-ocsf`](../skills/ingestion/ingest-azure-defender-for-cloud-ocsf/) | Defender for Cloud findings → OCSF |
| Ingest | [`ingest-entra-directory-audit-ocsf`](../skills/ingestion/ingest-entra-directory-audit-ocsf/) | Entra directory audit → OCSF |
| Ingest | [`ingest-nsg-flow-logs-azure-ocsf`](../skills/ingestion/ingest-nsg-flow-logs-azure-ocsf/) | NSG Flow Logs → OCSF Network Activity |
| Detect | [`detect-azure-activity-logs-disabled`](../skills/detection/detect-azure-activity-logs-disabled/) | T1562.001 — diagnostic-setting deletion |
| Detect | [`detect-azure-open-nsg`](../skills/detection/detect-azure-open-nsg/) | T1190 — 0.0.0.0/0 NSG ingress |
| Detect | [`detect-entra-credential-addition`](../skills/detection/detect-entra-credential-addition/) | T1098.001 — app credential addition |
| Detect | [`detect-entra-role-grant-escalation`](../skills/detection/detect-entra-role-grant-escalation/) | T1098.003 — privileged role grant |
| Evaluate | [`cspm-azure-cis-benchmark`](../skills/evaluation/cspm-azure-cis-benchmark/) | CIS Azure v2.1 — 53% control coverage |
| Remediate | [`iam-departures-azure-entra`](../skills/remediation/iam-departures-azure-entra/) | HITL — Entra principal disable on departure |
| Remediate | [`remediate-azure-nsg-revoke`](../skills/remediation/remediate-azure-nsg-revoke/) | HITL — close open NSG ingress |
| Remediate | [`remediate-entra-credential-revoke`](../skills/remediation/remediate-entra-credential-revoke/) | HITL — revoke Entra app credentials |

### Kubernetes — 9 skills

| Layer | Skill | What it does |
|---|---|---|
| Ingest | [`ingest-k8s-audit-ocsf`](../skills/ingestion/ingest-k8s-audit-ocsf/) | K8s audit → OCSF API Activity 6003 |
| Detect | [`detect-container-escape-k8s`](../skills/detection/detect-container-escape-k8s/) | T1611 — privileged / hostPath escape |
| Detect | [`detect-privilege-escalation-k8s`](../skills/detection/detect-privilege-escalation-k8s/) | T1078 — RBAC escalation via cluster-admin grant |
| Detect | [`detect-sensitive-secret-read-k8s`](../skills/detection/detect-sensitive-secret-read-k8s/) | T1552.001 — anomalous Secret read |
| Evaluate | [`container-security`](../skills/evaluation/container-security/) | CIS Docker Benchmark v1.6 |
| Evaluate | [`gpu-cluster-security`](../skills/evaluation/gpu-cluster-security/) | NVIDIA GPU Operator + node hardening |
| Evaluate | [`k8s-security-benchmark`](../skills/evaluation/k8s-security-benchmark/) | CIS Kubernetes Benchmark v1.10 |
| Remediate | [`remediate-container-escape-k8s`](../skills/remediation/remediate-container-escape-k8s/) | HITL — quarantine pod / drain node |
| Remediate | [`remediate-k8s-rbac-revoke`](../skills/remediation/remediate-k8s-rbac-revoke/) | HITL — revoke RoleBindings, dry-run-first |

### Identity (Okta · Google Workspace) — 7 skills

| Layer | Skill | What it does |
|---|---|---|
| Ingest | [`ingest-google-workspace-login-ocsf`](../skills/ingestion/ingest-google-workspace-login-ocsf/) | Workspace login events → OCSF Authentication 3002 |
| Ingest | [`ingest-okta-system-log-ocsf`](../skills/ingestion/ingest-okta-system-log-ocsf/) | Okta System Log → OCSF |
| Detect | [`detect-credential-stuffing-okta`](../skills/detection/detect-credential-stuffing-okta/) | T1110.004 — high-velocity Okta auth failures |
| Detect | [`detect-google-workspace-suspicious-login`](../skills/detection/detect-google-workspace-suspicious-login/) | T1078.004 — impossible-travel / risky-IP login |
| Detect | [`detect-okta-mfa-fatigue`](../skills/detection/detect-okta-mfa-fatigue/) | T1621 — MFA-bombing |
| Remediate | [`remediate-okta-session-kill`](../skills/remediation/remediate-okta-session-kill/) | HITL — kill Okta sessions on principal |
| Remediate | [`remediate-workspace-session-kill`](../skills/remediation/remediate-workspace-session-kill/) | HITL — sign-out Workspace user |

### AI runtime · MCP · model serving — 10 skills

| Layer | Skill | What it does |
|---|---|---|
| Ingest | [`ingest-mcp-proxy-ocsf`](../skills/ingestion/ingest-mcp-proxy-ocsf/) | MCP proxy logs → OCSF Application Activity 6002 |
| Discover | [`discover-ai-bom`](../skills/discovery/discover-ai-bom/) | CycloneDX ML-BOM — models, datasets, tools |
| Detect | [`detect-agent-credential-leak-mcp`](../skills/detection/detect-agent-credential-leak-mcp/) | OWASP MCP — leaked secrets in `tools/call` results |
| Detect | [`detect-mcp-tool-drift`](../skills/detection/detect-mcp-tool-drift/) | T1195.001 — tool-poisoning / rug-pull |
| Detect | [`detect-prompt-injection-mcp-proxy`](../skills/detection/detect-prompt-injection-mcp-proxy/) | OWASP LLM01 — prompt injection patterns |
| Detect | [`detect-system-prompt-extraction`](../skills/detection/detect-system-prompt-extraction/) | OWASP LLM07 — extraction attempts |
| Detect | [`detect-tool-output-exfiltration-instructions`](../skills/detection/detect-tool-output-exfiltration-instructions/) | OWASP LLM06 — exfil instructions in tool output |
| Detect | [`detect-tool-output-policy-bypass`](../skills/detection/detect-tool-output-policy-bypass/) | OWASP LLM02 — agentic policy-bypass payloads |
| Evaluate | [`model-serving-security`](../skills/evaluation/model-serving-security/) | OWASP LLM Top 10 + ATLAS posture for model APIs |
| Remediate | [`remediate-mcp-tool-quarantine`](../skills/remediation/remediate-mcp-tool-quarantine/) | HITL — quarantine an MCP tool by fingerprint |

### Web application (OWASP Top 10) — 3 skills

| Layer | Skill | What it does |
|---|---|---|
| Detect | [`detect-web-auth-failures`](../skills/detection/detect-web-auth-failures/) | OWASP A07 — auth failure burst |
| Detect | [`detect-web-broken-access-control`](../skills/detection/detect-web-broken-access-control/) | OWASP A01 — IDOR / forced-browsing |
| Detect | [`detect-web-injection`](../skills/detection/detect-web-injection/) | OWASP A03 — SQLi / shell / NoSQL / template injection |

### Warehouse (Snowflake · Databricks · ClickHouse) — 2 skills

| Layer | Skill | What it does |
|---|---|---|
| Detect | [`detect-snowflake-bulk-data-egress`](../skills/detection/detect-snowflake-bulk-data-egress/) | T1567 — bulk data egress across multiple Snowflake stages |
| Detect | [`detect-clickhouse-bulk-export`](../skills/detection/detect-clickhouse-bulk-export/) | T1567 — bulk row export via INTO OUTFILE / s3() / URL() |

### Cross-environment plumbing — 13 skills

| Layer | Skill | What it does |
|---|---|---|
| Discover | [`discover-cloud-control-evidence`](../skills/discovery/discover-cloud-control-evidence/) | Per-control evidence (logging / segmentation / encryption / KMS) |
| Discover | [`discover-control-evidence`](../skills/discovery/discover-control-evidence/) | Cross-cloud control-evidence ledger |
| Discover | [`discover-environment`](../skills/discovery/discover-environment/) | Inventory + relationship graph |
| Discover | [`iam-departures-reconciler`](../skills/discovery/iam-departures-reconciler/) | HR-source → canonical departure manifest |
| Detect | [`detect-lateral-movement`](../skills/detection/detect-lateral-movement/) | Cross-cloud principal-graph traversal |
| View | [`convert-ocsf-to-mermaid-attack-flow`](../skills/view/convert-ocsf-to-mermaid-attack-flow/) | Findings → MITRE ATT&CK Flow Mermaid |
| View | [`convert-ocsf-to-sarif`](../skills/view/convert-ocsf-to-sarif/) | Findings → SARIF 2.1.0 |
| Output | [`sink-clickhouse-jsonl`](../skills/output/sink-clickhouse-jsonl/) | Append-only ClickHouse sink |
| Output | [`sink-s3-jsonl`](../skills/output/sink-s3-jsonl/) | Append-only S3 sink |
| Output | [`sink-snowflake-jsonl`](../skills/output/sink-snowflake-jsonl/) | Append-only Snowflake sink |
| Source | [`source-databricks-query`](../skills/ingestion/source-databricks-query/) | Databricks SQL warehouse adapter |
| Source | [`source-s3-select`](../skills/ingestion/source-s3-select/) | S3 Select adapter |
| Source | [`source-snowflake-query`](../skills/ingestion/source-snowflake-query/) | Snowflake warehouse adapter |

## By purpose

| Layer | Count | Index |
|---|---:|---|
| Ingest | 15 | [`skills/ingestion/`](../skills/ingestion/) (excludes the 3 warehouse sources below) |
| Discover | 5 | [`skills/discovery/`](../skills/discovery/) |
| Detect | 34 | [`skills/detection/`](../skills/detection/) |
| Evaluate | 7 | [`skills/evaluation/`](../skills/evaluation/) |
| Remediate | 12 | [`skills/remediation/`](../skills/remediation/) |
| View | 2 | [`skills/view/`](../skills/view/) |
| Output | 3 | [`skills/output/`](../skills/output/) |
| Source | 3 | warehouse adapters: `source-databricks-query`, `source-s3-select`, `source-snowflake-query` (filed under `skills/ingestion/` on disk) |

Total = 15 + 5 + 34 + 7 + 12 + 2 + 3 + 3 = **81**.

## By framework

This index is intentionally a pointer, not a duplicate of the framework
mappings. Two existing docs are the source of truth:

- [`docs/FRAMEWORK_MAPPINGS.md`](FRAMEWORK_MAPPINGS.md) — every skill's frontmatter `frameworks:` list, rolled up.
- [`docs/FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md) — auto-generated, CI-gated, per-control depth (not just count).

Quick orientation:

| Framework | Where it lives in this repo |
|---|---|
| OCSF 1.8 | wire format on every ingester, every detector, every view |
| MITRE ATT&CK v14 | `finding_info.attacks` on every detector |
| MITRE ATLAS | model-exfil + AI-runtime detectors |
| OWASP Top 10 (web) | `detect-web-*` |
| OWASP LLM Top 10 | `detect-prompt-injection-*`, `detect-system-prompt-extraction`, `detect-tool-output-*`, `detect-agent-credential-leak-mcp`, `model-serving-security` |
| OWASP MCP Top 10 | `detect-mcp-tool-drift`, `detect-agent-credential-leak-mcp`, `detect-prompt-injection-mcp-proxy`, `remediate-mcp-tool-quarantine` |
| CIS AWS / GCP / Azure / K8s / Containers | `cspm-*`, `container-security`, `k8s-security-benchmark` |
| NIST CSF 2.0 / AI RMF | `cspm-*` benchmark mappings + AI runtime evaluators |
| SOC 2 / ISO 27001 / PCI / FedRAMP | rolled up via `discover-control-evidence` |
| CycloneDX ML-BOM | `discover-ai-bom` |
