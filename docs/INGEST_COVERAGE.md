# Ingest coverage — vendor signals → OCSF 1.8 classes

What each cloud / identity / AI-runtime data source becomes when it flows
through this repo's ingest layer — and what's not yet covered.

This page is the single source of truth for **"which signal can I send and
get OCSF out the other side?"** The rows below are the canonical answer at
HEAD; the not-yet-shipped rows below distinguish active tracking issues from
explicit follow-on gaps.

## Currently shipped — 22 ingest skills

| Vendor | Source signal | OCSF 1.8 class | Skill |
|---|---|---|---|
| AWS | CloudTrail event records | API Activity 6003 | [`ingest-cloudtrail-ocsf`](../skills/ingestion/ingest-cloudtrail-ocsf/) |
| AWS | Config item history + compliance changes | API Activity 6003 / Compliance Finding 2003 | [`ingest-aws-config-ocsf`](../skills/ingestion/ingest-aws-config-ocsf/) — closes [`#29`](https://github.com/msaad00/cloud-ai-security-skills/issues/29) |
| AWS | GuardDuty findings | Detection Finding 2004 | [`ingest-guardduty-ocsf`](../skills/ingestion/ingest-guardduty-ocsf/) |
| AWS | Security Hub findings | Detection Finding 2004 | [`ingest-security-hub-ocsf`](../skills/ingestion/ingest-security-hub-ocsf/) |
| AWS | VPC Flow Logs | Network Activity 4001 | [`ingest-vpc-flow-logs-ocsf`](../skills/ingestion/ingest-vpc-flow-logs-ocsf/) |
| GCP | Cloud Audit (Admin / Data) | API Activity 6003 | [`ingest-gcp-audit-ocsf`](../skills/ingestion/ingest-gcp-audit-ocsf/) |
| GCP | Security Command Center findings | Detection Finding 2004 | [`ingest-gcp-scc-ocsf`](../skills/ingestion/ingest-gcp-scc-ocsf/) |
| GCP | VPC Flow Logs | Network Activity 4001 | [`ingest-vpc-flow-logs-gcp-ocsf`](../skills/ingestion/ingest-vpc-flow-logs-gcp-ocsf/) |
| Azure | Activity Log | API Activity 6003 | [`ingest-azure-activity-ocsf`](../skills/ingestion/ingest-azure-activity-ocsf/) |
| Azure | Defender for Cloud findings | Detection Finding 2004 | [`ingest-azure-defender-for-cloud-ocsf`](../skills/ingestion/ingest-azure-defender-for-cloud-ocsf/) |
| Azure | NSG Flow Logs | Network Activity 4001 | [`ingest-nsg-flow-logs-azure-ocsf`](../skills/ingestion/ingest-nsg-flow-logs-azure-ocsf/) |
| Microsoft Entra | Directory Audit logs | IAM events — Authentication 3002 / Account Change 3001 / User Access 3005 | [`ingest-entra-directory-audit-ocsf`](../skills/ingestion/ingest-entra-directory-audit-ocsf/) |
| Kubernetes | API server audit log | API Activity 6003 | [`ingest-k8s-audit-ocsf`](../skills/ingestion/ingest-k8s-audit-ocsf/) |
| Okta | System Log | IAM events — Authentication 3002 / Account Change 3001 / User Access 3005 | [`ingest-okta-system-log-ocsf`](../skills/ingestion/ingest-okta-system-log-ocsf/) |
| Google Workspace | Login activity (Reports API) | Authentication 3002 | [`ingest-google-workspace-login-ocsf`](../skills/ingestion/ingest-google-workspace-login-ocsf/) |
| Google Workspace | Admin SDK Reports API login / token / admin activity | Authentication 3002 / Account Change 3001 | [`ingest-workspace-admin-ocsf`](../skills/ingestion/ingest-workspace-admin-ocsf/) — closes [`#32`](https://github.com/msaad00/cloud-ai-security-skills/issues/32) |
| GitHub | Organization Audit Log | API Activity 6003 / Authentication 3002 / User Access 3005 | [`ingest-github-audit-log-ocsf`](../skills/ingestion/ingest-github-audit-log-ocsf/) — closes [`#31`](https://github.com/msaad00/cloud-ai-security-skills/issues/31) |
| MCP proxy | JSON-RPC request/response log | Application Activity 6002 | [`ingest-mcp-proxy-ocsf`](../skills/ingestion/ingest-mcp-proxy-ocsf/) |
| Slack | Audit Logs API (`/audit/v1/logs`, Enterprise Grid) | Authentication 3002 / User Access 3005 / API Activity 6003 | [`ingest-slack-audit-ocsf`](../skills/ingestion/ingest-slack-audit-ocsf/) — closes [`#33`](https://github.com/msaad00/cloud-ai-security-skills/issues/33) |
| Workday | REST / RaaS audit and HR lifecycle report exports | Account Change 3001 | [`ingest-workday-audit-ocsf`](../skills/ingestion/ingest-workday-audit-ocsf/) — closes [`#34`](https://github.com/msaad00/cloud-ai-security-skills/issues/34) |
| Salesforce | Event Monitoring EventLogFile / REST exports | Application Activity 6002 | [`ingest-salesforce-event-mon-ocsf`](../skills/ingestion/ingest-salesforce-event-mon-ocsf/) — closes [`#35`](https://github.com/msaad00/cloud-ai-security-skills/issues/35) |
| SAP | Security Audit Log | Application Activity 6002 | [`ingest-sap-audit-log-ocsf`](../skills/ingestion/ingest-sap-audit-log-ocsf/) — closes [`#36`](https://github.com/msaad00/cloud-ai-security-skills/issues/36) |
| AWS / GCP / Azure | Cross-cloud secret-scan + AI-BOM input pipes | (consumed by downstream detect-agent-credential-leak-mcp / discover-ai-bom) | covered transitively via the four above |

> 23 rows for 22 ingest skills: Entra, Okta, GitHub, Slack, AWS Config, and Workspace Admin emit
> multiple OCSF classes depending on the source event family. The cross-cloud
> row documents downstream coverage, so the row count exceeds the skill count.

## Warehouse read-side adapters — 3 skills

These do **not** emit OCSF directly; they expose a read-side adapter that the
matching warehouse-depth detectors (Snowflake / Databricks / ClickHouse —
shipped under issue #436) consume. The detectors are what produces the OCSF
Detection Finding 2004 records.

| Warehouse | Source | Adapter skill | Consuming detectors |
|---|---|---|---|
| Snowflake | `query_history`, audit views | [`source-snowflake-query`](../skills/ingestion/source-snowflake-query/) | `detect-snowflake-bulk-data-egress`, `detect-snowflake-share-creation`, `detect-snowflake-account-key-creation`, `detect-snowflake-warehouse-resize-burst`, `detect-snowflake-unauthorized-grant` |
| Databricks | SQL Warehouse + audit | [`source-databricks-query`](../skills/ingestion/source-databricks-query/) | `detect-databricks-token-creation` |
| AWS S3 | `s3 select` (Athena-style) | [`source-s3-select`](../skills/ingestion/source-s3-select/) | any detector reading historical CloudTrail / GuardDuty exports from S3 |

A dedicated native `ingest-clickhouse-query-log-ocsf` is on the roadmap (see
below) — for now `detect-clickhouse-bulk-export` reads `system.query_log`
records already shaped as OCSF API Activity 6003 by an upstream pipeline.

## Roadmap and explicit gaps — not yet shipped

| Vendor | Source | Target OCSF class | Tracking / disposition |
|---|---|---|---|
| ClickHouse | `system.query_log` native ingest | API Activity 6003 | [`#436`](https://github.com/msaad00/cloud-ai-security-skills/issues/436) — `ingest-clickhouse-query-log-ocsf` |
| AWS | Lambda + API Gateway access logs | HTTP Activity 4002 | [`#253`](https://github.com/msaad00/cloud-ai-security-skills/issues/253) — first detection-side use case is the web-app exfil arc |
| Google Workspace | Drive / Mobile feeds (beyond login, token, and admin role activity) | API Activity 6003 + User Access 3005 | Explicit follow-on gap; [`#32`](https://github.com/msaad00/cloud-ai-security-skills/issues/32) delivered the login / token / admin baseline |

## What "shipped" means here

A row in the shipped table guarantees:

1. There's a `SKILL.md` documenting the input schema, exact OCSF class emitted, and the do-not-use list.
2. There's a synthetic golden fixture under [`skills/detection-engineering/golden/`](../skills/detection-engineering/golden/) — see [`golden/README.md`](../skills/detection-engineering/golden/README.md) for the honesty contract on what those fixtures verify (contract, determinism, schema validity) vs. what they don't (precision/recall on real workloads).
3. The skill is exercised by at least one downstream detector or test in CI.
4. The OCSF wire shape is locked by snapshot test.

A row in the roadmap / explicit-gaps table guarantees:

1. If a tracking issue is linked, it owns the next shipped slice; otherwise the row is a deliberately documented gap, not an active claim.
2. The intended OCSF class is documented up-front.
3. Nothing is half-built or stubbed in the repo today.

## Adding a new vendor mapping

1. Open or claim the tracking issue, unless the row is only being documented as an explicit future gap.
2. Add the SKILL.md + `src/ingest.py` + golden fixture under `skills/ingestion/ingest-<vendor>-<source>-ocsf/`.
3. Run `scripts/coverage_summary.py --write` and `scripts/generate_framework_coverage_doc.py` to refresh the auto-generated docs.
4. Move the row in this file from the roadmap table to the shipped table in the same PR.
5. The CI count-consistency gate enforces the move.
