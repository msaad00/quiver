# Architecture

Short overview. The load-bearing design contract lives in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); read that when you need
guarantees, invariants, or roadmap anchors.

## Mental model

Six shipped skill layers at the center. Three edge or runtime layers around
them. One shared skill bundle contract.

| Layer | Responsibility | Shipped examples |
|---|---|---|
| L1 Ingest | raw source → native, OCSF, or bridge stream | `ingest-cloudtrail-ocsf`, `ingest-k8s-audit-ocsf`, `ingest-okta-system-log-ocsf`, `ingest-entra-directory-audit-ocsf`, `ingest-google-workspace-login-ocsf`, `ingest-mcp-proxy-ocsf`, `ingest-vpc-flow-logs-*-ocsf`, `ingest-guardduty-ocsf`, `ingest-security-hub-ocsf`, `ingest-gcp-audit-ocsf`, `ingest-gcp-scc-ocsf`, `ingest-azure-activity-ocsf`, `ingest-azure-defender-for-cloud-ocsf`, `ingest-nsg-flow-logs-azure-ocsf` |
| L2 Discover | live inventory, evidence, AI BOM, graph context | `discover-ai-bom`, `discover-cloud-control-evidence`, `discover-control-evidence`, `discover-environment` |
| L3 Detect | deterministic attack-pattern findings | `detect-lateral-movement`, `detect-container-escape-k8s`, `detect-privilege-escalation-k8s`, `detect-sensitive-secret-read-k8s`, `detect-mcp-tool-drift`, `detect-prompt-injection-mcp-proxy`, `detect-okta-mfa-fatigue`, `detect-credential-stuffing-okta`, `detect-entra-credential-addition`, `detect-entra-role-grant-escalation`, `detect-google-workspace-suspicious-login` |
| L4 Evaluate | benchmark and posture results | `cspm-aws-cis-benchmark`, `cspm-gcp-cis-benchmark`, `cspm-azure-cis-benchmark`, `k8s-security-benchmark`, `container-security`, `gpu-cluster-security`, `model-serving-security` |
| L5 Remediate | guarded writes with HITL and dual audit | `iam-departures-aws`, `remediate-okta-session-kill`, `remediate-container-escape-k8s` |
| L6 View | export into downstream formats | `convert-ocsf-to-sarif`, `convert-ocsf-to-mermaid-attack-flow` |

OCSF 1.8 is the default interoperable wire format, not a layer. It is pinned
in [`skills/detection-engineering/OCSF_CONTRACT.md`](skills/detection-engineering/OCSF_CONTRACT.md)
and validated by the frozen golden fixtures under
`skills/detection-engineering/golden/`.

## Edge and runtime

- **Sources and sinks** — `source-*` adapters pull warehouse or object-store
  rows; `sink-*` adapters persist outputs. Neither normalizes payloads.
- **Query packs** — warehouse-native SQL implementations that mirror a
  detection pattern for Snowflake, Databricks, or ClickHouse.
- **Runtime surfaces** — CLI, CI, MCP, and runners all invoke the same skill
  bundles. Wrappers add orchestration, not a second implementation.

## Layer composition

Skills are standalone Python bundles (`SKILL.md` + `src/` + `tests/` +
`REFERENCES.md`). They compose via stdin/stdout pipes. One representative
pipeline:

```bash
python skills/ingestion/ingest-k8s-audit-ocsf/src/ingest.py audit.jsonl \
  | python skills/detection/detect-privilege-escalation-k8s/src/detect.py \
  | python skills/view/convert-ocsf-to-sarif/src/convert.py \
  > findings.sarif
```

## Where things sit today

| Layer | Shipped | Planned / roadmap |
|---|---|---|
| L1 Ingest | 22 shipped ingesters across AWS, GCP, Azure, K8s, Okta, Entra, Workspace, GitHub, Slack, Salesforce, SAP, Workday, MCP, plus 4 source adapters (S3 Select, Snowflake, Databricks, ClickHouse) | more identity and SaaS sources as demand justifies |
| L2 Discover | 5 shipped skills (AI BOM, cloud control evidence, control evidence, environment graph, IAM-departures reconciler) | wider SaaS and infra evidence sources |
| L3 Detect | 71 shipped detectors tied to MITRE ATT&CK / OWASP techniques (lateral movement, K8s container escape + privesc + secret read, MCP tool drift + prompt injection, identity attacks across Okta / Entra / Workspace, cloud-config and AI-runtime signals) | impossible travel, more AI-agent signals |
| L4 Evaluate | 12 shipped benchmarks (CIS AWS / GCP / Azure, K8s, Docker / container, GPU cluster, model serving, CIS AWS Foundations OCSF, NIST AI RMF govern / map / measure / manage) | native by default, OCSF Compliance Finding (`class_uid=2003`) shipped as opt-in output |
| L5 Remediate | 12 shipped HITL-gated write skills — `iam-departures-{aws,gcp,azure-entra}`, network revokes (`remediate-aws-sg-revoke`, `remediate-gcp-firewall-revoke`, `remediate-azure-nsg-revoke`), session kills (Okta, Workspace), `remediate-container-escape-k8s`, `remediate-k8s-rbac-revoke`, `remediate-mcp-tool-quarantine`, `remediate-entra-credential-revoke` — all with HITL, dual audit, dry-run | broader remediation families (see issues #155, #242, #307) |
| L6 View | `convert-ocsf-to-sarif`, `convert-ocsf-to-mermaid-attack-flow` | graph overlay, warehouse-ready converters |
| L7 Output | 3 shipped sinks (`sink-s3-jsonl`, `sink-snowflake-jsonl`, `sink-clickhouse-jsonl`) | BigQuery, Security Lake |

## Directory layout

```
skills/
├── ingestion/      ← L1 (plus source-* adapters at the L0 edge)
├── discovery/      ← L2
├── detection/      ← L3
├── evaluation/     ← L4
├── remediation/    ← L5 (mutating actions — identity, cloud-config)
├── view/           ← L6
└── output/         ← L7 (sink-* skills: append-only persistence)
```

The repo ships **131 skills** across these seven layers: 22 ingest skills plus 4 `source-*` adapters, 5 discover, 71 detect, 12 evaluate, 12 remediate, 2 view, and 3 output sinks. The authoritative per-skill registry is [`docs/framework-coverage.json`](docs/framework-coverage.json); `scripts/validate_doc_counts.py` gates this paragraph against it in CI.

`skills/detection-engineering/` holds the shared OCSF contract and frozen
golden fixtures. Executable skills live only under the six layered
directories above.

## Where to go next

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full design contract and
  invariants.
- [`docs/SCHEMA_COVERAGE.md`](docs/SCHEMA_COVERAGE.md) — per-source schema
  coverage tables.
- [`docs/FRAMEWORK_MAPPINGS.md`](docs/FRAMEWORK_MAPPINGS.md) — MITRE ATT&CK,
  CIS, NIST coverage per skill.
- [`SECURITY_BAR.md`](SECURITY_BAR.md) — skill security contract.
