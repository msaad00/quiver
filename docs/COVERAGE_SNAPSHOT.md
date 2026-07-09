# Coverage Snapshot

Auto-generated from [`framework-coverage.json`](framework-coverage.json) by [`scripts/coverage_summary.py`](../scripts/coverage_summary.py). Do not edit by hand — the CI gate `--check` will refuse the PR. Regenerate with:

```bash
python scripts/coverage_summary.py --write
```

**Total shipped skills:** 131

## By cloud / vendor

Skills overlap when a skill targets multiple providers (the `multi` row), so the column may sum to more than the total.

| Cloud / vendor | Skills | % of repo |
|---|---:|---:|
| AWS | 26 | 19.8% |
| Multi-cloud (vendor-neutral) | 21 | 16.0% |
| Azure | 19 | 14.5% |
| GCP | 18 | 13.7% |
| MCP / AI runtime | 14 | 10.7% |
| Snowflake | 13 | 9.9% |
| Kubernetes | 9 | 6.9% |
| Databricks | 9 | 6.9% |
| Google Workspace | 6 | 4.6% |
| ClickHouse | 5 | 3.8% |
| Okta | 4 | 3.1% |
| Microsoft Entra | 4 | 3.1% |
| github | 4 | 3.1% |
| Slack | 4 | 3.1% |
| salesforce | 3 | 2.3% |
| Workday | 3 | 2.3% |
| sap | 3 | 2.3% |
| Microsoft Graph | 3 | 2.3% |
| Containers (runtime) | 3 | 2.3% |

## By framework

Skills can carry multiple framework tags (e.g. a CIS check tagged with NIST CSF mapping); the column does not sum to 100%.

| Framework | Skills | % of repo |
|---|---:|---:|
| OCSF 1.8 | 110 | 84.0% |
| MITRE ATT&CK v14 | 86 | 65.6% |
| OWASP Top 10 | 27 | 20.6% |
| SOC 2 TSC | 22 | 16.8% |
| NIST CSF 2.0 | 22 | 16.8% |
| OWASP LLM Top 10 | 19 | 14.5% |
| MITRE ATLAS | 17 | 13.0% |
| OWASP MCP Top 10 | 11 | 8.4% |
| NIST AI RMF | 8 | 6.1% |
| CIS AWS v3 | 6 | 4.6% |
| CIS Azure v2.1 | 6 | 4.6% |
| CIS GCP v3 | 5 | 3.8% |
| ISO 27001:2022 | 5 | 3.8% |
| PCI DSS 4.0 | 4 | 3.1% |
| CycloneDX ML-BOM | 2 | 1.5% |
| CIS Controls v8 | 2 | 1.5% |
| CIS Kubernetes | 2 | 1.5% |
| CIS Docker | 1 | 0.8% |

## By layer

| Layer | Skills | % of repo |
|---|---:|---:|
| detection | 71 | 54.2% |
| ingestion | 26 | 19.8% |
| evaluation | 12 | 9.2% |
| remediation | 12 | 9.2% |
| discovery | 5 | 3.8% |
| output | 3 | 2.3% |
| view | 2 | 1.5% |

## Per-framework control coverage

**Depth, not breadth.** Skills declare per-control coverage via explicit `control_id` literals (CSPM benchmarks), OWASP LLM/MCP depth markers in detection skills, and NIST AI RMF subcategory IDs in evaluation manifests. This table counts unique controls covered against each framework's published total. Same control covered by two skills counts once.

| Framework | Controls covered | Total | Coverage % |
|---|---:|---:|---:|
| NIST AI RMF | 44 | 72 | 61% |
| CIS GCP v3 | 30 | 60 | 50% |
| CIS AWS v3 | 27 | 58 | 47% |
| CIS Azure v2.1 | 22 | 60 | 37% |
| OWASP LLM Top 10 | 8 | 10 | 80% |
| OWASP MCP Top 10 | 7 | 10 | 70% |
| CIS Controls v8 | 0 | 18 | 0% |
| CIS Docker | 0 | 17 | 0% |
| CIS Kubernetes | 0 | 30 | 0% |
| OWASP Top 10 | 0 | 10 | 0% |

## Roadmap progress

Per-track breadth toward the published target. The 'Today' column uses **per-control coverage** when the framework has known totals (see table above), else falls back to skill-tag breadth.

| Track | Tag | Issue | Target | Today |
|---|---|---|---:|---:|
| MITRE ATT&CK breadth | `mitre-attack-v14` | #253 | 50% | 66% |
| MITRE ATLAS | `mitre-atlas` | #255 | 40% | 13% |
| OWASP LLM Top 10 | `owasp-llm-top-10` | #255 | 40% | 80% |
| OWASP MCP Top 10 | `owasp-mcp-top-10` | #255 | 50% | 70% |
| OWASP Top 10 (web) | `owasp-top-10` | TBD | 30% | 0% |
| NIST AI RMF | `nist-ai-rmf` | TBD | 30% | 61% |

## Where the gaps are

- **CIS depth** — only 4–6 controls per cloud × 3 clouds today. Roadmap [#254](https://github.com/msaad00/cloud-ai-security-skills/issues/254) calls for 50% per platform; ~35–40 more controls to ship.
- **OWASP Top 10 (web)** — zero detectors today. The hero banner advertises the framework — coverage owed.
- **NIST AI RMF + CycloneDX ML-BOM** — only 4 + 2 skills. AI inventory and posture is a credible next theme.
- **Per-vendor depth** — Snowflake / Databricks / ClickHouse are 3–4 skills each. Detect-side coverage on those is thin.
- **PCI / ISO** — 3–4 skills each, mostly evidence-side. Detect / remediate slices could be added cheaply.

