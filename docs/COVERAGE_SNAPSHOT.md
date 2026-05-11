# Coverage Snapshot

Auto-generated from [`framework-coverage.json`](framework-coverage.json) by [`scripts/coverage_summary.py`](../scripts/coverage_summary.py). Do not edit by hand — the CI gate `--check` will refuse the PR. Regenerate with:

```bash
python scripts/coverage_summary.py --write
```

**Total shipped skills:** 105

## By cloud / vendor

Skills overlap when a skill targets multiple providers (the `multi` row), so the column may sum to more than the total.

| Cloud / vendor | Skills | % of repo |
|---|---:|---:|
| AWS | 22 | 21.0% |
| Multi-cloud (vendor-neutral) | 21 | 20.0% |
| Azure | 18 | 17.1% |
| GCP | 17 | 16.2% |
| Snowflake | 13 | 12.4% |
| MCP / AI runtime | 11 | 10.5% |
| Kubernetes | 9 | 8.6% |
| ClickHouse | 4 | 3.8% |
| Okta | 4 | 3.8% |
| Databricks | 4 | 3.8% |
| Microsoft Entra | 4 | 3.8% |
| github | 4 | 3.8% |
| Slack | 4 | 3.8% |
| Microsoft Graph | 3 | 2.9% |
| Google Workspace | 3 | 2.9% |
| Containers (runtime) | 3 | 2.9% |
| Workday | 1 | 1.0% |

## By framework

Skills can carry multiple framework tags (e.g. a CIS check tagged with NIST CSF mapping); the column does not sum to 100%.

| Framework | Skills | % of repo |
|---|---:|---:|
| OCSF 1.8 | 84 | 80.0% |
| MITRE ATT&CK v14 | 69 | 65.7% |
| SOC 2 TSC | 20 | 19.0% |
| NIST CSF 2.0 | 20 | 19.0% |
| OWASP Top 10 | 16 | 15.2% |
| OWASP LLM Top 10 | 15 | 14.3% |
| MITRE ATLAS | 14 | 13.3% |
| OWASP MCP Top 10 | 8 | 7.6% |
| NIST AI RMF | 8 | 7.6% |
| CIS Azure v2.1 | 6 | 5.7% |
| CIS GCP v3 | 5 | 4.8% |
| CIS AWS v3 | 4 | 3.8% |
| PCI DSS 4.0 | 4 | 3.8% |
| ISO 27001:2022 | 3 | 2.9% |
| CycloneDX ML-BOM | 2 | 1.9% |
| CIS Controls v8 | 2 | 1.9% |
| CIS Kubernetes | 2 | 1.9% |
| CIS Docker | 1 | 1.0% |

## By layer

| Layer | Skills | % of repo |
|---|---:|---:|
| detection | 52 | 49.5% |
| ingestion | 20 | 19.0% |
| remediation | 12 | 11.4% |
| evaluation | 11 | 10.5% |
| discovery | 5 | 4.8% |
| output | 3 | 2.9% |
| view | 2 | 1.9% |

## Per-framework control coverage

**Depth, not breadth.** When a skill ships a `checks.py` with explicit `control_id` literals (the CSPM benchmarks today), this table counts the unique controls covered against the framework's published total. Same control covered by two skills counts once.

| Framework | Controls covered | Total | Coverage % |
|---|---:|---:|---:|
| CIS Azure v2.1 | 32 | 60 | 53% |
| CIS GCP v3 | 30 | 60 | 50% |
| CIS AWS v3 | 29 | 58 | 50% |
| CIS Controls v8 | 0 | 18 | 0% |
| CIS Docker | 0 | 17 | 0% |
| CIS Kubernetes | 0 | 30 | 0% |
| NIST AI RMF | 0 | 72 | 0% |
| OWASP LLM Top 10 | 0 | 10 | 0% |
| OWASP MCP Top 10 | 0 | 10 | 0% |
| OWASP Top 10 | 0 | 10 | 0% |

## Roadmap progress

Per-track breadth toward the published target. The 'Today' column uses **per-control coverage** when the framework has known totals (see table above), else falls back to skill-tag breadth.

| Track | Tag | Issue | Target | Today |
|---|---|---|---:|---:|
| MITRE ATT&CK breadth | `mitre-attack-v14` | #253 | 50% | 66% |
| MITRE ATLAS | `mitre-atlas` | #255 | 40% | 13% |
| OWASP LLM Top 10 | `owasp-llm-top-10` | #255 | 40% | 0% |
| OWASP MCP Top 10 | `owasp-mcp-top-10` | #255 | 50% | 0% |
| OWASP Top 10 (web) | `owasp-top-10` | TBD | 30% | 0% |
| NIST AI RMF | `nist-ai-rmf` | TBD | 30% | 0% |

## Where the gaps are

- **CIS depth** — only 4–6 controls per cloud × 3 clouds today. Roadmap [#254](https://github.com/msaad00/cloud-ai-security-skills/issues/254) calls for 50% per platform; ~35–40 more controls to ship.
- **OWASP Top 10 (web)** — zero detectors today. The hero banner advertises the framework — coverage owed.
- **NIST AI RMF + CycloneDX ML-BOM** — only 4 + 2 skills. AI inventory and posture is a credible next theme.
- **Per-vendor depth** — Snowflake / Databricks / ClickHouse are 3–4 skills each. Detect-side coverage on those is thin.
- **PCI / ISO** — 3–4 skills each, mostly evidence-side. Detect / remediate slices could be added cheaply.

