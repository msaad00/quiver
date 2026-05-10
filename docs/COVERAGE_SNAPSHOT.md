# Coverage Snapshot

Auto-generated from [`framework-coverage.json`](framework-coverage.json) by [`scripts/coverage_summary.py`](../scripts/coverage_summary.py). Do not edit by hand — the CI gate `--check` will refuse the PR. Regenerate with:

```bash
python scripts/coverage_summary.py --write
```

**Total shipped skills:** 76

## By cloud / vendor

Skills overlap when a skill targets multiple providers (the `multi` row), so the column may sum to more than the total.

| Cloud / vendor | Skills | % of repo |
|---|---:|---:|
| AWS | 22 | 28.9% |
| Azure | 18 | 23.7% |
| GCP | 17 | 22.4% |
| Multi-cloud (vendor-neutral) | 14 | 18.4% |
| Kubernetes | 9 | 11.8% |
| MCP / AI runtime | 8 | 10.5% |
| Snowflake | 4 | 5.3% |
| Microsoft Entra | 4 | 5.3% |
| Okta | 4 | 5.3% |
| Databricks | 3 | 3.9% |
| Microsoft Graph | 3 | 3.9% |
| Google Workspace | 3 | 3.9% |
| Containers (runtime) | 3 | 3.9% |
| ClickHouse | 3 | 3.9% |
| Workday | 1 | 1.3% |

## By framework

Skills can carry multiple framework tags (e.g. a CIS check tagged with NIST CSF mapping); the column does not sum to 100%.

| Framework | Skills | % of repo |
|---|---:|---:|
| OCSF 1.8 | 55 | 72.4% |
| MITRE ATT&CK v14 | 49 | 64.5% |
| NIST CSF 2.0 | 20 | 26.3% |
| SOC 2 TSC | 20 | 26.3% |
| MITRE ATLAS | 13 | 17.1% |
| OWASP LLM Top 10 | 8 | 10.5% |
| OWASP MCP Top 10 | 7 | 9.2% |
| CIS Azure v2.1 | 6 | 7.9% |
| CIS GCP v3 | 5 | 6.6% |
| NIST AI RMF | 4 | 5.3% |
| PCI DSS 4.0 | 4 | 5.3% |
| CIS AWS v3 | 4 | 5.3% |
| ISO 27001:2022 | 3 | 3.9% |
| CycloneDX ML-BOM | 2 | 2.6% |
| CIS Kubernetes | 2 | 2.6% |
| CIS Controls v8 | 2 | 2.6% |
| CIS Docker | 1 | 1.3% |

## By layer

| Layer | Skills | % of repo |
|---|---:|---:|
| detection | 29 | 38.2% |
| ingestion | 18 | 23.7% |
| remediation | 12 | 15.8% |
| evaluation | 7 | 9.2% |
| discovery | 5 | 6.6% |
| output | 3 | 3.9% |
| view | 2 | 2.6% |

## Per-framework control coverage

**Depth, not breadth.** When a skill ships a `checks.py` with explicit `control_id` literals (the CSPM benchmarks today), this table counts the unique controls covered against the framework's published total. Same control covered by two skills counts once.

| Framework | Controls covered | Total | Coverage % |
|---|---:|---:|---:|
| CIS AWS v3 | 20 | 58 | 34% |
| CIS GCP v3 | 10 | 60 | 17% |
| CIS Azure v2.1 | 6 | 60 | 10% |
| CIS Controls v8 | 0 | 18 | 0% |
| CIS Docker | 0 | 17 | 0% |
| CIS Kubernetes | 0 | 30 | 0% |
| NIST AI RMF | 0 | 24 | 0% |
| OWASP LLM Top 10 | 0 | 10 | 0% |
| OWASP MCP Top 10 | 0 | 10 | 0% |

## Roadmap progress

Per-track breadth toward the published target. The 'Today' column uses **per-control coverage** when the framework has known totals (see table above), else falls back to skill-tag breadth.

| Track | Tag | Issue | Target | Today |
|---|---|---|---:|---:|
| MITRE ATT&CK breadth | `mitre-attack-v14` | #253 | 50% | 64% |
| MITRE ATLAS | `mitre-atlas` | #255 | 40% | 17% |
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

