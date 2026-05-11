# Coverage Snapshot

Auto-generated from [`framework-coverage.json`](framework-coverage.json) by [`scripts/coverage_summary.py`](../scripts/coverage_summary.py). Do not edit by hand — the CI gate `--check` will refuse the PR. Regenerate with:

```bash
python scripts/coverage_summary.py --write
```

**Total shipped skills:** 94

## By cloud / vendor

Skills overlap when a skill targets multiple providers (the `multi` row), so the column may sum to more than the total.

| Cloud / vendor | Skills | % of repo |
|---|---:|---:|
| AWS | 22 | 23.4% |
| Multi-cloud (vendor-neutral) | 21 | 22.3% |
| Azure | 18 | 19.1% |
| GCP | 17 | 18.1% |
| Snowflake | 13 | 13.8% |
| Kubernetes | 9 | 9.6% |
| MCP / AI runtime | 8 | 8.5% |
| ClickHouse | 4 | 4.3% |
| Okta | 4 | 4.3% |
| Databricks | 4 | 4.3% |
| Microsoft Entra | 4 | 4.3% |
| Microsoft Graph | 3 | 3.2% |
| Google Workspace | 3 | 3.2% |
| Containers (runtime) | 3 | 3.2% |
| Workday | 1 | 1.1% |

## By framework

Skills can carry multiple framework tags (e.g. a CIS check tagged with NIST CSF mapping); the column does not sum to 100%.

| Framework | Skills | % of repo |
|---|---:|---:|
| OCSF 1.8 | 73 | 77.7% |
| MITRE ATT&CK v14 | 63 | 67.0% |
| SOC 2 TSC | 20 | 21.3% |
| NIST CSF 2.0 | 20 | 21.3% |
| MITRE ATLAS | 13 | 13.8% |
| OWASP Top 10 | 13 | 13.8% |
| OWASP LLM Top 10 | 9 | 9.6% |
| NIST AI RMF | 8 | 8.5% |
| OWASP MCP Top 10 | 7 | 7.4% |
| CIS Azure v2.1 | 6 | 6.4% |
| CIS GCP v3 | 5 | 5.3% |
| CIS AWS v3 | 4 | 4.3% |
| PCI DSS 4.0 | 4 | 4.3% |
| ISO 27001:2022 | 3 | 3.2% |
| CycloneDX ML-BOM | 2 | 2.1% |
| CIS Controls v8 | 2 | 2.1% |
| CIS Kubernetes | 2 | 2.1% |
| CIS Docker | 1 | 1.1% |

## By layer

| Layer | Skills | % of repo |
|---|---:|---:|
| detection | 43 | 45.7% |
| ingestion | 18 | 19.1% |
| remediation | 12 | 12.8% |
| evaluation | 11 | 11.7% |
| discovery | 5 | 5.3% |
| output | 3 | 3.2% |
| view | 2 | 2.1% |

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
| MITRE ATT&CK breadth | `mitre-attack-v14` | #253 | 50% | 67% |
| MITRE ATLAS | `mitre-atlas` | #255 | 40% | 14% |
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

