# Coverage Snapshot

Auto-generated from [`framework-coverage.json`](framework-coverage.json) by [`scripts/coverage_summary.py`](../scripts/coverage_summary.py). Do not edit by hand — the CI gate `--check` will refuse the PR. Regenerate with:

```bash
python scripts/coverage_summary.py --write
```

**Total shipped skills:** 82

## By cloud / vendor

Skills overlap when a skill targets multiple providers (the `multi` row), so the column may sum to more than the total.

| Cloud / vendor | Skills | % of repo |
|---|---:|---:|
| AWS | 22 | 26.8% |
| Azure | 18 | 22.0% |
| GCP | 17 | 20.7% |
| Multi-cloud (vendor-neutral) | 17 | 20.7% |
| Kubernetes | 9 | 11.0% |
| MCP / AI runtime | 8 | 9.8% |
| Snowflake | 5 | 6.1% |
| Databricks | 4 | 4.9% |
| Microsoft Entra | 4 | 4.9% |
| Okta | 4 | 4.9% |
| ClickHouse | 4 | 4.9% |
| Microsoft Graph | 3 | 3.7% |
| Google Workspace | 3 | 3.7% |
| Containers (runtime) | 3 | 3.7% |
| Workday | 1 | 1.2% |

## By framework

Skills can carry multiple framework tags (e.g. a CIS check tagged with NIST CSF mapping); the column does not sum to 100%.

| Framework | Skills | % of repo |
|---|---:|---:|
| OCSF 1.8 | 61 | 74.4% |
| MITRE ATT&CK v14 | 55 | 67.1% |
| NIST CSF 2.0 | 20 | 24.4% |
| SOC 2 TSC | 20 | 24.4% |
| MITRE ATLAS | 13 | 15.9% |
| OWASP LLM Top 10 | 9 | 11.0% |
| OWASP MCP Top 10 | 7 | 8.5% |
| CIS Azure v2.1 | 6 | 7.3% |
| CIS GCP v3 | 5 | 6.1% |
| OWASP Top 10 | 5 | 6.1% |
| NIST AI RMF | 4 | 4.9% |
| PCI DSS 4.0 | 4 | 4.9% |
| CIS AWS v3 | 4 | 4.9% |
| ISO 27001:2022 | 3 | 3.7% |
| CycloneDX ML-BOM | 2 | 2.4% |
| CIS Kubernetes | 2 | 2.4% |
| CIS Controls v8 | 2 | 2.4% |
| CIS Docker | 1 | 1.2% |

## By layer

| Layer | Skills | % of repo |
|---|---:|---:|
| detection | 35 | 42.7% |
| ingestion | 18 | 22.0% |
| remediation | 12 | 14.6% |
| evaluation | 7 | 8.5% |
| discovery | 5 | 6.1% |
| output | 3 | 3.7% |
| view | 2 | 2.4% |

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
| NIST AI RMF | 0 | 24 | 0% |
| OWASP LLM Top 10 | 0 | 10 | 0% |
| OWASP MCP Top 10 | 0 | 10 | 0% |
| OWASP Top 10 | 0 | 10 | 0% |

## Roadmap progress

Per-track breadth toward the published target. The 'Today' column uses **per-control coverage** when the framework has known totals (see table above), else falls back to skill-tag breadth.

| Track | Tag | Issue | Target | Today |
|---|---|---|---:|---:|
| MITRE ATT&CK breadth | `mitre-attack-v14` | #253 | 50% | 67% |
| MITRE ATLAS | `mitre-atlas` | #255 | 40% | 16% |
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

