# References — evaluate-nist-ai-rmf-manage

## Standard implemented

- **NIST AI RMF 1.0 (AI 100-1)** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST AI RMF Playbook** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **OCSF 1.8 Compliance Finding (class 2003)** — https://schema.ocsf.io/1.8.0/classes/compliance_finding

## Function and subcategory citations

This skill implements 10 subcategories of the MANAGE function. Each is
named, scoped, and cited against the published AI RMF 1.0 Core (Section
5.4):

| Subcategory | Plain-English scope | Section in AI RMF 1.0 Core |
|---|---|---|
| MANAGE-1.1 | Risks prioritized | 5.4.1 |
| MANAGE-1.2 | Treatment of high-priority risks responded to | 5.4.1 |
| MANAGE-1.3 | Decisions on response approach communicated | 5.4.1 |
| MANAGE-1.4 | Negative impacts mitigated | 5.4.1 |
| MANAGE-2.1 | Resources allocated for risk management | 5.4.2 |
| MANAGE-2.2 | Mechanisms for sustained risk management | 5.4.2 |
| MANAGE-2.4 | Mechanisms for incident response | 5.4.2 |
| MANAGE-3.1 | Third-party risks regularly monitored | 5.4.3 |
| MANAGE-3.2 | Mechanisms to track + report on risk management | 5.4.3 |
| MANAGE-4.1 | Plans for ongoing risk monitoring | 5.4.4 |

## What gets checked

For each subcategory, the manifest entry is graded against four
predicates: `documented`, `review_cadence_days` + `last_reviewed`
within cadence, `evidence_uri` set, and `coverage >= 0.5`. All four →
PASS. Three with documented + coverage → PARTIAL. Fewer → FAIL. Opt-out
via `not_applicable: true` with a reason → NOT_APPLICABLE.

## Output schema

JSON output is the per-finding `Finding` dataclass (see `src/checks.py`).
OCSF output is class 2003 Compliance Finding 1.8.0; `compliance.control`
carries the subcategory ID.

## Permissions

None at runtime — the skill reads one local file.

## Honesty contract

This skill is a manifest-completeness and freshness audit. NIST AI RMF
1.0 MANAGE is an org-level + per-system function whose qualitative
assessment must still be performed by humans.
