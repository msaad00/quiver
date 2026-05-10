# References — evaluate-nist-ai-rmf-measure

## Standard implemented

- **NIST AI RMF 1.0 (AI 100-1)** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST AI RMF Playbook** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **OCSF 1.8 Compliance Finding (class 2003)** — https://schema.ocsf.io/1.8.0/classes/compliance_finding

## Function and subcategory citations

This skill implements 10 subcategories of the MEASURE function. Each is
named, scoped, and cited against the published AI RMF 1.0 Core (Section
5.3):

| Subcategory | Plain-English scope | Section in AI RMF 1.0 Core |
|---|---|---|
| MEASURE-1.1 | Measurement approaches selected | 5.3.1 |
| MEASURE-1.3 | Internal experts + external stakeholders consulted | 5.3.1 |
| MEASURE-2.1 | Test sets + metrics for trustworthy characteristics | 5.3.2 |
| MEASURE-2.3 | Performance evaluated under nominal conditions | 5.3.2 |
| MEASURE-2.4 | System validated for context-of-use | 5.3.2 |
| MEASURE-2.5 | Reliability assessed under context-of-use | 5.3.2 |
| MEASURE-2.6 | Safety risks measured + documented | 5.3.2 |
| MEASURE-2.7 | Security + resilience assessed | 5.3.2 |
| MEASURE-2.10 | Privacy risks measured | 5.3.2 |
| MEASURE-3.1 | Approaches for ongoing monitoring documented | 5.3.3 |

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
1.0 MEASURE is a per-system function whose qualitative assessment must
still be performed by humans.
