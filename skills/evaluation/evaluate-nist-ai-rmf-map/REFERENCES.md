# References — evaluate-nist-ai-rmf-map

## Standard implemented

- **NIST AI RMF 1.0 (AI 100-1)** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST AI RMF Playbook** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **OCSF 1.8 Compliance Finding (class 2003)** — https://schema.ocsf.io/1.8.0/classes/compliance_finding

## Function and subcategory citations

This skill implements 10 subcategories of the MAP function. Each is
named, scoped, and cited against the published AI RMF 1.0 Core (Section
5.2):

| Subcategory | Plain-English scope | Section in AI RMF 1.0 Core |
|---|---|---|
| MAP-1.1 | Intended purposes documented | 5.2.1 |
| MAP-1.2 | AI categorized per intended use | 5.2.1 |
| MAP-1.3 | AI capabilities + limitations + assumptions documented | 5.2.1 |
| MAP-2.1 | System task + AI capability documented | 5.2.2 |
| MAP-2.2 | Information about scientific / technical foundations | 5.2.2 |
| MAP-3.1 | System benefits documented | 5.2.3 |
| MAP-3.2 | Costs documented | 5.2.3 |
| MAP-4.1 | Approaches for mapping AI risks documented | 5.2.4 |
| MAP-5.1 | Impacts on individuals + groups documented | 5.2.5 |
| MAP-5.2 | Likelihood + magnitude of impacts assessed | 5.2.5 |

## What gets checked

For each subcategory, the manifest entry is graded against four
predicates: `documented`, `review_cadence_days` + `last_reviewed`
within cadence, `evidence_uri` set, and `coverage >= 0.5`. All four →
PASS. Three with documented + coverage → PARTIAL. Fewer → FAIL.
Opt-out via `not_applicable: true` with a reason → NOT_APPLICABLE.

## Output schema

JSON output is the per-finding `Finding` dataclass (see `src/checks.py`).
OCSF output is class 2003 Compliance Finding 1.8.0; `compliance.control`
carries the subcategory ID.

## Permissions

None at runtime — the skill reads one local file.

## Honesty contract

This skill is a manifest-completeness and freshness audit. NIST AI RMF
1.0 MAP is an organisation-level + per-system function whose qualitative
assessment must still be performed by humans.
