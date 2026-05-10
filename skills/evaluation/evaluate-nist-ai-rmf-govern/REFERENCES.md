# References — evaluate-nist-ai-rmf-govern

## Standard implemented

- **NIST AI RMF 1.0 (AI 100-1)** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST AI RMF Playbook** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **OCSF 1.8 Compliance Finding (class 2003)** — https://schema.ocsf.io/1.8.0/classes/compliance_finding

## Function and subcategory citations

This skill implements 10 subcategories of the GOVERN function. Each is
named, scoped, and cited against the published AI RMF 1.0 Core (Section
5.1):

| Subcategory | Plain-English scope | Section in AI RMF 1.0 Core |
|---|---|---|
| GOVERN-1.1 | AI risk management documented and reviewed | 5.1.1 |
| GOVERN-1.2 | Roles, responsibilities, and lines of authority defined | 5.1.1 |
| GOVERN-1.4 | AI risk management integrated with enterprise risk | 5.1.1 |
| GOVERN-1.6 | Mechanisms to inventory AI systems | 5.1.1 |
| GOVERN-2.1 | Workforce trained on AI risk | 5.1.2 |
| GOVERN-3.1 | Policies for impacted communities | 5.1.3 |
| GOVERN-4.1 | Organizational practices documented for AI development | 5.1.4 |
| GOVERN-5.1 | Policies for third-party AI input | 5.1.5 |
| GOVERN-6.1 | AI risk decisions communicated upward | 5.1.6 |
| GOVERN-6.2 | Mechanisms to address AI risk in third-party transactions | 5.1.6 |

## What gets checked

For each subcategory, the manifest entry is graded against four
predicates derived from the AI RMF Playbook ("documented, reviewed,
covered, evidenced"):

1. `documented: true`
2. `review_cadence_days` set AND `last_reviewed` within cadence
3. `evidence_uri` set
4. `coverage >= 0.5`

All four predicates → PASS. Three of four (with documented + coverage)
→ PARTIAL. Fewer → FAIL. The entry can opt out via `not_applicable: true`
with a reason; that resolves to NOT_APPLICABLE.

## Output schema

JSON output is the per-finding `Finding` dataclass (see `src/checks.py`).
OCSF output is class 2003 Compliance Finding 1.8.0; `compliance.control`
carries the subcategory ID and `compliance.status` ∈ {PASS, PARTIAL,
FAIL, NOT_APPLICABLE, ERROR}.

## Permissions

None at runtime — the skill reads one local file. The CI step that
collects evidence from internal systems is responsible for any source
credentials.

## Honesty contract

This skill is a manifest-completeness and freshness audit. NIST AI RMF
1.0 GOVERN is an organisation-level function whose qualitative
assessment must still be performed by humans. The manifest is the input
to that assessment; this skill verifies the input.
