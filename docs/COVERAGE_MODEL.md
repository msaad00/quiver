# Coverage Model

`cloud-ai-security-skills` does not use vague framework claims. Coverage is measured
against an explicit scope:

- framework version
- provider scope
- asset-class scope
- layer scope
- implementation status
- test status
- validation status

The source of truth for current coverage is
[`docs/framework-coverage.json`](framework-coverage.json).

## What "coverage" means

Coverage is tracked across four levels:

| Level | Meaning |
|---|---|
| **mapped** | the skill explicitly maps to the framework or control family |
| **implemented** | the code emits or evaluates that mapping today |
| **tested** | the mapping is exercised by automated tests or golden fixtures |
| **validated** | shared repo validators enforce the contract, references, and safety bar |

The repo should only claim broad framework coverage when the relevant scope is
both **implemented** and **tested**.

## Coverage dimensions

Every material coverage statement should be measurable across these dimensions:

| Dimension | Examples |
|---|---|
| **Layer** | ingest, discover, detect, evaluate, view, remediate |
| **Provider** | AWS, Azure, GCP, Kubernetes, containers, MCP, multi |
| **Asset class** | identities, compute, storage, network, logging, clusters, AI endpoints, models, datasets, GPUs, evidence |
| **Framework** | OCSF, MITRE ATT&CK, MITRE ATLAS, CIS, NIST CSF, NIST AI RMF, PCI DSS, SOC 2, ISO 27001, OWASP LLM |
| **Execution mode** | CLI, CI, MCP, persistent/serverless |
| **Approval model** | read-only, dry-run first, HITL, side-effectful edge |

## Coverage policy

The repo follows these rules:

1. Use native **OCSF** classes, profiles, or extensions when they fit.
2. If OCSF does not fit cleanly, use a deterministic bridge artifact and
   document the mapping path back to OCSF.
3. Use only official vendor, schema, benchmark, or framework docs in
   `REFERENCES.md`.
4. Do not claim "100% coverage" without naming:
   - framework version
   - providers in scope
   - asset classes in scope
   - implementation and test status
5. Keep coverage machine-readable so CI can validate it.

## Target language

The strongest safe claim format is:

> `mapped coverage` target: 100% across the declared provider and asset scope
> for framework version `X`, with implementation/test status tracked in the
> coverage registry.

This is better than claiming universal completeness without scope.

## Progress model

Use these progress states in roadmap and reviews:

| State | Meaning |
|---|---|
| **gap** | no meaningful support yet |
| **mapped** | documented and scoped, but not fully implemented |
| **implemented** | code exists |
| **tested** | implementation has automated coverage |
| **validated** | implementation is also enforced by repo validators and CI |

## Why this exists

Security teams and engineers need to know:

- what the repo actually covers today
- which skills can be trusted for which frameworks
- where the gaps still are
- which layers are ready for just-in-time use, CI, MCP, or continuous runs

This model keeps that story explicit, versioned, and auditable.
