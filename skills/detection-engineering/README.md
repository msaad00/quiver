# detection-engineering/ (shared assets)

This folder owns shared OCSF wire-contract and golden-fixture assets used by
the layered skills elsewhere in the repo.

Canonical skill locations are:

- ingestion skills: [`../ingestion/`](../ingestion/)
- detection skills: [`../detection/`](../detection/)
- view / convert skills: [`../view/`](../view/)

This folder owns shared cross-skill assets:

- [`OCSF_CONTRACT.md`](./OCSF_CONTRACT.md)
- [`golden/`](./golden/) — synthetic snapshot fixtures only; see [`golden/README.md`](./golden/README.md) for what they verify and what they do not

It is not a skill layer. New executable skills belong under `ingestion/`,
`detection/`, or `view/` as appropriate.
