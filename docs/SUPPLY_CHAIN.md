# Supply Chain And Dependency Trust

This repo is intentionally conservative about dependencies.

The dependency policy is:

1. **Official vendor SDK first**
   - AWS: `boto3`
   - Azure: `azure-*`
   - Google Cloud: `google-cloud-*`, `google-api-python-client`
   - Snowflake: `snowflake-connector-python`
   - Databricks: `databricks-sql-connector`
   - ClickHouse: `clickhouse-connect`
2. **Repo-owned code second**
   - if the logic can stay inside the repo cleanly, prefer that over adding a
     new package
3. **Canonical OSS library only when needed**
   - use a broadly trusted ecosystem package only when the vendor does not ship
     a usable SDK or when the stdlib would materially worsen security,
     correctness, or maintainability

## Current Runtime Story

The full `uv.lock` is the **ceiling**, not a typical installation shape.

- `uv.lock` includes dev, test, CI, and security-tooling dependencies
- real operator installs are driven by dependency groups in
  [`pyproject.toml`](../pyproject.toml)
- the repo is not packaged as one installable application; operators install
  only the dependency groups needed for the skills they run

The operator-facing install path is documented in [`INSTALL.md`](INSTALL.md).
The short version: use GitHub tags or signed GitHub Release source tarballs,
not PyPI, Homebrew, or a container image.

Today the direct runtime dependency groups are:

- `aws`
- `azure`
- `gcp`
- `iam_departures`

The CI SBOM artifact therefore serves two transparency goals:

- **full-lock SBOM**
  - the entire pinned dependency ceiling across dev + runtime + CI groups
- **dependency-policy docs**
  - the explanation of which groups are real runtime surfaces versus CI-only or
    test-only tooling

## Documented Runtime Exception

The one deliberate non-vendor runtime exception today is:

- `httpx`
  - used only by the direct Workday RaaS API source in
    [`skills/discovery/iam-departures-reconciler/src/reconciler/sources.py`](../skills/discovery/iam-departures-reconciler/src/reconciler/sources.py)
  - kept because Workday does not provide a first-party Python SDK for this
    path, and `httpx` gives clearer timeout, auth, and transport handling than
    a stdlib `urllib.request` implementation

This is acceptable under the repo policy because it is:

- narrow in scope
- tied to a documented vendor API
- isolated to one remediation source path
- easier to reason about than a bespoke HTTP wrapper

## What We Trust

We prefer packages from:

- official cloud and data-platform vendors
- Python ecosystem steward orgs such as PyPA, PyCQA, pytest-dev, Pallets,
  PyCA, and Astral
- other established projects when the package has a clear maintainer and
  ecosystem role

We do **not** add dependencies casually for:

- convenience wrappers around official SDKs
- telemetry or analytics
- hidden agent behavior
- narrow single-maintainer abstractions when repo-owned code is simpler

## CI Transparency

The CI pipeline now publishes a CycloneDX SBOM artifact generated from the
locked dependency graph.

That artifact is now accompanied by a Sigstore keyless signature and
certificate generated from GitHub Actions OIDC during the `sbom` lane.

That artifact is intended to support:

- auditor review
- release review
- dependency provenance discussion
- downstream customer ingest into their own supply-chain tooling

The uploaded artifact set contains:

- `cloud-ai-security-skills-full-lock.cdx.json`
- `cloud-ai-security-skills-full-lock.cdx.json.sigstore.json`

This gives consumers both the SBOM itself and the materials needed to verify
that the CI workflow, not an out-of-band process, produced it.

See:

- [`docs/CI_WORKFLOW.md`](CI_WORKFLOW.md)
- [`SECURITY_BAR.md`](../SECURITY_BAR.md)
- [`docs/RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)

## Release Distribution

Published GitHub Releases rebuild and attach both a signed CycloneDX SBOM and a
signed source tarball, each with a SLSA build-provenance attestation and a
CycloneDX SBOM attestation linking the tarball to its dependency graph:

- SBOM: `cloud-ai-security-skills-full-lock.cdx.json` plus the matching
  `.sigstore.json` Sigstore bundle
- Source tarball: `cloud-ai-security-skills-<tag>-source.tar.gz` plus the
  matching `.sigstore.json` Sigstore bundle, downloaded from the
  GitHub `tarball/refs/tags/<tag>` endpoint at release time and signed
  keylessly via `cosign sign-blob` with GitHub OIDC
- Attestations: `actions/attest-build-provenance@v2` publishes SLSA
  provenance for both the SBOM and the source tarball to the repo's
  GitHub attestation log, and `actions/attest-sbom@v3` binds the SBOM to
  the source tarball so consumers can verify the dependency graph came
  from the same release

That keeps the release surface self-contained for buyers, auditors, and
downstream automation that reads release assets instead of CI artifacts, and
lets consumers verify with either `cosign verify-blob` against the Sigstore
cert or `gh attestation verify` against the GitHub attestation log.

Verification example (consumer side):

```bash
tag=vX.Y.Z
tarball="cloud-ai-security-skills-${tag}-source.tar.gz"
cosign verify-blob \
  --certificate      "${tarball}.pem" \
  --signature        "${tarball}.sig" \
  --certificate-identity-regexp 'https://github.com/msaad00/cloud-ai-security-skills/' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com' \
  "${tarball}"

gh attestation verify "${tarball}" \
  --repo msaad00/cloud-ai-security-skills
```

## Future Tightenings

- export a runtime-group SBOM artifact once the repo's non-package group layout
  supports a clean grouped CycloneDX export without workarounds
- emit SPDX alongside CycloneDX if a customer or procurement workflow requires
  both formats
