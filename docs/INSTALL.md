# Install And Use

This repo is usable today from GitHub releases and source checkouts. It is not
ready to be advertised as a PyPI-installed product because the repo is a bundle
of independent skills, runners, validators, and docs rather than one importable
Python package.

## Recommended Distribution

Use GitHub Releases as the public download surface:

1. Cut a signed tag with the release checklist.
2. Publish a GitHub Release for that tag.
3. Let the release workflow attach the signed source tarball, signed CycloneDX
   SBOM, and GitHub attestations.
4. Tell users to download the release tarball or clone the tag.

Do not publish this to PyPI yet. `pyproject.toml` intentionally sets
`package = false`, and dependency groups are scoped by operator surface.

## Download

Clone a signed tag:

```bash
git clone https://github.com/msaad00/cloud-ai-security-skills.git
cd cloud-ai-security-skills
git fetch --tags
git tag -v v0.8.1
git checkout v0.8.1
```

Or download the source tarball from the matching GitHub Release.

## Verify Release Assets

For release tarballs, verify the GitHub attestation before use:

```bash
tag=v0.8.1
tarball="cloud-ai-security-skills-${tag}-source.tar.gz"

gh attestation verify "${tarball}" \
  --repo msaad00/cloud-ai-security-skills
```

When the Sigstore bundle is present, also verify the signed blob:

```bash
cosign verify-blob \
  --bundle "${tarball}.sigstore.json" \
  --certificate-identity-regexp 'https://github.com/msaad00/cloud-ai-security-skills/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${tarball}"
```

## Install Dependencies

Install only the groups needed for the skills you run.

Read-only detection from JSONL fixtures usually needs no cloud SDK group:

```bash
uv run python skills/detection/detect-cloudtrail-disabled/src/detect.py input.ocsf.jsonl
```

AWS live access:

```bash
uv sync --group aws
```

GCP live access:

```bash
uv sync --group gcp
```

Azure live access:

```bash
uv sync --group azure
```

IAM departures planning and source adapters:

```bash
uv sync --group iam_departures
```

MCP stdio wrapper (`mcp-server/src/server.py`):

```bash
uv sync --group mcp
```

Development and validation:

```bash
uv sync --group dev
```

## Smoke Test

Run the contract and count gates before using a downloaded release in
automation:

```bash
uv run python scripts/validate_skill_contract.py
uv run python scripts/validate_skill_integrity.py
uv run python scripts/validate_framework_coverage.py
uv run python scripts/validate_skill_count_consistency.py
```

For a fuller local bar:

```bash
uv run ruff check skills/ tests/ mcp-server/ scripts/ --config pyproject.toml
uv run pytest -q
bash scripts/run_mypy.sh
```

## Run A Skill

Each skill is a standalone `SKILL.md + src/ + tests/` bundle. Most read-only
skills accept JSONL on stdin or a file path.

Example:

```bash
python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py cloudtrail.jsonl \
  | python skills/detection/detect-cloudtrail-disabled/src/detect.py \
  > findings.ocsf.jsonl
```

MCP and runner usage is documented separately:

- MCP: [`mcp-server/README.md`](../mcp-server/README.md)
- Runtime model: [`docs/RUNNER_CONTRACT.md`](RUNNER_CONTRACT.md)
- Supply chain: [`docs/SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md)

## Readiness

Ready to post:

- GitHub repository
- GitHub Releases with signed source tarball, SBOM, and attestations
- README, architecture docs, per-skill contracts, and CI badges

Not ready to post as:

- PyPI package
- Homebrew formula
- container image
- managed SaaS or hosted MCP endpoint

Those distribution channels need a separate packaging contract, runtime entry
point, upgrade policy, and support policy.
