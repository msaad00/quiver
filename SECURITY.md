# Security Policy

## Supported Versions

The `main` branch is the supported release line. Security fixes land there first.

## Reporting a Vulnerability

Please do not open public GitHub issues for suspected vulnerabilities.

Send reports through [GitHub private security reporting](https://github.com/msaad00/cloud-ai-security-skills/security/advisories/new)
or directly by email if a contact is listed on the maintainer profile. Include:

- affected skill and file path
- impact and attack scenario
- steps to reproduce
- proof-of-concept details if available
- whether secrets, credentials, or customer data were involved

## Response Expectations

- initial acknowledgment target: 48 hours
- remediation triage target: 7 business days
- critical or high-severity fix/mitigation target: 30 calendar days when a safe patch path exists
- medium-severity fix/mitigation target: 90 calendar days or the next planned minor release, whichever comes first
- coordinated disclosure after a fix or mitigation is available

## Secure Usage Requirements

- never commit credentials, tokens, or customer data
- source runtime secrets from AWS Secrets Manager, SSM Parameter Store, Vault, or workload identity
- prefer federation and short-lived credentials over static passwords or long-lived API tokens
- treat the repo as secret-minimizing, not password-free: a few vendor paths still require injected client secrets, passwords, or scoped tokens today
- keep CSPM execution roles read-only unless the skill is explicitly remediation-oriented
- run CI checks before merging changes that affect IAM, cloud auth, or infrastructure templates
- keep S3 artifacts KMS-encrypted and scope cross-account trust by `aws:PrincipalOrgID`

## Dependency Trust And SBOM

- prefer official vendor SDKs and repo-owned code over convenience wrappers
- add a third-party runtime dependency only when the vendor has no usable SDK or
  the stdlib would materially worsen the implementation
- review direct runtime dependency additions as security-relevant changes
- use the published CycloneDX CI artifact and [`docs/SUPPLY_CHAIN.md`](docs/SUPPLY_CHAIN.md)
  as the source of truth for dependency transparency

## Credential Posture

- prefer workload identity, STS, impersonation, OIDC, or other short-lived execution identity first
- prefer official vendor-issued tokens second
- use manager-injected passwords or client secrets only where the vendor path still requires them
- never log, echo, or persist secret values in findings, evidence, stderr telemetry, or audit records
- redact sensitive values if they appear in bug reports, examples, screenshots, or operator-provided input

See [docs/CREDENTIAL_PROVENANCE.md](docs/CREDENTIAL_PROVENANCE.md) for the repo-wide credential hierarchy, current exceptions, and the rationale for keeping a narrow direct Workday `httpx` path in remediation.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the repo's asset,
adversary, trust-boundary, and mitigation model.
