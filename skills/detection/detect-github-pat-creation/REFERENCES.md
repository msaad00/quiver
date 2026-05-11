# References — detect-github-pat-creation

## GitHub documentation

- **Personal Access Tokens** — https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
- **Fine-grained PAT API approval flow** — https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-programmatic-access-to-your-organization/managing-requests-for-personal-access-tokens-in-your-organization
- **Audit log event documentation — `personal_access_token.*`** — https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization

## Detection rationale

- **MITRE ATT&CK T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **MITRE ATT&CK T1098.001 — Additional Cloud Credentials** — https://attack.mitre.org/techniques/T1098/001/
- **OWASP LLM Top 10 LLM02 — Insecure Output Handling** — https://owasp.org/www-project-top-10-for-large-language-model-applications/

## Wire format

- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding
- **OCSF 1.8 finding_info object** — https://schema.ocsf.io/1.8.0/objects/finding_info

## Required permissions (upstream ingester only)

- Read-only access to GitHub audit log (`read:audit_log` on org admin)
- This detector itself runs offline on already-normalized OCSF JSONL
  and has no IAM dependency.
