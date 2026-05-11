# References — detect-github-org-secret-exposure

## GitHub documentation

- **GitHub Actions secrets — overview** — https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
- **REST API — org-level Actions secrets** — https://docs.github.com/en/rest/actions/secrets#list-organization-secrets
- **REST API — org-level Codespaces secrets** — https://docs.github.com/en/rest/codespaces/organization-secrets
- **REST API — org-level Dependabot secrets** — https://docs.github.com/en/rest/dependabot/secrets#list-organization-secrets
- **Audit log event documentation — `actions.org_secret_*` / `codespaces.org_secret_*` / `dependabot_secrets.*`** — https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization

## Detection rationale

- **MITRE ATT&CK T1078 — Valid Accounts** — https://attack.mitre.org/techniques/T1078/
- **MITRE ATT&CK T1078.004 — Cloud Accounts** — https://attack.mitre.org/techniques/T1078/004/
- **OWASP LLM Top 10 LLM02 — Insecure Output Handling** — https://owasp.org/www-project-top-10-for-large-language-model-applications/

## Wire format

- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Configuration

- `GITHUB_ORG_SECRET_REPO_DELTA` — integer, default `5`. The maximum
  number of repos that can be added to `selected_repositories` in a
  single event before the detector fires MEDIUM.

## Required permissions (upstream ingester only)

- Read-only access to GitHub audit log (`read:audit_log` on org admin)
- This detector itself runs offline on already-normalized OCSF JSONL
  and has no IAM dependency.
