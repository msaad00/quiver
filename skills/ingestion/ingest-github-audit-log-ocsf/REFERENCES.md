# References — ingest-github-audit-log-ocsf

## Source formats and schemas

- **GitHub Organization Audit Log overview** — https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization
- **Audit log REST API** — https://docs.github.com/en/rest/orgs/orgs#get-the-audit-log-for-an-organization
- **Audit log streaming** — https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise
- **Audit log event documentation** (action catalog) — https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
- **GitHub Actions secrets** — https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
- **Personal Access Tokens** — https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens

## Output format

- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Authentication (3002)** — https://schema.ocsf.io/1.8.0/classes/authentication
- **OCSF 1.8 User Access Management (3005)** — https://schema.ocsf.io/1.8.0/classes/user_access
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor

## Collection guidance

The skill itself reads JSON from stdin or local files and does not call
GitHub. Upstream collectors should:

- prefer audit-log streaming (S3 / GCS / Azure Blob / Splunk / Datadog /
  Amazon Event Bridge) over polling the REST endpoint
- follow `link: rel="next"` headers when polling `/orgs/{org}/audit-log`
- preserve raw `_document_id`, `@timestamp`, `request_id`, and (when
  present) `hashed_token`
- request `include=all` on the REST call to capture both `git` and `web`
  events

GitHub documents that audit-log entries may take up to a few minutes to
materialize after the underlying API call. The skill keeps the source
`@timestamp` and GitHub natural IDs intact so downstream correlation can
reason about that lag explicitly.

## MITRE ATT&CK references

- **T1098 — Account Manipulation** — https://attack.mitre.org/techniques/T1098/
- **T1098.001 — Additional Cloud Credentials** — https://attack.mitre.org/techniques/T1098/001/
- **T1078.004 — Cloud Accounts** — https://attack.mitre.org/techniques/T1078/004/
- **T1552.004 — Private Keys / Credentials in Logs** — https://attack.mitre.org/techniques/T1552/004/

## Required permissions

- `read:audit_log` (org admin) or audit-log streaming destination read
  access. Read-only — no write scopes required.
