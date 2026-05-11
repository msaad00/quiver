# References — detect-github-actions-secret-disclosure

## GitHub documentation

- **Using secrets in GitHub Actions** — https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
- **GitHub Actions secrets masking** — https://docs.github.com/en/actions/security-guides/encrypted-secrets#accessing-your-secrets
- **REST API — get a workflow run log** — https://docs.github.com/en/rest/actions/workflow-runs#download-workflow-run-logs
- **Audit log event documentation — `workflows.*`** — https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization#workflows-category-actions

## Detection rationale

- **MITRE ATT&CK T1552 — Unsecured Credentials** — https://attack.mitre.org/techniques/T1552/
- **MITRE ATT&CK T1552.004 — Private Keys** — https://attack.mitre.org/techniques/T1552/004/
- **CWE-532 — Insertion of Sensitive Information into Log File** — https://cwe.mitre.org/data/definitions/532.html
- **OWASP LLM Top 10 LLM02 — Insecure Output Handling** — https://owasp.org/www-project-top-10-for-large-language-model-applications/

## Wire format

- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Heuristic notes

- The detector requires Shannon entropy ≥ 3.5 bits/byte on candidates
  to avoid firing on repeated-character base64 / hex patterns
  (`aaaa...`, `00000...`).
- Previews shipped in the finding are length-truncated
  (`<first8>...<last4>`) so the full secret never travels on the wire.

## Required permissions (upstream ingester only)

- Read-only access to workflow run logs
  (`actions:read` repo scope or `workflow_run` webhook subscription
  + log fetch).
- This detector itself runs offline on already-normalized OCSF JSONL
  and has no IAM dependency.
