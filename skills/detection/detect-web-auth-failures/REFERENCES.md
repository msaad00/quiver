# References — detect-web-auth-failures

## OWASP

- OWASP Top 10 — A07:2021 Identification and Authentication Failures: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- OWASP Cheat Sheet — Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Cheat Sheet — Multifactor Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- OWASP Cheat Sheet — Credential Stuffing Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- OWASP ASVS V2 — Authentication Verification Requirements: https://github.com/OWASP/ASVS

## CWE

- CWE-287 — Improper Authentication: https://cwe.mitre.org/data/definitions/287.html
- CWE-307 — Improper Restriction of Excessive Authentication Attempts: https://cwe.mitre.org/data/definitions/307.html
- CWE-308 — Use of Single-factor Authentication: https://cwe.mitre.org/data/definitions/308.html
- CWE-521 — Weak Password Requirements: https://cwe.mitre.org/data/definitions/521.html
- CWE-798 — Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html

## MITRE ATT&CK

- T1110 — Brute Force: https://attack.mitre.org/techniques/T1110/
- T1078 — Valid Accounts: https://attack.mitre.org/techniques/T1078/
- TA0006 — Credential Access: https://attack.mitre.org/tactics/TA0006/

## OCSF

- HTTP Activity (class 4002): https://schema.ocsf.io/1.8.0/classes/http_activity (input shape)
- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding (output shape)

## Related repo skills

- [`detect-credential-stuffing-okta`](../detect-credential-stuffing-okta/) — Okta-native credential-stuffing detector
- [`detect-okta-mfa-fatigue`](../detect-okta-mfa-fatigue/) — Okta MFA-push-bombing detector
- [`detect-google-workspace-suspicious-login`](../detect-google-workspace-suspicious-login/) — Workspace login anomalies
- [`detect-web-broken-access-control`](../detect-web-broken-access-control/) — A01:2021 sibling
- [`detect-web-injection`](../detect-web-injection/) — A03:2021 sibling
