# References — detect-web-broken-access-control

## OWASP

- OWASP Top 10 — A01:2021 Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Cheat Sheet — Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Cheat Sheet — Insecure Direct Object Reference Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

## CWE

- CWE-284 — Improper Access Control: https://cwe.mitre.org/data/definitions/284.html
- CWE-285 — Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
- CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR): https://cwe.mitre.org/data/definitions/639.html

## MITRE ATT&CK

- T1212 — Exploitation for Credential Access: https://attack.mitre.org/techniques/T1212/
- T1078 — Valid Accounts (alt mapping for cross-user variants): https://attack.mitre.org/techniques/T1078/
- TA0006 — Credential Access: https://attack.mitre.org/tactics/TA0006/

## OCSF

- HTTP Activity (class 4002): https://schema.ocsf.io/1.8.0/classes/http_activity (input shape)
- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding (output shape)
- Repo-pinned contract: [`skills/detection-engineering/OCSF_CONTRACT.md`](../../detection-engineering/OCSF_CONTRACT.md)

## Related repo skills

- [`detect-web-injection`](../detect-web-injection/) — A03:2021 sibling
- [`detect-web-auth-failures`](../detect-web-auth-failures/) — A07:2021 sibling
