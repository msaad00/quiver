# References — detect-web-injection

## OWASP

- OWASP Top 10 — A03:2021 Injection: https://owasp.org/Top10/A03_2021-Injection/
- OWASP Cheat Sheet — SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet — OS Command Injection Defense: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- OWASP Cheat Sheet — LDAP Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- OWASP Cheat Sheet — Server Side Template Injection (SSTI): https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- OWASP WSTG — NoSQL Injection: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection

## CWE

- CWE-89 — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection): https://cwe.mitre.org/data/definitions/89.html
- CWE-78 — OS Command Injection: https://cwe.mitre.org/data/definitions/78.html
- CWE-90 — LDAP Injection: https://cwe.mitre.org/data/definitions/90.html
- CWE-91 — XML Injection (XPath/XQuery): https://cwe.mitre.org/data/definitions/91.html
- CWE-94 — Improper Control of Generation of Code (Code Injection): https://cwe.mitre.org/data/definitions/94.html
- CWE-943 — Improper Neutralization of Special Elements in Data Query Logic (NoSQL): https://cwe.mitre.org/data/definitions/943.html
- CWE-1336 — Improper Neutralization of Special Elements Used in a Template Engine: https://cwe.mitre.org/data/definitions/1336.html

## MITRE ATT&CK

- T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- TA0001 — Initial Access: https://attack.mitre.org/tactics/TA0001/

## OCSF

- HTTP Activity (class 4002): https://schema.ocsf.io/1.8.0/classes/http_activity (input shape)
- Detection Finding (class 2004): https://schema.ocsf.io/1.8.0/classes/detection_finding (output shape)

## Related repo skills

- [`detect-web-broken-access-control`](../detect-web-broken-access-control/) — A01:2021 sibling
- [`detect-web-auth-failures`](../detect-web-auth-failures/) — A07:2021 sibling
