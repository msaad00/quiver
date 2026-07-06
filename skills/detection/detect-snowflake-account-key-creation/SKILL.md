---
name: detect-snowflake-account-key-creation
description: >-
  Detect addition of an RSA / public-key credential to a Snowflake user. Reads
  OCSF 1.8 API Activity (class 6003) records normalized from Snowflake
  `query_history` carrying `actor.user.uid`, `api.operation == "ALTER_USER"`,
  and Snowflake-shaped `unmapped.snowflake.{target_user,statement_kind,
  rsa_public_key_set}` fields, and emits one OCSF 1.8 Detection Finding (class
  2004) per `ALTER USER ... SET RSA_PUBLIC_KEY` event, tagged with MITRE
  ATT&CK T1098.001 Additional Cloud Credentials. Use when the user mentions
  "Snowflake key-pair auth added", "RSA_PUBLIC_KEY set on Snowflake user",
  "T1098.001 in Snowflake", or "additional cloud credentials in Snowflake".
  Do NOT use on raw Snowflake QUERY_HISTORY JSON before OCSF normalization,
  as a posture-at-rest key inventory check, or as a generic
  credential-issuance detector for non-Snowflake platforms.
purpose: Detect addition of an RSA / public-key credential to a Snowflake user.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: ocsf
output_formats: native, ocsf
concurrency_safety: stateless
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-account-key-creation
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-account-key-creation

## Attack pattern

Snowflake supports key-pair authentication as an alternative to passwords.
Once an RSA public key is bound to a user (`ALTER USER <name> SET
RSA_PUBLIC_KEY = '...'`), the holder of the matching private key can
authenticate via the Snowflake driver / SQL API / JDBC without an
interactive login and without triggering MFA. An attacker who reaches
`ACCOUNTADMIN`, `SECURITYADMIN`, or a role with `OWNERSHIP` on the target
user can register their own public key and persist headless access until the
key is rotated.

On the wire the pattern is:

- `ALTER USER <name> SET RSA_PUBLIC_KEY = '...'`
- `ALTER USER <name> SET RSA_PUBLIC_KEY_2 = '...'` (rolling-key slot)

Both surfaces materialize in Snowflake QUERY_HISTORY and both normalize into
OCSF 1.8 API Activity (class `6003`) once ingested.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to `api.operation == "ALTER_USER"`.
2. Require a successful event (`status_id == 1`).
3. Require `unmapped.snowflake.rsa_public_key_set == True` **or**
   `unmapped.snowflake.statement_kind` containing `RSA_PUBLIC_KEY`.
4. Require a non-empty `unmapped.snowflake.target_user`.
5. Emit one finding per anchor event.

The detector is stateless — every successful key-add event fires once.

Operators can tune the key-field set at runtime without forking:

- `SNOWFLAKE_KEY_STATEMENT_HINTS` — comma-separated, default
  `RSA_PUBLIC_KEY,RSA_PUBLIC_KEY_2`.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-account-key-creation", "OWASP-Top-10-A07"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1098.001` (tactic
  `TA0003 Persistence`)
- `evidence.target_user`, `evidence.statement_kind`, `evidence.key_slot`
- `observables[]` carrying granter, target user, and key slot

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_account_key_findings.ocsf.jsonl

cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > snowflake_account_key_findings.native.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY JSON before OCSF normalization
- As a posture-at-rest key inventory check
- As a remediation skill — key revocation lives in the remediation layer
- On non-Snowflake API Activity 6003

## Tests

The test suite covers:

- positive: `ALTER USER SET RSA_PUBLIC_KEY` fires once
- positive: `RSA_PUBLIC_KEY_2` slot also fires
- negative: `ALTER USER SET DEFAULT_ROLE` (no key) does not fire
- negative: failed key-set does not fire
- negative: events from a non-Snowflake producer are ignored
- edge: missing `target_user` is ignored
- edge: duplicate `metadata.uid` does not inflate counts
- env-override: `SNOWFLAKE_KEY_STATEMENT_HINTS` honored

## Roadmap

Third of 18 warehouse-platform vendor-depth detectors for issue #436.
