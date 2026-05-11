---
name: detect-snowflake-network-policy-disable
description: >-
  Detect Snowflake network-policy changes that remove or widen IP allowlists.
  Reads OCSF 1.8 API Activity (class 6003) records normalized from
  `account_usage.query_history` carrying the Snowflake-shaped
  `unmapped.snowflake.{policy_name,allowed_ip_list,blocked_ip_list,
  operation_kind}` block and emits an OCSF 1.8 Detection Finding (class 2004)
  tagged with MITRE ATT&CK T1562.007 Impair Defenses: Disable or Modify Cloud
  Firewall whenever `ALTER ACCOUNT SET NETWORK_POLICY = NULL`,
  `ALTER NETWORK POLICY ... SET ALLOWED_IP_LIST` containing `0.0.0.0/0`, or
  any other change that effectively disables IP-based network controls is
  observed. Use when you suspect a compromised credential is opening the
  Snowflake account to the open internet. Do NOT use on raw Snowflake
  QUERY_HISTORY rows — normalize them through the upstream Snowflake ingest
  pipeline first. Do NOT use as a generic firewall-drift detector for
  non-Snowflake providers.
purpose: Detect Snowflake network-policy changes that remove or widen IP allowlists.
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
concurrency_safety: requires_consistent_sharding
metadata:
  homepage: https://github.com/msaad00/cloud-ai-security-skills
  source: https://github.com/msaad00/cloud-ai-security-skills/tree/main/skills/detection/detect-snowflake-network-policy-disable
  version: 0.1.0
  frameworks:
    - OCSF 1.8
    - MITRE ATT&CK v14
    - OWASP Top 10
  cloud:
    - snowflake
---

# detect-snowflake-network-policy-disable

## Attack pattern

Snowflake network policies are IP-allowlist objects bound at the account or
user level. Disabling or widening them is a clean way for an attacker to keep
a compromised credential reachable from an arbitrary IP:

- `ALTER ACCOUNT SET NETWORK_POLICY = NULL` removes the account-wide policy
  entirely.
- `ALTER NETWORK POLICY <name> SET ALLOWED_IP_LIST = ('0.0.0.0/0')` widens
  the policy to permit every public IP.
- `ALTER NETWORK POLICY <name> UNSET BLOCKED_IP_LIST` removes blocks that
  had previously kept attacker ranges out.

This skill keeps the logic narrow to those three flavors. It does not flag
benign policy renames or rotations to a different, still-restrictive
allowlist.

## Detection logic

One pass over OCSF 1.8 API Activity (class `6003`) events whose
`metadata.product.feature.name` identifies a Snowflake ingest source:

1. Filter to `ALTER_ACCOUNT`, `ALTER_NETWORK_POLICY`, `CREATE_NETWORK_POLICY`,
   `CREATE_OR_REPLACE_NETWORK_POLICY`, and `UNSET_NETWORK_POLICY` operations.
2. Fire **once per event** when ANY of the following is true:
   - The Snowflake block records `operation_kind = "unset_network_policy"` or
     the operation explicitly NULL-ed the account-level network policy.
   - `allowed_ip_list` contains `0.0.0.0/0` (or `::/0`).
   - `allowed_ip_list` is empty / null while a non-empty list was recorded
     immediately prior on the same policy (recorded by the upstream
     normaliser as `operation_kind = "widened_allowlist"`).

The detector emits one finding per policy modification — never aggregated —
and dedupes via `metadata.uid`.

There are no operator-tunable thresholds; widening to `0.0.0.0/0` or NULLing
the policy is always reported.

## Output contract

Emits OCSF 1.8 Detection Finding (class `2004`) by default. With
`--output-format native`, emits the repo-owned native finding projection.

OCSF output includes:

- deterministic `metadata.uid` and `finding_info.uid`
- `finding_info.types[] = ["snowflake-network-policy-disable", "OWASP-Top-10-A05"]`
- `finding_info.attacks[]` populated with MITRE ATT&CK `T1562.007` (tactic
  `TA0005 Defense Evasion`)
- `evidence.policy_name`, `evidence.operation`, `evidence.operation_kind`,
  `evidence.allowed_ip_list`, `evidence.opened_wide`, `evidence.raw_event_uids`
- `observables[]` carrying the impacted principal, policy name, and the
  allowed/blocked IP lists

Severity is `HIGH` (severity_id `4`).

## Usage

```bash
# OCSF 1.8 API Activity 6003 in, OCSF Detection Finding 2004 out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py \
  > snowflake_network_policy_disable_findings.ocsf.jsonl

# Same input, native finding projection out:
cat snowflake_query_history.ocsf.jsonl \
  | python src/detect.py --output-format native \
  > snowflake_network_policy_disable_findings.native.jsonl
```

## Do NOT use

- On raw Snowflake QUERY_HISTORY JSON before OCSF normalization
- As a generic firewall drift detector for AWS / GCP / Azure (those skills
  exist separately under `detect-aws-open-security-group`,
  `detect-gcp-open-firewall`, `detect-azure-open-nsg`)
- As a remediation skill — restoring network policies lives in the
  remediation layer
- On non-Snowflake API Activity 6003 (we filter on the Snowflake-shaped
  `unmapped.snowflake.*` block plus the producer source skill)

## Tests

The test suite covers:

- positive: `ALTER ACCOUNT SET NETWORK_POLICY = NULL` fires
- positive: `ALTER NETWORK POLICY ... SET ALLOWED_IP_LIST = ('0.0.0.0/0')`
  fires
- positive: IPv6 `::/0` in the allowlist also fires
- negative: `ALTER NETWORK POLICY` that rotates to a restrictive allowlist
  does NOT fire
- negative: non-network operations are ignored
- negative: events from a non-Snowflake producer are ignored
- edge: duplicate `metadata.uid` does not inflate counts
- edge: failed events are ignored

## Roadmap

Closes the Snowflake column under issue #436. Remaining 11 detectors
(Databricks + ClickHouse) stay open and reuse the same input contract.
