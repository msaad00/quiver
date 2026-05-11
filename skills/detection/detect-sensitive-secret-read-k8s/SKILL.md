---
name: detect-sensitive-secret-read-k8s
description: >-
  Detect targeted reads of Kubernetes Secrets whose names match sensitive
  patterns from normalized K8s audit events in native or OCSF mode. Emits
  findings aligned to MITRE ATT&CK T1552.007 when workloads read high-value
  secrets by name without requiring a preceding enumeration sequence. Use
  when the user mentions Kubernetes secret access, credential reads through
  the Container API, or workloads reading secrets by name. Do NOT use on raw
  audit logs — pipe them through ingest-k8s-audit-ocsf first. Do NOT use for
  list-then-get enumeration patterns; that belongs to
  detect-privilege-escalation-k8s. Do NOT use for cross-namespace analysis.
purpose: Detect targeted reads of Kubernetes Secrets whose names match sensitive patterns from normalized K8s audit events in native or OCSF mode.
capability: detect
persistence: none
telemetry: stderr_jsonl
privilege_escalation: none
license: Apache-2.0
approval_model: none
execution_modes: jit, ci, mcp, persistent
side_effects: none
input_formats: native, ocsf
output_formats: native, ocsf
concurrency_safety: stateless
---

# detect-sensitive-secret-read-k8s

## Use when

- Kubernetes secret-access telemetry is already normalized by `ingest-k8s-audit-ocsf`
- you want a direct-read detector for high-value secret names
- you want native or OCSF findings for targeted secret access attempts

## Attack pattern

Workloads should mount the secrets they need as files — the K8s API isn't supposed to be the credential read path at runtime. When an audit log shows a workload's service account calling `get` or `list` on a secret whose **name matches a known sensitive pattern**, that's a direct credential-read attempt. It's the MITRE T1552.007 technique as observed by `kube-apiserver` rather than by a pod-level hook.

This skill complements [`detect-privilege-escalation-k8s` Rule 1](../detect-privilege-escalation-k8s/SKILL.md) (which requires a `list` + `get` correlation in a window). Rule 1 catches enumeration-then-read. This skill catches **targeted reads with no preceding list** — an attacker who already knows the secret name.

## Detection logic

For each OCSF API Activity event on the `secrets` resource type:

1. Verb is `get` or `list` (K8s read verbs)
2. `objectRef.name` (projected into `resources[0].name`) matches at least one pattern in the default sensitive-name list
3. Emit one OCSF Detection Finding per match, keyed on `(actor, namespace, secret_name)` for idempotency

The default sensitive-name patterns are:

| Pattern (case-insensitive glob) | Why |
|---|---|
| `*credential*`, `*creds*` | Generic credential secrets |
| `*token*`, `*-token` | Bearer tokens, service-account tokens, OAuth refresh tokens |
| `*api-key*`, `*apikey*`, `*api_key*` | API keys |
| `*password*`, `*passwd*`, `*pwd*` | Database / app passwords |
| `*secret-key*`, `*-secret` | Signing keys, HMAC secrets |
| `aws-*`, `*-aws`, `*aws-creds*`, `*aws-access*` | AWS credential patterns |
| `gcp-*`, `*-gcp`, `*gcp-creds*`, `*service-account-key*` | GCP service account keys |
| `azure-*`, `*-azure`, `*azure-creds*` | Azure credential patterns |
| `dockerconfig*`, `*dockerconfigjson*` | Docker registry pull secrets |
| `*-tls`, `tls-*`, `*certificate*`, `*private-key*` | TLS material |
| `kube-root-ca*` | Kubernetes cluster root CA (rare legitimate workload read) |

The full pattern list lives in `src/detect.py` as the `SENSITIVE_NAME_PATTERNS` constant. Override at runtime with `--sensitive-pattern "foo-*" --sensitive-pattern "bar-*"` to add extra patterns for your environment (tests cover both default and custom patterns).

## What does NOT fire

- `get` on a secret with a name like `my-app-config` (no sensitive pattern match) — not fired
- `get` on a secret by an admin user (no filtering for admin — this rule is about the secret name, not the actor; even admin reads of credentials should be logged)
- `list` on all secrets without a specific name in `objectRef.name` — not fired (this is the enumeration pattern covered by `detect-privilege-escalation-k8s` Rule 1)
- `watch` verb — not fired (watches establish long-lived streams, different TTP)

## Output contract

One OCSF Detection Finding (class `2004`) per `(actor, namespace, secret_name)` match by default. Populates:

- `finding_info.attacks[]` — MITRE ATT&CK v14, tactic TA0006 (Credential Access), technique T1552 (Unsecured Credentials), sub-technique T1552.007 (Container API)
- `finding_info.types[]` — `["k8s-sensitive-secret-read"]`
- `finding_info.uid` — deterministic (`det-k8s-secret-read-<actor-hash>-<secret-hash>`)
- `observables[]` — actor.name, namespace, secret.name, matched_patterns
- `severity_id` — 4 (High)

## Native output format

`--output-format native` emits one native detection-finding record per match with:

- `schema_mode`
- `record_type`
- `finding_uid`
- `event_uid`
- `provider`
- `time_ms`
- `severity`
- `severity_id`
- `status`
- `status_id`
- `title`
- `description`
- `finding_types`
- `first_seen_time_ms`
- `last_seen_time_ms`
- `mitre_attacks`
- `actor_name`
- `namespace`
- `secret_name`
- `matched_patterns`
- `verb`
- `rule_name`

## Usage

```bash
# Piped from ingest-k8s-audit-ocsf
python ../ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python src/detect.py \
  > findings.ocsf.jsonl

# Native end-to-end path
python ../ingest-k8s-audit-ocsf/src/ingest.py --output-format native audit.log \
  | python src/detect.py --output-format native \
  > findings.native.jsonl

# With custom patterns
python ../ingest-k8s-audit-ocsf/src/ingest.py audit.log \
  | python src/detect.py --sensitive-pattern "stripe-*" --sensitive-pattern "*-mfa-seed"
```

## Tests

Golden fixture parity against [`../golden/k8s_sensitive_secret_read_sample.ocsf.jsonl`](../golden/k8s_sensitive_secret_read_sample.ocsf.jsonl) → [`../golden/k8s_sensitive_secret_read_findings.ocsf.jsonl`](../golden/k8s_sensitive_secret_read_findings.ocsf.jsonl). Plus unit tests for each pattern category (credential / token / API key / cloud creds / TLS / root CA), the `watch`-verb negative control, non-sensitive-name negative controls, custom pattern injection, and deterministic finding UIDs.

## See also

- [`SKILL.md`](../detect-privilege-escalation-k8s/SKILL.md) for the complementary `detect-privilege-escalation-k8s` Rule 1 (list + get enumeration)
- [`REFERENCES.md`](REFERENCES.md) for official K8s / OCSF / MITRE links
- [`../../remediation/iam-departures-aws/RUNBOOK.md`](../../remediation/iam-departures-aws/) for the remediation-side runbook pattern this skill's runbook follows
