# ingest-security-hub-ocsf OCSF field map

Full ASFF-field → OCSF-field mapping for `ingest-security-hub-ocsf`. Pulled out of `SKILL.md` to keep that file under the progressive-disclosure target ([#247](https://github.com/msaad00/cloud-ai-security-skills/issues/247)).

## Native output format

`--output-format native` returns one JSON object per Security Hub finding with:

- `schema_mode: "native"`
- `canonical_schema_version`
- `record_type: "detection_finding"`
- `event_uid` and `finding_uid`
- `provider`, `account_uid`, `region`
- `time_ms`
- `severity_id`, `severity_label`, `severity_normalized`, `status_id`, `status`
- `title`, `description`, `finding_types`
- `attacks`, `resources`, `cloud`, `source`, `compliance`, and `evidence`

The native shape keeps the same normalized semantics as the OCSF projection,
but omits `class_uid`, `category_uid`, `type_uid`, and `metadata.product`.

## ASFF validation

The skill enforces the ASFF required fields defined in the AWS Security Hub user guide. A finding is **dropped with a stderr warning** (never fatal) if any of these are missing or empty:

- `SchemaVersion`
- `Id`
- `ProductArn`
- `GeneratorId`
- `AwsAccountId`
- `Types` (must be a non-empty list)
- `CreatedAt`
- `UpdatedAt`
- `Severity` (must be a dict with `Label` or `Normalized`)
- `Title`
- `Description`
- `Resources` (must be a non-empty list)

This keeps the downstream OCSF stream trustable: every record that makes it past the ingester is ASFF-valid *and* OCSF-valid.

## Severity mapping

ASFF carries both a `Label` enum and a 0–100 `Normalized` score. The skill prefers `Label` (more stable), falling back to `Normalized`:

| ASFF `Severity.Label` | Normalized fallback | OCSF `severity_id` |
|---|---:|---:|
| `INFORMATIONAL` | 0 | 1 (Informational) |
| `LOW` | 1–39 | 2 (Low) |
| `MEDIUM` | 40–69 | 3 (Medium) |
| `HIGH` | 70–89 | 4 (High) |
| `CRITICAL` | 90–100 | 5 (Critical) |

The raw label and score are both preserved as observables so rules can pivot either way.

## MITRE ATT&CK extraction

ASFF doesn't have a first-class MITRE field, but several AWS products (GuardDuty, Inspector, Config Conformance Packs) now populate `ProductFields` with `aws/securityhub/annotations/mitre-*` keys or include MITRE hints in the `Types[]` taxonomy. The skill extracts both sources:

1. **Types[] taxonomy walk.** ASFF Types use the format `<namespace>/<category>/<classifier>`. When the namespace is `TTPs` and the category matches a MITRE tactic name, the skill emits a tactic-only attack entry.
2. **ProductFields lookup.** When a key matches `aws/securityhub/annotations/mitre-technique`, the value is parsed for a `T####` technique ID and promoted into `attacks[].technique.uid`.

Findings without any MITRE hints still get a valid OCSF event — `finding_info.attacks[]` is simply empty. Downstream pivots that filter by technique will just skip these, which is the intended behaviour.

## Deterministic finding UID

`finding_info.uid` is derived as `det-shub-<first 8 chars of sha256(ASFF Id)>`. The original ASFF Id (a long ARN) is preserved on `evidence.raw_events[].uid`.

## Compliance passthrough

When the ASFF finding carries a `Compliance` block (typical for Config rules, CIS benchmarks, PCI packs), the skill lifts `Compliance.Status`, `Compliance.StatusReasons[]`, and `Compliance.SecurityControlId` into observables. This lets downstream compliance evaluators (cspm-aws-cis-benchmark, etc.) consume Security Hub findings through the same OCSF pipeline without needing to re-read the raw ASFF.
