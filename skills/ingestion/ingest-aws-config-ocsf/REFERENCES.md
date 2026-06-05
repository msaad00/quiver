# References — ingest-aws-config-ocsf

## AWS Config

- **ConfigurationItem API shape** — https://docs.aws.amazon.com/config/latest/APIReference/API_ConfigurationItem.html
  AWS Config's recorded resource item fields such as `resourceType`,
  `resourceId`, `awsRegion`, `awsAccountId`, `configurationItemStatus`,
  `configuration`, `relationships`, and `tags`.
- **Components of a configuration item** — https://docs.aws.amazon.com/config/latest/developerguide/config-item-table.html
  Developer Guide explanation of configuration item capture, state IDs,
  relationships, and tag handling.
- **Example configuration item change notifications** — https://docs.aws.amazon.com/config/latest/developerguide/example-sns-notification.html
  AWS Config sends SNS notifications for configuration item changes,
  configuration history/snapshot delivery status, and resource compliance
  changes. The examples show `messageType`,
  `ConfigurationItemChangeNotification`, `configurationItem`,
  `configurationItemDiff`, and relationship diffs.
- **AWS Config rule compliance** — https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html
  Config rules evaluate resources and produce compliant/non-compliant
  evaluation results. This skill maps those compliance-change messages into
  OCSF Compliance Finding records.

## OCSF 1.8

- **API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
  Used for configuration item changes and snapshot records because the event is
  an AWS Config service activity describing a recorded resource state.
- **Compliance Finding (2003)** — https://schema.ocsf.io/1.8.0/classes/compliance_finding
  Used for Config rule compliance change messages.
- **OCSF metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
  `metadata.uid` is deterministic for dedupe and carries
  `cloud-ai-security-skills` product identity.

## Related skills

- `ingest-cloudtrail-ocsf` — AWS control-plane API audit logs.
- `ingest-security-hub-ocsf` — ASFF findings from AWS Security Hub, including
  Config-derived findings that were already aggregated through Security Hub.
- `cspm-aws-cis-benchmark` — live read-only CIS AWS Foundations assessment.
  `ingest-aws-config-ocsf` is the evidence-ingest side of the migration away
  from direct live evaluation.
