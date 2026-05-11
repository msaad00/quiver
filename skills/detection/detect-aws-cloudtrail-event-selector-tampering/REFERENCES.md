# References — detect-aws-cloudtrail-event-selector-tampering

## Source formats and schemas

- **AWS CloudTrail event reference** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- **AWS CloudTrail `PutEventSelectors` API** — https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html
- **AWS CloudTrail `UpdateTrail` API** — https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html
- **CloudTrail event selectors overview** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html
- **CloudTrail multi-region trails** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1562.001 Impair Defenses: Disable or Modify Tools** — https://attack.mitre.org/techniques/T1562/001/
- **MITRE ATT&CK TA0005 Defense Evasion tactic** — https://attack.mitre.org/tactics/TA0005/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8
API Activity 6003 events emitted by `ingest-cloudtrail-ocsf`. The
upstream ingester needs `cloudtrail:LookupEvents` or read access to the
CloudTrail log bucket; this detector reads stdin only.
