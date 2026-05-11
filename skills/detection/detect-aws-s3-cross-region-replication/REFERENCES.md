# References — detect-aws-s3-cross-region-replication

## Source formats and schemas

- **AWS CloudTrail event reference** — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- **AWS S3 `PutBucketReplication` API** — https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html
- **AWS S3 Replication overview** — https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html
- **AWS S3 Cross-Region Replication (CRR)** — https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-walkthrough-2.html
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1537 Transfer Data to Cloud Account** — https://attack.mitre.org/techniques/T1537/
- **MITRE ATT&CK T1567 Exfiltration Over Web Service** — https://attack.mitre.org/techniques/T1567/
- **MITRE ATT&CK TA0010 Exfiltration tactic** — https://attack.mitre.org/tactics/TA0010/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8
API Activity 6003 events emitted by `ingest-cloudtrail-ocsf`. The
upstream ingester needs `cloudtrail:LookupEvents` or read access to the
CloudTrail log bucket; this detector reads stdin only.
