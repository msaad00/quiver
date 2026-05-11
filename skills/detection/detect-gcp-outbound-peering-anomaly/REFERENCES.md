# References — detect-gcp-outbound-peering-anomaly

## Source formats and schemas

- **GCP Cloud Audit Logs** — https://cloud.google.com/logging/docs/audit
- **GCP VPC Network Peering** — https://cloud.google.com/vpc/docs/vpc-peering
- **GCP `compute.networks.addPeering` REST** — https://cloud.google.com/compute/docs/reference/rest/v1/networks/addPeering
- **GCP shared-VPC** — https://cloud.google.com/vpc/docs/shared-vpc
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1071.001 Web Protocols** — https://attack.mitre.org/techniques/T1071/001/
- **MITRE ATT&CK T1041 Exfiltration Over C2 Channel** — https://attack.mitre.org/techniques/T1041/
- **MITRE ATT&CK TA0011 Command and Control** — https://attack.mitre.org/tactics/TA0011/
- **MITRE ATT&CK TA0010 Exfiltration** — https://attack.mitre.org/tactics/TA0010/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8
API Activity 6003 events emitted by `ingest-gcp-audit-ocsf`. The upstream
ingester needs `logging.logEntries.list` on the project; this detector
reads stdin only.
