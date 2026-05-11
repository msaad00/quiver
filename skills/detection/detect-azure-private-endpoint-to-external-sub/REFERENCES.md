# References — detect-azure-private-endpoint-to-external-sub

## Source formats and schemas

- **Azure Activity Log schema** — https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
- **Azure `Microsoft.Network/privateEndpoints` REST** — https://learn.microsoft.com/en-us/rest/api/virtualnetwork/private-endpoints/create-or-update
- **Azure Private Link overview** — https://learn.microsoft.com/en-us/azure/private-link/private-link-overview
- **Azure resource id format (subscriptions/<guid>/)** — https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules
- **OCSF 1.8 API Activity (6003)** — https://schema.ocsf.io/1.8.0/classes/api_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## Threat framework

- **MITRE ATT&CK T1071.001 Application Layer Protocol — Web** — https://attack.mitre.org/techniques/T1071/001/
- **MITRE ATT&CK T1567 Exfiltration Over Web Service** — https://attack.mitre.org/techniques/T1567/
- **MITRE ATT&CK TA0011 Command and Control tactic** — https://attack.mitre.org/tactics/TA0011/
- **MITRE ATT&CK TA0010 Exfiltration tactic** — https://attack.mitre.org/tactics/TA0010/

## Required permissions

None for the detector itself. It consumes already-normalized OCSF 1.8
API Activity 6003 events emitted by `ingest-azure-activity-ocsf`. The
upstream ingester needs the `Microsoft.Insights/eventtypes/values/read`
permission (Monitoring Reader) to pull Activity Log entries; this
detector reads stdin only.
