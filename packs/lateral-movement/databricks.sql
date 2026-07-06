-- sqlfluff:dialect:databricks
-- lateral-movement query pack for Databricks SQL
--
-- Required parameter substitution before execution:
--   replace ${source_table} with the source table or view name
--   replace ${lookback_hours} with an integer hour window
--
-- Input contract:
--   ${source_table} must expose a `raw_json STRING` column with one
--   OCSF 1.8 event per row.
--
-- Output contract:
--   One OCSF-compatible Detection Finding row per deterministic
--   (provider, session_uid, dst_ip, dst_port) tuple.

WITH source_events AS (
    SELECT raw_json AS event
    FROM ${source_table}
    WHERE COALESCE(CAST(get_json_object(raw_json, '$.time') AS BIGINT), 0) >= unix_millis(
        current_timestamp() - INTERVAL ${lookback_hours} HOURS
    )
),
normalized AS (
    SELECT
        event,
        CAST(get_json_object(event, '$.class_uid') AS INT) AS class_uid,
        CAST(get_json_object(event, '$.activity_id') AS INT) AS activity_id,
        UPPER(COALESCE(get_json_object(event, '$.cloud.provider'), '')) AS provider,
        COALESCE(get_json_object(event, '$.cloud.account.uid'), '') AS account_uid,
        COALESCE(CAST(get_json_object(event, '$.time') AS BIGINT), 0) AS time_ms,
        COALESCE(get_json_object(event, '$.actor.session.uid'), '') AS session_uid,
        COALESCE(get_json_object(event, '$.actor.user.name'), '') AS actor_name,
        COALESCE(get_json_object(event, '$.api.operation'), '') AS operation,
        COALESCE(get_json_object(event, '$.api.service.name'), '') AS service_name,
        COALESCE(get_json_object(event, '$.src_endpoint.ip'), '') AS src_ip,
        COALESCE(get_json_object(event, '$.src_endpoint.instance_uid'), '') AS src_instance_uid,
        COALESCE(get_json_object(event, '$.dst_endpoint.ip'), '') AS dst_ip,
        CAST(get_json_object(event, '$.dst_endpoint.port') AS INT) AS dst_port,
        COALESCE(CAST(get_json_object(event, '$.traffic.bytes') AS BIGINT), 0) AS traffic_bytes
    FROM source_events
    WHERE CAST(get_json_object(event, '$.class_uid') AS INT) IN (6003, 4001)
),
identity_anchors AS (
    SELECT *
    FROM normalized
    WHERE class_uid = 6003
      AND (
        (
            provider = 'AWS'
            AND operation IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
        )
        OR (
            provider = 'GCP'
            AND UPPER(service_name) IN ('IAMCREDENTIALS.GOOGLEAPIS.COM', 'IAM.GOOGLEAPIS.COM')
            AND operation RLIKE '(GenerateAccessToken|GenerateIdToken|SignJwt|SignBlob|CreateServiceAccountKey)$'
        )
        OR (
            provider = 'AZURE'
            AND (
                UPPER(operation) IN (
                    'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE',
                    'MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION',
                    'MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/ASSIGN/ACTION'
                )
                OR (
                    UPPER(service_name) IN (
                        'GRAPH.MICROSOFT.COM',
                        'MICROSOFT GRAPH',
                        'MICROSOFT ENTRA ID',
                        'CORE DIRECTORY'
                    )
                    AND (
                        UPPER(operation) IN (
                            'ADD SERVICE PRINCIPAL CREDENTIALS',
                            'UPDATE APPLICATION - CERTIFICATES AND SECRETS MANAGEMENT',
                            'ADD APP ROLE ASSIGNMENT TO SERVICE PRINCIPAL',
                            'CREATE FEDERATED IDENTITY CREDENTIAL',
                            'ADD FEDERATED IDENTITY CREDENTIAL'
                        )
                        OR REPLACE(UPPER(operation), ' ', '') RLIKE 'ADDPASSWORD|ADDKEY'
                        OR REPLACE(UPPER(operation), ' ', '') RLIKE 'APPROLEASSIGNMENTS|APPROLEASSIGNEDTO'
                        OR REPLACE(UPPER(operation), ' ', '') RLIKE 'FEDERATEDIDENTITYCREDENTIALS'
                    )
                )
            )
        )
      )
),
flows AS (
    SELECT *
    FROM normalized
    WHERE class_uid = 4001
      AND activity_id = 6
      AND traffic_bytes >= 1024
      AND (
        dst_ip RLIKE '^10\\.'
        OR dst_ip RLIKE '^192\\.168\\.'
        OR dst_ip RLIKE '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.'
        OR dst_ip RLIKE '^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.'
      )
),
candidate_pairs AS (
    SELECT
        anchor.provider,
        anchor.account_uid,
        anchor.session_uid,
        anchor.actor_name,
        anchor.operation AS anchor_operation,
        flow.src_instance_uid,
        flow.src_ip,
        flow.dst_ip,
        flow.dst_port,
        flow.traffic_bytes,
        anchor.time_ms AS first_seen_time_ms,
        flow.time_ms AS last_seen_time_ms,
        flow.time_ms AS finding_time_ms,
        ROW_NUMBER() OVER (
            PARTITION BY anchor.provider, anchor.session_uid, flow.dst_ip, flow.dst_port
            ORDER BY flow.time_ms
        ) AS pair_rank
    FROM identity_anchors AS anchor
    INNER JOIN flows AS flow
      ON flow.provider = anchor.provider
     AND (
        anchor.account_uid = ''
        OR flow.account_uid = ''
        OR flow.account_uid = anchor.account_uid
     )
     AND flow.time_ms BETWEEN anchor.time_ms AND anchor.time_ms + 900000
),
findings AS (
    SELECT
        provider,
        account_uid,
        session_uid,
        actor_name,
        anchor_operation,
        src_instance_uid,
        src_ip,
        dst_ip,
        dst_port,
        traffic_bytes,
        first_seen_time_ms,
        last_seen_time_ms,
        finding_time_ms,
        CONCAT(
            'det-lm-',
            SUBSTRING(SHA2(LOWER(COALESCE(NULLIF(provider, ''), 'cloud')), 256), 1, 8),
            '-',
            SUBSTRING(SHA2(COALESCE(session_uid, ''), 256), 1, 8),
            '-',
            SUBSTRING(SHA2(CONCAT(COALESCE(dst_ip, ''), ':', COALESCE(CAST(dst_port AS STRING), '')), 256), 1, 8)
        ) AS finding_uid,
        CASE WHEN provider = 'AZURE' THEN 'Azure' ELSE provider END AS provider_display
    FROM candidate_pairs
    WHERE pair_rank = 1
)
SELECT
    CAST(finding_uid AS STRING) AS finding_uid,
    CAST(finding_uid AS STRING) AS event_uid,
    CAST(provider AS STRING) AS provider,
    CAST(account_uid AS STRING) AS account_uid,
    CAST(session_uid AS STRING) AS session_uid,
    CAST(actor_name AS STRING) AS actor_name,
    CAST(anchor_operation AS STRING) AS anchor_operation,
    CAST(src_instance_uid AS STRING) AS src_instance_uid,
    CAST(src_ip AS STRING) AS src_ip,
    CAST(dst_ip AS STRING) AS dst_ip,
    CAST(dst_port AS INT) AS dst_port,
    CAST(traffic_bytes AS BIGINT) AS traffic_bytes,
    CAST(first_seen_time_ms AS BIGINT) AS first_seen_time_ms,
    CAST(last_seen_time_ms AS BIGINT) AS last_seen_time_ms,
    CAST(finding_time_ms AS BIGINT) AS finding_time_ms,
    CAST(900 AS INT) AS correlation_window_seconds,
    CAST('cloud-lateral-movement' AS STRING) AS finding_type,
    CAST('T1021' AS STRING) AS primary_technique_uid,
    CAST('T1078.004' AS STRING) AS secondary_technique_uid,
    CAST(
        TO_JSON(
            NAMED_STRUCT(
            'activity_id', 1,
            'category_uid', 2,
            'category_name', 'Findings',
            'class_uid', 2004,
            'class_name', 'Detection Finding',
            'type_uid', 200401,
            'severity_id', 4,
            'status_id', 1,
            'time', finding_time_ms,
            'metadata', NAMED_STRUCT(
                'version', '1.8.0',
                'uid', finding_uid,
                'product', NAMED_STRUCT(
                    'name', 'cloud-ai-security-skills',
                    'vendor_name', 'msaad00/cloud-ai-security-skills',
                    'feature', NAMED_STRUCT('name', 'packs/lateral-movement/databricks.sql')
                ),
                'labels', ARRAY('query-pack', LOWER(provider), 'lateral-movement', 'databricks')
            ),
            'finding_info', NAMED_STRUCT(
                'uid', finding_uid,
                'title', CONCAT(provider_display, ' lateral movement: identity pivot followed by east-west traffic'),
                'desc', CONCAT(
                    'Principal ''', actor_name, ''' triggered identity pivot operation ''', anchor_operation,
                    ''' (session ''', session_uid,
                    '''), and within the 15-minute correlation window an accepted east-west flow moved ',
                    CAST(traffic_bytes AS STRING), ' bytes from ',
                    COALESCE(NULLIF(src_instance_uid, ''), src_ip),
                    ' to ', dst_ip, ':', COALESCE(CAST(dst_port AS STRING), ''),
                    '. This is the canonical ', provider_display,
                    ' lateral movement pattern (MITRE T1021 Remote Services via T1078.004 Cloud Accounts).'
                ),
                'types', ARRAY('cloud-lateral-movement'),
                'first_seen_time', first_seen_time_ms,
                'last_seen_time', last_seen_time_ms,
                'attacks', ARRAY(
                    NAMED_STRUCT(
                        'version', 'v14',
                        'tactic', NAMED_STRUCT('name', 'Lateral Movement', 'uid', 'TA0008'),
                        'technique', NAMED_STRUCT('name', 'Remote Services', 'uid', 'T1021')
                    ),
                    NAMED_STRUCT(
                        'version', 'v14',
                        'tactic', NAMED_STRUCT('name', 'Persistence', 'uid', 'TA0003'),
                        'technique', NAMED_STRUCT('name', 'Valid Accounts', 'uid', 'T1078'),
                        'sub_technique', NAMED_STRUCT('name', 'Cloud Accounts', 'uid', 'T1078.004')
                    )
                )
            ),
            'observables', ARRAY(
                NAMED_STRUCT('name', 'cloud.provider', 'type', 'Other', 'value', provider_display),
                NAMED_STRUCT('name', 'cloud.account', 'type', 'Other', 'value', account_uid),
                NAMED_STRUCT('name', 'session.uid', 'type', 'Other', 'value', session_uid),
                NAMED_STRUCT('name', 'actor.name', 'type', 'Other', 'value', actor_name),
                NAMED_STRUCT('name', 'anchor.operation', 'type', 'Other', 'value', anchor_operation),
                NAMED_STRUCT('name', 'src.instance_uid', 'type', 'Other', 'value', src_instance_uid),
                NAMED_STRUCT('name', 'src.ip', 'type', 'Other', 'value', src_ip),
                NAMED_STRUCT('name', 'dst.ip', 'type', 'Other', 'value', dst_ip),
                NAMED_STRUCT('name', 'dst.port', 'type', 'Other', 'value', COALESCE(CAST(dst_port AS STRING), '')),
                NAMED_STRUCT('name', 'traffic.bytes', 'type', 'Other', 'value', CAST(traffic_bytes AS STRING)),
                NAMED_STRUCT('name', 'window.seconds', 'type', 'Other', 'value', '900'),
                NAMED_STRUCT('name', 'rule', 'type', 'Other', 'value', 'cloud-lateral-movement')
            ),
            'evidence', NAMED_STRUCT(
                'events_observed', 2,
                'first_seen_time', first_seen_time_ms,
                'last_seen_time', last_seen_time_ms,
                'raw_events', ARRAY()
            )
            )
        ) AS STRING
    ) AS finding_json
FROM findings
ORDER BY provider, session_uid, dst_ip, dst_port;
