-- lateral-movement query pack for Snowflake
--
-- Required session variables:
--   SET source_table = 'SECURITY_EVENTS_OCSF';
--   SET lookback_hours = 24;
--
-- Input contract:
--   IDENTIFIER($source_table) must expose a `raw_json VARIANT` column with one
--   OCSF 1.8 event per row.
--
-- Output contract:
--   One OCSF-compatible Detection Finding row per deterministic
--   (provider, session_uid, dst_ip, dst_port) tuple.

WITH source_events AS (
    SELECT raw_json AS event
    FROM IDENTIFIER($source_table)
    WHERE COALESCE(TRY_TO_NUMBER(raw_json:time), 0) >= DATE_PART(
        EPOCH_MILLISECOND,
        DATEADD('hour', -$lookback_hours, CURRENT_TIMESTAMP())
    )
),
normalized AS (
    SELECT
        event,
        TRY_TO_NUMBER(event:class_uid) AS class_uid,
        TRY_TO_NUMBER(event:activity_id) AS activity_id,
        UPPER(COALESCE(event:cloud.provider::string, '')) AS provider,
        COALESCE(event:cloud.account.uid::string, '') AS account_uid,
        COALESCE(TRY_TO_NUMBER(event:time), 0) AS time_ms,
        COALESCE(event:actor.session.uid::string, '') AS session_uid,
        COALESCE(event:actor.user.name::string, '') AS actor_name,
        COALESCE(event:api.operation::string, '') AS operation,
        COALESCE(event:api.service.name::string, '') AS service_name,
        COALESCE(event:src_endpoint.ip::string, '') AS src_ip,
        COALESCE(event:src_endpoint.instance_uid::string, '') AS src_instance_uid,
        COALESCE(event:dst_endpoint.ip::string, '') AS dst_ip,
        TRY_TO_NUMBER(event:dst_endpoint.port) AS dst_port,
        COALESCE(TRY_TO_NUMBER(event:traffic.bytes), 0) AS traffic_bytes
    FROM source_events
    WHERE TRY_TO_NUMBER(event:class_uid) IN (6003, 4001)
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
            AND REGEXP_LIKE(
                operation,
                '(GenerateAccessToken|GenerateIdToken|SignJwt|SignBlob|CreateServiceAccountKey)$'
            )
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
                        OR REGEXP_LIKE(REPLACE(UPPER(operation), ' ', ''), 'ADDPASSWORD|ADDKEY')
                        OR REGEXP_LIKE(
                            REPLACE(UPPER(operation), ' ', ''),
                            'APPROLEASSIGNMENTS|APPROLEASSIGNEDTO'
                        )
                        OR REGEXP_LIKE(
                            REPLACE(UPPER(operation), ' ', ''),
                            'FEDERATEDIDENTITYCREDENTIALS'
                        )
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
        REGEXP_LIKE(dst_ip, '^10\\.')
        OR REGEXP_LIKE(dst_ip, '^192\\.168\\.')
        OR REGEXP_LIKE(dst_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.')
        OR REGEXP_LIKE(dst_ip, '^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.')
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
        flow.time_ms AS finding_time_ms
    FROM identity_anchors AS anchor
    JOIN flows AS flow
      ON flow.provider = anchor.provider
     AND (
        anchor.account_uid = ''
        OR flow.account_uid = ''
        OR flow.account_uid = anchor.account_uid
     )
     AND flow.time_ms BETWEEN anchor.time_ms AND anchor.time_ms + 900000
    QUALIFY ROW_NUMBER() OVER (
        PARTITION BY anchor.provider, anchor.session_uid, flow.dst_ip, flow.dst_port
        ORDER BY flow.time_ms
    ) = 1
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
            SUBSTR(SHA2(LOWER(COALESCE(NULLIF(provider, ''), 'cloud')), 256), 1, 8),
            '-',
            SUBSTR(SHA2(COALESCE(session_uid, ''), 256), 1, 8),
            '-',
            SUBSTR(SHA2(CONCAT(COALESCE(dst_ip, ''), ':', COALESCE(dst_port::STRING, '')), 256), 1, 8)
        ) AS finding_uid,
        IFF(provider = 'AZURE', 'Azure', provider) AS provider_display
    FROM candidate_pairs
)
SELECT
    finding_uid::varchar AS finding_uid,
    finding_uid::varchar AS event_uid,
    provider::varchar AS provider,
    account_uid::varchar AS account_uid,
    session_uid::varchar AS session_uid,
    actor_name::varchar AS actor_name,
    anchor_operation::varchar AS anchor_operation,
    src_instance_uid::varchar AS src_instance_uid,
    src_ip::varchar AS src_ip,
    dst_ip::varchar AS dst_ip,
    dst_port::number AS dst_port,
    traffic_bytes::number AS traffic_bytes,
    first_seen_time_ms::number AS first_seen_time_ms,
    last_seen_time_ms::number AS last_seen_time_ms,
    finding_time_ms::number AS finding_time_ms,
    900::number AS correlation_window_seconds,
    'cloud-lateral-movement'::varchar AS finding_type,
    'T1021'::varchar AS primary_technique_uid,
    'T1078.004'::varchar AS secondary_technique_uid,
    OBJECT_CONSTRUCT(
        'activity_id', 1,
        'category_uid', 2,
        'category_name', 'Findings',
        'class_uid', 2004,
        'class_name', 'Detection Finding',
        'type_uid', 200401,
        'severity_id', 4,
        'status_id', 1,
        'time', finding_time_ms,
        'metadata', OBJECT_CONSTRUCT(
            'version', '1.8.0',
            'uid', finding_uid,
            'product', OBJECT_CONSTRUCT(
                'name', 'cloud-ai-security-skills',
                'vendor_name', 'msaad00/cloud-ai-security-skills',
                'feature', OBJECT_CONSTRUCT('name', 'packs/lateral-movement/snowflake.sql')
            ),
            'labels', ARRAY_CONSTRUCT('query-pack', LOWER(provider), 'lateral-movement', 'snowflake')
        ),
        'finding_info', OBJECT_CONSTRUCT(
            'uid', finding_uid,
            'title', provider_display || ' lateral movement: identity pivot followed by east-west traffic',
            'desc', 'Principal ''' || actor_name || ''' triggered identity pivot operation ''' || anchor_operation
                || ''' (session ''' || session_uid || '''), and within the 15-minute correlation window an accepted east-west flow moved '
                || traffic_bytes::STRING || ' bytes from ' || COALESCE(NULLIF(src_instance_uid, ''), src_ip)
                || ' to ' || dst_ip || ':' || COALESCE(dst_port::STRING, '') || '. This is the canonical '
                || provider_display || ' lateral movement pattern (MITRE T1021 Remote Services via T1078.004 Cloud Accounts).',
            'types', ARRAY_CONSTRUCT('cloud-lateral-movement'),
            'first_seen_time', first_seen_time_ms,
            'last_seen_time', last_seen_time_ms,
            'attacks', ARRAY_CONSTRUCT(
                OBJECT_CONSTRUCT(
                    'version', 'v14',
                    'tactic', OBJECT_CONSTRUCT('name', 'Lateral Movement', 'uid', 'TA0008'),
                    'technique', OBJECT_CONSTRUCT('name', 'Remote Services', 'uid', 'T1021')
                ),
                OBJECT_CONSTRUCT(
                    'version', 'v14',
                    'tactic', OBJECT_CONSTRUCT('name', 'Persistence', 'uid', 'TA0003'),
                    'technique', OBJECT_CONSTRUCT('name', 'Valid Accounts', 'uid', 'T1078'),
                    'sub_technique', OBJECT_CONSTRUCT('name', 'Cloud Accounts', 'uid', 'T1078.004')
                )
            )
        ),
        'observables', ARRAY_CONSTRUCT(
            OBJECT_CONSTRUCT('name', 'cloud.provider', 'type', 'Other', 'value', provider_display),
            OBJECT_CONSTRUCT('name', 'cloud.account', 'type', 'Other', 'value', account_uid),
            OBJECT_CONSTRUCT('name', 'session.uid', 'type', 'Other', 'value', session_uid),
            OBJECT_CONSTRUCT('name', 'actor.name', 'type', 'Other', 'value', actor_name),
            OBJECT_CONSTRUCT('name', 'anchor.operation', 'type', 'Other', 'value', anchor_operation),
            OBJECT_CONSTRUCT('name', 'src.instance_uid', 'type', 'Other', 'value', src_instance_uid),
            OBJECT_CONSTRUCT('name', 'src.ip', 'type', 'Other', 'value', src_ip),
            OBJECT_CONSTRUCT('name', 'dst.ip', 'type', 'Other', 'value', dst_ip),
            OBJECT_CONSTRUCT('name', 'dst.port', 'type', 'Other', 'value', COALESCE(dst_port::STRING, '')),
            OBJECT_CONSTRUCT('name', 'traffic.bytes', 'type', 'Other', 'value', traffic_bytes::STRING),
            OBJECT_CONSTRUCT('name', 'window.seconds', 'type', 'Other', 'value', '900'),
            OBJECT_CONSTRUCT('name', 'rule', 'type', 'Other', 'value', 'cloud-lateral-movement')
        ),
        'evidence', OBJECT_CONSTRUCT(
            'events_observed', 2,
            'first_seen_time', first_seen_time_ms,
            'last_seen_time', last_seen_time_ms,
            'raw_events', ARRAY_CONSTRUCT()
        )
    )::object AS finding_json
FROM findings
ORDER BY provider, session_uid, dst_ip, dst_port;
