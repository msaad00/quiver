-- privilege-escalation-k8s query pack for Snowflake
--
-- Required session variables:
--   SET source_table = 'K8S_AUDIT_OCSF';
--   SET lookback_hours = 24;
--
-- Input contract:
--   IDENTIFIER($source_table) must expose a `raw_json VARIANT` column with one
--   OCSF 1.8 API Activity event per row.
--
-- Output contract:
--   One OCSF-compatible Detection Finding row per deterministic
--   privilege-escalation event or correlation.

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
        COALESCE(TRY_TO_NUMBER(event:time), 0) AS time_ms,
        COALESCE(event:actor.user.name::string, '') AS actor_name,
        COALESCE(event:actor.user.type::string, '') AS actor_type,
        COALESCE(event:api.operation::string, '') AS operation,
        COALESCE(event:resources[0].type::string, '') AS resource_type,
        COALESCE(event:resources[0].name::string, '') AS resource_name,
        COALESCE(event:resources[0].namespace::string, '') AS namespace,
        COALESCE(event:resources[0].subresource::string, '') AS subresource
    FROM source_events
    WHERE TRY_TO_NUMBER(event:class_uid) = 6003
),
service_account_events AS (
    SELECT *
    FROM normalized
    WHERE actor_type = 'ServiceAccount'
),
rule1_list AS (
    SELECT actor_name, namespace, time_ms
    FROM service_account_events
    WHERE operation = 'list'
      AND resource_type = 'secrets'
),
rule1_findings AS (
    SELECT
        CONCAT('r1|', getter.actor_name, '|', getter.namespace, '|', getter.resource_name) AS dedupe_key,
        'r1-secret-enum' AS rule_name,
        4 AS severity_id,
        getter.actor_name AS actor_name,
        getter.namespace AS namespace,
        getter.resource_name AS target_name,
        getter.resource_type AS resource_type,
        getter.subresource AS subresource,
        MIN(lister.time_ms) AS first_seen_time_ms,
        getter.time_ms AS last_seen_time_ms,
        getter.time_ms AS finding_time_ms,
        'T1552' AS mitre_technique_uid,
        'T1552.007' AS mitre_subtechnique_uid,
        'k8s-r1-secret-enum' AS finding_type,
        'Service account enumerated and read a Kubernetes secret' AS title,
        'Credential Access' AS tactic_name,
        'TA0006' AS tactic_uid,
        'Unsecured Credentials' AS technique_name,
        'Container API' AS subtechnique_name,
        getter.resource_name AS observable_name
    FROM service_account_events AS getter
    JOIN rule1_list AS lister
      ON getter.actor_name = lister.actor_name
     AND getter.namespace = lister.namespace
     AND getter.time_ms > lister.time_ms
     AND getter.time_ms - lister.time_ms <= 300000
    WHERE getter.operation = 'get'
      AND getter.resource_type = 'secrets'
    GROUP BY getter.actor_name, getter.namespace, getter.resource_name, getter.resource_type, getter.subresource, getter.time_ms
),
rule2_findings AS (
    SELECT DISTINCT
        CONCAT('r2|', actor_name, '|', namespace, '/', resource_name) AS dedupe_key,
        'r2-pod-exec' AS rule_name,
        5 AS severity_id,
        actor_name,
        namespace,
        resource_name AS target_name,
        resource_type,
        subresource,
        time_ms AS first_seen_time_ms,
        time_ms AS last_seen_time_ms,
        time_ms AS finding_time_ms,
        'T1611' AS mitre_technique_uid,
        CAST(NULL AS STRING) AS mitre_subtechnique_uid,
        'k8s-r2-pod-exec' AS finding_type,
        'Service account executed a shell inside a pod' AS title,
        'Privilege Escalation' AS tactic_name,
        'TA0004' AS tactic_uid,
        'Escape to Host' AS technique_name,
        CAST(NULL AS STRING) AS subtechnique_name,
        resource_name AS observable_name
    FROM service_account_events
    WHERE operation = 'create'
      AND resource_type = 'pods'
      AND subresource = 'exec'
),
admin_groups AS (
    SELECT
        event,
        ARRAY_AGG(COALESCE(group_item.value:name::string, group_item.value::string)) AS group_names
    FROM source_events,
         LATERAL FLATTEN(input => event:actor.user.groups, outer => TRUE) AS group_item
    GROUP BY event
),
rule3_base AS (
    SELECT
        n.*,
        COALESCE(a.group_names, ARRAY_CONSTRUCT()) AS actor_groups
    FROM normalized AS n
    LEFT JOIN admin_groups AS a
      ON n.event = a.event
),
rule3_findings AS (
    SELECT DISTINCT
        CONCAT('r3|', actor_name, '|', resource_type, '/', namespace, '/', resource_name) AS dedupe_key,
        'r3-rbac-self-grant' AS rule_name,
        5 AS severity_id,
        actor_name,
        namespace,
        resource_name AS target_name,
        resource_type,
        subresource,
        time_ms AS first_seen_time_ms,
        time_ms AS last_seen_time_ms,
        time_ms AS finding_time_ms,
        'T1098' AS mitre_technique_uid,
        CAST(NULL AS STRING) AS mitre_subtechnique_uid,
        'k8s-r3-rbac-self-grant' AS finding_type,
        IFF(resource_type = 'clusterrolebindings', 'Non-admin principal created a clusterrolebinding', 'Non-admin principal created a rolebinding') AS title,
        'Persistence' AS tactic_name,
        'TA0003' AS tactic_uid,
        'Account Manipulation' AS technique_name,
        CAST(NULL AS STRING) AS subtechnique_name,
        resource_name AS observable_name
    FROM rule3_base
    WHERE operation = 'create'
      AND resource_type IN ('rolebindings', 'clusterrolebindings')
      AND actor_name NOT IN ('kubernetes-admin', 'kube-admin')
      AND NOT ARRAY_CONTAINS('system:masters'::VARIANT, actor_groups)
),
rule4_findings AS (
    SELECT DISTINCT
        CONCAT('r4|', actor_name, '|', namespace, '/', resource_name) AS dedupe_key,
        'r4-token-self-grant' AS rule_name,
        4 AS severity_id,
        actor_name,
        namespace,
        resource_name AS target_name,
        resource_type,
        subresource,
        time_ms AS first_seen_time_ms,
        time_ms AS last_seen_time_ms,
        time_ms AS finding_time_ms,
        'T1550' AS mitre_technique_uid,
        'T1550.001' AS mitre_subtechnique_uid,
        'k8s-r4-token-self-grant' AS finding_type,
        'Service account issued itself (or another SA) an API token' AS title,
        'Lateral Movement' AS tactic_name,
        'TA0008' AS tactic_uid,
        'Use Alternate Authentication Material' AS technique_name,
        'Application Access Tokens' AS subtechnique_name,
        resource_name AS observable_name
    FROM service_account_events
    WHERE operation = 'create'
      AND (
        (resource_type = 'serviceaccounts' AND subresource IN ('token', 'tokenrequest'))
        OR resource_type = 'tokenreviews'
      )
),
combined AS (
    SELECT * FROM rule1_findings
    UNION ALL
    SELECT * FROM rule2_findings
    UNION ALL
    SELECT * FROM rule3_findings
    UNION ALL
    SELECT * FROM rule4_findings
),
final_findings AS (
    SELECT
        rule_name,
        severity_id,
        actor_name,
        namespace,
        target_name,
        resource_type,
        subresource,
        first_seen_time_ms,
        last_seen_time_ms,
        finding_time_ms,
        mitre_technique_uid,
        mitre_subtechnique_uid,
        finding_type,
        title,
        tactic_name,
        tactic_uid,
        technique_name,
        subtechnique_name,
        CONCAT(
            'det-k8s-',
            rule_name,
            '-',
            SUBSTR(SHA2(COALESCE(actor_name, ''), 256), 1, 8),
            '-',
            SUBSTR(SHA2(COALESCE(namespace, '') || '/' || COALESCE(target_name, ''), 256), 1, 8)
        ) AS finding_uid
    FROM combined
)
SELECT
    finding_uid::varchar AS finding_uid,
    finding_uid::varchar AS event_uid,
    rule_name::varchar AS rule_name,
    severity_id::number AS severity_id,
    actor_name::varchar AS actor_name,
    namespace::varchar AS namespace,
    target_name::varchar AS target_name,
    resource_type::varchar AS resource_type,
    subresource::varchar AS subresource,
    first_seen_time_ms::number AS first_seen_time_ms,
    last_seen_time_ms::number AS last_seen_time_ms,
    finding_time_ms::number AS finding_time_ms,
    mitre_technique_uid::varchar AS mitre_technique_uid,
    mitre_subtechnique_uid::varchar AS mitre_subtechnique_uid,
    finding_type::varchar AS finding_type,
    OBJECT_CONSTRUCT(
        'activity_id', 1,
        'category_uid', 2,
        'category_name', 'Findings',
        'class_uid', 2004,
        'class_name', 'Detection Finding',
        'type_uid', 200401,
        'severity_id', severity_id,
        'status_id', 1,
        'time', finding_time_ms,
        'metadata', OBJECT_CONSTRUCT(
            'version', '1.8.0',
            'uid', finding_uid,
            'product', OBJECT_CONSTRUCT(
                'name', 'cloud-ai-security-skills',
                'vendor_name', 'msaad00/cloud-ai-security-skills',
                'feature', OBJECT_CONSTRUCT('name', 'packs/privilege-escalation-k8s/snowflake.sql')
            ),
            'labels', ARRAY_CONSTRUCT('query-pack', 'kubernetes', 'privilege-escalation', rule_name)
        ),
        'finding_info', OBJECT_CONSTRUCT(
            'uid', finding_uid,
            'title', title,
            'desc',
                CASE
                    WHEN rule_name = 'r1-secret-enum' THEN
                        'Service account ''' || actor_name || ''' performed `list` on secrets in namespace '''
                        || namespace || ''' and then `get` on secret ''' || target_name
                        || ''' within the 300-second correlation window. Workloads that need secret data should mount secrets as files, not call the K8s API for them — this pattern is a strong signal of a compromised pod searching for credentials. (MITRE T1552.007)'
                    WHEN rule_name = 'r2-pod-exec' THEN
                        'Service account ''' || actor_name || ''' called `create` on pods/exec for pod '''
                        || target_name || ''' in namespace ''' || namespace
                        || '''. Workloads (as opposed to human operators) should never exec into other pods — this is the precursor to container escape. (MITRE T1611)'
                    WHEN rule_name = 'r3-rbac-self-grant' THEN
                        'Principal ''' || actor_name || ''' created ' || IFF(resource_type = 'clusterrolebindings', 'clusterrolebinding', 'rolebinding')
                        || ' ''' || target_name || ''''
                        || IFF(namespace = '', '', ' in namespace ' || namespace)
                        || '. This principal is not in system:masters and is not a recognised admin user — creating a binding is the canonical K8s privilege-escalation move after initial compromise. (MITRE T1098)'
                    ELSE
                        'Service account ''' || actor_name || ''' created a token for '''
                        || IFF(target_name = '', 'tokenreview', target_name)
                        || ''' in namespace ''' || namespace
                        || '''. Combined with secret access or RBAC manipulation this is token-theft in progress. (MITRE T1550.001)'
                END,
            'types', ARRAY_CONSTRUCT(finding_type),
            'first_seen_time', first_seen_time_ms,
            'last_seen_time', last_seen_time_ms,
            'attacks', ARRAY_CONSTRUCT(
                IFF(
                    mitre_subtechnique_uid IS NULL,
                    OBJECT_CONSTRUCT(
                        'version', 'v14',
                        'tactic', OBJECT_CONSTRUCT('name', tactic_name, 'uid', tactic_uid),
                        'technique', OBJECT_CONSTRUCT('name', technique_name, 'uid', mitre_technique_uid)
                    ),
                    OBJECT_CONSTRUCT(
                        'version', 'v14',
                        'tactic', OBJECT_CONSTRUCT('name', tactic_name, 'uid', tactic_uid),
                        'technique', OBJECT_CONSTRUCT('name', technique_name, 'uid', mitre_technique_uid),
                        'sub_technique', OBJECT_CONSTRUCT('name', subtechnique_name, 'uid', mitre_subtechnique_uid)
                    )
                )
            )
        ),
        'observables', ARRAY_CONSTRUCT(
            OBJECT_CONSTRUCT('name', 'actor.name', 'type', 'Other', 'value', actor_name),
            OBJECT_CONSTRUCT(
                'name',
                CASE
                    WHEN rule_name = 'r1-secret-enum' THEN 'secret.name'
                    WHEN rule_name = 'r2-pod-exec' THEN 'pod.name'
                    WHEN rule_name = 'r3-rbac-self-grant' THEN 'binding.name'
                    ELSE 'target.serviceaccount'
                END,
                'type', 'Other',
                'value', target_name
            ),
            OBJECT_CONSTRUCT('name', 'namespace', 'type', 'Other', 'value', namespace),
            OBJECT_CONSTRUCT('name', 'rule', 'type', 'Other', 'value', rule_name)
        ),
        'evidence', OBJECT_CONSTRUCT(
            'events_observed', IFF(rule_name = 'r1-secret-enum', 2, 1),
            'first_seen_time', first_seen_time_ms,
            'last_seen_time', last_seen_time_ms,
            'raw_events', ARRAY_CONSTRUCT()
        )
    )::object AS finding_json
FROM final_findings
ORDER BY finding_time_ms, rule_name, actor_name, target_name;
