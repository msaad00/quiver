-- sqlfluff:dialect:databricks
-- privilege-escalation-k8s query pack for Databricks SQL
--
-- Required parameter substitution before execution:
--   replace ${source_table} with the source table or view name
--   replace ${lookback_hours} with an integer hour window
--
-- Input contract:
--   ${source_table} must expose a `raw_json STRING` column with one
--   OCSF 1.8 API Activity event per row.
--
-- Output contract:
--   One OCSF-compatible Detection Finding row per deterministic
--   privilege-escalation event or correlation.

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
        COALESCE(CAST(get_json_object(event, '$.time') AS BIGINT), 0) AS time_ms,
        COALESCE(get_json_object(event, '$.actor.user.name'), '') AS actor_name,
        COALESCE(get_json_object(event, '$.actor.user.type'), '') AS actor_type,
        COALESCE(get_json_object(event, '$.api.operation'), '') AS operation,
        COALESCE(get_json_object(event, '$.resources[0].type'), '') AS resource_type,
        COALESCE(get_json_object(event, '$.resources[0].name'), '') AS resource_name,
        COALESCE(get_json_object(event, '$.resources[0].namespace'), '') AS namespace,
        COALESCE(get_json_object(event, '$.resources[0].subresource'), '') AS subresource
    FROM source_events
    WHERE CAST(get_json_object(event, '$.class_uid') AS INT) = 6003
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
        'Container API' AS subtechnique_name
    FROM service_account_events AS getter
    INNER JOIN rule1_list AS lister
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
        CAST(NULL AS STRING) AS subtechnique_name
    FROM service_account_events
    WHERE operation = 'create'
      AND resource_type = 'pods'
      AND subresource = 'exec'
),
admin_groups AS (
    SELECT
        n.event,
        transform(
            from_json(
                COALESCE(get_json_object(n.event, '$.actor.user.groups'), '[]'),
                'array<string>'
            ),
            group_name -> COALESCE(group_name, '')
        ) AS actor_groups
    FROM normalized AS n
),
rule3_base AS (
    SELECT
        n.*,
        COALESCE(a.actor_groups, ARRAY()) AS actor_groups
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
        CASE
            WHEN resource_type = 'clusterrolebindings' THEN 'Non-admin principal created a clusterrolebinding'
            ELSE 'Non-admin principal created a rolebinding'
        END AS title,
        'Persistence' AS tactic_name,
        'TA0003' AS tactic_uid,
        'Account Manipulation' AS technique_name,
        CAST(NULL AS STRING) AS subtechnique_name
    FROM rule3_base
    WHERE operation = 'create'
      AND resource_type IN ('rolebindings', 'clusterrolebindings')
      AND actor_name NOT IN ('kubernetes-admin', 'kube-admin')
      AND NOT array_contains(actor_groups, 'system:masters')
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
        'Application Access Tokens' AS subtechnique_name
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
            SUBSTRING(SHA2(COALESCE(actor_name, ''), 256), 1, 8),
            '-',
            SUBSTRING(SHA2(CONCAT(COALESCE(namespace, ''), '/', COALESCE(target_name, '')), 256), 1, 8)
        ) AS finding_uid
    FROM combined
)
SELECT
    CAST(finding_uid AS STRING) AS finding_uid,
    CAST(finding_uid AS STRING) AS event_uid,
    CAST(rule_name AS STRING) AS rule_name,
    CAST(severity_id AS INT) AS severity_id,
    CAST(actor_name AS STRING) AS actor_name,
    CAST(namespace AS STRING) AS namespace,
    CAST(target_name AS STRING) AS target_name,
    CAST(resource_type AS STRING) AS resource_type,
    CAST(subresource AS STRING) AS subresource,
    CAST(first_seen_time_ms AS BIGINT) AS first_seen_time_ms,
    CAST(last_seen_time_ms AS BIGINT) AS last_seen_time_ms,
    CAST(finding_time_ms AS BIGINT) AS finding_time_ms,
    CAST(mitre_technique_uid AS STRING) AS mitre_technique_uid,
    CAST(mitre_subtechnique_uid AS STRING) AS mitre_subtechnique_uid,
    CAST(finding_type AS STRING) AS finding_type,
    CAST(
        TO_JSON(
            NAMED_STRUCT(
                'activity_id', 1,
                'category_uid', 2,
                'category_name', 'Findings',
                'class_uid', 2004,
                'class_name', 'Detection Finding',
                'type_uid', 200401,
                'severity_id', severity_id,
                'status_id', 1,
                'time', finding_time_ms,
                'metadata', NAMED_STRUCT(
                    'version', '1.8.0',
                    'uid', finding_uid,
                    'product', NAMED_STRUCT(
                        'name', 'cloud-ai-security-skills',
                        'vendor_name', 'msaad00/cloud-ai-security-skills',
                        'feature', NAMED_STRUCT('name', 'packs/privilege-escalation-k8s/databricks.sql')
                    ),
                    'labels', ARRAY('query-pack', 'kubernetes', 'privilege-escalation', rule_name, 'databricks')
                ),
                'finding_info', NAMED_STRUCT(
                    'uid', finding_uid,
                    'title', title,
                    'desc',
                        CASE
                            WHEN rule_name = 'r1-secret-enum' THEN
                                CONCAT(
                                    'Service account ''', actor_name,
                                    ''' performed `list` on secrets in namespace ''', namespace,
                                    ''' and then `get` on secret ''', target_name,
                                    ''' within the 300-second correlation window. Workloads that need secret data should mount secrets as files, not call the K8s API for them — this pattern is a strong signal of a compromised pod searching for credentials. (MITRE T1552.007)'
                                )
                            WHEN rule_name = 'r2-pod-exec' THEN
                                CONCAT(
                                    'Service account ''', actor_name,
                                    ''' called `create` on pods/exec for pod ''', target_name,
                                    ''' in namespace ''', namespace,
                                    '''. Workloads (as opposed to human operators) should never exec into other pods — this is the precursor to container escape. (MITRE T1611)'
                                )
                            WHEN rule_name = 'r3-rbac-self-grant' THEN
                                CONCAT(
                                    'Principal ''', actor_name,
                                    ''' created ',
                                    CASE WHEN resource_type = 'clusterrolebindings' THEN 'clusterrolebinding' ELSE 'rolebinding' END,
                                    ' ''', target_name, '''',
                                    CASE WHEN namespace = '' THEN '' ELSE CONCAT(' in namespace ', namespace) END,
                                    '. This principal is not in system:masters and is not a recognised admin user — creating a binding is the canonical K8s privilege-escalation move after initial compromise. (MITRE T1098)'
                                )
                            ELSE
                                CONCAT(
                                    'Service account ''', actor_name,
                                    ''' created a token for ''',
                                    CASE WHEN target_name = '' THEN 'tokenreview' ELSE target_name END,
                                    ''' in namespace ''', namespace,
                                    '''. Combined with secret access or RBAC manipulation this is token-theft in progress. (MITRE T1550.001)'
                                )
                        END,
                    'types', ARRAY(finding_type),
                    'first_seen_time', first_seen_time_ms,
                    'last_seen_time', last_seen_time_ms
                )
            )
        ) AS STRING
    ) AS finding_json
FROM final_findings
ORDER BY rule_name, actor_name, namespace, target_name;
