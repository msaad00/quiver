-- Row access policies — multi-tenant isolation by cloud account.
--
-- Snowflake evaluates the policy predicate at query time. A per-tenant role is
-- mapped to its `cloud.account.uid` claim through the mapping table below; the
-- policy then admits only rows whose payload account uid matches the caller's
-- role mapping. Operators provision the role→tenant rows; the skills never do.
--
-- The skill registry stays tenant-agnostic: the platform manager that brokers
-- the connection selects the tenant role, and Snowflake enforces the boundary.

CREATE TABLE IF NOT EXISTS security_db.ops.tenant_role_map (
    role_name   STRING NOT NULL,
    tenant_uid  STRING NOT NULL,
    CONSTRAINT pk_tenant_role_map PRIMARY KEY (role_name, tenant_uid)
)
COMMENT = 'Maps a Snowflake role to the cloud.account.uid it may read.';

CREATE ROW ACCESS POLICY IF NOT EXISTS security_db.ops.tenant_isolation
  AS (payload VARIANT) RETURNS BOOLEAN ->
    -- Operator/admin roles see everything; tenant roles see only their account.
    CURRENT_ROLE() IN ('SECURITY_LAKE_OPERATOR', 'ACCOUNTADMIN')
    OR EXISTS (
      SELECT 1
      FROM security_db.ops.tenant_role_map m
      WHERE m.role_name = CURRENT_ROLE()
        AND m.tenant_uid = payload:cloud.account.uid::string
    );

ALTER TABLE security_db.ops.findings_sink
  ADD ROW ACCESS POLICY security_db.ops.tenant_isolation ON (payload);
ALTER TABLE security_db.ops.events_sink
  ADD ROW ACCESS POLICY security_db.ops.tenant_isolation ON (payload);
ALTER TABLE security_db.ops.evidence_sink
  ADD ROW ACCESS POLICY security_db.ops.tenant_isolation ON (payload);
