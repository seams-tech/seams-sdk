-- R103E operation credentials were added after migration 0008 had already
-- reached persistent environments. Apply the schema change at a new boundary.

ALTER TABLE wallet_session_authorizations_v2
  ADD COLUMN operation_credential_hash TEXT
  CHECK (operation_credential_hash IS NULL OR length(operation_credential_hash) > 0);

CREATE UNIQUE INDEX wallet_session_authorizations_v2_operation_credential_uidx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id, operation_credential_hash
  )
  WHERE operation_credential_hash IS NOT NULL;
