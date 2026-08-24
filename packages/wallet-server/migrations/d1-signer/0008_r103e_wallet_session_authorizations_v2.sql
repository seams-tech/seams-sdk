-- R103E ordinary Wallet Session authorization records.
--
-- `reusable_wallet_sessions` remains the V1 boundary while its consumers are
-- cut over. V2 stores the exact authority snapshot used to issue a session;
-- no authority, auth-method, or capability subject is inferred at read time.

CREATE UNIQUE INDEX wallet_authorities_wallet_identity_uidx
  ON wallet_authorities (
    namespace, org_id, project_id, env_id, authority_id, wallet_id
  );

CREATE UNIQUE INDEX wallet_auth_methods_authority_identity_uidx
  ON wallet_auth_methods (
    namespace, org_id, project_id, env_id,
    wallet_auth_method_id, wallet_id, wallet_authority_id
  );

CREATE TABLE wallet_session_authorizations_v2 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  mint_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  authority_digest_b64u TEXT NOT NULL,
  authority_revocation_epoch INTEGER NOT NULL,
  capability_subjects_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  retired_at_ms INTEGER,
  operation_credential_hash TEXT,
  record_json TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, tenant_id, authorization_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, mint_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, wallet_session_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, quota_id),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, authority_id, wallet_id
  ) REFERENCES wallet_authorities(
    namespace, org_id, project_id, env_id, authority_id, wallet_id
  ),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id,
    wallet_auth_method_id, wallet_id, authority_id
  ) REFERENCES wallet_auth_methods(
    namespace, org_id, project_id, env_id,
    wallet_auth_method_id, wallet_id, wallet_authority_id
  ),
  FOREIGN KEY (namespace, tenant_id, quota_id)
    REFERENCES authorization_wallet_session_quotas(namespace, tenant_id, quota_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(tenant_id) > 0),
  CHECK (length(authorization_id) > 0),
  CHECK (length(mint_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(quota_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(authority_id) > 0),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (authorization_id != wallet_session_id),
  CHECK (authorization_id != quota_id),
  CHECK (wallet_session_id != quota_id),
  CHECK (length(authority_digest_b64u) > 0),
  CHECK (authority_revocation_epoch >= 0),
  CHECK (
    length(capability_subjects_json) > 0
    AND json_valid(capability_subjects_json)
    AND json_type(capability_subjects_json) = 'array'
    AND json_array_length(capability_subjects_json) > 0
  ),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (retired_at_ms IS NULL OR retired_at_ms >= issued_at_ms),
  CHECK (operation_credential_hash IS NULL OR length(operation_credential_hash) > 0),
  CHECK (length(record_json) > 0 AND json_valid(record_json)),
  CHECK (COALESCE(json_extract(record_json, '$.kind') = 'wallet_session_authorization_v2', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.tenantId') = tenant_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.principalId') = principal_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.authorityId') = authority_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletAuthMethodId') = wallet_auth_method_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.authorityDigestB64u') = authority_digest_b64u, 0)),
  CHECK (
    COALESCE(
      json_extract(record_json, '$.authorityRevocationEpoch') = authority_revocation_epoch,
      0
    )
  ),
  CHECK (COALESCE(json_extract(record_json, '$.mintId') = mint_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.authorizationId') = authorization_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletSessionId') = wallet_session_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.quotaId') = quota_id, 0)),
  CHECK (
    json_type(record_json, '$.capabilitySubjects') = 'array'
    AND json_array_length(record_json, '$.capabilitySubjects') > 0
    AND json_extract(record_json, '$.capabilitySubjects') = json(capability_subjects_json)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = issued_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

CREATE INDEX wallet_session_authorizations_v2_authority_idx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    wallet_id, authority_id, wallet_auth_method_id, retired_at_ms
  );

CREATE INDEX wallet_session_authorizations_v2_method_idx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    wallet_id, wallet_auth_method_id, retired_at_ms
  );

CREATE INDEX wallet_session_authorizations_v2_wallet_idx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    wallet_id, retired_at_ms, expires_at_ms
  );

CREATE INDEX wallet_session_authorizations_v2_expiry_idx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    expires_at_ms, retired_at_ms
  );

CREATE UNIQUE INDEX wallet_session_authorizations_v2_operation_credential_uidx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id, operation_credential_hash
  )
  WHERE operation_credential_hash IS NOT NULL;
