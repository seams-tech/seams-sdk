-- R103F final enforcement and deletion cutover.
--
-- The additive bridge is intentionally one-way. This migration validates the
-- remaining registration journal inventory, removes V1 ownership surfaces,
-- and rebuilds the V2 aggregate so every active row has an exact primary
-- credential digest.

PRAGMA defer_foreign_keys = ON;

-- Registration completion rows are the only persisted boundary that may still
-- contain a historical bearer. Claims and V2 receipts are credential-free;
-- the exact V1 completion envelope is known legacy state and is deleted.
-- A duplicate guard row is an executable ABORT in SQLite; RAISE() is only
-- legal inside a trigger body.
CREATE TABLE r103f_registration_shape_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
INSERT INTO r103f_registration_shape_guard (guard_id) VALUES (1);
INSERT INTO r103f_registration_shape_guard (guard_id)
SELECT 1
  FROM router_ab_yao_versioned_json_records AS record
 WHERE (
   record.record_key LIKE 'wallet-registration-activate:%'
   OR record.record_key LIKE 'wallet-registration-near-provisioning:%'
 )
 AND NOT (
   (
     json_extract(record.record_json, '$.kind')
       = 'router_ab_ed25519_yao_registration_side_effect_claim_v1'
     AND json_extract(record.record_json, '$.operation') = CASE
       WHEN record.record_key LIKE 'wallet-registration-activate:%'
         THEN 'registration_activate'
       ELSE 'near_provisioning'
     END
     AND (SELECT COUNT(*) FROM json_each(record.record_json)) = 6
     AND NOT EXISTS (
       SELECT 1
         FROM json_each(record.record_json) AS field
        WHERE field.key NOT IN (
          'kind', 'operation', 'requestFingerprint',
          'preparedArtifactFingerprint', 'claimedAtMs', 'prepared'
        )
     )
     AND json_type(record.record_json, '$.requestFingerprint') = 'text'
     AND length(trim(json_extract(record.record_json, '$.requestFingerprint'))) > 0
     AND json_type(record.record_json, '$.preparedArtifactFingerprint') = 'text'
     AND length(trim(json_extract(record.record_json, '$.preparedArtifactFingerprint'))) > 0
     AND json_type(record.record_json, '$.claimedAtMs') = 'integer'
     AND json_type(record.record_json, '$.prepared') = 'object'
     AND (SELECT COUNT(*) FROM json_each(json_extract(record.record_json, '$.prepared'))) = 4
     AND NOT EXISTS (
       SELECT 1
         FROM json_each(json_extract(record.record_json, '$.prepared')) AS field
        WHERE field.key NOT IN ('kind', 'walletAuthorityId', 'deviceId', 'walletAuthMethodId')
     )
     AND json_extract(record.record_json, '$.prepared.kind')
       = 'd1_wallet_registration_operation_prepared_v1'
     AND json_type(record.record_json, '$.prepared.walletAuthorityId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.walletAuthorityId'))) > 0
     AND json_type(record.record_json, '$.prepared.deviceId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.deviceId'))) > 0
     AND json_type(record.record_json, '$.prepared.walletAuthMethodId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.walletAuthMethodId'))) > 0
   )
   OR
   (
     json_extract(record.record_json, '$.kind')
       = 'router_ab_ed25519_yao_registration_side_effect_completion_v1'
     AND json_extract(record.record_json, '$.operation') = CASE
       WHEN record.record_key LIKE 'wallet-registration-activate:%'
         THEN 'registration_activate'
       ELSE 'near_provisioning'
     END
     AND (SELECT COUNT(*) FROM json_each(record.record_json)) = 8
     AND NOT EXISTS (
       SELECT 1
         FROM json_each(record.record_json) AS field
        WHERE field.key NOT IN (
          'kind', 'operation', 'requestFingerprint',
          'preparedArtifactFingerprint', 'claimedAtMs', 'completedAtMs',
          'prepared', 'response'
        )
     )
     AND json_type(record.record_json, '$.requestFingerprint') = 'text'
     AND length(trim(json_extract(record.record_json, '$.requestFingerprint'))) > 0
     AND json_type(record.record_json, '$.preparedArtifactFingerprint') = 'text'
     AND length(trim(json_extract(record.record_json, '$.preparedArtifactFingerprint'))) > 0
     AND json_type(record.record_json, '$.claimedAtMs') = 'integer'
     AND json_type(record.record_json, '$.completedAtMs') = 'integer'
     AND json_extract(record.record_json, '$.completedAtMs')
       >= json_extract(record.record_json, '$.claimedAtMs')
     AND json_type(record.record_json, '$.prepared') = 'object'
     AND (SELECT COUNT(*) FROM json_each(json_extract(record.record_json, '$.prepared'))) = 4
     AND NOT EXISTS (
       SELECT 1
         FROM json_each(json_extract(record.record_json, '$.prepared')) AS field
        WHERE field.key NOT IN ('kind', 'walletAuthorityId', 'deviceId', 'walletAuthMethodId')
     )
     AND json_extract(record.record_json, '$.prepared.kind')
       = 'd1_wallet_registration_operation_prepared_v1'
     AND json_type(record.record_json, '$.prepared.walletAuthorityId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.walletAuthorityId'))) > 0
     AND json_type(record.record_json, '$.prepared.deviceId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.deviceId'))) > 0
     AND json_type(record.record_json, '$.prepared.walletAuthMethodId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.walletAuthMethodId'))) > 0
     AND json_type(record.record_json, '$.response') = 'object'
   )
   OR
   (
     json_extract(record.record_json, '$.kind')
       = 'router_ab_ed25519_yao_registration_side_effect_completion_v2'
     AND json_extract(record.record_json, '$.operation') = CASE
       WHEN record.record_key LIKE 'wallet-registration-activate:%'
         THEN 'registration_activate'
       ELSE 'near_provisioning'
     END
     AND (SELECT COUNT(*) FROM json_each(record.record_json)) = 8
     AND NOT EXISTS (
       SELECT 1
         FROM json_each(record.record_json) AS field
        WHERE field.key NOT IN (
          'kind', 'operation', 'requestFingerprint',
          'preparedArtifactFingerprint', 'claimedAtMs', 'completedAtMs',
          'prepared', 'receipt'
        )
     )
     AND json_type(record.record_json, '$.requestFingerprint') = 'text'
     AND length(trim(json_extract(record.record_json, '$.requestFingerprint'))) > 0
     AND json_type(record.record_json, '$.preparedArtifactFingerprint') = 'text'
     AND length(trim(json_extract(record.record_json, '$.preparedArtifactFingerprint'))) > 0
     AND json_type(record.record_json, '$.claimedAtMs') = 'integer'
     AND json_type(record.record_json, '$.completedAtMs') = 'integer'
     AND json_extract(record.record_json, '$.completedAtMs')
       >= json_extract(record.record_json, '$.claimedAtMs')
     AND json_type(record.record_json, '$.prepared') = 'object'
     AND (SELECT COUNT(*) FROM json_each(json_extract(record.record_json, '$.prepared'))) = 4
     AND NOT EXISTS (
       SELECT 1
         FROM json_each(json_extract(record.record_json, '$.prepared')) AS field
        WHERE field.key NOT IN ('kind', 'walletAuthorityId', 'deviceId', 'walletAuthMethodId')
     )
     AND json_extract(record.record_json, '$.prepared.kind')
       = 'd1_wallet_registration_operation_prepared_v1'
     AND json_type(record.record_json, '$.prepared.walletAuthorityId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.walletAuthorityId'))) > 0
     AND json_type(record.record_json, '$.prepared.deviceId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.deviceId'))) > 0
     AND json_type(record.record_json, '$.prepared.walletAuthMethodId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.prepared.walletAuthMethodId'))) > 0
     AND json_type(record.record_json, '$.receipt') = 'object'
     AND json_extract(record.record_json, '$.receipt.kind')
       = 'wallet_registration_session_commit_receipt_v2'
     AND json_extract(record.record_json, '$.receipt.operation')
       = json_extract(record.record_json, '$.operation')
     AND json_type(record.record_json, '$.receipt.operationFingerprint') = 'text'
     AND json_extract(record.record_json, '$.receipt.operationFingerprint')
       = json_extract(record.record_json, '$.requestFingerprint')
     AND json_type(record.record_json, '$.receipt.registrationCeremonyId') = 'text'
     AND length(trim(json_extract(record.record_json, '$.receipt.registrationCeremonyId'))) > 0
     AND json_type(record.record_json, '$.receipt.committed') = 'object'
     AND json_type(record.record_json, '$.receipt.committed.kind') = 'text'
     AND length(trim(json_extract(record.record_json, '$.receipt.committed.kind'))) > 0
     AND NOT EXISTS (
       SELECT 1
         FROM json_tree(record.record_json) AS field
        WHERE field.key IN (
          'walletSessionToken', 'primaryOperationCredential',
          'childOperationCredential', 'operationCredential',
          'clientRootProof', 'passkeyBootstrapAuthorization', 'response'
        )
     )
   )
 );
DROP TABLE r103f_registration_shape_guard;

DELETE FROM router_ab_yao_versioned_json_records
 WHERE (
   record_key LIKE 'wallet-registration-activate:%'
   OR record_key LIKE 'wallet-registration-near-provisioning:%'
 )
 AND json_extract(record_json, '$.kind')
   = 'router_ab_ed25519_yao_registration_side_effect_completion_v1';

-- A partial-scope pending grant is neither the retired V1 shape nor a valid
-- V2 grant. The all-null V1 shape is deleted below; fully scoped rows remain.
CREATE TABLE r103f_pending_grant_scope_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
INSERT INTO r103f_pending_grant_scope_guard (guard_id) VALUES (1);
INSERT INTO r103f_pending_grant_scope_guard (guard_id)
SELECT 1
  FROM authorized_operations AS operation
 WHERE operation.lifecycle_kind = 'claimed'
   AND operation.authorization_source_kind = 'authorization_grant'
   AND operation.authorization_grant_kind = 'wallet_session_authorization'
   AND NOT (
     (
       operation.linked_scope_org_id IS NULL
       AND operation.linked_scope_project_id IS NULL
       AND operation.linked_scope_env_id IS NULL
     )
     OR (
       operation.linked_scope_org_id IS NOT NULL
       AND operation.linked_scope_project_id IS NOT NULL
       AND operation.linked_scope_env_id IS NOT NULL
       AND length(trim(operation.linked_scope_org_id)) > 0
       AND length(trim(operation.linked_scope_project_id)) > 0
       AND length(trim(operation.linked_scope_env_id)) > 0
     )
   );
DROP TABLE r103f_pending_grant_scope_guard;

DELETE FROM authorized_operation_audit_events
 WHERE result_kind = 'pending'
   AND authorization_source_kind = 'authorization_grant'
   AND authorization_grant_kind = 'wallet_session_authorization'
   AND linked_scope_org_id IS NULL
   AND linked_scope_project_id IS NULL
   AND linked_scope_env_id IS NULL;
DELETE FROM authorized_operations
 WHERE lifecycle_kind = 'claimed'
   AND authorization_source_kind = 'authorization_grant'
   AND authorization_grant_kind = 'wallet_session_authorization'
   AND linked_scope_org_id IS NULL
   AND linked_scope_project_id IS NULL
   AND linked_scope_env_id IS NULL;

-- Remove V1 children before their reusable-session parent. The replay adapter
-- was already removed by 0031, so IF EXISTS keeps this cutover valid for both
-- clean and current-history databases.
DROP INDEX IF EXISTS authorized_operations_v1_pending_scope_idx;
DROP TRIGGER IF EXISTS hosted_wallet_session_exchange_mint_token;
DROP TRIGGER IF EXISTS reusable_wallet_session_authorization_identity_insert;
DROP TRIGGER IF EXISTS reusable_wallet_session_authorization_identity_update;
DROP TABLE IF EXISTS hosted_wallet_session_exchange_codes;
DROP TABLE IF EXISTS opaque_wallet_session_tokens;
DROP TABLE IF EXISTS registration_replay_opaque_wallet_session_tokens_v1;
DROP TABLE IF EXISTS reusable_wallet_sessions;

DELETE FROM authorization_wallet_session_quotas AS quota
 WHERE NOT EXISTS (
   SELECT 1
     FROM wallet_session_authorizations_v2 AS session
    WHERE session.namespace = quota.namespace
      AND session.tenant_id = quota.tenant_id
      AND session.quota_id = quota.quota_id
 )
 AND NOT EXISTS (
   SELECT 1
     FROM authorized_operations AS operation
    WHERE operation.namespace = quota.namespace
      AND operation.tenant_id = quota.tenant_id
      AND operation.quota_id = quota.quota_id
 )
 AND NOT EXISTS (
   SELECT 1
     FROM authorized_operation_audit_events AS audit
    WHERE audit.namespace = quota.namespace
      AND audit.tenant_id = quota.tenant_id
      AND audit.quota_id = quota.quota_id
 );

-- Null-digest and expired active rows are retained as retired history. This
-- keeps exact child/audit identities while making only usable rows eligible
-- for the final active-tuple index.
UPDATE wallet_session_authorizations_v2
   SET retired_at_ms = CASE
     WHEN operation_credential_hash IS NULL THEN issued_at_ms
     ELSE expires_at_ms
   END
 WHERE retired_at_ms IS NULL
   AND (
     operation_credential_hash IS NULL
     OR expires_at_ms <= (unixepoch() * 1000)
   );

CREATE TABLE r103f_active_tuple_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
INSERT INTO r103f_active_tuple_guard (guard_id) VALUES (1);
INSERT INTO r103f_active_tuple_guard (guard_id)
SELECT 1
  FROM wallet_session_authorizations_v2
 WHERE retired_at_ms IS NULL
   AND operation_credential_hash IS NOT NULL
 GROUP BY namespace, org_id, project_id, env_id,
   tenant_id, wallet_id, authority_id, wallet_auth_method_id
 HAVING COUNT(*) > 1;
DROP TABLE r103f_active_tuple_guard;

-- The child tables retain their exact composite foreign keys. Drop the old
-- parent indexes before replacing the parent so their names can be reused.
DROP INDEX IF EXISTS wallet_session_authorizations_v2_authority_idx;
DROP INDEX IF EXISTS wallet_session_authorizations_v2_method_idx;
DROP INDEX IF EXISTS wallet_session_authorizations_v2_wallet_idx;
DROP INDEX IF EXISTS wallet_session_authorizations_v2_expiry_idx;
DROP INDEX IF EXISTS wallet_session_authorizations_v2_credential_lifecycle_idx;
DROP INDEX IF EXISTS wallet_session_authorizations_v2_exact_identity_uidx;
DROP INDEX IF EXISTS wallet_session_authorizations_v2_operation_credential_uidx;
DROP INDEX IF EXISTS wallet_session_authorizations_v2_active_exact_tuple_uidx;

CREATE TABLE wallet_session_authorizations_v2_next (
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
  record_json TEXT NOT NULL,
  operation_credential_hash TEXT,
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
  CHECK (length(record_json) > 0 AND json_valid(record_json)),
  CHECK (operation_credential_hash IS NULL OR length(operation_credential_hash) > 0),
  CHECK (retired_at_ms IS NOT NULL OR operation_credential_hash IS NOT NULL),
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

INSERT INTO wallet_session_authorizations_v2_next (
  namespace, org_id, project_id, env_id, tenant_id, authorization_id,
  mint_id, wallet_session_id, quota_id, principal_id, wallet_id,
  authority_id, wallet_auth_method_id, authority_digest_b64u,
  authority_revocation_epoch, capability_subjects_json, issued_at_ms,
  expires_at_ms, retired_at_ms, record_json, operation_credential_hash
)
SELECT
  namespace, org_id, project_id, env_id, tenant_id, authorization_id,
  mint_id, wallet_session_id, quota_id, principal_id, wallet_id,
  authority_id, wallet_auth_method_id, authority_digest_b64u,
  authority_revocation_epoch, capability_subjects_json, issued_at_ms,
  expires_at_ms, retired_at_ms, record_json, operation_credential_hash
FROM wallet_session_authorizations_v2;

DROP TABLE wallet_session_authorizations_v2;
ALTER TABLE wallet_session_authorizations_v2_next RENAME TO wallet_session_authorizations_v2;

CREATE UNIQUE INDEX wallet_session_authorizations_v2_exact_identity_uidx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id,
    wallet_session_id, quota_id, principal_id, wallet_id,
    authority_id, wallet_auth_method_id
  );

CREATE UNIQUE INDEX wallet_session_authorizations_v2_active_exact_tuple_uidx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    wallet_id, authority_id, wallet_auth_method_id
  )
  WHERE retired_at_ms IS NULL;

CREATE UNIQUE INDEX wallet_session_authorizations_v2_operation_credential_uidx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id, operation_credential_hash
  )
  WHERE operation_credential_hash IS NOT NULL;

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

CREATE INDEX wallet_session_authorizations_v2_credential_lifecycle_idx
  ON wallet_session_authorizations_v2 (
    namespace, org_id, project_id, env_id, tenant_id,
    wallet_id, authority_id, wallet_auth_method_id,
    retired_at_ms, expires_at_ms, operation_credential_hash
  );

-- D1 has no convenient SQL-level RAISE outside triggers. A duplicate guard
-- makes any foreign-key-check result fail the migration before it can finish.
PRAGMA defer_foreign_keys = OFF;
CREATE TABLE r103f_foreign_key_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
INSERT INTO r103f_foreign_key_guard (guard_id) VALUES (1);
INSERT INTO r103f_foreign_key_guard (guard_id)
SELECT 1
  FROM pragma_foreign_key_check
 LIMIT 1;
DROP TABLE r103f_foreign_key_guard;
