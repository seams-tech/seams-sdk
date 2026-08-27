-- Refactor 115: admit authorities created by wallet recovery.
--
-- SQLite cannot alter the provenance CHECK constraint. Rebuild the authority
-- table while preserving every existing registration and device-link row.

PRAGMA defer_foreign_keys = ON;

DROP INDEX IF EXISTS wallet_authorities_active_device_uidx;
DROP INDEX IF EXISTS wallet_authorities_enrollment_uidx;
DROP INDEX IF EXISTS wallet_authorities_inventory_idx;
DROP INDEX IF EXISTS wallet_authorities_wallet_identity_uidx;

CREATE TABLE wallet_authorities_next (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  authority_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  provenance_kind TEXT NOT NULL,
  enrollment_id TEXT,
  source_authority_id TEXT,
  link_session_id TEXT,
  recovery_operation_id TEXT,
  continuity_authority_id TEXT,
  lifecycle_state TEXT NOT NULL,
  permissions_json TEXT NOT NULL,
  signer_activations_json TEXT NOT NULL,
  local_install_package_set_digest_b64u TEXT,
  signer_activation_set_digest_b64u TEXT NOT NULL,
  authority_digest_b64u TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  activated_at_ms INTEGER,
  revoked_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, authority_id),
  CHECK (length(authority_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (provenance_kind IN ('wallet_registration', 'device_link', 'wallet_recovery')),
  CHECK (lifecycle_state IN ('pending_local_install', 'active', 'revoked')),
  CHECK (length(permissions_json) > 0 AND json_valid(permissions_json)),
  CHECK (length(signer_activations_json) > 0 AND json_valid(signer_activations_json)),
  CHECK (length(record_json) > 0 AND json_valid(record_json)),
  CHECK (length(signer_activation_set_digest_b64u) > 0),
  CHECK (length(authority_digest_b64u) > 0),
  CHECK (revocation_epoch >= 0),
  CHECK (created_at_ms >= 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (
    (provenance_kind = 'wallet_registration'
      AND enrollment_id IS NULL
      AND source_authority_id IS NULL
      AND link_session_id IS NULL
      AND recovery_operation_id IS NULL
      AND continuity_authority_id IS NULL)
    OR
    (provenance_kind = 'device_link'
      AND enrollment_id IS NOT NULL AND length(enrollment_id) > 0
      AND source_authority_id IS NOT NULL AND length(source_authority_id) > 0
      AND link_session_id IS NOT NULL AND length(link_session_id) > 0
      AND recovery_operation_id IS NULL
      AND continuity_authority_id IS NULL)
    OR
    (provenance_kind = 'wallet_recovery'
      AND enrollment_id IS NULL
      AND source_authority_id IS NULL
      AND link_session_id IS NULL
      AND recovery_operation_id IS NOT NULL
      AND length(recovery_operation_id) > 0
      AND continuity_authority_id IS NOT NULL
      AND length(continuity_authority_id) > 0)
  ),
  CHECK (
    (lifecycle_state = 'pending_local_install'
      AND local_install_package_set_digest_b64u IS NOT NULL
      AND length(local_install_package_set_digest_b64u) > 0
      AND activated_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND revocation_epoch = 0)
    OR
    (lifecycle_state = 'active'
      AND local_install_package_set_digest_b64u IS NULL
      AND activated_at_ms IS NOT NULL
      AND revoked_at_ms IS NULL)
    OR
    (lifecycle_state = 'revoked'
      AND local_install_package_set_digest_b64u IS NULL
      AND activated_at_ms IS NOT NULL
      AND revoked_at_ms IS NOT NULL
      AND revocation_epoch >= 1)
  ),
  CHECK (json_extract(record_json, '$.authorityId') = authority_id),
  CHECK (json_extract(record_json, '$.walletId') = wallet_id),
  CHECK (json_extract(record_json, '$.state') = lifecycle_state),
  CHECK (json_extract(record_json, '$.revocationEpoch') = revocation_epoch),
  CHECK (json_extract(record_json, '$.authorityDigestB64u') = authority_digest_b64u),
  CHECK (
    json_extract(record_json, '$.signerActivationSetDigestB64u')
      = signer_activation_set_digest_b64u
  )
);

INSERT INTO wallet_authorities_next (
  namespace, org_id, project_id, env_id,
  authority_id, wallet_id, device_id, provenance_kind,
  enrollment_id, source_authority_id, link_session_id,
  recovery_operation_id, continuity_authority_id,
  lifecycle_state, permissions_json, signer_activations_json,
  local_install_package_set_digest_b64u,
  signer_activation_set_digest_b64u, authority_digest_b64u,
  revocation_epoch, record_json, created_at_ms, updated_at_ms,
  activated_at_ms, revoked_at_ms
)
SELECT
  namespace, org_id, project_id, env_id,
  authority_id, wallet_id, device_id, provenance_kind,
  enrollment_id, source_authority_id, link_session_id,
  NULL, NULL,
  lifecycle_state, permissions_json, signer_activations_json,
  local_install_package_set_digest_b64u,
  signer_activation_set_digest_b64u, authority_digest_b64u,
  revocation_epoch, record_json, created_at_ms, updated_at_ms,
  activated_at_ms, revoked_at_ms
FROM wallet_authorities;

DROP TABLE wallet_authorities;
ALTER TABLE wallet_authorities_next RENAME TO wallet_authorities;

CREATE UNIQUE INDEX wallet_authorities_active_device_uidx
  ON wallet_authorities (
    namespace, org_id, project_id, env_id, wallet_id, device_id
  )
  WHERE lifecycle_state <> 'revoked';

CREATE UNIQUE INDEX wallet_authorities_enrollment_uidx
  ON wallet_authorities (
    namespace, org_id, project_id, env_id, wallet_id, enrollment_id
  )
  WHERE enrollment_id IS NOT NULL;

CREATE INDEX wallet_authorities_inventory_idx
  ON wallet_authorities (
    namespace, org_id, project_id, env_id, wallet_id, lifecycle_state,
    updated_at_ms, authority_id
  );

CREATE UNIQUE INDEX wallet_authorities_wallet_identity_uidx
  ON wallet_authorities (
    namespace, org_id, project_id, env_id, authority_id, wallet_id
  );

PRAGMA defer_foreign_keys = OFF;
