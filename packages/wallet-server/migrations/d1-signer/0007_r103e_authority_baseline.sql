-- R103E authority baseline.
--
-- Local and staging deployments use the reset policy from refactor-103E. The
-- historical auth-method table is retained under a boundary-only name so
-- linked-device records and their foreign keys remain inspectable; runtime
-- readers use the new table below. No historical row is reconstructed into a
-- WalletAuthorityV1 or a V2 auth method here.

CREATE TABLE wallet_authorities (
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
  CHECK (provenance_kind IN ('wallet_registration', 'device_link')),
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
      AND link_session_id IS NULL)
    OR
    (provenance_kind = 'device_link'
      AND enrollment_id IS NOT NULL AND length(enrollment_id) > 0
      AND source_authority_id IS NOT NULL AND length(source_authority_id) > 0
      AND link_session_id IS NOT NULL AND length(link_session_id) > 0)
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

CREATE TABLE wallet_authority_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);

INSERT INTO wallet_authority_cas_guard (guard_id) VALUES (1);

DROP INDEX IF EXISTS wallet_auth_methods_email_uidx;
DROP INDEX IF EXISTS wallet_auth_methods_identifier_idx;
DROP INDEX IF EXISTS wallet_auth_methods_passkey_uidx;
DROP INDEX IF EXISTS wallet_auth_methods_wallet_idx;

ALTER TABLE wallet_auth_methods RENAME TO wallet_auth_methods_legacy;

CREATE TABLE wallet_auth_methods (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_authority_id TEXT NOT NULL,
  rp_id TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  auth_identifier_key TEXT NOT NULL,
  credential_id_b64u TEXT,
  credential_public_key_b64u TEXT,
  email_hash_hex TEXT,
  registration_authority_id TEXT,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  activated_at_ms INTEGER,
  revoked_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_auth_method_id),
  FOREIGN KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    wallet_authority_id
  ) REFERENCES wallet_authorities(
    namespace,
    org_id,
    project_id,
    env_id,
    authority_id
  ),
  CHECK (length(wallet_id) > 0),
  CHECK (length(wallet_authority_id) > 0),
  CHECK (kind IN ('passkey', 'email_otp')),
  CHECK (status IN ('pending_local_install', 'active', 'revoked')),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (length(auth_identifier_key) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms >= 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (
    (status = 'pending_local_install' AND activated_at_ms IS NULL AND revoked_at_ms IS NULL)
    OR
    (status = 'active' AND activated_at_ms IS NOT NULL AND revoked_at_ms IS NULL)
    OR
    (status = 'revoked' AND activated_at_ms IS NOT NULL AND revoked_at_ms IS NOT NULL)
  ),
  CHECK (
    (kind = 'passkey'
      AND length(rp_id) > 0
      AND credential_id_b64u IS NOT NULL
      AND length(credential_id_b64u) > 0
      AND credential_public_key_b64u IS NOT NULL
      AND length(credential_public_key_b64u) > 0
      AND email_hash_hex IS NULL
      AND registration_authority_id IS NULL
      AND auth_identifier_key = credential_id_b64u)
    OR
    (kind = 'email_otp'
      AND rp_id = ''
      AND credential_id_b64u IS NULL
      AND credential_public_key_b64u IS NULL
      AND email_hash_hex IS NOT NULL
      AND length(email_hash_hex) > 0
      AND registration_authority_id IS NOT NULL
      AND length(registration_authority_id) > 0
      AND auth_identifier_key = email_hash_hex)
  ),
  CHECK (json_extract(record_json, '$.version') = 'wallet_auth_method_v2'),
  CHECK (json_extract(record_json, '$.walletAuthMethodId') = wallet_auth_method_id),
  CHECK (json_extract(record_json, '$.walletId') = wallet_id),
  CHECK (json_extract(record_json, '$.walletAuthorityId') = wallet_authority_id),
  CHECK (json_extract(record_json, '$.kind') = kind),
  CHECK (json_extract(record_json, '$.status') = status),
  CHECK (json_extract(record_json, '$.createdAtMs') = created_at_ms),
  CHECK (json_extract(record_json, '$.updatedAtMs') = updated_at_ms),
  CHECK (
    (kind = 'passkey'
      AND json_extract(record_json, '$.rpId') = rp_id
      AND json_extract(record_json, '$.credentialIdB64u') = credential_id_b64u
      AND json_extract(record_json, '$.credentialPublicKeyB64u') = credential_public_key_b64u
      AND json_extract(record_json, '$.counter') >= 0)
    OR
    (kind = 'email_otp'
      AND json_extract(record_json, '$.emailHashHex') = email_hash_hex
      AND json_extract(record_json, '$.registrationAuthorityId') = registration_authority_id)
  )
);

CREATE INDEX wallet_auth_methods_wallet_authority_status_idx
  ON wallet_auth_methods (
    namespace, org_id, project_id, env_id, wallet_id, wallet_authority_id, status
  );

CREATE UNIQUE INDEX wallet_auth_methods_v2_passkey_uidx
  ON wallet_auth_methods (
    namespace, org_id, project_id, env_id, rp_id, credential_id_b64u
  )
  WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL;

CREATE UNIQUE INDEX wallet_auth_methods_v2_email_uidx
  ON wallet_auth_methods (
    namespace, org_id, project_id, env_id, wallet_id, email_hash_hex
  )
  WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL;
