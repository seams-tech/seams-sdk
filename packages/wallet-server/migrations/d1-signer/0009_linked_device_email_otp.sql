-- Refactor 103 Phase 6: move the target-factor and linked-owner schema changes
-- out of the applied initial migration. The target-preparation digest changed
-- when QR v5 added targetFactor. Pre-v5 target rows cannot be rehashed by SQL,
-- so only already-canonical rows are carried forward; stale rows are removed
-- with their deployment descriptors and must be started again.

DROP INDEX linked_device_target_credentials_credential_idx;

DELETE FROM linked_device_target_deployment_descriptors
 WHERE EXISTS (
   SELECT 1
     FROM linked_device_target_credentials AS legacy
    WHERE legacy.namespace = linked_device_target_deployment_descriptors.namespace
      AND legacy.org_id = linked_device_target_deployment_descriptors.org_id
      AND legacy.project_id = linked_device_target_deployment_descriptors.project_id
      AND legacy.env_id = linked_device_target_deployment_descriptors.env_id
      AND legacy.link_session_id = linked_device_target_deployment_descriptors.link_session_id
      AND (
        COALESCE(json_extract(legacy.preparation_json, '$.targetFactor.kind'), '') <> 'passkey_prf'
        OR (
          legacy.state = 'registered'
          AND COALESCE(json_extract(legacy.registration_json, '$.targetFactor.kind'), '') <> 'passkey_prf'
        )
      )
 );

ALTER TABLE linked_device_target_credentials RENAME TO linked_device_target_credentials_legacy;
CREATE TABLE linked_device_target_credentials_next (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  state TEXT NOT NULL,
  target_factor TEXT NOT NULL,
  preparation_digest_b64u TEXT NOT NULL,
  preparation_json TEXT NOT NULL,
  registration_json TEXT,
  credential_id_b64u TEXT,
  credential_public_key_b64u TEXT,
  credential_counter INTEGER,
  email_otp_grant_id TEXT,
  key_manifest_digest_b64u TEXT,
  prepared_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  registered_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(wallet_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (state IN ('prepared', 'registered')),
  CHECK (target_factor IN ('passkey_prf', 'email_otp')),
  CHECK (length(preparation_digest_b64u) > 0),
  CHECK (json_valid(preparation_json)),
  CHECK (COALESCE(json_extract(preparation_json, '$.targetFactor.kind') = target_factor, 0)),
  CHECK (expires_at_ms > prepared_at_ms),
  CHECK (
    (state = 'prepared'
      AND registration_json IS NULL
      AND credential_id_b64u IS NULL
      AND credential_public_key_b64u IS NULL
      AND credential_counter IS NULL
      AND email_otp_grant_id IS NULL
      AND key_manifest_digest_b64u IS NULL
      AND registered_at_ms IS NULL)
    OR
    (state = 'registered'
      AND target_factor = 'passkey_prf'
      AND json_valid(registration_json)
      AND COALESCE(json_extract(registration_json, '$.targetFactor.kind') = 'passkey_prf', 0)
      AND length(credential_id_b64u) > 0
      AND length(credential_public_key_b64u) > 0
      AND credential_counter >= 0
      AND email_otp_grant_id IS NULL
      AND length(key_manifest_digest_b64u) > 0
      AND registered_at_ms > 0)
    OR
    (state = 'registered'
      AND target_factor = 'email_otp'
      AND json_valid(registration_json)
      AND COALESCE(json_extract(registration_json, '$.targetFactor.kind') = 'email_otp', 0)
      AND credential_id_b64u IS NOT NULL
      AND length(credential_id_b64u) > 0
      AND credential_public_key_b64u IS NULL
      AND credential_counter IS NULL
      AND email_otp_grant_id IS NOT NULL
      AND length(email_otp_grant_id) > 0
      AND length(key_manifest_digest_b64u) > 0
      AND registered_at_ms > 0)
  )
);
INSERT INTO linked_device_target_credentials_next (
  namespace, org_id, project_id, env_id, link_session_id,
  wallet_id, enrollment_id, device_id, state, target_factor,
  preparation_digest_b64u, preparation_json, registration_json,
  credential_id_b64u, credential_public_key_b64u, credential_counter,
  email_otp_grant_id, key_manifest_digest_b64u, prepared_at_ms,
  expires_at_ms, registered_at_ms
)
SELECT namespace, org_id, project_id, env_id, link_session_id,
       wallet_id, enrollment_id, device_id, state,
       json_extract(preparation_json, '$.targetFactor.kind'),
       preparation_digest_b64u, preparation_json, registration_json,
       credential_id_b64u, credential_public_key_b64u, credential_counter,
       NULL, key_manifest_digest_b64u, prepared_at_ms, expires_at_ms,
       registered_at_ms
  FROM linked_device_target_credentials_legacy
 WHERE json_extract(preparation_json, '$.targetFactor.kind') = 'passkey_prf'
   AND (
     state = 'prepared'
     OR (
       state = 'registered'
       AND json_extract(registration_json, '$.targetFactor.kind') = 'passkey_prf'
     )
   );
DROP TABLE linked_device_target_credentials_legacy;
ALTER TABLE linked_device_target_credentials_next RENAME TO linked_device_target_credentials;
CREATE UNIQUE INDEX linked_device_target_credentials_credential_idx
  ON linked_device_target_credentials(
    namespace,
    org_id,
    project_id,
    env_id,
    credential_id_b64u
  )
  WHERE credential_id_b64u IS NOT NULL;

DROP INDEX email_otp_challenges_context_idx;
DROP INDEX email_otp_challenges_expires_idx;
ALTER TABLE email_otp_challenges RENAME TO email_otp_challenges_legacy;
CREATE TABLE email_otp_challenges_next (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  challenge_subject_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  otp_channel TEXT NOT NULL,
  owner_proof_binding_digest TEXT NOT NULL,
  action TEXT NOT NULL,
  operation TEXT NOT NULL,
  otp_code TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (length(challenge_subject_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (otp_channel = 'email_otp'),
  CHECK (length(owner_proof_binding_digest) > 0),
  CHECK (
    action IN (
      'wallet_email_otp_login',
      'wallet_email_otp_registration',
      'wallet_email_otp_device_recovery',
      'wallet_email_otp_device_link'
    )
  ),
  CHECK (operation IN ('wallet_unlock', 'transaction_sign', 'export_key', 'registration', 'device_link')),
  CHECK (length(otp_code) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'email_otp_challenge_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeId') = challenge_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeSubjectId') = challenge_subject_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.otpChannel') = otp_channel, 0)),
  CHECK (
    COALESCE(json_extract(record_json, '$.ownerProofBindingDigest') = owner_proof_binding_digest, 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.action') = action, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.operation') = operation, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.otpCode') = otp_code, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);
INSERT INTO email_otp_challenges_next (
  namespace, org_id, project_id, env_id, challenge_id, challenge_subject_id,
  wallet_id, record_org_id, otp_channel, owner_proof_binding_digest, action,
  operation, otp_code, record_json, created_at_ms, expires_at_ms
)
SELECT namespace, org_id, project_id, env_id, challenge_id, challenge_subject_id,
       wallet_id, record_org_id, otp_channel, owner_proof_binding_digest, action,
       operation, otp_code, record_json, created_at_ms, expires_at_ms
  FROM email_otp_challenges_legacy;
DROP TABLE email_otp_challenges_legacy;
ALTER TABLE email_otp_challenges_next RENAME TO email_otp_challenges;
CREATE INDEX email_otp_challenges_context_idx
  ON email_otp_challenges (
    namespace, org_id, project_id, env_id, challenge_subject_id, wallet_id,
    record_org_id, otp_channel, owner_proof_binding_digest, action, operation,
    expires_at_ms, created_at_ms
  );
CREATE INDEX email_otp_challenges_expires_idx
  ON email_otp_challenges (namespace, org_id, project_id, env_id, expires_at_ms);

DROP INDEX linked_device_owner_auth_bindings_device_idx;
DROP INDEX linked_device_owner_auth_bindings_method_idx;
DROP INDEX linked_device_owner_auth_bindings_wallet_idx;
ALTER TABLE linked_device_owner_auth_bindings RENAME TO linked_device_owner_auth_bindings_legacy;
CREATE TABLE linked_device_owner_auth_bindings_next (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  base_wallet_auth_method_id TEXT NOT NULL,
  factor_kind TEXT NOT NULL,
  rp_id TEXT,
  credential_id_b64u TEXT,
  email_hash_hex TEXT,
  registration_authority_id TEXT,
  key_manifest_digest_b64u TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, base_wallet_auth_method_id)
    REFERENCES wallet_auth_methods(namespace, org_id, project_id, env_id, wallet_auth_method_id),
  CHECK (length(tenant_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(wallet_auth_method_id) > 0),
  CHECK (length(base_wallet_auth_method_id) > 0),
  CHECK (length(key_manifest_digest_b64u) > 0),
  CHECK (factor_kind IN ('passkey', 'email_otp')),
  CHECK (lifecycle_state IN ('active', 'paused', 'revoked')),
  CHECK (revocation_epoch >= 0),
  CHECK (lifecycle_state <> 'revoked' OR revocation_epoch >= 1),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.kind') = 'linked_device_owner_auth_binding_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.enrollmentId') = enrollment_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.deviceId') = device_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletAuthMethodId') = wallet_auth_method_id, 0)),
  CHECK (
    (
      factor_kind = 'passkey'
      AND rp_id IS NOT NULL
      AND length(rp_id) > 0
      AND credential_id_b64u IS NOT NULL
      AND length(credential_id_b64u) > 0
      AND email_hash_hex IS NULL
      AND registration_authority_id IS NULL
      AND wallet_auth_method_id = 'passkey:' || rp_id || ':' || credential_id_b64u
      AND base_wallet_auth_method_id = wallet_auth_method_id
    )
    OR
    (
      factor_kind = 'email_otp'
      AND rp_id IS NULL
      AND credential_id_b64u IS NULL
      AND email_hash_hex IS NOT NULL
      AND length(email_hash_hex) > 0
      AND registration_authority_id IS NOT NULL
      AND length(registration_authority_id) > 0
      AND wallet_auth_method_id = 'email_otp_linked:' || wallet_id || ':' || enrollment_id
        || ':' || device_id || ':' || email_hash_hex
      AND base_wallet_auth_method_id = 'email_otp:' || wallet_id || ':' || email_hash_hex
      AND COALESCE(
        json_extract(record_json, '$.factor.baseWalletAuthMethodId')
          = base_wallet_auth_method_id,
        0
      )
    )
  )
);
INSERT INTO linked_device_owner_auth_bindings_next (
  namespace, org_id, project_id, env_id, tenant_id, wallet_id,
  enrollment_id, device_id, wallet_auth_method_id, base_wallet_auth_method_id,
  factor_kind, rp_id, credential_id_b64u, email_hash_hex,
  registration_authority_id, key_manifest_digest_b64u, lifecycle_state,
  revocation_epoch, record_json, created_at_ms, updated_at_ms
)
SELECT namespace, org_id, project_id, env_id, tenant_id, wallet_id,
       enrollment_id, device_id,
       CASE factor_kind
         WHEN 'passkey' THEN wallet_auth_method_id
         ELSE 'email_otp_linked:' || wallet_id || ':' || enrollment_id || ':'
           || device_id || ':' || email_hash_hex
       END,
       wallet_auth_method_id,
       factor_kind, rp_id, credential_id_b64u, email_hash_hex,
       registration_authority_id, key_manifest_digest_b64u, lifecycle_state,
       revocation_epoch,
       CASE factor_kind
         WHEN 'passkey' THEN record_json
         ELSE json_set(
           record_json,
           '$.walletAuthMethodId',
           'email_otp_linked:' || wallet_id || ':' || enrollment_id || ':'
             || device_id || ':' || email_hash_hex,
           '$.factor.baseWalletAuthMethodId',
           wallet_auth_method_id
         )
       END,
       created_at_ms, updated_at_ms
  FROM linked_device_owner_auth_bindings_legacy;
DROP TABLE linked_device_owner_auth_bindings_legacy;
ALTER TABLE linked_device_owner_auth_bindings_next RENAME TO linked_device_owner_auth_bindings;
CREATE UNIQUE INDEX linked_device_owner_auth_bindings_device_idx
  ON linked_device_owner_auth_bindings (namespace, org_id, project_id, env_id, wallet_id, device_id);
CREATE UNIQUE INDEX linked_device_owner_auth_bindings_method_idx
  ON linked_device_owner_auth_bindings (namespace, org_id, project_id, env_id, wallet_id, wallet_auth_method_id);
CREATE INDEX linked_device_owner_auth_bindings_wallet_idx
  ON linked_device_owner_auth_bindings (namespace, org_id, project_id, env_id, wallet_id, lifecycle_state);

CREATE TABLE linked_device_email_otp_grants (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  grant_token_digest_b64u TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  target_factor TEXT NOT NULL,
  target_preparation_digest_b64u TEXT NOT NULL,
  base_wallet_auth_method_id TEXT NOT NULL,
  linked_owner_auth_method_id TEXT NOT NULL,
  authority_digest_b64u TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  state TEXT NOT NULL,
  record_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, grant_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, base_wallet_auth_method_id)
    REFERENCES wallet_auth_methods(namespace, org_id, project_id, env_id, wallet_auth_method_id),
  CHECK (length(grant_id) > 0),
  CHECK (length(grant_token_digest_b64u) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(link_session_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (target_factor = 'email_otp'),
  CHECK (length(target_preparation_digest_b64u) > 0),
  CHECK (length(base_wallet_auth_method_id) > 0),
  CHECK (length(linked_owner_auth_method_id) > 0),
  CHECK (length(authority_digest_b64u) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (state IN ('issued', 'consumed')),
  CHECK (json_valid(record_json)),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (
    (state = 'issued' AND consumed_at_ms IS NULL)
    OR (state = 'consumed' AND consumed_at_ms >= issued_at_ms)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.kind') = 'linked_device_email_otp_grant_record_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.grantId') = grant_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.grantTokenDigestB64u') = grant_token_digest_b64u, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.linkSessionId') = link_session_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.enrollmentId') = enrollment_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.deviceId') = device_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.targetFactor.kind') = target_factor, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.targetPreparationDigestB64u') = target_preparation_digest_b64u, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.baseWalletAuthMethodId') = base_wallet_auth_method_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.linkedOwnerAuthMethodId') = linked_owner_auth_method_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.authorityDigestB64u') = authority_digest_b64u, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeId') = challenge_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.state.kind') = state, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.issuedAtMs') = issued_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0)),
  CHECK (
    consumed_at_ms IS NULL
    OR COALESCE(json_extract(record_json, '$.state.consumedAtMs') = consumed_at_ms, 0)
  )
);
CREATE INDEX linked_device_email_otp_grants_session_idx
  ON linked_device_email_otp_grants (
    namespace, org_id, project_id, env_id, link_session_id, state, expires_at_ms
  );
CREATE INDEX linked_device_email_otp_grants_expiry_idx
  ON linked_device_email_otp_grants (namespace, org_id, project_id, env_id, expires_at_ms);
