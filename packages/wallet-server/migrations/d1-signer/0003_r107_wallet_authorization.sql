CREATE TABLE verified_wallet_operation_evidence_sets (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  evidence_set_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_digest TEXT NOT NULL,
  request_origin TEXT NOT NULL,
  audience TEXT NOT NULL,
  evidence_set_digest TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  assurance TEXT NOT NULL,
  verified_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, evidence_set_id),
  UNIQUE (namespace, tenant_id, evidence_set_digest),
  CHECK (json_valid(evidence_json)),
  CHECK (assurance = 'step_up'),
  CHECK (expires_at_ms > verified_at_ms),
  CHECK (
    (capability_kind = 'near_ed25519_mpc_signing'
      AND operation_kind IN (
        'near.sign_transaction',
        'near.sign_delegate_action',
        'near.sign_nep413_message',
        'near.export_key'
      ))
    OR (capability_kind = 'evm_ecdsa_mpc_signing'
      AND operation_kind IN ('evm.sign_transaction', 'evm.export_key'))
    OR (capability_kind = 'vault_access'
      AND operation_kind IN ('vault.proxy_use', 'vault.reveal'))
  )
);

CREATE TABLE verified_owner_proof_consumptions (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  proof_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  method TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  authority_digest TEXT NOT NULL,
  replay_identity TEXT NOT NULL,
  consumption_scope_id TEXT NOT NULL,
  consumed_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, proof_id),
  UNIQUE (namespace, tenant_id, replay_identity),
  CHECK (purpose IN ('wallet_session', 'operation')),
  CHECK (method IN ('passkey', 'email_otp')),
  CHECK (consumed_at_ms > 0)
);

CREATE INDEX idx_verified_wallet_operation_evidence_expiry
  ON verified_wallet_operation_evidence_sets(namespace, tenant_id, expires_at_ms);

CREATE TABLE opaque_wallet_session_tokens (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  curve TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  binding_json TEXT NOT NULL,
  PRIMARY KEY (namespace, tenant_id, token_hash),
  UNIQUE (namespace, tenant_id, wallet_session_id, curve),
  FOREIGN KEY (namespace, tenant_id, wallet_session_id)
    REFERENCES reusable_wallet_sessions(namespace, tenant_id, wallet_session_id),
  CHECK (curve IN ('ecdsa', 'ed25519')),
  CHECK (json_valid(binding_json))
);

DROP TRIGGER authorized_operation_step_up_claim_atomic;

CREATE TRIGGER authorized_operation_step_up_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'verified_step_up'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
        SELECT 1
          FROM verified_wallet_operation_evidence_sets AS evidence
         WHERE evidence.namespace = NEW.namespace
           AND evidence.tenant_id = NEW.tenant_id
           AND evidence.evidence_set_digest = NEW.evidence_set_digest
           AND evidence.principal_id = NEW.principal_id
           AND evidence.capability_kind = NEW.capability_kind
           AND evidence.operation_kind = NEW.operation_kind
           AND evidence.lane_digest = NEW.lane_digest
           AND evidence.intent_digest = NEW.intent_digest
           AND evidence.display_digest = NEW.display_digest
           AND evidence.assurance = 'step_up'
           AND evidence.expires_at_ms > NEW.claimed_at_ms
      )
    THEN RAISE(ABORT, 'authorization_evidence_claim_rejected')
  END;
END;

DROP TRIGGER trg_hosted_wallet_exchange_create_target_session;
DROP TABLE hosted_wallet_session_exchange_codes;

CREATE TABLE hosted_wallet_session_exchange_codes (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  exchange_code_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  nonce_digest TEXT NOT NULL,
  app_origin TEXT NOT NULL,
  wallet_origin TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  token_hash TEXT,
  curve TEXT,
  binding_json TEXT,
  consumed_at_ms INTEGER,
  PRIMARY KEY (namespace, tenant_id, exchange_code_id),
  UNIQUE (namespace, code_hash),
  FOREIGN KEY (namespace, tenant_id, wallet_session_id)
    REFERENCES reusable_wallet_sessions(namespace, tenant_id, wallet_session_id),
  CHECK (lifecycle_kind IN ('issued', 'consumed')),
  CHECK (curve IN ('ecdsa', 'ed25519')),
  CHECK (json_valid(binding_json)),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (
    (lifecycle_kind = 'issued'
      AND token_hash IS NULL
      AND curve IS NOT NULL
      AND binding_json IS NOT NULL
      AND consumed_at_ms IS NULL)
    OR (lifecycle_kind = 'consumed'
      AND token_hash IS NOT NULL
      AND curve IS NOT NULL
      AND binding_json IS NOT NULL
      AND consumed_at_ms IS NOT NULL)
  )
);

CREATE INDEX idx_hosted_wallet_session_exchange_expiry
  ON hosted_wallet_session_exchange_codes(namespace, tenant_id, expires_at_ms);

CREATE TRIGGER hosted_wallet_session_exchange_mint_token
AFTER UPDATE OF lifecycle_kind ON hosted_wallet_session_exchange_codes
WHEN OLD.lifecycle_kind = 'issued' AND NEW.lifecycle_kind = 'consumed'
BEGIN
  INSERT INTO opaque_wallet_session_tokens (
    namespace,
    tenant_id,
    token_hash,
    curve,
    wallet_session_id,
    binding_json
  ) VALUES (
    NEW.namespace,
    NEW.tenant_id,
    NEW.token_hash,
    NEW.curve,
    NEW.wallet_session_id,
    NEW.binding_json
  );
END;

DROP TABLE verified_grant_evidence_sets;
DROP TABLE authorization_sessions;
DROP TABLE IF EXISTS app_session_versions;
DROP TABLE IF EXISTS google_email_otp_session_exchange_journals;
DROP TABLE ecdsa_authorization_atomic_guards;
DROP TABLE email_otp_recovery_wrapped_enrollment_escrows;

ALTER TABLE email_otp_challenges RENAME TO email_otp_challenges_r106;

CREATE TABLE email_otp_challenges (
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
      'wallet_email_otp_device_recovery'
    )
  ),
  CHECK (operation IN ('wallet_unlock', 'transaction_sign', 'export_key', 'registration')),
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

DROP TABLE email_otp_challenges_r106;

CREATE INDEX email_otp_challenges_context_idx
  ON email_otp_challenges (
    namespace, org_id, project_id, env_id, challenge_subject_id, wallet_id,
    record_org_id, otp_channel, owner_proof_binding_digest, action, operation,
    expires_at_ms, created_at_ms
  );
CREATE INDEX email_otp_challenges_expires_idx
  ON email_otp_challenges (namespace, org_id, project_id, env_id, expires_at_ms);

DROP TABLE email_otp_registration_attempts;

CREATE TABLE email_otp_registration_attempts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  email TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  state TEXT NOT NULL,
  owner_proof_binding_digest TEXT NOT NULL,
  runtime_org_id TEXT NOT NULL,
  runtime_policy_key TEXT NOT NULL,
  offer_wallet_ids_json TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, attempt_id),
  CHECK (length(attempt_id) > 0),
  CHECK (length(provider_subject) > 0),
  CHECK (length(email) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (state IN ('started', 'key_finalized', 'active', 'abandoned', 'failed', 'expired')),
  CHECK (length(owner_proof_binding_digest) > 0),
  CHECK (json_valid(offer_wallet_ids_json)),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'google_email_otp_registration_attempt_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.attemptId') = attempt_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.providerSubject') = provider_subject, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.email') = email, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.state') = state, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.ownerProofBindingDigest') = owner_proof_binding_digest, 0)),
  CHECK (runtime_org_id = '' OR COALESCE(json_extract(record_json, '$.runtimePolicyScope.orgId') = runtime_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

CREATE INDEX email_otp_registration_attempts_subject_idx
  ON email_otp_registration_attempts (
    namespace, org_id, project_id, env_id, provider_subject, email, state,
    expires_at_ms, owner_proof_binding_digest, runtime_org_id, runtime_policy_key,
    updated_at_ms
  );
CREATE INDEX email_otp_registration_attempts_wallet_idx
  ON email_otp_registration_attempts (
    namespace, org_id, project_id, env_id, wallet_id, state, expires_at_ms
  );
