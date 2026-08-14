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
  UNIQUE (namespace, tenant_id, wallet_session_id),
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
  CHECK (curve IS NULL OR curve IN ('ecdsa', 'ed25519')),
  CHECK (binding_json IS NULL OR json_valid(binding_json)),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (
    (lifecycle_kind = 'issued'
      AND token_hash IS NULL
      AND curve IS NULL
      AND binding_json IS NULL
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
DROP TABLE ecdsa_authorization_atomic_guards;
DROP TABLE email_otp_recovery_wrapped_enrollment_escrows;
