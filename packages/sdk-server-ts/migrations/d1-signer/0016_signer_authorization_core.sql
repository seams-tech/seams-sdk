CREATE TABLE IF NOT EXISTS authorization_sessions (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  assurance TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, session_id),
  CHECK (assurance IN ('session', 'step_up')),
  CHECK (lifecycle_kind = 'active'),
  CHECK (expires_at_ms > created_at_ms)
);

CREATE TABLE IF NOT EXISTS verified_grant_evidence_sets (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  evidence_set_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  evidence_set_digest TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  assurance TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, evidence_set_id),
  FOREIGN KEY (namespace, tenant_id, session_id)
    REFERENCES authorization_sessions(namespace, tenant_id, session_id),
  CHECK (json_valid(evidence_json)),
  CHECK (assurance IN ('session', 'step_up')),
  CHECK (
    (capability_kind = 'vault_access'
      AND operation_kind IN ('vault.proxy_use', 'vault.reveal'))
    OR (capability_kind = 'near_ed25519_mpc_signing'
      AND operation_kind IN (
        'near.sign_transaction',
        'near.sign_delegate_action',
        'near.sign_nep413_message',
        'near.export_key'
      ))
    OR (capability_kind = 'evm_ecdsa_mpc_signing'
      AND operation_kind IN ('evm.sign_transaction', 'evm.export_key'))
  )
);

CREATE TABLE IF NOT EXISTS authorization_wallet_session_quotas (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  remaining_uses INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, quota_id),
  UNIQUE (namespace, tenant_id, wallet_session_id),
  CHECK (remaining_uses >= 0),
  CHECK (lifecycle_kind IN ('active', 'exhausted')),
  CHECK (
    (lifecycle_kind = 'active' AND remaining_uses > 0)
    OR (lifecycle_kind = 'exhausted' AND remaining_uses = 0)
  )
);

CREATE TABLE IF NOT EXISTS capability_grants (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  binding_id TEXT NOT NULL,
  evidence_set_id TEXT NOT NULL,
  evidence_set_digest TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  authority_kind TEXT NOT NULL,
  wallet_session_id TEXT,
  quota_id TEXT,
  remaining_uses INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  PRIMARY KEY (namespace, tenant_id, grant_id),
  FOREIGN KEY (namespace, tenant_id, evidence_set_id)
    REFERENCES verified_grant_evidence_sets(namespace, tenant_id, evidence_set_id),
  CHECK (authority_kind IN ('reusable_wallet_session', 'operation_step_up')),
  CHECK (
    (authority_kind = 'reusable_wallet_session'
      AND wallet_session_id IS NOT NULL
      AND quota_id IS NOT NULL)
    OR (authority_kind = 'operation_step_up'
      AND wallet_session_id IS NULL
      AND quota_id IS NULL
      AND remaining_uses IN (0, 1))
  ),
  CHECK (remaining_uses >= 0),
  CHECK (lifecycle_kind IN ('active', 'consumed')),
  CHECK (
    (lifecycle_kind = 'active' AND remaining_uses > 0 AND consumed_at_ms IS NULL)
    OR (lifecycle_kind = 'consumed' AND remaining_uses = 0 AND consumed_at_ms IS NOT NULL)
  ),
  CHECK (
    (capability_kind = 'vault_access'
      AND operation_kind IN ('vault.proxy_use', 'vault.reveal'))
    OR (capability_kind = 'near_ed25519_mpc_signing'
      AND operation_kind IN (
        'near.sign_transaction',
        'near.sign_delegate_action',
        'near.sign_nep413_message',
        'near.export_key'
      ))
    OR (capability_kind = 'evm_ecdsa_mpc_signing'
      AND operation_kind IN ('evm.sign_transaction', 'evm.export_key'))
  )
);

CREATE TABLE IF NOT EXISTS capability_grant_uses (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  use_id TEXT NOT NULL,
  audit_event_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  evidence_set_digest TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  authorization_kind TEXT NOT NULL,
  wallet_session_id TEXT,
  quota_id TEXT,
  quota_kind TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  result_kind TEXT NOT NULL,
  result_digest TEXT,
  result_storage_ref TEXT,
  claimed_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  PRIMARY KEY (namespace, tenant_id, use_id),
  UNIQUE (namespace, tenant_id, operation_fingerprint_digest),
  FOREIGN KEY (namespace, tenant_id, grant_id)
    REFERENCES capability_grants(namespace, tenant_id, grant_id),
  CHECK (authorization_kind IN ('reusable_wallet_session', 'operation_step_up')),
  CHECK (quota_kind IN ('consume_reusable_wallet_session', 'quota_neutral')),
  CHECK (
    (authorization_kind = 'reusable_wallet_session'
      AND wallet_session_id IS NOT NULL
      AND quota_id IS NOT NULL)
    OR (authorization_kind = 'operation_step_up'
      AND wallet_session_id IS NULL
      AND quota_id IS NULL
      AND quota_kind = 'quota_neutral')
  ),
  CHECK (
    (quota_kind = 'consume_reusable_wallet_session'
      AND operation_kind NOT IN ('near.export_key', 'evm.export_key')
      AND capability_kind != 'vault_access')
    OR (quota_kind = 'quota_neutral'
      AND (
        operation_kind IN ('near.export_key', 'evm.export_key')
        OR capability_kind = 'vault_access'
        OR authorization_kind = 'operation_step_up'
      ))
  ),
  CHECK (lifecycle_kind IN ('claimed', 'completed')),
  CHECK (
    (lifecycle_kind = 'claimed'
      AND result_kind = 'pending'
      AND result_digest IS NULL
      AND result_storage_ref IS NULL
      AND completed_at_ms IS NULL)
    OR (lifecycle_kind = 'completed'
      AND result_kind IN (
        'succeeded',
        'failed_before_side_effect',
        'failed_after_side_effect'
      )
      AND result_digest IS NOT NULL
      AND result_storage_ref IS NOT NULL
      AND completed_at_ms IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS authorization_audit_events (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  use_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  evidence_set_digest TEXT NOT NULL,
  result_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, event_id),
  UNIQUE (namespace, tenant_id, use_id),
  CHECK (result_kind IN (
    'claimed',
    'succeeded',
    'failed_before_side_effect',
    'failed_after_side_effect'
  ))
);

CREATE TRIGGER IF NOT EXISTS capability_grant_use_claim_atomic
AFTER INSERT ON capability_grant_uses
WHEN NEW.lifecycle_kind = 'claimed'
BEGIN
  UPDATE capability_grants
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'consumed' ELSE 'active' END,
         consumed_at_ms = CASE WHEN remaining_uses = 1 THEN NEW.claimed_at_ms ELSE NULL END
   WHERE namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND grant_id = NEW.grant_id
     AND principal_id = NEW.principal_id
     AND capability_id = NEW.capability_id
     AND capability_kind = NEW.capability_kind
     AND operation_kind = NEW.operation_kind
     AND evidence_set_digest = NEW.evidence_set_digest
     AND lane_digest = NEW.lane_digest
     AND intent_digest = NEW.intent_digest
     AND display_digest = NEW.display_digest
     AND authority_kind = NEW.authorization_kind
     AND COALESCE(wallet_session_id, '') = COALESCE(NEW.wallet_session_id, '')
     AND COALESCE(quota_id, '') = COALESCE(NEW.quota_id, '')
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN changes() != 1 THEN RAISE(ABORT, 'authorization_grant_claim_rejected')
  END;

  UPDATE authorization_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.quota_kind = 'consume_reusable_wallet_session'
     AND namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND quota_id = NEW.quota_id
     AND wallet_session_id = NEW.wallet_session_id
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
      THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;

  INSERT INTO authorization_audit_events (
    namespace,
    tenant_id,
    event_id,
    principal_id,
    session_id,
    device_id,
    grant_id,
    use_id,
    capability_id,
    capability_kind,
    operation_kind,
    operation_fingerprint_digest,
    evidence_set_digest,
    result_kind,
    created_at_ms
  )
  SELECT
    NEW.namespace,
    NEW.tenant_id,
    NEW.audit_event_id,
    NEW.principal_id,
    evidence.session_id,
    evidence.device_id,
    NEW.grant_id,
    NEW.use_id,
    NEW.capability_id,
    NEW.capability_kind,
    NEW.operation_kind,
    NEW.operation_fingerprint_digest,
    NEW.evidence_set_digest,
    'claimed',
    NEW.claimed_at_ms
  FROM verified_grant_evidence_sets AS evidence
  JOIN capability_grants AS grant
    ON grant.namespace = NEW.namespace
   AND grant.tenant_id = NEW.tenant_id
   AND grant.grant_id = NEW.grant_id
   AND grant.evidence_set_id = evidence.evidence_set_id
  WHERE evidence.namespace = NEW.namespace
    AND evidence.tenant_id = NEW.tenant_id
    AND evidence.evidence_set_digest = NEW.evidence_set_digest
    AND evidence.principal_id = NEW.principal_id
    AND evidence.capability_kind = NEW.capability_kind
    AND evidence.operation_kind = NEW.operation_kind
    AND evidence.lane_digest = NEW.lane_digest
    AND evidence.intent_digest = NEW.intent_digest
    AND evidence.display_digest = NEW.display_digest
    AND evidence.expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN changes() != 1 THEN RAISE(ABORT, 'authorization_evidence_claim_rejected')
  END;
END;

CREATE TRIGGER IF NOT EXISTS capability_grant_use_complete_atomic
AFTER UPDATE OF lifecycle_kind ON capability_grant_uses
WHEN OLD.lifecycle_kind = 'claimed' AND NEW.lifecycle_kind = 'completed'
BEGIN
  UPDATE authorization_audit_events
     SET result_kind = NEW.result_kind
   WHERE namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND event_id = NEW.audit_event_id
     AND use_id = NEW.use_id
     AND result_kind = 'claimed';

  SELECT CASE
    WHEN changes() != 1 THEN RAISE(ABORT, 'authorization_audit_completion_rejected')
  END;
END;

CREATE INDEX IF NOT EXISTS idx_authorization_sessions_expiry
  ON authorization_sessions(namespace, tenant_id, expires_at_ms);

CREATE INDEX IF NOT EXISTS idx_verified_grant_evidence_sets_expiry
  ON verified_grant_evidence_sets(namespace, tenant_id, expires_at_ms);

CREATE INDEX IF NOT EXISTS idx_capability_grants_expiry
  ON capability_grants(namespace, tenant_id, expires_at_ms);
