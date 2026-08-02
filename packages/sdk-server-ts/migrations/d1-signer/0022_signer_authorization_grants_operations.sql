-- Refactor 90 Unit 3d: direct Wallet Session grants and replay-safe operations.
-- Historical capability-grant tables remain immutable. Current code writes only
-- these tables; no dual-schema reader or synthetic grant conversion is allowed.

CREATE TABLE IF NOT EXISTS authorization_grants (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorization_grant_ref TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, authorization_grant_ref),
  UNIQUE (namespace, tenant_id, authorization_id),
  UNIQUE (namespace, tenant_id, wallet_session_id),
  FOREIGN KEY (namespace, tenant_id, wallet_session_id)
    REFERENCES reusable_wallet_sessions(namespace, tenant_id, wallet_session_id),
  FOREIGN KEY (namespace, tenant_id, quota_id)
    REFERENCES authorization_wallet_session_quotas(namespace, tenant_id, quota_id),
  CHECK (revocation_epoch > 0),
  CHECK (lifecycle_kind IN ('active', 'revoked')),
  CHECK (expires_at_ms > created_at_ms)
);

CREATE INDEX IF NOT EXISTS idx_authorization_grants_active
  ON authorization_grants(namespace, tenant_id, principal_id, lifecycle_kind, expires_at_ms);

CREATE TABLE IF NOT EXISTS authorized_operations (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorized_operation_id TEXT NOT NULL,
  audit_event_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  capability_operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  authorization_kind TEXT NOT NULL,
  authorization_grant_ref TEXT,
  evidence_set_digest TEXT,
  authorization_grant_revocation_epoch INTEGER,
  wallet_session_id TEXT,
  quota_id TEXT,
  quota_kind TEXT NOT NULL,
  material_activation_id TEXT,
  lifecycle_kind TEXT NOT NULL,
  result_kind TEXT NOT NULL,
  result_digest TEXT,
  result_storage_ref TEXT,
  claimed_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  PRIMARY KEY (namespace, tenant_id, authorized_operation_id),
  UNIQUE (namespace, tenant_id, operation_fingerprint_digest),
  UNIQUE (namespace, tenant_id, audit_event_id),
  CHECK (authorization_kind IN ('authorization_grant', 'verified_step_up')),
  CHECK (quota_kind IN ('consume_reusable_wallet_session', 'quota_neutral')),
  CHECK (lifecycle_kind IN ('claimed', 'completed')),
  CHECK (
    (authorization_kind = 'authorization_grant'
      AND authorization_grant_ref IS NOT NULL
      AND evidence_set_digest IS NULL
      AND authorization_grant_revocation_epoch IS NOT NULL
      AND authorization_grant_revocation_epoch > 0
      AND wallet_session_id IS NOT NULL
      AND quota_id IS NOT NULL)
    OR (authorization_kind = 'verified_step_up'
      AND authorization_grant_ref IS NULL
      AND evidence_set_digest IS NOT NULL
      AND authorization_grant_revocation_epoch IS NULL
      AND wallet_session_id IS NULL
      AND quota_id IS NULL
      AND quota_kind = 'quota_neutral')
  ),
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

CREATE TABLE IF NOT EXISTS authorized_operation_audit_events (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  authorized_operation_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  capability_operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  authorization_kind TEXT NOT NULL,
  authorization_grant_ref TEXT,
  evidence_set_digest TEXT,
  result_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, event_id),
  UNIQUE (namespace, tenant_id, authorized_operation_id),
  CHECK (authorization_kind IN ('authorization_grant', 'verified_step_up')),
  CHECK (result_kind IN (
    'claimed',
    'succeeded',
    'failed_before_side_effect',
    'failed_after_side_effect'
  )),
  CHECK (
    (authorization_kind = 'authorization_grant'
      AND authorization_grant_ref IS NOT NULL
      AND evidence_set_digest IS NULL)
    OR (authorization_kind = 'verified_step_up'
      AND authorization_grant_ref IS NULL
      AND evidence_set_digest IS NOT NULL)
  )
);

CREATE TRIGGER authorized_operation_claim_validate
BEFORE INSERT ON authorized_operations
BEGIN
  SELECT CASE
    WHEN NEW.authorization_kind = 'authorization_grant'
      AND NOT EXISTS (
        SELECT 1
          FROM authorization_grants AS grant_record
         WHERE grant_record.namespace = NEW.namespace
           AND grant_record.tenant_id = NEW.tenant_id
           AND grant_record.authorization_grant_ref = NEW.authorization_grant_ref
           AND grant_record.principal_id = NEW.principal_id
           AND grant_record.wallet_session_id = NEW.wallet_session_id
           AND grant_record.quota_id = NEW.quota_id
           AND grant_record.revocation_epoch = NEW.authorization_grant_revocation_epoch
           AND grant_record.lifecycle_kind = 'active'
           AND grant_record.expires_at_ms > NEW.claimed_at_ms
      )
    THEN RAISE(ABORT, 'authorization_grant_rejected')
  END;

  SELECT CASE
    WHEN NEW.authorization_kind = 'verified_step_up'
      AND NOT EXISTS (
        SELECT 1
          FROM verified_grant_evidence_sets AS evidence
         WHERE evidence.namespace = NEW.namespace
           AND evidence.tenant_id = NEW.tenant_id
           AND evidence.principal_id = NEW.principal_id
           AND evidence.evidence_set_digest = NEW.evidence_set_digest
           AND evidence.capability_kind = NEW.capability_kind
           AND evidence.operation_kind = NEW.operation_kind
           AND evidence.lane_digest = NEW.lane_digest
           AND evidence.intent_digest = NEW.intent_digest
           AND evidence.display_digest = NEW.display_digest
           AND evidence.expires_at_ms >= NEW.claimed_at_ms
      )
    THEN RAISE(ABORT, 'verified_step_up_rejected')
  END;
END;

CREATE TRIGGER authorized_operation_claim_quota_and_audit
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
BEGIN
  UPDATE authorization_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.authorization_kind = 'authorization_grant'
     AND NEW.quota_kind = 'consume_reusable_wallet_session'
     AND namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND quota_id = NEW.quota_id
     AND wallet_session_id = NEW.wallet_session_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.authorization_kind = 'authorization_grant'
      AND NEW.quota_kind = 'consume_reusable_wallet_session'
      AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;

  INSERT INTO authorized_operation_audit_events (
    namespace,
    tenant_id,
    event_id,
    authorized_operation_id,
    principal_id,
    capability_id,
    capability_kind,
    operation_kind,
    capability_operation_id,
    operation_fingerprint_digest,
    authorization_kind,
    authorization_grant_ref,
    evidence_set_digest,
    result_kind,
    created_at_ms
  ) VALUES (
    NEW.namespace,
    NEW.tenant_id,
    NEW.audit_event_id,
    NEW.authorized_operation_id,
    NEW.principal_id,
    NEW.capability_id,
    NEW.capability_kind,
    NEW.operation_kind,
    NEW.capability_operation_id,
    NEW.operation_fingerprint_digest,
    NEW.authorization_kind,
    NEW.authorization_grant_ref,
    NEW.evidence_set_digest,
    'claimed',
    NEW.claimed_at_ms
  );
END;

CREATE TRIGGER authorized_operation_complete_audit
AFTER UPDATE OF lifecycle_kind ON authorized_operations
WHEN OLD.lifecycle_kind = 'claimed' AND NEW.lifecycle_kind = 'completed'
BEGIN
  UPDATE authorized_operation_audit_events
     SET result_kind = NEW.result_kind
   WHERE namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND event_id = NEW.audit_event_id
     AND authorized_operation_id = NEW.authorized_operation_id
     AND result_kind = 'claimed';

  SELECT CASE
    WHEN changes() != 1 THEN RAISE(ABORT, 'authorization_audit_completion_rejected')
  END;
END;
