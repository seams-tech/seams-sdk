CREATE TABLE IF NOT EXISTS authorization_operation_fingerprints (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  use_id TEXT NOT NULL,
  authorization_kind TEXT NOT NULL,
  PRIMARY KEY (namespace, tenant_id, operation_fingerprint_digest),
  UNIQUE (namespace, tenant_id, use_id),
  CHECK (authorization_kind IN ('reusable_wallet_session', 'operation_step_up'))
);

INSERT INTO authorization_operation_fingerprints (
  namespace,
  tenant_id,
  operation_fingerprint_digest,
  use_id,
  authorization_kind
)
SELECT
  namespace,
  tenant_id,
  operation_fingerprint_digest,
  use_id,
  authorization_kind
FROM capability_grant_uses;

CREATE TRIGGER capability_grant_use_reserve_operation_fingerprint
BEFORE INSERT ON capability_grant_uses
BEGIN
  INSERT INTO authorization_operation_fingerprints (
    namespace,
    tenant_id,
    operation_fingerprint_digest,
    use_id,
    authorization_kind
  ) VALUES (
    NEW.namespace,
    NEW.tenant_id,
    NEW.operation_fingerprint_digest,
    NEW.use_id,
    NEW.authorization_kind
  );
END;

CREATE TABLE IF NOT EXISTS reusable_wallet_session_operation_uses (
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
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  quota_kind TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  result_kind TEXT NOT NULL,
  result_digest TEXT,
  result_storage_ref TEXT,
  claimed_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  PRIMARY KEY (namespace, tenant_id, use_id),
  UNIQUE (namespace, tenant_id, operation_fingerprint_digest),
  FOREIGN KEY (namespace, tenant_id, wallet_session_id)
    REFERENCES reusable_wallet_sessions(namespace, tenant_id, wallet_session_id),
  FOREIGN KEY (namespace, tenant_id, quota_id)
    REFERENCES authorization_wallet_session_quotas(namespace, tenant_id, quota_id),
  CHECK (quota_kind IN ('consume_reusable_wallet_session', 'quota_neutral')),
  CHECK (
    (quota_kind = 'consume_reusable_wallet_session'
      AND operation_kind NOT IN ('near.export_key', 'evm.export_key')
      AND capability_kind != 'vault_access')
    OR (quota_kind = 'quota_neutral'
      AND (
        operation_kind IN ('near.export_key', 'evm.export_key')
        OR capability_kind = 'vault_access'
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

CREATE TABLE IF NOT EXISTS reusable_wallet_session_operation_audit_events (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  use_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  evidence_set_digest TEXT NOT NULL,
  result_kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, tenant_id, event_id),
  UNIQUE (namespace, tenant_id, use_id),
  FOREIGN KEY (namespace, tenant_id, wallet_session_id)
    REFERENCES reusable_wallet_sessions(namespace, tenant_id, wallet_session_id),
  CHECK (result_kind IN (
    'claimed',
    'succeeded',
    'failed_before_side_effect',
    'failed_after_side_effect'
  ))
);

CREATE TRIGGER reusable_wallet_session_operation_use_claim_atomic
AFTER INSERT ON reusable_wallet_session_operation_uses
WHEN NEW.lifecycle_kind = 'claimed'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
        FROM reusable_wallet_sessions AS session
       WHERE session.namespace = NEW.namespace
         AND session.tenant_id = NEW.tenant_id
         AND session.wallet_session_id = NEW.wallet_session_id
         AND session.quota_id = NEW.quota_id
         AND session.principal_id = NEW.principal_id
         AND session.lifecycle_kind = 'active'
         AND session.expires_at_ms > NEW.claimed_at_ms
    ) THEN RAISE(ABORT, 'authorization_wallet_session_rejected')
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

  INSERT INTO reusable_wallet_session_operation_audit_events (
    namespace,
    tenant_id,
    event_id,
    principal_id,
    wallet_session_id,
    grant_id,
    use_id,
    capability_id,
    capability_kind,
    operation_kind,
    operation_id,
    operation_fingerprint_digest,
    evidence_set_digest,
    result_kind,
    created_at_ms
  ) VALUES (
    NEW.namespace,
    NEW.tenant_id,
    NEW.audit_event_id,
    NEW.principal_id,
    NEW.wallet_session_id,
    NEW.grant_id,
    NEW.use_id,
    NEW.capability_id,
    NEW.capability_kind,
    NEW.operation_kind,
    NEW.operation_id,
    NEW.operation_fingerprint_digest,
    NEW.evidence_set_digest,
    'claimed',
    NEW.claimed_at_ms
  );
END;

CREATE TRIGGER reusable_wallet_session_operation_use_complete_atomic
AFTER UPDATE OF lifecycle_kind ON reusable_wallet_session_operation_uses
WHEN OLD.lifecycle_kind = 'claimed' AND NEW.lifecycle_kind = 'completed'
BEGIN
  UPDATE reusable_wallet_session_operation_audit_events
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

CREATE TRIGGER reusable_wallet_session_operation_reserve_fingerprint
BEFORE INSERT ON reusable_wallet_session_operation_uses
BEGIN
  INSERT INTO authorization_operation_fingerprints (
    namespace,
    tenant_id,
    operation_fingerprint_digest,
    use_id,
    authorization_kind
  ) VALUES (
    NEW.namespace,
    NEW.tenant_id,
    NEW.operation_fingerprint_digest,
    NEW.use_id,
    'reusable_wallet_session'
  );
END;
