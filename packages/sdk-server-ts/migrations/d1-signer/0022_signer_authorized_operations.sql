-- Refactor 90: copy operation claims into the single current operation table.
-- The follow-up runtime cutover removes the legacy source tables at the same
-- persistence boundary after this copy has been verified.
CREATE TABLE IF NOT EXISTS authorized_operations (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorized_operation_id TEXT NOT NULL,
  audit_event_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  capability_kind TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  lane_digest TEXT NOT NULL,
  intent_digest TEXT NOT NULL,
  display_digest TEXT NOT NULL,
  authorization_source_kind TEXT NOT NULL,
  authorization_id TEXT,
  evidence_set_digest TEXT,
  quota_id TEXT,
  quota_kind TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  result_kind TEXT NOT NULL,
  result_digest TEXT,
  result_storage_ref TEXT,
  claimed_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  material_activation_id TEXT,
  PRIMARY KEY (namespace, tenant_id, authorized_operation_id),
  UNIQUE (namespace, tenant_id, operation_fingerprint_digest),
  CHECK (authorization_source_kind IN ('authorization_grant', 'verified_step_up')),
  CHECK (
    (authorization_source_kind = 'authorization_grant'
      AND authorization_id IS NOT NULL
      AND evidence_set_digest IS NULL)
    OR (authorization_source_kind = 'verified_step_up'
      AND authorization_id IS NULL
      AND evidence_set_digest IS NOT NULL)
  ),
  CHECK (quota_kind IN ('consume_reusable_wallet_session', 'quota_neutral')),
  CHECK (
    (quota_kind = 'consume_reusable_wallet_session'
      AND authorization_source_kind = 'authorization_grant'
      AND operation_kind NOT IN ('near.export_key', 'evm.export_key')
      AND capability_kind != 'vault_access')
    OR (quota_kind = 'quota_neutral'
      AND (
        operation_kind IN ('near.export_key', 'evm.export_key')
        OR capability_kind = 'vault_access'
        OR authorization_source_kind = 'verified_step_up'
      ))
  ),
  CHECK (
    (quota_kind = 'consume_reusable_wallet_session' AND quota_id IS NOT NULL)
    OR (quota_kind = 'quota_neutral' AND quota_id IS NULL)
  ),
  CHECK (lifecycle_kind IN ('claimed', 'completed')),
  CHECK (
    (lifecycle_kind = 'claimed'
      AND result_kind = 'pending'
      AND result_digest IS NULL
      AND result_storage_ref IS NULL
      AND completed_at_ms IS NULL)
    OR (lifecycle_kind = 'completed'
      AND result_kind IN ('succeeded', 'failed_before_side_effect', 'failed_after_side_effect')
      AND result_digest IS NOT NULL
      AND result_storage_ref IS NOT NULL
      AND completed_at_ms IS NOT NULL)
  )
);

INSERT INTO authorized_operations (
  namespace, tenant_id, authorized_operation_id, audit_event_id,
  principal_id, capability_id, capability_kind, operation_kind, operation_id,
  operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
  authorization_source_kind, authorization_id, evidence_set_digest,
  quota_id, quota_kind, lifecycle_kind, result_kind, result_digest,
  result_storage_ref, claimed_at_ms, completed_at_ms, material_activation_id
)
SELECT
  namespace, tenant_id, use_id, audit_event_id,
  principal_id, capability_id, capability_kind, operation_kind, operation_id,
  operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
  'authorization_grant', wallet_session_id, NULL,
  CASE WHEN quota_kind = 'consume_reusable_wallet_session' THEN quota_id ELSE NULL END,
  quota_kind, lifecycle_kind, result_kind, result_digest,
  result_storage_ref, claimed_at_ms, completed_at_ms, material_activation_id
FROM reusable_wallet_session_operation_uses;

INSERT INTO authorized_operations (
  namespace, tenant_id, authorized_operation_id, audit_event_id,
  principal_id, capability_id, capability_kind, operation_kind, operation_id,
  operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
  authorization_source_kind, authorization_id, evidence_set_digest,
  quota_id, quota_kind, lifecycle_kind, result_kind, result_digest,
  result_storage_ref, claimed_at_ms, completed_at_ms, material_activation_id
)
SELECT
  namespace, tenant_id, use_id, audit_event_id,
  principal_id, capability_id, capability_kind, operation_kind, operation_id,
  operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
  CASE authorization_kind
    WHEN 'reusable_wallet_session' THEN 'authorization_grant'
    ELSE 'verified_step_up'
  END,
  CASE authorization_kind WHEN 'reusable_wallet_session' THEN wallet_session_id ELSE NULL END,
  CASE authorization_kind WHEN 'operation_step_up' THEN evidence_set_digest ELSE NULL END,
  CASE
    WHEN authorization_kind = 'reusable_wallet_session'
      AND quota_kind = 'consume_reusable_wallet_session'
    THEN quota_id
    ELSE NULL
  END,
  CASE WHEN authorization_kind = 'reusable_wallet_session' THEN quota_kind ELSE 'quota_neutral' END,
  lifecycle_kind, result_kind, result_digest,
  result_storage_ref, claimed_at_ms, completed_at_ms, material_activation_id
FROM capability_grant_uses;

CREATE INDEX IF NOT EXISTS authorized_operations_tenant_fingerprint_idx
  ON authorized_operations(namespace, tenant_id, operation_fingerprint_digest);

CREATE INDEX IF NOT EXISTS authorized_operations_tenant_lifecycle_idx
  ON authorized_operations(namespace, tenant_id, lifecycle_kind);

-- Admission is one SQLite transaction: the insert, source validation, and
-- reusable-session quota decrement either all commit or all roll back.
CREATE TRIGGER IF NOT EXISTS authorized_operation_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
BEGIN
  SELECT CASE
    WHEN NEW.authorization_source_kind = 'authorization_grant'
      AND NOT EXISTS (
        SELECT 1
          FROM reusable_wallet_sessions AS session
         WHERE session.namespace = NEW.namespace
           AND session.tenant_id = NEW.tenant_id
           AND session.wallet_session_id = NEW.authorization_id
           AND session.principal_id = NEW.principal_id
           AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms > NEW.claimed_at_ms
      )
    THEN RAISE(ABORT, 'authorization_wallet_session_rejected')
  END;

  SELECT CASE
    WHEN NEW.authorization_source_kind = 'verified_step_up'
      AND NOT EXISTS (
        SELECT 1
          FROM verified_grant_evidence_sets AS evidence
          JOIN authorization_sessions AS session
            ON session.namespace = evidence.namespace
           AND session.tenant_id = evidence.tenant_id
           AND session.session_id = evidence.session_id
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
           AND session.lifecycle_kind = 'active'
           AND session.expires_at_ms > NEW.claimed_at_ms
      )
    THEN RAISE(ABORT, 'authorization_evidence_claim_rejected')
  END;

  UPDATE authorization_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.authorization_source_kind = 'authorization_grant'
     AND NEW.quota_kind = 'consume_reusable_wallet_session'
     AND namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND quota_id = NEW.quota_id
     AND wallet_session_id = NEW.authorization_id
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;
END;

CREATE TRIGGER IF NOT EXISTS authorized_operation_complete_atomic
BEFORE UPDATE OF lifecycle_kind ON authorized_operations
WHEN OLD.lifecycle_kind = 'completed' OR NEW.lifecycle_kind != 'completed'
BEGIN
  SELECT RAISE(ABORT, 'authorized_operation_lifecycle_transition_rejected');
END;

CREATE TABLE authorized_operation_migration_guard (
  verified INTEGER NOT NULL CHECK (verified = 1)
);

INSERT INTO authorized_operation_migration_guard (verified)
SELECT CASE
  WHEN EXISTS (
    SELECT 1
      FROM reusable_wallet_session_operation_uses AS source
     WHERE NOT EXISTS (
       SELECT 1
         FROM authorized_operations AS operation
        WHERE operation.namespace = source.namespace
          AND operation.tenant_id = source.tenant_id
          AND operation.authorized_operation_id = source.use_id
          AND operation.operation_fingerprint_digest = source.operation_fingerprint_digest
          AND operation.authorization_source_kind = 'authorization_grant'
          AND operation.authorization_id = source.wallet_session_id
     )
  ) OR EXISTS (
    SELECT 1
      FROM capability_grant_uses AS source
     WHERE NOT EXISTS (
       SELECT 1
         FROM authorized_operations AS operation
        WHERE operation.namespace = source.namespace
          AND operation.tenant_id = source.tenant_id
          AND operation.authorized_operation_id = source.use_id
          AND operation.operation_fingerprint_digest = source.operation_fingerprint_digest
          AND operation.authorization_source_kind = CASE source.authorization_kind
            WHEN 'reusable_wallet_session' THEN 'authorization_grant'
            ELSE 'verified_step_up'
          END
     )
  ) THEN 0
  ELSE 1
END;

DROP TABLE authorized_operation_migration_guard;

DROP TRIGGER IF EXISTS capability_grant_use_claim_atomic;
DROP TRIGGER IF EXISTS capability_grant_use_complete_atomic;
DROP TRIGGER IF EXISTS capability_grant_exact_operation_insert;
DROP TRIGGER IF EXISTS authorization_audit_exact_operation;
DROP TRIGGER IF EXISTS capability_grant_use_exact_operation;
DROP TRIGGER IF EXISTS capability_grant_use_reserve_operation_fingerprint;
DROP TRIGGER IF EXISTS reusable_wallet_session_operation_use_claim_atomic;
DROP TRIGGER IF EXISTS reusable_wallet_session_operation_use_complete_atomic;
DROP TRIGGER IF EXISTS reusable_wallet_session_operation_reserve_fingerprint;

DROP TABLE authorization_audit_events;
DROP TABLE reusable_wallet_session_operation_audit_events;
DROP TABLE reusable_wallet_session_operation_uses;
DROP TABLE capability_grant_uses;
DROP TABLE capability_grants;
DROP TABLE authorization_operation_fingerprints;
