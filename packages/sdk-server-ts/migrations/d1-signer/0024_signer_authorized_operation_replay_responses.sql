-- Replace the opaque result-storage pointer with a bounded replay response.
-- Legacy completed rows are terminalized as an explicit unavailable response;
-- they are never re-executed and remain auditable.

DROP TRIGGER IF EXISTS authorized_operation_claim_atomic;
DROP TRIGGER IF EXISTS authorized_operation_complete_atomic;
DROP TRIGGER IF EXISTS authorized_operation_audit_complete;

CREATE TABLE authorized_operations_replay_v2 (
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
  result_status INTEGER,
  result_content_type TEXT,
  result_body_text TEXT,
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
      AND result_status IS NULL
      AND result_content_type IS NULL
      AND result_body_text IS NULL
      AND completed_at_ms IS NULL)
    OR (lifecycle_kind = 'completed'
      AND result_kind IN ('succeeded', 'failed_before_side_effect', 'failed_after_side_effect')
      AND result_digest IS NOT NULL
      AND result_status BETWEEN 100 AND 599
      AND result_content_type IS NOT NULL
      AND trim(result_content_type) = result_content_type
      AND length(result_content_type) BETWEEN 1 AND 255
      AND result_body_text IS NOT NULL
      AND length(CAST(result_body_text AS BLOB)) <= 65536
      AND completed_at_ms IS NOT NULL)
  )
);

INSERT INTO authorized_operations_replay_v2 (
  namespace, tenant_id, authorized_operation_id, audit_event_id,
  principal_id, capability_id, capability_kind, operation_kind, operation_id,
  operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
  authorization_source_kind, authorization_id, evidence_set_digest,
  quota_id, quota_kind, lifecycle_kind, result_kind, result_digest,
  result_status, result_content_type, result_body_text,
  claimed_at_ms, completed_at_ms, material_activation_id
)
SELECT
  namespace, tenant_id, authorized_operation_id, audit_event_id,
  principal_id, capability_id, capability_kind, operation_kind, operation_id,
  operation_fingerprint_digest, lane_digest, intent_digest, display_digest,
  authorization_source_kind, authorization_id, evidence_set_digest,
  quota_id, quota_kind, lifecycle_kind, result_kind,
  CASE
    WHEN lifecycle_kind = 'completed' THEN
      'JmoybW-NRuNmWfZ7E74g9Ak4x8vSmSSBITDMlZIX8pY'
    ELSE NULL
  END,
  CASE WHEN lifecycle_kind = 'completed' THEN 409 ELSE NULL END,
  CASE WHEN lifecycle_kind = 'completed' THEN 'application/json' ELSE NULL END,
  CASE
    WHEN lifecycle_kind = 'completed' THEN '{"code":"legacy_result_unavailable"}'
    ELSE NULL
  END,
  claimed_at_ms, completed_at_ms, material_activation_id
FROM authorized_operations;

DROP TABLE authorized_operations;
ALTER TABLE authorized_operations_replay_v2 RENAME TO authorized_operations;

CREATE INDEX authorized_operations_tenant_fingerprint_idx
  ON authorized_operations(namespace, tenant_id, operation_fingerprint_digest);

CREATE INDEX authorized_operations_tenant_lifecycle_idx
  ON authorized_operations(namespace, tenant_id, lifecycle_kind);

CREATE TRIGGER authorized_operation_claim_atomic
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
           AND session.authorization_id = NEW.authorization_id
           AND session.principal_id = NEW.principal_id
           AND (NEW.quota_kind = 'quota_neutral' OR session.quota_id = NEW.quota_id)
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
           AND session.principal_id = evidence.principal_id
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
     AND wallet_session_id = (
       SELECT session.wallet_session_id
         FROM reusable_wallet_sessions AS session
        WHERE session.namespace = NEW.namespace
          AND session.tenant_id = NEW.tenant_id
          AND session.authorization_id = NEW.authorization_id
          AND session.quota_id = NEW.quota_id
     )
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;

  INSERT INTO authorized_operation_audit_events (
    namespace, tenant_id, audit_event_id, authorized_operation_id,
    operation_fingerprint_digest, authorization_source_kind, authorization_id,
    evidence_set_digest, quota_id, material_activation_id, result_kind,
    claimed_at_ms, completed_at_ms
  ) VALUES (
    NEW.namespace, NEW.tenant_id, NEW.audit_event_id, NEW.authorized_operation_id,
    NEW.operation_fingerprint_digest, NEW.authorization_source_kind, NEW.authorization_id,
    NEW.evidence_set_digest, NEW.quota_id, NEW.material_activation_id, NEW.result_kind,
    NEW.claimed_at_ms, NEW.completed_at_ms
  );
END;

CREATE TRIGGER authorized_operation_complete_atomic
BEFORE UPDATE OF lifecycle_kind ON authorized_operations
WHEN OLD.lifecycle_kind = 'completed' OR NEW.lifecycle_kind != 'completed'
BEGIN
  SELECT RAISE(ABORT, 'authorized_operation_lifecycle_transition_rejected');
END;

CREATE TRIGGER authorized_operation_audit_complete
AFTER UPDATE OF lifecycle_kind ON authorized_operations
WHEN OLD.lifecycle_kind = 'claimed' AND NEW.lifecycle_kind = 'completed'
BEGIN
  UPDATE authorized_operation_audit_events
     SET result_kind = NEW.result_kind,
         completed_at_ms = NEW.completed_at_ms
   WHERE namespace = NEW.namespace
     AND tenant_id = NEW.tenant_id
     AND authorized_operation_id = NEW.authorized_operation_id;

  SELECT CASE
    WHEN changes() != 1
    THEN RAISE(ABORT, 'authorized_operation_audit_completion_rejected')
  END;
END;
