-- Refactor 90: separate reusable authorization identity from Wallet Session
-- identity and restore durable audit linkage for authorized operations.
ALTER TABLE reusable_wallet_sessions
  ADD COLUMN authorization_id TEXT;

-- Existing rows crossed the old persistence boundary with one aliased value.
-- Assign a distinct boundary-only authorization identity during the cutover.
UPDATE reusable_wallet_sessions
   SET authorization_id = 'wsa_migrated_' || wallet_session_id
 WHERE authorization_id IS NULL;

CREATE UNIQUE INDEX reusable_wallet_sessions_authorization_idx
  ON reusable_wallet_sessions(namespace, tenant_id, authorization_id);

CREATE TRIGGER reusable_wallet_session_authorization_identity_insert
BEFORE INSERT ON reusable_wallet_sessions
WHEN NEW.authorization_id IS NULL
  OR trim(NEW.authorization_id) = ''
  OR NEW.authorization_id = NEW.wallet_session_id
  OR NEW.authorization_id = NEW.quota_id
  OR NEW.wallet_session_id = NEW.quota_id
BEGIN
  SELECT RAISE(ABORT, 'reusable_wallet_session_authorization_identity_rejected');
END;

CREATE TRIGGER reusable_wallet_session_authorization_identity_update
BEFORE UPDATE OF authorization_id, wallet_session_id ON reusable_wallet_sessions
WHEN NEW.authorization_id IS NULL
  OR trim(NEW.authorization_id) = ''
  OR NEW.authorization_id = NEW.wallet_session_id
  OR NEW.authorization_id = NEW.quota_id
  OR NEW.wallet_session_id = NEW.quota_id
BEGIN
  SELECT RAISE(ABORT, 'reusable_wallet_session_authorization_identity_rejected');
END;

UPDATE authorized_operations
   SET authorization_id = (
     SELECT session.authorization_id
       FROM reusable_wallet_sessions AS session
      WHERE session.namespace = authorized_operations.namespace
        AND session.tenant_id = authorized_operations.tenant_id
        AND session.wallet_session_id = authorized_operations.authorization_id
   )
 WHERE authorization_source_kind = 'authorization_grant';

CREATE TABLE authorized_operation_audit_events (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  audit_event_id TEXT NOT NULL,
  authorized_operation_id TEXT NOT NULL,
  operation_fingerprint_digest TEXT NOT NULL,
  authorization_source_kind TEXT NOT NULL,
  authorization_id TEXT,
  evidence_set_digest TEXT,
  quota_id TEXT,
  material_activation_id TEXT,
  result_kind TEXT NOT NULL,
  claimed_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  PRIMARY KEY (namespace, tenant_id, audit_event_id),
  UNIQUE (namespace, tenant_id, authorized_operation_id),
  CHECK (authorization_source_kind IN ('authorization_grant', 'verified_step_up')),
  CHECK (
    (authorization_source_kind = 'authorization_grant'
      AND authorization_id IS NOT NULL
      AND evidence_set_digest IS NULL)
    OR (authorization_source_kind = 'verified_step_up'
      AND authorization_id IS NULL
      AND evidence_set_digest IS NOT NULL)
  ),
  CHECK (result_kind IN ('pending', 'succeeded', 'failed_before_side_effect', 'failed_after_side_effect')),
  CHECK (
    (result_kind = 'pending' AND completed_at_ms IS NULL)
    OR (result_kind != 'pending' AND completed_at_ms IS NOT NULL)
  )
);

INSERT INTO authorized_operation_audit_events (
  namespace, tenant_id, audit_event_id, authorized_operation_id,
  operation_fingerprint_digest, authorization_source_kind, authorization_id,
  evidence_set_digest, quota_id, material_activation_id, result_kind,
  claimed_at_ms, completed_at_ms
)
SELECT
  namespace, tenant_id, audit_event_id, authorized_operation_id,
  operation_fingerprint_digest, authorization_source_kind, authorization_id,
  evidence_set_digest, quota_id, material_activation_id, result_kind,
  claimed_at_ms, completed_at_ms
FROM authorized_operations;

CREATE INDEX authorized_operation_audit_fingerprint_idx
  ON authorized_operation_audit_events(namespace, tenant_id, operation_fingerprint_digest);

DROP TRIGGER IF EXISTS authorized_operation_claim_atomic;

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
