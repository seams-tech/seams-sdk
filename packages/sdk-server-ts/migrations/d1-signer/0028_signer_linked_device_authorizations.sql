-- R103 linked-device Wallet Session grants. Grant and quota persistence are
-- scoped to the same D1 signer partition for atomic admission.
CREATE TABLE linked_device_wallet_session_authorizations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  key_manifest_digest_b64u TEXT NOT NULL,
  permission_json TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  revoked_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, tenant_id, authorization_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, wallet_session_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, quota_id),
  CHECK (length(authorization_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(quota_id) > 0),
  CHECK (length(key_manifest_digest_b64u) > 0),
  CHECK (json_valid(permission_json)),
  CHECK (revocation_epoch >= 0),
  CHECK (lifecycle_kind IN ('active', 'revoked')),
  CHECK (issued_at_ms > 0 AND expires_at_ms > issued_at_ms),
  CHECK (
    (lifecycle_kind = 'active' AND revoked_at_ms IS NULL)
    OR (lifecycle_kind = 'revoked' AND revoked_at_ms IS NOT NULL AND revoked_at_ms >= issued_at_ms)
  )
);

CREATE INDEX linked_device_wallet_session_authorizations_identity_idx
  ON linked_device_wallet_session_authorizations(
    namespace, org_id, project_id, env_id, tenant_id, device_id, wallet_session_id
  );

CREATE TABLE linked_device_wallet_session_quotas (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  quota_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  wallet_session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  remaining_uses INTEGER NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, tenant_id, quota_id),
  UNIQUE (namespace, org_id, project_id, env_id, tenant_id, wallet_session_id),
  FOREIGN KEY (
    namespace, org_id, project_id, env_id, tenant_id, authorization_id
  ) REFERENCES linked_device_wallet_session_authorizations(
    namespace, org_id, project_id, env_id, tenant_id, authorization_id
  ),
  CHECK (length(quota_id) > 0),
  CHECK (length(authorization_id) > 0),
  CHECK (length(wallet_session_id) > 0),
  CHECK (length(principal_id) > 0),
  CHECK (remaining_uses >= 0),
  CHECK (lifecycle_kind IN ('active', 'exhausted', 'revoked')),
  CHECK (
    (remaining_uses > 0 AND lifecycle_kind = 'active')
    OR (remaining_uses = 0 AND lifecycle_kind IN ('exhausted', 'revoked'))
  ),
  CHECK (expires_at_ms > 0)
);

CREATE INDEX linked_device_wallet_session_quotas_identity_idx
  ON linked_device_wallet_session_quotas(
    namespace, org_id, project_id, env_id, tenant_id, authorization_id, wallet_session_id
  );

-- The original operation table predates linked-device grants. Keep the
-- operation and audit rows in the same table while recording which grant
-- variant owns the authorization identity. The nullable shape preserves the
-- old verified-step-up branch and allows this migration to run against an
-- already-populated signer database.
ALTER TABLE authorized_operations ADD COLUMN authorization_grant_kind TEXT;
ALTER TABLE authorized_operations ADD COLUMN material_activation_capability TEXT;
ALTER TABLE authorized_operations ADD COLUMN material_activation_owner TEXT;
ALTER TABLE authorized_operations ADD COLUMN material_activation_key_binding TEXT;
ALTER TABLE authorized_operations ADD COLUMN material_activation_lifecycle_binding TEXT;
ALTER TABLE authorized_operations ADD COLUMN material_activation_signing_worker TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_wallet_id TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_enrollment_id TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_device_id TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_wallet_key_id TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_lane_id TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_lane_share_epoch TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_revocation_epoch INTEGER;
ALTER TABLE authorized_operations ADD COLUMN linked_scope_org_id TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_scope_project_id TEXT;
ALTER TABLE authorized_operations ADD COLUMN linked_scope_env_id TEXT;

UPDATE authorized_operations
   SET authorization_grant_kind = 'wallet_session_authorization'
 WHERE authorization_source_kind = 'authorization_grant'
   AND authorization_grant_kind IS NULL;

ALTER TABLE authorized_operation_audit_events ADD COLUMN authorization_grant_kind TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN material_activation_capability TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN material_activation_owner TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN material_activation_key_binding TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN material_activation_lifecycle_binding TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN material_activation_signing_worker TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_wallet_id TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_enrollment_id TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_device_id TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_wallet_key_id TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_lane_id TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_lane_share_epoch TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_revocation_epoch INTEGER;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_scope_org_id TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_scope_project_id TEXT;
ALTER TABLE authorized_operation_audit_events ADD COLUMN linked_scope_env_id TEXT;

UPDATE authorized_operation_audit_events
   SET authorization_grant_kind = 'wallet_session_authorization'
 WHERE authorization_source_kind = 'authorization_grant'
   AND authorization_grant_kind IS NULL;

-- Replace the shared claim trigger with mutually exclusive owner, linked, and
-- step-up branches. Each branch owns its source validation and quota update;
-- the common audit trigger below only records a claim after the branch has
-- completed. All checks and quota changes remain one SQLite transaction.
DROP TRIGGER IF EXISTS authorized_operation_claim_atomic;
DROP TRIGGER IF EXISTS authorized_operation_owner_grant_claim_atomic;
DROP TRIGGER IF EXISTS authorized_operation_linked_grant_claim_atomic;
DROP TRIGGER IF EXISTS authorized_operation_step_up_claim_atomic;
DROP TRIGGER IF EXISTS authorized_operation_grant_shape_guard;

CREATE TRIGGER authorized_operation_grant_shape_guard
BEFORE INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND (
    NEW.authorization_source_kind NOT IN ('authorization_grant', 'verified_step_up')
    OR (NEW.authorization_source_kind = 'authorization_grant'
      AND (NEW.authorization_grant_kind IS NULL OR NEW.authorization_grant_kind NOT IN (
        'wallet_session_authorization',
        'linked_device_wallet_session_authorization_v1'
      )))
    OR (NEW.authorization_source_kind = 'authorization_grant'
      AND NEW.authorization_grant_kind = 'linked_device_wallet_session_authorization_v1'
      AND (NEW.linked_scope_org_id IS NULL
        OR NEW.linked_scope_project_id IS NULL
        OR NEW.linked_scope_env_id IS NULL))
    OR (NEW.authorization_source_kind = 'verified_step_up'
      AND NEW.authorization_grant_kind IS NOT NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'authorization_grant_kind_rejected');
END;

CREATE TRIGGER authorized_operation_owner_grant_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'authorization_grant'
  AND NEW.authorization_grant_kind = 'wallet_session_authorization'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
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

  UPDATE authorization_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.quota_kind = 'consume_reusable_wallet_session'
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
END;

CREATE TRIGGER authorized_operation_linked_grant_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'authorization_grant'
  AND NEW.authorization_grant_kind = 'linked_device_wallet_session_authorization_v1'
BEGIN
  SELECT CASE
    WHEN NEW.quota_kind != 'consume_reusable_wallet_session'
      OR NEW.capability_kind NOT IN ('near_ed25519_mpc_signing', 'evm_ecdsa_mpc_signing')
      OR NEW.operation_kind IN ('near.export_key', 'evm.export_key')
      OR NOT EXISTS (
        SELECT 1
          FROM linked_device_wallet_session_authorizations AS grant_record
          JOIN lane_enrollments AS enrollment
            ON enrollment.namespace = grant_record.namespace
           AND enrollment.org_id = grant_record.org_id
           AND enrollment.project_id = grant_record.project_id
           AND enrollment.env_id = grant_record.env_id
           AND enrollment.org_id = NEW.linked_scope_org_id
           AND enrollment.project_id = NEW.linked_scope_project_id
           AND enrollment.env_id = NEW.linked_scope_env_id
           AND enrollment.enrollment_id = grant_record.enrollment_id
           AND enrollment.wallet_id = grant_record.wallet_id
           AND json_extract(enrollment.lifecycle_json, '$.state') = 'active'
           AND json_extract(enrollment.lifecycle_json, '$.manifestDigestB64u') = grant_record.key_manifest_digest_b64u
         JOIN lane_product_epochs AS product
            ON product.namespace = grant_record.namespace
           AND product.org_id = grant_record.org_id
           AND product.project_id = grant_record.project_id
           AND product.env_id = grant_record.env_id
           AND product.org_id = NEW.linked_scope_org_id
           AND product.project_id = NEW.linked_scope_project_id
           AND product.env_id = NEW.linked_scope_env_id
           AND product.enrollment_id = grant_record.enrollment_id
           AND product.wallet_id = grant_record.wallet_id
           AND product.wallet_id = NEW.linked_wallet_id
           AND product.enrollment_id = NEW.linked_enrollment_id
           AND product.wallet_key_id = NEW.linked_wallet_key_id
           AND product.lane_id = NEW.linked_lane_id
           AND product.lane_share_epoch = NEW.linked_lane_share_epoch
           AND product.target_material_activation_id = NEW.material_activation_id
           AND product.revocation_epoch = grant_record.revocation_epoch
           AND product.revocation_epoch = NEW.linked_revocation_epoch
           AND product.state = 'active'
           AND product.lane_kind = 'linked_device'
           AND (
             (NEW.capability_kind = 'near_ed25519_mpc_signing' AND product.key_family = 'ed25519')
             OR (NEW.capability_kind = 'evm_ecdsa_mpc_signing' AND product.key_family = 'ecdsa_secp256k1')
           )
           AND json_extract(product.material_activation_json, '$.activationId') = NEW.material_activation_id
           AND json_extract(product.material_activation_json, '$.capability') = NEW.material_activation_capability
           AND json_extract(product.material_activation_json, '$.materialOwner') = NEW.material_activation_owner
           AND json_extract(product.material_activation_json, '$.keyBinding') = NEW.material_activation_key_binding
           AND json_extract(product.material_activation_json, '$.lifecycleBinding') = NEW.material_activation_lifecycle_binding
           AND json_extract(product.material_activation_json, '$.signingWorker') = NEW.material_activation_signing_worker
         JOIN lane_protocol_operations AS protocol
          ON protocol.namespace = product.namespace
          AND protocol.org_id = product.org_id
          AND protocol.project_id = product.project_id
          AND protocol.env_id = product.env_id
          AND protocol.org_id = NEW.linked_scope_org_id
          AND protocol.project_id = NEW.linked_scope_project_id
          AND protocol.env_id = NEW.linked_scope_env_id
          AND protocol.operation_id = product.operation_id
          AND protocol.enrollment_id = product.enrollment_id
          AND protocol.enrollment_id = NEW.linked_enrollment_id
          AND protocol.wallet_id = NEW.linked_wallet_id
          AND protocol.wallet_key_id = NEW.linked_wallet_key_id
          AND protocol.target_lane_id = NEW.linked_lane_id
          AND protocol.target_lane_share_epoch = NEW.linked_lane_share_epoch
          AND protocol.target_material_activation_id = product.target_material_activation_id
          AND protocol.target_material_activation_id = NEW.material_activation_id
          AND json_extract(protocol.lifecycle_json, '$.state') = 'active'
         WHERE grant_record.namespace = NEW.namespace
           AND grant_record.org_id = NEW.linked_scope_org_id
           AND grant_record.project_id = NEW.linked_scope_project_id
           AND grant_record.env_id = NEW.linked_scope_env_id
           AND grant_record.org_id = product.org_id
           AND grant_record.project_id = product.project_id
           AND grant_record.env_id = product.env_id
           AND grant_record.tenant_id = NEW.tenant_id
           AND grant_record.authorization_id = NEW.authorization_id
           AND grant_record.principal_id = NEW.principal_id
           AND grant_record.quota_id = NEW.quota_id
           AND grant_record.wallet_id = NEW.linked_wallet_id
           AND grant_record.enrollment_id = NEW.linked_enrollment_id
           AND grant_record.device_id = NEW.linked_device_id
           AND grant_record.revocation_epoch = NEW.linked_revocation_epoch
           AND grant_record.lifecycle_kind = 'active'
           AND grant_record.expires_at_ms > NEW.claimed_at_ms
           AND json_extract(grant_record.permission_json, '$.kind') = 'owner_equivalent_signing'
           AND json_extract(grant_record.permission_json, '$.administrationScope') = 'signing_only'
           AND json_extract(grant_record.permission_json, '$.localUserPresence') = 'required'
      )
    THEN RAISE(ABORT, 'authorization_linked_device_rejected')
  END;

  UPDATE linked_device_wallet_session_quotas
     SET remaining_uses = remaining_uses - 1,
         lifecycle_kind = CASE WHEN remaining_uses = 1 THEN 'exhausted' ELSE 'active' END
   WHERE NEW.quota_kind = 'consume_reusable_wallet_session'
     AND namespace = NEW.namespace
     AND org_id = NEW.linked_scope_org_id
     AND project_id = NEW.linked_scope_project_id
     AND env_id = NEW.linked_scope_env_id
     AND tenant_id = NEW.tenant_id
     AND quota_id = NEW.quota_id
     AND authorization_id = NEW.authorization_id
     AND principal_id = NEW.principal_id
     AND lifecycle_kind = 'active'
     AND remaining_uses > 0
     AND expires_at_ms > NEW.claimed_at_ms;

  SELECT CASE
    WHEN NEW.quota_kind = 'consume_reusable_wallet_session' AND changes() != 1
    THEN RAISE(ABORT, 'authorization_wallet_session_quota_rejected')
  END;
END;

CREATE TRIGGER authorized_operation_step_up_claim_atomic
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
  AND NEW.authorization_source_kind = 'verified_step_up'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
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
END;

CREATE TRIGGER authorized_operation_audit_claim
AFTER INSERT ON authorized_operations
WHEN NEW.lifecycle_kind = 'claimed'
BEGIN
  INSERT INTO authorized_operation_audit_events (
    namespace, tenant_id, audit_event_id, authorized_operation_id,
    operation_fingerprint_digest, authorization_source_kind, authorization_id,
    authorization_grant_kind, evidence_set_digest, quota_id, material_activation_id,
    material_activation_capability, material_activation_owner,
    material_activation_key_binding, material_activation_lifecycle_binding,
    material_activation_signing_worker, linked_wallet_id, linked_enrollment_id,
    linked_device_id, linked_wallet_key_id, linked_lane_id, linked_lane_share_epoch,
    linked_revocation_epoch, linked_scope_org_id, linked_scope_project_id,
    linked_scope_env_id, result_kind, claimed_at_ms, completed_at_ms
  ) VALUES (
    NEW.namespace, NEW.tenant_id, NEW.audit_event_id, NEW.authorized_operation_id,
    NEW.operation_fingerprint_digest, NEW.authorization_source_kind, NEW.authorization_id,
    NEW.authorization_grant_kind, NEW.evidence_set_digest, NEW.quota_id,
    NEW.material_activation_id, NEW.material_activation_capability,
    NEW.material_activation_owner, NEW.material_activation_key_binding,
    NEW.material_activation_lifecycle_binding, NEW.material_activation_signing_worker,
    NEW.linked_wallet_id, NEW.linked_enrollment_id, NEW.linked_device_id,
    NEW.linked_wallet_key_id, NEW.linked_lane_id, NEW.linked_lane_share_epoch,
    NEW.linked_revocation_epoch, NEW.linked_scope_org_id, NEW.linked_scope_project_id,
    NEW.linked_scope_env_id, NEW.result_kind, NEW.claimed_at_ms, NEW.completed_at_ms
  );
END;

DROP TRIGGER IF EXISTS authorized_operation_audit_complete;

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

CREATE TRIGGER IF NOT EXISTS linked_device_wallet_session_authorization_identity_insert
BEFORE INSERT ON linked_device_wallet_session_authorizations
WHEN NEW.principal_id != 'linked-device:' || NEW.device_id
  OR NEW.wallet_session_id = NEW.authorization_id
  OR NEW.wallet_session_id = NEW.quota_id
  OR NEW.authorization_id = NEW.quota_id
  OR json_extract(NEW.permission_json, '$.kind') IS NOT 'owner_equivalent_signing'
  OR json_extract(NEW.permission_json, '$.administrationScope') IS NOT 'signing_only'
  OR json_extract(NEW.permission_json, '$.localUserPresence') IS NOT 'required'
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_authorization_identity_rejected');
END;

CREATE TRIGGER IF NOT EXISTS linked_device_wallet_session_authorization_identity_update
BEFORE UPDATE OF principal_id, device_id, authorization_id, wallet_session_id, quota_id, permission_json
ON linked_device_wallet_session_authorizations
WHEN NEW.principal_id != 'linked-device:' || NEW.device_id
  OR NEW.wallet_session_id = NEW.authorization_id
  OR NEW.wallet_session_id = NEW.quota_id
  OR NEW.authorization_id = NEW.quota_id
  OR json_extract(NEW.permission_json, '$.kind') IS NOT 'owner_equivalent_signing'
  OR json_extract(NEW.permission_json, '$.administrationScope') IS NOT 'signing_only'
  OR json_extract(NEW.permission_json, '$.localUserPresence') IS NOT 'required'
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_authorization_identity_rejected');
END;

CREATE TRIGGER IF NOT EXISTS linked_device_wallet_session_authorization_revoke_atomic
AFTER UPDATE OF lifecycle_kind ON linked_device_wallet_session_authorizations
WHEN OLD.lifecycle_kind = 'active' AND NEW.lifecycle_kind = 'revoked'
BEGIN
  UPDATE linked_device_wallet_session_quotas
     SET remaining_uses = 0,
         lifecycle_kind = 'revoked'
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id
     AND project_id = NEW.project_id
     AND env_id = NEW.env_id
     AND tenant_id = NEW.tenant_id
     AND authorization_id = NEW.authorization_id
     AND quota_id = NEW.quota_id
     AND lifecycle_kind != 'revoked';

  SELECT CASE
    WHEN changes() != 1
    THEN RAISE(ABORT, 'linked_device_wallet_session_quota_revoke_rejected')
  END;
END;

CREATE TRIGGER IF NOT EXISTS linked_device_wallet_session_quota_revoke_guard
BEFORE UPDATE OF lifecycle_kind, remaining_uses ON linked_device_wallet_session_quotas
WHEN NEW.lifecycle_kind = 'revoked'
  AND NOT EXISTS (
    SELECT 1
      FROM linked_device_wallet_session_authorizations AS authorization
     WHERE authorization.namespace = NEW.namespace
       AND authorization.org_id = NEW.org_id
       AND authorization.project_id = NEW.project_id
       AND authorization.env_id = NEW.env_id
       AND authorization.tenant_id = NEW.tenant_id
       AND authorization.authorization_id = NEW.authorization_id
       AND authorization.quota_id = NEW.quota_id
       AND authorization.lifecycle_kind = 'revoked'
  )
BEGIN
  SELECT RAISE(ABORT, 'linked_device_wallet_session_quota_revoke_rejected');
END;
