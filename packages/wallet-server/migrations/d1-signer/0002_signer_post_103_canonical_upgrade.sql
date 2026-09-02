-- Forward bridge from the last deployed signer schema to the post-103 canonical schema.
-- This migration is safe after the canonical 0001 baseline and preserves deployed rows.

DROP TRIGGER IF EXISTS "authorized_operation_audit_claim";
DROP TRIGGER IF EXISTS "authorized_operation_audit_complete";
DROP TRIGGER IF EXISTS "authorized_operation_claim_atomic";
DROP TRIGGER IF EXISTS "authorized_operation_complete_atomic";
DROP TRIGGER IF EXISTS "authorized_operation_grant_shape_guard";
DROP TRIGGER IF EXISTS "authorized_operation_linked_grant_claim_atomic";
DROP TRIGGER IF EXISTS "authorized_operation_owner_grant_claim_atomic";
DROP TRIGGER IF EXISTS "authorized_operation_step_up_claim_atomic";

DROP TABLE IF EXISTS "authorized_operation_audit_events_post_103_upgrade";
CREATE TABLE "authorized_operation_audit_events_post_103_upgrade" (
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
  completed_at_ms INTEGER, authorization_grant_kind TEXT, material_activation_capability TEXT, material_activation_owner TEXT, material_activation_key_binding TEXT, material_activation_lifecycle_binding TEXT, material_activation_signing_worker TEXT, linked_wallet_id TEXT, linked_enrollment_id TEXT, linked_device_id TEXT, linked_wallet_key_id TEXT, linked_lane_id TEXT, linked_lane_share_epoch TEXT, linked_revocation_epoch INTEGER, linked_scope_org_id TEXT, linked_scope_project_id TEXT, linked_scope_env_id TEXT,
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
INSERT INTO "authorized_operation_audit_events_post_103_upgrade" (
  "namespace",
  "tenant_id",
  "audit_event_id",
  "authorized_operation_id",
  "operation_fingerprint_digest",
  "authorization_source_kind",
  "authorization_id",
  "evidence_set_digest",
  "quota_id",
  "material_activation_id",
  "result_kind",
  "claimed_at_ms",
  "completed_at_ms",
  "authorization_grant_kind",
  "material_activation_capability",
  "material_activation_owner",
  "material_activation_key_binding",
  "material_activation_lifecycle_binding",
  "material_activation_signing_worker",
  "linked_wallet_id",
  "linked_enrollment_id",
  "linked_device_id",
  "linked_wallet_key_id",
  "linked_lane_id",
  "linked_lane_share_epoch",
  "linked_revocation_epoch",
  "linked_scope_org_id",
  "linked_scope_project_id",
  "linked_scope_env_id"
) SELECT
  "namespace",
  "tenant_id",
  "audit_event_id",
  "authorized_operation_id",
  "operation_fingerprint_digest",
  "authorization_source_kind",
  "authorization_id",
  "evidence_set_digest",
  "quota_id",
  "material_activation_id",
  "result_kind",
  "claimed_at_ms",
  "completed_at_ms",
  CASE
    WHEN authorization_source_kind = 'authorization_grant'
      THEN 'wallet_session_authorization'
    ELSE NULL
  END,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
FROM "authorized_operation_audit_events";
DROP TABLE "authorized_operation_audit_events";
ALTER TABLE "authorized_operation_audit_events_post_103_upgrade" RENAME TO "authorized_operation_audit_events";

DROP TABLE IF EXISTS "authorized_operations_post_103_upgrade";
CREATE TABLE "authorized_operations_post_103_upgrade" (
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
  material_activation_id TEXT, authorization_grant_kind TEXT, material_activation_capability TEXT, material_activation_owner TEXT, material_activation_key_binding TEXT, material_activation_lifecycle_binding TEXT, material_activation_signing_worker TEXT, linked_wallet_id TEXT, linked_enrollment_id TEXT, linked_device_id TEXT, linked_wallet_key_id TEXT, linked_lane_id TEXT, linked_lane_share_epoch TEXT, linked_revocation_epoch INTEGER, linked_scope_org_id TEXT, linked_scope_project_id TEXT, linked_scope_env_id TEXT,
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
INSERT INTO "authorized_operations_post_103_upgrade" (
  "namespace",
  "tenant_id",
  "authorized_operation_id",
  "audit_event_id",
  "principal_id",
  "capability_id",
  "capability_kind",
  "operation_kind",
  "operation_id",
  "operation_fingerprint_digest",
  "lane_digest",
  "intent_digest",
  "display_digest",
  "authorization_source_kind",
  "authorization_id",
  "evidence_set_digest",
  "quota_id",
  "quota_kind",
  "lifecycle_kind",
  "result_kind",
  "result_digest",
  "result_status",
  "result_content_type",
  "result_body_text",
  "claimed_at_ms",
  "completed_at_ms",
  "material_activation_id",
  "authorization_grant_kind",
  "material_activation_capability",
  "material_activation_owner",
  "material_activation_key_binding",
  "material_activation_lifecycle_binding",
  "material_activation_signing_worker",
  "linked_wallet_id",
  "linked_enrollment_id",
  "linked_device_id",
  "linked_wallet_key_id",
  "linked_lane_id",
  "linked_lane_share_epoch",
  "linked_revocation_epoch",
  "linked_scope_org_id",
  "linked_scope_project_id",
  "linked_scope_env_id"
) SELECT
  "namespace",
  "tenant_id",
  "authorized_operation_id",
  "audit_event_id",
  "principal_id",
  "capability_id",
  "capability_kind",
  "operation_kind",
  "operation_id",
  "operation_fingerprint_digest",
  "lane_digest",
  "intent_digest",
  "display_digest",
  "authorization_source_kind",
  "authorization_id",
  "evidence_set_digest",
  "quota_id",
  "quota_kind",
  "lifecycle_kind",
  "result_kind",
  "result_digest",
  "result_status",
  "result_content_type",
  "result_body_text",
  "claimed_at_ms",
  "completed_at_ms",
  "material_activation_id",
  CASE
    WHEN authorization_source_kind = 'authorization_grant'
      THEN 'wallet_session_authorization'
    ELSE NULL
  END,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
FROM "authorized_operations";
DROP TABLE "authorized_operations";
ALTER TABLE "authorized_operations_post_103_upgrade" RENAME TO "authorized_operations";

DROP TABLE IF EXISTS "webauthn_challenges_post_103_upgrade";
CREATE TABLE "webauthn_challenges_post_103_upgrade" (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  challenge_kind TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
  CHECK (length(challenge_id) > 0),
  CHECK (challenge_kind IN ('login', 'sync', 'recovery_registration')),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms)
);
INSERT INTO "webauthn_challenges_post_103_upgrade" (
  "namespace",
  "org_id",
  "project_id",
  "env_id",
  "challenge_id",
  "challenge_kind",
  "record_json",
  "created_at_ms",
  "expires_at_ms"
) SELECT
  "namespace",
  "org_id",
  "project_id",
  "env_id",
  "challenge_id",
  "challenge_kind",
  "record_json",
  "created_at_ms",
  "expires_at_ms"
FROM "webauthn_challenges";
DROP TABLE "webauthn_challenges";
ALTER TABLE "webauthn_challenges_post_103_upgrade" RENAME TO "webauthn_challenges";

CREATE TABLE IF NOT EXISTS lane_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);

CREATE TABLE IF NOT EXISTS lane_effect_journal (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  effect_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_key_id TEXT NOT NULL,
  lane_id TEXT NOT NULL,
  lane_share_epoch TEXT NOT NULL,
  effect_kind TEXT NOT NULL,
  request_digest_b64u TEXT NOT NULL,
  status TEXT NOT NULL,
  response_digest_b64u TEXT,
  recorded_at_ms INTEGER NOT NULL,
  confirmed_at_ms INTEGER,
  version INTEGER NOT NULL,
  command_digest_b64u TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, effect_id),
  UNIQUE (namespace, org_id, project_id, env_id, operation_id, effect_kind),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, operation_id)
    REFERENCES lane_protocol_operations(namespace, org_id, project_id, env_id, operation_id),
  CHECK (effect_kind IN ('activate_server_material', 'retire_server_material', 'invalidate_holder_material')),
  CHECK (status IN ('recorded', 'confirmed')),
  CHECK (
    (status = 'recorded' AND response_digest_b64u IS NULL AND confirmed_at_ms IS NULL)
    OR (status = 'confirmed' AND response_digest_b64u IS NOT NULL AND confirmed_at_ms IS NOT NULL AND confirmed_at_ms >= recorded_at_ms)
  ),
  CHECK (version > 0),
  CHECK (recorded_at_ms >= 0)
);

CREATE TABLE IF NOT EXISTS lane_enrollments (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  lifecycle_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  command_digest_b64u TEXT NOT NULL,
  revocation_fence_command_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, enrollment_id),
  UNIQUE (namespace, org_id, project_id, env_id, manifest_digest_b64u),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(manifest_json)),
  CHECK (json_valid(lifecycle_json)),
  CHECK (version > 0),
  CHECK (created_at_ms >= 0 AND updated_at_ms >= created_at_ms)
);

CREATE TABLE IF NOT EXISTS lane_locks (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  lock_key TEXT NOT NULL,
  lock_kind TEXT NOT NULL,
  enrollment_id TEXT,
  wallet_key_id TEXT,
  lane_id TEXT,
  lock_id TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  acquired_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, lock_key),
  CHECK (lock_kind IN ('wallet_key', 'enrollment')),
  CHECK (length(lock_id) > 0),
  CHECK (expires_at_ms > acquired_at_ms),
  CHECK ((lock_kind = 'wallet_key' AND wallet_key_id IS NOT NULL AND enrollment_id IS NULL AND lane_id IS NULL) OR
         (lock_kind = 'enrollment' AND enrollment_id IS NOT NULL AND wallet_key_id IS NULL AND lane_id IS NULL))
);

CREATE TABLE IF NOT EXISTS lane_product_epochs (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_key_id TEXT NOT NULL,
  lane_id TEXT NOT NULL,
  lane_share_epoch TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  target_material_activation_id TEXT NOT NULL,
  material_activation_json TEXT NOT NULL,
  holder_participant_json TEXT NOT NULL,
  signing_worker_participant_json TEXT NOT NULL,
  participant_set_binding_digest_b64u TEXT NOT NULL,
  revocation_epoch INTEGER NOT NULL,
  lane_kind TEXT NOT NULL,
  key_family TEXT NOT NULL,
  public_identity_digest_b64u TEXT NOT NULL,
  state TEXT NOT NULL,
  product_json TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  command_digest_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_key_id, lane_id, lane_share_epoch),
  UNIQUE (namespace, org_id, project_id, env_id, target_material_activation_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, operation_id)
    REFERENCES lane_protocol_operations(namespace, org_id, project_id, env_id, operation_id),
  CHECK (json_valid(material_activation_json)),
  CHECK (json_valid(holder_participant_json)),
  CHECK (json_valid(signing_worker_participant_json)),
  CHECK (length(participant_set_binding_digest_b64u) > 0),
  CHECK (revocation_epoch >= 0),
  CHECK (json_valid(product_json)),
  CHECK (state IN ('pending_visibility', 'active', 'retired', 'revocation_pending', 'revoked')),
  CHECK (lane_kind IN ('owner_passkey', 'owner_email_otp', 'linked_device', 'delegated_execution', 'recovery', 'break_glass')),
  CHECK (length(command_digest_b64u) > 0),
  CHECK (version > 0),
  CHECK (key_family IN ('ed25519', 'ecdsa_secp256k1')),
  CHECK (created_at_ms >= 0 AND updated_at_ms >= created_at_ms)
);

CREATE TABLE IF NOT EXISTS lane_protocol_operations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  wallet_key_id TEXT NOT NULL,
  source_lane_id TEXT NOT NULL,
  source_lane_share_epoch TEXT NOT NULL,
  source_revocation_epoch INTEGER NOT NULL,
  target_lane_id TEXT NOT NULL,
  target_lane_share_epoch TEXT NOT NULL,
  target_material_activation_id TEXT NOT NULL,
  key_family TEXT NOT NULL,
  job_json TEXT NOT NULL,
  lifecycle_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  command_digest_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, operation_id),
  UNIQUE (namespace, org_id, project_id, env_id, target_material_activation_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  CHECK (source_revocation_epoch >= 0),
  CHECK (key_family IN ('ed25519', 'ecdsa_secp256k1')),
  CHECK (json_valid(job_json)),
  CHECK (json_valid(lifecycle_json)),
  CHECK (version > 0),
  CHECK (created_at_ms >= 0 AND updated_at_ms >= created_at_ms)
);

CREATE TABLE IF NOT EXISTS lane_receipts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  operation_id TEXT,
  receipt_kind TEXT NOT NULL,
  receipt_digest_b64u TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, receipt_id),
  UNIQUE (namespace, org_id, project_id, env_id, operation_id, receipt_kind),
  FOREIGN KEY (namespace, org_id, project_id, env_id, enrollment_id)
    REFERENCES lane_enrollments(namespace, org_id, project_id, env_id, enrollment_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, operation_id)
    REFERENCES lane_protocol_operations(namespace, org_id, project_id, env_id, operation_id),
  CHECK (json_valid(receipt_json)),
  CHECK (created_at_ms >= 0)
);

CREATE TABLE IF NOT EXISTS linked_device_owner_planning_snapshots (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  owner_context_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  policy_digest_b64u TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  ordered_key_bindings_json TEXT NOT NULL,
  protocol_versions_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  source_children_json TEXT NOT NULL,
  ordered_owner_source_lane_hints_json TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  snapshot_digest_b64u TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(link_session_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(policy_digest_b64u) > 0),
  CHECK (length(operation_id) > 0),
  CHECK (length(idempotency_key) > 0),
  CHECK (json_valid(owner_context_json)),
  CHECK (json_valid(payload_json)),
  CHECK (json_valid(ordered_key_bindings_json)),
  CHECK (json_valid(protocol_versions_json)),
  CHECK (json_valid(source_children_json)),
  CHECK (json_valid(ordered_owner_source_lane_hints_json)),
  CHECK (json_valid(snapshot_json)),
  CHECK (expires_at_ms > 0),
  CHECK (created_at_ms > 0 AND updated_at_ms >= created_at_ms)
);

CREATE TABLE IF NOT EXISTS linked_device_provisioning_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  deliveries_json TEXT NOT NULL,
  aggregate_receipt_json TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(deliveries_json)),
  CHECK (aggregate_receipt_json IS NULL OR json_valid(aggregate_receipt_json))
);

CREATE TABLE IF NOT EXISTS linked_device_request_proof_nonces (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  request_nonce_b64u TEXT NOT NULL,
  proof_digest_b64u TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    request_nonce_b64u
  ),
  CHECK (length(link_session_id) > 0),
  CHECK (length(request_nonce_b64u) > 0),
  CHECK (length(proof_digest_b64u) > 0),
  CHECK (issued_at_ms > 0),
  CHECK (expires_at_ms > issued_at_ms),
  CHECK (consumed_at_ms >= issued_at_ms),
  CHECK (consumed_at_ms < expires_at_ms)
);

CREATE TABLE IF NOT EXISTS linked_device_session_transcripts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  transcript_kind TEXT NOT NULL,
  digest_b64u TEXT NOT NULL,
  transcript_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    transcript_kind
  ),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (transcript_kind IN ('claim', 'approval')),
  CHECK (length(digest_b64u) > 0),
  CHECK (json_valid(transcript_json)),
  CHECK (created_at_ms > 0)
);

CREATE TABLE IF NOT EXISTS linked_device_sessions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  link_public_key_b64u TEXT NOT NULL,
  device_public_key_b64u TEXT NOT NULL,
  state TEXT NOT NULL,
  record_json TEXT NOT NULL,
  revision INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  claim_expires_at_ms INTEGER,
  claim_digest_b64u TEXT,
  approval_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(link_session_id) > 0),
  CHECK (length(link_public_key_b64u) > 0),
  CHECK (length(device_public_key_b64u) > 0),
  CHECK (state IN (
    'displaying_qr',
    'claimed_by_owner',
    'awaiting_target_passkey',
    'provisioning',
    'active',
    'expired_unclaimed',
    'expired_claimed',
    'cancelled_unclaimed',
    'cancelled_claimed_precommit',
    'committed_completion_required'
  )),
  CHECK (json_valid(record_json)),
  CHECK (revision > 0),
  CHECK (expires_at_ms > 0),
  CHECK (claim_expires_at_ms IS NULL OR claim_expires_at_ms > 0),
  CHECK (claim_digest_b64u IS NULL OR length(claim_digest_b64u) > 0),
  CHECK (approval_digest_b64u IS NULL OR length(approval_digest_b64u) > 0),
  CHECK (created_at_ms > 0 AND updated_at_ms >= created_at_ms)
);

CREATE TABLE IF NOT EXISTS linked_device_source_handoffs (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  target_ready_json TEXT NOT NULL,
  target_ready_digest_b64u TEXT NOT NULL,
  manifest_digest_b64u TEXT NOT NULL,
  deliveries_json TEXT,
  deliveries_digest_b64u TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (length(target_ready_digest_b64u) > 0),
  CHECK (length(manifest_digest_b64u) > 0),
  CHECK (json_valid(target_ready_json)),
  CHECK (
    (deliveries_json IS NULL AND deliveries_digest_b64u IS NULL)
    OR
    (deliveries_json IS NOT NULL AND json_valid(deliveries_json) AND length(deliveries_digest_b64u) > 0)
  )
);

CREATE TABLE IF NOT EXISTS linked_device_target_commit_reservations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  registration_digest_b64u TEXT NOT NULL,
  state TEXT NOT NULL,
  reserved_at_ms INTEGER NOT NULL,
  committed_at_ms INTEGER,
  key_manifest_digest_b64u TEXT,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(registration_digest_b64u) > 0),
  CHECK (state IN ('reserved', 'committed')),
  CHECK (
    (state = 'reserved' AND committed_at_ms IS NULL AND key_manifest_digest_b64u IS NULL)
    OR
    (state = 'committed' AND committed_at_ms IS NOT NULL AND length(key_manifest_digest_b64u) > 0)
  )
);

CREATE TABLE IF NOT EXISTS linked_device_target_credentials (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  state TEXT NOT NULL,
  preparation_digest_b64u TEXT NOT NULL,
  preparation_json TEXT NOT NULL,
  registration_json TEXT,
  credential_id_b64u TEXT,
  credential_public_key_b64u TEXT,
  credential_counter INTEGER,
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
  CHECK (length(preparation_digest_b64u) > 0),
  CHECK (json_valid(preparation_json)),
  CHECK (expires_at_ms > prepared_at_ms),
  CHECK (
    (state = 'prepared'
      AND registration_json IS NULL
      AND credential_id_b64u IS NULL
      AND credential_public_key_b64u IS NULL
      AND credential_counter IS NULL
      AND key_manifest_digest_b64u IS NULL
      AND registered_at_ms IS NULL)
    OR
    (state = 'registered'
      AND json_valid(registration_json)
      AND length(credential_id_b64u) > 0
      AND length(credential_public_key_b64u) > 0
      AND credential_counter >= 0
      AND length(key_manifest_digest_b64u) > 0
      AND registered_at_ms > 0)
  )
);

CREATE TABLE IF NOT EXISTS linked_device_target_deployment_descriptors (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  target_preparation_digest_b64u TEXT NOT NULL,
  registration_digest_b64u TEXT NOT NULL,
  child_index INTEGER NOT NULL,
  request_digest_b64u TEXT NOT NULL,
  descriptor_digest_b64u TEXT NOT NULL,
  descriptor_json TEXT NOT NULL,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    target_preparation_digest_b64u,
    registration_digest_b64u,
    child_index
  ),
  CHECK (length(target_preparation_digest_b64u) > 0),
  CHECK (length(registration_digest_b64u) > 0),
  CHECK (child_index >= 0),
  CHECK (length(request_digest_b64u) > 0),
  CHECK (length(descriptor_digest_b64u) > 0),
  CHECK (json_valid(descriptor_json)),
  CHECK (issued_at_ms > 0 AND expires_at_ms > issued_at_ms)
);

CREATE TABLE IF NOT EXISTS linked_device_wallet_session_authorizations (
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

CREATE TABLE IF NOT EXISTS linked_device_wallet_session_quotas (
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

INSERT OR IGNORE INTO lane_cas_guard (guard_id) VALUES (1);

CREATE INDEX IF NOT EXISTS authorized_operation_audit_fingerprint_idx
  ON authorized_operation_audit_events(namespace, tenant_id, operation_fingerprint_digest);
CREATE INDEX IF NOT EXISTS authorized_operation_audit_linked_device_activity_idx
  ON authorized_operation_audit_events(
    namespace,
    authorization_grant_kind,
    linked_scope_org_id,
    linked_scope_project_id,
    linked_scope_env_id,
    linked_wallet_id,
    linked_enrollment_id,
    linked_device_id
  );
CREATE INDEX IF NOT EXISTS authorized_operation_audit_linked_device_activity_idx
  ON authorized_operation_audit_events(
    namespace,
    authorization_grant_kind,
    linked_scope_org_id,
    linked_scope_project_id,
    linked_scope_env_id,
    linked_wallet_id,
    linked_enrollment_id,
    linked_device_id
  );
CREATE INDEX IF NOT EXISTS authorized_operations_tenant_fingerprint_idx
  ON authorized_operations(namespace, tenant_id, operation_fingerprint_digest);
CREATE INDEX IF NOT EXISTS authorized_operations_tenant_lifecycle_idx
  ON authorized_operations(namespace, tenant_id, lifecycle_kind);
CREATE INDEX IF NOT EXISTS lane_enrollments_wallet_idx
  ON lane_enrollments(namespace, org_id, project_id, env_id, wallet_id, updated_at_ms);
CREATE UNIQUE INDEX IF NOT EXISTS lane_product_epochs_one_active_idx
  ON lane_product_epochs(namespace, org_id, project_id, env_id, wallet_key_id, lane_id)
  WHERE state = 'active';
CREATE INDEX IF NOT EXISTS lane_product_epochs_wallet_active_idx
  ON lane_product_epochs(namespace, org_id, project_id, env_id, wallet_id, state, updated_at_ms);
CREATE INDEX IF NOT EXISTS lane_protocol_operations_enrollment_idx
  ON lane_protocol_operations(namespace, org_id, project_id, env_id, enrollment_id, operation_id);
CREATE UNIQUE INDEX IF NOT EXISTS linked_device_owner_planning_snapshots_operation_idx
  ON linked_device_owner_planning_snapshots(
    namespace, org_id, project_id, env_id, operation_id
  );
CREATE INDEX IF NOT EXISTS linked_device_owner_planning_snapshots_wallet_idx
  ON linked_device_owner_planning_snapshots(
    namespace, org_id, project_id, env_id, wallet_id, expires_at_ms
  );
CREATE INDEX IF NOT EXISTS linked_device_request_proof_nonces_expiry_idx
  ON linked_device_request_proof_nonces(
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX IF NOT EXISTS linked_device_session_transcripts_digest_idx
  ON linked_device_session_transcripts(
    namespace,
    org_id,
    project_id,
    env_id,
    digest_b64u
  );
CREATE INDEX IF NOT EXISTS linked_device_sessions_state_idx
  ON linked_device_sessions(namespace, org_id, project_id, env_id, state, updated_at_ms);
CREATE UNIQUE INDEX IF NOT EXISTS linked_device_target_credentials_credential_idx
  ON linked_device_target_credentials(
    namespace,
    org_id,
    project_id,
    env_id,
    credential_id_b64u
  )
  WHERE credential_id_b64u IS NOT NULL;
CREATE INDEX IF NOT EXISTS linked_device_target_deployment_descriptors_wallet_idx
  ON linked_device_target_deployment_descriptors(
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
CREATE INDEX IF NOT EXISTS linked_device_wallet_session_authorizations_identity_idx
  ON linked_device_wallet_session_authorizations(
    namespace, org_id, project_id, env_id, tenant_id, device_id, wallet_session_id
  );
CREATE INDEX IF NOT EXISTS linked_device_wallet_session_quotas_identity_idx
  ON linked_device_wallet_session_quotas(
    namespace, org_id, project_id, env_id, tenant_id, authorization_id, wallet_session_id
  );
CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry_idx
  ON webauthn_challenges (
    namespace,
    org_id,
    project_id,
    env_id,
    challenge_kind,
    expires_at_ms
  );

CREATE TRIGGER IF NOT EXISTS authorized_operation_audit_claim
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_audit_claim
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_audit_complete
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_complete_atomic
BEFORE UPDATE OF lifecycle_kind ON authorized_operations
WHEN OLD.lifecycle_kind = 'completed' OR NEW.lifecycle_kind != 'completed'
BEGIN
  SELECT RAISE(ABORT, 'authorized_operation_lifecycle_transition_rejected');
END;

CREATE TRIGGER IF NOT EXISTS authorized_operation_grant_shape_guard
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_grant_shape_guard
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_linked_grant_claim_atomic
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_linked_grant_claim_atomic
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_owner_grant_claim_atomic
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_owner_grant_claim_atomic
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_step_up_claim_atomic
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

CREATE TRIGGER IF NOT EXISTS authorized_operation_step_up_claim_atomic
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

CREATE TRIGGER IF NOT EXISTS lane_cas_guard_no_delete
BEFORE DELETE ON lane_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'lane_cas_guard is immutable');
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
