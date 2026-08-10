-- R102 Gateway state. These tables contain protocol metadata, digests, and
-- lifecycle facts only. Holder/server ciphertext and private material remain
-- in their respective participant stores.
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

CREATE INDEX IF NOT EXISTS lane_enrollments_wallet_idx
  ON lane_enrollments(namespace, org_id, project_id, env_id, wallet_id, updated_at_ms);

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

CREATE INDEX IF NOT EXISTS lane_protocol_operations_enrollment_idx
  ON lane_protocol_operations(namespace, org_id, project_id, env_id, enrollment_id, operation_id);

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
  CHECK (state IN ('pending_visibility', 'active', 'retired', 'revoked')),
  CHECK (lane_kind IN ('owner_passkey', 'owner_email_otp', 'linked_device', 'delegated_execution', 'recovery', 'break_glass')),
  CHECK (length(command_digest_b64u) > 0),
  CHECK (version > 0),
  CHECK (key_family IN ('ed25519', 'ecdsa_secp256k1')),
  CHECK (created_at_ms >= 0 AND updated_at_ms >= created_at_ms)
);

CREATE INDEX IF NOT EXISTS lane_product_epochs_wallet_active_idx
  ON lane_product_epochs(namespace, org_id, project_id, env_id, wallet_id, state, updated_at_ms);

CREATE UNIQUE INDEX IF NOT EXISTS lane_product_epochs_one_active_idx
  ON lane_product_epochs(namespace, org_id, project_id, env_id, wallet_key_id, lane_id)
  WHERE state = 'active';

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

CREATE TABLE IF NOT EXISTS lane_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);

INSERT OR IGNORE INTO lane_cas_guard (guard_id) VALUES (1);

CREATE TRIGGER IF NOT EXISTS lane_cas_guard_no_delete
BEFORE DELETE ON lane_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'lane_cas_guard is immutable');
END;
