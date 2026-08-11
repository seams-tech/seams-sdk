-- R103 durable owner planning snapshot. The row is the authoritative,
-- request-scoped input to the owner-authorization and target-planning ports.
-- Browser source projections are retained only after registration validation.
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

CREATE INDEX IF NOT EXISTS linked_device_owner_planning_snapshots_wallet_idx
  ON linked_device_owner_planning_snapshots(
    namespace, org_id, project_id, env_id, wallet_id, expires_at_ms
  );

CREATE UNIQUE INDEX IF NOT EXISTS linked_device_owner_planning_snapshots_operation_idx
  ON linked_device_owner_planning_snapshots(
    namespace, org_id, project_id, env_id, operation_id
  );
