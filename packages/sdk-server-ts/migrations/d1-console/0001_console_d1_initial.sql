CREATE TABLE IF NOT EXISTS billing_prepaid_reservation_summaries (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  reserved_minor INTEGER NOT NULL DEFAULT 0,
  active_reservation_count INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (reserved_minor >= 0),
  CHECK (active_reservation_count >= 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE IF NOT EXISTS billing_prepaid_reservations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  policy_id TEXT,
  source_event_id TEXT NOT NULL,
  requested_minor INTEGER NOT NULL,
  posted_balance_minor INTEGER NOT NULL,
  settled_minor INTEGER NOT NULL DEFAULT 0,
  released_minor INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  tx_or_execution_ref TEXT,
  pricing_version TEXT,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (length(environment_id) > 0),
  CHECK (length(source_event_id) > 0),
  CHECK (requested_minor > 0),
  CHECK (posted_balance_minor >= 0),
  CHECK (settled_minor >= 0),
  CHECK (released_minor >= 0),
  CHECK (status IN ('RESERVED', 'SETTLED', 'RELEASED', 'EXPIRED')),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (
    (status = 'RESERVED' AND settled_minor = 0 AND released_minor = 0 AND tx_or_execution_ref IS NULL AND pricing_version IS NULL)
    OR (status = 'SETTLED' AND released_minor = CASE WHEN requested_minor > settled_minor THEN requested_minor - settled_minor ELSE 0 END)
    OR (status IN ('RELEASED', 'EXPIRED') AND settled_minor = 0 AND released_minor = requested_minor)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS billing_prepaid_reservations_source_event_idx
  ON billing_prepaid_reservations (namespace, org_id, source_event_id);

CREATE UNIQUE INDEX IF NOT EXISTS billing_prepaid_reservations_namespace_id_idx
  ON billing_prepaid_reservations (namespace, id);

CREATE INDEX IF NOT EXISTS billing_prepaid_reservations_org_status_idx
  ON billing_prepaid_reservations (namespace, org_id, status, expires_at_ms ASC);

CREATE INDEX IF NOT EXISTS billing_prepaid_reservations_status_idx
  ON billing_prepaid_reservations (namespace, status, expires_at_ms ASC);

CREATE TRIGGER IF NOT EXISTS billing_prepaid_reservations_reserve_insert
BEFORE INSERT ON billing_prepaid_reservations
WHEN NEW.status = 'RESERVED'
BEGIN
  INSERT INTO billing_prepaid_reservation_summaries
    (namespace, org_id, reserved_minor, active_reservation_count, created_at_ms, updated_at_ms)
  VALUES
    (NEW.namespace, NEW.org_id, 0, 0, NEW.created_at_ms, NEW.created_at_ms)
  ON CONFLICT(namespace, org_id) DO NOTHING;

  SELECT CASE
    WHEN (
      SELECT reserved_minor
      FROM billing_prepaid_reservation_summaries
      WHERE namespace = NEW.namespace AND org_id = NEW.org_id
    ) + NEW.requested_minor > NEW.posted_balance_minor
    THEN RAISE(ABORT, 'prepaid_balance_insufficient')
  END;

  UPDATE billing_prepaid_reservation_summaries
     SET reserved_minor = reserved_minor + NEW.requested_minor,
         active_reservation_count = active_reservation_count + 1,
         updated_at_ms = NEW.created_at_ms
   WHERE namespace = NEW.namespace AND org_id = NEW.org_id;
END;

CREATE TRIGGER IF NOT EXISTS billing_prepaid_reservations_reserved_exit_update
AFTER UPDATE OF status ON billing_prepaid_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status IN ('SETTLED', 'RELEASED', 'EXPIRED')
BEGIN
  UPDATE billing_prepaid_reservation_summaries
     SET reserved_minor = MAX(0, reserved_minor - OLD.requested_minor),
         active_reservation_count = MAX(0, active_reservation_count - 1),
         updated_at_ms = NEW.updated_at_ms
   WHERE namespace = NEW.namespace AND org_id = NEW.org_id;
END;

CREATE TABLE IF NOT EXISTS sponsored_call_records (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  api_key_id TEXT NOT NULL,
  api_key_kind TEXT NOT NULL,
  route TEXT NOT NULL,
  policy_id TEXT NOT NULL DEFAULT '',
  policy_name_at_event TEXT,
  template_id TEXT,
  chain_family TEXT NOT NULL DEFAULT 'evm',
  intent_kind TEXT NOT NULL DEFAULT 'evm_call',
  executor_kind TEXT NOT NULL DEFAULT 'evm_eoa',
  account_ref TEXT NOT NULL DEFAULT '',
  target_ref TEXT NOT NULL DEFAULT '',
  sponsor_ref TEXT NOT NULL DEFAULT '',
  tx_or_execution_ref TEXT,
  receipt_status TEXT NOT NULL,
  fee_unit TEXT NOT NULL DEFAULT 'wei',
  fee_amount TEXT NOT NULL DEFAULT '0',
  details_json TEXT NOT NULL DEFAULT '{}',
  estimated_spend_minor INTEGER,
  settled_spend_minor INTEGER,
  pricing_version TEXT,
  pricing_source TEXT,
  billing_ledger_entry_id TEXT,
  prepaid_reservation_id TEXT,
  charged INTEGER NOT NULL DEFAULT 0,
  charged_reason TEXT,
  settled_at_iso TEXT,
  error_code TEXT,
  error_message TEXT,
  idempotency_key TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (api_key_kind IN ('secret_key', 'publishable_key')),
  CHECK (receipt_status IN ('success', 'reverted', 'broadcast_failed', 'rpc_rejected')),
  CHECK (chain_family IN ('evm', 'near')),
  CHECK (intent_kind IN ('evm_call', 'near_delegate')),
  CHECK (executor_kind IN ('evm_eoa', 'near_delegate')),
  CHECK (fee_unit IN ('wei', 'yocto_near')),
  CHECK (charged IN (0, 1)),
  CHECK (length(idempotency_key) > 0),
  CHECK (json_valid(details_json)),
  CHECK (estimated_spend_minor IS NULL OR estimated_spend_minor >= 0),
  CHECK (settled_spend_minor IS NULL OR settled_spend_minor >= 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE UNIQUE INDEX IF NOT EXISTS sponsored_call_idempotency_key_idx
  ON sponsored_call_records (namespace, org_id, idempotency_key);

CREATE INDEX IF NOT EXISTS sponsored_call_org_created_idx
  ON sponsored_call_records (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS sponsored_call_org_environment_created_idx
  ON sponsored_call_records (namespace, org_id, environment_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS sponsored_call_org_policy_created_idx
  ON sponsored_call_records (namespace, org_id, policy_id, created_at_ms DESC, id DESC);

CREATE TABLE IF NOT EXISTS runtime_snapshots (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  environment_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  effective_at_ms INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, snapshot_id),
  UNIQUE (namespace, org_id, project_id, environment_id, version),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(environment_id) > 0),
  CHECK (length(snapshot_id) > 0),
  CHECK (version >= 1),
  CHECK (effective_at_ms > 0),
  CHECK (length(checksum) > 0),
  CHECK (length(payload_json) > 0),
  CHECK (json_valid(payload_json)),
  CHECK (created_at_ms > 0),
  CHECK (length(created_by) > 0)
);

CREATE INDEX IF NOT EXISTS runtime_snapshots_scope_version_idx
  ON runtime_snapshots (
    namespace,
    org_id,
    project_id,
    environment_id,
    version DESC,
    created_at_ms DESC
  );

CREATE INDEX IF NOT EXISTS runtime_snapshots_env_version_idx
  ON runtime_snapshots (
    namespace,
    org_id,
    environment_id,
    version DESC,
    created_at_ms DESC
  );

CREATE TABLE IF NOT EXISTS runtime_snapshot_outbox (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  environment_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  snapshot_version INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  available_at_ms INTEGER NOT NULL,
  claimed_by TEXT,
  claim_expires_at_ms INTEGER,
  last_error TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  dispatched_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, event_id),
  UNIQUE (namespace, org_id, snapshot_id, snapshot_version, event_type),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(environment_id) > 0),
  CHECK (length(event_id) > 0),
  CHECK (event_type IN ('RUNTIME_SNAPSHOT_PUBLISHED_V1')),
  CHECK (length(snapshot_id) > 0),
  CHECK (status IN ('PENDING', 'DISPATCHED', 'DEAD_LETTER')),
  CHECK (snapshot_version >= 1),
  CHECK (json_valid(payload_json)),
  CHECK (attempt_count >= 0),
  CHECK (available_at_ms > 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (dispatched_at_ms IS NULL OR dispatched_at_ms >= created_at_ms),
  CHECK (last_error IS NULL OR length(last_error) > 0),
  CHECK (
    (claimed_by IS NULL AND claim_expires_at_ms IS NULL)
    OR
    (
      claimed_by IS NOT NULL
      AND length(claimed_by) > 0
      AND COALESCE(claim_expires_at_ms > updated_at_ms, 0)
    )
  ),
  CHECK (
    (
      status = 'PENDING'
      AND dispatched_at_ms IS NULL
    )
    OR
    (
      status = 'DISPATCHED'
      AND claimed_by IS NULL
      AND claim_expires_at_ms IS NULL
      AND dispatched_at_ms IS NOT NULL
      AND last_error IS NULL
      AND attempt_count >= 1
    )
    OR
    (
      status = 'DEAD_LETTER'
      AND claimed_by IS NULL
      AND claim_expires_at_ms IS NULL
      AND dispatched_at_ms IS NULL
      AND last_error IS NOT NULL
      AND attempt_count >= 1
    )
  )
);

CREATE INDEX IF NOT EXISTS runtime_snapshot_outbox_visible_idx
  ON runtime_snapshot_outbox (
    namespace,
    org_id,
    status,
    available_at_ms ASC,
    created_at_ms ASC,
    event_id ASC
  );

CREATE INDEX IF NOT EXISTS runtime_snapshot_outbox_claim_idx
  ON runtime_snapshot_outbox (
    namespace,
    org_id,
    claimed_by,
    claim_expires_at_ms
  );
