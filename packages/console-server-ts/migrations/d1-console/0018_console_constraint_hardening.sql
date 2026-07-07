DROP TRIGGER IF EXISTS billing_ledger_entries_account_apply;
DROP TRIGGER IF EXISTS billing_ledger_entries_sponsored_postings;
DROP INDEX IF EXISTS billing_ledger_entries_idempotency_uidx;
DROP INDEX IF EXISTS billing_ledger_entries_type_source_uidx;
DROP INDEX IF EXISTS billing_ledger_entries_org_created_idx;
DROP INDEX IF EXISTS billing_ledger_entries_org_month_idx;
DROP INDEX IF EXISTS billing_ledger_postings_entry_idx;
DROP INDEX IF EXISTS billing_monthly_active_wallets_source_uidx;
DROP TABLE IF EXISTS billing_accounts_constraints;
DROP TABLE IF EXISTS billing_ledger_entries_constraints;
DROP TABLE IF EXISTS billing_ledger_postings_saved;
DROP TABLE IF EXISTS billing_ledger_postings_constraints;
DROP TABLE IF EXISTS billing_monthly_active_wallets_constraints;

CREATE TABLE billing_ledger_postings_saved AS
SELECT
  namespace,
  org_id,
  id,
  ledger_entry_id,
  account_code,
  direction,
  amount_minor,
  created_at_ms
FROM billing_ledger_postings;

DROP TABLE billing_ledger_postings;

CREATE TABLE billing_accounts_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  credit_balance_minor INTEGER NOT NULL DEFAULT 0,
  low_balance_threshold_minor INTEGER NOT NULL DEFAULT 2000,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (low_balance_threshold_minor >= 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

INSERT INTO billing_accounts_constraints (
  namespace,
  org_id,
  credit_balance_minor,
  low_balance_threshold_minor,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  credit_balance_minor,
  low_balance_threshold_minor,
  created_at_ms,
  updated_at_ms
FROM billing_accounts;

DROP TABLE billing_accounts;
ALTER TABLE billing_accounts_constraints
  RENAME TO billing_accounts;

CREATE TABLE billing_ledger_entries_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  entry_type TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  description TEXT NOT NULL,
  month_utc TEXT,
  related_invoice_id TEXT,
  related_purchase_id TEXT,
  source_event_id TEXT,
  actor_type TEXT NOT NULL,
  actor_user_id TEXT,
  reason_code TEXT,
  note TEXT,
  idempotency_key TEXT,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (entry_type IN ('CREDIT_PURCHASE', 'USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT', 'REFUND', 'REVERSAL')),
  CHECK (amount_minor != 0),
  CHECK (
    (entry_type = 'CREDIT_PURCHASE' AND amount_minor > 0)
    OR (entry_type IN ('USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT') AND amount_minor < 0)
    OR (entry_type IN ('MANUAL_ADJUSTMENT', 'REFUND', 'REVERSAL') AND amount_minor != 0)
  ),
  CHECK (currency = 'USD'),
  CHECK (length(description) > 0),
  CHECK (
    month_utc IS NULL
    OR (
      month_utc GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]'
      AND substr(month_utc, 6, 2) BETWEEN '01' AND '12'
    )
  ),
  CHECK (related_invoice_id IS NULL OR length(related_invoice_id) > 0),
  CHECK (related_purchase_id IS NULL OR length(related_purchase_id) > 0),
  CHECK (source_event_id IS NULL OR length(source_event_id) > 0),
  CHECK (actor_type IN ('USER', 'SYSTEM', 'PROVIDER')),
  CHECK (actor_user_id IS NULL OR length(actor_user_id) > 0),
  CHECK (reason_code IS NULL OR length(reason_code) > 0),
  CHECK (note IS NULL OR length(note) > 0),
  CHECK (idempotency_key IS NULL OR length(idempotency_key) > 0),
  CHECK (created_at_ms > 0)
);

INSERT INTO billing_ledger_entries_constraints (
  namespace,
  org_id,
  id,
  entry_type,
  amount_minor,
  currency,
  description,
  month_utc,
  related_invoice_id,
  related_purchase_id,
  source_event_id,
  actor_type,
  actor_user_id,
  reason_code,
  note,
  idempotency_key,
  created_at_ms
)
SELECT
  namespace,
  org_id,
  id,
  entry_type,
  amount_minor,
  currency,
  description,
  month_utc,
  related_invoice_id,
  related_purchase_id,
  source_event_id,
  actor_type,
  actor_user_id,
  reason_code,
  note,
  idempotency_key,
  created_at_ms
FROM billing_ledger_entries;

DROP TABLE billing_ledger_entries;
ALTER TABLE billing_ledger_entries_constraints
  RENAME TO billing_ledger_entries;

CREATE UNIQUE INDEX billing_ledger_entries_idempotency_uidx
  ON billing_ledger_entries (namespace, org_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX billing_ledger_entries_type_source_uidx
  ON billing_ledger_entries (namespace, org_id, entry_type, source_event_id)
  WHERE source_event_id IS NOT NULL;

CREATE INDEX billing_ledger_entries_org_created_idx
  ON billing_ledger_entries (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX billing_ledger_entries_org_month_idx
  ON billing_ledger_entries (namespace, org_id, month_utc, entry_type);

CREATE TABLE billing_ledger_postings_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  ledger_entry_id TEXT NOT NULL,
  account_code TEXT NOT NULL,
  direction TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id, ledger_entry_id)
    REFERENCES billing_ledger_entries(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (length(ledger_entry_id) > 0),
  CHECK (length(account_code) > 0),
  CHECK (direction IN ('DEBIT', 'CREDIT')),
  CHECK (amount_minor > 0),
  CHECK (created_at_ms > 0)
);

INSERT INTO billing_ledger_postings_constraints (
  namespace,
  org_id,
  id,
  ledger_entry_id,
  account_code,
  direction,
  amount_minor,
  created_at_ms
)
SELECT
  namespace,
  org_id,
  id,
  ledger_entry_id,
  account_code,
  direction,
  amount_minor,
  created_at_ms
FROM billing_ledger_postings_saved;

DROP TABLE billing_ledger_postings_saved;
ALTER TABLE billing_ledger_postings_constraints
  RENAME TO billing_ledger_postings;

CREATE INDEX billing_ledger_postings_entry_idx
  ON billing_ledger_postings (namespace, org_id, ledger_entry_id);

CREATE TABLE billing_monthly_active_wallets_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  month_utc TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  source_event_id TEXT,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, month_utc, wallet_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (
    month_utc GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]'
    AND substr(month_utc, 6, 2) BETWEEN '01' AND '12'
  ),
  CHECK (length(wallet_id) > 0),
  CHECK (source_event_id IS NULL OR length(source_event_id) > 0),
  CHECK (created_at_ms > 0)
);

INSERT INTO billing_monthly_active_wallets_constraints (
  namespace,
  org_id,
  month_utc,
  wallet_id,
  source_event_id,
  created_at_ms
)
SELECT
  namespace,
  org_id,
  month_utc,
  wallet_id,
  source_event_id,
  created_at_ms
FROM billing_monthly_active_wallets;

DROP TABLE billing_monthly_active_wallets;
ALTER TABLE billing_monthly_active_wallets_constraints
  RENAME TO billing_monthly_active_wallets;

CREATE UNIQUE INDEX billing_monthly_active_wallets_source_uidx
  ON billing_monthly_active_wallets (namespace, org_id, source_event_id)
  WHERE source_event_id IS NOT NULL;

CREATE TRIGGER billing_ledger_entries_account_apply
AFTER INSERT ON billing_ledger_entries
BEGIN
  INSERT INTO billing_accounts
    (namespace, org_id, credit_balance_minor, low_balance_threshold_minor, created_at_ms, updated_at_ms)
  VALUES
    (NEW.namespace, NEW.org_id, 0, 2000, NEW.created_at_ms, NEW.created_at_ms)
  ON CONFLICT(namespace, org_id) DO NOTHING;

  UPDATE billing_accounts
     SET credit_balance_minor = credit_balance_minor + NEW.amount_minor,
         updated_at_ms = NEW.created_at_ms
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id;
END;

CREATE TRIGGER billing_ledger_entries_sponsored_postings
AFTER INSERT ON billing_ledger_entries
WHEN NEW.entry_type = 'SPONSORED_EXECUTION_DEBIT' AND ABS(NEW.amount_minor) > 0
BEGIN
  INSERT INTO billing_ledger_postings
    (namespace, org_id, id, ledger_entry_id, account_code, direction, amount_minor, created_at_ms)
  VALUES
    (NEW.namespace, NEW.org_id, NEW.id || ':debit_prepaid_liability', NEW.id, 'org_prepaid_liability', 'DEBIT', ABS(NEW.amount_minor), NEW.created_at_ms),
    (NEW.namespace, NEW.org_id, NEW.id || ':credit_sponsored_revenue', NEW.id, 'revenue_sponsored_execution', 'CREDIT', ABS(NEW.amount_minor), NEW.created_at_ms);
END;

DROP TRIGGER IF EXISTS billing_prepaid_reservations_reserve_insert;
DROP TRIGGER IF EXISTS billing_prepaid_reservations_reserved_exit_update;
DROP INDEX IF EXISTS billing_prepaid_reservations_source_event_idx;
DROP INDEX IF EXISTS billing_prepaid_reservations_namespace_id_idx;
DROP INDEX IF EXISTS billing_prepaid_reservations_org_status_idx;
DROP INDEX IF EXISTS billing_prepaid_reservations_status_idx;

CREATE TABLE billing_prepaid_reservation_summaries_constraints (
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

INSERT INTO billing_prepaid_reservation_summaries_constraints (
  namespace,
  org_id,
  reserved_minor,
  active_reservation_count,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  reserved_minor,
  active_reservation_count,
  created_at_ms,
  updated_at_ms
FROM billing_prepaid_reservation_summaries;

DROP TABLE billing_prepaid_reservation_summaries;
ALTER TABLE billing_prepaid_reservation_summaries_constraints
  RENAME TO billing_prepaid_reservation_summaries;

CREATE TABLE billing_prepaid_reservations_constraints (
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

INSERT INTO billing_prepaid_reservations_constraints (
  namespace,
  org_id,
  id,
  environment_id,
  policy_id,
  source_event_id,
  requested_minor,
  posted_balance_minor,
  settled_minor,
  released_minor,
  status,
  tx_or_execution_ref,
  pricing_version,
  expires_at_ms,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  id,
  environment_id,
  policy_id,
  source_event_id,
  requested_minor,
  posted_balance_minor,
  settled_minor,
  released_minor,
  status,
  tx_or_execution_ref,
  pricing_version,
  expires_at_ms,
  created_at_ms,
  updated_at_ms
FROM billing_prepaid_reservations;

DROP TABLE billing_prepaid_reservations;
ALTER TABLE billing_prepaid_reservations_constraints
  RENAME TO billing_prepaid_reservations;

CREATE UNIQUE INDEX billing_prepaid_reservations_source_event_idx
  ON billing_prepaid_reservations (namespace, org_id, source_event_id);

CREATE UNIQUE INDEX billing_prepaid_reservations_namespace_id_idx
  ON billing_prepaid_reservations (namespace, id);

CREATE INDEX billing_prepaid_reservations_org_status_idx
  ON billing_prepaid_reservations (namespace, org_id, status, expires_at_ms ASC);

CREATE INDEX billing_prepaid_reservations_status_idx
  ON billing_prepaid_reservations (namespace, status, expires_at_ms ASC);

CREATE TRIGGER billing_prepaid_reservations_reserve_insert
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

CREATE TRIGGER billing_prepaid_reservations_reserved_exit_update
AFTER UPDATE OF status ON billing_prepaid_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status IN ('SETTLED', 'RELEASED', 'EXPIRED')
BEGIN
  UPDATE billing_prepaid_reservation_summaries
     SET reserved_minor = MAX(0, reserved_minor - OLD.requested_minor),
         active_reservation_count = MAX(0, active_reservation_count - 1),
         updated_at_ms = NEW.updated_at_ms
   WHERE namespace = NEW.namespace AND org_id = NEW.org_id;
END;

DROP INDEX IF EXISTS sponsored_call_idempotency_key_idx;
DROP INDEX IF EXISTS sponsored_call_org_created_idx;
DROP INDEX IF EXISTS sponsored_call_org_environment_created_idx;
DROP INDEX IF EXISTS sponsored_call_org_policy_created_idx;

CREATE TABLE IF NOT EXISTS sponsored_call_records_required_idempotency (
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

INSERT INTO sponsored_call_records_required_idempotency (
  namespace,
  org_id,
  id,
  environment_id,
  api_key_id,
  api_key_kind,
  route,
  policy_id,
  policy_name_at_event,
  template_id,
  chain_family,
  intent_kind,
  executor_kind,
  account_ref,
  target_ref,
  sponsor_ref,
  tx_or_execution_ref,
  receipt_status,
  fee_unit,
  fee_amount,
  details_json,
  estimated_spend_minor,
  settled_spend_minor,
  pricing_version,
  pricing_source,
  billing_ledger_entry_id,
  prepaid_reservation_id,
  charged,
  charged_reason,
  settled_at_iso,
  error_code,
  error_message,
  idempotency_key,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  id,
  environment_id,
  api_key_id,
  api_key_kind,
  route,
  policy_id,
  policy_name_at_event,
  template_id,
  chain_family,
  intent_kind,
  executor_kind,
  account_ref,
  target_ref,
  sponsor_ref,
  tx_or_execution_ref,
  receipt_status,
  fee_unit,
  fee_amount,
  details_json,
  estimated_spend_minor,
  settled_spend_minor,
  pricing_version,
  pricing_source,
  billing_ledger_entry_id,
  prepaid_reservation_id,
  charged,
  charged_reason,
  settled_at_iso,
  error_code,
  error_message,
  idempotency_key,
  created_at_ms,
  updated_at_ms
FROM sponsored_call_records;

DROP TABLE sponsored_call_records;
ALTER TABLE sponsored_call_records_required_idempotency
  RENAME TO sponsored_call_records;

CREATE UNIQUE INDEX sponsored_call_idempotency_key_idx
  ON sponsored_call_records (namespace, org_id, idempotency_key);

CREATE INDEX sponsored_call_org_created_idx
  ON sponsored_call_records (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX sponsored_call_org_environment_created_idx
  ON sponsored_call_records (namespace, org_id, environment_id, created_at_ms DESC, id DESC);

CREATE INDEX sponsored_call_org_policy_created_idx
  ON sponsored_call_records (namespace, org_id, policy_id, created_at_ms DESC, id DESC);

DROP INDEX IF EXISTS webhook_endpoint_categories_lookup_idx;
DROP INDEX IF EXISTS webhook_endpoints_org_created_idx;
DROP TABLE IF EXISTS webhook_endpoint_categories_saved;
DROP TABLE IF EXISTS webhook_endpoint_categories_constraints;
DROP TABLE IF EXISTS webhook_endpoints_constraints;

CREATE TABLE webhook_endpoint_categories_saved (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  category TEXT NOT NULL
);

INSERT INTO webhook_endpoint_categories_saved (
  namespace,
  org_id,
  endpoint_id,
  category
)
SELECT
  namespace,
  org_id,
  endpoint_id,
  category
FROM webhook_endpoint_categories;

DROP TABLE webhook_endpoint_categories;

CREATE TABLE webhook_endpoints_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  url TEXT NOT NULL,
  status TEXT NOT NULL,
  signing_secret_ciphertext_b64u TEXT NOT NULL,
  signing_secret_key_id TEXT NOT NULL,
  signing_secret_envelope_version TEXT NOT NULL,
  secret_version INTEGER NOT NULL,
  secret_preview TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (url GLOB 'http://*' OR url GLOB 'https://*'),
  CHECK (status IN ('ACTIVE', 'DISABLED')),
  CHECK (length(signing_secret_ciphertext_b64u) > 0),
  CHECK (signing_secret_ciphertext_b64u NOT GLOB '*[^A-Za-z0-9_-]*'),
  CHECK (length(signing_secret_key_id) > 0),
  CHECK (length(signing_secret_envelope_version) > 0),
  CHECK (secret_version > 0),
  CHECK (length(secret_preview) > 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

INSERT INTO webhook_endpoints_constraints (
  namespace,
  org_id,
  id,
  url,
  status,
  signing_secret_ciphertext_b64u,
  signing_secret_key_id,
  signing_secret_envelope_version,
  secret_version,
  secret_preview,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  id,
  url,
  status,
  signing_secret_ciphertext_b64u,
  signing_secret_key_id,
  signing_secret_envelope_version,
  secret_version,
  secret_preview,
  created_at_ms,
  updated_at_ms
FROM webhook_endpoints;

DROP TABLE webhook_endpoints;
ALTER TABLE webhook_endpoints_constraints
  RENAME TO webhook_endpoints;

CREATE TABLE webhook_endpoint_categories_constraints (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  category TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, endpoint_id, category),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(endpoint_id) > 0),
  CHECK (category IN ('wallet', 'policy', 'auth', 'tx', 'billing', 'session')),
  FOREIGN KEY (namespace, org_id, endpoint_id)
    REFERENCES webhook_endpoints(namespace, org_id, id)
    ON DELETE CASCADE
);

INSERT INTO webhook_endpoint_categories_constraints (
  namespace,
  org_id,
  endpoint_id,
  category
)
SELECT
  namespace,
  org_id,
  endpoint_id,
  category
FROM webhook_endpoint_categories_saved;

ALTER TABLE webhook_endpoint_categories_constraints
  RENAME TO webhook_endpoint_categories;

DROP TABLE webhook_endpoint_categories_saved;

CREATE INDEX webhook_endpoints_org_created_idx
  ON webhook_endpoints (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX webhook_endpoint_categories_lookup_idx
  ON webhook_endpoint_categories (namespace, org_id, category, endpoint_id);

DROP INDEX IF EXISTS runtime_snapshots_scope_version_idx;
DROP INDEX IF EXISTS runtime_snapshots_env_version_idx;
DROP INDEX IF EXISTS runtime_snapshot_outbox_visible_idx;
DROP INDEX IF EXISTS runtime_snapshot_outbox_claim_idx;
DROP TABLE IF EXISTS runtime_snapshots_constraints;
DROP TABLE IF EXISTS runtime_snapshot_outbox_constraints;

CREATE TABLE runtime_snapshots_constraints (
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

INSERT INTO runtime_snapshots_constraints (
  namespace,
  org_id,
  project_id,
  environment_id,
  snapshot_id,
  version,
  effective_at_ms,
  checksum,
  payload_json,
  created_at_ms,
  created_by
)
SELECT
  namespace,
  org_id,
  project_id,
  environment_id,
  snapshot_id,
  version,
  effective_at_ms,
  checksum,
  payload_json,
  created_at_ms,
  created_by
FROM runtime_snapshots;

DROP TABLE runtime_snapshots;
ALTER TABLE runtime_snapshots_constraints
  RENAME TO runtime_snapshots;

CREATE INDEX runtime_snapshots_scope_version_idx
  ON runtime_snapshots (
    namespace,
    org_id,
    project_id,
    environment_id,
    version DESC,
    created_at_ms DESC
  );

CREATE INDEX runtime_snapshots_env_version_idx
  ON runtime_snapshots (
    namespace,
    org_id,
    environment_id,
    version DESC,
    created_at_ms DESC
  );

CREATE TABLE runtime_snapshot_outbox_constraints (
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

INSERT INTO runtime_snapshot_outbox_constraints (
  namespace,
  org_id,
  project_id,
  environment_id,
  event_id,
  event_type,
  snapshot_id,
  snapshot_version,
  payload_json,
  status,
  attempt_count,
  available_at_ms,
  claimed_by,
  claim_expires_at_ms,
  last_error,
  created_at_ms,
  updated_at_ms,
  dispatched_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  environment_id,
  event_id,
  event_type,
  snapshot_id,
  snapshot_version,
  payload_json,
  status,
  attempt_count,
  available_at_ms,
  claimed_by,
  claim_expires_at_ms,
  last_error,
  created_at_ms,
  updated_at_ms,
  dispatched_at_ms
FROM runtime_snapshot_outbox;

DROP TABLE runtime_snapshot_outbox;
ALTER TABLE runtime_snapshot_outbox_constraints
  RENAME TO runtime_snapshot_outbox;

CREATE INDEX runtime_snapshot_outbox_visible_idx
  ON runtime_snapshot_outbox (
    namespace,
    org_id,
    status,
    available_at_ms ASC,
    created_at_ms ASC,
    event_id ASC
  );

CREATE INDEX runtime_snapshot_outbox_claim_idx
  ON runtime_snapshot_outbox (
    namespace,
    org_id,
    claimed_by,
    claim_expires_at_ms
  );
