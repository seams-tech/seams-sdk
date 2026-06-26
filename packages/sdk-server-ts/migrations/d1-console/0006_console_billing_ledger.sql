CREATE TABLE IF NOT EXISTS console_billing_accounts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  credit_balance_minor INTEGER NOT NULL DEFAULT 0,
  low_balance_threshold_minor INTEGER NOT NULL DEFAULT 2000,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id),
  CHECK (low_balance_threshold_minor >= 0)
);

CREATE TABLE IF NOT EXISTS console_billing_ledger_entries (
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
  CHECK (entry_type IN ('CREDIT_PURCHASE', 'USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT', 'REFUND', 'REVERSAL')),
  CHECK (currency = 'USD'),
  CHECK (actor_type IN ('USER', 'SYSTEM', 'PROVIDER'))
);

CREATE UNIQUE INDEX IF NOT EXISTS console_billing_ledger_entries_idempotency_uidx
  ON console_billing_ledger_entries (namespace, org_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS console_billing_ledger_entries_type_source_uidx
  ON console_billing_ledger_entries (namespace, org_id, entry_type, source_event_id)
  WHERE source_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS console_billing_ledger_entries_org_created_idx
  ON console_billing_ledger_entries (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_billing_ledger_entries_org_month_idx
  ON console_billing_ledger_entries (namespace, org_id, month_utc, entry_type);

CREATE TABLE IF NOT EXISTS console_billing_ledger_postings (
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
    REFERENCES console_billing_ledger_entries(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (direction IN ('DEBIT', 'CREDIT')),
  CHECK (amount_minor >= 0)
);

CREATE INDEX IF NOT EXISTS console_billing_ledger_postings_entry_idx
  ON console_billing_ledger_postings (namespace, org_id, ledger_entry_id);

CREATE TABLE IF NOT EXISTS console_billing_monthly_active_wallets (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  month_utc TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  source_event_id TEXT,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, month_utc, wallet_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS console_billing_monthly_active_wallets_source_uidx
  ON console_billing_monthly_active_wallets (namespace, org_id, source_event_id)
  WHERE source_event_id IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS console_billing_ledger_entries_account_apply
AFTER INSERT ON console_billing_ledger_entries
BEGIN
  INSERT INTO console_billing_accounts
    (namespace, org_id, credit_balance_minor, low_balance_threshold_minor, created_at_ms, updated_at_ms)
  VALUES
    (NEW.namespace, NEW.org_id, 0, 2000, NEW.created_at_ms, NEW.created_at_ms)
  ON CONFLICT(namespace, org_id) DO NOTHING;

  UPDATE console_billing_accounts
     SET credit_balance_minor = credit_balance_minor + NEW.amount_minor,
         updated_at_ms = NEW.created_at_ms
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id;
END;

CREATE TRIGGER IF NOT EXISTS console_billing_ledger_entries_sponsored_postings
AFTER INSERT ON console_billing_ledger_entries
WHEN NEW.entry_type = 'SPONSORED_EXECUTION_DEBIT' AND ABS(NEW.amount_minor) > 0
BEGIN
  INSERT INTO console_billing_ledger_postings
    (namespace, org_id, id, ledger_entry_id, account_code, direction, amount_minor, created_at_ms)
  VALUES
    (NEW.namespace, NEW.org_id, NEW.id || ':debit_prepaid_liability', NEW.id, 'org_prepaid_liability', 'DEBIT', ABS(NEW.amount_minor), NEW.created_at_ms),
    (NEW.namespace, NEW.org_id, NEW.id || ':credit_sponsored_revenue', NEW.id, 'revenue_sponsored_execution', 'CREDIT', ABS(NEW.amount_minor), NEW.created_at_ms);
END;
