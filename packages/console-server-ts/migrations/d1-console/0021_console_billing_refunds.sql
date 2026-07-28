PRAGMA defer_foreign_keys = ON;

DROP TRIGGER IF EXISTS billing_ledger_entries_account_apply;
DROP TRIGGER IF EXISTS billing_ledger_entries_sponsored_postings;
DROP TRIGGER IF EXISTS billing_ledger_entries_balanced_postings;
DROP INDEX IF EXISTS billing_ledger_entries_idempotency_uidx;
DROP INDEX IF EXISTS billing_ledger_entries_type_source_uidx;
DROP INDEX IF EXISTS billing_ledger_entries_org_created_idx;
DROP INDEX IF EXISTS billing_ledger_entries_org_month_idx;
DROP INDEX IF EXISTS billing_ledger_postings_entry_idx;

DROP TABLE billing_ledger_postings;

CREATE TABLE billing_ledger_entries_next (
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
  CHECK (
    entry_type IN (
      'CREDIT_PURCHASE',
      'USAGE_DEBIT',
      'SPONSORED_EXECUTION_DEBIT',
      'MANUAL_ADJUSTMENT',
      'REFUND',
      'DISPUTE_OPENED',
      'DISPUTE_WON'
    )
  ),
  CHECK (
    (entry_type IN ('CREDIT_PURCHASE', 'DISPUTE_WON') AND amount_minor > 0)
    OR (
      entry_type IN (
        'USAGE_DEBIT',
        'SPONSORED_EXECUTION_DEBIT',
        'REFUND',
        'DISPUTE_OPENED'
      )
      AND amount_minor < 0
    )
    OR (entry_type = 'MANUAL_ADJUSTMENT' AND amount_minor != 0)
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

INSERT INTO billing_ledger_entries_next (
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
  CASE WHEN entry_type = 'REVERSAL' THEN 'MANUAL_ADJUSTMENT' ELSE entry_type END,
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
ALTER TABLE billing_ledger_entries_next RENAME TO billing_ledger_entries;

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

CREATE TABLE billing_ledger_postings (
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
  CHECK (
    account_code IN (
      'org_prepaid_liability',
      'stripe_cash_clearing',
      'revenue_usage',
      'revenue_sponsored_execution',
      'manual_adjustment_clearing',
      'stripe_dispute_clearing'
    )
  ),
  CHECK (direction IN ('DEBIT', 'CREDIT')),
  CHECK (amount_minor > 0),
  CHECK (created_at_ms > 0)
);

CREATE INDEX billing_ledger_postings_entry_idx
  ON billing_ledger_postings (namespace, org_id, ledger_entry_id);

INSERT INTO billing_ledger_postings (
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
  id || ':debit',
  id,
  CASE
    WHEN amount_minor < 0 THEN 'org_prepaid_liability'
    WHEN entry_type IN ('CREDIT_PURCHASE', 'REFUND') THEN 'stripe_cash_clearing'
    WHEN entry_type IN ('DISPUTE_OPENED', 'DISPUTE_WON') THEN 'stripe_dispute_clearing'
    WHEN entry_type = 'USAGE_DEBIT' THEN 'revenue_usage'
    WHEN entry_type = 'SPONSORED_EXECUTION_DEBIT' THEN 'revenue_sponsored_execution'
    ELSE 'manual_adjustment_clearing'
  END,
  'DEBIT',
  ABS(amount_minor),
  created_at_ms
FROM billing_ledger_entries
UNION ALL
SELECT
  namespace,
  org_id,
  id || ':credit',
  id,
  CASE
    WHEN amount_minor > 0 THEN 'org_prepaid_liability'
    WHEN entry_type IN ('CREDIT_PURCHASE', 'REFUND') THEN 'stripe_cash_clearing'
    WHEN entry_type IN ('DISPUTE_OPENED', 'DISPUTE_WON') THEN 'stripe_dispute_clearing'
    WHEN entry_type = 'USAGE_DEBIT' THEN 'revenue_usage'
    WHEN entry_type = 'SPONSORED_EXECUTION_DEBIT' THEN 'revenue_sponsored_execution'
    ELSE 'manual_adjustment_clearing'
  END,
  'CREDIT',
  ABS(amount_minor),
  created_at_ms
FROM billing_ledger_entries;

CREATE TRIGGER billing_ledger_entries_balanced_postings
AFTER INSERT ON billing_ledger_entries
BEGIN
  INSERT INTO billing_ledger_postings (
    namespace,
    org_id,
    id,
    ledger_entry_id,
    account_code,
    direction,
    amount_minor,
    created_at_ms
  )
  VALUES
    (
      NEW.namespace,
      NEW.org_id,
      NEW.id || ':debit',
      NEW.id,
      CASE
        WHEN NEW.amount_minor < 0 THEN 'org_prepaid_liability'
        WHEN NEW.entry_type IN ('CREDIT_PURCHASE', 'REFUND') THEN 'stripe_cash_clearing'
        WHEN NEW.entry_type IN ('DISPUTE_OPENED', 'DISPUTE_WON') THEN 'stripe_dispute_clearing'
        WHEN NEW.entry_type = 'USAGE_DEBIT' THEN 'revenue_usage'
        WHEN NEW.entry_type = 'SPONSORED_EXECUTION_DEBIT' THEN 'revenue_sponsored_execution'
        ELSE 'manual_adjustment_clearing'
      END,
      'DEBIT',
      ABS(NEW.amount_minor),
      NEW.created_at_ms
    ),
    (
      NEW.namespace,
      NEW.org_id,
      NEW.id || ':credit',
      NEW.id,
      CASE
        WHEN NEW.amount_minor > 0 THEN 'org_prepaid_liability'
        WHEN NEW.entry_type IN ('CREDIT_PURCHASE', 'REFUND') THEN 'stripe_cash_clearing'
        WHEN NEW.entry_type IN ('DISPUTE_OPENED', 'DISPUTE_WON') THEN 'stripe_dispute_clearing'
        WHEN NEW.entry_type = 'USAGE_DEBIT' THEN 'revenue_usage'
        WHEN NEW.entry_type = 'SPONSORED_EXECUTION_DEBIT' THEN 'revenue_sponsored_execution'
        ELSE 'manual_adjustment_clearing'
      END,
      'CREDIT',
      ABS(NEW.amount_minor),
      NEW.created_at_ms
    );
END;

CREATE TABLE billing_accounts_next (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
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

INSERT INTO billing_accounts_next (
  namespace,
  org_id,
  low_balance_threshold_minor,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  low_balance_threshold_minor,
  created_at_ms,
  updated_at_ms
FROM billing_accounts;

DROP TABLE billing_accounts;
ALTER TABLE billing_accounts_next RENAME TO billing_accounts;

DROP INDEX IF EXISTS billing_credit_purchases_checkout_uidx;
DROP INDEX IF EXISTS billing_credit_purchases_namespace_checkout_idx;
DROP INDEX IF EXISTS billing_credit_purchases_namespace_customer_idx;

CREATE TABLE billing_credit_purchases_next (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  credit_pack_id TEXT NOT NULL,
  status TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  provider TEXT NOT NULL,
  provider_checkout_session_ref TEXT,
  provider_customer_ref TEXT,
  provider_payment_ref TEXT,
  related_invoice_id TEXT,
  settled_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (credit_pack_id IN ('usd_10', 'usd_25', 'usd_50')),
  CHECK (status IN ('PENDING', 'SETTLED', 'CANCELED')),
  CHECK (amount_minor > 0),
  CHECK (currency = 'USD'),
  CHECK (provider = 'stripe'),
  CHECK (
    (
      status = 'SETTLED'
      AND provider_checkout_session_ref IS NOT NULL
      AND provider_customer_ref IS NOT NULL
      AND provider_payment_ref IS NOT NULL
      AND related_invoice_id IS NOT NULL
      AND settled_at_ms IS NOT NULL
    )
    OR (
      status IN ('PENDING', 'CANCELED')
      AND provider_payment_ref IS NULL
      AND related_invoice_id IS NULL
      AND settled_at_ms IS NULL
    )
  )
);

INSERT INTO billing_credit_purchases_next (
  namespace,
  org_id,
  id,
  credit_pack_id,
  status,
  amount_minor,
  currency,
  provider,
  provider_checkout_session_ref,
  provider_customer_ref,
  provider_payment_ref,
  related_invoice_id,
  settled_at_ms,
  created_at_ms,
  updated_at_ms
)
SELECT
  namespace,
  org_id,
  id,
  credit_pack_id,
  status,
  amount_minor,
  currency,
  provider,
  provider_checkout_session_ref,
  provider_customer_ref,
  CASE
    WHEN status = 'SETTLED' THEN 'legacy:' || provider_checkout_session_ref
    ELSE NULL
  END,
  related_invoice_id,
  settled_at_ms,
  created_at_ms,
  updated_at_ms
FROM billing_credit_purchases;

DROP TABLE billing_credit_purchases;
ALTER TABLE billing_credit_purchases_next RENAME TO billing_credit_purchases;

CREATE UNIQUE INDEX billing_credit_purchases_checkout_uidx
  ON billing_credit_purchases (namespace, org_id, provider_checkout_session_ref)
  WHERE provider_checkout_session_ref IS NOT NULL;

CREATE INDEX billing_credit_purchases_namespace_checkout_idx
  ON billing_credit_purchases (namespace, provider_checkout_session_ref)
  WHERE provider_checkout_session_ref IS NOT NULL;

CREATE INDEX billing_credit_purchases_namespace_customer_idx
  ON billing_credit_purchases (namespace, provider_customer_ref)
  WHERE provider_customer_ref IS NOT NULL;

CREATE UNIQUE INDEX billing_credit_purchases_payment_uidx
  ON billing_credit_purchases (namespace, provider_payment_ref)
  WHERE provider_payment_ref IS NOT NULL;

CREATE TABLE billing_refunds (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  purchase_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  reason TEXT NOT NULL,
  origin TEXT NOT NULL,
  requester_user_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  status TEXT NOT NULL,
  provider_refund_id TEXT,
  failure_code TEXT,
  journal_entry_id TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id, purchase_id)
    REFERENCES billing_credit_purchases(namespace, org_id, id),
  FOREIGN KEY (namespace, org_id, journal_entry_id)
    REFERENCES billing_ledger_entries(namespace, org_id, id),
  CHECK (amount_minor > 0),
  CHECK (currency = 'USD'),
  CHECK (length(reason) > 0),
  CHECK (origin IN ('console', 'provider')),
  CHECK (length(requester_user_id) > 0),
  CHECK (length(idempotency_key) > 0),
  CHECK (
    (
      status = 'requested'
      AND provider_refund_id IS NULL
      AND failure_code IS NULL
      AND journal_entry_id IS NULL
    )
    OR (
      status = 'provider_pending'
      AND provider_refund_id IS NOT NULL
      AND failure_code IS NULL
      AND journal_entry_id IS NULL
    )
    OR (
      status = 'succeeded'
      AND provider_refund_id IS NOT NULL
      AND failure_code IS NULL
      AND journal_entry_id IS NOT NULL
    )
    OR (
      status = 'failed'
      AND failure_code IS NOT NULL
      AND journal_entry_id IS NULL
    )
    OR (
      status = 'canceled'
      AND provider_refund_id IS NOT NULL
      AND failure_code IS NULL
      AND journal_entry_id IS NULL
    )
  ),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE UNIQUE INDEX billing_refunds_idempotency_uidx
  ON billing_refunds (namespace, org_id, idempotency_key);

CREATE UNIQUE INDEX billing_refunds_provider_uidx
  ON billing_refunds (namespace, provider_refund_id)
  WHERE provider_refund_id IS NOT NULL;

CREATE INDEX billing_refunds_purchase_idx
  ON billing_refunds (namespace, org_id, purchase_id, created_at_ms DESC);

CREATE TABLE billing_disputes (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  purchase_id TEXT NOT NULL,
  provider_dispute_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  status TEXT NOT NULL,
  opened_journal_entry_id TEXT NOT NULL,
  resolution_journal_entry_id TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id, purchase_id)
    REFERENCES billing_credit_purchases(namespace, org_id, id),
  FOREIGN KEY (namespace, org_id, opened_journal_entry_id)
    REFERENCES billing_ledger_entries(namespace, org_id, id),
  FOREIGN KEY (namespace, org_id, resolution_journal_entry_id)
    REFERENCES billing_ledger_entries(namespace, org_id, id),
  CHECK (length(provider_dispute_id) > 0),
  CHECK (amount_minor > 0),
  CHECK (
    (status IN ('open', 'lost') AND resolution_journal_entry_id IS NULL)
    OR (status = 'won' AND resolution_journal_entry_id IS NOT NULL)
  ),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE UNIQUE INDEX billing_disputes_provider_uidx
  ON billing_disputes (namespace, provider_dispute_id);
