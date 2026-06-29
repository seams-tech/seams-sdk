CREATE TABLE IF NOT EXISTS billing_credit_purchases (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  credit_pack_id TEXT NOT NULL,
  status TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  provider TEXT NOT NULL,
  provider_checkout_session_ref TEXT NOT NULL,
  provider_customer_ref TEXT,
  related_invoice_id TEXT,
  settled_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (status IN ('PENDING', 'SETTLED', 'CANCELED')),
  CHECK (amount_minor > 0),
  CHECK (currency = 'USD'),
  CHECK (provider = 'stripe')
);

CREATE UNIQUE INDEX IF NOT EXISTS billing_credit_purchases_checkout_uidx
  ON billing_credit_purchases (namespace, org_id, provider_checkout_session_ref);

CREATE INDEX IF NOT EXISTS billing_credit_purchases_namespace_checkout_idx
  ON billing_credit_purchases (namespace, provider_checkout_session_ref);

CREATE INDEX IF NOT EXISTS billing_credit_purchases_namespace_customer_idx
  ON billing_credit_purchases (namespace, provider_customer_ref)
  WHERE provider_customer_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS invoices (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  document_type TEXT NOT NULL,
  status TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  amount_due_minor INTEGER NOT NULL,
  amount_paid_minor INTEGER NOT NULL,
  period_month_utc TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  due_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (document_type IN ('PURCHASE_RECEIPT', 'USAGE_STATEMENT')),
  CHECK (status IN ('OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE')),
  CHECK (currency = 'USD'),
  CHECK (amount_due_minor >= 0),
  CHECK (amount_paid_minor >= 0)
);

CREATE INDEX IF NOT EXISTS invoices_org_created_idx
  ON invoices (namespace, org_id, created_at_ms DESC, id DESC);

CREATE UNIQUE INDEX IF NOT EXISTS invoices_org_statement_month_uidx
  ON invoices (namespace, org_id, document_type, period_month_utc)
  WHERE document_type = 'USAGE_STATEMENT';

CREATE TABLE IF NOT EXISTS invoice_line_items (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  period_month_utc TEXT NOT NULL,
  item_type TEXT NOT NULL,
  description TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  unit_amount_minor INTEGER NOT NULL,
  amount_minor INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id, invoice_id)
    REFERENCES invoices(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (item_type IN ('CREDIT_TOP_UP', 'MAW_USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT')),
  CHECK (quantity > 0),
  CHECK (unit_amount_minor >= 0),
  CHECK (amount_minor >= 0)
);

CREATE INDEX IF NOT EXISTS invoice_line_items_invoice_idx
  ON invoice_line_items (namespace, org_id, invoice_id);

CREATE TABLE IF NOT EXISTS stripe_webhook_events (
  namespace TEXT NOT NULL,
  event_id TEXT NOT NULL,
  provider_ref TEXT NOT NULL,
  org_id TEXT NOT NULL,
  processed_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, event_id)
);

CREATE INDEX IF NOT EXISTS stripe_webhook_events_org_idx
  ON stripe_webhook_events (namespace, org_id, processed_at_ms DESC);
