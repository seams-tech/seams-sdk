PRAGMA defer_foreign_keys = ON;

CREATE TABLE audit_events_r105 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  project_id TEXT,
  environment_id TEXT,
  actor_user_id TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  category TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  summary TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (actor_type IN ('USER', 'SYSTEM')),
  CHECK (outcome IN ('SUCCESS', 'FAILURE', 'PENDING')),
  CHECK (json_valid(metadata_json))
);

INSERT INTO audit_events_r105
SELECT * FROM audit_events;

DROP TABLE audit_events;
ALTER TABLE audit_events_r105 RENAME TO audit_events;

CREATE INDEX audit_events_org_category_idx
  ON audit_events (namespace, org_id, category, created_at_ms DESC);
CREATE INDEX audit_events_org_created_idx
  ON audit_events (namespace, org_id, created_at_ms DESC, id DESC);
CREATE INDEX audit_events_org_outcome_idx
  ON audit_events (namespace, org_id, outcome, created_at_ms DESC);

CREATE TABLE audit_evidence_r105 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  project_id TEXT,
  environment_id TEXT,
  domain TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  event_ids_json TEXT NOT NULL,
  references_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (json_valid(event_ids_json)),
  CHECK (json_valid(references_json))
);

INSERT INTO audit_evidence_r105
SELECT * FROM audit_evidence;

DROP TABLE audit_evidence;
ALTER TABLE audit_evidence_r105 RENAME TO audit_evidence;

CREATE INDEX audit_evidence_org_created_idx
  ON audit_evidence (namespace, org_id, created_at_ms DESC, id DESC);
CREATE INDEX audit_evidence_org_domain_idx
  ON audit_evidence (namespace, org_id, domain, created_at_ms DESC);

DROP TRIGGER billing_ledger_entries_balanced_postings;

CREATE TABLE billing_ledger_entries_r105 (
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
      'PRODUCT_EXECUTION_DEBIT',
      'MANUAL_ADJUSTMENT',
      'REFUND',
      'DISPUTE_OPENED',
      'DISPUTE_WON'
    )
  ),
  CHECK (
    (entry_type IN ('CREDIT_PURCHASE', 'REFUND', 'DISPUTE_WON') AND amount_minor > 0)
    OR (entry_type IN ('USAGE_DEBIT', 'PRODUCT_EXECUTION_DEBIT', 'DISPUTE_OPENED') AND amount_minor < 0)
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

INSERT INTO billing_ledger_entries_r105 (
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
  CASE entry_type
    WHEN 'SPONSORED_EXECUTION_DEBIT' THEN 'PRODUCT_EXECUTION_DEBIT'
    ELSE entry_type
  END,
  CASE entry_type
    WHEN 'REFUND' THEN ABS(amount_minor)
    ELSE amount_minor
  END,
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

CREATE TABLE billing_ledger_postings_r105 (
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
      'revenue_product_execution',
      'manual_adjustment_clearing',
      'stripe_dispute_clearing'
    )
  ),
  CHECK (direction IN ('DEBIT', 'CREDIT')),
  CHECK (amount_minor > 0),
  CHECK (created_at_ms > 0)
);

INSERT INTO billing_ledger_postings_r105 (
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
  posting.namespace,
  posting.org_id,
  posting.id,
  posting.ledger_entry_id,
  CASE posting.account_code
    WHEN 'revenue_sponsored_execution' THEN 'revenue_product_execution'
    ELSE posting.account_code
  END,
  CASE
    WHEN entry.entry_type = 'REFUND' AND posting.direction = 'DEBIT' THEN 'CREDIT'
    WHEN entry.entry_type = 'REFUND' AND posting.direction = 'CREDIT' THEN 'DEBIT'
    ELSE posting.direction
  END,
  posting.amount_minor,
  posting.created_at_ms
FROM billing_ledger_postings AS posting
JOIN billing_ledger_entries AS entry
  ON entry.namespace = posting.namespace
 AND entry.org_id = posting.org_id
 AND entry.id = posting.ledger_entry_id;

DROP TABLE billing_ledger_postings;
DROP TABLE billing_ledger_entries;
ALTER TABLE billing_ledger_entries_r105 RENAME TO billing_ledger_entries;
ALTER TABLE billing_ledger_postings_r105 RENAME TO billing_ledger_postings;

CREATE UNIQUE INDEX billing_ledger_entries_idempotency_uidx
  ON billing_ledger_entries (namespace, org_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX billing_ledger_entries_org_created_idx
  ON billing_ledger_entries (namespace, org_id, created_at_ms DESC, id DESC);
CREATE INDEX billing_ledger_entries_org_month_idx
  ON billing_ledger_entries (namespace, org_id, month_utc, entry_type);
CREATE UNIQUE INDEX billing_ledger_entries_type_source_uidx
  ON billing_ledger_entries (namespace, org_id, entry_type, source_event_id)
  WHERE source_event_id IS NOT NULL;
CREATE INDEX billing_ledger_postings_entry_idx
  ON billing_ledger_postings (namespace, org_id, ledger_entry_id);

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
        WHEN NEW.entry_type = 'MANUAL_ADJUSTMENT' THEN 'manual_adjustment_clearing'
        ELSE 'revenue_product_execution'
      END,
      'CREDIT',
      ABS(NEW.amount_minor),
      NEW.created_at_ms
    );
END;

DROP INDEX billing_monthly_active_wallets_source_uidx;
ALTER TABLE billing_monthly_active_wallets RENAME TO billing_monthly_active_resources;
ALTER TABLE billing_monthly_active_resources RENAME COLUMN wallet_id TO resource_id;
CREATE UNIQUE INDEX billing_monthly_active_resources_source_uidx
  ON billing_monthly_active_resources (namespace, org_id, source_event_id)
  WHERE source_event_id IS NOT NULL;

ALTER TABLE environments RENAME COLUMN signing_root_version TO runtime_version;

CREATE TABLE invoice_line_items_r105 (
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
  CHECK (quantity > 0),
  CHECK (unit_amount_minor >= 0),
  CHECK (amount_minor >= 0)
);

INSERT INTO invoice_line_items_r105
SELECT * FROM invoice_line_items;

DROP TABLE invoice_line_items;
ALTER TABLE invoice_line_items_r105 RENAME TO invoice_line_items;
CREATE INDEX invoice_line_items_invoice_idx
  ON invoice_line_items (namespace, org_id, invoice_id);

CREATE TABLE webhook_endpoint_categories_r105 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  category TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, endpoint_id, category),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(endpoint_id) > 0),
  FOREIGN KEY (namespace, org_id, endpoint_id)
    REFERENCES webhook_endpoints(namespace, org_id, id)
    ON DELETE CASCADE
);

INSERT INTO webhook_endpoint_categories_r105
SELECT * FROM webhook_endpoint_categories;

DROP TABLE webhook_endpoint_categories;
ALTER TABLE webhook_endpoint_categories_r105 RENAME TO webhook_endpoint_categories;
CREATE INDEX webhook_endpoint_categories_lookup_idx
  ON webhook_endpoint_categories (namespace, org_id, category, endpoint_id);
