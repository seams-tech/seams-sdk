-- Composed Wallet Console fresh schema (owner: composition root).
-- Section 1: Console core tables (owner: console-core).
-- Section 2: Wallet Console tables (owner: wallet-console).
-- R105 Phase 6; one private seams-console D1 during R105.

-- Canonical D1 schema.
CREATE TABLE api_keys (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  ip_allowlist_json TEXT NOT NULL,
  allowed_origins_json TEXT NOT NULL,
  rate_limit_bucket TEXT NOT NULL,
  quota_bucket TEXT NOT NULL,
  risk_policy_json TEXT NOT NULL,
  payment_policy_json TEXT NOT NULL,
  status TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  secret_version INTEGER NOT NULL,
  secret_preview TEXT NOT NULL,
  last_used_at_ms INTEGER,
  expires_at_ms INTEGER,
  revoked_reason TEXT,
  endpoint_usage_counts_json TEXT NOT NULL,
  anomaly_flags_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (kind IN ('secret_key', 'publishable_key')),
  CHECK (status IN ('ACTIVE', 'REVOKED')),
  CHECK (secret_version >= 1),
  CHECK (json_valid(scopes_json)),
  CHECK (json_valid(ip_allowlist_json)),
  CHECK (json_valid(allowed_origins_json)),
  CHECK (json_valid(risk_policy_json)),
  CHECK (json_valid(payment_policy_json)),
  CHECK (json_valid(endpoint_usage_counts_json)),
  CHECK (json_valid(anomaly_flags_json)),
  CHECK (
    (kind = 'secret_key'
      AND allowed_origins_json = '[]'
      AND rate_limit_bucket = ''
      AND quota_bucket = ''
      AND risk_policy_json = '{}'
      AND payment_policy_json = '{}')
    OR
    (kind = 'publishable_key'
      AND scopes_json = '[]'
      AND ip_allowlist_json = '[]')
  )
);

CREATE TABLE audit_events (
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

CREATE TABLE audit_evidence (
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

CREATE TABLE "billing_accounts" (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  low_balance_threshold_minor INTEGER NOT NULL DEFAULT 2000,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL, low_balance_warning_active INTEGER NOT NULL DEFAULT 1
CHECK (low_balance_warning_active IN (0, 1)),
  PRIMARY KEY (namespace, org_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (low_balance_threshold_minor >= 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE "billing_credit_purchases" (
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

CREATE TABLE "billing_ledger_entries" (
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
      'revenue_product_execution',
      'manual_adjustment_clearing',
      'stripe_dispute_clearing'
    )
  ),
  CHECK (direction IN ('DEBIT', 'CREDIT')),
  CHECK (amount_minor > 0),
  CHECK (created_at_ms > 0)
);

CREATE TABLE billing_monthly_active_resources (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  month_utc TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  source_event_id TEXT,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, month_utc, resource_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (
    month_utc GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]'
    AND substr(month_utc, 6, 2) BETWEEN '01' AND '12'
  ),
  CHECK (length(resource_id) > 0),
  CHECK (source_event_id IS NULL OR length(source_event_id) > 0),
  CHECK (created_at_ms > 0)
);

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

CREATE TABLE billing_stripe_post_processing_outbox (
  namespace TEXT NOT NULL,
  event_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  audit_completed_at_ms INTEGER,
  customer_webhook_completed_at_ms INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, event_id),
  CHECK (length(namespace) > 0),
  CHECK (length(event_id) > 0),
  CHECK (length(org_id) > 0),
  CHECK (json_valid(payload_json)),
  CHECK (json_extract(payload_json, '$.kind') = 'credit_purchase_settled_v1'),
  CHECK (audit_completed_at_ms IS NULL OR audit_completed_at_ms >= created_at_ms),
  CHECK (
    customer_webhook_completed_at_ms IS NULL
    OR customer_webhook_completed_at_ms >= created_at_ms
  ),
  CHECK (attempt_count >= 0),
  CHECK (updated_at_ms >= created_at_ms),
  FOREIGN KEY (namespace, event_id)
    REFERENCES stripe_webhook_events(namespace, event_id)
    ON DELETE CASCADE
);

CREATE TABLE console_email_deliveries (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  outbox_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  outcome TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_message_id TEXT,
  provider_status_code INTEGER,
  error_code TEXT,
  attempted_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, outbox_id, attempt_number),
  FOREIGN KEY (namespace, org_id, outbox_id)
    REFERENCES console_email_outbox(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (length(outbox_id) > 0),
  CHECK (attempt_number > 0),
  CHECK (outcome IN ('SENT', 'RETRYABLE_FAILED', 'FINAL_FAILED')),
  CHECK (provider IN ('capture', 'resend')),
  CHECK (provider_message_id IS NULL OR length(provider_message_id) > 0),
  CHECK (provider_status_code IS NULL OR provider_status_code >= 100),
  CHECK (error_code IS NULL OR length(error_code) > 0),
  CHECK (attempted_at_ms > 0),
  CHECK (
    (
      outcome = 'SENT'
      AND provider_message_id IS NOT NULL
      AND error_code IS NULL
    )
    OR
    (
      outcome IN ('RETRYABLE_FAILED', 'FINAL_FAILED')
      AND provider_message_id IS NULL
      AND error_code IS NOT NULL
    )
  )
);

CREATE TABLE "console_email_outbox" (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  recipient_email TEXT NOT NULL,
  recipient_display_name TEXT NOT NULL,
  template_family TEXT NOT NULL,
  template_version INTEGER NOT NULL,
  template_payload_json TEXT NOT NULL,
  invitation_id TEXT,
  invitation_secret_ciphertext_b64u TEXT,
  invitation_secret_key_id TEXT,
  invitation_secret_envelope_version TEXT,
  status TEXT NOT NULL,
  total_attempt_count INTEGER NOT NULL DEFAULT 0,
  cycle_attempt_count INTEGER NOT NULL DEFAULT 0,
  available_at_ms INTEGER,
  claimed_by TEXT,
  claim_expires_at_ms INTEGER,
  last_error_code TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  sent_at_ms INTEGER,
  canceled_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, dedupe_key),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE,
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (length(dedupe_key) > 0),
  CHECK (length(recipient_email) > 3),
  CHECK (instr(recipient_email, '@') > 1),
  CHECK (length(recipient_display_name) > 0),
  CHECK (
    template_family IN (
      'ACCOUNT_WELCOME',
      'ORGANIZATION_INVITATION',
      'OWNER_MEMBERSHIP_CHANGED',
      'MEMBERSHIP_ACCESS_CHANGED',
      'PREPAID_TOP_UP_RECEIPT',
      'BILLING_REFUND_RESULT',
      'LOW_BALANCE_WARNING'
    )
  ),
  CHECK (template_version = 1),
  CHECK (json_valid(template_payload_json)),
  CHECK (status IN ('PENDING', 'SENT', 'FINAL_FAILED', 'CANCELED')),
  CHECK (total_attempt_count >= 0),
  CHECK (cycle_attempt_count >= 0),
  CHECK (cycle_attempt_count <= total_attempt_count),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (last_error_code IS NULL OR length(last_error_code) > 0),
  CHECK (
    (
      invitation_secret_ciphertext_b64u IS NULL
      AND invitation_secret_key_id IS NULL
      AND invitation_secret_envelope_version IS NULL
    )
    OR
    (
      invitation_secret_ciphertext_b64u IS NOT NULL
      AND length(invitation_secret_ciphertext_b64u) > 0
      AND invitation_secret_ciphertext_b64u NOT GLOB '*[^A-Za-z0-9_-]*'
      AND invitation_secret_key_id IS NOT NULL
      AND length(invitation_secret_key_id) > 0
      AND invitation_secret_envelope_version IS NOT NULL
      AND length(invitation_secret_envelope_version) > 0
    )
  ),
  CHECK (
    (
      template_family = 'ORGANIZATION_INVITATION'
      AND invitation_id IS NOT NULL
      AND length(invitation_id) > 0
      AND (
        invitation_secret_ciphertext_b64u IS NOT NULL
        OR status IN ('SENT', 'CANCELED')
      )
    )
    OR
    (
      template_family != 'ORGANIZATION_INVITATION'
      AND invitation_id IS NULL
      AND invitation_secret_ciphertext_b64u IS NULL
    )
  ),
  CHECK (
    (claimed_by IS NULL AND claim_expires_at_ms IS NULL)
    OR
    (
      claimed_by IS NOT NULL
      AND length(claimed_by) > 0
      AND claim_expires_at_ms IS NOT NULL
      AND claim_expires_at_ms > updated_at_ms
    )
  ),
  CHECK (
    (
      status = 'PENDING'
      AND available_at_ms IS NOT NULL
      AND available_at_ms >= created_at_ms
      AND sent_at_ms IS NULL
      AND canceled_at_ms IS NULL
    )
    OR
    (
      status = 'SENT'
      AND available_at_ms IS NULL
      AND claimed_by IS NULL
      AND claim_expires_at_ms IS NULL
      AND last_error_code IS NULL
      AND sent_at_ms IS NOT NULL
      AND sent_at_ms >= created_at_ms
      AND canceled_at_ms IS NULL
      AND total_attempt_count >= 1
    )
    OR
    (
      status = 'FINAL_FAILED'
      AND available_at_ms IS NULL
      AND claimed_by IS NULL
      AND claim_expires_at_ms IS NULL
      AND last_error_code IS NOT NULL
      AND sent_at_ms IS NULL
      AND canceled_at_ms IS NULL
      AND total_attempt_count >= 1
    )
    OR
    (
      status = 'CANCELED'
      AND available_at_ms IS NULL
      AND claimed_by IS NULL
      AND claim_expires_at_ms IS NULL
      AND last_error_code IS NULL
      AND sent_at_ms IS NULL
      AND canceled_at_ms IS NOT NULL
      AND canceled_at_ms >= created_at_ms
    )
  )
);

CREATE TABLE environments (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_key TEXT NOT NULL,
  runtime_version TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, id),
  CHECK (status IN ('ACTIVE', 'DISABLED', 'ARCHIVED')),
  CHECK (env_key IN ('dev', 'staging', 'prod')),
  UNIQUE (namespace, project_id, env_key),
  FOREIGN KEY (namespace, project_id, org_id)
    REFERENCES projects(namespace, id, org_id)
    ON DELETE CASCADE
);

CREATE TABLE invoice_line_items (
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

CREATE TABLE invoices (
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

CREATE TABLE observability_event_dedup (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, event_id)
);

CREATE TABLE observability_events (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  source TEXT NOT NULL,
  ingested_at_ms INTEGER NOT NULL,
  timestamp_ms INTEGER NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  environment_id TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL,
  component TEXT NOT NULL,
  level TEXT NOT NULL,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  request_id TEXT NOT NULL DEFAULT '',
  trace_id TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL,
  redaction_version INTEGER NOT NULL,
  redaction_applied INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, created_at_ms, event_id),
  CHECK (schema_version >= 1),
  CHECK (source IN ('WEBHOOK', 'BILLING', 'APPROVAL', 'SYSTEM')),
  CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
  CHECK (json_valid(metadata_json)),
  CHECK (redaction_version >= 1),
  CHECK (redaction_applied IN (0, 1))
);

CREATE TABLE observability_ingest_windows (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  window_start_ms INTEGER NOT NULL,
  accepted_count INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, window_start_ms),
  CHECK (accepted_count >= 0)
);

CREATE TABLE observability_request_rollups_minute (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  window_start_ms INTEGER NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  environment_id TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL,
  route_family TEXT NOT NULL,
  method TEXT NOT NULL,
  status_class TEXT NOT NULL,
  request_count INTEGER NOT NULL,
  error_count INTEGER NOT NULL,
  latency_sum_ms REAL NOT NULL,
  latency_max_ms REAL NOT NULL,
  latency_bucket_le_50 INTEGER NOT NULL,
  latency_bucket_le_100 INTEGER NOT NULL,
  latency_bucket_le_250 INTEGER NOT NULL,
  latency_bucket_le_500 INTEGER NOT NULL,
  latency_bucket_le_1000 INTEGER NOT NULL,
  latency_bucket_le_2000 INTEGER NOT NULL,
  latency_bucket_le_5000 INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    window_start_ms,
    project_id,
    environment_id,
    service,
    route_family,
    method,
    status_class
  ),
  CHECK (request_count >= 0),
  CHECK (error_count >= 0),
  CHECK (latency_sum_ms >= 0),
  CHECK (latency_max_ms >= 0),
  CHECK (error_count <= request_count)
);

CREATE TABLE organization_admin_permissions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  permission TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, membership_id, permission),
  FOREIGN KEY (namespace, org_id, membership_id)
    REFERENCES organization_memberships(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (permission IN ('members.manage', 'projects.manage', 'billing.view', 'billing.manage')),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE organization_invitations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  invited_by_user_id TEXT NOT NULL,
  role TEXT NOT NULL,
  admin_permissions_json TEXT NOT NULL DEFAULT '[]',
  project_access_json TEXT NOT NULL DEFAULT '[]',
  kind TEXT NOT NULL,
  token_hash TEXT,
  expires_at_ms INTEGER,
  membership_id TEXT,
  accepted_at_ms INTEGER,
  declined_at_ms INTEGER,
  revoked_at_ms INTEGER,
  expired_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE,
  FOREIGN KEY (namespace, org_id, membership_id)
    REFERENCES organization_memberships(namespace, org_id, id),
  CHECK (length(email) > 0),
  CHECK (email = email_normalized),
  CHECK (length(invited_by_user_id) > 0),
  CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER')),
  CHECK (json_valid(admin_permissions_json)),
  CHECK (json_type(admin_permissions_json) = 'array'),
  CHECK (json_valid(project_access_json)),
  CHECK (json_type(project_access_json) = 'array'),
  CHECK (
    (role = 'OWNER' AND json_array_length(admin_permissions_json) = 0 AND json_array_length(project_access_json) = 0)
    OR (role = 'ADMIN' AND json_array_length(project_access_json) = 0)
    OR (role = 'MEMBER' AND json_array_length(admin_permissions_json) = 0)
  ),
  CHECK (kind IN ('PENDING', 'ACCEPTED', 'DECLINED', 'REVOKED', 'EXPIRED')),
  CHECK (
    (
      kind = 'PENDING'
      AND token_hash IS NOT NULL
      AND expires_at_ms IS NOT NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'ACCEPTED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NOT NULL
      AND accepted_at_ms IS NOT NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'DECLINED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NOT NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'REVOKED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NOT NULL
      AND expired_at_ms IS NULL
    )
    OR
    (
      kind = 'EXPIRED'
      AND token_hash IS NULL
      AND expires_at_ms IS NULL
      AND membership_id IS NULL
      AND accepted_at_ms IS NULL
      AND declined_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND expired_at_ms IS NOT NULL
    )
  ),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE organization_memberships (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  display_name TEXT,
  kind TEXT NOT NULL,
  role TEXT NOT NULL,
  suspended_at_ms INTEGER,
  removed_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE,
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(id) > 0),
  CHECK (length(user_id) > 0),
  CHECK (length(email) > 0),
  CHECK (email = email_normalized),
  CHECK (kind IN ('ACTIVE', 'SUSPENDED', 'REMOVED')),
  CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER')),
  CHECK (role <> 'OWNER' OR kind = 'ACTIVE'),
  CHECK (
    (kind = 'ACTIVE' AND suspended_at_ms IS NULL AND removed_at_ms IS NULL)
    OR
    (kind = 'SUSPENDED' AND suspended_at_ms IS NOT NULL AND removed_at_ms IS NULL)
    OR
    (kind = 'REMOVED' AND suspended_at_ms IS NULL AND removed_at_ms IS NOT NULL)
  ),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE organization_owner_events (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  actor_user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE,
  CHECK (kind IN ('OWNER_ADDED', 'OWNER_REMOVED')),
  CHECK (length(owner_user_id) > 0),
  CHECK (length(actor_user_id) > 0),
  CHECK (created_at_ms > 0)
);

CREATE TABLE organizations (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  created_by_user_id TEXT,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL, owner_anchor_membership_id TEXT, owner_set_version INTEGER NOT NULL DEFAULT 0, authorization_version INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (namespace, id),
  CHECK (status IN ('ACTIVE'))
);

CREATE TABLE project_member_access (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  access_level TEXT NOT NULL,
  granted_by_user_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, membership_id),
  FOREIGN KEY (namespace, org_id, membership_id)
    REFERENCES organization_memberships(namespace, org_id, id)
    ON DELETE CASCADE,
  FOREIGN KEY (namespace, project_id, org_id)
    REFERENCES projects(namespace, id, org_id)
    ON DELETE CASCADE,
  CHECK (access_level IN ('viewer', 'editor')),
  CHECK (length(granted_by_user_id) > 0),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE projects (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, id),
  CHECK (status IN ('ACTIVE', 'ARCHIVED')),
  FOREIGN KEY (namespace, org_id)
    REFERENCES organizations(namespace, id)
    ON DELETE CASCADE
);

CREATE TABLE stripe_webhook_events (
  namespace TEXT NOT NULL,
  event_id TEXT NOT NULL,
  provider_ref TEXT NOT NULL,
  org_id TEXT NOT NULL,
  processed_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, event_id)
);

CREATE TABLE user_backup_emails (
  namespace TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, user_id, email_normalized),
  CHECK (status IN ('PENDING', 'VERIFIED'))
);

CREATE TABLE user_profiles (
  namespace TEXT NOT NULL,
  user_id TEXT NOT NULL,
  display_name TEXT,
  primary_email TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, user_id)
);

CREATE TABLE webhook_attempts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  delivery_id TEXT NOT NULL,
  attempt_no INTEGER NOT NULL,
  status TEXT NOT NULL,
  response_status INTEGER,
  response_body TEXT,
  error_message TEXT,
  attempted_at_ms INTEGER NOT NULL,
  is_replay INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, delivery_id, attempt_no),
  CHECK (attempt_no > 0),
  CHECK (status IN ('SUCCEEDED', 'FAILED')),
  CHECK (is_replay IN (0, 1)),
  FOREIGN KEY (namespace, org_id, delivery_id)
    REFERENCES webhook_deliveries(namespace, org_id, id)
    ON DELETE CASCADE
);

CREATE TABLE webhook_dead_letters (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  delivery_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL,
  last_response_status INTEGER,
  last_error_message TEXT,
  payload_json TEXT NOT NULL,
  moved_to_dlq_at_ms INTEGER NOT NULL,
  resolved_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, delivery_id),
  CHECK (failed_attempts > 0),
  CHECK (json_valid(payload_json)),
  FOREIGN KEY (namespace, org_id, delivery_id)
    REFERENCES webhook_deliveries(namespace, org_id, id)
    ON DELETE CASCADE
);

CREATE TABLE webhook_deliveries (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  attempt_count INTEGER NOT NULL,
  replay_count INTEGER NOT NULL,
  response_status INTEGER,
  response_body TEXT,
  error_message TEXT,
  payload_json TEXT NOT NULL,
  delivered_at_ms INTEGER,
  last_attempt_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL, retry_claimed_by TEXT, retry_claim_expires_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (status IN ('SUCCEEDED', 'FAILED')),
  CHECK (attempt_count >= 0),
  CHECK (replay_count >= 0),
  CHECK (json_valid(payload_json)),
  FOREIGN KEY (namespace, org_id, endpoint_id)
    REFERENCES webhook_endpoints(namespace, org_id, id)
    ON DELETE CASCADE
);

CREATE TABLE "webhook_endpoint_categories" (
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

CREATE TABLE "webhook_endpoints" (
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

CREATE VIEW organization_access_ownerless_organizations AS
SELECT
  organization.namespace,
  organization.id AS org_id
FROM organizations AS organization
WHERE organization.owner_anchor_membership_id IS NULL
   OR NOT EXISTS (
     SELECT 1
     FROM organization_memberships AS owner
     WHERE owner.namespace = organization.namespace
       AND owner.org_id = organization.id
       AND owner.kind = 'ACTIVE'
       AND owner.role = 'OWNER'
   );

CREATE UNIQUE INDEX api_keys_auth_lookup_uidx
  ON api_keys (namespace, kind, key_prefix, secret_hash);

CREATE UNIQUE INDEX api_keys_namespace_id_uidx
  ON api_keys (namespace, id);

CREATE INDEX api_keys_org_status_idx
  ON api_keys (namespace, org_id, status);

CREATE INDEX api_keys_org_updated_idx
  ON api_keys (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX audit_events_org_category_idx
  ON audit_events (namespace, org_id, category, created_at_ms DESC);

CREATE INDEX audit_events_org_created_idx
  ON audit_events (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX audit_events_org_outcome_idx
  ON audit_events (namespace, org_id, outcome, created_at_ms DESC);

CREATE INDEX audit_evidence_org_created_idx
  ON audit_evidence (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX audit_evidence_org_domain_idx
  ON audit_evidence (namespace, org_id, domain, created_at_ms DESC);

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

CREATE UNIQUE INDEX billing_disputes_provider_uidx
  ON billing_disputes (namespace, provider_dispute_id);

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

CREATE UNIQUE INDEX billing_monthly_active_resources_source_uidx
  ON billing_monthly_active_resources (namespace, org_id, source_event_id)
  WHERE source_event_id IS NOT NULL;

CREATE UNIQUE INDEX billing_refunds_idempotency_uidx
  ON billing_refunds (namespace, org_id, idempotency_key);

CREATE UNIQUE INDEX billing_refunds_provider_uidx
  ON billing_refunds (namespace, provider_refund_id)
  WHERE provider_refund_id IS NOT NULL;

CREATE INDEX billing_refunds_purchase_idx
  ON billing_refunds (namespace, org_id, purchase_id, created_at_ms DESC);

CREATE INDEX billing_stripe_post_processing_pending_idx
  ON billing_stripe_post_processing_outbox (
    namespace,
    audit_completed_at_ms,
    customer_webhook_completed_at_ms,
    created_at_ms,
    event_id
  );

CREATE INDEX console_email_deliveries_outbox_idx
  ON console_email_deliveries (namespace, org_id, outbox_id, attempt_number DESC);

CREATE INDEX console_email_outbox_dispatch_idx
  ON console_email_outbox (namespace, status, available_at_ms ASC, created_at_ms ASC, id ASC);

CREATE INDEX console_email_outbox_final_failure_idx
  ON console_email_outbox (namespace, org_id, status, updated_at_ms DESC, id DESC);

CREATE INDEX console_email_outbox_invitation_idx
  ON console_email_outbox (namespace, org_id, invitation_id, status)
  WHERE invitation_id IS NOT NULL;

CREATE UNIQUE INDEX environments_namespace_id_project_org_unique_idx
  ON environments (namespace, id, project_id, org_id);

CREATE INDEX environments_org_project_updated_idx
  ON environments (namespace, org_id, project_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX invoice_line_items_invoice_idx
  ON invoice_line_items (namespace, org_id, invoice_id);

CREATE INDEX invoices_org_created_idx
  ON invoices (namespace, org_id, created_at_ms DESC, id DESC);

CREATE UNIQUE INDEX invoices_org_statement_month_uidx
  ON invoices (namespace, org_id, document_type, period_month_utc)
  WHERE document_type = 'USAGE_STATEMENT';

CREATE INDEX observability_event_dedup_created_idx
  ON observability_event_dedup (namespace, org_id, created_at_ms);

CREATE INDEX observability_events_org_created_idx
  ON observability_events (namespace, org_id, created_at_ms DESC, event_id DESC);

CREATE INDEX observability_events_org_level_created_idx
  ON observability_events (namespace, org_id, level, created_at_ms DESC, event_id DESC);

CREATE INDEX observability_events_org_service_created_idx
  ON observability_events (namespace, org_id, service, created_at_ms DESC, event_id DESC);

CREATE INDEX observability_events_org_timestamp_idx
  ON observability_events (namespace, org_id, timestamp_ms DESC, event_id DESC);

CREATE INDEX observability_ingest_windows_window_idx
  ON observability_ingest_windows (namespace, org_id, window_start_ms);

CREATE INDEX observability_request_rollups_org_route_window_idx
  ON observability_request_rollups_minute (namespace, org_id, route_family, window_start_ms DESC);

CREATE INDEX observability_request_rollups_org_service_window_idx
  ON observability_request_rollups_minute (namespace, org_id, service, window_start_ms DESC);

CREATE INDEX observability_request_rollups_org_window_idx
  ON observability_request_rollups_minute (namespace, org_id, window_start_ms DESC);

CREATE INDEX org_created_by_user_idx
  ON organizations (namespace, created_by_user_id, updated_at_ms DESC, created_at_ms DESC);

CREATE UNIQUE INDEX organization_invitations_namespace_id_uidx
  ON organization_invitations (namespace, id);

CREATE INDEX organization_invitations_org_kind_idx
  ON organization_invitations (namespace, org_id, kind, updated_at_ms DESC);

CREATE UNIQUE INDEX organization_invitations_pending_email_uidx
  ON organization_invitations (namespace, org_id, email_normalized)
  WHERE kind = 'PENDING';

CREATE UNIQUE INDEX organization_memberships_current_email_uidx
  ON organization_memberships (namespace, org_id, email_normalized)
  WHERE kind <> 'REMOVED';

CREATE UNIQUE INDEX organization_memberships_current_user_uidx
  ON organization_memberships (namespace, org_id, user_id)
  WHERE kind <> 'REMOVED';

CREATE INDEX organization_memberships_org_kind_idx
  ON organization_memberships (namespace, org_id, kind, updated_at_ms DESC);

CREATE INDEX organization_memberships_org_role_idx
  ON organization_memberships (namespace, org_id, role, kind);

CREATE INDEX organization_owner_events_org_created_idx
  ON organization_owner_events (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX project_member_access_membership_idx
  ON project_member_access (namespace, org_id, membership_id, project_id);

CREATE UNIQUE INDEX projects_namespace_id_org_unique_idx
  ON projects (namespace, id, org_id);

CREATE INDEX projects_org_updated_idx
  ON projects (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX stripe_webhook_events_org_idx
  ON stripe_webhook_events (namespace, org_id, processed_at_ms DESC);

CREATE INDEX webhook_attempts_endpoint_delivery_page_idx
  ON webhook_attempts (namespace, org_id, endpoint_id, delivery_id, attempted_at_ms DESC, id DESC);

CREATE INDEX webhook_attempts_endpoint_page_idx
  ON webhook_attempts (namespace, org_id, endpoint_id, attempted_at_ms DESC, id DESC);

CREATE INDEX webhook_dead_letters_endpoint_page_idx
  ON webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC);

CREATE INDEX webhook_dead_letters_unresolved_endpoint_page_idx
  ON webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC)
  WHERE resolved_at_ms IS NULL;

CREATE INDEX webhook_deliveries_endpoint_page_idx
  ON webhook_deliveries (namespace, org_id, endpoint_id, created_at_ms DESC, id DESC);

CREATE UNIQUE INDEX webhook_deliveries_event_endpoint_uidx
  ON webhook_deliveries (namespace, org_id, endpoint_id, event_id);

CREATE INDEX webhook_deliveries_event_idx
  ON webhook_deliveries (namespace, org_id, event_id);

CREATE INDEX webhook_deliveries_retry_claim_idx
  ON webhook_deliveries (
    namespace,
    org_id,
    status,
    retry_claim_expires_at_ms,
    last_attempt_at_ms,
    created_at_ms,
    id
  );

CREATE INDEX webhook_endpoint_categories_lookup_idx
  ON webhook_endpoint_categories (namespace, org_id, category, endpoint_id);

CREATE INDEX webhook_endpoints_org_created_idx
  ON webhook_endpoints (namespace, org_id, created_at_ms DESC, id DESC);

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

CREATE TRIGGER organization_admin_permissions_authorization_delete
AFTER DELETE ON organization_admin_permissions
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = OLD.namespace
    AND id = OLD.org_id;
END;

CREATE TRIGGER organization_admin_permissions_authorization_insert
AFTER INSERT ON organization_admin_permissions
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER organization_admin_permissions_role_insert
BEFORE INSERT ON organization_admin_permissions
WHEN NOT EXISTS (
  SELECT 1
  FROM organization_memberships
  WHERE namespace = NEW.namespace
    AND org_id = NEW.org_id
    AND id = NEW.membership_id
    AND role = 'ADMIN'
    AND kind <> 'REMOVED'
)
BEGIN
  SELECT RAISE(ABORT, 'admin_permission_membership_invalid');
END;

CREATE TRIGGER organization_memberships_authorization_delete
AFTER DELETE ON organization_memberships
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1,
      owner_set_version = owner_set_version + CASE
        WHEN OLD.kind = 'ACTIVE' AND OLD.role = 'OWNER' THEN 1
        ELSE 0
      END
  WHERE namespace = OLD.namespace
    AND id = OLD.org_id;
END;

CREATE TRIGGER organization_memberships_authorization_insert
AFTER INSERT ON organization_memberships
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1,
      owner_set_version = owner_set_version + CASE
        WHEN NEW.kind = 'ACTIVE' AND NEW.role = 'OWNER' THEN 1
        ELSE 0
      END
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER organization_memberships_authorization_update
AFTER UPDATE OF kind, role ON organization_memberships
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1,
      owner_set_version = owner_set_version + CASE
        WHEN OLD.kind = 'ACTIVE' AND OLD.role = 'OWNER'
         AND (NEW.kind <> 'ACTIVE' OR NEW.role <> 'OWNER') THEN 1
        WHEN (OLD.kind <> 'ACTIVE' OR OLD.role <> 'OWNER')
         AND NEW.kind = 'ACTIVE' AND NEW.role = 'OWNER' THEN 1
        ELSE 0
      END
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER organization_memberships_last_owner_delete
BEFORE DELETE ON organization_memberships
WHEN OLD.kind = 'ACTIVE'
 AND OLD.role = 'OWNER'
 AND (
   SELECT COUNT(*)
   FROM organization_memberships
   WHERE namespace = OLD.namespace
     AND org_id = OLD.org_id
     AND kind = 'ACTIVE'
     AND role = 'OWNER'
 ) <= 1
BEGIN
  SELECT RAISE(ABORT, 'last_owner_required');
END;

CREATE TRIGGER organization_memberships_last_owner_update
BEFORE UPDATE OF kind, role ON organization_memberships
WHEN OLD.kind = 'ACTIVE'
 AND OLD.role = 'OWNER'
 AND (NEW.kind <> 'ACTIVE' OR NEW.role <> 'OWNER')
 AND (
   SELECT COUNT(*)
   FROM organization_memberships
   WHERE namespace = OLD.namespace
     AND org_id = OLD.org_id
     AND kind = 'ACTIVE'
     AND role = 'OWNER'
 ) <= 1
BEGIN
  SELECT RAISE(ABORT, 'last_owner_required');
END;

CREATE TRIGGER organization_memberships_owner_anchor_update
BEFORE UPDATE OF kind, role ON organization_memberships
WHEN OLD.id = (
   SELECT owner_anchor_membership_id
   FROM organizations
   WHERE namespace = OLD.namespace
     AND id = OLD.org_id
 )
 AND (NEW.kind <> 'ACTIVE' OR NEW.role <> 'OWNER')
BEGIN
  SELECT RAISE(ABORT, 'owner_anchor_required');
END;

CREATE TRIGGER organizations_owner_anchor_update
BEFORE UPDATE OF owner_anchor_membership_id ON organizations
WHEN NEW.owner_anchor_membership_id IS NOT NULL
 AND NOT EXISTS (
   SELECT 1
   FROM organization_memberships
   WHERE namespace = NEW.namespace
     AND org_id = NEW.id
     AND id = NEW.owner_anchor_membership_id
     AND kind = 'ACTIVE'
     AND role = 'OWNER'
 )
BEGIN
  SELECT RAISE(ABORT, 'owner_anchor_invalid');
END;

CREATE TRIGGER project_member_access_authorization_delete
AFTER DELETE ON project_member_access
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = OLD.namespace
    AND id = OLD.org_id;
END;

CREATE TRIGGER project_member_access_authorization_insert
AFTER INSERT ON project_member_access
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER project_member_access_authorization_update
AFTER UPDATE OF access_level ON project_member_access
BEGIN
  UPDATE organizations
  SET authorization_version = authorization_version + 1
  WHERE namespace = NEW.namespace
    AND id = NEW.org_id;
END;

CREATE TRIGGER project_member_access_role_insert
BEFORE INSERT ON project_member_access
WHEN NOT EXISTS (
  SELECT 1
  FROM organization_memberships
  WHERE namespace = NEW.namespace
    AND org_id = NEW.org_id
    AND id = NEW.membership_id
    AND role = 'MEMBER'
    AND kind = 'ACTIVE'
)
BEGIN
  SELECT RAISE(ABORT, 'project_access_membership_invalid');
END;

-- ===== Wallet Console section (owner: wallet-console) =====

CREATE TABLE approvals (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  required_approvals INTEGER NOT NULL,
  require_mfa INTEGER NOT NULL,
  project_id TEXT,
  environment_id TEXT,
  resource_type TEXT,
  resource_id TEXT,
  metadata_json TEXT NOT NULL,
  decisions_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  resolved_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (operation_type IN ('POLICY_PUBLISH', 'KEY_EXPORT')),
  CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELED')),
  CHECK (required_approvals > 0),
  CHECK (require_mfa IN (0, 1)),
  CHECK (json_valid(metadata_json)),
  CHECK (json_valid(decisions_json))
);

CREATE TABLE "billing_prepaid_reservation_summaries" (
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

CREATE TABLE "billing_prepaid_reservations" (
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

CREATE TABLE key_exports (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  wallet_id TEXT,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  requested_by_user_id TEXT NOT NULL,
  required_approvals INTEGER NOT NULL,
  approvals_json TEXT NOT NULL,
  constraints_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (mode IN ('DISABLED', 'APPROVAL_REQUIRED', 'ALLOWED_WITH_CONSTRAINTS')),
  CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXECUTED', 'CANCELED')),
  CHECK (required_approvals > 0),
  CHECK (json_valid(approvals_json)),
  CHECK (json_valid(constraints_json))
);

CREATE TABLE policies (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'TRANSACTION',
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL,
  version INTEGER NOT NULL,
  rules_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  published_at_ms INTEGER,
  is_system_default INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
  CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
  CHECK (version >= 0),
  CHECK (is_system_default IN (0, 1)),
  CHECK (json_valid(rules_json))
);

CREATE TABLE policy_assignments (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, scope_type, scope_id),
  FOREIGN KEY (namespace, org_id, policy_id)
    REFERENCES policies(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (scope_type IN ('ORG', 'PROJECT', 'ENVIRONMENT', 'WALLET'))
);

CREATE TABLE policy_versions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'TRANSACTION',
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  rules_json TEXT NOT NULL,
  published_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  actor_user_id TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, policy_id, version),
  FOREIGN KEY (namespace, org_id, policy_id)
    REFERENCES policies(namespace, org_id, id)
    ON DELETE CASCADE,
  CHECK (kind IN ('TRANSACTION', 'GAS_SPONSORSHIP')),
  CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
  CHECK (version >= 0),
  CHECK (json_valid(rules_json))
);

CREATE TABLE "runtime_snapshot_outbox" (
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

CREATE TABLE "runtime_snapshots" (
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

CREATE TABLE "sponsored_call_records" (
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

CREATE TABLE sponsorship_pricing_rules (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  policy_id TEXT NOT NULL DEFAULT '',
  chain_family TEXT NOT NULL,
  chain_id INTEGER NOT NULL,
  intent_kind TEXT NOT NULL,
  executor_kind TEXT NOT NULL,
  model_kind TEXT NOT NULL,
  pricing_version TEXT NOT NULL,
  estimate_fee_per_gas_wei TEXT NOT NULL,
  minor_per_wei_numerator TEXT NOT NULL,
  minor_per_wei_denominator TEXT NOT NULL,
  min_spend_minor INTEGER NOT NULL DEFAULT 0,
  rounding_mode TEXT NOT NULL,
  status TEXT NOT NULL,
  effective_from_ms INTEGER NOT NULL,
  effective_until_ms INTEGER,
  created_by TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, pricing_version),
  CHECK (chain_family = 'evm'),
  CHECK (chain_id > 0),
  CHECK (intent_kind = 'evm_call'),
  CHECK (executor_kind = 'evm_eoa'),
  CHECK (model_kind = 'evm_static_gas_v1'),
  CHECK (length(pricing_version) > 0),
  CHECK (length(estimate_fee_per_gas_wei) > 0),
  CHECK (length(minor_per_wei_numerator) > 0),
  CHECK (length(minor_per_wei_denominator) > 0),
  CHECK (min_spend_minor >= 0),
  CHECK (rounding_mode = 'ceil'),
  CHECK (status IN ('active', 'retired')),
  CHECK (effective_from_ms > 0),
  CHECK (effective_until_ms IS NULL OR effective_until_ms > effective_from_ms),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms)
);

CREATE TABLE sponsorship_spend_cap_reservations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  account_ref TEXT NOT NULL DEFAULT '',
  chain_id INTEGER NOT NULL,
  mode TEXT NOT NULL,
  period TEXT NOT NULL,
  window_start_ms INTEGER NOT NULL,
  window_end_ms INTEGER NOT NULL,
  cap_minor INTEGER NOT NULL,
  requested_minor INTEGER NOT NULL,
  settled_minor INTEGER NOT NULL DEFAULT 0,
  released_minor INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (chain_id > 0),
  CHECK (mode IN ('CHAIN_TOTAL', 'WALLET_CHAIN_TOTAL')),
  CHECK (period IN ('WEEKLY', 'MONTHLY')),
  CHECK (status IN ('RESERVED', 'SETTLED', 'RELEASED')),
  CHECK (window_end_ms > window_start_ms),
  CHECK (cap_minor >= 0),
  CHECK (requested_minor >= 0),
  CHECK (settled_minor >= 0),
  CHECK (released_minor >= 0)
);

CREATE TABLE sponsorship_spend_cap_windows (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  account_ref TEXT NOT NULL DEFAULT '',
  chain_id INTEGER NOT NULL,
  mode TEXT NOT NULL,
  period TEXT NOT NULL,
  window_start_ms INTEGER NOT NULL,
  window_end_ms INTEGER NOT NULL,
  cap_minor INTEGER NOT NULL,
  reserved_minor INTEGER NOT NULL DEFAULT 0,
  settled_minor INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    environment_id,
    policy_id,
    account_ref,
    chain_id,
    mode,
    period,
    window_start_ms
  ),
  CHECK (chain_id > 0),
  CHECK (mode IN ('CHAIN_TOTAL', 'WALLET_CHAIN_TOTAL')),
  CHECK (period IN ('WEEKLY', 'MONTHLY')),
  CHECK (window_end_ms > window_start_ms),
  CHECK (cap_minor >= 0),
  CHECK (reserved_minor >= 0),
  CHECK (settled_minor >= 0)
);

CREATE TABLE wallet_index (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  external_ref_id TEXT NOT NULL,
  address TEXT NOT NULL,
  chain TEXT NOT NULL,
  wallet_type TEXT NOT NULL,
  status TEXT NOT NULL,
  policy_id TEXT,
  balance_minor INTEGER NOT NULL,
  last_activity_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, address),
  CHECK (chain IN ('Ethereum', 'Base', 'Tempo', 'Arc Circle', 'NEAR')),
  CHECK (wallet_type IN ('EOA', 'SMART')),
  CHECK (status IN ('ACTIVE', 'FROZEN', 'ARCHIVED'))
);

CREATE INDEX approvals_org_operation_idx
  ON approvals (namespace, org_id, operation_type, updated_at_ms DESC);

CREATE INDEX approvals_org_status_idx
  ON approvals (namespace, org_id, status, updated_at_ms DESC);

CREATE INDEX approvals_org_updated_idx
  ON approvals (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE UNIQUE INDEX billing_prepaid_reservations_namespace_id_idx
  ON billing_prepaid_reservations (namespace, id);

CREATE INDEX billing_prepaid_reservations_org_status_idx
  ON billing_prepaid_reservations (namespace, org_id, status, expires_at_ms ASC);

CREATE UNIQUE INDEX billing_prepaid_reservations_source_event_idx
  ON billing_prepaid_reservations (namespace, org_id, source_event_id);

CREATE INDEX billing_prepaid_reservations_status_idx
  ON billing_prepaid_reservations (namespace, status, expires_at_ms ASC);

CREATE INDEX key_exports_org_environment_idx
  ON key_exports (namespace, org_id, environment_id, updated_at_ms DESC);

CREATE INDEX key_exports_org_status_idx
  ON key_exports (namespace, org_id, status, updated_at_ms DESC);

CREATE INDEX key_exports_org_updated_idx
  ON key_exports (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE UNIQUE INDEX policies_namespace_id_uidx
  ON policies (namespace, id);

CREATE INDEX policies_org_status_idx
  ON policies (namespace, org_id, status);

CREATE UNIQUE INDEX policies_org_system_default_uidx
  ON policies (namespace, org_id)
  WHERE is_system_default = 1;

CREATE INDEX policies_org_updated_idx
  ON policies (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX policy_assignments_org_scope_idx
  ON policy_assignments (namespace, org_id, scope_type, scope_id);

CREATE INDEX policy_assignments_org_updated_idx
  ON policy_assignments (namespace, org_id, updated_at_ms DESC, created_at_ms DESC);

CREATE INDEX policy_versions_org_policy_created_idx
  ON policy_versions (namespace, org_id, policy_id, created_at_ms DESC);

CREATE INDEX runtime_snapshot_outbox_claim_idx
  ON runtime_snapshot_outbox (
    namespace,
    org_id,
    claimed_by,
    claim_expires_at_ms
  );

CREATE INDEX runtime_snapshot_outbox_visible_idx
  ON runtime_snapshot_outbox (
    namespace,
    org_id,
    status,
    available_at_ms ASC,
    created_at_ms ASC,
    event_id ASC
  );

CREATE INDEX runtime_snapshots_env_version_idx
  ON runtime_snapshots (
    namespace,
    org_id,
    environment_id,
    version DESC,
    created_at_ms DESC
  );

CREATE INDEX runtime_snapshots_scope_version_idx
  ON runtime_snapshots (
    namespace,
    org_id,
    project_id,
    environment_id,
    version DESC,
    created_at_ms DESC
  );

CREATE UNIQUE INDEX sponsored_call_idempotency_key_idx
  ON sponsored_call_records (namespace, org_id, idempotency_key);

CREATE INDEX sponsored_call_org_created_idx
  ON sponsored_call_records (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX sponsored_call_org_environment_created_idx
  ON sponsored_call_records (namespace, org_id, environment_id, created_at_ms DESC, id DESC);

CREATE INDEX sponsored_call_org_policy_created_idx
  ON sponsored_call_records (namespace, org_id, policy_id, created_at_ms DESC, id DESC);

CREATE UNIQUE INDEX sponsorship_pricing_active_selector_idx
  ON sponsorship_pricing_rules (
    namespace,
    org_id,
    project_id,
    environment_id,
    policy_id,
    chain_family,
    chain_id,
    intent_kind,
    executor_kind
  )
  WHERE status = 'active';

CREATE INDEX sponsorship_pricing_environment_idx
  ON sponsorship_pricing_rules (
    namespace,
    environment_id,
    policy_id,
    chain_id,
    status,
    effective_from_ms DESC
  );

CREATE UNIQUE INDEX sponsorship_spend_cap_source_event_idx
  ON sponsorship_spend_cap_reservations (namespace, org_id, source_event_id);

CREATE INDEX sponsorship_spend_cap_windows_updated_idx
  ON sponsorship_spend_cap_windows (namespace, org_id, updated_at_ms DESC);

CREATE INDEX wallet_index_org_balance_idx
  ON wallet_index (namespace, org_id, balance_minor DESC, id DESC);

CREATE INDEX wallet_index_org_created_idx
  ON wallet_index (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX wallet_index_org_external_ref_idx
  ON wallet_index (namespace, org_id, external_ref_id);

CREATE INDEX wallet_index_org_last_activity_idx
  ON wallet_index (namespace, org_id, COALESCE(last_activity_at_ms, 0) DESC, id DESC);

CREATE INDEX wallet_index_org_project_env_idx
  ON wallet_index (namespace, org_id, project_id, environment_id);

CREATE INDEX wallet_index_org_status_type_chain_idx
  ON wallet_index (namespace, org_id, status, wallet_type, chain);

CREATE INDEX wallet_index_org_user_idx
  ON wallet_index (namespace, org_id, user_id);

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

CREATE TRIGGER sponsorship_spend_cap_reservations_release_update
BEFORE UPDATE OF status ON sponsorship_spend_cap_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status = 'RELEASED'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
        FROM sponsorship_spend_cap_windows
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms
    )
    THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
  END;

  SELECT CASE
    WHEN (
      SELECT reserved_minor
        FROM sponsorship_spend_cap_windows
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms
    ) < OLD.requested_minor
    THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
  END;

  UPDATE sponsorship_spend_cap_windows
     SET reserved_minor = reserved_minor - OLD.requested_minor,
         updated_at_ms = NEW.updated_at_ms
   WHERE namespace = OLD.namespace
     AND org_id = OLD.org_id
     AND environment_id = OLD.environment_id
     AND policy_id = OLD.policy_id
     AND account_ref = OLD.account_ref
     AND chain_id = OLD.chain_id
     AND mode = OLD.mode
     AND period = OLD.period
     AND window_start_ms = OLD.window_start_ms;
END;

CREATE TRIGGER sponsorship_spend_cap_reservations_reserve_insert
BEFORE INSERT ON sponsorship_spend_cap_reservations
WHEN NEW.status = 'RESERVED'
BEGIN
  INSERT INTO sponsorship_spend_cap_windows (
    namespace,
    org_id,
    environment_id,
    policy_id,
    account_ref,
    chain_id,
    mode,
    period,
    window_start_ms,
    window_end_ms,
    cap_minor,
    reserved_minor,
    settled_minor,
    created_at_ms,
    updated_at_ms
  )
  VALUES (
    NEW.namespace,
    NEW.org_id,
    NEW.environment_id,
    NEW.policy_id,
    NEW.account_ref,
    NEW.chain_id,
    NEW.mode,
    NEW.period,
    NEW.window_start_ms,
    NEW.window_end_ms,
    NEW.cap_minor,
    0,
    0,
    NEW.created_at_ms,
    NEW.created_at_ms
  )
  ON CONFLICT (
    namespace,
    org_id,
    environment_id,
    policy_id,
    account_ref,
    chain_id,
    mode,
    period,
    window_start_ms
  ) DO NOTHING;

  SELECT CASE
    WHEN (
      SELECT reserved_minor + settled_minor
        FROM sponsorship_spend_cap_windows
       WHERE namespace = NEW.namespace
         AND org_id = NEW.org_id
         AND environment_id = NEW.environment_id
         AND policy_id = NEW.policy_id
         AND account_ref = NEW.account_ref
         AND chain_id = NEW.chain_id
         AND mode = NEW.mode
         AND period = NEW.period
         AND window_start_ms = NEW.window_start_ms
    ) + NEW.requested_minor > NEW.cap_minor
    THEN RAISE(ABORT, 'sponsorship_spend_cap_exceeded')
  END;

  UPDATE sponsorship_spend_cap_windows
     SET window_end_ms = NEW.window_end_ms,
         cap_minor = NEW.cap_minor,
         reserved_minor = reserved_minor + NEW.requested_minor,
         updated_at_ms = NEW.created_at_ms
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id
     AND environment_id = NEW.environment_id
     AND policy_id = NEW.policy_id
     AND account_ref = NEW.account_ref
     AND chain_id = NEW.chain_id
     AND mode = NEW.mode
     AND period = NEW.period
     AND window_start_ms = NEW.window_start_ms;
END;

CREATE TRIGGER sponsorship_spend_cap_reservations_settle_update
BEFORE UPDATE OF status ON sponsorship_spend_cap_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status = 'SETTLED'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
        FROM sponsorship_spend_cap_windows
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms
    )
    THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
  END;

  SELECT CASE
    WHEN (
      SELECT reserved_minor
        FROM sponsorship_spend_cap_windows
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms
    ) < OLD.requested_minor
    THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
  END;

  SELECT CASE
    WHEN (
      SELECT reserved_minor + settled_minor - OLD.requested_minor + NEW.settled_minor
        FROM sponsorship_spend_cap_windows
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms
    ) > (
      SELECT cap_minor
        FROM sponsorship_spend_cap_windows
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms
    )
    THEN RAISE(ABORT, 'sponsorship_spend_cap_exceeded')
  END;

  UPDATE sponsorship_spend_cap_windows
     SET reserved_minor = reserved_minor - OLD.requested_minor,
         settled_minor = settled_minor + NEW.settled_minor,
         updated_at_ms = NEW.updated_at_ms
   WHERE namespace = OLD.namespace
     AND org_id = OLD.org_id
     AND environment_id = OLD.environment_id
     AND policy_id = OLD.policy_id
     AND account_ref = OLD.account_ref
     AND chain_id = OLD.chain_id
     AND mode = OLD.mode
     AND period = OLD.period
     AND window_start_ms = OLD.window_start_ms;
END;
