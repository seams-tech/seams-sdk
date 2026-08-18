-- Console core fresh schema (owner: console-core).
-- Product-neutral customer control plane tables only; R105 Phase 6.

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
  CHECK (category IN ('POLICY', 'SETTINGS', 'KEY_EXPORT', 'BILLING', 'WEBHOOK', 'API_KEY', 'TEAM', 'APPROVAL', 'ORG_PROJECT_ENV', 'RUNTIME_SNAPSHOT', 'SYSTEM')),
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
  CHECK (domain IN ('POLICY', 'BILLING', 'KEY_EXPORT', 'SECURITY')),
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
  signing_root_version TEXT NOT NULL DEFAULT 'default',
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
  CHECK (item_type IN ('CREDIT_TOP_UP', 'MAW_USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT')),
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
  CHECK (category IN ('wallet', 'policy', 'auth', 'tx', 'billing', 'session')),
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
