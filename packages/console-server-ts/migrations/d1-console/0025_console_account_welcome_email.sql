DROP INDEX IF EXISTS console_email_deliveries_outbox_idx;
DROP INDEX IF EXISTS console_email_outbox_dispatch_idx;
DROP INDEX IF EXISTS console_email_outbox_invitation_idx;
DROP INDEX IF EXISTS console_email_outbox_final_failure_idx;

CREATE TABLE console_email_deliveries_saved AS
SELECT * FROM console_email_deliveries;

DROP TABLE console_email_deliveries;

CREATE TABLE console_email_outbox_next (
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

INSERT INTO console_email_outbox_next
SELECT * FROM console_email_outbox;

DROP TABLE console_email_outbox;
ALTER TABLE console_email_outbox_next RENAME TO console_email_outbox;

CREATE INDEX console_email_outbox_dispatch_idx
  ON console_email_outbox (namespace, status, available_at_ms ASC, created_at_ms ASC, id ASC);

CREATE INDEX console_email_outbox_invitation_idx
  ON console_email_outbox (namespace, org_id, invitation_id, status)
  WHERE invitation_id IS NOT NULL;

CREATE INDEX console_email_outbox_final_failure_idx
  ON console_email_outbox (namespace, org_id, status, updated_at_ms DESC, id DESC);

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

INSERT INTO console_email_deliveries
SELECT * FROM console_email_deliveries_saved;

DROP TABLE console_email_deliveries_saved;

CREATE INDEX console_email_deliveries_outbox_idx
  ON console_email_deliveries (namespace, org_id, outbox_id, attempt_number DESC);
