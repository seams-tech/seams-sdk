-- Refactor 109D: the same verified Email identity may authenticate methods on
-- multiple wallets. Custody enrollment material remains isolated per wallet.

DROP INDEX IF EXISTS email_otp_wallet_enrollments_provider_idx;

CREATE TABLE email_otp_wallet_enrollments_v2 (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  verified_email TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, wallet_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(provider_user_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (length(verified_email) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (
    COALESCE(json_extract(record_json, '$.version') = 'email_otp_wallet_enrollment_v1', 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.providerUserId') = provider_user_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.verifiedEmail') = verified_email, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.updatedAtMs') = updated_at_ms, 0))
);

INSERT INTO email_otp_wallet_enrollments_v2 (
  namespace, org_id, project_id, env_id, wallet_id, provider_user_id,
  record_org_id, verified_email, record_json, created_at_ms, updated_at_ms
)
SELECT
  namespace, org_id, project_id, env_id, wallet_id, provider_user_id,
  record_org_id, verified_email, record_json, created_at_ms, updated_at_ms
FROM email_otp_wallet_enrollments;

DROP TABLE email_otp_wallet_enrollments;
ALTER TABLE email_otp_wallet_enrollments_v2 RENAME TO email_otp_wallet_enrollments;

CREATE INDEX email_otp_wallet_enrollments_provider_idx
  ON email_otp_wallet_enrollments (
    namespace, org_id, project_id, env_id, record_org_id,
    provider_user_id, updated_at_ms
  );
