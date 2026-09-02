-- Refactor 115: admit the recovery-bound Email OTP challenge purpose.

PRAGMA defer_foreign_keys = ON;

DROP INDEX email_otp_challenges_context_idx;
DROP INDEX email_otp_challenges_expires_idx;

ALTER TABLE email_otp_challenges RENAME TO email_otp_challenges_r114;

CREATE TABLE email_otp_challenges (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  challenge_subject_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  record_org_id TEXT NOT NULL,
  otp_channel TEXT NOT NULL,
  owner_proof_binding_digest TEXT NOT NULL,
  action TEXT NOT NULL,
  operation TEXT NOT NULL,
  otp_code TEXT NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, challenge_id),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(challenge_id) > 0),
  CHECK (length(challenge_subject_id) > 0),
  CHECK (length(wallet_id) > 0),
  CHECK (length(record_org_id) > 0),
  CHECK (otp_channel = 'email_otp'),
  CHECK (length(owner_proof_binding_digest) > 0),
  CHECK (
    action IN (
      'wallet_email_otp_login',
      'wallet_email_otp_registration',
      'wallet_email_otp_device_recovery',
      'wallet_email_otp_device_link',
      'wallet_email_otp_recovery_bootstrap'
    )
  ),
  CHECK (operation IN ('wallet_unlock', 'transaction_sign', 'export_key', 'registration', 'device_link')),
  CHECK (length(otp_code) > 0),
  CHECK (json_valid(record_json)),
  CHECK (created_at_ms > 0),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (COALESCE(json_extract(record_json, '$.version') = 'email_otp_challenge_v1', 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeId') = challenge_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.challengeSubjectId') = challenge_subject_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.walletId') = wallet_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.orgId') = record_org_id, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.otpChannel') = otp_channel, 0)),
  CHECK (
    COALESCE(json_extract(record_json, '$.ownerProofBindingDigest') = owner_proof_binding_digest, 0)
  ),
  CHECK (COALESCE(json_extract(record_json, '$.action') = action, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.operation') = operation, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.otpCode') = otp_code, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.createdAtMs') = created_at_ms, 0)),
  CHECK (COALESCE(json_extract(record_json, '$.expiresAtMs') = expires_at_ms, 0))
);

INSERT INTO email_otp_challenges (
  namespace, org_id, project_id, env_id, challenge_id, challenge_subject_id,
  wallet_id, record_org_id, otp_channel, owner_proof_binding_digest, action,
  operation, otp_code, record_json, created_at_ms, expires_at_ms
)
SELECT namespace, org_id, project_id, env_id, challenge_id, challenge_subject_id,
       wallet_id, record_org_id, otp_channel, owner_proof_binding_digest, action,
       operation, otp_code, record_json, created_at_ms, expires_at_ms
  FROM email_otp_challenges_r114;

DROP TABLE email_otp_challenges_r114;

CREATE INDEX email_otp_challenges_context_idx
  ON email_otp_challenges (
    namespace, org_id, project_id, env_id, challenge_subject_id, wallet_id,
    record_org_id, otp_channel, owner_proof_binding_digest, action, operation,
    expires_at_ms, created_at_ms
  );

CREATE INDEX email_otp_challenges_expires_idx
  ON email_otp_challenges (namespace, org_id, project_id, env_id, expires_at_ms);

PRAGMA defer_foreign_keys = OFF;
