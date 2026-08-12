-- Durable idempotency boundary for Google Email OTP session exchange.
-- The prepared session and device identities are generated once at claim time
-- and every later phase advances the same row with an optimistic version.
CREATE TABLE IF NOT EXISTS google_email_otp_session_exchange_journals (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  account_mode TEXT NOT NULL,
  lifecycle_kind TEXT NOT NULL,
  phase TEXT NOT NULL,
  version INTEGER NOT NULL,
  phase_data_json TEXT NOT NULL,
  prepared_seams_session_id TEXT NOT NULL,
  prepared_device_id TEXT NOT NULL,
  prepared_created_at_ms INTEGER NOT NULL,
  response_status INTEGER,
  response_body_text TEXT,
  response_set_cookie TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, idempotency_key),
  CHECK (length(namespace) > 0),
  CHECK (length(org_id) > 0),
  CHECK (length(project_id) > 0),
  CHECK (length(env_id) > 0),
  CHECK (length(idempotency_key) BETWEEN 1 AND 512),
  CHECK (length(request_fingerprint) BETWEEN 1 AND 512),
  CHECK (account_mode = 'login'),
  CHECK (lifecycle_kind IN ('in_progress', 'completed')),
  CHECK (
    phase IN (
      'claimed',
      'session_prepared',
      'completed'
    )
  ),
  CHECK (version >= 1),
  CHECK (json_valid(phase_data_json)),
  CHECK (length(CAST(phase_data_json AS BLOB)) <= 65536),
  CHECK (length(prepared_seams_session_id) > 0),
  CHECK (length(prepared_device_id) > 0),
  CHECK (prepared_created_at_ms > 0),
  CHECK (prepared_created_at_ms = created_at_ms),
  CHECK (updated_at_ms >= created_at_ms),
  CHECK (expires_at_ms > created_at_ms),
  CHECK (
    (lifecycle_kind = 'in_progress'
      AND phase != 'completed'
      AND response_status IS NULL
      AND response_body_text IS NULL
      AND response_set_cookie IS NULL)
    OR (lifecycle_kind = 'completed'
      AND phase = 'completed'
      AND response_status BETWEEN 100 AND 599
      AND response_body_text IS NOT NULL
      AND length(CAST(response_body_text AS BLOB)) <= 65536)
  ),
  CHECK (response_set_cookie IS NULL OR length(CAST(response_set_cookie AS BLOB)) <= 8192)
);

CREATE INDEX IF NOT EXISTS google_email_otp_session_exchange_journals_expires_idx
  ON google_email_otp_session_exchange_journals (
    namespace,
    org_id,
    project_id,
    env_id,
    expires_at_ms
  );
