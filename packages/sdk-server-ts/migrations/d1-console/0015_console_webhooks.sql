CREATE TABLE IF NOT EXISTS console_webhook_endpoints (
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
  CHECK (status IN ('ACTIVE', 'DISABLED')),
  CHECK (length(signing_secret_ciphertext_b64u) > 0),
  CHECK (length(signing_secret_key_id) > 0),
  CHECK (length(signing_secret_envelope_version) > 0),
  CHECK (secret_version > 0)
);

CREATE TABLE IF NOT EXISTS console_webhook_endpoint_categories (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  category TEXT NOT NULL,
  PRIMARY KEY (namespace, org_id, endpoint_id, category),
  FOREIGN KEY (namespace, org_id, endpoint_id)
    REFERENCES console_webhook_endpoints(namespace, org_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS console_webhook_deliveries (
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
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (status IN ('SUCCEEDED', 'FAILED')),
  CHECK (attempt_count >= 0),
  CHECK (replay_count >= 0),
  CHECK (json_valid(payload_json)),
  FOREIGN KEY (namespace, org_id, endpoint_id)
    REFERENCES console_webhook_endpoints(namespace, org_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS console_webhook_attempts (
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
    REFERENCES console_webhook_deliveries(namespace, org_id, id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS console_webhook_dead_letters (
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
    REFERENCES console_webhook_deliveries(namespace, org_id, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS console_webhook_endpoints_org_created_idx
  ON console_webhook_endpoints (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_webhook_endpoint_categories_lookup_idx
  ON console_webhook_endpoint_categories (namespace, org_id, category, endpoint_id);

CREATE INDEX IF NOT EXISTS console_webhook_deliveries_endpoint_page_idx
  ON console_webhook_deliveries (namespace, org_id, endpoint_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_webhook_deliveries_event_idx
  ON console_webhook_deliveries (namespace, org_id, event_id);

CREATE INDEX IF NOT EXISTS console_webhook_attempts_endpoint_page_idx
  ON console_webhook_attempts (namespace, org_id, endpoint_id, attempted_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_webhook_attempts_endpoint_delivery_page_idx
  ON console_webhook_attempts (namespace, org_id, endpoint_id, delivery_id, attempted_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_webhook_dead_letters_endpoint_page_idx
  ON console_webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_webhook_dead_letters_unresolved_endpoint_page_idx
  ON console_webhook_dead_letters (namespace, org_id, endpoint_id, moved_to_dlq_at_ms DESC, id DESC)
  WHERE resolved_at_ms IS NULL;
