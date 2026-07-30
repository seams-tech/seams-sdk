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

CREATE INDEX billing_stripe_post_processing_pending_idx
  ON billing_stripe_post_processing_outbox (
    namespace,
    audit_completed_at_ms,
    customer_webhook_completed_at_ms,
    created_at_ms,
    event_id
  );

CREATE UNIQUE INDEX webhook_deliveries_event_endpoint_uidx
  ON webhook_deliveries (namespace, org_id, endpoint_id, event_id);
