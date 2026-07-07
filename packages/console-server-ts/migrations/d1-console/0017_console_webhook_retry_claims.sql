ALTER TABLE webhook_deliveries ADD COLUMN retry_claimed_by TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN retry_claim_expires_at_ms INTEGER;

CREATE INDEX IF NOT EXISTS webhook_deliveries_retry_claim_idx
  ON webhook_deliveries (
    namespace,
    org_id,
    status,
    retry_claim_expires_at_ms,
    last_attempt_at_ms,
    created_at_ms,
    id
  );
