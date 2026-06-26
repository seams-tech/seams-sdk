CREATE TABLE IF NOT EXISTS console_sponsorship_spend_cap_windows (
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

CREATE TABLE IF NOT EXISTS console_sponsorship_spend_cap_reservations (
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

CREATE UNIQUE INDEX IF NOT EXISTS console_sponsorship_spend_cap_source_event_idx
  ON console_sponsorship_spend_cap_reservations (namespace, org_id, source_event_id);

CREATE INDEX IF NOT EXISTS console_sponsorship_spend_cap_windows_updated_idx
  ON console_sponsorship_spend_cap_windows (namespace, org_id, updated_at_ms DESC);

CREATE TRIGGER IF NOT EXISTS console_sponsorship_spend_cap_reservations_reserve_insert
BEFORE INSERT ON console_sponsorship_spend_cap_reservations
WHEN NEW.status = 'RESERVED'
BEGIN
  INSERT INTO console_sponsorship_spend_cap_windows (
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
        FROM console_sponsorship_spend_cap_windows
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

  UPDATE console_sponsorship_spend_cap_windows
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

CREATE TRIGGER IF NOT EXISTS console_sponsorship_spend_cap_reservations_settle_update
BEFORE UPDATE OF status ON console_sponsorship_spend_cap_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status = 'SETTLED'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
        FROM console_sponsorship_spend_cap_windows
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
        FROM console_sponsorship_spend_cap_windows
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
        FROM console_sponsorship_spend_cap_windows
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
        FROM console_sponsorship_spend_cap_windows
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

  UPDATE console_sponsorship_spend_cap_windows
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

CREATE TRIGGER IF NOT EXISTS console_sponsorship_spend_cap_reservations_release_update
BEFORE UPDATE OF status ON console_sponsorship_spend_cap_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status = 'RELEASED'
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (
      SELECT 1
        FROM console_sponsorship_spend_cap_windows
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
        FROM console_sponsorship_spend_cap_windows
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

  UPDATE console_sponsorship_spend_cap_windows
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
