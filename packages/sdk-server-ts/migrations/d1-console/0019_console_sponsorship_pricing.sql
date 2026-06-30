CREATE TABLE IF NOT EXISTS sponsorship_pricing_rules (
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

CREATE UNIQUE INDEX IF NOT EXISTS sponsorship_pricing_active_selector_idx
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

CREATE INDEX IF NOT EXISTS sponsorship_pricing_environment_idx
  ON sponsorship_pricing_rules (
    namespace,
    environment_id,
    policy_id,
    chain_id,
    status,
    effective_from_ms DESC
  );
