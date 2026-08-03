ALTER TABLE capability_grant_uses
  ADD COLUMN material_activation_id TEXT
  CHECK (material_activation_id IS NULL OR length(material_activation_id) > 0);

ALTER TABLE reusable_wallet_session_operation_uses
  ADD COLUMN material_activation_id TEXT
  CHECK (material_activation_id IS NULL OR length(material_activation_id) > 0);

CREATE TABLE ecdsa_authorization_atomic_guards (
  namespace TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  matched INTEGER NOT NULL CHECK (matched = 1),
  PRIMARY KEY (namespace, tenant_id, check_id)
);
