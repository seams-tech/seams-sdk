CREATE TABLE IF NOT EXISTS router_ab_yao_capability_replacements (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  operation_fingerprint TEXT NOT NULL,
  previous_capability_binding_json TEXT NOT NULL,
  next_capability_binding_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id, env_id, operation_id),
  CHECK (length(operation_id) > 0),
  CHECK (length(operation_fingerprint) > 0),
  CHECK (json_valid(previous_capability_binding_json)),
  CHECK (json_valid(next_capability_binding_json)),
  CHECK (created_at_ms >= 0)
);
