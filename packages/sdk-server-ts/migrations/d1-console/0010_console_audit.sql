CREATE TABLE IF NOT EXISTS console_audit_events (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  project_id TEXT,
  environment_id TEXT,
  actor_user_id TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  category TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  summary TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (actor_type IN ('USER', 'SYSTEM')),
  CHECK (category IN ('POLICY', 'SETTINGS', 'KEY_EXPORT', 'BILLING', 'WEBHOOK', 'API_KEY', 'TEAM', 'APPROVAL', 'ORG_PROJECT_ENV', 'RUNTIME_SNAPSHOT', 'SYSTEM')),
  CHECK (outcome IN ('SUCCESS', 'FAILURE', 'PENDING')),
  CHECK (json_valid(metadata_json))
);

CREATE INDEX IF NOT EXISTS console_audit_events_org_created_idx
  ON console_audit_events (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_audit_events_org_category_idx
  ON console_audit_events (namespace, org_id, category, created_at_ms DESC);

CREATE INDEX IF NOT EXISTS console_audit_events_org_outcome_idx
  ON console_audit_events (namespace, org_id, outcome, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS console_audit_evidence (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  project_id TEXT,
  environment_id TEXT,
  domain TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  event_ids_json TEXT NOT NULL,
  references_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  CHECK (domain IN ('POLICY', 'BILLING', 'KEY_EXPORT', 'SECURITY')),
  CHECK (json_valid(event_ids_json)),
  CHECK (json_valid(references_json))
);

CREATE INDEX IF NOT EXISTS console_audit_evidence_org_created_idx
  ON console_audit_evidence (namespace, org_id, created_at_ms DESC, id DESC);

CREATE INDEX IF NOT EXISTS console_audit_evidence_org_domain_idx
  ON console_audit_evidence (namespace, org_id, domain, created_at_ms DESC);
