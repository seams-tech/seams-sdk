CREATE TABLE IF NOT EXISTS observability_events (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  source TEXT NOT NULL,
  ingested_at_ms INTEGER NOT NULL,
  timestamp_ms INTEGER NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  environment_id TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL,
  component TEXT NOT NULL,
  level TEXT NOT NULL,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  request_id TEXT NOT NULL DEFAULT '',
  trace_id TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL,
  redaction_version INTEGER NOT NULL,
  redaction_applied INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, created_at_ms, event_id),
  CHECK (schema_version >= 1),
  CHECK (source IN ('WEBHOOK', 'BILLING', 'APPROVAL', 'SYSTEM')),
  CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
  CHECK (json_valid(metadata_json)),
  CHECK (redaction_version >= 1),
  CHECK (redaction_applied IN (0, 1))
);

CREATE TABLE IF NOT EXISTS observability_event_dedup (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, event_id)
);

CREATE TABLE IF NOT EXISTS observability_ingest_windows (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  window_start_ms INTEGER NOT NULL,
  accepted_count INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, window_start_ms),
  CHECK (accepted_count >= 0)
);

CREATE TABLE IF NOT EXISTS observability_request_rollups_minute (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  window_start_ms INTEGER NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  environment_id TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL,
  route_family TEXT NOT NULL,
  method TEXT NOT NULL,
  status_class TEXT NOT NULL,
  request_count INTEGER NOT NULL,
  error_count INTEGER NOT NULL,
  latency_sum_ms REAL NOT NULL,
  latency_max_ms REAL NOT NULL,
  latency_bucket_le_50 INTEGER NOT NULL,
  latency_bucket_le_100 INTEGER NOT NULL,
  latency_bucket_le_250 INTEGER NOT NULL,
  latency_bucket_le_500 INTEGER NOT NULL,
  latency_bucket_le_1000 INTEGER NOT NULL,
  latency_bucket_le_2000 INTEGER NOT NULL,
  latency_bucket_le_5000 INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    window_start_ms,
    project_id,
    environment_id,
    service,
    route_family,
    method,
    status_class
  ),
  CHECK (request_count >= 0),
  CHECK (error_count >= 0),
  CHECK (latency_sum_ms >= 0),
  CHECK (latency_max_ms >= 0),
  CHECK (error_count <= request_count)
);

CREATE INDEX IF NOT EXISTS observability_events_org_created_idx
  ON observability_events (namespace, org_id, created_at_ms DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS observability_events_org_service_created_idx
  ON observability_events (namespace, org_id, service, created_at_ms DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS observability_events_org_level_created_idx
  ON observability_events (namespace, org_id, level, created_at_ms DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS observability_events_org_timestamp_idx
  ON observability_events (namespace, org_id, timestamp_ms DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS observability_event_dedup_created_idx
  ON observability_event_dedup (namespace, org_id, created_at_ms);

CREATE INDEX IF NOT EXISTS observability_ingest_windows_window_idx
  ON observability_ingest_windows (namespace, org_id, window_start_ms);

CREATE INDEX IF NOT EXISTS observability_request_rollups_org_window_idx
  ON observability_request_rollups_minute (namespace, org_id, window_start_ms DESC);

CREATE INDEX IF NOT EXISTS observability_request_rollups_org_service_window_idx
  ON observability_request_rollups_minute (namespace, org_id, service, window_start_ms DESC);

CREATE INDEX IF NOT EXISTS observability_request_rollups_org_route_window_idx
  ON observability_request_rollups_minute (namespace, org_id, route_family, window_start_ms DESC);
