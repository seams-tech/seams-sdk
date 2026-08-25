DROP INDEX linked_device_session_transcripts_digest_idx;

ALTER TABLE linked_device_session_transcripts
  RENAME TO linked_device_session_transcripts_legacy;

CREATE TABLE linked_device_session_transcripts (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  transcript_kind TEXT NOT NULL,
  digest_b64u TEXT NOT NULL,
  transcript_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    project_id,
    env_id,
    link_session_id,
    transcript_kind
  ),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (transcript_kind IN ('claim', 'approval', 'source_contribution')),
  CHECK (length(digest_b64u) > 0),
  CHECK (json_valid(transcript_json)),
  CHECK (created_at_ms > 0)
);

INSERT INTO linked_device_session_transcripts (
  namespace,
  org_id,
  project_id,
  env_id,
  link_session_id,
  transcript_kind,
  digest_b64u,
  transcript_json,
  created_at_ms
)
SELECT
  namespace,
  org_id,
  project_id,
  env_id,
  link_session_id,
  transcript_kind,
  digest_b64u,
  transcript_json,
  created_at_ms
FROM linked_device_session_transcripts_legacy;

DROP TABLE linked_device_session_transcripts_legacy;

CREATE INDEX linked_device_session_transcripts_digest_idx
  ON linked_device_session_transcripts(
    namespace,
    org_id,
    project_id,
    env_id,
    digest_b64u
  );
