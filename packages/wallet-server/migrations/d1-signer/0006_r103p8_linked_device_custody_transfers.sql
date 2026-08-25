-- Refactor 103 Phase 8: the relay row for one cross-device custody transfer.
--
-- Device 2 publishes the recipient key it will decapsulate with, and Device 1
-- returns the seed sealed to that key. Neither half is a secret — the private
-- half never leaves Device 2's custody module — so this table stores public
-- routing facts and opaque ciphertext.
--
-- One row per link session, matching `linked_device_target_credentials`, with
-- the same two-state shape: a row is `recipient_registered` until the sealed
-- package lands, and `sealed` afterwards. The CHECK makes the two column sets
-- mutually exclusive, so a half-written transfer cannot be read as a complete
-- one.
--
-- The recipient key is immutable once registered. Device 1 seals to whatever
-- this row says, so allowing it to change after registration would let a later
-- write redirect a seed that is already in flight.
CREATE TABLE linked_device_custody_transfers (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  link_session_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  state TEXT NOT NULL,
  transfer_alg TEXT NOT NULL,
  recipient_public_key_b64u TEXT NOT NULL,
  recipient_json TEXT NOT NULL,
  package_json TEXT,
  ephemeral_public_key_b64u TEXT,
  ciphertext_digest_b64u TEXT,
  registered_at_ms INTEGER NOT NULL,
  sealed_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id),
  FOREIGN KEY (namespace, org_id, project_id, env_id, link_session_id)
    REFERENCES linked_device_sessions(namespace, org_id, project_id, env_id, link_session_id),
  CHECK (length(wallet_id) > 0),
  CHECK (length(enrollment_id) > 0),
  CHECK (length(device_id) > 0),
  CHECK (state IN ('recipient_registered', 'sealed')),
  CHECK (transfer_alg = 'x25519-hkdf-sha256-chacha20poly1305-v1'),
  CHECK (length(recipient_public_key_b64u) > 0),
  CHECK (json_valid(recipient_json)),
  CHECK (registered_at_ms > 0),
  CHECK (
    COALESCE(json_extract(recipient_json, '$.recipientPublicKeyB64u')
      = recipient_public_key_b64u, 0)
  ),
  CHECK (
    (state = 'recipient_registered'
      AND package_json IS NULL
      AND ephemeral_public_key_b64u IS NULL
      AND ciphertext_digest_b64u IS NULL
      AND sealed_at_ms IS NULL)
    OR
    (state = 'sealed'
      AND json_valid(package_json)
      AND length(ephemeral_public_key_b64u) > 0
      AND length(ciphertext_digest_b64u) > 0
      AND sealed_at_ms >= registered_at_ms
      -- A package that names another recipient key would be addressed to a
      -- device this row never registered.
      AND COALESCE(json_extract(package_json, '$.recipientPublicKeyB64u')
        = recipient_public_key_b64u, 0)
      -- Republishing the recipient key as the ephemeral key is never a valid
      -- seal; it means no ephemeral key was generated.
      AND ephemeral_public_key_b64u <> recipient_public_key_b64u)
  )
);

-- Device management and the enrollment flow both resolve a transfer by the
-- enrollment rather than the link session, so that lookup gets its own index.
CREATE UNIQUE INDEX linked_device_custody_transfers_enrollment_idx
  ON linked_device_custody_transfers (
    namespace, org_id, project_id, env_id, wallet_id, enrollment_id, device_id
  );
