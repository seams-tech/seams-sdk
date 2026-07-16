-- Device metadata captured at WebAuthn registration verification (UA parse +
-- attestation AAGUID/backup flag + transports), serialized as JSON. Rows
-- written before this migration keep the '{}' default and are surfaced as an
-- "Unknown device" by the parse fallback.
ALTER TABLE webauthn_authenticators
  ADD COLUMN device_info_json TEXT NOT NULL DEFAULT '{}';
