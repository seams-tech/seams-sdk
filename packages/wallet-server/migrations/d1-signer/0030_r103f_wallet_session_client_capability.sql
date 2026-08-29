-- R103F direct issuance rollout metadata.
--
-- Existing V2 rows remain readable through the bridge with null metadata.
-- Direct rows carry the exact client capability and response family at insert.

ALTER TABLE wallet_session_authorizations_v2
  ADD COLUMN wallet_session_client_capability TEXT
  CHECK (
    wallet_session_client_capability IS NULL
    OR length(wallet_session_client_capability) > 0
  );

ALTER TABLE wallet_session_authorizations_v2
  ADD COLUMN response_family TEXT
  CHECK (response_family IS NULL OR length(response_family) > 0);

-- Direct issuance enforces both fields through the exact aggregate/store path.
