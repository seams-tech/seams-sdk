-- R103F final cutover: registration replay is credential-free and no longer
-- has an issuer or resolver for temporary replay bearers.

DROP TABLE registration_replay_opaque_wallet_session_tokens_v1;
