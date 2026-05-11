BEGIN;

TRUNCATE TABLE
  threshold_signing_session_seal_idempotency,
  threshold_ecdsa_presignatures,
  threshold_ecdsa_presign_sessions,
  threshold_ecdsa_signing_sessions,
  threshold_ed25519_auth_consumptions,
  threshold_ed25519_sessions,
  signing_root_secret_shares,
  threshold_ecdsa_keys,
  threshold_ed25519_keys,
  email_otp_registration_attempts,
  email_otp_unlock_challenges,
  email_otp_auth_states,
  email_otp_recovery_wrapped_enrollment_escrows,
  email_otp_wallet_enrollments,
  email_otp_grants,
  email_otp_challenges;

COMMIT;
