# Threshold Postgres Reset

This reset is for local and development environments after the `refactor-36`
record-shape cleanup. It clears threshold signing/session state that may still
contain pre-refactor rows.

It does not touch unrelated product tables such as account, console, billing,
or recovery execution state.

## When to use it

Run this reset when one of these is true:

- local development data predates the refactor-36 Postgres parser tightening
- a dev database still contains malformed threshold or Email OTP rows that you
  do not need to preserve
- you want a clean threshold-signing state without recreating the entire
  database

## Scope

The reset clears only the threshold/session/signing tables tightened by
Phase 10B:

- `threshold_ed25519_keys`
- `threshold_ecdsa_keys`
- `signing_root_secret_shares`
- `threshold_ed25519_sessions`
- `threshold_ed25519_auth_consumptions`
- `threshold_ecdsa_signing_sessions`
- `threshold_ecdsa_presign_sessions`
- `threshold_ecdsa_presignatures`
- `threshold_signing_session_seal_idempotency`
- `email_otp_challenges`
- `email_otp_grants`
- `email_otp_wallet_enrollments`
- `email_otp_recovery_wrapped_enrollment_escrows`
- `email_otp_auth_states`
- `email_otp_unlock_challenges`
- `email_otp_registration_attempts`

## Reset

```sql
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
```

Example:

```sh
psql "$POSTGRES_URL" -f docs/deployment/threshold-postgres-reset.sql
```

If you prefer not to create a local `.sql` file, paste the SQL block above into
`psql "$POSTGRES_URL"`.

## After reset

1. restart the relay/server process
2. rerun the flow that provisions threshold or Email OTP state
3. do not copy pre-refactor `record_json` rows back into these tables
