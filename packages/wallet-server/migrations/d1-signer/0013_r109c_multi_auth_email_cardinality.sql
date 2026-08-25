-- Refactor 109C: give Email OTP auth methods their canonical provider identity
-- and enforce one active Email method per authority.
--
-- R103E's V2 Email branch stores `email_hash_hex` and a
-- `registration_authority_id` — the OTP challenge that happened to create the
-- method. That is provenance, not identity: `EmailOtpWalletAuthAuthority`
-- needs `provider` and `providerUserId`, and R103E worked around their absence
-- by inferring the subject from an installation's own Ed25519 lanes and
-- requiring exactly one such subject per wallet. That inference cannot survive
-- a wallet with more than one Email method, which is precisely what R109C and
-- R109D create.
--
-- Forward-only. Migrations 0011 and 0012 are applied and are not rewritten;
-- 0011 dropped the wallet-wide Email uniqueness index deliberately, so linked
-- devices could share one verified address, and this migration replaces it
-- with the per-authority constraint rather than restoring it.

-- The provider identity, joined from the wallet's canonical enrollment.
ALTER TABLE wallet_auth_methods ADD COLUMN provider TEXT;
ALTER TABLE wallet_auth_methods ADD COLUMN provider_user_id TEXT;

UPDATE wallet_auth_methods
   SET provider_user_id = (
         SELECT enrollment.provider_user_id
           FROM email_otp_wallet_enrollments AS enrollment
          WHERE enrollment.namespace = wallet_auth_methods.namespace
            AND enrollment.org_id = wallet_auth_methods.org_id
            AND enrollment.project_id = wallet_auth_methods.project_id
            AND enrollment.env_id = wallet_auth_methods.env_id
            AND enrollment.wallet_id = wallet_auth_methods.wallet_id
       )
 WHERE kind = 'email_otp';

-- The current rule, stated once: a `google:` subject is Google, anything else
-- is a plain verified address.
UPDATE wallet_auth_methods
   SET provider = CASE
         WHEN provider_user_id LIKE 'google:%' THEN 'google'
         ELSE 'email'
       END
 WHERE kind = 'email_otp'
   AND provider_user_id IS NOT NULL;

-- Revoked history that cannot resolve an enrollment is dropped: it is audit
-- residue for a method nothing can authenticate, and keeping it would force a
-- nullable provider identity on the live shape.
DELETE FROM wallet_auth_methods
 WHERE kind = 'email_otp'
   AND status = 'revoked'
   AND provider_user_id IS NULL;

-- An active or pending Email method that cannot resolve its enrollment is a
-- different matter: it is a method a user can still authenticate with, whose
-- identity this schema can no longer express. Abort rather than guess.
CREATE TABLE r109c_email_identity_backfill_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);
INSERT INTO r109c_email_identity_backfill_guard (guard_id) VALUES (1);
INSERT INTO r109c_email_identity_backfill_guard (guard_id)
SELECT 1
 WHERE EXISTS (
   SELECT 1
     FROM wallet_auth_methods
    WHERE kind = 'email_otp'
      AND status <> 'revoked'
      AND provider_user_id IS NULL
 );
DROP TABLE r109c_email_identity_backfill_guard;

-- Fold the identity into the canonical record and drop the retired field, so
-- no reader can fall back to provenance.
UPDATE wallet_auth_methods
   SET record_json = json_remove(
         json_set(
           json_set(record_json, '$.provider', provider),
           '$.providerUserId',
           provider_user_id
         ),
         '$.registrationAuthorityId'
       )
 WHERE kind = 'email_otp';

UPDATE wallet_auth_methods
   SET registration_authority_id = NULL
 WHERE kind = 'email_otp';

-- R109C cardinality: one active Email OTP method per authority, across
-- providers. Passkeys are deliberately excluded — an authority may hold
-- several, and their uniqueness is credential-scoped by
-- wallet_auth_methods_v2_passkey_uidx.
CREATE UNIQUE INDEX wallet_auth_methods_v2_authority_email_uidx
  ON wallet_auth_methods (
    namespace, org_id, project_id, env_id, wallet_id, wallet_authority_id
  )
  WHERE kind = 'email_otp' AND status = 'active';

CREATE INDEX wallet_auth_methods_v2_email_provider_idx
  ON wallet_auth_methods (
    namespace, org_id, project_id, env_id, provider, provider_user_id
  )
  WHERE kind = 'email_otp' AND provider_user_id IS NOT NULL;
