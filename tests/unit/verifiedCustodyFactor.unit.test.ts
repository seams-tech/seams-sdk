import { expect, test } from '@playwright/test';
import { verifiedCustodyFactorFromAuthority } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/verifiedCustodyFactor';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  EMAIL_OTP_FACTOR_KEK_VERSION_V1,
  PASSKEY_PRF_KEK_VERSION_V1,
} from '../../packages/shared-ts/src/passkey-custody';

/**
 * Where a custody envelope's factor comes from.
 *
 * The factor is what the envelope's AAD binds the seed to, so it must name the
 * credential this server verified — never one the client's payload asked for.
 * These own that: the factor is a function of the verified authority, and the
 * Email OTP arm refuses to guess the enrollment it would otherwise seal against.
 */

const WALLET_ID = 'alice.testnet';
const RP_ID = 'example.localhost';
const CREDENTIAL_ID_B64U = 'Y3JlZGVudGlhbC1pZC1vbmU';
const ENROLLMENT_ID = 'enrollment-1';
const ENROLLMENT_SEAL_KEY_VERSION = 'seal-v1';

function passkeyAuthority() {
  return buildPasskeyWalletAuthAuthority({
    walletId: WALLET_ID,
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
  });
}

function emailOtpAuthority() {
  return buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: 'google-user-1',
    emailHashHex: 'a'.repeat(64),
  });
}

test('a verified passkey authority names its own credential', () => {
  const result = verifiedCustodyFactorFromAuthority({ authority: passkeyAuthority() });

  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.factor).toEqual({
    kind: 'passkey',
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
    kekVersion: PASSKEY_PRF_KEK_VERSION_V1,
  });
});

test('the passkey factor takes the RP id the verification ran against', () => {
  // `verifier.rpId` is what WebAuthn was checked against. A factor built from
  // anything else would bind custody to an origin nobody proved.
  const authority = passkeyAuthority();
  const result = verifiedCustodyFactorFromAuthority({ authority });
  expect(result.ok && result.factor.kind === 'passkey' && result.factor.rpId).toBe(
    String(authority.verifier.rpId),
  );
});

test('a verified Email OTP authority names the enrollment it was given', () => {
  const result = verifiedCustodyFactorFromAuthority({
    authority: emailOtpAuthority(),
    emailOtpEnrollment: {
      enrollmentId: ENROLLMENT_ID,
      enrollmentSealKeyVersion: ENROLLMENT_SEAL_KEY_VERSION,
    },
  });

  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.factor).toEqual({
    kind: 'email_otp',
    enrollmentId: ENROLLMENT_ID,
    enrollmentSealKeyVersion: ENROLLMENT_SEAL_KEY_VERSION,
    kekVersion: EMAIL_OTP_FACTOR_KEK_VERSION_V1,
  });
});

test('an Email OTP authority without its enrollment is refused, not defaulted', () => {
  // Sealing against a guessed enrollment produces an envelope that never opens,
  // and the failure would surface much later as a wallet that cannot unlock.
  for (const enrollment of [
    undefined,
    { enrollmentId: '', enrollmentSealKeyVersion: ENROLLMENT_SEAL_KEY_VERSION },
    { enrollmentId: ENROLLMENT_ID, enrollmentSealKeyVersion: '  ' },
  ]) {
    const result = verifiedCustodyFactorFromAuthority({
      authority: emailOtpAuthority(),
      ...(enrollment ? { emailOtpEnrollment: enrollment } : {}),
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toContain('verified enrollment');
  }
});

test('an Email OTP enrollment is ignored for a passkey authority', () => {
  // The authority decides the factor kind. A passkey registration that also
  // carried OTP enrollment facts must still produce a passkey factor.
  const result = verifiedCustodyFactorFromAuthority({
    authority: passkeyAuthority(),
    emailOtpEnrollment: {
      enrollmentId: ENROLLMENT_ID,
      enrollmentSealKeyVersion: ENROLLMENT_SEAL_KEY_VERSION,
    },
  });
  expect(result.ok && result.factor.kind).toBe('passkey');
});

test('each factor carries its own KEK version, never the other kind s', () => {
  // signer-core refuses a factor whose declared KEK version belongs to the
  // other kind, so these must not be interchangeable here either.
  const passkey = verifiedCustodyFactorFromAuthority({ authority: passkeyAuthority() });
  const emailOtp = verifiedCustodyFactorFromAuthority({
    authority: emailOtpAuthority(),
    emailOtpEnrollment: {
      enrollmentId: ENROLLMENT_ID,
      enrollmentSealKeyVersion: ENROLLMENT_SEAL_KEY_VERSION,
    },
  });

  expect(passkey.ok && passkey.factor.kekVersion).toBe(PASSKEY_PRF_KEK_VERSION_V1);
  expect(emailOtp.ok && emailOtp.factor.kekVersion).toBe(EMAIL_OTP_FACTOR_KEK_VERSION_V1);
  expect(PASSKEY_PRF_KEK_VERSION_V1).not.toBe(EMAIL_OTP_FACTOR_KEK_VERSION_V1);
});
