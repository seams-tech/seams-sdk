import { expect, test } from '@playwright/test';
import {
  EMAIL_OTP_HKDF_SALTS,
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SECRET_KIND,
  emailOtpEcdsaRestoreInfoFields,
  emailOtpEd25519RestoreInfoFields,
  emailOtpSigningSessionRestoreRootInfoFields,
  emailOtpSigningSessionSecretInfoFields,
  emailOtpThresholdEd25519HssInfoFields,
  encodeSigningSessionHkdfTuple,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';

function utf8(value: string): number[] {
  return Array.from(new TextEncoder().encode(value));
}

test.describe('shared signing-session seal specs', () => {
  test('freezes sealed record schema constants and TypeScript shape', () => {
    const record = {
      v: SIGNING_SESSION_SEALED_RECORD_VERSION,
      alg: SIGNING_SESSION_SEAL_ALG,
      storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
      authMethod: 'email_otp',
      secretKind: SIGNING_SESSION_SECRET_KIND,
      storeKey: 'wallet-session-1:email_otp:ecdsa',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: {
        ed25519: 'ed-session',
        ecdsa: 'ec-session',
      },
      sealedSecretB64u: 'sealed-k',
      curve: 'ecdsa',
      subjectId: 'wallet:alice',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'root',
      signingRootVersion: 'root-v1',
      relayerUrl: 'https://relay.example',
      keyVersion: 'seal-v1',
      shamirPrimeB64u: 'prime',
      issuedAtMs: 1,
      expiresAtMs: 2,
      remainingUses: 3,
      updatedAtMs: 4,
    } satisfies SealedSigningSessionRecord;

    expect(record).toMatchObject({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      secretKind: 'signing_session_secret32',
    });
  });

  test('freezes passkey PRF salts in shared code', () => {
    expect(PASSKEY_PRF_FIRST_SALT_V1).toHaveLength(32);
    expect(PASSKEY_PRF_SECOND_SALT_V1).toHaveLength(32);
    expect(Array.from(PASSKEY_PRF_FIRST_SALT_V1.slice(0, 4))).toEqual([0x40, 0x0c, 0x31, 0x8b]);
    expect(Array.from(PASSKEY_PRF_SECOND_SALT_V1.slice(0, 4))).toEqual([0x26, 0xda, 0x50, 0xe5]);
  });

  test('freezes Email OTP signing-session HKDF salts and 32-bit length-prefixed info fields', () => {
    expect(EMAIL_OTP_HKDF_SALTS).toEqual({
      thresholdEd25519Hss: 'seams/email-otp/threshold-ed25519-hss/v1',
      signingSessionSecret: 'seams/email-otp/signing-session-secret/v1',
      signingSessionRestoreRoot: 'seams/signing-session/restore-root/v1',
      thresholdEcdsaClientRoot: 'seams/signing-session/threshold-ecdsa-client-root/v1',
      thresholdEd25519RestoreSeed: 'seams/signing-session/threshold-ed25519-restore-seed/v1',
    });
    expect(Array.from(encodeSigningSessionHkdfTuple(['email_otp', 'alice.testnet']))).toEqual([
      0x00,
      0x00,
      0x00,
      0x09,
      ...utf8('email_otp'),
      0x00,
      0x00,
      0x00,
      0x0d,
      ...utf8('alice.testnet'),
    ]);

    expect(
      emailOtpSigningSessionSecretInfoFields({
        walletId: 'alice.testnet',
        userId: 'user-1',
        signingRootId: 'root',
        signingRootVersion: 'root-v1',
        walletSigningSessionId: 'wallet-session',
      }),
    ).toEqual(['alice.testnet', 'user-1', 'root', 'root-v1', 'wallet-session', 'email_otp']);
    expect(
      emailOtpSigningSessionRestoreRootInfoFields({
        walletId: 'alice.testnet',
        userId: 'user-1',
        signingRootId: 'root',
        signingRootVersion: 'root-v1',
        walletSigningSessionId: 'wallet-session',
      }),
    ).toEqual(['email_otp', 'alice.testnet', 'user-1', 'root', 'root-v1', 'wallet-session']);
    expect(
      emailOtpThresholdEd25519HssInfoFields({
        walletId: 'alice.testnet',
        userId: 'user-1',
      }),
    ).toEqual(['threshold-ed25519-hss-client-seed', 'alice.testnet', 'user-1']);
    expect(
      emailOtpEcdsaRestoreInfoFields({
        ecdsaThresholdSessionId: 'ecdsa-session',
        ecdsaThresholdKeyId: 'ecdsa-key',
        chainTarget: {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 11155111,
          networkSlug: 'sepolia',
        },
        participantIds: [1, 3],
        relayerKeyId: 'relayer-key',
      }),
    ).toEqual([
      'ecdsa-session',
      'ecdsa-key',
      'evm:eip155:11155111',
      'evm-signing',
      '1,3',
      'relayer-key',
    ]);
    expect(
      emailOtpEd25519RestoreInfoFields({
        ed25519ThresholdSessionId: 'ed-session',
        participantIds: [1, 2],
        relayerKeyId: 'relayer-key',
      }),
    ).toEqual(['ed-session', 'relayer-key', '1,2']);
  });
});
