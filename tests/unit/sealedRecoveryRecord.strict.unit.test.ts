import { expect, test } from '@playwright/test';

import {
  normalizeSealedRecoveryRecord,
  type RawSigningSessionSealedStoreRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord';

const TEMPO_CHAIN_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const;

const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'root',
  envId: 'email-otp',
  signingRootVersion: 'v1',
} as const;

function emailOtpEcdsaSealedRecoveryRecord(
  overrides: Partial<RawSigningSessionSealedStoreRecord> = {},
): RawSigningSessionSealedStoreRecord {
  const now = Date.now();
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: 'email_otp',
    secretKind: 'signing_session_secret32',
    storeKey: 'email_otp:ecdsa:tempo:tsess-ecdsa',
    signingGrantId: 'wsess-ecdsa',
    thresholdSessionIds: {
      ecdsa: 'tsess-ecdsa',
    },
    sealedSecretB64u: 'sealed-secret',
    curve: 'ecdsa',
    walletId: 'alice.testnet',
    relayerUrl: 'https://relay.example',
    ecdsaRestore: {
      chainTarget: TEMPO_CHAIN_TARGET,
      source: 'email_otp',
      evmFamilySigningKeySlotId: 'wallet-key:evm-family:alice:root:email-otp:v1',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      providerSubjectId: 'google:alice',
      emailHashHex: 'email-hash-alice',
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ecdsa',
      keyHandle: 'key-handle-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      relayerKeyId: 'relayer-key',
      participantIds: [1, 2],
    },
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    remainingUses: 3,
    updatedAtMs: now,
    ...overrides,
  };
}

test.describe('sealed recovery record strict normalization', () => {
  test('accepts canonical Email OTP ECDSA sealed recovery records', () => {
    const normalized = normalizeSealedRecoveryRecord(emailOtpEcdsaSealedRecoveryRecord());

    expect(normalized).toMatchObject({
      kind: 'accepted',
      record: {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        walletId: 'alice.testnet',
      },
    });
  });

  test('rejects top-level userId as stale sealed recovery identity', () => {
    const normalized = normalizeSealedRecoveryRecord(
      emailOtpEcdsaSealedRecoveryRecord({ userId: 'legacy-user-id' }),
    );

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'invalid_identity',
      },
    });
  });
});
