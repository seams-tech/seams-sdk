import { expect, test } from '@playwright/test';
import { claimPasskeyEcdsaPrfFirst } from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery';
import { restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery';
import type { SigningSessionSealedStoreRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  normalizeSealedRecoveryRecord,
  type EmailOtpEcdsaSealedRecoveryRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord';

const TEMPO_CHAIN_TARGET = {
  kind: 'tempo' as const,
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

function legacySigningGrantFieldName(): string {
  return ['wallet', 'SigningSessionId'].join('');
}

function makeEmailOtpEcdsaSealedRecord(
  overrides?: Partial<SigningSessionSealedStoreRecord>,
): EmailOtpEcdsaSealedRecoveryRecord {
  const now = Date.now();
  const normalized = normalizeSealedRecoveryRecord({
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: 'email_otp',
    secretKind: 'signing_session_secret32',
    storeKey: 'email_otp:ecdsa:tempo:tsess-ecdsa',
    signingGrantId: 'wsess-ecdsa',
    thresholdSessionIds: {
      ecdsa: 'tsess-ecdsa',
      ed25519: 'tsess-ed25519',
    },
    sealedSecretB64u: 'sealed-secret',
    curve: 'ecdsa',
    walletId: 'alice.testnet',
    userId: 'alice.testnet',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    relayerUrl: 'https://relay.example',
    shamirPrimeB64u: 'prime-b64u',
    keyVersion: 'signing-session-seal-kek-test-r1',
    ecdsaRestore: {
      chainTarget: TEMPO_CHAIN_TARGET,
      rpId: 'example.com',
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ecdsa',
      keyHandle: 'key-handle-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
      participantIds: [1, 2],
    },
    ed25519Restore: {
      rpId: 'example.com',
      relayerKeyId: 'relayer-key-ed25519',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ed25519',
      xClientBaseB64u: 'x-client-base',
      clientVerifyingShareB64u: 'client-verifying-share-ed25519',
    },
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    remainingUses: 3,
    updatedAtMs: now,
    ...overrides,
  });
  if (
    normalized.kind !== 'accepted' ||
    normalized.record.authMethod !== 'email_otp' ||
    normalized.record.curve !== 'ecdsa'
  ) {
    throw new Error('Expected accepted Email OTP ECDSA recovery record fixture');
  }
  return normalized.record;
}

test.describe('sealed recovery method adapters', () => {
  test('normalizes legacy sealed-recovery id fields at the storage boundary', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'email_otp:ecdsa:tempo:legacy-threshold-session',
      [legacySigningGrantFieldName()]: 'legacy-signing-grant',
      thresholdSessionId: 'legacy-threshold-session',
      sealedSecretB64u: 'sealed-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      signingRootId: 'root-1',
      signingRootVersion: 'v1',
      relayerUrl: 'https://relay.example',
      ecdsaRestore: {
        chainTarget: TEMPO_CHAIN_TARGET,
        rpId: 'example.com',
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ecdsa',
        keyHandle: 'key-handle-ecdsa',
        ecdsaThresholdKeyId: 'ecdsa-key',
        ethereumAddress: `0x${'33'.repeat(20)}`,
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
        participantIds: [1, 2],
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized.kind).toBe('accepted');
    if (normalized.kind !== 'accepted') return;
    expect(normalized.record.signingGrantId).toBe('legacy-signing-grant');
    expect(normalized.record.thresholdSessionId).toBe('legacy-threshold-session');
    expect(legacySigningGrantFieldName() in normalized.record).toBe(false);
    expect('thresholdSessionIds' in normalized.record).toBe(false);
  });

  test('rejects ECDSA sealed recovery records with subjectId', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
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
      userId: 'alice.testnet',
      subjectId: 'alice.testnet',
      signingRootId: 'root-1',
      signingRootVersion: 'v1',
      relayerUrl: 'https://relay.example',
      ecdsaRestore: {
        chainTarget: TEMPO_CHAIN_TARGET,
        rpId: 'example.com',
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ecdsa',
        keyHandle: 'key-handle-ecdsa',
        ecdsaThresholdKeyId: 'ecdsa-key',
        ethereumAddress: `0x${'33'.repeat(20)}`,
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
        participantIds: [1, 2],
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'invalid_identity',
      },
    });
  });

  test('rejects passkey Ed25519 sealed recovery records with raw client-base metadata', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'passkey',
      secretKind: 'signing_session_secret32',
      storeKey: 'passkey:ed25519:near:tsess-ed25519',
      signingGrantId: 'wsess-passkey-ed25519',
      thresholdSessionIds: {
        ed25519: 'tsess-passkey-ed25519',
      },
      sealedSecretB64u: 'sealed-secret',
      curve: 'ed25519',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      relayerUrl: 'https://relay.example',
      shamirPrimeB64u: 'prime-b64u',
      keyVersion: 'signing-session-seal-kek-test-r1',
      ed25519Restore: {
        rpId: 'example.com',
        relayerKeyId: 'relayer-key-ed25519',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ed25519',
        xClientBaseB64u: 'stale-x-client-base',
        clientVerifyingShareB64u: 'stale-client-verifying-share',
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'missing_restore_metadata',
      },
    });
  });

  test('restores before claiming passkey ECDSA PRF material', async () => {
    const calls: Array<{ kind: 'restore' | 'claim'; args: Record<string, unknown> }> = [];
    const prfFirstB64u = await claimPasskeyEcdsaPrfFirst({
      touchConfirm: {
        restorePersistedSessionForSigning: async (args) => {
          calls.push({ kind: 'restore', args: args as Record<string, unknown> });
          return { attempted: 0, restored: 0, deferred: 0 };
        },
        claimWarmSessionMaterial: async (args) => {
          calls.push({ kind: 'claim', args: args as Record<string, unknown> });
          return {
            ok: true as const,
            prfFirstB64u: 'prf-first-passkey-ecdsa',
            remainingUses: 2,
            expiresAtMs: Date.now() + 60_000,
          };
        },
      },
      walletId: 'alice.testnet',
      signingGrantId: 'wsess-passkey-ecdsa',
      thresholdSessionId: 'tsess-passkey-ecdsa',
      chainTarget: TEMPO_CHAIN_TARGET,
      errorContext: 'passkey ECDSA test',
    });

    expect(prfFirstB64u).toBe('prf-first-passkey-ecdsa');
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      kind: 'restore',
      args: {
        walletId: 'alice.testnet',
        authMethod: 'passkey',
        curve: 'ecdsa',
        signingGrantId: 'wsess-passkey-ecdsa',
        thresholdSessionId: 'tsess-passkey-ecdsa',
      },
    });
    expect(calls[1]).toMatchObject({
      kind: 'claim',
      args: {
        sessionId: 'tsess-passkey-ecdsa',
        curve: 'ecdsa',
        chainTarget: TEMPO_CHAIN_TARGET,
      },
    });
  });

  test('rejects Email OTP ECDSA sealed restore on signing grant mismatch', async () => {
    const sealedRecord = makeEmailOtpEcdsaSealedRecord();

    await expect(
      restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
        configs: { signing: { sessionSeal: {} } } as never,
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async () => {
            throw new Error('worker should not be called on identity mismatch');
          },
        }),
        commitEvmFamilyThresholdEcdsaSessions: async () => {
          throw new Error('commit should not be called on identity mismatch');
        },
        hydrateSigningSession: async () => undefined,
        requireRpId: () => 'example.com',
        sealedRecord,
        ecdsaRecord: {
          source: 'email_otp',
          nearAccountId: 'alice.testnet',
          thresholdSessionId: 'tsess-ecdsa',
          signingGrantId: 'wsess-mismatch',
          relayerUrl: 'https://relay.example',
          walletSessionJwt: 'jwt-ecdsa',
          signingSessionSealShamirPrimeB64u: 'prime-b64u',
          chainTarget: TEMPO_CHAIN_TARGET,
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
          signingRootId: 'root-1',
          signingRootVersion: 'v1',
          ecdsaThresholdKeyId: 'ecdsa-key',
          relayerKeyId: 'relayer-key',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          subjectId: 'alice.testnet',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
          createdAtMs: Date.now(),
          updatedAtMs: Date.now(),
        } as never,
      }),
    ).rejects.toThrow('signing grant id mismatch');
  });

  for (const staleCase of [
    { label: 'expired', overrides: { expiresAtMs: Date.now() - 1, remainingUses: 1 } },
    { label: 'exhausted', overrides: { expiresAtMs: Date.now() + 60_000, remainingUses: 0 } },
  ] as const) {
    test(`rejects ${staleCase.label} Email OTP ECDSA sealed records`, async () => {
      const sealedRecord = {
        ...makeEmailOtpEcdsaSealedRecord(),
        ...staleCase.overrides,
      };

      await expect(
        restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
          configs: { signing: { sessionSeal: {} } } as never,
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async () => {
              throw new Error('worker should not be called for stale sealed records');
            },
          }),
          commitEvmFamilyThresholdEcdsaSessions: async () => {
            throw new Error('commit should not be called for stale sealed records');
          },
          hydrateSigningSession: async () => undefined,
          requireRpId: () => 'example.com',
          sealedRecord,
        }),
      ).rejects.toThrow(`${staleCase.label} sealed record`);
    });
  }

  test('rejects Email OTP Ed25519 sealed recovery records with raw client-base metadata', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'email_otp:ed25519:near:tsess-ed25519',
      signingGrantId: 'wsess-ecdsa',
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa',
        ed25519: 'tsess-ed25519',
      },
      sealedSecretB64u: 'sealed-secret',
      curve: 'ed25519',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      relayerUrl: 'https://relay.example',
      shamirPrimeB64u: 'prime-b64u',
      keyVersion: 'signing-session-seal-kek-test-r1',
      ed25519Restore: {
        rpId: 'example.com',
        relayerKeyId: 'relayer-key-ed25519',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ed25519',
        xClientBaseB64u: 'x-client-base',
        clientVerifyingShareB64u: 'client-verifying-share-ed25519',
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'missing_restore_metadata',
      },
    });
  });
});
