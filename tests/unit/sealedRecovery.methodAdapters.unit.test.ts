import { expect, test } from '@playwright/test';
import { claimPasskeyEcdsaPrfFirst } from '../../client/src/core/signingEngine/session/passkey/ecdsaRecovery';
import { restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord } from '../../client/src/core/signingEngine/session/emailOtp/ecdsaRecovery';
import { restoreEmailOtpEd25519SealedRecordForAccount } from '../../client/src/core/signingEngine/session/emailOtp/ed25519Recovery';
import type { SigningSessionSealedStoreRecord } from '../../client/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  normalizeSealedRecoveryRecord,
  type EmailOtpEcdsaSealedRecoveryRecord,
  type EmailOtpEd25519SealedRecoveryRecord,
} from '../../client/src/core/signingEngine/session/sealedRecovery/recoveryRecord';

const TEMPO_CHAIN_TARGET = {
  kind: 'tempo' as const,
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

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
    walletSigningSessionId: 'wsess-ecdsa',
    thresholdSessionIds: {
      ecdsa: 'tsess-ecdsa',
      ed25519: 'tsess-ed25519',
    },
    sealedSecretB64u: 'sealed-secret',
    curve: 'ecdsa',
    walletId: 'alice.testnet',
    userId: 'alice.testnet',
    subjectId: 'alice.testnet',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    relayerUrl: 'https://relay.example',
    shamirPrimeB64u: 'prime-b64u',
    keyVersion: 'seal-v1',
    ecdsaRestore: {
      chainTarget: TEMPO_CHAIN_TARGET,
      rpId: 'example.com',
      sessionKind: 'jwt',
      thresholdSessionAuthToken: 'jwt-ecdsa',
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
      thresholdSessionAuthToken: 'jwt-ed25519',
      xClientBaseB64u: 'x-client-base',
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

function makeEmailOtpEd25519SealedRecord(
  overrides?: Partial<SigningSessionSealedStoreRecord>,
): EmailOtpEd25519SealedRecoveryRecord {
  const now = Date.now();
  const normalized = normalizeSealedRecoveryRecord({
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: 'email_otp',
    secretKind: 'signing_session_secret32',
    storeKey: 'email_otp:ed25519:near:tsess-ed25519',
    walletSigningSessionId: 'wsess-ecdsa',
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
    keyVersion: 'seal-v1',
    ecdsaRestore: {
      chainTarget: TEMPO_CHAIN_TARGET,
      rpId: 'example.com',
      sessionKind: 'jwt',
      thresholdSessionAuthToken: 'jwt-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
      participantIds: [1, 2],
    },
    subjectId: 'alice.testnet',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    ed25519Restore: {
      rpId: 'example.com',
      relayerKeyId: 'relayer-key-ed25519',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      thresholdSessionAuthToken: 'jwt-ed25519',
      xClientBaseB64u: 'x-client-base',
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
    normalized.record.curve !== 'ed25519'
  ) {
    throw new Error('Expected accepted Email OTP Ed25519 recovery record fixture');
  }
  return normalized.record;
}

test.describe('sealed recovery method adapters', () => {
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
      walletSigningSessionId: 'wsess-passkey-ecdsa',
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
        walletSigningSessionId: 'wsess-passkey-ecdsa',
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

  test('rejects Email OTP ECDSA sealed restore on wallet signing-session mismatch', async () => {
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
          walletSigningSessionId: 'wsess-mismatch',
          relayerUrl: 'https://relay.example',
          thresholdSessionAuthToken: 'jwt-ecdsa',
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
    ).rejects.toThrow('wallet signing-session id mismatch');
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

  test('restores Email OTP Ed25519 companion session through shared readback contracts', async () => {
    const restoredSessions = new Set<string>();
    const recordedStatuses: Array<{ sessionId: string; remainingUses: number; expiresAtMs: number }> = [];
    const record = makeEmailOtpEd25519SealedRecord();

    const result = await restoreEmailOtpEd25519SealedRecordForAccount({
      accountId: 'alice.testnet',
      record,
      purpose: {
        walletId: 'alice.testnet',
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        walletSigningSessionId: 'wsess-ecdsa',
        thresholdSessionId: 'tsess-ed25519',
        reason: 'transaction',
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      readWarmSessionStatusFromWorker: async (sessionId) => {
        if (!restoredSessions.has(sessionId)) {
          return { ok: false as const, code: 'not_found', message: 'missing' };
        }
        return {
          ok: true as const,
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
        };
      },
      recordSessionMaterialRestored: async (sessionId, status) => {
        restoredSessions.add(sessionId);
        recordedStatuses.push({
          sessionId,
          remainingUses: status.remainingUses,
          expiresAtMs: status.expiresAtMs,
        });
      },
      restoreEcdsaSigningSessionMaterialFromSealedRecord: async () => ({
        bootstrap: {} as never,
        warmCapability: {} as never,
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
        ed25519RestoreSeedB64u: 'restored-ed25519-seed',
      }),
    });

    expect(result).toBe('restored');
    expect(recordedStatuses.map((entry) => entry.sessionId)).toEqual([
      'tsess-ecdsa',
      'tsess-ed25519',
    ]);
  });
});
