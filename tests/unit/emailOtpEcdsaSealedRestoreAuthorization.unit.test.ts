import { expect, test } from '@playwright/test';
import {
  EmailOtpEcdsaSealedRestoreSupersededError,
  requireEmailOtpSealedRestoreAuthorization,
  restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord,
} from '@/core/signingEngine/session/emailOtp/ecdsaRecovery';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { normalizeSealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import {
  activeEvmFamilyWalletSessionAuthorizationFixture,
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { resolveThresholdEcdsaSigningQueueKey } from '@/core/signingEngine/threshold/ecdsa/signingQueue';

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value?: T) => void;
} {
  let resolve!: (value?: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = (value?: T) => res(value as T);
  });
  return { promise, resolve };
}

const ACTIVE_JWT = [
  Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
  Buffer.from(
    JSON.stringify({
      kind: 'router_ab_ecdsa_derivation_wallet_session_v1',
      walletId: 'ecdsa-manifest-fixture-wallet',
      authorizationId: 'ecdsa-fixture-authorization',
      walletSessionId: 'ecdsa-fixture-wallet-session',
      quotaId: 'ecdsa-fixture-quota',
      sid: 'ecdsa-fixture-authorization-session',
      thresholdExpiresAtMs: 1_900_000_000_000,
      exp: 1_900_000_000,
    }),
  ).toString('base64url'),
  'current',
].join('.');

function restoreFixture() {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const storedRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const normalized = normalizeSealedRecoveryRecord(storedRecord);
  if (normalized.kind !== 'accepted' || normalized.record.authMethod !== 'email_otp') {
    throw new Error('fixture must normalize to an Email OTP ECDSA recovery record');
  }
  const authorization = activeEvmFamilyWalletSessionAuthorizationFixture({
    manifest,
    authMethod: 'email_otp',
    walletSessionJwt: ACTIVE_JWT,
  }).projection;
  return { authorization, sealedRecord: normalized.record, storedRecord };
}

test('Email OTP sealed restore uses the current active authorization bearer', () => {
  const { authorization, sealedRecord, storedRecord } = restoreFixture();
  expect(storedRecord.ecdsaRestore.walletSessionJwt).not.toBe(ACTIVE_JWT);

  const resolved = requireEmailOtpSealedRestoreAuthorization({
    sealedRecord,
    authorizationRead: { kind: 'found', projection: authorization },
    nowMs: Date.now(),
  });

  expect(resolved.walletSessionTokens.ecdsa.walletSessionJwt).toBe(ACTIVE_JWT);
});

test('Email OTP sealed restore fails closed without active authorization', () => {
  const { sealedRecord } = restoreFixture();
  expect(() =>
    requireEmailOtpSealedRestoreAuthorization({
      sealedRecord,
      authorizationRead: { kind: 'missing' },
      nowMs: Date.now(),
    }),
  ).toThrow('requires active Wallet Session authorization: missing');
});

test('queued ECDSA restore rejects a replacement before worker or durable side effects', async () => {
  const initialManifest = (await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp'))
    .manifest;
  const replacementManifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const initialStoredRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
    manifest: initialManifest,
  });
  const replacementStoredRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
    manifest: replacementManifest,
  });
  const initialNormalized = normalizeSealedRecoveryRecord(initialStoredRecord);
  if (
    initialNormalized.kind !== 'accepted' ||
    initialNormalized.record.authMethod !== 'email_otp'
  ) {
    throw new Error('initial Email OTP ECDSA recovery fixture must normalize');
  }
  const initialRecord = initialNormalized.record;
  const initialWalletId = toWalletId(String(initialManifest.signer.walletId));
  const initialResolution = resolveExactEcdsaSealedRuntime({
    manifest: initialManifest,
    walletId: initialWalletId,
    chainTarget: initialStoredRecord.ecdsaRestore.chainTarget,
    sealedRecords: [initialStoredRecord],
  });
  const replacementResolution = resolveExactEcdsaSealedRuntime({
    manifest: replacementManifest,
    walletId: initialWalletId,
    chainTarget: replacementStoredRecord.ecdsaRestore.chainTarget,
    sealedRecords: [replacementStoredRecord],
  });
  if (initialResolution.kind !== 'resolved') {
    throw new Error('initial ECDSA sealed-runtime fixture must resolve');
  }
  const authorization = activeEvmFamilyWalletSessionAuthorizationFixture({
    manifest: initialManifest,
    authMethod: 'email_otp',
    walletSessionJwt: ACTIVE_JWT,
  }).projection;
  let currentResolution = initialResolution;
  let workerCalls = 0;
  let provisionCalls = 0;
  let commitCalls = 0;
  const queueKey = resolveThresholdEcdsaSigningQueueKey({
    materialActivation: initialRecord.roleLocalMaterialRef.materialActivation,
  });
  const queueEntered = deferred<void>();
  const queueBlocker = deferred<void>();

  const restorePromise = restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
    configs: PASSKEY_MANAGER_DEFAULT_CONFIGS,
    sealedRecord: initialRecord,
    withThresholdEcdsaSigningQueue: async (queueArgs) => {
      expect(queueArgs.queueKey).toBe(queueKey);
      expect(queueArgs.walletId).toBe(initialWalletId);
      expect(queueArgs.enabled).toBe(true);
      queueEntered.resolve();
      await queueBlocker.promise;
      return await queueArgs.task();
    },
    getSignerWorkerContext: () => ({
      requestWorkerOperation: async () => {
        workerCalls += 1;
        throw new Error('worker must not run after replacement');
      },
    }),
    readActiveWalletSessionAuthorization: async () => ({
      kind: 'found' as const,
      projection: authorization,
    }),
    provisionThresholdEcdsaSession: async () => {
      provisionCalls += 1;
      throw new Error('provisioning must not run after replacement');
    },
    commitEvmFamilyThresholdEcdsaSessions: async () => {
      commitCalls += 1;
      throw new Error('commit must not run after replacement');
    },
    resolveCurrentEcdsaCapabilityRuntime: async () => currentResolution,
  });

  await queueEntered.promise;
  currentResolution = replacementResolution;
  queueBlocker.resolve();
  await expect(restorePromise).rejects.toMatchObject({
    code: 'material_activation_superseded',
    phase: 'before_rehydrate',
  } satisfies Pick<EmailOtpEcdsaSealedRestoreSupersededError, 'code' | 'phase'>);
  expect(workerCalls).toBe(0);
  expect(provisionCalls).toBe(0);
  expect(commitCalls).toBe(0);
});
