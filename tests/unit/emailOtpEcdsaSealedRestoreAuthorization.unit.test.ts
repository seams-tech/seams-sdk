import { expect, test } from '@playwright/test';
import {
  EmailOtpEcdsaSealedRestoreSupersededError,
  requireEmailOtpSealedRestoreAuthorization,
  restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord,
} from '@/core/signingEngine/session/emailOtp/ecdsaRecovery';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { normalizeSealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { WalletSessionAuthorizationExactOperationCredentialReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { buildActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildEmailOtpEcdsaWalletSessionFixture,
  type EmailOtpEcdsaWalletSessionFixture,
} from './helpers/linkedDeviceManagement.fixtures';
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

type CanonicalCapabilityFixture = Awaited<
  ReturnType<typeof canonicalEvmFamilyEcdsaSigningCapabilityFixture>
>;

type ResolvedSelectedWalletAuthority = Extract<
  ResolveSelectedWalletAuthorityResultV1,
  { readonly kind: 'resolved' }
>;

function selectedAuthorityFixture(args: {
  readonly session: EmailOtpEcdsaWalletSessionFixture;
  readonly authorityDigestB64u: string;
}): ResolvedSelectedWalletAuthority {
  const authority = buildActiveWalletAuthorityV1({
    ...args.session.authority,
    authorityDigestB64u: parseDigestB64u(args.authorityDigestB64u),
  });
  return {
    kind: 'resolved',
    selection: args.session.selection,
    authMethod: args.session.authMethod,
    authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

async function restoreFixtureFromCapability(capability: CanonicalCapabilityFixture) {
  const manifest = capability.manifest;
  const storedRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const normalized = normalizeSealedRecoveryRecord(storedRecord);
  if (normalized.kind !== 'accepted' || normalized.record.authMethod !== 'email_otp') {
    throw new Error('fixture must normalize to an Email OTP ECDSA recovery record');
  }
  const runtimeResolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: toWalletId(String(manifest.signer.walletId)),
    chainTarget: normalized.record.chainTarget,
    sealedRecords: [storedRecord],
  });
  if (runtimeResolution.kind !== 'resolved') {
    throw new Error(
      `exact Email OTP ECDSA runtime fixture did not resolve: ${runtimeResolution.reason}`,
    );
  }
  const session = await buildEmailOtpEcdsaWalletSessionFixture({
    label: 'sealed-restore-authorization',
    walletId: String(manifest.signer.walletId),
    materialActivation: runtimeResolution.runtime.materialActivation,
    providerUserId: `google:${String(manifest.signer.walletId)}`,
    emailHashHex: 'email-hash',
    expiresAtMs: 1_900_000_000_000,
  });
  const selected = selectedAuthorityFixture({
    session,
    authorityDigestB64u: String(manifest.signer.authority.authorityDigest),
  });
  const record = {
    ...session.activeWalletSession,
    authorityDigestB64u: selected.authority.authorityDigestB64u,
  };
  const authorizationRead: WalletSessionAuthorizationExactOperationCredentialReadResult = {
    kind: 'found',
    record,
    operationCredential: session.operationCredential,
  };
  return {
    capability: capability.capability,
    selected,
    authorizationRead,
    sealedRecord: normalized.record,
    storedRecord,
    runtime: runtimeResolution.runtime,
  };
}

async function restoreFixture() {
  return await restoreFixtureFromCapability(
    await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp'),
  );
}

test('Email OTP sealed restore uses the current exact operation credential', async () => {
  const { authorizationRead, capability, runtime, selected, sealedRecord, storedRecord } =
    await restoreFixture();
  if (authorizationRead.kind !== 'found') {
    throw new Error('fixture must provide an exact Wallet Session authorization');
  }
  const operationCredentialToken = authorizationRead.operationCredential.token;
  expect(storedRecord.ecdsaRestore.walletSessionJwt).not.toBe(operationCredentialToken);

  const resolved = requireEmailOtpSealedRestoreAuthorization({
    sealedRecord,
    authorizationRead,
    selected,
    runtime,
    capability,
    nowMs: Date.now(),
  });

  expect(resolved.operationCredential.token).toBe(operationCredentialToken);
});

test('Email OTP sealed restore fails closed without active authorization', async () => {
  const { capability, runtime, selected, sealedRecord } = await restoreFixture();
  expect(() =>
    requireEmailOtpSealedRestoreAuthorization({
      sealedRecord,
      authorizationRead: { kind: 'missing' },
      selected,
      runtime,
      capability,
      nowMs: Date.now(),
    }),
  ).toThrow('requires active Wallet Session authorization: missing');
});

test('queued ECDSA restore rejects a replacement before worker or durable side effects', async () => {
  const initialCapability = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp');
  const initialFixture = await restoreFixtureFromCapability(initialCapability);
  const initialManifest = initialCapability.manifest;
  const initialStoredRecord = initialFixture.storedRecord;
  const replacementManifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
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
    resolveSelectedWalletAuthority: async () => initialFixture.selected,
    readExactWalletSessionAuthorization: async () => initialFixture.authorizationRead,
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
