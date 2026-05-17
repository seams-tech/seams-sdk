import { expect, test } from '@playwright/test';
import { EmailOtpThresholdSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator';
import { requestEmailOtpExportAuthorization } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/exportAuthorization';
import { toAuthorizingWalletSigningSessionId } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertStoredThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentEcdsaSealedSessionRecordInput,
  clearAllSealedSessions,
  type listExactSealedSessionsForWallet,
  publishResolvedIdentity,
  type SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetsEqual,
  toWalletSubjectId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const TEST_SUBJECT_ID = toWalletSubjectId('alice.testnet');
const TEMPO_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});
const EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});
const TEST_WALLET_SESSION = walletSessionRefFromSession({
  walletId: 'alice.testnet',
  walletSessionUserId: 'alice.testnet',
});

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function appSessionJwt(expSeconds = Math.floor(Date.now() / 1000) + 3600): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    exp: expSeconds,
  })}.sig`;
}

type EcdsaSealedRecordFixtureArgs = {
  expiresAtMs: number;
  thresholdSessionId?: string;
  thresholdSessionIds?: BuildCurrentEcdsaSealedSessionRecordInput['thresholdSessionIds'];
  walletSigningSessionId?: string;
  walletId?: string;
  userId?: string;
  subjectId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  relayerUrl?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  sealedSecretB64u?: string;
  chainTarget?: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']['chainTarget'];
  ecdsaRestore?: Partial<BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore']>;
  issuedAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
};

function buildEcdsaSealedRecordFixture(
  args: EcdsaSealedRecordFixtureArgs,
): SigningSessionSealedStoreRecord {
  const chainTarget = args.ecdsaRestore?.chainTarget || args.chainTarget || TEMPO_CHAIN_TARGET;
  const thresholdSessionId =
    args.thresholdSessionId || args.thresholdSessionIds?.ecdsa || 'ecdsa-session';
  const ecdsaRestore: BuildCurrentEcdsaSealedSessionRecordInput['ecdsaRestore'] = {
    chainTarget,
    rpId: args.ecdsaRestore?.rpId || 'example.com',
    thresholdSessionAuthToken:
      args.ecdsaRestore?.thresholdSessionAuthToken || 'threshold-session-jwt',
    sessionKind: args.ecdsaRestore?.sessionKind || 'jwt',
    ecdsaThresholdKeyId: args.ecdsaRestore?.ecdsaThresholdKeyId || 'ecdsa-key',
    ethereumAddress: args.ecdsaRestore?.ethereumAddress || `0x${'33'.repeat(20)}`,
    relayerKeyId: args.ecdsaRestore?.relayerKeyId || 'relayer-key',
    clientVerifyingShareB64u:
      args.ecdsaRestore?.clientVerifyingShareB64u || 'verifying-share',
    thresholdEcdsaPublicKeyB64u:
      args.ecdsaRestore?.thresholdEcdsaPublicKeyB64u || 'threshold-public-key',
    participantIds: args.ecdsaRestore?.participantIds || [1, 3],
    ...(args.ecdsaRestore?.runtimePolicyScope === undefined
      ? {}
      : { runtimePolicyScope: args.ecdsaRestore.runtimePolicyScope }),
  };
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    authMethod: 'email_otp',
    walletId: args.walletId || 'alice.testnet',
    userId: args.userId || 'alice.testnet',
    subjectId: args.subjectId || TEST_SUBJECT_ID,
    signingRootId: args.signingRootId || 'signing-root',
    signingRootVersion: args.signingRootVersion || 'root-v1',
    relayerUrl: args.relayerUrl || 'https://relay.example',
    keyVersion: args.keyVersion || 'seal-v1',
    shamirPrimeB64u: args.shamirPrimeB64u || 'prime-b64u',
    walletSigningSessionId: args.walletSigningSessionId || 'wallet-session-1',
    thresholdSessionId,
    thresholdSessionIds: args.thresholdSessionIds,
    sealedSecretB64u: args.sealedSecretB64u || 'sealed-session-secret',
    ecdsaRestore,
    issuedAtMs: args.issuedAtMs || Date.now(),
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses ?? 2,
    updatedAtMs: args.updatedAtMs || Date.now(),
  });
  if (!record) {
    throw new Error('invalid ECDSA sealed session fixture');
  }
  return record;
}

function createCoordinator(overrides?: {
  requestWorkerOperation?: (call: any) => Promise<any>;
  refreshAppSessionJwt?: () => Promise<string>;
  getRpId?: () => string | null;
  configs?: Record<string, any>;
  writeExactSealedSession?: (args: any) => Promise<void>;
  readExactSealedSession?: (thresholdSessionId: string, purpose?: any) => Promise<any>;
  listExactSealedSessionsForWallet?: typeof listExactSealedSessionsForWallet;
  listThresholdEcdsaSessionRecordsForWallet?: (walletId: string) => any[];
  getThresholdEcdsaSessionRecordByThresholdSessionId?: (thresholdSessionId: string) => any;
  acquireSigningSessionRestoreLease?: (args: any) => Promise<any>;
  releaseSigningSessionRestoreLease?: (lease: any) => Promise<void>;
}) {
  const workerCalls: any[] = [];
  let refreshCount = 0;
  const buildWorkerEcdsaBootstrap = (call: any, chainTarget: any) => ({
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: call.request.payload.walletId,
      subjectId: call.request.payload.subjectId,
      relayerUrl: call.request.payload.relayUrl,
      ecdsaThresholdKeyId: 'ecdsa-key',
      chainTarget,
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
      thresholdSessionId: call.request.payload.sessionId || 'ecdsa-session',
      walletSigningSessionId:
        call.request.payload.walletSigningSessionId ||
        call.request.payload.sessionId ||
        'ecdsa-session',
      thresholdSessionKind: 'jwt',
      thresholdSessionAuthToken: 'threshold-session-jwt',
      participantIds: [1, 3],
      backendBinding: { relayerKeyId: 'relayer-key' },
    },
    keygen: { ok: true, rpId: 'example.com' },
    session: {
      ok: true,
      sessionId: call.request.payload.sessionId || 'ecdsa-session',
      walletSigningSessionId:
        call.request.payload.walletSigningSessionId ||
        call.request.payload.sessionId ||
        'ecdsa-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 3,
      jwt: 'threshold-session-jwt',
    },
  });
  const worker = {
    requestWorkerOperation: async (call: any) => {
      workerCalls.push(call);
      if (overrides?.requestWorkerOperation) {
        return overrides.requestWorkerOperation(call);
      }
      if (call.request?.type === 'requestEmailOtpChallenge') {
        return { challengeId: 'challenge-1', emailHint: 'a***@example.com' };
      }
      if (call.request?.type === 'loginWithEmailOtpWallet') {
        return {
          recovery: { thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-login' },
          clientRootShare32B64u: 'client-root-share',
        };
      }
      if (call.request?.type === 'recoverEmailOtpEd25519ExportPrfFirst') {
        return {
          challengeId: call.request.payload.challengeId,
          thresholdEd25519PrfFirstB64u: 'prf-first',
        };
      }
      if (call.request?.type === 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization') {
        return {
          publicKeyHex: '02'.padEnd(66, '1'),
          privateKeyHex: '11'.repeat(32),
          ethereumAddress: '0x'.padEnd(42, 'a'),
        };
      }
      if (call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare') {
        return {
          bootstraps: call.request.payload.publicationChainTargets.map((chainTarget: any) =>
            buildWorkerEcdsaBootstrap(call, chainTarget),
          ),
        };
      }
      if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
        return {
          ok: true,
          sealedSecretB64u: 'sealed-email-otp-session-secret',
          keyVersion: 'seal-v1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
        };
      }
      if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
        return {
          ok: true,
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
          bootstrap: {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: call.request.payload.restore.userId || call.request.payload.restore.walletId,
              subjectId: call.request.payload.restore.subjectId,
              relayerUrl: call.request.payload.transport.relayerUrl,
              ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
              chainTarget: call.request.payload.restore.chainTarget,
              signingRootId: call.request.payload.restore.signingRootId,
              signingRootVersion: call.request.payload.restore.signingRootVersion,
              thresholdSessionId: call.request.payload.restore.sessionId,
              walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
              thresholdSessionAuthToken: call.request.payload.transport.thresholdSessionAuthToken,
            },
            keygen: { ok: true, rpId: 'example.com' },
            session: {
              ok: true,
              sessionId: call.request.payload.restore.sessionId,
              walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 2,
              jwt: call.request.payload.transport.thresholdSessionAuthToken,
            },
          },
        };
      }
      if (call.request?.type === 'enrollEmailOtpWallet') {
        return {
          thresholdEcdsaClientVerifyingShareB64u: 'verifying-share',
          challengeId: call.request.payload.challengeId,
          otpChannel: 'email_otp',
          enrollmentSealKeyVersion: 'email-v1',
          clientUnlockPublicKeyB64u: 'unlock-public',
          unlockKeyVersion: 'unlock-v1',
          thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-enroll',
          clientRootShare32B64u: 'client-root-share-enroll',
        };
      }
      return { ok: true };
    },
  };
  const ecdsaCommitCalls: any[] = [];
  const ed25519ProvisionCalls: any[] = [];
  const ed25519MetadataWrites: any[] = [];
  const ed25519WarmSessionWrites: any[] = [];
  const hydratedSessions: any[] = [];
  const sealedRecordWrites: SigningSessionSealedStoreRecord[] = [];
  const toSealedRecordReadback = (
    record: SigningSessionSealedStoreRecord,
  ): SigningSessionSealedStoreRecord => record;
  const recordMatchesSealedPurpose = (
    write: any,
    thresholdSessionId: string | undefined,
    purpose?: any,
  ) => {
    if (
      thresholdSessionId &&
      write.thresholdSessionIds?.ed25519 !== thresholdSessionId &&
      write.thresholdSessionIds?.ecdsa !== thresholdSessionId
    ) {
      return false;
    }
    if (purpose?.authMethod && write.authMethod !== purpose.authMethod) return false;
    if (purpose?.curve && write.curve !== purpose.curve) return false;
    if (
      purpose?.chainTarget &&
      (!write.ecdsaRestore?.chainTarget ||
        !thresholdEcdsaChainTargetsEqual(write.ecdsaRestore.chainTarget, purpose.chainTarget))
    ) {
      return false;
    }
    return true;
  };
  const defaultReadExactSealedSession = async (thresholdSessionId: string, purpose?: any) => {
    const record = sealedRecordWrites.find((write) =>
      recordMatchesSealedPurpose(write, thresholdSessionId, purpose),
    );
    return record ? toSealedRecordReadback(record) : null;
  };
  const defaultListExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet = async ({
    walletId,
    filter,
  }) =>
    sealedRecordWrites
      .filter((write) => {
        if (write.walletId !== walletId && write.userId !== walletId) {
          return false;
        }
        return recordMatchesSealedPurpose(write, undefined, filter);
      })
      .map(toSealedRecordReadback);
  const baseConfigs = {
    registration: {
      mode: 'backend_proxy',
      bootstrapUrl: 'https://relay.example/registration/bootstrap',
    },
    network: {
      relayer: { url: 'https://relay.example' },
      chains: [
        {
          network: 'tempo-testnet',
          rpcUrl: 'https://rpc.tempo.test',
          explorerUrl: 'https://explorer.tempo.test',
          chainId: 42431,
        },
        {
          network: 'arc-testnet',
          rpcUrl: 'https://rpc.arc.test',
          explorerUrl: 'https://explorer.arc.test',
          chainId: 5042002,
        },
      ],
    },
    signing: {
      emailOtp: { authPolicy: 'per_operation' },
      sessionPersistenceMode: 'none',
      sessionSeal: { shamirPrimeB64u: 'prime-b64u' },
    },
  };
  const defaultEcdsaRecord = {
    walletId: 'alice.testnet',
    subjectId: TEST_SUBJECT_ID,
    chainTarget: TEMPO_CHAIN_TARGET,
    source: 'email_otp',
    relayerUrl: 'https://relay.example',
    ecdsaThresholdKeyId: 'ecdsa-key',
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'verifying-share',
    participantIds: [1, 3],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'ecdsa-session',
    walletSigningSessionId: 'wallet-session-ecdsa',
    thresholdSessionAuthToken: 'threshold-session-jwt',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
    updatedAtMs: Date.now(),
  };
  const coordinator = new EmailOtpThresholdSessionCoordinator({
    configs: {
      ...baseConfigs,
      ...(overrides?.configs || {}),
      registration: {
        ...baseConfigs.registration,
        ...(overrides?.configs?.registration || {}),
      },
      network: {
        ...baseConfigs.network,
        ...(overrides?.configs?.network || {}),
      },
      signing: {
        ...baseConfigs.signing,
        ...(overrides?.configs?.signing || {}),
        emailOtp: {
          ...baseConfigs.signing.emailOtp,
          ...(overrides?.configs?.signing?.emailOtp || {}),
        },
        sessionSeal: {
          ...baseConfigs.signing.sessionSeal,
          ...(overrides?.configs?.signing?.sessionSeal || {}),
        },
      },
    } as any,
    signerWorkerManager: worker as any,
    getRpId: overrides?.getRpId || (() => 'localhost'),
    getSignerWorkerContext: () => worker as any,
    refreshAppSessionJwt: async () => {
      refreshCount += 1;
      return overrides?.refreshAppSessionJwt ? overrides.refreshAppSessionJwt() : appSessionJwt();
    },
    commitEvmFamilyThresholdEcdsaSessions: async (args) => {
      ecdsaCommitCalls.push(args);
      return {
        bootstrap: args.bootstrap,
        warmCapability: { capability: 'ecdsa', state: 'ready' } as any,
      };
    },
    listThresholdEcdsaSessionRecordsForWallet:
      overrides?.listThresholdEcdsaSessionRecordsForWallet ||
      ((walletId) => [{ ...defaultEcdsaRecord, walletId }]),
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      overrides?.getThresholdEcdsaSessionRecordByThresholdSessionId ||
      ((thresholdSessionId) =>
        thresholdSessionId === defaultEcdsaRecord.thresholdSessionId
          ? defaultEcdsaRecord
          : null),
    getThresholdEd25519SessionRecordByThresholdSessionId: (thresholdSessionId) =>
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId),
    persistEmailOtpThresholdEd25519LocalMetadata: async (args) => {
      ed25519MetadataWrites.push(args);
    },
    persistWarmSessionEd25519Capability: async (args) => {
      ed25519WarmSessionWrites.push(args);
    },
    hydrateSigningSession: async (args) => {
      hydratedSessions.push(args);
    },
    writeExactSealedSession: async (args) => {
      sealedRecordWrites.push(args);
      if (overrides?.writeExactSealedSession) {
        await overrides.writeExactSealedSession(args);
      }
    },
    readExactSealedSession:
      overrides?.readExactSealedSession || defaultReadExactSealedSession,
    listExactSealedSessionsForWallet:
      overrides?.listExactSealedSessionsForWallet || defaultListExactSealedSessionsForWallet,
    acquireSigningSessionRestoreLease: overrides?.acquireSigningSessionRestoreLease || (async () => null),
    releaseSigningSessionRestoreLease: overrides?.releaseSigningSessionRestoreLease || (async () => {}),
    deleteExactSealedSession: async () => {},
    updateExactSealedSessionPolicy: async () => {},
  });
  const runtime = (coordinator as any).runtime;
  const runtimeProvisionEd25519Capability = runtime?.provisionEd25519Capability?.bind(runtime);
  let provisionEd25519CapabilityImpl = coordinator.provisionEd25519Capability.bind(coordinator);
  Object.defineProperty(coordinator, 'provisionEd25519Capability', {
    configurable: true,
    get: () => provisionEd25519CapabilityImpl,
    set: (value) => {
      provisionEd25519CapabilityImpl = value;
      if (runtime) {
        runtime.provisionEd25519Capability = value;
      }
    },
  });
  if (runtime && runtimeProvisionEd25519Capability) {
    runtime.provisionEd25519Capability = runtimeProvisionEd25519Capability;
  }

  return {
    coordinator,
    workerCalls,
    ecdsaCommitCalls,
    ed25519ProvisionCalls,
    ed25519MetadataWrites,
    ed25519WarmSessionWrites,
    hydratedSessions,
    sealedRecordWrites,
    getRefreshCount: () => refreshCount,
  };
}

test.describe('EmailOtpThresholdSessionCoordinator', () => {
  test('normalizes warm-session status requests and maps worker failures', async () => {
    const invalid = createCoordinator();
    await expect(invalid.coordinator.readWarmSessionStatusOnly('   ')).resolves.toMatchObject({
      ok: false,
      code: 'invalid_args',
    });
    expect(invalid.workerCalls).toHaveLength(0);

    const failing = createCoordinator({
      requestWorkerOperation: async () => {
        throw new Error('worker unavailable');
      },
    });
    await expect(failing.coordinator.readWarmSessionStatusOnly(' session-1 ')).resolves.toMatchObject({
      ok: false,
      code: 'worker_error',
      message: 'worker unavailable',
    });
    expect(failing.workerCalls[0].request.payload.sessionId).toBe('session-1');
  });

  test('consumes warm-session uses without returning secret material', async () => {
    const { coordinator, workerCalls } = createCoordinator({
      requestWorkerOperation: async () => ({
        ok: true,
        remainingUses: 2,
        expiresAtMs: Date.now() + 60_000,
      }),
    });

    const result = await coordinator.consumeWarmSessionUses({ sessionId: ' session-1 ', uses: 2 });

    expect(result).toMatchObject({ ok: true, remainingUses: 2 });
    expect(JSON.stringify(result)).not.toContain('prfFirstB64u');
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'consumeEmailOtpWarmSessionUses',
        payload: {
          sessionId: 'session-1',
          uses: 2,
        },
      },
    });
  });

  test('requests transaction challenges with signing-session auth only', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();
    const thresholdSessionAuthToken = 'threshold-session-jwt';

    const challenge = await coordinator.requestTransactionSigningChallenge({
      kind: 'near_account_challenge',
      nearAccountId: 'alice.testnet',
      chain: 'near',
      authLane: {
        kind: 'signing_session',
        jwt: thresholdSessionAuthToken,
        thresholdSessionId: 'ed25519-session',
        authorizingWalletSigningSessionId:
          toAuthorizingWalletSigningSessionId('wallet-signing-session'),
        curve: 'ed25519',
      },
    });

    expect(challenge).toMatchObject({
      challengeId: 'challenge-1',
      emailHint: 'a***@example.com',
    });
    expect(getRefreshCount()).toBe(0);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: thresholdSessionAuthToken,
              thresholdSessionId: 'ed25519-session',
              authorizingWalletSigningSessionId: 'wallet-signing-session',
              curve: 'ed25519',
            },
            operation: 'transaction_sign',
          },
          otpChannel: 'email_otp',
        },
      },
    });
  });

  test('NEAR transaction challenge falls back to app-session OTP without signing-session authority', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();

    const challenge = await coordinator.requestTransactionSigningChallenge({
      kind: 'near_account_challenge',
      nearAccountId: 'alice.testnet',
      chain: 'near',
    });

    expect(challenge).toMatchObject({
      challengeId: 'challenge-1',
      emailHint: 'a***@example.com',
    });
    expect(getRefreshCount()).toBe(1);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session' },
            operation: 'transaction_sign',
          },
          otpChannel: 'email_otp',
        },
      },
    });
  });

  test('Email OTP export resend updates the challenge used for authorization', async () => {
    const challengeRequests: Array<Record<string, unknown>> = [];
    const thresholdSessionAuthToken = 'threshold-session-jwt';
    const { coordinator } = createCoordinator({
      requestWorkerOperation: async (call) => {
        if (call.request?.type !== 'requestEmailOtpChallenge') return { ok: true };
        challengeRequests.push(call.request.payload);
        const issueNumber = challengeRequests.length;
        return {
          challengeId: `export-challenge-${issueNumber}`,
          emailHint: `a***${issueNumber}@example.test`,
        };
      },
    });

    await expect(
      requestEmailOtpExportAuthorization({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        publicKey: '02'.padEnd(66, '1'),
        curve: 'ecdsa',
        challengeSource: {
          requestChallenge: async () =>
            await coordinator.requestExportChallenge({
              kind: 'near_account_challenge',
              nearAccountId: 'alice.testnet',
              chain: 'evm',
              authLane: {
                kind: 'signing_session',
                jwt: thresholdSessionAuthToken,
                thresholdSessionId: 'ecdsa-session',
                authorizingWalletSigningSessionId:
                  toAuthorizingWalletSigningSessionId('wallet-signing-session'),
                curve: 'ecdsa',
                chainTarget: EVM_CHAIN_TARGET,
              },
            }),
        },
        confirmer: {
          requestUserConfirmation: async (request: any) => {
            expect(request.payload.signingAuthPlan.emailOtpPrompt.challengeId).toBe(
              'export-challenge-1',
            );
            const resent = await request.payload.signingAuthPlan.emailOtpPrompt.onResend();
            expect(resent).toEqual({
              challengeId: 'export-challenge-2',
              emailHint: 'a***2@example.test',
            });
            return {
              requestId: request.requestId,
              confirmed: true,
              otpCode: '654321',
              emailOtpChallengeId: resent.challengeId,
            };
          },
        },
      }),
    ).resolves.toEqual({
      challengeId: 'export-challenge-2',
      otpCode: '654321',
    });
    expect(challengeRequests).toEqual([
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: thresholdSessionAuthToken,
            thresholdSessionId: 'ecdsa-session',
            authorizingWalletSigningSessionId: 'wallet-signing-session',
            curve: 'ecdsa',
            chainTarget: EVM_CHAIN_TARGET,
          },
          operation: 'export_key',
        },
        otpChannel: 'email_otp',
      },
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: thresholdSessionAuthToken,
            thresholdSessionId: 'ecdsa-session',
            authorizingWalletSigningSessionId: 'wallet-signing-session',
            curve: 'ecdsa',
            chainTarget: EVM_CHAIN_TARGET,
          },
          operation: 'export_key',
        },
        otpChannel: 'email_otp',
      },
    ]);
  });

  test('transaction challenges reject app-session route auth instead of resolving it', async () => {
    const { coordinator, getRefreshCount, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();

    await expect(
      coordinator.requestTransactionSigningChallenge({
        kind: 'near_account_challenge',
        nearAccountId: 'alice.testnet',
        chain: 'near',
        routeAuth: { kind: 'app_session', jwt },
      }),
    ).rejects.toThrow('Email OTP signing-session authority is unavailable; unlock wallet again');

    expect(getRefreshCount()).toBe(0);
    expect(workerCalls).toHaveLength(0);
  });

  test('logs in Ed25519 Email OTP capability with normalized auth context', async () => {
    const { coordinator, ed25519ProvisionCalls } = createCoordinator();
    const thresholdSessionAuthToken = 'threshold-jwt';
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      return {
        publicKey: 'ed25519-public',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        sessionId: 'ed-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        participantIds: [1, 2],
        jwt: 'threshold-jwt',
      };
    };

    const result = await coordinator.loginWithEd25519CapabilityForSigning({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionAuthToken },
      record: {
        thresholdSessionId: 'old-session',
        walletSigningSessionId: 'wallet-session-ed25519',
        curve: 'ed25519',
        relayerUrl: '',
        rpId: '',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        thresholdSessionAuthToken,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        source: 'email_otp',
      } as any,
    });

    expect(result.sessionId).toBe('ed-session');
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      prfFirstB64u: 'prf-first-ecdsa-login',
      routeAuth: { kind: 'threshold_session', jwt: 'threshold-session-jwt' },
      participantIds: [1, 2],
      remainingUses: 1,
      ecdsaThresholdSessionId: 'ecdsa-session',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
      },
    });
  });

  test('recovers Ed25519 export material without provisioning or hydrating a signing session', async () => {
    const { coordinator, workerCalls, ed25519ProvisionCalls, hydratedSessions, getRefreshCount } =
      createCoordinator();
    const thresholdSessionAuthToken = `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
      kind: 'threshold_ed25519_session_v1',
      sessionId: 'ed25519-restored-session',
      sub: 'alice.testnet',
      walletId: 'alice.testnet',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.sig`;
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      throw new Error('Ed25519 export must not provision a signing session');
    };

    const result = await coordinator.recoverEd25519ExportPrfFirst({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionAuthToken },
      record: {
        thresholdSessionId: 'ed25519-restored-session',
        walletSigningSessionId: 'wallet-signing-session-1',
        relayerUrl: 'https://relay.example',
        rpId: 'localhost',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        thresholdSessionAuthToken,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 4,
        source: 'email_otp',
      } as any,
    });

    expect(result).toEqual({ prfFirstB64u: 'prf-first' });
    expect(ed25519ProvisionCalls).toEqual([]);
    expect(getRefreshCount()).toBe(0);
    expect(workerCalls[0].request).toMatchObject({
      type: 'recoverEmailOtpEd25519ExportPrfFirst',
      payload: {
        walletId: 'alice.testnet',
        challengeId: 'challenge-1',
        otpCode: '123456',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: thresholdSessionAuthToken,
            thresholdSessionId: 'ed25519-restored-session',
            authorizingWalletSigningSessionId: 'wallet-signing-session-1',
            curve: 'ed25519',
          },
          operation: 'export_key',
        },
      },
    });
    expect(hydratedSessions).toEqual([]);
  });

  test('logs in ECDSA Email OTP capability with normalized worker payload and persistence callback', async () => {
    const { coordinator, workerCalls, ecdsaCommitCalls, ed25519ProvisionCalls } =
      createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      return {
        publicKey: 'ed25519-public',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        sessionId: 'ed-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        participantIds: [1, 2],
        jwt: 'threshold-jwt',
      };
    };

    const result = await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'proj',
        envId: 'dev',
        signingRootVersion: 'v1',
      },
    });

    expect(result.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId).toBe('ecdsa-key');
    expect(workerCalls.at(-2)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpWallet',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          challengeId: 'challenge-1',
          otpCode: '123456',
          routePlan: {
            routeFamily: 'login',
            authLane: { kind: 'app_session', jwt },
            operation: 'wallet_unlock',
          },
        },
      },
    });
    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          rpId: 'localhost',
          ecdsaThresholdKeyId: 'ecdsa-key',
          participantIds: [1, 3],
          sessionKind: 'jwt',
          remainingUses: 1,
          routeAuth: { kind: 'app_session', jwt },
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      walletId: 'alice.testnet',
      primaryChain: { kind: 'tempo', chainId: 42431 },
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
    await expect.poll(() => ed25519ProvisionCalls.length).toBe(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      relayUrl: 'https://relay.example',
      rpId: 'localhost',
      prfFirstB64u: 'prf-first-ecdsa-login',
      appSessionJwt: jwt,
      participantIds: [1, 3],
      remainingUses: 1,
    });
  });

  test('normal ECDSA Email OTP login derives app-session route auth from appSessionJwt', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
    });

    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare',
        payload: {
          routeAuth: { kind: 'app_session', jwt },
        },
      },
    });
  });

  test('Email OTP registration bootstrap derives app-session route auth from appSessionJwt', async () => {
    const { coordinator, workerCalls } = createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });

    await coordinator.enrollAndLoginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
    });

    expect(workerCalls.at(-2)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'enrollEmailOtpWallet',
        payload: {
          routePlan: {
            routeFamily: 'registration',
            authLane: { kind: 'app_session', jwt },
            operation: 'wallet_unlock',
          },
        },
      },
    });
    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare',
        payload: {
          routeAuth: { kind: 'app_session', jwt },
        },
      },
    });
  });

  test('persists sealed Email OTP signing-session refresh only for session-retained ECDSA login', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'loginWithEmailOtpWallet') {
          return {
            recovery: {
              loginGrant: 'login-grant',
              challengeId: 'challenge-1',
              enrollmentSealKeyVersion: 'email-v1',
              unlockChallengeId: 'unlock-challenge',
              unlockChallengeB64u: 'unlock-challenge-b64u',
              clientUnlockPublicKeyB64u: 'unlock-public',
              unlockSignatureB64u: 'unlock-sig',
              thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-login',
            },
            clientRootShare32B64u: 'client-root-share',
          };
        }
        if (call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare') {
          return {
            bootstraps: call.request.payload.publicationChainTargets.map((chainTarget: any) => ({
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                subjectId: call.request.payload.subjectId,
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId: 'ecdsa-key',
                chainTarget,
                signingRootId: 'signing-root',
                signingRootVersion: 'root-v1',
                ethereumAddress: `0x${'33'.repeat(20)}`,
                thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
                thresholdSessionId: 'ecdsa-session',
                walletSigningSessionId: call.request.payload.walletSigningSessionId,
                thresholdSessionKind: 'jwt',
                thresholdSessionAuthToken: 'threshold-session-jwt',
                participantIds: [1, 3],
                backendBinding: { relayerKeyId: 'relayer-key' },
              },
              keygen: { ok: true, rpId: 'example.com' },
              session: {
                ok: true,
                sessionId: 'ecdsa-session',
                walletSigningSessionId: call.request.payload.walletSigningSessionId,
                expiresAtMs: Date.now() + 60_000,
                remainingUses: 9,
                jwt: 'threshold-session-jwt',
              },
            })),
          };
        }
        if (call.request?.type === 'sealEmailOtpWarmSessionMaterial') {
          return {
            ok: true,
            sealedSecretB64u: 'sealed-email-otp-session-secret',
            keyVersion: 'seal-v1',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 9,
          };
        }
        return { ok: true };
      },
    });
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });
    const jwt = appSessionJwt();

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
    });

    const sealCall = workerCalls.find(
      (call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial',
    );
    expect(sealCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'sealEmailOtpWarmSessionMaterial',
        payload: {
          sessionId: 'ecdsa-session',
          transport: {
            relayerUrl: 'https://relay.example',
            thresholdSessionAuthToken: 'threshold-session-jwt',
            keyVersion: 'seal-v1',
            shamirPrimeB64u: 'prime-b64u',
          },
        },
      },
    });
    expect(sealedRecordWrites).toHaveLength(2);
    expect(
      sealedRecordWrites.map((record) => record.ecdsaRestore?.chainTarget?.kind).sort(),
    ).toEqual(['evm', 'tempo']);
    for (const sealedRecordWrite of sealedRecordWrites) {
      expect(sealedRecordWrite).toMatchObject({
        sealedSecretB64u: 'sealed-email-otp-session-secret',
        curve: 'ecdsa',
        authMethod: 'email_otp',
        thresholdSessionIds: { ecdsa: 'ecdsa-session' },
        walletId: 'alice.testnet',
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        relayerUrl: 'https://relay.example',
        keyVersion: 'seal-v1',
        shamirPrimeB64u: 'prime-b64u',
        remainingUses: 9,
      });
    }
  });

  test('fails session-retained Email OTP login when sealed refresh is not durably readable', async () => {
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      readExactSealedSession: async () => null,
    });

    await expect(
      coordinator.loginWithEcdsaCapabilityInternal({
        walletSession: TEST_WALLET_SESSION,
        subjectId: TEST_SUBJECT_ID,
        chainTarget: TEMPO_CHAIN_TARGET,
        challengeId: 'challenge-1',
        otpCode: '123456',
        routeAuth: { kind: 'app_session', jwt: appSessionJwt() },
        ecdsaThresholdKeyId: 'ecdsa-key',
        participantIds: [1, 3],
        sessionKind: 'jwt',
      }),
    ).rejects.toThrow('Email OTP sealed refresh tempo:42431 record was not durably persisted');
  });

  test('does not persist sealed Email OTP refresh records for per-operation ECDSA login', async () => {
    const { coordinator, workerCalls, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
    });
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });
    const jwt = appSessionJwt();

    await coordinator.loginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
    });

    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(false);
    expect(sealedRecordWrites).toHaveLength(0);
  });

  test('Email OTP per-operation ECDSA signing mints a fresh wallet signing-session id', async () => {
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'per_operation' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
    });
    coordinator.scheduleEd25519CapabilityProvisioning = () => undefined;
    coordinator.provisionEd25519Capability = async () => ({
      publicKey: 'ed25519-public',
      relayerKeyId: 'relayer-key',
      keyVersion: 'v1',
      sessionId: 'ed-session',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      participantIds: [1, 2],
      jwt: 'threshold-jwt',
    });
    const thresholdSessionAuthToken = 'exhausted-threshold-session-jwt';
    const authorizingWalletSigningSessionId = 'exhausted-wallet-signing-session';

    const result = await coordinator.loginWithEcdsaCapabilityForSigning({
      walletSession: TEST_WALLET_SESSION,
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionAuthToken },
      record: {
        walletId: 'alice.testnet' as any,
        subjectId: TEST_SUBJECT_ID,
        rpId: 'localhost',
        chainTarget: TEMPO_CHAIN_TARGET,
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-key' as any,
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'exhausted-threshold-session',
        },
        participantIds: [1, 3],
        ethereumAddress: '0x'.padEnd(42, 'a'),
        thresholdSessionKind: 'jwt',
        thresholdSessionId: 'exhausted-threshold-session',
        walletSigningSessionId: authorizingWalletSigningSessionId,
        thresholdSessionAuthToken,
        expiresAtMs: Date.now() - 1_000,
        remainingUses: 0,
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'sign',
          authMethod: 'email_otp',
        },
        runtimePolicyScope: {
          orgId: 'org',
          projectId: 'proj',
          envId: 'dev',
          signingRootVersion: 'root-v1',
        },
        updatedAtMs: Date.now(),
        source: 'email_otp',
      },
    });

    const loginCall = workerCalls.find(
      (call) => call.request?.type === 'loginWithEmailOtpWallet',
    );
    const bootstrapCall = workerCalls.find(
      (call) => call.request?.type === 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare',
    );
    expect(loginCall?.request.payload.routePlan).toMatchObject({
      routeFamily: 'signing_session',
      authLane: {
        kind: 'signing_session',
        jwt: thresholdSessionAuthToken,
        thresholdSessionId: 'exhausted-threshold-session',
        authorizingWalletSigningSessionId,
        curve: 'ecdsa',
        chainTarget: TEMPO_CHAIN_TARGET,
      },
      operation: 'transaction_sign',
    });
    const mintedWalletSigningSessionId = String(
      bootstrapCall?.request.payload.walletSigningSessionId || '',
    );
    expect(mintedWalletSigningSessionId).toBeTruthy();
    expect(mintedWalletSigningSessionId).not.toBe(authorizingWalletSigningSessionId);
    expect(result.bootstrap.session.walletSigningSessionId).toBe(mintedWalletSigningSessionId);
  });

  test('export ECDSA reauth uses operation-scoped auth without replacing transaction sealed refresh', async () => {
    const {
      coordinator,
      workerCalls,
      sealedRecordWrites,
      ecdsaCommitCalls,
      ed25519ProvisionCalls,
    } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
    });
    coordinator.scheduleEd25519CapabilityProvisioning = () => undefined;
    const thresholdSessionAuthToken = 'transaction-threshold-session-jwt';
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });

    const artifact = await coordinator.exportEcdsaKeyWithAuthorization({
      walletSession: {
        walletId: 'alice.testnet' as any,
        walletSessionUserId: 'alice.testnet',
      },
      challengeId: 'export-challenge-1',
      otpCode: '123456',
      rpId: 'localhost',
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionAuthToken },
      record: {
        walletId: 'alice.testnet' as any,
        subjectId: toWalletSubjectId('alice.testnet'),
        rpId: 'localhost',
        chainTarget: tempoChainTarget,
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-key' as any,
        signingRootId: 'signing-root',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'transaction-ecdsa-session',
        },
        participantIds: [1, 3],
        ethereumAddress: '0x'.padEnd(42, 'a'),
        thresholdSessionKind: 'jwt',
        thresholdSessionId: 'transaction-ecdsa-session',
        walletSigningSessionId: 'transaction-wallet-signing-session',
        thresholdSessionAuthToken,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 7,
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        updatedAtMs: Date.now(),
        source: 'email_otp',
      },
    });

    expect(artifact).toMatchObject({
      publicKeyHex: '02'.padEnd(66, '1'),
      privateKeyHex: '11'.repeat(32),
      ethereumAddress: '0x'.padEnd(42, 'a'),
    });
    const exportCall = workerCalls.find(
      (call) => call.request?.type === 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
    );
    expect(exportCall).toMatchObject({
      request: {
        payload: {
          challengeId: 'export-challenge-1',
          otpCode: '123456',
          thresholdSessionAuthToken,
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: thresholdSessionAuthToken,
              thresholdSessionId: 'transaction-ecdsa-session',
              authorizingWalletSigningSessionId: 'transaction-wallet-signing-session',
              curve: 'ecdsa',
              chainTarget: tempoChainTarget,
            },
            operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          },
        },
      },
    });
    expect(exportCall.request.payload).not.toHaveProperty('sessionId', 'transaction-ecdsa-session');
    expect(
      workerCalls.some((call) => call.request?.type === 'sealEmailOtpWarmSessionMaterial'),
    ).toBe(false);
    expect(ecdsaCommitCalls).toEqual([]);
    expect(ed25519ProvisionCalls).toEqual([]);
    expect(sealedRecordWrites).toHaveLength(0);
  });

  test('explicit signing restore rehydrates session-retained ECDSA Email OTP material from sealed refresh record', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
    });
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.userId,
                subjectId: call.request.payload.restore.subjectId,
                relayerUrl: call.request.payload.transport.relayerUrl,
                ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
                chainTarget: call.request.payload.restore.chainTarget,
                signingRootId: call.request.payload.restore.signingRootId,
                signingRootVersion: call.request.payload.restore.signingRootVersion,
                thresholdSessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                thresholdSessionAuthToken: call.request.payload.transport.thresholdSessionAuthToken,
              },
              keygen: { ok: true, rpId: 'example.com' },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.thresholdSessionAuthToken,
              },
            },
          };
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget?.kind === 'tempo'
          ? [sealedRecord]
          : [],
      readExactSealedSession: async (thresholdSessionId, purpose) =>
        thresholdSessionId === 'ecdsa-session' &&
        purpose?.authMethod === 'email_otp' &&
        purpose?.curve === 'ecdsa' &&
        purpose?.chainTarget?.kind === 'tempo'
          ? sealedRecord
          : null,
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const result = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: tempoChainTarget,
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionId: 'ecdsa-session',
      reason: 'transaction',
    });

    expect(result).toMatchObject({
      attempted: 1,
      restored: 1,
      deferred: 0,
    });
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );
    expect(restoreCall).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        payload: {
          sealedSecretB64u: 'sealed-session-secret',
          remainingUses: 2,
          expiresAtMs,
          transport: {
            relayerUrl: 'https://relay.example',
            thresholdSessionAuthToken: 'threshold-session-jwt',
            keyVersion: 'seal-v1',
            shamirPrimeB64u: 'prime-b64u',
          },
          restore: {
            sessionId: 'ecdsa-session',
            walletId: 'alice.testnet',
            userId: 'alice.testnet',
            rpId: 'localhost',
            subjectId: TEST_SUBJECT_ID,
            chainTarget: tempoChainTarget,
            walletSigningSessionId: 'wallet-session-1',
            signingRootId: 'signing-root',
            signingRootVersion: 'root-v1',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 3],
            sessionKind: 'jwt',
          },
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      walletId: 'alice.testnet',
      primaryChain: { kind: 'tempo', chainId: 42431 },
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
  });

  test('does not resolve ECDSA sealed refresh from an Ed25519 status read', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      thresholdSessionIds: {
        ed25519: 'ed25519-session',
        ecdsa: 'ecdsa-session',
      },
    });
    const sealedReads: Array<{ thresholdSessionId: string; curve?: string }> = [];
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.userId,
                subjectId: call.request.payload.restore.subjectId,
                relayerUrl: call.request.payload.transport.relayerUrl,
                ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
                chainTarget: call.request.payload.restore.chainTarget,
                signingRootId: call.request.payload.restore.signingRootId,
                signingRootVersion: call.request.payload.restore.signingRootVersion,
                thresholdSessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                thresholdSessionAuthToken: call.request.payload.transport.thresholdSessionAuthToken,
              },
              keygen: { ok: true, rpId: 'example.com' },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.thresholdSessionAuthToken,
              },
            },
          };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        sealedReads.push({ thresholdSessionId, curve: purpose?.curve });
        if (purpose?.curve === 'ed25519' && thresholdSessionId === 'ed25519-session') {
          return sealedRecord;
        }
        if (purpose?.curve === 'ecdsa' && thresholdSessionId === 'ecdsa-session') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
        thresholdSessionId === 'ecdsa-session'
          ? {
              nearAccountId: 'alice.testnet' as any,
              chain: 'tempo',
              relayerUrl: 'https://relay.example',
              ecdsaThresholdKeyId: 'ecdsa-key' as any,
              signingRootId: 'signing-root',
              signingRootVersion: 'root-v1',
              relayerKeyId: 'relayer-key',
              clientVerifyingShareB64u: 'client-verifying-share',
              clientAdditiveShareHandle: {
                kind: 'email_otp_worker_session',
                sessionId: 'ed25519-session',
              },
              participantIds: [1, 3],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'ecdsa-session',
              walletSigningSessionId: 'wallet-session-1',
              thresholdSessionAuthToken: 'threshold-session-jwt',
              signingSessionSealKeyVersion: 'seal-v1',
              signingSessionSealShamirPrimeB64u: 'prime-b64u',
              expiresAtMs,
              remainingUses: 2,
              emailOtpAuthContext: {
                policy: 'session',
                retention: 'session',
                reason: 'login',
                authMethod: 'email_otp',
              },
              updatedAtMs: Date.now(),
              source: 'email_otp',
            }
          : null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    try {
      persistWarmSessionEd25519Capability({
        kind: 'jwt_email_otp',
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        xClientBaseB64u: 'x-client-base',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      const status = await coordinator.readWarmSessionStatusOnly('ed25519-session');

      expect(status).toMatchObject({ ok: false, code: 'not_found' });
      expect(
        sealedReads.some(
          (read) => read.thresholdSessionId === 'ed25519-session' && read.curve === 'ecdsa',
        ),
      ).toBe(false);
      expect(
        workerCalls.some(
          (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        ),
      ).toBe(false);
      expect(ecdsaCommitCalls).toHaveLength(0);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('status reads do not probe sealed ECDSA records while session records are indexing', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEcdsaSealedRecordFixture({ expiresAtMs });
    const warnCalls: any[][] = [];
    const debugCalls: any[][] = [];
    const originalWarn = console.warn;
    const originalDebug = console.debug;
    console.warn = (...args: any[]) => {
      warnCalls.push(args);
    };
    console.debug = (...args: any[]) => {
      debugCalls.push(args);
    };
    const { coordinator } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
    });

    try {
      await coordinator.readWarmSessionStatusOnly('ecdsa-session');
      await coordinator.readWarmSessionStatusOnly('ecdsa-session');
    } finally {
      console.warn = originalWarn;
      console.debug = originalDebug;
    }

    expect(
      warnCalls.some((args) =>
        String(args[0] || '').includes(
          'sealed refresh restore missing session-retained ECDSA record',
        ),
      ),
    ).toBe(false);
    expect(
      debugCalls.filter((args) =>
        String(args[0] || '').includes('sealed refresh restore waiting for ECDSA record'),
      ),
    ).toHaveLength(0);
  });

  test('does not probe ECDSA sealed restore for an Ed25519 status miss', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedReads: Array<{ thresholdSessionId: string; curve?: string }> = [];
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'worker reloaded' };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        sealedReads.push({ thresholdSessionId, curve: purpose?.curve });
        return null;
      },
    });

    try {
      persistWarmSessionEd25519Capability({
        kind: 'jwt_email_otp',
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      const status = await coordinator.readWarmSessionStatusOnly('ed25519-session');

      expect(status).toMatchObject({ ok: false, code: 'not_found' });
      expect(sealedReads).toEqual([]);
      expect(
        workerCalls.some(
          (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
        ),
      ).toBe(false);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('explicit signing restore restores sealed ECDSA Email OTP session from durable metadata', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
    });
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.userId,
                subjectId: call.request.payload.restore.subjectId,
                relayerUrl: call.request.payload.transport.relayerUrl,
                ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
                chainTarget: call.request.payload.restore.chainTarget,
                signingRootId: call.request.payload.restore.signingRootId,
                signingRootVersion: call.request.payload.restore.signingRootVersion,
                thresholdSessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                thresholdSessionAuthToken: call.request.payload.transport.thresholdSessionAuthToken,
              },
              keygen: { ok: true, rpId: 'example.com' },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.thresholdSessionAuthToken,
              },
            },
          };
        }
        return { ok: true };
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget?.kind === 'tempo'
          ? [sealedRecord]
          : [],
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const restoreResult = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: tempoChainTarget,
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionId: 'ecdsa-session',
      reason: 'transaction',
    });
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );

    expect(restoreResult).toMatchObject({ attempted: 1, restored: 1, deferred: 0 });
    expect(restoreCall).toMatchObject({
      request: {
        payload: {
          transport: {
            thresholdSessionAuthToken: 'threshold-session-jwt',
          },
          restore: {
            sessionId: 'ecdsa-session',
            subjectId: TEST_SUBJECT_ID,
            chainTarget: tempoChainTarget,
            walletSigningSessionId: 'wallet-session-1',
            signingRootId: 'signing-root',
            signingRootVersion: 'root-v1',
            ecdsaThresholdKeyId: 'ecdsa-key',
            relayerKeyId: 'relayer-key',
            participantIds: [1, 3],
            sessionKind: 'jwt',
          },
        },
      },
    });
    expect(ecdsaCommitCalls).toHaveLength(1);
  });

  test('Ed25519 signing restore without durable Ed25519 metadata defers without worker restore', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          throw new Error('worker restore should not run without Ed25519 metadata');
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ed25519'
          ? []
          : [],
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const first = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionId: 'ed25519-session',
      reason: 'transaction',
    });
    const second = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionId: 'ed25519-session',
      reason: 'transaction',
    });

    expect(first).toMatchObject({ attempted: 0, restored: 0, deferred: 0 });
    expect(second).toMatchObject({ attempted: 0, restored: 0, deferred: 0 });
    expect(
      workerCalls.some(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toBe(false);
  });

  test('wallet-scoped restore enumerates durable sealed ECDSA records after reload', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const evmChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'evm',
      chainId: 5042002,
      networkSlug: 'arc-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
    });
    const { coordinator, workerCalls, ecdsaCommitCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call: any) => {
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: call.request.payload.restore.userId,
                subjectId: call.request.payload.restore.subjectId,
                relayerUrl: call.request.payload.transport.relayerUrl,
                ecdsaThresholdKeyId: call.request.payload.restore.ecdsaThresholdKeyId,
                chainTarget: call.request.payload.restore.chainTarget,
                signingRootId: call.request.payload.restore.signingRootId,
                signingRootVersion: call.request.payload.restore.signingRootVersion,
                thresholdSessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                thresholdSessionAuthToken: call.request.payload.transport.thresholdSessionAuthToken,
              },
              keygen: { ok: true, rpId: 'example.com' },
              session: {
                ok: true,
                sessionId: call.request.payload.restore.sessionId,
                walletSigningSessionId: call.request.payload.restore.walletSigningSessionId,
                expiresAtMs,
                remainingUses: 2,
                jwt: call.request.payload.transport.thresholdSessionAuthToken,
              },
            },
          };
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async (args) => {
        expect(args).toMatchObject({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp' },
        });
        return args.filter?.curve === 'ecdsa' ? [sealedRecord] : [];
      },
      readExactSealedSession: async (thresholdSessionId, purpose) => {
        if (thresholdSessionId === 'ecdsa-session' && purpose?.curve === 'ecdsa') {
          return sealedRecord;
        }
        return null;
      },
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => null,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    await coordinator.restorePersistedSessionsForWallet({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });
    await coordinator.restorePersistedSessionsForWallet({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      ecdsaChainTargets: [tempoChainTarget, evmChainTarget],
    });
    const restoreCall = workerCalls.find(
      (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
    );

    expect(restoreCall).toBeTruthy();
    expect(restoreCall.request.payload.restore).toMatchObject({
      sessionId: 'ecdsa-session',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: tempoChainTarget,
      walletSigningSessionId: 'wallet-session-1',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
    });
    expect(ecdsaCommitCalls).toHaveLength(1);
    expect(
      workerCalls.filter(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toHaveLength(1);
  });

  test('does not restore sealed Email OTP session when worker status throws during status read', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEcdsaSealedRecordFixture({ expiresAtMs });
    const ecdsaRecord = {
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerKeyId: 'relayer-key',
      participantIds: [1, 3],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'ecdsa-session',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionAuthToken: 'threshold-session-jwt',
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      updatedAtMs: Date.now(),
      source: 'email_otp',
    };
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          throw new Error('worker still booting');
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          return {
            ok: true,
            remainingUses: 2,
            expiresAtMs,
            bootstrap: {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                ecdsaThresholdKeyId: 'ecdsa-key',
                signingRootId: 'signing-root',
                signingRootVersion: 'root-v1',
                thresholdSessionId: 'ecdsa-session',
                walletSigningSessionId: 'wallet-session-1',
                thresholdSessionAuthToken: 'threshold-session-jwt',
              },
              keygen: { ok: true, rpId: 'example.com' },
              session: {
                ok: true,
                sessionId: 'ecdsa-session',
                walletSigningSessionId: 'wallet-session-1',
                expiresAtMs,
                remainingUses: 2,
                jwt: 'threshold-session-jwt',
              },
            },
          };
        }
        return { ok: true };
      },
      readExactSealedSession: async () => sealedRecord,
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => ecdsaRecord,
      acquireSigningSessionRestoreLease: async () => ({
        v: 1,
        thresholdSessionId: 'ecdsa-session',
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'unit-test-attempt',
        startedAtMs: Date.now(),
        expiresAtMs: Date.now() + 15_000,
      }),
    });

    await expect(coordinator.readWarmSessionStatusOnly('ecdsa-session')).resolves.toMatchObject({
      ok: false,
      code: 'worker_error',
    });
    expect(workerCalls.map((call) => call.request?.type)).toEqual(['getEmailOtpWarmSessionStatus']);
  });

  test('fails closed before worker restore when sealed signing-root metadata mismatches session state', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    });
    const sealedRecord = buildEcdsaSealedRecordFixture({
      expiresAtMs,
      chainTarget: tempoChainTarget,
      signingRootId: 'other-signing-root',
    });
    const ecdsaRecord = {
      nearAccountId: 'alice.testnet' as any,
      chain: 'tempo',
      subjectId: toWalletSubjectId('alice.testnet'),
      chainTarget: tempoChainTarget,
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key' as any,
      signingRootId: 'signing-root',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientAdditiveShareHandle: {
        kind: 'email_otp_worker_session',
        sessionId: 'ecdsa-session',
      },
      participantIds: [1, 3],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'ecdsa-session',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionAuthToken: 'threshold-session-jwt',
      signingSessionSealKeyVersion: 'seal-v1',
      signingSessionSealShamirPrimeB64u: 'prime-b64u',
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      updatedAtMs: Date.now(),
      source: 'email_otp',
    };
    const { coordinator, workerCalls } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      requestWorkerOperation: async (call) => {
        if (call.request?.type === 'getEmailOtpWarmSessionStatus') {
          return { ok: false, code: 'not_found', message: 'missing after reload' };
        }
        if (call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          throw new Error('worker restore should not run');
        }
        return { ok: true };
      },
      listExactSealedSessionsForWallet: async ({ walletId, filter }) =>
        walletId === 'alice.testnet' &&
        filter?.authMethod === 'email_otp' &&
        filter?.curve === 'ecdsa' &&
        filter?.chainTarget?.kind === 'tempo'
          ? [sealedRecord]
          : [],
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => ecdsaRecord,
      acquireSigningSessionRestoreLease: async (args) => ({
        ...args,
        v: 1,
        walletSigningSessionId: 'wallet-session-1',
        ownerId: 'unit-test',
        attemptId: 'restore-attempt-1',
        startedAtMs: Date.now(),
        expiresAtMs,
      }),
      releaseSigningSessionRestoreLease: async () => {},
    });

    const restoreResult = await coordinator.restorePersistedSessionForSigning({
      walletId: 'alice.testnet',
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: tempoChainTarget,
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionId: 'ecdsa-session',
      reason: 'transaction',
    });

    expect(restoreResult).toMatchObject({ attempted: 1, restored: 0, deferred: 1 });
    expect(
      workerCalls.some(
        (call) => call.request?.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      ),
    ).toBe(false);
  });

  test('attaches Ed25519 threshold session id to existing Email OTP sealed refresh record', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const ecdsaRecord = {
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key',
      signingRootId: 'signing-root',
      signingRootVersion: 'root-v1',
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'verifying-share',
      participantIds: [1, 3],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'ecdsa-session',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionAuthToken: 'threshold-session-jwt',
      expiresAtMs,
      remainingUses: 2,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      source: 'email_otp',
      subjectId: toWalletSubjectId('alice.testnet'),
      chainTarget: thresholdEcdsaChainTargetFromChainFamily({
        chain: 'tempo',
        chainId: 42431,
        networkSlug: 'tempo-testnet',
      }),
      updatedAtMs: Date.now(),
    };
    const { coordinator, sealedRecordWrites } = createCoordinator({
      configs: {
        signing: {
          emailOtp: { authPolicy: 'session' },
          sessionPersistenceMode: 'sealed_refresh_v1',
          sessionSeal: { keyVersion: 'seal-v1', shamirPrimeB64u: 'prime-b64u' },
        },
      },
      readExactSealedSession: async (thresholdSessionId) => ({
        v: 1,
        alg: 'shamir3pass-v1',
        storageScope: 'iframe_origin_indexeddb',
        runtimeSessionId: 'runtime-1',
        authMethod: 'email_otp',
        secretKind: 'signing_session_secret32',
        walletSigningSessionId: 'wallet-session-1',
        thresholdSessionIds: { ecdsa: thresholdSessionId },
        sealedSecretB64u: 'sealed-session-secret',
        curve: 'ecdsa',
        walletId: 'alice.testnet',
        userId: 'alice.testnet',
        subjectId: TEST_SUBJECT_ID,
        signingRootId: 'signing-root',
        signingRootVersion: 'root-v1',
        relayerUrl: 'https://relay.example',
        keyVersion: 'seal-v1',
        shamirPrimeB64u: 'prime-b64u',
        ecdsaRestore: {
          chainTarget: ecdsaRecord.chainTarget,
          rpId: 'example.com',
          thresholdSessionAuthToken: 'threshold-session-jwt',
          sessionKind: 'jwt',
          ecdsaThresholdKeyId: 'ecdsa-key',
          ethereumAddress: `0x${'33'.repeat(20)}`,
          relayerKeyId: 'relayer-key',
          clientVerifyingShareB64u: 'verifying-share',
          thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
          participantIds: [1, 3],
        },
        issuedAtMs: Date.now(),
        expiresAtMs,
        remainingUses: 2,
        updatedAtMs: Date.now(),
      }),
      getThresholdEcdsaSessionRecordByThresholdSessionId: () => ecdsaRecord,
    });

    try {
      persistWarmSessionEd25519Capability({
        kind: 'jwt_email_otp',
        nearAccountId: 'alice.testnet',
        rpId: 'localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-session-1',
        expiresAtMs,
        remainingUses: 2,
        sessionKind: 'jwt',
        jwt: appSessionJwt(),
        xClientBaseB64u: 'x-client-base',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      await (coordinator as any).attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
        ecdsaThresholdSessionId: 'ecdsa-session',
        ed25519ThresholdSessionId: 'ed25519-session',
      });
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }

    expect(sealedRecordWrites).toHaveLength(1);
    expect(sealedRecordWrites[0]).toMatchObject({
      sealedSecretB64u: 'sealed-session-secret',
      authMethod: 'email_otp',
      walletSigningSessionId: 'wallet-session-1',
      thresholdSessionIds: {
        ecdsa: 'ecdsa-session',
        ed25519: 'ed25519-session',
      },
    });
  });

  test('enrolls ECDSA Email OTP capability and awaits Ed25519 provisioning', async () => {
    const { coordinator, ecdsaCommitCalls, ed25519ProvisionCalls } = createCoordinator();
    const jwt = appSessionJwt();
    coordinator.provisionEd25519Capability = async (args) => {
      ed25519ProvisionCalls.push(args);
      return {
        publicKey: 'ed25519-public',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        sessionId: 'ed-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        participantIds: [1, 2],
        jwt: 'threshold-jwt',
      };
    };

    const result = await coordinator.enrollAndLoginWithEcdsaCapabilityInternal({
      walletSession: TEST_WALLET_SESSION,
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      routeAuth: { kind: 'app_session', jwt },
      clientSecret32: new Uint8Array(32).fill(7),
      registrationAttemptId: 'registration-attempt-1',
    });

    expect(result.enrollment.thresholdEcdsaClientVerifyingShareB64u).toBe('verifying-share');
    expect(ecdsaCommitCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      prfFirstB64u: 'prf-first-ecdsa-enroll',
      registrationAttemptId: 'registration-attempt-1',
      ecdsaThresholdSessionId: 'ecdsa-session',
    });
  });
});
