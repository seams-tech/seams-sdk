import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '@shared/utils/encoders';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import { planAccountSignerActivation, SignerLifecycleError } from '@/core/indexedDB';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordForAccount,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmSigning/persistence';
import { EmailOtpThresholdSessionCoordinator } from '@/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';

function expectSignerLifecycleError(fn: () => unknown, code: string): void {
  try {
    fn();
    throw new Error('expected SignerLifecycleError');
  } catch (error) {
    expect(error).toBeInstanceOf(SignerLifecycleError);
    expect(error).toMatchObject({
      name: 'SignerLifecycleError',
      code,
    });
  }
}

function makeWorkerBootstrap(args?: {
  walletId?: string;
  sessionId?: string;
  walletSigningSessionId?: string;
  remainingUses?: number;
}) {
  const walletId = args?.walletId || 'alice.testnet';
  const sessionId = args?.sessionId || 'ecdsa-session-worker';
  const walletSigningSessionId = args?.walletSigningSessionId || '';
  const clientAdditiveShareHandle = {
    kind: 'email_otp_worker_session' as const,
    sessionId,
  };
  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1' as const,
      userId: walletId,
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      backendBinding: {
        relayerKeyId: 'rk-worker',
        clientVerifyingShareB64u: 'AQ',
        clientAdditiveShareHandle,
      },
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt' as const,
      thresholdSessionId: sessionId,
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
      thresholdSessionJwt: 'jwt-worker',
      signingRootId: 'signing-root-worker',
      signingRootVersion: 'v1',
    },
    keygen: {
      ok: true,
      keygenSessionId: 'keygen-worker',
      rpId: 'example.localhost',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      relayerKeyId: 'rk-worker',
      clientVerifyingShareB64u: 'AQ',
      participantIds: [1, 2],
    },
    session: {
      ok: true,
      sessionId,
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
      jwt: 'jwt-worker',
      remainingUses: args?.remainingUses ?? 7,
      expiresAtMs: Date.now() + 60_000,
      clientVerifyingShareB64u: 'AQ',
    },
  };
}

function makeUnsignedJwt(payload: Record<string, unknown>): string {
  const encode = (value: Record<string, unknown>) =>
    btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`;
}

function makeThresholdSessionJwt(
  kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1',
  payload?: Record<string, unknown>,
): string {
  const walletId = String(payload?.walletId || payload?.sub || 'alice.testnet');
  return makeUnsignedJwt({
    kind,
    sub: walletId,
    walletId,
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...payload,
  });
}

function makeBareSigningEngine(): SigningEngine {
  const engine = Object.create(SigningEngine.prototype) as SigningEngine;
  const engineAny = engine as any;
  engineAny.tatchiPasskeyConfigs = {
    network: {
      relayer: { url: 'https://relay.example' },
    },
    signing: {
      sessionSeal: { shamirPrimeB64u: 'prime-b64u' },
    },
  };
  engineAny.thresholdEcdsaSessionByLane = new Map();
  engineAny.thresholdEcdsaExportArtifactByLane = new Map();
  engineAny.orchestrationDeps = {
    signingSessionCoordinator: {
      getAvailableStatus: async () => null,
    },
  };
  return engine;
}

function installEmailOtpSessionsFixture(
  engineAny: any,
  args?: {
    requestWorkerOperation?: (input: { kind: string; request: any }) => Promise<any>;
    requestTransactionSigningChallenge?: (input: Record<string, unknown>) => Promise<{
      challengeId: string;
      emailHint?: string;
      appSessionJwt?: string;
    }>;
    writeSigningSessionSealedRecord?: (input: Record<string, any>) => Promise<void>;
    readSigningSessionSealedRecord?: (thresholdSessionId: string) => Promise<any>;
    acquireSigningSessionRestoreLease?: (input: Record<string, any>) => Promise<any>;
    releaseSigningSessionRestoreLease?: (input: any) => Promise<void>;
    loginWithEcdsaCapabilityForSigning?: (input: Record<string, unknown>) => Promise<any> | any;
    loginWithEd25519CapabilityForSigning?: (input: Record<string, unknown>) => Promise<any> | any;
  },
): any {
  const workerOperation =
    args?.requestWorkerOperation ||
    (async () => {
      throw new Error('unexpected Email OTP worker operation');
    });
  const coordinator = new EmailOtpThresholdSessionCoordinator({
    configs: engineAny.tatchiPasskeyConfigs || {
      network: { relayer: { url: 'https://relay.example' } },
      signing: {
        emailOtp: { authPolicy: 'session' },
        sessionSeal: { shamirPrimeB64u: 'prime-b64u' },
      },
    },
    signerWorkerManager: {
      requestWorkerOperation: workerOperation,
    } as any,
    touchIdPrompt: engineAny.touchIdPrompt || {
      getRpId: () => 'example.localhost',
    },
    requestUserConfirmation: (request: any) =>
      engineAny.touchConfirm.requestUserConfirmation(request),
    getSignerWorkerContext: () => ({
      requestWorkerOperation: workerOperation,
    }),
    commitWorkerProvisionedThresholdEcdsaSessions: async (callArgs: any) =>
      await (SigningEngine.prototype as any).commitWorkerProvisionedThresholdEcdsaSessions.call(
        engineAny,
        callArgs,
      ),
    getThresholdEcdsaKeyRefForLookup: (callArgs: any) =>
      engineAny.getThresholdEcdsaKeyRefForLookup(callArgs),
    getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId: string) =>
      (SigningEngine.prototype as any).getThresholdEcdsaSessionRecordByThresholdSessionId.call(
        engineAny,
        thresholdSessionId,
      ),
    persistEmailOtpThresholdEd25519LocalMetadata: async () => undefined,
    persistWarmSessionEd25519Capability,
    hydrateSigningSession: async () => undefined,
    ...(args?.writeSigningSessionSealedRecord
      ? { writeSigningSessionSealedRecord: args.writeSigningSessionSealedRecord }
      : {}),
    ...(args?.readSigningSessionSealedRecord
      ? { readSigningSessionSealedRecord: args.readSigningSessionSealedRecord }
      : {}),
    ...(args?.acquireSigningSessionRestoreLease
      ? { acquireSigningSessionRestoreLease: args.acquireSigningSessionRestoreLease as any }
      : {}),
    ...(args?.releaseSigningSessionRestoreLease
      ? { releaseSigningSessionRestoreLease: args.releaseSigningSessionRestoreLease }
      : {}),
  }) as any;
  if (args?.requestTransactionSigningChallenge) {
    coordinator.requestTransactionSigningChallenge = args.requestTransactionSigningChallenge;
  }
  if (args?.loginWithEcdsaCapabilityForSigning) {
    coordinator.loginWithEcdsaCapabilityForSigning = args.loginWithEcdsaCapabilityForSigning;
  }
  if (args?.loginWithEd25519CapabilityForSigning) {
    coordinator.loginWithEd25519CapabilityForSigning = args.loginWithEd25519CapabilityForSigning;
  }
  engineAny.emailOtpSessions = coordinator;
  return coordinator;
}

function makeEngine(args: {
  requestWorkerOperation: (input: { kind: string; request: any }) => Promise<any>;
  authPolicy?: 'session' | 'per_operation';
  rpId?: string;
  warmReady?: boolean;
  touchConfirm?: Record<string, unknown>;
  writeSigningSessionSealedRecord?: (input: Record<string, any>) => Promise<void>;
  readSigningSessionSealedRecord?: (
    thresholdSessionId: string,
  ) => Promise<Record<string, any> | null>;
  acquireSigningSessionRestoreLease?: (input: Record<string, any>) => Promise<any>;
  releaseSigningSessionRestoreLease?: (input: any) => Promise<void>;
}) {
  const engine = makeBareSigningEngine();
  const engineAny = engine as any;
  const persistCalls: Array<Record<string, unknown>> = [];
  const upsertCalls: Array<Record<string, unknown>> = [];
  const readyChecks: Array<Record<string, unknown>> = [];
  const ed25519ProvisionCalls: Array<Record<string, unknown>> = [];

  engineAny.tatchiPasskeyConfigs = {
    network: {
      relayer: {
        url: 'https://relay.example',
      },
    },
    signing: {
      emailOtp: {
        authPolicy: args.authPolicy || 'session',
      },
      sessionSeal: {
        shamirPrimeB64u: 'prime-b64u',
      },
    },
  };
  engineAny.touchIdPrompt = {
    getRpId: () => args.rpId ?? 'example.localhost',
  };
  engineAny.touchConfirm = args.touchConfirm || {};
  engineAny.thresholdEcdsaBootstrapQueueByAccount = new Map();
  engineAny.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap = async () => undefined;
  engineAny.orchestrationDeps = {
    signingSessionCoordinator: {
      getAvailableStatus: async () => null,
    },
    thresholdSessionActivationDeps: {
      getSignerWorkerContext: () => ({
        requestWorkerOperation: args.requestWorkerOperation,
      }),
    },
  };
  engineAny.bootstrapEcdsaSession = async () => {
    throw new Error('main-thread Email OTP bootstrap fallback must not run');
  };
  engineAny.persistThresholdEcdsaBootstrapChainAccount = async (
    callArgs: Record<string, unknown>,
  ) => {
    persistCalls.push(callArgs);
  };
  engineAny.upsertThresholdEcdsaSessionFromBootstrap = (callArgs: Record<string, unknown>) => {
    upsertCalls.push(callArgs);
  };
  engineAny.assertWarmThresholdEcdsaCapabilityReady = async (callArgs: {
    nearAccountId: string;
    chain: 'evm' | 'tempo';
  }) => {
    readyChecks.push({ ...callArgs });
    if (args.warmReady === false) {
      throw new Error(
        `[SigningEngine] Email OTP bootstrap did not reach warm-session ready state for ${callArgs.nearAccountId} (${callArgs.chain}, state=prf_missing)`,
      );
    }
    const policy = args.authPolicy || 'session';
    const emailOtpAuthContext = {
      policy,
      retention: policy === 'per_operation' ? 'single_use' : 'session',
      reason: 'login',
      authMethod: 'email_otp',
    };
    return {
      capability: 'ecdsa',
      chain: callArgs.chain,
      record: {
        nearAccountId: callArgs.nearAccountId,
        thresholdSessionId: 'ecdsa-session-worker',
        thresholdSessionKind: 'jwt',
        source: 'email_otp',
        emailOtpAuthContext,
      },
      auth: {
        capability: 'ecdsa',
        chain: callArgs.chain,
        record: {
          nearAccountId: callArgs.nearAccountId,
          thresholdSessionId: 'ecdsa-session-worker',
          thresholdSessionKind: 'jwt',
          source: 'email_otp',
          emailOtpAuthContext,
        },
        thresholdSessionJwt: 'jwt-worker',
        thresholdSessionJwtSource: 'app-session',
      },
      prfClaim: {
        state: 'warm',
        sessionId: 'ecdsa-session-worker',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: policy === 'per_operation' ? 1 : 7,
      },
      emailOtpAuthContext,
      state: 'ready',
    };
  };
  engineAny.provisionEmailOtpThresholdEd25519Capability = async (
    callArgs: Record<string, unknown>,
  ) => {
    ed25519ProvisionCalls.push(callArgs);
    return {
      publicKey: 'ed25519:email-otp-public-key',
      relayerKeyId: 'ed25519-relayer-key',
      keyVersion: 'threshold-ed25519-hss-v1',
      sessionId: 'ed25519-session-worker',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 7,
      participantIds: [1, 2],
      jwt: 'ed25519-jwt-worker',
      xClientBaseB64u: 'x-client-base-worker',
    };
  };
  const emailOtpSessions = installEmailOtpSessionsFixture(engineAny, {
    requestWorkerOperation: args.requestWorkerOperation,
    writeSigningSessionSealedRecord: args.writeSigningSessionSealedRecord,
    readSigningSessionSealedRecord: args.readSigningSessionSealedRecord,
    acquireSigningSessionRestoreLease: args.acquireSigningSessionRestoreLease,
    releaseSigningSessionRestoreLease: args.releaseSigningSessionRestoreLease,
  });
  emailOtpSessions.provisionEd25519Capability =
    engineAny.provisionEmailOtpThresholdEd25519Capability;

  return { engine, persistCalls, upsertCalls, readyChecks, ed25519ProvisionCalls };
}

test.describe('SigningEngine Email OTP bootstrap runtime', () => {
  test('generic signer activation planning rejects duplicate same-kind registration', () => {
    const plan = () =>
      planAccountSignerActivation({
        signer: {
          signerId: 'threshold-ed25519:rk-new',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'email_otp',
          signerSource: 'email_otp_registration',
        },
        activeSigners: [
          {
            signerId: 'threshold-ed25519:rk-old',
            signerSlot: 1,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
            metadata: { signerMaterialFingerprint: 'old-material' },
          },
        ],
        activationPolicy: {
          mode: 'reuse_existing',
          signerId: 'threshold-ed25519:rk-new',
          materialFingerprint: 'new-material',
        },
      });
    expectSignerLifecycleError(plan, 'signer_lifecycle_duplicate_registration');
  });

  test('generic signer activation planning allocates a new slot without evicting active signers', () => {
    const plan = planAccountSignerActivation({
      signer: {
        signerId: 'threshold-ed25519:rk-new',
        signerKind: 'threshold-ed25519',
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
      },
      activeSigners: [
        {
          signerId: 'threshold-ed25519:passkey-primary',
          signerSlot: 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
        },
      ],
      activationPolicy: {
        mode: 'allocate_next_free',
      },
    });

    expect(plan).toEqual({
      signerSlot: 2,
    });
  });

  test('generic signer activation planning is idempotent for the same signer', () => {
    const plan = planAccountSignerActivation({
      signer: {
        signerId: 'threshold-ed25519:rk-current',
        signerKind: 'threshold-ed25519',
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
      },
      activeSigners: [
        {
          signerId: 'threshold-ed25519:rk-current',
          signerSlot: 4,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'email_otp',
          signerSource: 'email_otp_registration',
          metadata: { signerMaterialFingerprint: 'current-material' },
        },
      ],
      activationPolicy: {
        mode: 'reuse_existing',
        signerId: 'threshold-ed25519:rk-current',
        materialFingerprint: 'current-material',
      },
    });

    expect(plan).toEqual({
      signerSlot: 4,
    });
  });

  test('generic signer activation planning fails when all tested slots are occupied', () => {
    const plan = () =>
      planAccountSignerActivation({
        signer: {
          signerId: 'threshold-ed25519:rk-new',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'email_otp',
          signerSource: 'email_otp_registration',
        },
        activeSigners: Array.from({ length: 999 }, (_, index) => ({
          signerId: `threshold-ed25519:passkey-${index + 1}`,
          signerSlot: index + 1,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
        })),
        activationPolicy: {
          mode: 'allocate_next_free',
        },
      });
    expect(plan).toThrow('No available account signer slot');
    expectSignerLifecycleError(plan, 'signer_lifecycle_no_available_slot');
  });

  test('generic signer activation planning rejects occupied requested slots with a typed error', () => {
    const plan = () =>
      planAccountSignerActivation({
        signer: {
          signerId: 'threshold-ecdsa:rk-new',
          signerKind: 'threshold-ecdsa',
          signerAuthMethod: 'email_otp',
          signerSource: 'email_otp_registration',
        },
        activeSigners: [
          {
            signerId: 'threshold-ed25519:rk-current',
            signerSlot: 2,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'passkey',
            signerSource: 'passkey_registration',
          },
        ],
        activationPolicy: {
          mode: 'fail_if_occupied',
          signerSlot: 2,
        },
      });
    expect(plan).toThrow('Active signer slot 2 is already occupied');
    expectSignerLifecycleError(plan, 'signer_lifecycle_slot_occupied');
  });

  test('generic signer activation planning rejects signer material mismatch with a typed error', () => {
    const plan = () =>
      planAccountSignerActivation({
        signer: {
          signerId: 'threshold-ed25519:rk-current',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'email_otp',
          signerSource: 'email_otp_registration',
        },
        activeSigners: [
          {
            signerId: 'threshold-ed25519:rk-current',
            signerSlot: 1,
            signerType: 'threshold',
            signerKind: 'threshold-ed25519',
            signerAuthMethod: 'email_otp',
            signerSource: 'email_otp_registration',
            metadata: { signerMaterialFingerprint: 'old-material' },
          },
        ],
        activationPolicy: {
          mode: 'reuse_existing',
          signerId: 'threshold-ed25519:rk-current',
          materialFingerprint: 'new-material',
        },
      });
    expectSignerLifecycleError(plan, 'signer_lifecycle_material_mismatch');
  });

  test('generic signer activation planning rejects invalid signer metadata with a typed error', () => {
    const plan = () =>
      planAccountSignerActivation({
        signer: {
          signerId: '',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'email_otp',
          signerSource: 'email_otp_registration',
        },
        activeSigners: [],
        activationPolicy: {
          mode: 'allocate_next_free',
        },
      });
    expect(plan).toThrow('signerId is required');
    expectSignerLifecycleError(plan, 'signer_lifecycle_invalid_input');
  });

  test('enrollment bridge dispatches secret-bearing enrollment to the Email OTP worker', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const clientSecret32 = base64UrlDecode('AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE');
    const { engine } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('enrollEmailOtpWallet');
        return {
          thresholdEcdsaClientVerifyingShareB64u: 'verifier-worker',
          challengeId: 'enroll-1',
          otpChannel: 'email_otp',
          enrollmentSealKeyVersion: 'email-otp-kv-1',
          clientUnlockPublicKeyB64u: 'unlock-public-key-worker',
          unlockKeyVersion: 'email-otp-unlock-v1',
        };
      },
    });

    const result = await engine.enrollEmailOtpInternal({
      nearAccountId: walletId,
      challengeId: 'enroll-1',
      otpCode: '123456',
      appSessionJwt: 'app-session-jwt',
      clientSecret32,
    });

    expect(workerRequests).toHaveLength(1);
    expect(workerRequests[0]?.request).toMatchObject({
      type: 'enrollEmailOtpWallet',
      payload: {
        relayUrl: 'https://relay.example',
        walletId,
        userId: walletId,
        challengeId: 'enroll-1',
        otpCode: '123456',
        shamirPrimeB64u: 'prime-b64u',
        routePlan: {
          routeFamily: 'registration',
          authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
          operation: 'wallet_unlock',
        },
        otpChannel: 'email_otp',
      },
    });
    expect(workerRequests[0]?.request.payload.clientSecret32).toBeInstanceOf(ArrayBuffer);
    expect(result.challengeId).toBe('enroll-1');
    expect(result.enrollmentSealKeyVersion).toBe('email-otp-kv-1');
    expect(result.unlockKeyVersion).toBe('email-otp-unlock-v1');
  });

  test('Google SSO registration can enroll Email OTP and bootstrap ECDSA with a cookie session', async () => {
    const walletId = 'g-1234567890abcdef1234567890abcdef.testnet';
    const runtimePolicyScope = {
      orgId: 'org_test',
      envId: 'env_test',
      projectId: 'project_test',
      signingRootVersion: 'v1',
    };
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, persistCalls, upsertCalls, readyChecks, ed25519ProvisionCalls } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('enrollEmailOtpWalletAndBootstrapEcdsaSession');
        return {
          enrollment: {
            thresholdEcdsaClientVerifyingShareB64u: 'verifier-worker',
            thresholdEd25519PrfFirstB64u: 'email-otp-ed25519-prf-worker',
            challengeId: 'enroll-otp-1',
            otpChannel: 'email_otp',
            enrollmentSealKeyVersion: 'email-otp-kv-1',
            clientUnlockPublicKeyB64u: 'unlock-public-key-worker',
            unlockKeyVersion: 'email-otp-unlock-v1',
          },
          bootstrap: makeWorkerBootstrap({ walletId, sessionId: 'cookie-ecdsa-session-worker' }),
        };
      },
    });

    const result = await engine.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'tempo',
      challengeId: 'enroll-otp-1',
      otpCode: '123456',
      sessionKind: 'cookie',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionId: 'cookie-ecdsa-session-worker',
      runtimePolicyScope,
    });

    expect(workerRequests).toHaveLength(1);
    expect(workerRequests[0]?.request).toMatchObject({
      type: 'enrollEmailOtpWalletAndBootstrapEcdsaSession',
      timeoutMs: 60_000,
      payload: {
        relayUrl: 'https://relay.example',
        walletId,
        userId: walletId,
        challengeId: 'enroll-otp-1',
        otpCode: '123456',
        shamirPrimeB64u: 'prime-b64u',
        otpChannel: 'email_otp',
        rpId: 'example.localhost',
        ecdsaThresholdKeyId: 'ecdsa-key-worker',
        participantIds: [1, 2],
        sessionKind: 'cookie',
        sessionId: 'cookie-ecdsa-session-worker',
        runtimePolicyScope,
      },
    });
    expect(workerRequests[0]?.request.payload.routeAuth).toBeUndefined();
    expect(result.enrollment.enrollmentSealKeyVersion).toBe('email-otp-kv-1');
    expect(persistCalls).toHaveLength(2);
    expect(persistCalls.map((call) => call.chain)).toEqual(['tempo', 'evm']);
    for (const call of persistCalls) {
      expect(call).toMatchObject({ ensureEmailOtpNearAccountMapping: true });
    }
    expect(upsertCalls).toHaveLength(2);
    expect(upsertCalls.map((call) => call.chain)).toEqual(['tempo', 'evm']);
    expect(readyChecks).toEqual([
      { nearAccountId: walletId, chain: 'tempo' },
      { nearAccountId: walletId, chain: 'evm' },
    ]);
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: walletId,
      relayUrl: 'https://relay.example',
      rpId: 'example.localhost',
      prfFirstB64u: 'email-otp-ed25519-prf-worker',
      runtimePolicyScope,
      participantIds: [1, 2],
    });
  });

  test('default Email OTP login completes ECDSA authorization bootstrap inside the Email OTP worker', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, persistCalls, upsertCalls, readyChecks, ed25519ProvisionCalls } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            challengeId: 'challenge-worker',
            enrollmentSealKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            clientUnlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
            thresholdEd25519PrfFirstB64u: 'email-otp-ed25519-prf-worker',
          },
          bootstrap: makeWorkerBootstrap({ walletId, sessionId: 'ecdsa-session-worker' }),
        };
      },
    });

    const result = await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      challengeId: 'preissued-rc-worker',
      otpCode: '123456',
      appSessionJwt: 'app-session-jwt',
      routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
      ttlMs: 120_000,
      remainingUses: 7,
    });

    expect(workerRequests).toHaveLength(1);
    expect(workerRequests[0]?.request).toMatchObject({
      type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
      timeoutMs: 60_000,
      payload: {
        relayUrl: 'https://relay.example',
        walletId,
        userId: walletId,
        challengeId: 'preissued-rc-worker',
        otpCode: '123456',
        shamirPrimeB64u: 'prime-b64u',
        otpChannel: 'email_otp',
        rpId: 'example.localhost',
        ecdsaThresholdKeyId: 'ecdsa-key-worker',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-worker',
        routePlan: {
          routeFamily: 'login',
          authLane: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
          operation: 'wallet_unlock',
        },
        ttlMs: 120_000,
        remainingUses: 7,
      },
    });
    expect(persistCalls).toHaveLength(2);
    expect(persistCalls.map((call) => call.chain)).toEqual(['evm', 'tempo']);
    for (const call of persistCalls) {
      expect(call).toMatchObject({ ensureEmailOtpNearAccountMapping: true });
    }
    expect(upsertCalls).toHaveLength(2);
    expect(upsertCalls.map((call) => call.chain)).toEqual(['evm', 'tempo']);
    expect(upsertCalls[0]).toMatchObject({
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      bootstrap: {
        thresholdEcdsaKeyRef: {
          backendBinding: {
            clientAdditiveShareHandle: {
              kind: 'email_otp_worker_session',
              sessionId: 'ecdsa-session-worker',
            },
          },
        },
      },
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
    expect(
      ((upsertCalls[0]?.bootstrap as any)?.thresholdEcdsaKeyRef?.backendBinding || {})
        .clientAdditiveShare32B64u,
    ).toBeUndefined();
    expect(upsertCalls[1]).toMatchObject({
      nearAccountId: walletId,
      chain: 'tempo',
      source: 'email_otp',
      bootstrap: {
        thresholdEcdsaKeyRef: {
          backendBinding: {
            clientAdditiveShareHandle: {
              kind: 'email_otp_worker_session',
              sessionId: 'ecdsa-session-worker',
            },
          },
        },
      },
    });
    expect(readyChecks).toEqual([
      { nearAccountId: walletId, chain: 'evm' },
      { nearAccountId: walletId, chain: 'tempo' },
    ]);
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: walletId,
      relayUrl: 'https://relay.example',
      rpId: 'example.localhost',
      prfFirstB64u: 'email-otp-ed25519-prf-worker',
      appSessionJwt: 'bootstrap-auth-jwt',
      participantIds: [1, 2],
      ttlMs: 120_000,
      remainingUses: 7,
    });
    expect('clientRootShare32B64u' in result.recovery).toBe(false);
    expect(result.bootstrap.thresholdEcdsaKeyRef.thresholdSessionId).toBe('ecdsa-session-worker');
    expect(result.warmCapability.state).toBe('ready');
  });

  test('Email OTP warm-session status restores sealed ECDSA material after worker reload', async () => {
    const walletId = 'sealed-status.testnet';
    const ecdsaSessionId = 'ecdsa-sealed-status-session';
    const walletSigningSessionId = 'wallet-signing-sealed-status-session';
    const workerRequests: string[] = [];
    const sealedRecords = new Map<string, Record<string, any>>();
    let workerMaterialAvailable = false;
    const bootstrap = makeWorkerBootstrap({
      walletId,
      sessionId: ecdsaSessionId,
      walletSigningSessionId,
      remainingUses: 9,
    });
    const { engine } = makeEngine({
      requestWorkerOperation: async ({ request }) => {
        workerRequests.push(request.type);
        if (request.type === 'loginWithEmailOtpAndBootstrapEcdsaSession') {
          workerMaterialAvailable = true;
          return {
            recovery: {
              challengeId: 'challenge-worker',
              enrollmentSealKeyVersion: 'email-otp-kv-worker',
              unlockChallengeId: 'unlock-worker',
              unlockChallengeB64u: 'unlock-b64u',
              clientUnlockPublicKeyB64u: 'unlock-pub',
              unlockSignatureB64u: 'unlock-sig',
              thresholdEd25519PrfFirstB64u: 'email-otp-ed25519-prf-worker',
            },
            bootstrap,
          };
        }
        if (request.type === 'sealEmailOtpWarmSessionMaterial') {
          return {
            ok: true,
            sealedSecretB64u: 'sealed-session-secret-status',
            keyVersion: 'seal-kv-status',
            remainingUses: 9,
            expiresAtMs: Date.now() + 60_000,
          };
        }
        if (request.type === 'getEmailOtpWarmSessionStatus') {
          return workerMaterialAvailable
            ? { ok: true, remainingUses: 8, expiresAtMs: Date.now() + 60_000 }
            : {
                ok: false,
                code: 'not_found',
                message: 'Email OTP worker was reloaded',
              };
        }
        if (request.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          workerMaterialAvailable = true;
          return {
            ok: true,
            bootstrap,
            remainingUses: 8,
            expiresAtMs: Date.now() + 60_000,
          };
        }
        throw new Error(`unexpected worker request: ${request.type}`);
      },
      writeSigningSessionSealedRecord: async (record) => {
        sealedRecords.set(record.thresholdSessionId, {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-sealed-status',
          authMethod: record.authMethod || 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: record.walletSigningSessionId,
          thresholdSessionIds: record.thresholdSessionIds,
          sealedSecretB64u: record.sealedSecretB64u,
          curve: record.curve,
          walletId: record.walletId,
          userId: record.userId,
          signingRootId: record.signingRootId,
          signingRootVersion: record.signingRootVersion,
          relayerUrl: record.relayerUrl,
          keyVersion: record.keyVersion,
          shamirPrimeB64u: record.shamirPrimeB64u,
          issuedAtMs: Date.now(),
          expiresAtMs: record.expiresAtMs,
          remainingUses: record.remainingUses,
          updatedAtMs: record.updatedAtMs || Date.now(),
        });
      },
      readSigningSessionSealedRecord: async (thresholdSessionId) =>
        sealedRecords.get(thresholdSessionId) || null,
      acquireSigningSessionRestoreLease: async ({ thresholdSessionId }) => ({
        v: 1,
        thresholdSessionId,
        walletSigningSessionId,
        ownerId: 'unit-test',
        attemptId: 'unit-test-attempt',
        startedAtMs: Date.now(),
        expiresAtMs: Date.now() + 15_000,
      }),
      releaseSigningSessionRestoreLease: async () => undefined,
    });
    (engine as any).tatchiPasskeyConfigs.signing.sessionPersistenceMode = 'sealed_refresh_v1';

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'tempo',
      challengeId: 'challenge-worker',
      otpCode: '123456',
      routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
      sessionId: ecdsaSessionId,
      walletSigningSessionId,
    } as any);
    (SigningEngine.prototype as any).upsertThresholdEcdsaSessionFromBootstrap.call(engine as any, {
      nearAccountId: walletId,
      chain: 'tempo',
      bootstrap,
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });

    workerMaterialAvailable = false;
    const status = await (engine as any).emailOtpSessions.getWarmSessionStatus(ecdsaSessionId);

    expect(status).toMatchObject({ ok: true, remainingUses: 8 });
    expect(workerRequests).toContain('sealEmailOtpWarmSessionMaterial');
    expect(workerRequests).toContain('rehydrateEmailOtpEcdsaWarmSessionMaterial');
  });

  test('Email OTP ECDSA status listing restores sealed material before UI readiness', async () => {
    const walletId = 'alice-list-status.testnet';
    const ecdsaSessionId = 'ecdsa-session-list-status';
    const walletSigningSessionId = 'wallet-session-list-status';
    const workerRequests: string[] = [];
    const sealedRecords = new Map<string, Record<string, any>>();
    let workerMaterialAvailable = true;
    const bootstrap = makeWorkerBootstrap({
      walletId,
      sessionId: ecdsaSessionId,
      walletSigningSessionId,
    });
    const { engine } = makeEngine({
      requestWorkerOperation: async ({ request }) => {
        workerRequests.push(request.type);
        if (request.type === 'loginWithEmailOtpAndBootstrapEcdsaSession') {
          return {
            recovery: {
              challengeId: 'challenge-worker',
              enrollmentSealKeyVersion: 'email-otp-kv-worker',
              unlockChallengeId: 'unlock-worker',
              unlockChallengeB64u: 'unlock-b64u',
              clientUnlockPublicKeyB64u: 'unlock-pub',
              unlockSignatureB64u: 'unlock-sig',
              thresholdEd25519PrfFirstB64u: 'email-otp-ed25519-prf-worker',
            },
            bootstrap,
          };
        }
        if (request.type === 'sealEmailOtpWarmSessionMaterial') {
          return {
            ok: true,
            sealedSecretB64u: 'sealed-session-secret-list-status',
            keyVersion: 'seal-kv-list-status',
            remainingUses: 9,
            expiresAtMs: Date.now() + 60_000,
          };
        }
        if (request.type === 'getEmailOtpWarmSessionStatus') {
          return workerMaterialAvailable
            ? { ok: true, remainingUses: 8, expiresAtMs: Date.now() + 60_000 }
            : {
                ok: false,
                code: 'not_found',
                message: 'Email OTP worker was reloaded',
              };
        }
        if (request.type === 'rehydrateEmailOtpEcdsaWarmSessionMaterial') {
          workerMaterialAvailable = true;
          return {
            ok: true,
            bootstrap,
            remainingUses: 8,
            expiresAtMs: Date.now() + 60_000,
          };
        }
        throw new Error(`unexpected worker request: ${request.type}`);
      },
      writeSigningSessionSealedRecord: async (record) => {
        sealedRecords.set(record.thresholdSessionId, {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-sealed-list-status',
          authMethod: record.authMethod || 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: record.walletSigningSessionId,
          thresholdSessionIds: record.thresholdSessionIds,
          sealedSecretB64u: record.sealedSecretB64u,
          curve: record.curve,
          walletId: record.walletId,
          userId: record.userId,
          signingRootId: record.signingRootId,
          signingRootVersion: record.signingRootVersion,
          relayerUrl: record.relayerUrl,
          keyVersion: record.keyVersion,
          shamirPrimeB64u: record.shamirPrimeB64u,
          issuedAtMs: Date.now(),
          expiresAtMs: record.expiresAtMs,
          remainingUses: record.remainingUses,
          updatedAtMs: record.updatedAtMs || Date.now(),
        });
      },
      readSigningSessionSealedRecord: async (thresholdSessionId) =>
        sealedRecords.get(thresholdSessionId) || null,
      acquireSigningSessionRestoreLease: async ({ thresholdSessionId }) => ({
        v: 1,
        thresholdSessionId,
        walletSigningSessionId,
        ownerId: 'unit-test',
        attemptId: 'unit-test-attempt',
        startedAtMs: Date.now(),
        expiresAtMs: Date.now() + 15_000,
      }),
      releaseSigningSessionRestoreLease: async () => undefined,
    });
    const engineAny = engine as any;
    engineAny.tatchiPasskeyConfigs.signing.sessionPersistenceMode = 'sealed_refresh_v1';
    engineAny.orchestrationDeps.signingSessionCoordinator = new SigningSessionCoordinator({
      touchConfirm: {},
      listThresholdEcdsaSessionRecordsForLookup: ({ nearAccountId, chain }) =>
        engineAny.listThresholdEcdsaSessionRecordsForLookup({ nearAccountId, chain }),
      getEmailOtpWarmSessionStatus: async () =>
        workerMaterialAvailable
          ? { ok: true, remainingUses: 8, expiresAtMs: Date.now() + 60_000 }
          : {
              ok: false,
              code: 'not_found',
              message: 'Email OTP worker was reloaded',
            },
    });

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'tempo',
      challengeId: 'challenge-worker',
      otpCode: '123456',
      routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
      sessionId: ecdsaSessionId,
      walletSigningSessionId,
    } as any);
    (SigningEngine.prototype as any).upsertThresholdEcdsaSessionFromBootstrap.call(engineAny, {
      nearAccountId: walletId,
      chain: 'tempo',
      bootstrap,
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });

    workerMaterialAvailable = false;
    const statuses = await engine.listWarmThresholdEcdsaSessionStatuses(walletId, 'tempo');

    expect(statuses).toHaveLength(1);
    expect(statuses[0]).toMatchObject({
      sessionId: ecdsaSessionId,
      status: 'active',
      authMethod: 'email_otp',
      retention: 'session',
      remainingUses: 8,
    });
    expect(workerRequests).toContain('rehydrateEmailOtpEcdsaWarmSessionMaterial');
  });

  test('transaction-specific ECDSA Email OTP bootstrap forwards operation to worker verify', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            challengeId: 'challenge-worker',
            enrollmentSealKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            clientUnlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
          },
          bootstrap: makeWorkerBootstrap({ walletId, sessionId: 'ecdsa-session-worker' }),
        };
      },
    });

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      challengeId: 'sign-challenge',
      otpCode: '123456',
      operation: 'transaction_sign' as any,
      appSessionJwt: 'app-session-jwt',
      routeAuth: { kind: 'app_session', jwt: 'app-session-jwt' },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload).toMatchObject({
      challengeId: 'sign-challenge',
      routePlan: {
        routeFamily: 'login',
        authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
        operation: 'transaction_sign',
      },
    });
  });

  test('transaction ECDSA Email OTP reauth uses signing-session auth instead of app-session fallback', async () => {
    const walletId = 'alice.testnet';
    const internalLoginRequests: Array<Record<string, any>> = [];
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    engineAny.getThresholdEcdsaKeyRefForLookup = () =>
      makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef;
    const emailOtpSessions = installEmailOtpSessionsFixture(engineAny);
    emailOtpSessions.loginWithEcdsaCapabilityInternal = async (input: Record<string, any>) => {
      internalLoginRequests.push(input);
    };

    await emailOtpSessions.loginWithEcdsaCapabilityForSigning({
      nearAccountId: walletId,
      chain: 'evm',
      challengeId: 'sign-challenge',
      otpCode: '123456',
      authLane: {
        kind: 'signing_session',
        jwt: 'threshold-session-jwt-stale',
        thresholdSessionId: 'ecdsa-session-worker',
        curve: 'ecdsa',
        chain: 'evm',
      },
      record: {
        nearAccountId: walletId,
        chain: 'evm',
        source: 'email_otp',
        ecdsaThresholdKeyId: 'ecdsa-key-worker',
        thresholdSessionId: 'ecdsa-session-worker',
        thresholdSessionKind: 'jwt',
        thresholdSessionJwt: 'threshold-session-jwt-stale',
        participantIds: [1, 2],
      },
    });

    expect(internalLoginRequests).toEqual([
      expect.objectContaining({
        operation: 'transaction_sign',
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: 'threshold-session-jwt-stale',
            thresholdSessionId: 'ecdsa-session-worker',
            curve: 'ecdsa',
            chain: 'evm',
          },
          operation: 'transaction_sign',
        },
      }),
    ]);
    expect(internalLoginRequests[0]).not.toHaveProperty('sessionId');
  });

  test('Email OTP ECDSA sealed restore rejects cross-curve sealed records before worker restore', async () => {
    let workerCalls = 0;
    const engine = makeBareSigningEngine();
    const emailOtpSessions = installEmailOtpSessionsFixture(engine as any, {
      requestWorkerOperation: async () => {
        workerCalls += 1;
        throw new Error('worker restore should not run');
      },
    });

    await expect(
      emailOtpSessions.rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord({
        sealedRecord: {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-curve-mismatch',
          authMethod: 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: 'wallet-signing-session-curve-mismatch',
          thresholdSessionIds: { ecdsa: 'ecdsa-curve-mismatch-session' },
          sealedSecretB64u: 'sealed-session-secret',
          curve: 'ed25519',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 120_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        },
        ecdsaRecord: {
          nearAccountId: 'curve-mismatch.testnet',
          chain: 'evm',
          source: 'email_otp',
          thresholdSessionId: 'ecdsa-curve-mismatch-session',
          thresholdSessionKind: 'jwt',
          thresholdSessionJwt: 'jwt:ecdsa-curve-mismatch-session',
          walletSigningSessionId: 'wallet-signing-session-curve-mismatch',
          relayerUrl: 'https://relay.example',
          ecdsaThresholdKeyId: 'ecdsa-key-curve-mismatch',
          relayerKeyId: 'relayer-key-curve-mismatch',
          participantIds: [1, 2],
          signingSessionSealShamirPrimeB64u: 'prime-b64u',
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
        },
      }),
    ).rejects.toThrow('Email OTP sealed refresh curve mismatch');
    expect(workerCalls).toBe(0);
  });

  test('transaction ECDSA Email OTP reauth provisions a one-use transaction session', async () => {
    const walletId = 'alice.testnet';
    const internalLoginRequests: Array<Record<string, any>> = [];
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    engineAny.tatchiPasskeyConfigs = {
      network: { relayer: { url: 'https://relay.example' } },
      signing: {
        emailOtp: { authPolicy: 'session' },
        sessionDefaults: { remainingUses: 11 },
        sessionSeal: { shamirPrimeB64u: 'prime-b64u' },
      },
    };
    engineAny.getThresholdEcdsaKeyRefForLookup = () =>
      makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef;
    const emailOtpSessions = installEmailOtpSessionsFixture(engineAny);
    emailOtpSessions.loginWithEcdsaCapabilityInternal = async (input: Record<string, any>) => {
      internalLoginRequests.push(input);
    };

    await emailOtpSessions.loginWithEcdsaCapabilityForSigning({
      nearAccountId: walletId,
      chain: 'tempo',
      challengeId: 'sign-challenge',
      otpCode: '123456',
      authLane: {
        kind: 'signing_session',
        jwt: 'threshold-session-jwt-stale',
        thresholdSessionId: 'ecdsa-session-worker',
        curve: 'ecdsa',
        chain: 'tempo',
      },
      record: {
        nearAccountId: walletId,
        chain: 'tempo',
        source: 'email_otp',
        ecdsaThresholdKeyId: 'ecdsa-key-worker',
        thresholdSessionId: 'ecdsa-session-worker',
        thresholdSessionKind: 'jwt',
        thresholdSessionJwt: 'threshold-session-jwt-stale',
        participantIds: [1, 2],
        remainingUses: 0,
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
      },
    });

    expect(internalLoginRequests).toHaveLength(1);
    expect(internalLoginRequests[0]).toMatchObject({
      chain: 'tempo',
      operation: 'transaction_sign',
      emailOtpAuthPolicy: 'per_operation',
      emailOtpAuthReason: 'sign',
      remainingUses: 1,
      routePlan: {
        routeFamily: 'signing_session',
        authLane: {
          kind: 'signing_session',
          jwt: 'threshold-session-jwt-stale',
          thresholdSessionId: 'ecdsa-session-worker',
          curve: 'ecdsa',
          chain: 'tempo',
        },
        operation: 'transaction_sign',
      },
    });
  });

  test('Email OTP ECDSA bootstrap accepts threshold-session route auth for JWT sessions', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            challengeId: 'challenge-worker',
            enrollmentSealKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            clientUnlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
          },
          bootstrap: makeWorkerBootstrap({ walletId }),
        };
      },
    });
    const thresholdSessionJwt = makeThresholdSessionJwt('threshold_ecdsa_session_v1');

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      challengeId: 'sign-challenge',
      otpCode: '123456',
      operation: 'transaction_sign' as any,
      routeAuth: { kind: 'threshold_session', jwt: thresholdSessionJwt },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload.routePlan).toMatchObject({
      routeFamily: 'signing_session',
      authLane: {
        kind: 'signing_session',
        jwt: thresholdSessionJwt,
        curve: 'ecdsa',
      },
      operation: 'transaction_sign',
    });
  });

  test('Email OTP Ed25519 provisioning reuses app-session route auth when appSessionJwt is omitted', async () => {
    const walletId = 'alice.testnet';
    const appSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, ed25519ProvisionCalls } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            challengeId: 'challenge-worker',
            enrollmentSealKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            clientUnlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
            thresholdEd25519PrfFirstB64u: 'email-otp-ed25519-prf-worker',
          },
          bootstrap: makeWorkerBootstrap({ walletId, sessionId: 'ecdsa-session-worker' }),
        };
      },
    });

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      otpCode: '123456',
      routeAuth: { kind: 'app_session', jwt: appSessionJwt },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload.routePlan).toEqual({
      routeFamily: 'login',
      authLane: {
        kind: 'app_session',
        jwt: appSessionJwt,
      },
      operation: 'wallet_unlock',
    });
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: walletId,
      appSessionJwt,
      prfFirstB64u: 'email-otp-ed25519-prf-worker',
    });
  });

  test('Email OTP enrollment Ed25519 provisioning reuses app-session route auth when appSessionJwt is omitted', async () => {
    const walletId = 'alice.testnet';
    const appSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, ed25519ProvisionCalls } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('enrollEmailOtpWalletAndBootstrapEcdsaSession');
        return {
          enrollment: {
            thresholdEcdsaClientVerifyingShareB64u: 'verifier-worker',
            thresholdEd25519PrfFirstB64u: 'email-otp-ed25519-prf-worker',
            challengeId: 'enroll-otp-1',
            otpChannel: 'email_otp',
            enrollmentSealKeyVersion: 'email-otp-kv-1',
            clientUnlockPublicKeyB64u: 'unlock-public-key-worker',
            unlockKeyVersion: 'email-otp-unlock-v1',
          },
          bootstrap: makeWorkerBootstrap({ walletId, sessionId: 'ecdsa-session-worker' }),
        };
      },
    });

    await engine.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      otpCode: '123456',
      routeAuth: { kind: 'app_session', jwt: appSessionJwt },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload.routePlan).toEqual({
      routeFamily: 'registration',
      authLane: {
        kind: 'app_session',
        jwt: appSessionJwt,
      },
      operation: 'wallet_unlock',
    });
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: walletId,
      appSessionJwt,
      prfFirstB64u: 'email-otp-ed25519-prf-worker',
    });
  });

  test('Email OTP bootstrap does not use passkey sealed-refresh persistence', async () => {
    const walletId = 'alice.testnet';
    const sealPersistCalls: unknown[] = [];
    const { engine } = makeEngine({
      touchConfirm: {
        sealAndPersistWarmSessionMaterial: async (args: unknown) => {
          sealPersistCalls.push(args);
          return {
            ok: false,
            code: 'not_found',
            message: 'Warm-session material is not available for threshold session',
          };
        },
      },
      requestWorkerOperation: async ({ kind, request }) => {
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            challengeId: 'challenge-worker',
            enrollmentSealKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            clientUnlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
          },
          bootstrap: makeWorkerBootstrap({ walletId, sessionId: 'ecdsa-session-worker' }),
        };
      },
    });

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      otpCode: '123456',
      appSessionJwt: 'app-session-jwt',
      routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(sealPersistCalls).toEqual([]);
  });

  test('fails when Email OTP bootstrap does not reach warm-session ready state', async () => {
    const walletId = 'alice.testnet';
    const { engine } = makeEngine({
      warmReady: false,
      requestWorkerOperation: async ({ request }) => {
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            challengeId: 'challenge-worker',
            enrollmentSealKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            clientUnlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
          },
          bootstrap: makeWorkerBootstrap({ walletId }),
        };
      },
    });

    await expect(
      engine.loginWithEmailOtpEcdsaCapabilityInternal({
        nearAccountId: walletId,
        chain: 'evm',
        otpCode: '123456',
        appSessionJwt: 'app-session-jwt',
        routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-1',
      }),
    ).rejects.toThrow('did not reach warm-session ready state');
  });

  test('exports ECDSA with fresh Email OTP step-up for Email OTP sessions', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const confirmationTypes: string[] = [];
    const challengeRequests: Array<Record<string, unknown>> = [];
    const workerRequests: Array<Record<string, any>> = [];
    const consumedSessions: Array<Record<string, unknown>> = [];
    const restoredRecords: Array<Record<string, unknown>> = [];
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const keyRef = makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef;
    const originalFetch = globalThis.fetch;
    const originalThresholdSessionJwt = makeThresholdSessionJwt('threshold_ecdsa_session_v1');
    let ecdsaRecord: Record<string, unknown> = {
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      thresholdSessionId: 'ecdsa-session-worker',
      thresholdSessionKind: 'jwt',
      thresholdSessionJwt: originalThresholdSessionJwt,
      emailOtpAuthContext: {
        authSubjectId: 'google:117142622123955425762',
      },
    };

    engineAny.theme = 'dark';
    engineAny.getRpId = () => 'example.localhost';
    engineAny.getThresholdEcdsaSessionRecordForLookup = () => ecdsaRecord;
    engineAny.listThresholdEcdsaSessionRecordsForLookup = () => [ecdsaRecord];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      refreshRequests.push({
        url: String(input),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ ok: true, jwt: 'unexpected-refresh' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    installEmailOtpSessionsFixture(engineAny, {
      requestWorkerOperation: async (input: { kind: string; request: any }) => {
        workerRequests.push(input);
        if (input.request?.type === 'requestEmailOtpChallenge') {
          challengeRequests.push(input.request.payload);
          return { challengeId: 'export-challenge', emailHint: 'alice@example.test' };
        }
        return {
          publicKeyHex: '02'.padEnd(66, '1'),
          privateKeyHex: 'ab'.repeat(32),
          ethereumAddress: '0x1111111111111111111111111111111111111111',
        };
      },
    });
    engineAny.orchestrationDeps = {
      thresholdSessionActivationDeps: {
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async (input: { kind: string; request: any }) => {
            workerRequests.push(input);
            return {
              publicKeyHex: '02'.padEnd(66, '1'),
              privateKeyHex: 'ab'.repeat(32),
              ethereumAddress: '0x1111111111111111111111111111111111111111',
            };
          },
        }),
      },
    };
    engineAny.markThresholdEcdsaEmailOtpSessionConsumedForAccount = (
      input: Record<string, unknown>,
    ) => {
      consumedSessions.push(input);
    };
    engineAny.upsertStoredThresholdEcdsaSessionRecord = (record: Record<string, unknown>) => {
      restoredRecords.push(record);
      ecdsaRecord = record;
      return record;
    };
    engineAny.touchConfirm = {
      requestUserConfirmation: async (request: any) => {
        confirmationTypes.push(String(request.type));
        if (request.type === 'signIntentDigest') {
          expect(request.payload.signingAuthPlan).toMatchObject({
            kind: 'emailOtpReauth',
            method: 'email_otp',
            emailOtpPrompt: {
              challengeId: 'export-challenge',
              title: 'Enter email code to export',
            },
          });
          return {
            confirmed: true,
            otpCode: '123456',
            emailOtpChallengeId: 'export-challenge',
          };
        }
        return { confirmed: true };
      },
    };

    try {
      await expect(
        engineAny.exportThresholdEcdsaKeyWithAuthorization({
          nearAccountId: walletId,
          chain: 'evm',
          keyRef,
          options: {},
        }),
      ).resolves.toEqual({
        accountId: walletId,
        exportedSchemes: ['secp256k1'],
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(refreshRequests).toEqual([]);
    expect(challengeRequests).toEqual([
      {
        relayUrl: 'https://relay.example',
        walletId,
        routePlan: {
          routeFamily: 'signing_session',
          authLane: {
            kind: 'signing_session',
            jwt: originalThresholdSessionJwt,
            thresholdSessionId: 'ecdsa-session-worker',
            curve: 'ecdsa',
            chain: 'evm',
          },
          operation: 'export_key',
        },
        otpChannel: 'email_otp',
      },
    ]);
    expect(workerRequests).toEqual([
      expect.objectContaining({
        kind: 'emailOtp',
        request: expect.objectContaining({
          type: 'requestEmailOtpChallenge',
        }),
      }),
      expect.objectContaining({
        kind: 'emailOtp',
        request: expect.objectContaining({
          type: 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
          payload: expect.objectContaining({
            walletId,
            userId: 'google:117142622123955425762',
            challengeId: 'export-challenge',
            otpCode: '123456',
            rpId: 'example.localhost',
            thresholdSessionJwt: originalThresholdSessionJwt,
            ecdsaThresholdKeyId: 'ecdsa-key-worker',
            chain: 'evm',
            routePlan: expect.objectContaining({
              routeFamily: 'signing_session',
              operation: 'export_key',
            }),
          }),
        }),
      }),
    ]);
    expect(consumedSessions).toEqual([]);
    expect(restoredRecords).toEqual([]);
    expect(confirmationTypes).toEqual(['signIntentDigest', 'showSecurePrivateKeyUi']);
  });

  test('exports ECDSA with Email OTP app-session fallback bound to existing key metadata', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const exportCalls: Array<Record<string, unknown>> = [];
    const ecdsaRecord = {
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-existing-email-key',
      participantIds: [1, 2],
      thresholdSessionId: 'stale-session',
      thresholdSessionKind: 'jwt',
    };

    engineAny.getRpId = () => 'example.localhost';
    engineAny.listThresholdEcdsaSessionRecordsForLookup = () => [ecdsaRecord];
    engineAny.showThresholdEcdsaExportViewer = async () => undefined;
    engineAny.emailOtpSessions = {
      requestExportAuthorization: async (args: Record<string, unknown>) => {
        expect(args).toMatchObject({
          nearAccountId: walletId,
          chain: 'evm',
          curve: 'ecdsa',
        });
        expect(args).not.toHaveProperty('authLane');
        return {
          challengeId: 'export-challenge',
          otpCode: '123456',
        };
      },
      bootstrapAndExportEcdsaKeyWithAuthorization: async (args: Record<string, unknown>) => {
        exportCalls.push(args);
        return {
          publicKeyHex: '02'.padEnd(66, '1'),
          privateKeyHex: 'ab'.repeat(32),
          ethereumAddress: '0x1111111111111111111111111111111111111111',
        };
      },
    };

    await expect(
      engineAny.exportThresholdEcdsaKeyWithAuthorization({
        nearAccountId: walletId,
        chain: 'evm',
        options: {},
      }),
    ).resolves.toEqual({
      accountId: walletId,
      exportedSchemes: ['secp256k1'],
    });

    expect(exportCalls).toEqual([
      {
        nearAccountId: walletId,
        chain: 'evm',
        challengeId: 'export-challenge',
        otpCode: '123456',
        ecdsaThresholdKeyId: 'ecdsa-existing-email-key',
        participantIds: [1, 2],
      },
    ]);
  });

  test('does not consume Email OTP ECDSA signing session when export viewer fails', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const consumedSessions: Array<Record<string, unknown>> = [];
    const restoredRecords: Array<Record<string, unknown>> = [];
    const originalFetch = globalThis.fetch;
    const keyRef = makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef;
    const originalThresholdSessionJwt = makeUnsignedJwt({
      kind: 'threshold_ecdsa_session_v1',
      sub: walletId,
      walletId,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    let ecdsaRecord: Record<string, unknown> = {
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      thresholdSessionId: 'ecdsa-session-worker',
      thresholdSessionKind: 'jwt',
      thresholdSessionJwt: originalThresholdSessionJwt,
    };

    engineAny.theme = 'dark';
    engineAny.getRpId = () => 'example.localhost';
    engineAny.getThresholdEcdsaSessionRecordForLookup = () => ecdsaRecord;
    engineAny.listThresholdEcdsaSessionRecordsForLookup = () => [ecdsaRecord];
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ ok: true, jwt: 'unexpected-refresh' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch;
    installEmailOtpSessionsFixture(engineAny, {
      requestWorkerOperation: async (input: { kind: string; request: any }) => {
        if (input.request?.type === 'requestEmailOtpChallenge') {
          return { challengeId: 'export-challenge', emailHint: 'alice@example.test' };
        }
        return {
          publicKeyHex: '02'.padEnd(66, '1'),
          privateKeyHex: 'ab'.repeat(32),
          ethereumAddress: '0x1111111111111111111111111111111111111111',
        };
      },
    });
    engineAny.orchestrationDeps = {
      thresholdSessionActivationDeps: {
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async () => ({
            publicKeyHex: '02'.padEnd(66, '1'),
            privateKeyHex: 'ab'.repeat(32),
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          }),
        }),
      },
    };
    engineAny.showThresholdEcdsaExportViewer = async () => {
      throw new Error('viewer failed');
    };
    engineAny.markThresholdEcdsaEmailOtpSessionConsumedForAccount = (
      input: Record<string, unknown>,
    ) => {
      consumedSessions.push(input);
    };
    engineAny.upsertStoredThresholdEcdsaSessionRecord = (record: Record<string, unknown>) => {
      restoredRecords.push(record);
      ecdsaRecord = record;
      return record;
    };
    engineAny.touchConfirm = {
      requestUserConfirmation: async () => ({
        confirmed: true,
        otpCode: '123456',
        emailOtpChallengeId: 'export-challenge',
      }),
    };

    try {
      await expect(
        engineAny.exportThresholdEcdsaKeyWithAuthorization({
          nearAccountId: walletId,
          chain: 'evm',
          keyRef,
          options: {},
        }),
      ).rejects.toThrow('viewer failed');
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(consumedSessions).toEqual([]);
    expect(restoredRecords).toEqual([]);
    expect(ecdsaRecord).toMatchObject({
      thresholdSessionId: 'ecdsa-session-worker',
      thresholdSessionJwt: originalThresholdSessionJwt,
    });
  });

  test('discard cached threshold-session JWT before Email OTP app-session refresh', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
    const emailOtpSessions = installEmailOtpSessionsFixture(engineAny);
    emailOtpSessions.appSessionJwtByAccount = new Map([
      [
        walletId,
        makeUnsignedJwt({
          kind: 'threshold_ecdsa_session_v1',
          sub: walletId,
          walletId,
          sessionId: 'ecdsa-threshold-session',
        }),
      ],
    ]);
    const refreshedAppSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      sub: walletId,
      appSessionVersion: 'app-session-version-1',
    });
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      refreshRequests.push({
        url: String(input),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ ok: true, jwt: refreshedAppSessionJwt }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    try {
      await expect(
        emailOtpSessions.resolveAppSessionJwt({
          nearAccountId: walletId,
          relayUrl: 'https://relay.example',
        }),
      ).resolves.toBe(refreshedAppSessionJwt);
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(refreshRequests).toEqual([
      {
        url: 'https://relay.example/session/refresh',
        body: { session_kind: 'jwt' },
      },
    ]);
    expect(emailOtpSessions.appSessionJwtByAccount.get(walletId)).toBe(refreshedAppSessionJwt);
  });

  test('uses unexpired cached app-session JWT for Email OTP login-route challenge', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
    const emailOtpSessions = installEmailOtpSessionsFixture(engineAny);
    const cachedAppSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      sub: walletId,
      appSessionVersion: 'stale-app-session-version',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    emailOtpSessions.appSessionJwtByAccount = new Map([[walletId, cachedAppSessionJwt]]);
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      refreshRequests.push({
        url: String(input),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ ok: true, jwt: 'unexpected-refresh' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      await expect(
        emailOtpSessions.resolveAppSessionJwt({
          nearAccountId: walletId,
          relayUrl: 'https://relay.example',
        }),
      ).resolves.toBe(cachedAppSessionJwt);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(refreshRequests).toEqual([]);
    expect(emailOtpSessions.appSessionJwtByAccount.get(walletId)).toBe(cachedAppSessionJwt);
  });

  test('does not restore app-session JWT from sessionStorage after reload', async () => {
    const walletId = 'alice.testnet';
    const firstEngine = makeBareSigningEngine();
    const secondEngine = makeBareSigningEngine();
    const firstEmailOtpSessions = installEmailOtpSessionsFixture(firstEngine as any);
    const secondEmailOtpSessions = installEmailOtpSessionsFixture(secondEngine as any);
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
    const cachedAppSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      sub: walletId,
      appSessionVersion: 'same-tab-app-session-version',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const refreshedAppSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      sub: walletId,
      appSessionVersion: 'fresh-app-session-version',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const sessionStorageMap = new Map<string, string>();
    const originalSessionStorageDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'sessionStorage',
    );
    Object.defineProperty(globalThis, 'sessionStorage', {
      configurable: true,
      value: {
        getItem: (key: string) => sessionStorageMap.get(key) ?? null,
        setItem: (key: string, value: string) => {
          sessionStorageMap.set(key, String(value));
        },
        removeItem: (key: string) => {
          sessionStorageMap.delete(key);
        },
        clear: () => {
          sessionStorageMap.clear();
        },
      },
    });

    try {
      firstEmailOtpSessions.rememberAppSessionJwt({
        nearAccountId: walletId,
        appSessionJwt: cachedAppSessionJwt,
      });
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        refreshRequests.push({
          url: String(input),
          body: init?.body ? JSON.parse(String(init.body)) : null,
        });
        return new Response(JSON.stringify({ ok: true, jwt: refreshedAppSessionJwt }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      await expect(
        secondEmailOtpSessions.resolveAppSessionJwt({
          nearAccountId: walletId,
          relayUrl: 'https://relay.example',
        }),
      ).resolves.toBe(refreshedAppSessionJwt);
    } finally {
      globalThis.fetch = originalFetch;
      if (originalSessionStorageDescriptor) {
        Object.defineProperty(globalThis, 'sessionStorage', originalSessionStorageDescriptor);
      } else {
        Reflect.deleteProperty(globalThis, 'sessionStorage');
      }
    }

    expect(refreshRequests).toEqual([
      {
        url: 'https://relay.example/session/refresh',
        body: { session_kind: 'jwt' },
      },
    ]);
    expect(sessionStorageMap.size).toBe(0);
    expect(secondEmailOtpSessions.appSessionJwtByAccount.get(walletId)).toBe(
      refreshedAppSessionJwt,
    );
  });

  test('refreshes expired cached app-session JWT before Email OTP login-route challenge', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
    const emailOtpSessions = installEmailOtpSessionsFixture(engineAny);
    const cachedAppSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      sub: walletId,
      appSessionVersion: 'expired-app-session-version',
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    const refreshedAppSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      sub: walletId,
      appSessionVersion: 'fresh-app-session-version',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    emailOtpSessions.appSessionJwtByAccount = new Map([[walletId, cachedAppSessionJwt]]);
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      refreshRequests.push({
        url: String(input),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ ok: true, jwt: refreshedAppSessionJwt }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      await expect(
        emailOtpSessions.resolveAppSessionJwt({
          nearAccountId: walletId,
          relayUrl: 'https://relay.example',
        }),
      ).resolves.toBe(refreshedAppSessionJwt);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(refreshRequests).toEqual([
      {
        url: 'https://relay.example/session/refresh',
        body: { session_kind: 'jwt' },
      },
    ]);
    expect(emailOtpSessions.appSessionJwtByAccount.get(walletId)).toBe(refreshedAppSessionJwt);
  });

  test('exports NEAR Ed25519 with fresh Email OTP step-up for Email OTP sessions', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const expectedPublicKey = 'ed25519:email-otp-public-key';
    const confirmationTypes: string[] = [];
    const challengeRequests: Array<Record<string, unknown>> = [];
    const exportRecoveryRequests: Array<Record<string, any>> = [];
    const hssExportRequests: Array<Record<string, unknown>> = [];
    const consumedSessions: Array<Record<string, unknown>> = [];
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
    const originalThresholdSessionJwt = makeThresholdSessionJwt('threshold_ed25519_session_v1');

    engineAny.theme = 'dark';
    engineAny.orchestrationDeps = {
      indexedDB: {
        clientDB: {
          getLastProfileState: async () => ({ profileId: 'profile-1', activeSignerSlot: 1 }),
          resolveProfileAccountContext: async (accountRef: {
            chainIdKey: string;
            accountAddress: string;
          }) => ({ profileId: 'profile-1', accountRef }),
        },
        accountKeyMaterialDB: {
          getKeyMaterial: async () => ({
            profileId: 'profile-1',
            signerSlot: 1,
            chainIdKey: 'near:testnet',
            keyKind: 'threshold_share_v1',
            algorithm: 'ed25519',
            publicKey: expectedPublicKey,
            payload: {
              relayerKeyId: 'ed25519-relayer-key',
              keyVersion: 'threshold-ed25519-hss-v1',
            },
            timestamp: Date.now(),
            schemaVersion: 1,
          }),
          storeKeyMaterial: async () => undefined,
        },
      },
      thresholdSessionActivationDeps: {
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async () => {
            throw new Error('worker artifact builder should be stubbed in this unit test');
          },
        }),
      },
    };
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      refreshRequests.push({
        url: String(input),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ ok: true, jwt: 'unexpected-refresh' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    installEmailOtpSessionsFixture(engineAny, {
      requestWorkerOperation: async (input: { kind: string; request: any }) => {
        if (input.request?.type === 'requestEmailOtpChallenge') {
          challengeRequests.push(input.request.payload);
          return { challengeId: 'export-challenge', emailHint: 'alice@example.test' };
        }
        exportRecoveryRequests.push(input);
        return {
          challengeId: 'export-challenge',
          thresholdEd25519PrfFirstB64u: 'export-prf-first',
        };
      },
    });
    engineAny.runNearEd25519OptionAHssExport = async (input: Record<string, unknown>) => {
      hssExportRequests.push(input);
      return {
        preparedSession: { sessionId: 'prepared-session' },
        finalizedReport: { sessionId: 'finalized-report' },
      };
    };
    engineAny.buildThresholdEd25519SeedExportArtifactFromHssReport = async () => ({
      success: true,
      artifact: {
        publicKey: expectedPublicKey,
        privateKey: 'ed25519-private-key',
        seedB64u: 'seed-b64u',
      },
    });
    engineAny.markThresholdEd25519EmailOtpSessionConsumedForAccount = (
      input: Record<string, unknown>,
    ) => {
      consumedSessions.push(input);
    };
    engineAny.touchConfirm = {
      requestUserConfirmation: async (request: any) => {
        confirmationTypes.push(String(request.type));
        if (request.type === 'signIntentDigest') {
          expect(request.payload.signingAuthPlan).toMatchObject({
            kind: 'emailOtpReauth',
            method: 'email_otp',
            emailOtpPrompt: {
              challengeId: 'export-challenge',
              title: 'Enter email code to export',
            },
          });
          return {
            confirmed: true,
            otpCode: '123456',
            emailOtpChallengeId: 'export-challenge',
          };
        }
        return { confirmed: true };
      },
    };

    clearAllStoredThresholdEd25519SessionRecords();
    try {
      persistWarmSessionEd25519Capability({
        nearAccountId: walletId,
        rpId: 'example.localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'ed25519-relayer-key',
        runtimePolicyScope: {
          orgId: 'org_local',
          projectId: 'proj_local',
          envId: 'dev',
          signingRootVersion: 'v1',
        },
        participantIds: [1, 2],
        sessionId: 'ed25519-email-otp-export-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 7,
        jwt: originalThresholdSessionJwt,
        xClientBaseB64u: 'x-client-base-worker',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });

      await expect(
        engine.exportKeypairWithUI(walletId, {
          chain: 'near',
          variant: 'drawer',
        }),
      ).resolves.toEqual({
        accountId: walletId,
        exportedSchemes: ['ed25519'],
      });
      expect(challengeRequests).toEqual([
        {
          relayUrl: 'https://relay.example',
          walletId,
          routePlan: {
            routeFamily: 'signing_session',
            authLane: {
              kind: 'signing_session',
              jwt: originalThresholdSessionJwt,
              thresholdSessionId: 'ed25519-email-otp-export-session',
              curve: 'ed25519',
            },
            operation: 'export_key',
          },
          otpChannel: 'email_otp',
        },
      ]);
      expect(refreshRequests).toEqual([]);
      expect(exportRecoveryRequests).toEqual([
        expect.objectContaining({
          kind: 'emailOtp',
          request: expect.objectContaining({
            type: 'recoverEmailOtpEd25519ExportPrfFirst',
            payload: expect.objectContaining({
              walletId,
              challengeId: 'export-challenge',
              otpCode: '123456',
              routePlan: expect.objectContaining({
                routeFamily: 'signing_session',
                operation: 'export_key',
              }),
            }),
          }),
        }),
      ]);
      expect(hssExportRequests).toEqual([
        expect.objectContaining({
          signingRootId: 'proj_local:dev',
          nearAccountId: walletId,
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          thresholdSessionId: 'ed25519-email-otp-export-session',
          thresholdSessionJwt: originalThresholdSessionJwt,
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'ed25519-relayer-key',
          prfFirstB64u: 'export-prf-first',
        }),
      ]);
      expect(consumedSessions).toEqual([]);
      expect(getStoredThresholdEd25519SessionRecordForAccount(walletId)).toMatchObject({
        thresholdSessionId: 'ed25519-email-otp-export-session',
        thresholdSessionJwt: originalThresholdSessionJwt,
        xClientBaseB64u: 'x-client-base-worker',
        remainingUses: 7,
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
        },
      });
      expect(confirmationTypes).toEqual(['signIntentDigest', 'showSecurePrivateKeyUi']);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('keeps ECDSA export on WebAuthn authorization for passkey sessions', async () => {
    const walletId = 'alice.testnet';
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const confirmationTypes: string[] = [];
    const keyRef = {
      ...makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef,
      ecdsaHssExportArtifact: {
        publicKeyHex: '02'.padEnd(66, '1'),
        privateKeyHex: 'ab'.repeat(32),
        ethereumAddress: '0x1111111111111111111111111111111111111111',
      },
    };

    engineAny.theme = 'dark';
    engineAny.getRpId = () => 'example.localhost';
    engineAny.getThresholdEcdsaSessionRecordForLookup = () => ({
      nearAccountId: walletId,
      chain: 'evm',
      thresholdSessionId: keyRef.thresholdSessionId,
      source: 'login',
    });
    engineAny.clearThresholdEcdsaSigningArtifactsForLane = () => undefined;
    engineAny.clearThresholdEcdsaSessionRecordForLane = () => undefined;
    engineAny.touchConfirm = {
      getWarmSessionStatusBatch: async () => ({ sessions: {} }),
      requestUserConfirmation: async (request: any) => {
        confirmationTypes.push(String(request.type));
        if (request.type === 'decryptPrivateKeyWithPrf') {
          return {
            confirmed: true,
            credential: {
              clientExtensionResults: {
                prf: {
                  results: {
                    first: 'prf-first-b64u',
                  },
                },
              },
            },
          };
        }
        return { confirmed: true };
      },
    };

    await expect(
      engineAny.exportThresholdEcdsaKeyWithAuthorization({
        nearAccountId: walletId,
        chain: 'evm',
        keyRef,
        options: {},
      }),
    ).resolves.toEqual({
      accountId: walletId,
      exportedSchemes: ['secp256k1'],
    });
    expect(confirmationTypes).toEqual(['decryptPrivateKeyWithPrf', 'showSecurePrivateKeyUi']);
  });

  test('prefers Email OTP warm-session status and claims over the passkey runtime', async () => {
    const engine = makeBareSigningEngine();
    const engineAny = engine as any;
    const baseStatusCalls: string[] = [];
    const emailOtpStatusCalls: string[] = [];
    const baseClaimCalls: string[] = [];
    const emailOtpClaimCalls: string[] = [];

    const base = {
      getWarmSessionStatus: async ({ sessionId }: { sessionId: string }) => {
        baseStatusCalls.push(sessionId);
        return {
          ok: true,
          sessionId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 9,
        };
      },
      getWarmSessionStatuses: async ({ sessionIds }: { sessionIds: string[] }) => ({
        results: sessionIds.map((sessionId) => ({
          sessionId,
          result: {
            ok: true,
            sessionId,
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 9,
          },
        })),
      }),
      claimWarmSessionMaterial: async ({ sessionId }: { sessionId: string }) => {
        baseClaimCalls.push(sessionId);
        return {
          ok: true,
          prfFirstB64u: 'base-prf',
        };
      },
      clearWarmSessionMaterial: async () => undefined,
    };

    engineAny.emailOtpSessions = {
      getWarmSessionStatus: async (sessionId: string) => {
        emailOtpStatusCalls.push(sessionId);
        if (sessionId === 'email-otp-exhausted') {
          return { ok: false, code: 'exhausted', message: 'Email OTP session exhausted' };
        }
        return { ok: false, code: 'not_found', message: 'not found' };
      },
      claimWarmSessionMaterial: async ({ sessionId }: { sessionId: string }) => {
        emailOtpClaimCalls.push(sessionId);
        if (sessionId === 'email-otp-exhausted') {
          return { ok: false, code: 'exhausted', message: 'Email OTP session exhausted' };
        }
        return { ok: false, code: 'not_found', message: 'not found' };
      },
      clearWarmSessionMaterial: async () => undefined,
    };

    const bridge = engineAny.createWarmSessionAwareTouchConfirm(base);

    await expect(
      bridge.getWarmSessionStatus({ sessionId: 'email-otp-exhausted' }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'exhausted',
    });
    await expect(
      bridge.getWarmSessionStatus({ sessionId: 'passkey-session' }),
    ).resolves.toMatchObject({
      ok: true,
      remainingUses: 9,
    });
    await expect(
      bridge.getWarmSessionStatuses({
        sessionIds: ['email-otp-exhausted', 'passkey-session'],
      }),
    ).resolves.toMatchObject({
      results: [
        {
          sessionId: 'email-otp-exhausted',
          result: { ok: false, code: 'exhausted' },
        },
        {
          sessionId: 'passkey-session',
          result: { ok: true, remainingUses: 9 },
        },
      ],
    });
    await expect(
      bridge.claimWarmSessionMaterial({ sessionId: 'email-otp-exhausted', uses: 1 }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'exhausted',
    });
    await expect(
      bridge.claimWarmSessionMaterial({ sessionId: 'passkey-session', uses: 1 }),
    ).resolves.toMatchObject({
      ok: true,
      prfFirstB64u: 'base-prf',
    });

    expect(emailOtpStatusCalls).toEqual([
      'email-otp-exhausted',
      'passkey-session',
      'email-otp-exhausted',
      'passkey-session',
    ]);
    expect(baseStatusCalls).toEqual(['passkey-session']);
    expect(baseClaimCalls).toEqual(['passkey-session']);
    expect(emailOtpClaimCalls).toEqual(['email-otp-exhausted', 'passkey-session']);
  });

  test('uses per-operation Email OTP policy metadata and defaults remainingUses to 1', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, upsertCalls } = makeEngine({
      authPolicy: 'per_operation',
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        return {
          recovery: {
            challengeId: 'challenge-worker',
            enrollmentSealKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            clientUnlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
          },
          bootstrap: makeWorkerBootstrap({ walletId, remainingUses: 1 }),
        };
      },
    });

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      otpCode: '123456',
      emailOtpAuthPolicy: 'per_operation',
      routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
    });

    expect(workerRequests[0]?.request.payload.remainingUses).toBe(1);
    expect(upsertCalls[0]).toMatchObject({
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });
  });
});
