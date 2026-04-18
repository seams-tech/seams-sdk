import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '@shared/utils/encoders';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import { planAccountSignerActivation } from '@/core/indexedDB';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmSessionPersistence';

function makeWorkerBootstrap(args?: {
  walletId?: string;
  sessionId?: string;
  remainingUses?: number;
}) {
  const walletId = args?.walletId || 'alice.testnet';
  const sessionId = args?.sessionId || 'ecdsa-session-worker';
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
      thresholdSessionJwt: 'jwt-worker',
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

function makeEngine(args: {
  requestWorkerOperation: (input: { kind: string; request: any }) => Promise<any>;
  authPolicy?: 'session' | 'per_operation';
  rpId?: string;
  warmReady?: boolean;
  touchConfirm?: Record<string, unknown>;
}) {
  const engine = Object.create(SigningEngine.prototype) as SigningEngine;
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

  return { engine, persistCalls, upsertCalls, readyChecks, ed25519ProvisionCalls };
}

test.describe('SigningEngine Email OTP bootstrap runtime', () => {
  test('generic signer activation planning rejects duplicate same-kind registration', () => {
    expect(() =>
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
            metadata: { signerMaterialFingerprint: 'old-material' },
          },
        ],
        activationPolicy: {
          mode: 'reuse_existing',
          signerId: 'threshold-ed25519:rk-new',
          materialFingerprint: 'new-material',
        },
      }),
    ).toThrow(/Duplicate account registration for threshold-ed25519/);
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
    expect(() =>
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
        })),
        activationPolicy: {
          mode: 'allocate_next_free',
        },
      }),
    ).toThrow('No available account signer slot');
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
          emailOtpKeyVersion: 'email-otp-kv-1',
          unlockPublicKeyB64u: 'unlock-public-key-worker',
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
        appSessionJwt: 'app-session-jwt',
        otpChannel: 'email_otp',
      },
    });
    expect(workerRequests[0]?.request.payload.clientSecret32).toBeInstanceOf(ArrayBuffer);
    expect(result.challengeId).toBe('enroll-1');
    expect(result.emailOtpKeyVersion).toBe('email-otp-kv-1');
    expect(result.unlockKeyVersion).toBe('email-otp-unlock-v1');
  });

  test('Google SSO registration can enroll Email OTP and bootstrap ECDSA with a cookie session', async () => {
    const walletId = 'g-1234567890abcdef1234567890abcdef.testnet';
    const runtimePolicyScope = {
      orgId: 'org_test',
      environmentId: 'env_test',
      projectId: 'project_test',
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
            emailOtpKeyVersion: 'email-otp-kv-1',
            unlockPublicKeyB64u: 'unlock-public-key-worker',
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
    expect(workerRequests[0]?.request.payload.thresholdRouteAuth).toBeUndefined();
    expect(result.enrollment.emailOtpKeyVersion).toBe('email-otp-kv-1');
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
            loginGrant: 'grant-worker',
            challengeId: 'challenge-worker',
            emailOtpKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            unlockPublicKeyB64u: 'unlock-pub',
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
      thresholdRouteAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
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
        appSessionJwt: 'app-session-jwt',
        otpChannel: 'email_otp',
        rpId: 'example.localhost',
        ecdsaThresholdKeyId: 'ecdsa-key-worker',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-worker',
        thresholdRouteAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
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
      appSessionJwt: 'app-session-jwt',
      participantIds: [1, 2],
      ttlMs: 120_000,
      remainingUses: 7,
    });
    expect('clientRootShare32B64u' in result.recovery).toBe(false);
    expect(result.recovery.loginGrant).toBe('grant-worker');
    expect(result.bootstrap.thresholdEcdsaKeyRef.thresholdSessionId).toBe('ecdsa-session-worker');
    expect(result.warmCapability.state).toBe('ready');
  });

  test('operation-specific ECDSA Email OTP bootstrap forwards operation to worker verify', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            loginGrant: 'grant-worker',
            challengeId: 'challenge-worker',
            emailOtpKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            unlockPublicKeyB64u: 'unlock-pub',
            unlockSignatureB64u: 'unlock-sig',
          },
          bootstrap: makeWorkerBootstrap({ walletId, sessionId: 'ecdsa-session-worker' }),
        };
      },
    });

    await engine.loginWithEmailOtpEcdsaCapabilityInternal({
      nearAccountId: walletId,
      chain: 'evm',
      challengeId: 'export-challenge',
      otpCode: '123456',
      operation: 'export_key' as any,
      appSessionJwt: 'app-session-jwt',
      thresholdRouteAuth: { kind: 'app_session', jwt: 'app-session-jwt' },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload).toMatchObject({
      challengeId: 'export-challenge',
      operation: 'export_key',
      appSessionJwt: 'app-session-jwt',
    });
  });

  test('operation-specific ECDSA Email OTP bootstrap prefers app-session auth over stale threshold-session auth', async () => {
    const walletId = 'alice.testnet';
    const internalLoginRequests: Array<Record<string, any>> = [];
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    engineAny.loginWithEmailOtpEcdsaCapabilityInternal = async (input: Record<string, any>) => {
      internalLoginRequests.push(input);
    };
    engineAny.getThresholdEcdsaKeyRefForSigning = () =>
      makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef;

    await engineAny.loginWithEmailOtpEcdsaCapabilityForSigning({
      nearAccountId: walletId,
      chain: 'evm',
      challengeId: 'export-challenge',
      otpCode: '123456',
      operation: 'export_key',
      appSessionJwt: 'app-session-jwt',
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
        operation: 'export_key',
        appSessionJwt: 'app-session-jwt',
        thresholdRouteAuth: {
          kind: 'app_session',
          jwt: 'app-session-jwt',
        },
      }),
    ]);
  });

  test('Email OTP ECDSA bootstrap rejects threshold-session auth for JWT sessions', async () => {
    const walletId = 'alice.testnet';
    const { engine } = makeEngine({
      requestWorkerOperation: async () => {
        throw new Error('worker should not be called');
      },
    });

    await expect(
      engine.loginWithEmailOtpEcdsaCapabilityInternal({
        nearAccountId: walletId,
        chain: 'evm',
        challengeId: 'export-challenge',
        otpCode: '123456',
        operation: 'export_key' as any,
        thresholdRouteAuth: { kind: 'threshold_session', jwt: 'threshold-session-jwt-stale' },
        ecdsaThresholdKeyId: 'ecdsa-key-worker',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-worker',
      }),
    ).rejects.toThrow('Email OTP ECDSA bootstrap requires app-session route auth');
  });

  test('Email OTP Ed25519 provisioning reuses app-session route auth when appSessionJwt is omitted', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, ed25519ProvisionCalls } = makeEngine({
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        expect(kind).toBe('emailOtp');
        expect(request.type).toBe('loginWithEmailOtpAndBootstrapEcdsaSession');
        return {
          recovery: {
            loginGrant: 'grant-worker',
            challengeId: 'challenge-worker',
            emailOtpKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            unlockPublicKeyB64u: 'unlock-pub',
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
      thresholdRouteAuth: { kind: 'app_session', jwt: 'app-session-bootstrap-jwt' },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload.appSessionJwt).toBe('app-session-bootstrap-jwt');
    expect(workerRequests[0]?.request.payload.thresholdRouteAuth).toEqual({
      kind: 'app_session',
      jwt: 'app-session-bootstrap-jwt',
    });
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: walletId,
      appSessionJwt: 'app-session-bootstrap-jwt',
      prfFirstB64u: 'email-otp-ed25519-prf-worker',
    });
  });

  test('Email OTP enrollment Ed25519 provisioning reuses app-session route auth when appSessionJwt is omitted', async () => {
    const walletId = 'alice.testnet';
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
            emailOtpKeyVersion: 'email-otp-kv-1',
            unlockPublicKeyB64u: 'unlock-public-key-worker',
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
      thresholdRouteAuth: { kind: 'app_session', jwt: 'app-session-bootstrap-jwt' },
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload.appSessionJwt).toBe('app-session-bootstrap-jwt');
    expect(workerRequests[0]?.request.payload.thresholdRouteAuth).toEqual({
      kind: 'app_session',
      jwt: 'app-session-bootstrap-jwt',
    });
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: walletId,
      appSessionJwt: 'app-session-bootstrap-jwt',
      prfFirstB64u: 'email-otp-ed25519-prf-worker',
    });
  });

  test('Email OTP bootstrap does not use passkey PRF seal persistence', async () => {
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
            loginGrant: 'grant-worker',
            challengeId: 'challenge-worker',
            emailOtpKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            unlockPublicKeyB64u: 'unlock-pub',
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
      thresholdRouteAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
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
            loginGrant: 'grant-worker',
            challengeId: 'challenge-worker',
            emailOtpKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            unlockPublicKeyB64u: 'unlock-pub',
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
        thresholdRouteAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-1',
      }),
    ).rejects.toThrow('did not reach warm-session ready state');
  });

  test('exports ECDSA with fresh Email OTP step-up for Email OTP sessions', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    const confirmationTypes: string[] = [];
    const challengeRequests: Array<Record<string, unknown>> = [];
    const loginRequests: Array<Record<string, unknown>> = [];
    const workerRequests: Array<Record<string, any>> = [];
    const consumedSessions: Array<Record<string, unknown>> = [];
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const keyRef = makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef;
    const originalFetch = globalThis.fetch;
    let ecdsaRecord: Record<string, unknown> = {
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      thresholdSessionId: 'ecdsa-session-worker',
      thresholdSessionKind: 'jwt',
      thresholdSessionJwt: 'threshold-session-jwt-not-app-session',
    };

    engineAny.theme = 'dark';
    engineAny.getRpId = () => 'example.localhost';
    engineAny.getThresholdEcdsaSessionRecordForSigning = () => ecdsaRecord;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      refreshRequests.push({
        url: String(input),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ ok: true, jwt: 'refreshed-export-jwt' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    engineAny.requestEmailOtpChallengeForSigning = async (input: Record<string, unknown>) => {
      challengeRequests.push(input);
      return { challengeId: 'export-challenge', emailHint: 'alice@example.test' };
    };
    engineAny.loginWithEmailOtpEcdsaCapabilityForSigning = async (
      input: Record<string, unknown>,
    ) => {
      loginRequests.push(input);
      ecdsaRecord = {
        ...ecdsaRecord,
        thresholdSessionJwt: 'threshold-session-jwt-refreshed',
      };
    };
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
    expect(refreshRequests).toEqual([
      {
        url: 'https://relay.example/session/refresh',
        body: { session_kind: 'jwt' },
      },
    ]);
    expect(challengeRequests).toEqual([
      {
        nearAccountId: walletId,
        chain: 'evm',
        operation: 'export_key',
        appSessionJwt: 'refreshed-export-jwt',
      },
    ]);
    expect(loginRequests).toEqual([
      expect.objectContaining({
        nearAccountId: walletId,
        chain: 'evm',
        challengeId: 'export-challenge',
        otpCode: '123456',
        operation: 'export_key',
        appSessionJwt: 'refreshed-export-jwt',
      }),
    ]);
    expect(workerRequests).toEqual([
      expect.objectContaining({
        kind: 'emailOtp',
        request: expect.objectContaining({
          type: 'exportThresholdEcdsaHssKeyFromEmailOtpWarmSession',
          payload: expect.objectContaining({
            userId: walletId,
            rpId: 'example.localhost',
            sessionId: 'ecdsa-session-worker',
            thresholdSessionJwt: 'threshold-session-jwt-refreshed',
            ecdsaThresholdKeyId: 'ecdsa-key-worker',
            chain: 'evm',
          }),
        }),
      }),
    ]);
    expect(consumedSessions).toEqual([
      {
        nearAccountId: walletId,
        chain: 'evm',
      },
    ]);
    expect(confirmationTypes).toEqual(['signIntentDigest', 'showSecurePrivateKeyUi']);
  });

  test('consumes Email OTP ECDSA export session even when export viewer fails', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    const consumedSessions: Array<Record<string, unknown>> = [];
    const originalFetch = globalThis.fetch;
    const keyRef = makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef;
    let ecdsaRecord: Record<string, unknown> = {
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      thresholdSessionId: 'ecdsa-session-worker',
      thresholdSessionKind: 'jwt',
      thresholdSessionJwt: 'threshold-session-jwt-not-app-session',
    };

    engineAny.theme = 'dark';
    engineAny.getRpId = () => 'example.localhost';
    engineAny.getThresholdEcdsaSessionRecordForSigning = () => ecdsaRecord;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ ok: true, jwt: 'refreshed-export-jwt' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch;
    engineAny.requestEmailOtpChallengeForSigning = async () => ({
      challengeId: 'export-challenge',
      emailHint: 'alice@example.test',
    });
    engineAny.loginWithEmailOtpEcdsaCapabilityForSigning = async () => {
      ecdsaRecord = {
        ...ecdsaRecord,
        thresholdSessionJwt: 'threshold-session-jwt-refreshed',
      };
    };
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

    expect(consumedSessions).toEqual([
      {
        nearAccountId: walletId,
        chain: 'evm',
      },
    ]);
  });

  test('discard cached threshold-session JWT before Email OTP ECDSA export refresh', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
    engineAny.emailOtpAppSessionJwtByAccount = new Map([
      [
        walletId,
        makeUnsignedJwt({
          kind: 'threshold_session_v1',
          sub: walletId,
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
        engineAny.resolveEmailOtpAppSessionJwt({
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
    expect(engineAny.emailOtpAppSessionJwtByAccount.get(walletId)).toBe(refreshedAppSessionJwt);
  });

  test('uses unexpired cached app-session JWT for Email OTP export challenge', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
    const cachedAppSessionJwt = makeUnsignedJwt({
      kind: 'app_session_v1',
      sub: walletId,
      appSessionVersion: 'stale-app-session-version',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    engineAny.emailOtpAppSessionJwtByAccount = new Map([[walletId, cachedAppSessionJwt]]);
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
        engineAny.resolveEmailOtpAppSessionJwt({
          nearAccountId: walletId,
          relayUrl: 'https://relay.example',
        }),
      ).resolves.toBe(cachedAppSessionJwt);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(refreshRequests).toEqual([]);
    expect(engineAny.emailOtpAppSessionJwtByAccount.get(walletId)).toBe(cachedAppSessionJwt);
  });

  test('refreshes expired cached app-session JWT before Email OTP export challenge', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;
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
    engineAny.emailOtpAppSessionJwtByAccount = new Map([[walletId, cachedAppSessionJwt]]);
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
        engineAny.resolveEmailOtpAppSessionJwt({
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
    expect(engineAny.emailOtpAppSessionJwtByAccount.get(walletId)).toBe(refreshedAppSessionJwt);
  });

  test('exports NEAR Ed25519 with fresh Email OTP step-up for Email OTP sessions', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;
    const expectedPublicKey = 'ed25519:email-otp-public-key';
    const confirmationTypes: string[] = [];
    const challengeRequests: Array<Record<string, unknown>> = [];
    const loginRequests: Array<Record<string, unknown>> = [];
    const hssExportRequests: Array<Record<string, unknown>> = [];
    const consumedSessions: Array<Record<string, unknown>> = [];
    const refreshRequests: Array<{ url: string; body: unknown }> = [];
    const originalFetch = globalThis.fetch;

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
    engineAny.requestEmailOtpChallengeForSigning = async (input: Record<string, unknown>) => {
      challengeRequests.push(input);
      return { challengeId: 'export-challenge', emailHint: 'alice@example.test' };
    };
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      refreshRequests.push({
        url: String(input),
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return new Response(JSON.stringify({ ok: true, jwt: 'refreshed-ed25519-export-jwt' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    engineAny.loginWithEmailOtpEd25519CapabilityForSigning = async (
      input: Record<string, unknown>,
    ) => {
      loginRequests.push(input);
      persistWarmSessionEd25519Capability({
        nearAccountId: walletId,
        rpId: 'example.localhost',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'ed25519-relayer-key',
        runtimePolicyScope: {
          orgId: 'org_local',
          projectId: 'proj_local',
          envId: 'dev',
        },
        participantIds: [1, 2],
        sessionId: 'ed25519-email-otp-export-session-refreshed',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        jwt: 'ed25519-jwt-refreshed',
        xClientBaseB64u: 'x-client-base-refreshed',
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'sign',
          authMethod: 'email_otp',
        },
        source: 'email_otp',
      });
      return { sessionId: 'ed25519-email-otp-export-session-refreshed' };
    };
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
      claimWarmSessionMaterial: async (input: Record<string, unknown>) => {
        expect(input).toEqual({
          sessionId: 'ed25519-email-otp-export-session-refreshed',
          uses: 1,
        });
        return { ok: true, prfFirstB64u: 'export-prf-first' };
      },
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
        },
        participantIds: [1, 2],
        sessionId: 'ed25519-email-otp-export-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 7,
        jwt: 'ed25519-jwt-worker',
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
          nearAccountId: walletId,
          chain: 'near',
          operation: 'export_key',
          appSessionJwt: 'refreshed-ed25519-export-jwt',
        },
      ]);
      expect(refreshRequests).toEqual([
        {
          url: 'https://relay.example/session/refresh',
          body: { session_kind: 'jwt' },
        },
      ]);
      expect(loginRequests).toEqual([
        expect.objectContaining({
          nearAccountId: walletId,
          challengeId: 'export-challenge',
          otpCode: '123456',
          operation: 'export_key',
          appSessionJwt: 'refreshed-ed25519-export-jwt',
        }),
      ]);
      expect(hssExportRequests).toEqual([
        expect.objectContaining({
          signingRootId: 'proj_local:dev',
          nearAccountId: walletId,
          keyVersion: 'threshold-ed25519-hss-v1',
          participantIds: [1, 2],
          thresholdSessionId: 'ed25519-email-otp-export-session-refreshed',
          thresholdSessionJwt: 'ed25519-jwt-refreshed',
          relayerUrl: 'https://relay.example',
          relayerKeyId: 'ed25519-relayer-key',
          prfFirstB64u: 'export-prf-first',
        }),
      ]);
      expect(consumedSessions).toEqual([
        {
          nearAccountId: walletId,
          thresholdSessionId: 'ed25519-email-otp-export-session-refreshed',
        },
      ]);
      expect(confirmationTypes).toEqual([
        'signIntentDigest',
        'showSecurePrivateKeyUi',
        'showSecurePrivateKeyUi',
      ]);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('keeps ECDSA export on WebAuthn authorization for passkey sessions', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
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
    engineAny.getThresholdEcdsaSessionRecordForSigning = () => ({
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

  test('uses per-operation Email OTP policy metadata and defaults remainingUses to 1', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, upsertCalls } = makeEngine({
      authPolicy: 'per_operation',
      requestWorkerOperation: async ({ kind, request }) => {
        workerRequests.push({ kind, request });
        return {
          recovery: {
            loginGrant: 'grant-worker',
            challengeId: 'challenge-worker',
            emailOtpKeyVersion: 'email-otp-kv-worker',
            unlockChallengeId: 'unlock-worker',
            unlockChallengeB64u: 'unlock-b64u',
            unlockPublicKeyB64u: 'unlock-pub',
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
      thresholdRouteAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
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
