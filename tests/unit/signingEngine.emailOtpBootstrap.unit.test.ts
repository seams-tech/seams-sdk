import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '@shared/utils/encoders';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import { planEmailOtpThresholdEd25519SignerSlot } from '@/core/signingEngine/session/emailOtpThresholdEd25519SignerSlots';

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
      stepUpRequired: true,
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
  test('Email OTP Ed25519 slot planning revokes stale threshold signer and reuses slot 1', () => {
    const plan = planEmailOtpThresholdEd25519SignerSlot({
      signerId: 'threshold-ed25519:rk-new',
      activeSigners: [
        {
          signerId: 'threshold-ed25519:rk-old',
          signerSlot: 1,
          signerType: 'threshold',
        },
      ],
    });

    expect(plan).toEqual({
      signerSlot: 1,
      staleSignerIds: ['threshold-ed25519:rk-old'],
    });
  });

  test('Email OTP Ed25519 slot planning does not evict non-threshold signer slots', () => {
    const plan = planEmailOtpThresholdEd25519SignerSlot({
      signerId: 'threshold-ed25519:rk-new',
      activeSigners: [
        {
          signerId: 'passkey:primary',
          signerSlot: 1,
          signerType: 'passkey',
        },
      ],
    });

    expect(plan).toEqual({
      signerSlot: 2,
      staleSignerIds: [],
    });
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
    expect(workerRequests[0]?.request.payload.authorizationJwt).toBeUndefined();
    expect(result.enrollment.emailOtpKeyVersion).toBe('email-otp-kv-1');
    expect(persistCalls).toHaveLength(1);
    expect(persistCalls[0]).toMatchObject({ ensureEmailOtpNearAccountMapping: true });
    expect(upsertCalls).toHaveLength(1);
    expect(readyChecks).toEqual([{ nearAccountId: walletId, chain: 'tempo' }]);
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
      authorizationJwt: 'bootstrap-auth-jwt',
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
        authorizationJwt: 'bootstrap-auth-jwt',
        ttlMs: 120_000,
        remainingUses: 7,
      },
    });
    expect(persistCalls).toHaveLength(1);
    expect(persistCalls[0]).toMatchObject({ ensureEmailOtpNearAccountMapping: true });
    expect(upsertCalls).toHaveLength(1);
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
        stepUpRequired: true,
      },
    });
    expect(
      ((upsertCalls[0]?.bootstrap as any)?.thresholdEcdsaKeyRef?.backendBinding || {})
        .clientAdditiveShare32B64u,
    ).toBeUndefined();
    expect(readyChecks).toEqual([{ nearAccountId: walletId, chain: 'evm' }]);
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

  test('Email OTP Ed25519 provisioning reuses authorizationJwt when appSessionJwt is omitted', async () => {
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
      authorizationJwt: 'app-session-bootstrap-jwt',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload.appSessionJwt).toBe('app-session-bootstrap-jwt');
    expect(workerRequests[0]?.request.payload.authorizationJwt).toBe('app-session-bootstrap-jwt');
    expect(ed25519ProvisionCalls).toHaveLength(1);
    expect(ed25519ProvisionCalls[0]).toMatchObject({
      nearAccountId: walletId,
      appSessionJwt: 'app-session-bootstrap-jwt',
      prfFirstB64u: 'email-otp-ed25519-prf-worker',
    });
  });

  test('Email OTP enrollment Ed25519 provisioning reuses authorizationJwt when appSessionJwt is omitted', async () => {
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
      authorizationJwt: 'app-session-bootstrap-jwt',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-worker',
    });

    expect(workerRequests[0]?.request.payload.appSessionJwt).toBe('app-session-bootstrap-jwt');
    expect(workerRequests[0]?.request.payload.authorizationJwt).toBe('app-session-bootstrap-jwt');
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
      authorizationJwt: 'bootstrap-auth-jwt',
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
        authorizationJwt: 'bootstrap-auth-jwt',
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-1',
      }),
    ).rejects.toThrow('did not reach warm-session ready state');
  });

  test('fails closed for ECDSA export when the active session source is email_otp', async () => {
    const walletId = 'alice.testnet';
    const engine = Object.create(SigningEngine.prototype) as SigningEngine;
    const engineAny = engine as any;

    engineAny.getThresholdEcdsaSessionRecordForSigning = () => ({
      nearAccountId: walletId,
      source: 'email_otp',
    });

    await expect(
      engineAny.exportThresholdEcdsaKeyWithAuthorization({
        nearAccountId: walletId,
        chain: 'evm',
        keyRef: makeWorkerBootstrap({ walletId }).thresholdEcdsaKeyRef,
        options: {},
      }),
    ).rejects.toThrow(
      '[SigningEngine] threshold-ecdsa key export requires fresh passkey authentication after Email OTP login',
    );
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
      authorizationJwt: 'bootstrap-auth-jwt',
    });

    expect(workerRequests[0]?.request.payload.remainingUses).toBe(1);
    expect(upsertCalls[0]).toMatchObject({
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
    });
  });
});
