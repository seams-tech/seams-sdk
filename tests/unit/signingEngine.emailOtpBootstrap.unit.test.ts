import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '@shared/utils/encoders';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';

function makeWorkerBootstrap(args?: {
  walletId?: string;
  sessionId?: string;
  remainingUses?: number;
}) {
  const walletId = args?.walletId || 'alice.testnet';
  const sessionId = args?.sessionId || 'ecdsa-session-worker';
  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1' as const,
      userId: walletId,
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-key-worker',
      backendBinding: {
        relayerKeyId: 'rk-worker',
        clientVerifyingShareB64u: 'AQ',
        clientAdditiveShare32B64u: 'Ag',
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
      clientAdditiveShare32B64u: 'Ag',
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
}) {
  const engine = Object.create(SigningEngine.prototype) as SigningEngine;
  const engineAny = engine as any;
  const persistCalls: Array<Record<string, unknown>> = [];
  const upsertCalls: Array<Record<string, unknown>> = [];
  const readyChecks: Array<Record<string, unknown>> = [];

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
  engineAny.touchConfirm = {};
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
  engineAny.persistThresholdEcdsaBootstrapChainAccount = async (callArgs: Record<string, unknown>) => {
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

  return { engine, persistCalls, upsertCalls, readyChecks };
}

test.describe('SigningEngine Email OTP bootstrap runtime', () => {
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

  test('default Email OTP login completes ECDSA authorization bootstrap inside the Email OTP worker', async () => {
    const walletId = 'alice.testnet';
    const workerRequests: Array<Record<string, any>> = [];
    const { engine, persistCalls, upsertCalls, readyChecks } = makeEngine({
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
    expect(upsertCalls).toHaveLength(1);
    expect(upsertCalls[0]).toMatchObject({
      nearAccountId: walletId,
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
    });
    expect(readyChecks).toEqual([{ nearAccountId: walletId, chain: 'evm' }]);
    expect('clientRootShare32B64u' in result.recovery).toBe(false);
    expect(result.recovery.loginGrant).toBe('grant-worker');
    expect(result.bootstrap.thresholdEcdsaKeyRef.thresholdSessionId).toBe('ecdsa-session-worker');
    expect(result.warmCapability.state).toBe('ready');
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
