import { expect, test } from '@playwright/test';
import { EmailOtpThresholdSessionCoordinator } from '@/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator';

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function appSessionJwt(expSeconds = Math.floor(Date.now() / 1000) + 3600): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'app_session_v1',
    exp: expSeconds,
  })}.sig`;
}

function createCoordinator(overrides?: {
  requestWorkerOperation?: (call: any) => Promise<any>;
  refreshAppSessionJwt?: () => Promise<string>;
  requestUserConfirmation?: (request: any) => Promise<any>;
}) {
  const workerCalls: any[] = [];
  let refreshCount = 0;
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
        return { recovery: { thresholdEd25519PrfFirstB64u: 'prf-first' } };
      }
      if (call.request?.type === 'loginWithEmailOtpAndBootstrapEcdsaSession') {
        return {
          recovery: {
            loginGrant: 'login-grant',
            challengeId: call.request.payload.challengeId,
            emailOtpKeyVersion: 'email-v1',
            unlockChallengeId: 'unlock-challenge',
            unlockChallengeB64u: 'unlock-challenge-b64u',
            unlockPublicKeyB64u: 'unlock-public',
            unlockSignatureB64u: 'unlock-sig',
            thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-login',
          },
          bootstrap: {
            thresholdEcdsaKeyRef: {
              ecdsaThresholdKeyId: 'ecdsa-key',
              thresholdSessionId: call.request.payload.sessionId || 'ecdsa-session',
            },
            keygen: { ok: true },
            session: { ok: true },
          },
        };
      }
      if (call.request?.type === 'enrollEmailOtpWalletAndBootstrapEcdsaSession') {
        return {
          enrollment: {
            thresholdEcdsaClientVerifyingShareB64u: 'verifying-share',
            challengeId: call.request.payload.challengeId,
            otpChannel: 'email_otp',
            emailOtpKeyVersion: 'email-v1',
            unlockPublicKeyB64u: 'unlock-public',
            unlockKeyVersion: 'unlock-v1',
            thresholdEd25519PrfFirstB64u: 'prf-first-ecdsa-enroll',
          },
          bootstrap: {
            thresholdEcdsaKeyRef: {
              ecdsaThresholdKeyId: 'ecdsa-key',
              thresholdSessionId: call.request.payload.sessionId || 'ecdsa-session',
            },
            keygen: { ok: true },
            session: { ok: true },
          },
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
  const coordinator = new EmailOtpThresholdSessionCoordinator({
    configs: {
      network: {
        relayer: { url: 'https://relay.example' },
      },
      signing: {
        emailOtp: { authPolicy: 'per_operation' },
        sessionSeal: { shamirPrimeB64u: 'prime-b64u' },
      },
    } as any,
    signerWorkerManager: worker as any,
    touchIdPrompt: { getRpId: () => 'localhost' } as any,
    requestUserConfirmation:
      overrides?.requestUserConfirmation ||
      (async () => ({
        confirmed: true,
        otpCode: '123456',
      })),
    getSignerWorkerContext: () => worker as any,
    refreshAppSessionJwt: async () => {
      refreshCount += 1;
      return overrides?.refreshAppSessionJwt
        ? overrides.refreshAppSessionJwt()
        : appSessionJwt();
    },
    commitWorkerProvisionedThresholdEcdsaSessions: async (args) => {
      ecdsaCommitCalls.push(args);
      return {
        bootstrap: args.bootstrap,
        warmCapability: { capability: 'ecdsa', state: 'ready' } as any,
      };
    },
    getThresholdEcdsaKeyRefForSigning: (args) =>
      ({
        type: 'threshold-ecdsa-secp256k1',
        userId: String(args.nearAccountId),
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: 'ecdsa-key',
        ethereumAddress: '0xabc',
      }) as any,
    persistEmailOtpThresholdEd25519LocalMetadata: async (args) => {
      ed25519MetadataWrites.push(args);
    },
    persistWarmSessionEd25519Capability: async (args) => {
      ed25519WarmSessionWrites.push(args);
    },
    hydrateSigningSession: async (args) => {
      hydratedSessions.push(args);
    },
  });

  return {
    coordinator,
    workerCalls,
    ecdsaCommitCalls,
    ed25519ProvisionCalls,
    ed25519MetadataWrites,
    ed25519WarmSessionWrites,
    hydratedSessions,
    getRefreshCount: () => refreshCount,
  };
}

test.describe('EmailOtpThresholdSessionCoordinator', () => {
  test('normalizes warm-session status requests and maps worker failures', async () => {
    const invalid = createCoordinator();
    await expect(invalid.coordinator.getWarmSessionStatus('   ')).resolves.toMatchObject({
      ok: false,
      code: 'invalid_args',
    });
    expect(invalid.workerCalls).toHaveLength(0);

    const failing = createCoordinator({
      requestWorkerOperation: async () => {
        throw new Error('worker unavailable');
      },
    });
    await expect(failing.coordinator.getWarmSessionStatus(' session-1 ')).resolves.toMatchObject({
      ok: false,
      code: 'worker_error',
      message: 'worker unavailable',
    });
    expect(failing.workerCalls[0].request.payload.sessionId).toBe('session-1');
  });

  test('uses cached app-session JWTs for Email OTP challenge requests', async () => {
    const { coordinator, workerCalls, getRefreshCount } = createCoordinator();
    const cachedJwt = appSessionJwt();

    coordinator.rememberAppSessionJwt({
      nearAccountId: 'alice.testnet',
      appSessionJwt: cachedJwt,
    });

    const challenge = await coordinator.requestChallengeForSigning({
      nearAccountId: 'alice.testnet',
      chain: 'near',
    });

    expect(challenge).toMatchObject({
      challengeId: 'challenge-1',
      emailHint: 'a***@example.com',
      appSessionJwt: cachedJwt,
    });
    expect(getRefreshCount()).toBe(0);
    expect(workerCalls[0]).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          appSessionJwt: cachedJwt,
          otpChannel: 'email_otp',
          operation: 'transaction_sign',
        },
      },
    });
  });

  test('Email OTP export resend updates the challenge used for authorization', async () => {
    const challengeRequests: Array<Record<string, unknown>> = [];
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
      requestUserConfirmation: async (request) => {
        expect(request.payload.signingAuthPlan.emailOtpPrompt.challengeId).toBe(
          'export-challenge-1',
        );
        const resent = await request.payload.signingAuthPlan.emailOtpPrompt.onResend();
        expect(resent).toEqual({
          challengeId: 'export-challenge-2',
          emailHint: 'a***2@example.test',
        });
        return {
          confirmed: true,
          otpCode: '654321',
          emailOtpChallengeId: resent.challengeId,
        };
      },
    });

    await expect(
      coordinator.requestExportAuthorization({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        publicKey: '02'.padEnd(66, '1'),
        curve: 'ecdsa',
        appSessionJwt: 'fresh-app-session-jwt',
      }),
    ).resolves.toEqual({
      challengeId: 'export-challenge-2',
      otpCode: '654321',
    });
    expect(challengeRequests).toEqual([
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        appSessionJwt: 'fresh-app-session-jwt',
        otpChannel: 'email_otp',
        operation: 'export_key',
      },
      {
        relayUrl: 'https://relay.example',
        walletId: 'alice.testnet',
        appSessionJwt: 'fresh-app-session-jwt',
        otpChannel: 'email_otp',
        operation: 'export_key',
      },
    ]);
  });

  test('normalizes app-session route auth and remembers the JWT', async () => {
    const { coordinator, getRefreshCount } = createCoordinator();
    const jwt = appSessionJwt();

    const resolved = coordinator.resolveAppSessionJwtFromRouteAuth({
      nearAccountId: 'alice.testnet',
      thresholdRouteAuth: { kind: 'app_session', jwt },
    });

    expect(resolved).toBe(jwt);
    expect(coordinator.appSessionRouteAuth(jwt)).toEqual({ kind: 'app_session', jwt });
    await expect(
      coordinator.resolveAppSessionJwt({
        nearAccountId: 'alice.testnet',
        relayUrl: 'https://relay.example',
      }),
    ).resolves.toBe(jwt);
    expect(getRefreshCount()).toBe(0);
  });

  test('logs in Ed25519 Email OTP capability with normalized auth context', async () => {
    const { coordinator, ed25519ProvisionCalls } = createCoordinator();
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

    const result = await coordinator.loginWithEd25519CapabilityForSigning({
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      record: {
        thresholdSessionId: 'old-session',
        relayerUrl: '',
        rpId: '',
        relayerKeyId: 'relayer-key',
        keyVersion: 'v1',
        participantIds: [1, 2],
        thresholdSessionKind: 'jwt',
        thresholdSessionJwt: 'threshold-jwt',
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
      prfFirstB64u: 'prf-first',
      appSessionJwt: jwt,
      participantIds: [1, 2],
      remainingUses: 1,
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
      },
    });
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
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      thresholdRouteAuth: { kind: 'app_session', jwt },
      ecdsaThresholdKeyId: 'ecdsa-key',
      participantIds: [1, 3],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session',
      runtimePolicyScope: { orgId: 'org', projectId: 'proj', envId: 'dev' },
    });

    expect(result.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId).toBe('ecdsa-key');
    expect(workerCalls.at(-1)).toMatchObject({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
        payload: {
          relayUrl: 'https://relay.example',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          challengeId: 'challenge-1',
          otpCode: '123456',
          appSessionJwt: jwt,
          otpChannel: 'email_otp',
          rpId: 'localhost',
          ecdsaThresholdKeyId: 'ecdsa-key',
          participantIds: [1, 3],
          sessionKind: 'jwt',
          sessionId: 'ecdsa-session',
          thresholdRouteAuth: { kind: 'app_session', jwt },
          remainingUses: 1,
        },
      },
    });
    expect(ecdsaCommitCalls[0]).toMatchObject({
      nearAccountId: 'alice.testnet',
      primaryChain: 'tempo',
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
      nearAccountId: 'alice.testnet',
      challengeId: 'challenge-1',
      otpCode: '123456',
      appSessionJwt: jwt,
      thresholdRouteAuth: { kind: 'app_session', jwt },
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
    });
  });
});
