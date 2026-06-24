import { expect, test } from '@playwright/test';
import {
  beginGoogleEmailOtpWalletAuth,
  type GoogleEmailOtpWalletAuthDeps,
} from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import {
  registrationProvisioningScopeKey,
  walletIdFromString,
} from '@shared/utils/registrationIntent';

const TEMPO_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const satisfies ThresholdEcdsaChainTarget;

const EVM_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'ethereum-sepolia',
} as const satisfies ThresholdEcdsaChainTarget;

function testConfigs(): GoogleEmailOtpWalletAuthDeps['configs'] {
  return {
    network: { chains: [] },
    signing: {
      thresholdEcdsa: {
        provisioningDefaults: {
          tempo: { enabled: false },
          evm: { enabled: false },
        },
      },
    },
  } as unknown as GoogleEmailOtpWalletAuthDeps['configs'];
}

function loggedInSession(walletId: string) {
  return {
    login: {
      isLoggedIn: true,
      nearAccountId: walletId,
    },
  } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['getWalletSession']>>;
}

function makeRegisterResolution(input?: { walletId?: string; attemptId?: string }) {
  const walletId = input?.walletId ?? 'alice.testnet';
  const candidates = [
    { candidateId: 'registration-candidate-1', walletId: 'alice.testnet' },
    { candidateId: 'registration-candidate-2', walletId: 'alice-2.testnet' },
  ] as const;
  return {
    mode: 'register_started' as const,
    registrationAttemptId: input?.attemptId ?? 'registration-attempt-1',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    offer: {
      offerId: 'registration-offer-1',
      selectedCandidateId:
        walletId === 'alice-2.testnet' ? 'registration-candidate-2' : 'registration-candidate-1',
      candidates,
    },
  };
}

function makeRecoveryCodeSet() {
  return buildEmailOtpRecoveryCodeSet([
    '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
    '123456789ABCDEFGHJKMNPQRSTVWXYZ0',
    '23456789ABCDEFGHJKMNPQRSTVWXYZ01',
    '3456789ABCDEFGHJKMNPQRSTVWXYZ012',
    '456789ABCDEFGHJKMNPQRSTVWXYZ0123',
    '56789ABCDEFGHJKMNPQRSTVWXYZ01234',
    '6789ABCDEFGHJKMNPQRSTVWXYZ012345',
    '789ABCDEFGHJKMNPQRSTVWXYZ0123456',
    '89ABCDEFGHJKMNPQRSTVWXYZ01234567',
    '9ABCDEFGHJKMNPQRSTVWXYZ012345678',
  ]);
}

function makeEmailOtpRegistrationEnrollmentMaterial(args: {
  walletId: string;
  userId: string;
}): Awaited<
  ReturnType<GoogleEmailOtpWalletAuthDeps['prepareEmailOtpRegistrationEnrollmentMaterial']>
> {
  return {
    thresholdEcdsaClientVerifyingShareB64u: 'threshold-ecdsa-client-share',
    thresholdEd25519RecoveryCodeSecret32B64u: 'threshold-ed25519-prf-first',
    recoveryKeys: makeRecoveryCodeSet(),
    recoveryCodesIssuedAtMs: 1_700_000_000_000,
    otpChannel: 'email_otp',
    enrollmentId: `enrollment-${args.walletId}`,
    enrollmentSealKeyVersion: 'email-otp-v1',
    clientUnlockPublicKeyB64u: 'client-unlock-public-key',
    unlockKeyVersion: 'unlock-v1',
    clientRootShareHandle: {
      kind: 'email_otp_worker_session_handle_v1',
      sessionId: `client-root-share-${args.walletId}`,
      walletId: args.walletId,
      walletKeyId: `wallet-key-${args.walletId}`,
      authSubjectId: args.userId,
      action: 'wallet_registration_ecdsa_prepare',
      operation: 'registration',
      keyScope: 'evm-family',
    },
    emailOtpEnrollment: {
      recoveryWrappedEnrollmentEscrows: [
        {
          enrollmentId: `enrollment-${args.walletId}`,
        },
      ],
      enrollmentSealKeyVersion: 'email-otp-v1',
      clientUnlockPublicKeyB64u: 'client-unlock-public-key',
      unlockKeyVersion: 'unlock-v1',
      thresholdEcdsaClientVerifyingShareB64u: 'threshold-ecdsa-client-share',
    },
  };
}

function makeStartedPrecompute(
  args: Parameters<GoogleEmailOtpWalletAuthDeps['startWalletRegistrationPrecompute']>[0],
): ReturnType<GoogleEmailOtpWalletAuthDeps['startWalletRegistrationPrecompute']> {
  const walletId =
    args.wallet.kind === 'provided' ? String(args.wallet.walletId) : 'server-generated.testnet';
  return {
    kind: 'started',
    handle: {
      kind: 'wallet_registration_precompute_handle_v1',
      handleId: `precompute-${walletId}`,
      scope: {
        authMethodKind: args.authMethod.kind,
        walletScopeKey:
          args.wallet.kind === 'provided'
            ? `provided:${String(args.wallet.walletId)}`
            : 'server_generated',
        rpId: args.rpId,
        signerMode:
          args.signerSelection.mode === 'ed25519_and_ecdsa' ? 'ed25519_and_ecdsa' : 'ed25519_only',
        accountProvisioningScopeKey:
          args.signerSelection.mode === 'ed25519_and_ecdsa' ||
          args.signerSelection.mode === 'ed25519_only'
            ? registrationProvisioningScopeKey(args.signerSelection.ed25519.accountProvisioning)
            : walletId,
      },
      read: async () => {
        throw new Error('test precompute handle read should not be called by flow unit tests');
      },
      snapshot: () => ({}),
      routeDiagnosticsSnapshot: () => [],
      dispose: () => undefined,
    },
  } as ReturnType<GoogleEmailOtpWalletAuthDeps['startWalletRegistrationPrecompute']>;
}

function makeDeps(overrides?: Partial<GoogleEmailOtpWalletAuthDeps>): {
  deps: GoogleEmailOtpWalletAuthDeps;
  calls: Array<{ type: string; args: unknown }>;
} {
  const calls: Array<{ type: string; args: unknown }> = [];
  const registerWalletImpl =
    overrides?.registerWallet ??
    (async (args: Parameters<GoogleEmailOtpWalletAuthDeps['registerWallet']>[0]) => {
      calls.push({ type: 'registerWallet', args });
      return { success: true, walletId: walletIdFromString('alice.testnet') } satisfies Awaited<
        ReturnType<GoogleEmailOtpWalletAuthDeps['registerWallet']>
      >;
    });
  const registerWalletWithStartedPrecomputeImpl =
    overrides?.registerWalletWithStartedPrecompute ??
    (async (
      args: Parameters<GoogleEmailOtpWalletAuthDeps['registerWalletWithStartedPrecompute']>[0],
    ) => {
      calls.push({ type: 'registerWalletWithStartedPrecompute', args });
      return await registerWalletImpl(args.registration);
    });
  const deps: GoogleEmailOtpWalletAuthDeps = {
    configs: testConfigs(),
    getRpId: () => 'localhost',
    exchangeGoogleEmailOtpSession: async (args) => {
      calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
      const walletId = 'alice.testnet';
      return {
        session: {
          userId: 'google-subject-1',
          walletId,
          email: 'alice@example.com',
          googleEmailOtpResolution:
            args.accountMode === 'register'
              ? makeRegisterResolution({
                  walletId,
                  attemptId: 'registration-attempt-1',
                })
              : {
                  mode: 'existing_wallet',
                  expiresAt: new Date(Date.now() + 60_000).toISOString(),
                  loginChallenge: {
                    delivery: 'sent',
                    challengeId: 'login-challenge-1',
                    emailHint: 'alice@example.com',
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                  },
                },
        },
        jwt: 'app-session-jwt',
      } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
    },
    requestEmailOtpChallenge: async (args) => {
      calls.push({ type: 'requestEmailOtpChallenge', args });
      return {
        challengeId: 'login-challenge-1',
        otpChannel: 'email_otp',
        emailHint: 'alice@example.com',
      };
    },
    prepareEmailOtpRegistrationEnrollmentMaterial: async (args) => {
      calls.push({ type: 'prepareEmailOtpRegistrationEnrollmentMaterial', args });
      return makeEmailOtpRegistrationEnrollmentMaterial({
        walletId: String(args.walletId),
        userId: String(args.userId),
      });
    },
    registerWallet: registerWalletImpl,
    startWalletRegistrationPrecompute: (args) => {
      calls.push({ type: 'startWalletRegistrationPrecompute', args });
      return makeStartedPrecompute(args);
    },
    registerWalletWithStartedPrecompute: registerWalletWithStartedPrecomputeImpl,
    loginWithEmailOtpEcdsaCapability: async (args) => {
      calls.push({ type: 'loginWithEmailOtpEcdsaCapability', args });
      return { success: true } as unknown as Awaited<
        ReturnType<GoogleEmailOtpWalletAuthDeps['loginWithEmailOtpEcdsaCapability']>
      >;
    },
    loginWithEmailOtpEd25519Capability: async (args) => {
      calls.push({ type: 'loginWithEmailOtpEd25519Capability', args });
    },
    getWalletSession: async (walletId) => {
      calls.push({ type: 'getWalletSession', args: { walletId } });
      return loggedInSession(walletId);
    },
    ...overrides,
  };
  return { deps, calls };
}

test.describe('Google Email OTP wallet auth headless flow', () => {
  test('register path returns registration-ready flow and completes without OTP challenge', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      relayUrl: 'https://relay.example',
      sessionKind: 'jwt',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value.mode).toBe('register');
    if (started.value.mode !== 'register') throw new Error('expected register flow');
    expect(started.value.state).toBe('registration_ready');
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
    ]);
    expect(calls[1]?.args).toMatchObject({
      relayUrl: 'https://relay.example',
      walletId: 'alice.testnet',
      userId: 'google-subject-1',
      rpId: 'localhost',
      appSessionJwt: 'app-session-jwt',
    });

    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(true);
    if (!completed.ok) throw new Error(completed.error.message);
    expect(completed.value.walletId).toBe('alice.testnet');
    expect(completed.value.mode).toBe('register');
    expect(JSON.stringify(completed.value)).not.toContain('recoveryKeys');
    expect(JSON.stringify(completed.value)).not.toContain('app-session-jwt');
    const registerCall = calls.find((call) => call.type === 'registerWallet');
    expect(registerCall?.args).toMatchObject({
      wallet: { kind: 'provided', walletId: 'alice.testnet' },
      authMethod: {
        kind: 'email_otp',
        proofKind: 'google_sso_registration',
        email: 'alice@example.com',
        appSessionJwt: 'app-session-jwt',
        googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
        googleEmailOtpRegistrationOfferId: 'registration-offer-1',
        googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
      },
    });
    expect(JSON.stringify(registerCall?.args)).not.toContain('code-1');
    expect(JSON.stringify(registerCall?.args)).not.toContain('recoveryKeys');
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
      'registerWalletWithStartedPrecompute',
      'registerWallet',
      'getWalletSession',
    ]);
  });

  test('register path falls back to routed registration when precompute is unavailable', async () => {
    const { deps, calls } = makeDeps({
      startWalletRegistrationPrecompute: (args) => {
        calls.push({ type: 'startWalletRegistrationPrecompute', args });
        return {
          kind: 'unavailable',
          unavailableReason: 'wallet_iframe_registration_domain',
        };
      },
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      relayUrl: 'https://relay.example',
      sessionKind: 'jwt',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');
    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(true);
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
      'registerWallet',
      'getWalletSession',
    ]);
    expect(calls.find((call) => call.type === 'registerWalletWithStartedPrecompute')).toBeFalsy();
  });

  test('register path fails closed when the offer expiry is missing', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        const resolution = makeRegisterResolution();
        const { expiresAt: _expiresAt, ...withoutExpiry } = resolution;
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: withoutExpiry,
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(false);
    if (started.ok) throw new Error('expected missing-expiry failure');
    expect(started.error.code).toBe('google_exchange_failed');
    expect(started.error.message).toContain('expired or missing expiry');
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);
  });

  test('register path fails closed when the offer expiry is malformed', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: {
              ...makeRegisterResolution(),
              expiresAt: 'not-a-date',
            },
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(false);
    if (started.ok) throw new Error('expected malformed-expiry failure');
    expect(started.error.code).toBe('google_exchange_failed');
    expect(started.error.message).toContain('expired or missing expiry');
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);
  });

  test('expired registration flow clears prewarmed recovery-code material', async () => {
    const realNow = Date.now;
    let nowMs = realNow();
    let material:
      | Awaited<
          ReturnType<GoogleEmailOtpWalletAuthDeps['prepareEmailOtpRegistrationEnrollmentMaterial']>
        >
      | undefined;
    Date.now = () => nowMs;
    try {
      const { deps, calls } = makeDeps({
        exchangeGoogleEmailOtpSession: async (args) => {
          calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
          return {
            session: {
              userId: 'google-subject-1',
              walletId: 'alice.testnet',
              email: 'alice@example.com',
              googleEmailOtpResolution: {
                ...makeRegisterResolution(),
                expiresAtMs: nowMs + 1_000,
              },
            },
            jwt: 'app-session-jwt',
          } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
        },
        prepareEmailOtpRegistrationEnrollmentMaterial: async (args) => {
          calls.push({ type: 'prepareEmailOtpRegistrationEnrollmentMaterial', args });
          material = makeEmailOtpRegistrationEnrollmentMaterial({
            walletId: String(args.walletId),
            userId: String(args.userId),
          });
          return material;
        },
      });

      const started = await beginGoogleEmailOtpWalletAuth(deps, {
        idToken: 'google-id-token',
        mode: 'register',
        relayUrl: 'https://relay.example',
        ecdsaTargets: { kind: 'none' },
      });

      expect(started.ok).toBe(true);
      if (!started.ok || started.value.mode !== 'register')
        throw new Error('expected register flow');
      expect(material?.recoveryKeys).toHaveLength(10);

      nowMs += 2_000;
      const completed = await started.value.completeRegistration();

      expect(completed.ok).toBe(false);
      if (completed.ok) throw new Error('expected expired registration failure');
      expect(completed.error.code).toBe('flow_expired');
      expect(material?.recoveryKeys).toHaveLength(0);
      expect(material?.emailOtpEnrollment.recoveryWrappedEnrollmentEscrows).toHaveLength(0);
      expect(calls.map((call) => call.type)).toEqual([
        'exchangeGoogleEmailOtpSession',
        'prepareEmailOtpRegistrationEnrollmentMaterial',
        'startWalletRegistrationPrecompute',
      ]);
    } finally {
      Date.now = realNow;
    }
  });

  test('rerolled registration offer clears stale prewarmed recovery-code material', async () => {
    const materials: Array<
      Awaited<
        ReturnType<GoogleEmailOtpWalletAuthDeps['prepareEmailOtpRegistrationEnrollmentMaterial']>
      >
    > = [];
    const { deps, calls } = makeDeps({
      prepareEmailOtpRegistrationEnrollmentMaterial: async (args) => {
        calls.push({ type: 'prepareEmailOtpRegistrationEnrollmentMaterial', args });
        const material = makeEmailOtpRegistrationEnrollmentMaterial({
          walletId: String(args.walletId),
          userId: String(args.userId),
        });
        materials.push(material);
        return material;
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');
    expect(materials[0]?.recoveryKeys).toHaveLength(10);

    const rerolled = await started.value.rerollWalletId();

    expect(rerolled.ok).toBe(true);
    if (!rerolled.ok || rerolled.value.mode !== 'register') {
      throw new Error('expected rerolled register flow');
    }
    expect(rerolled.value.walletId).toBe('alice-2.testnet');
    expect(materials[0]?.recoveryKeys).toHaveLength(0);
    expect(materials[0]?.emailOtpEnrollment.recoveryWrappedEnrollmentEscrows).toHaveLength(0);
    expect(materials[1]?.recoveryKeys).toHaveLength(10);
    await rerolled.value.cancel();
  });

  test('cancelled registration cannot reuse prewarmed material', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');

    await started.value.cancel();
    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(false);
    if (completed.ok) throw new Error('expected cancelled registration failure');
    expect(completed.error.code).toBe('registration_failed');
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
    ]);
  });

  test('register path surfaces already-finalized replay as restore required', async () => {
    const { deps, calls } = makeDeps({
      registerWallet: async (args) => {
        calls.push({ type: 'registerWallet', args });
        return {
          success: false,
          error:
            'Wallet registration was already finalized. Restore or unlock the wallet to continue.',
          errorCode: 'already_finalized_restore_required',
        };
      },
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');
    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(false);
    if (completed.ok) throw new Error('expected restore-required failure');
    expect(completed.error.code).toBe('registration_restore_required');
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
      'registerWalletWithStartedPrecompute',
      'registerWallet',
    ]);
  });

  test('login path uses exchange-delivered login challenge and submits through Email OTP ECDSA capability', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value.mode).toBe('login');
    if (started.value.mode !== 'login') throw new Error('expected login flow');
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);

    const submitted = await started.value.submit({ otpCode: '123456' });

    expect(submitted.ok).toBe(true);
    if (!submitted.ok) throw new Error(submitted.error.message);
    expect(submitted.value.mode).toBe('login');
    const loginCall = calls.find((call) => call.type === 'loginWithEmailOtpEcdsaCapability');
    expect(loginCall?.args).toMatchObject({
      chainTarget: TEMPO_TARGET,
      publicationChainTargets: [TEMPO_TARGET],
      challengeId: 'login-challenge-1',
      otpCode: '123456',
    });
  });

  test('login path submits one OTP-backed ECDSA capability call for multiple targets', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET, EVM_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    const submitted = await started.value.submit({ otpCode: '123456' });

    expect(submitted.ok).toBe(true);
    const loginCalls = calls.filter((call) => call.type === 'loginWithEmailOtpEcdsaCapability');
    expect(loginCalls).toHaveLength(1);
    expect(loginCalls[0]?.args).toMatchObject({
      chainTarget: TEMPO_TARGET,
      publicationChainTargets: [TEMPO_TARGET, EVM_TARGET],
      challengeId: 'login-challenge-1',
      otpCode: '123456',
    });
  });

  test('login path supports NEAR-only Email OTP wallets without ECDSA targets', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    const submitted = await started.value.submit({ otpCode: '123456' });

    expect(submitted.ok).toBe(true);
    const ed25519Call = calls.find((call) => call.type === 'loginWithEmailOtpEd25519Capability');
    expect(ed25519Call?.args).toMatchObject({
      challengeId: 'login-challenge-1',
      otpCode: '123456',
      relayUrl: 'https://relay.example',
      appSessionJwt: 'app-session-jwt',
      walletSession: {
        walletId: 'alice.testnet',
        walletSessionUserId: 'google-subject-1',
      },
    });
    expect(calls.find((call) => call.type === 'loginWithEmailOtpEcdsaCapability')).toBeFalsy();
  });

  test('login path treats empty configured ECDSA targets as NEAR-only unlock', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    const submitted = await started.value.submit({ otpCode: '123456' });

    expect(submitted.ok).toBe(true);
    expect(calls.find((call) => call.type === 'loginWithEmailOtpEd25519Capability')).toBeTruthy();
    expect(calls.find((call) => call.type === 'loginWithEmailOtpEcdsaCapability')).toBeFalsy();
  });

  test('login path accepts exchange-reused login challenge without requesting another OTP', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: {
              mode: 'existing_wallet',
              loginChallenge: {
                delivery: 'reused',
                challengeId: 'login-challenge-reused-1',
                emailHint: 'a***@example.com',
              },
            },
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value.mode).toBe('login');
    if (started.value.mode !== 'login') throw new Error('expected login flow');
    const submitted = await started.value.submit({ otpCode: '123456' });
    expect(submitted.ok).toBe(true);
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'loginWithEmailOtpEcdsaCapability',
      'getWalletSession',
    ]);
    const loginCall = calls.find((call) => call.type === 'loginWithEmailOtpEcdsaCapability');
    expect(loginCall?.args).toMatchObject({
      challengeId: 'login-challenge-reused-1',
      otpCode: '123456',
    });
  });

  test('login path falls back to explicit challenge request when exchange does not deliver one', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: {
              mode: 'existing_wallet',
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
            },
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value.mode).toBe('login');
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'requestEmailOtpChallenge',
    ]);
  });

  test('login path surfaces exchange challenge rate limits without requesting another challenge', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: {
              mode: 'existing_wallet',
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              loginChallenge: {
                delivery: 'rate_limited',
                retryAfterMs: 30_000,
              },
            },
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
    });

    expect(started.ok).toBe(false);
    if (started.ok) throw new Error('expected rate-limited result');
    expect(started.error).toMatchObject({
      code: 'email_otp_rate_limited',
      retryAfterMs: 30_000,
    });
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);
  });

  test('register request resolving to existing wallet fails closed', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: {
              mode: 'existing_wallet',
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              loginChallenge: {
                delivery: 'sent',
                challengeId: 'login-challenge-1',
                emailHint: 'alice@example.com',
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
              },
            },
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
    });

    expect(started.ok).toBe(false);
    if (started.ok) throw new Error('expected registration exchange failure');
    expect(started.error).toMatchObject({
      code: 'google_exchange_failed',
      message: 'Google Email OTP registration did not return a registration offer',
    });
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);
  });

  test('login request resolving to existing wallet surfaces missing device escrow as recovery required', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: {
              mode: 'existing_wallet',
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              loginChallenge: {
                delivery: 'sent',
                challengeId: 'login-challenge-1',
                emailHint: 'alice@example.com',
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
              },
            },
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
      loginWithEmailOtpEcdsaCapability: async (args) => {
        calls.push({ type: 'loginWithEmailOtpEcdsaCapability', args });
        throw new Error('Email OTP device-local enc_s(S) is missing; recovery is required');
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    const submitted = await started.value.submit({ otpCode: '123456' });

    expect(submitted.ok).toBe(false);
    if (submitted.ok) throw new Error('expected recovery-required failure');
    expect(submitted.error).toMatchObject({
      code: 'email_otp_device_recovery_required',
      message:
        'This Email OTP wallet needs recovery on this device. Restore it with your recovery code to unlock.',
    });
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'loginWithEmailOtpEcdsaCapability',
    ]);
  });

  test('registration explicit ECDSA targets are used for signer selection', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      ecdsaTargets: { kind: 'explicit', targets: [EVM_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value.mode).toBe('register');
    if (started.value.mode !== 'register') throw new Error('expected register flow');
    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(true);
    const registerCall = calls.find((call) => call.type === 'registerWallet');
    expect(registerCall?.args).toMatchObject({
      signerSelection: {
        mode: 'ed25519_and_ecdsa',
        ecdsa: {
          chainTargets: [EVM_TARGET],
        },
      },
    });
  });

  test('registration completion reports recovery-code backup requirement without exposing secrets', async () => {
    const { deps } = makeDeps({
      registerWallet: async () =>
        ({
          success: false,
          error: 'Recovery code backup incomplete',
        }) as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['registerWallet']>>,
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');
    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(false);
    if (completed.ok) throw new Error('expected backup failure');
    expect(completed.error.code).toBe('recovery_code_backup_incomplete');
    expect(JSON.stringify(completed)).not.toContain('recoveryKeys');
    expect(JSON.stringify(completed)).not.toContain('app-session-jwt');
  });

  test('reroll changes wallet id without requesting an Email OTP challenge', async () => {
    const { deps, calls } = makeDeps();
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');

    const rerolled = await started.value.rerollWalletId();

    expect(rerolled.ok).toBe(true);
    if (!rerolled.ok) throw new Error(rerolled.error.message);
    expect(rerolled.value.mode).toBe('register');
    expect(rerolled.value.walletId).toBe('alice-2.testnet');
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
    ]);
    expect(calls[3]?.args).toMatchObject({
      walletId: 'alice-2.testnet',
      userId: 'google-subject-1',
    });
    const staleCompletion = await started.value.completeRegistration();
    expect(staleCompletion.ok).toBe(false);
  });

  test('registration reroll is local and cannot pivot into a login OTP challenge', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: makeRegisterResolution(),
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');
    const rerolled = await started.value.rerollWalletId();

    expect(rerolled.ok).toBe(true);
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
      'prepareEmailOtpRegistrationEnrollmentMaterial',
      'startWalletRegistrationPrecompute',
    ]);

    const completed = await started.value.completeRegistration();
    expect(completed.ok).toBe(false);
  });

  test('reroll failure leaves the registration flow active when no alternate candidate exists', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: {
              ...makeRegisterResolution(),
              offer: {
                offerId: 'registration-offer-1',
                selectedCandidateId: 'registration-candidate-1',
                candidates: [
                  { candidateId: 'registration-candidate-1', walletId: 'alice.testnet' },
                ],
              },
            },
          },
          jwt: 'app-session-jwt',
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'register') throw new Error('expected register flow');
    const rerolled = await started.value.rerollWalletId();
    expect(rerolled.ok).toBe(false);

    const completed = await started.value.completeRegistration();
    expect(completed.ok).toBe(true);
  });

  test('login resend failure leaves the flow active for submit', async () => {
    const { deps, calls } = makeDeps({
      requestEmailOtpChallenge: async (args) => {
        calls.push({ type: 'requestEmailOtpChallenge', args });
        throw new Error('Email OTP rate limit exceeded');
      },
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    const resent = await started.value.resend();
    expect(resent.ok).toBe(false);

    const submitted = await started.value.submit({ otpCode: '123456' });
    expect(submitted.ok).toBe(true);
  });
});
