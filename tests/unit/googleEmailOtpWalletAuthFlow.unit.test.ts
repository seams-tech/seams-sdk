import { expect, test } from '@playwright/test';
import {
  beginGoogleEmailOtpWalletAuth,
  type GoogleEmailOtpWalletAuthDeps,
} from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { DemoEmailOtpCodeResponse } from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { RegistrationResult } from '@/core/types/seams';
import { base64UrlEncode } from '@shared/utils/encoders';
import { walletIdFromString } from '@shared/utils/registrationIntent';

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

const TEST_RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'env-test',
  signingRootVersion: 'v1',
} as const;

const APP_SESSION_JWT = jwtWithPayload({
  kind: 'app_session_v1',
  sub: 'alice.testnet',
  runtimePolicyScope: TEST_RUNTIME_POLICY_SCOPE,
});

function jwtWithPayload(payload: Record<string, unknown>): string {
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'none' })));
  const body = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  return `${header}.${body}.fixture`;
}

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

function testConfigsWithConfiguredEcdsaChains(): GoogleEmailOtpWalletAuthDeps['configs'] {
  return {
    ...testConfigs(),
    network: {
      chains: [
        {
          network: 'tempo-testnet',
          chainId: TEMPO_TARGET.chainId,
          rpcUrl: 'https://tempo.example',
        },
        {
          network: EVM_TARGET.networkSlug,
          chainId: EVM_TARGET.chainId,
          rpcUrl: 'https://evm.example',
        },
      ],
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

function successfulEcdsaRegistrationResult(walletId: string): RegistrationResult {
  return {
    success: true,
    kind: 'ecdsa_wallet_registered',
    walletId: walletIdFromString(walletId),
    thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
    thresholdEcdsaPublicKeyB64u: 'public-key',
  };
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
      return successfulEcdsaRegistrationResult('alice.testnet');
    });
  const deps: GoogleEmailOtpWalletAuthDeps = {
    configs: testConfigs(),
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
                    delivery: {
                      kind: 'provider',
                      status: 'sent',
                      emailHint: 'alice@example.com',
                    },
                    challengeId: 'login-challenge-1',
                    emailHint: 'alice@example.com',
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                  },
                },
        },
        jwt: APP_SESSION_JWT,
      } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
    },
    requestEmailOtpChallenge: async (args) => {
      calls.push({ type: 'requestEmailOtpChallenge', args });
      return {
        challengeId: 'login-challenge-1',
        otpChannel: 'email_otp',
        delivery: {
          kind: 'provider',
          status: 'sent',
          emailHint: 'alice@example.com',
        },
        emailHint: 'alice@example.com',
      };
    },
    registerWallet: registerWalletImpl,
    loginWithEmailOtpEcdsaCapability: async (args) => {
      calls.push({ type: 'loginWithEmailOtpEcdsaCapability', args });
      return { success: true } as unknown as Awaited<
        ReturnType<GoogleEmailOtpWalletAuthDeps['loginWithEmailOtpEcdsaCapability']>
      >;
    },
    loginWithEmailOtpEd25519YaoCapability: async (args) => {
      calls.push({ type: 'loginWithEmailOtpEd25519YaoCapability', args });
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
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);

    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(true);
    if (!completed.ok) throw new Error(completed.error.message);
    expect(completed.value.walletId).toBe('alice.testnet');
    expect(completed.value.mode).toBe('register');
    expect(JSON.stringify(completed.value)).not.toContain('recoveryKeys');
    expect(JSON.stringify(completed.value)).not.toContain(APP_SESSION_JWT);
    const registerCall = calls.find((call) => call.type === 'registerWallet');
    expect(registerCall?.args).toMatchObject({
      wallet: { kind: 'provided', walletId: 'alice.testnet' },
      authMethod: {
        kind: 'email_otp',
        proofKind: 'google_sso_registration',
        email: 'alice@example.com',
        appSessionJwt: APP_SESSION_JWT,
        googleEmailOtpRegistrationAttemptId: 'registration-attempt-1',
        googleEmailOtpRegistrationOfferId: 'registration-offer-1',
        googleEmailOtpRegistrationCandidateId: 'registration-candidate-1',
      },
    });
    expect(registerCall?.args).toMatchObject({
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: {
              kind: 'implicit_account',
            },
          },
        ],
      },
    });
    expect(JSON.stringify(registerCall?.args)).not.toContain('code-1');
    expect(JSON.stringify(registerCall?.args)).not.toContain('recoveryKeys');
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'registerWallet',
      'getWalletSession',
    ]);
  });

  test('login without an Email OTP enrollment transitions to registration', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        if (args.accountMode === 'login') {
          throw Object.assign(new Error('Email OTP enrollment not found'), {
            code: 'not_found' as const,
          });
        }
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: makeRegisterResolution(),
          },
          jwt: APP_SESSION_JWT,
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      sessionKind: 'jwt',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value).toMatchObject({
      requestedMode: 'login',
      mode: 'register',
      state: 'registration_ready',
      walletId: 'alice.testnet',
    });
    expect(calls.map((call) => call.type)).toEqual([
      'exchangeGoogleEmailOtpSession',
      'exchangeGoogleEmailOtpSession',
    ]);
    expect(calls.map((call) => call.args)).toMatchObject([
      { accountMode: 'login' },
      { accountMode: 'register' },
    ]);
  });

  test('stale Google identity requires registration at the public SDK boundary', async () => {
    const { deps } = makeDeps({
      exchangeGoogleEmailOtpSession: async () => {
        throw Object.assign(new Error('No wallet is linked to this Google account yet.'), {
          code: 'stale_identity_mapping' as const,
        });
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      sessionKind: 'jwt',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started).toEqual({
      ok: false,
      error: {
        code: 'google_account_registration_required',
        message: 'No wallet is linked to this Google account yet.',
      },
    });
  });

  test('register path uses the selected offer candidate instead of a stale exchange wallet id', async () => {
    const { deps, calls } = makeDeps({
      exchangeGoogleEmailOtpSession: async (args) => {
        calls.push({ type: 'exchangeGoogleEmailOtpSession', args });
        return {
          session: {
            userId: 'google-subject-1',
            walletId: 'stale-wallet.testnet',
            email: 'alice@example.com',
            googleEmailOtpResolution: makeRegisterResolution({
              walletId: 'alice-2.testnet',
              attemptId: 'registration-attempt-1',
            }),
          },
          jwt: APP_SESSION_JWT,
        } as Awaited<ReturnType<GoogleEmailOtpWalletAuthDeps['exchangeGoogleEmailOtpSession']>>;
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
    expect(started.value.walletId).toBe('alice-2.testnet');

    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(true);
    if (!completed.ok) throw new Error(completed.error.message);
    expect(completed.value.walletId).toBe('alice-2.testnet');
    const registerCall = calls.find((call) => call.type === 'registerWallet');
    expect(registerCall?.args).toMatchObject({
      wallet: { kind: 'provided', walletId: 'alice-2.testnet' },
      authMethod: {
        googleEmailOtpRegistrationCandidateId: 'registration-candidate-2',
      },
    });
    expect(calls.at(-1)).toMatchObject({
      type: 'getWalletSession',
      args: { walletId: 'alice-2.testnet' },
    });
    expect(JSON.stringify(calls)).not.toContain('stale-wallet.testnet');
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
          jwt: APP_SESSION_JWT,
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
          jwt: APP_SESSION_JWT,
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
    const ed25519Call = calls.find((call) => call.type === 'loginWithEmailOtpEd25519YaoCapability');
    expect(ed25519Call?.args).toMatchObject({
      challengeId: 'login-challenge-1',
      otpCode: '123456',
      remainingUses: 3,
      appSessionJwt: APP_SESSION_JWT,
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
    expect(
      calls.find((call) => call.type === 'loginWithEmailOtpEd25519YaoCapability'),
    ).toBeTruthy();
    expect(calls.find((call) => call.type === 'loginWithEmailOtpEcdsaCapability')).toBeFalsy();
  });

  test('login path restores configured ECDSA targets independently from registration provisioning defaults', async () => {
    const { deps, calls } = makeDeps({
      configs: testConfigsWithConfiguredEcdsaChains(),
    });
    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    const submitted = await started.value.submit({ otpCode: '123456' });

    expect(submitted.ok).toBe(true);
    const loginCall = calls.find((call) => call.type === 'loginWithEmailOtpEcdsaCapability');
    expect(loginCall?.args).toMatchObject({
      chainTarget: TEMPO_TARGET,
      publicationChainTargets: [TEMPO_TARGET, EVM_TARGET],
      challengeId: 'login-challenge-1',
      otpCode: '123456',
    });
    expect(calls.find((call) => call.type === 'loginWithEmailOtpEd25519YaoCapability')).toBeFalsy();
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
                delivery: {
                  kind: 'provider',
                  status: 'reused',
                  emailHint: 'alice@example.com',
                },
                challengeId: 'login-challenge-reused-1',
                emailHint: 'a***@example.com',
              },
            },
          },
          jwt: APP_SESSION_JWT,
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
          jwt: APP_SESSION_JWT,
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
          jwt: APP_SESSION_JWT,
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
                delivery: {
                  kind: 'provider',
                  status: 'sent',
                  emailHint: 'alice@example.com',
                },
                challengeId: 'login-challenge-1',
                emailHint: 'alice@example.com',
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
              },
            },
          },
          jwt: APP_SESSION_JWT,
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
                delivery: {
                  kind: 'provider',
                  status: 'sent',
                  emailHint: 'alice@example.com',
                },
                challengeId: 'login-challenge-1',
                emailHint: 'alice@example.com',
                expiresAt: new Date(Date.now() + 60_000).toISOString(),
              },
            },
          },
          jwt: APP_SESSION_JWT,
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
        'This Email OTP wallet is not available on this device. Recover the wallet to continue.',
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
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET, EVM_TARGET] },
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
        kind: 'signer_set',
        signers: [
          { kind: 'near_ed25519' },
          {
            kind: 'evm_family_ecdsa',
            chainTargets: [TEMPO_TARGET, EVM_TARGET],
          },
        ],
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
    expect(JSON.stringify(completed)).not.toContain(APP_SESSION_JWT);
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
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);
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
          jwt: APP_SESSION_JWT,
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
    expect(calls.map((call) => call.type)).toEqual(['exchangeGoogleEmailOtpSession']);

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
          jwt: APP_SESSION_JWT,
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

  test('explicit demo delivery invokes the dedicated callback exactly once', async () => {
    const demoResponses: DemoEmailOtpCodeResponse[] = [];
    const events: unknown[] = [];
    const { deps } = makeDeps({
      exchangeGoogleEmailOtpSession: async () => ({
        session: {
          userId: 'google-subject-1',
          walletId: 'alice.testnet',
          email: 'alice@example.com',
          googleEmailOtpResolution: {
            mode: 'existing_wallet',
            loginChallenge: {
              delivery: {
                kind: 'demo_code_response',
                status: 'sent',
                emailHint: 'a***@example.test',
                otpCode: '123456',
              },
              challengeId: 'login-challenge-demo-1',
              emailHint: 'a***@example.test',
            },
          },
        },
        jwt: APP_SESSION_JWT,
      }),
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
      onDemoOtp: (response) => demoResponses.push(response),
      onEvent: (event) => events.push(event),
    });

    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    expect(demoResponses).toEqual([
      {
        kind: 'demo_code_response',
        status: 'sent',
        emailHint: 'a***@example.test',
        otpCode: '123456',
      },
    ]);
    expect(started.value.delivery).toEqual(demoResponses[0]);
    expect(JSON.stringify(events)).not.toContain('123456');
  });

  test('provider delivery never invokes the demo callback', async () => {
    const demoResponses: DemoEmailOtpCodeResponse[] = [];
    const { deps } = makeDeps();

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
      onDemoOtp: (response) => demoResponses.push(response),
    });

    expect(started.ok).toBe(true);
    expect(demoResponses).toEqual([]);
  });

  test('resend emits one replacement demo response through the same callback', async () => {
    const demoResponses: DemoEmailOtpCodeResponse[] = [];
    const { deps } = makeDeps({
      requestEmailOtpChallenge: async () => ({
        challengeId: 'login-challenge-demo-resend',
        otpChannel: 'email_otp',
        delivery: {
          kind: 'provider_and_demo_code',
          status: 'sent',
          emailHint: 'a***@example.test',
          otpCode: '654321',
        },
        emailHint: 'a***@example.test',
      }),
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
      onDemoOtp: (response) => demoResponses.push(response),
    });
    expect(started.ok).toBe(true);
    if (!started.ok || started.value.mode !== 'login') throw new Error('expected login flow');
    expect(demoResponses).toEqual([]);

    const resent = await started.value.resend();

    expect(resent.ok).toBe(true);
    expect(demoResponses).toEqual([
      {
        kind: 'provider_and_demo_code',
        status: 'sent',
        emailHint: 'a***@example.test',
        otpCode: '654321',
      },
    ]);
  });
});
