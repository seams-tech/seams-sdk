import { expect, test } from '@playwright/test';
import {
  beginGoogleEmailOtpWalletAuth,
  type GoogleEmailOtpWalletAuthDeps,
} from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  DemoEmailOtpCodeResponse,
  EmailOtpChallengeDelivery,
  EmailOtpUnlockSignerSelection,
  GoogleEmailOtpProviderResolution,
} from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { RegistrationResult } from '@/core/types/seams';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { activeWalletSessionFixture } from './helpers/walletSessionReadProjection.fixtures';

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

const ECDSA_SIGNER_SELECTION = {
  kind: 'ecdsa',
  keyHandle: 'ecdsa-key-handle-1',
  runtimePolicyScope: TEST_RUNTIME_POLICY_SCOPE,
} as const satisfies EmailOtpUnlockSignerSelection;

const ED25519_SIGNER_SELECTION = {
  kind: 'ed25519_only',
} as const satisfies EmailOtpUnlockSignerSelection;

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
  return activeWalletSessionFixture({ walletId, nearAccountId: walletId });
}

function makeRegisterResolution(
  input: {
    walletId?: string;
    selectedWalletId?: string;
    attemptId?: string;
    expiresAtMs?: number;
  } = {},
): Extract<GoogleEmailOtpProviderResolution, { mode: 'register_started' }> {
  const walletId = input.walletId ?? 'alice.testnet';
  const selectedWalletId = input.selectedWalletId ?? input.walletId ?? 'alice.testnet';
  const candidates = [
    { candidateId: 'registration-candidate-1', walletId: 'alice.testnet' },
    { candidateId: 'registration-candidate-2', walletId: 'alice-2.testnet' },
  ] as const;
  return {
    mode: 'register_started',
    walletId,
    providerSubject: 'google-subject-1',
    email: 'alice@example.com',
    registrationAttemptId: input.attemptId ?? 'registration-attempt-1',
    expiresAtMs: input.expiresAtMs ?? Date.now() + 60_000,
    offer: {
      offerId: 'registration-offer-1',
      selectedCandidateId:
        selectedWalletId === 'alice-2.testnet'
          ? 'registration-candidate-2'
          : 'registration-candidate-1',
      candidates,
    },
  };
}

function makeExistingResolution(
  input: {
    walletId?: string;
  } = {},
): Extract<GoogleEmailOtpProviderResolution, { mode: 'existing_wallet' }> {
  return {
    mode: 'existing_wallet',
    walletId: input.walletId ?? 'alice.testnet',
    providerSubject: 'google-subject-1',
    email: 'alice@example.com',
    hasEmailOtpEnrollment: true,
  };
}

function challengeResult(
  input: {
    challengeId?: string;
    delivery?: EmailOtpChallengeDelivery;
    walletAuthMethodId?: string;
    signerSelection?: EmailOtpUnlockSignerSelection;
  } = {},
) {
  const delivery =
    input.delivery ??
    ({
      kind: 'provider',
      status: 'sent',
      emailHint: 'alice@example.com',
    } as const);
  return {
    challengeId: input.challengeId ?? 'login-challenge-1',
    otpChannel: 'email_otp' as const,
    delivery,
    emailHint: delivery.emailHint,
    ownerProofBindingDigest: 'owner-proof-binding-1',
    walletAuthMethodId: input.walletAuthMethodId ?? 'email-otp-method-1',
    signerSelection: input.signerSelection ?? ECDSA_SIGNER_SELECTION,
  };
}

function successfulEcdsaRegistrationResult(walletId: string): RegistrationResult {
  return {
    success: true,
    kind: 'wallet_registered',
    walletId: walletIdFromString(walletId),
    capabilities: [
      {
        kind: 'evm_family_ecdsa',
        thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
        thresholdEcdsaPublicKeyB64u: 'public-key',
      },
    ],
  };
}

function makeDeps(overrides: Partial<GoogleEmailOtpWalletAuthDeps> = {}): {
  deps: GoogleEmailOtpWalletAuthDeps;
  calls: Array<{ type: string; args: unknown }>;
} {
  const calls: Array<{ type: string; args: unknown }> = [];
  const resolveGoogleEmailOtpProvider =
    overrides.resolveGoogleEmailOtpProvider ??
    (async (args: Parameters<GoogleEmailOtpWalletAuthDeps['resolveGoogleEmailOtpProvider']>[0]) => {
      calls.push({ type: 'resolveGoogleEmailOtpProvider', args });
      return args.accountMode === 'register' ? makeRegisterResolution() : makeExistingResolution();
    });
  const requestEmailOtpChallenge =
    overrides.requestEmailOtpChallenge ??
    (async (args: Parameters<GoogleEmailOtpWalletAuthDeps['requestEmailOtpChallenge']>[0]) => {
      calls.push({ type: 'requestEmailOtpChallenge', args });
      return challengeResult();
    });
  const registerWallet =
    overrides.registerWallet ??
    (async (args: Parameters<GoogleEmailOtpWalletAuthDeps['registerWallet']>[0]) => {
      calls.push({ type: 'registerWallet', args });
      return successfulEcdsaRegistrationResult('alice.testnet');
    });
  const deps: GoogleEmailOtpWalletAuthDeps = {
    configs: overrides.configs ?? testConfigs(),
    resolveGoogleEmailOtpProvider,
    requestEmailOtpChallenge,
    prewarmEmailOtpYao:
      overrides.prewarmEmailOtpYao ??
      (async () => {
        calls.push({ type: 'prewarmEmailOtpYao', args: undefined });
      }),
    registerWallet,
    loginWithEmailOtpEcdsaCapability:
      overrides.loginWithEmailOtpEcdsaCapability ??
      (async (args) => {
        calls.push({ type: 'loginWithEmailOtpEcdsaCapability', args });
        return { success: true } as unknown as Awaited<
          ReturnType<GoogleEmailOtpWalletAuthDeps['loginWithEmailOtpEcdsaCapability']>
        >;
      }),
    loginWithEmailOtpEd25519YaoCapability:
      overrides.loginWithEmailOtpEd25519YaoCapability ??
      (async (args) => {
        calls.push({ type: 'loginWithEmailOtpEd25519YaoCapability', args });
      }),
    getWalletSession:
      overrides.getWalletSession ??
      (async (walletId) => {
        calls.push({ type: 'getWalletSession', args: { walletId } });
        return loggedInSession(walletId);
      }),
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
      ecdsaTargets: { kind: 'none' },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value.mode).toBe('register');
    if (started.value.mode !== 'register') throw new Error('expected register flow');
    expect(started.value.state).toBe('registration_ready');
    expect(calls.map((call) => call.type)).toEqual([
      'resolveGoogleEmailOtpProvider',
      'prewarmEmailOtpYao',
    ]);

    const completed = await started.value.completeRegistration();

    expect(completed.ok).toBe(true);
    if (!completed.ok) throw new Error(completed.error.message);
    expect(completed.value.walletId).toBe('alice.testnet');
    expect(completed.value.mode).toBe('register');
    expect(JSON.stringify(completed.value)).not.toContain('recoveryKeys');
    const registerCall = calls.find((call) => call.type === 'registerWallet');
    expect(registerCall?.args).toMatchObject({
      wallet: { kind: 'provided', walletId: 'alice.testnet' },
      authMethod: {
        kind: 'email_otp',
        proofKind: 'google_sso_registration',
        email: 'alice@example.com',
        providerSubject: 'google-subject-1',
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
      'resolveGoogleEmailOtpProvider',
      'prewarmEmailOtpYao',
      'registerWallet',
      'getWalletSession',
    ]);
  });

  test('stale Google identity requires registration at the public SDK boundary', async () => {
    const { deps } = makeDeps({
      resolveGoogleEmailOtpProvider: async () => {
        throw Object.assign(new Error('No wallet is linked to this Google account yet.'), {
          code: 'stale_identity_mapping' as const,
        });
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
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

  test('explicit challenge failure stays a login failure', async () => {
    const { deps, calls } = makeDeps({
      requestEmailOtpChallenge: async (args) => {
        calls.push({ type: 'requestEmailOtpChallenge', args });
        throw Object.assign(new Error('Route not found'), {
          code: 'not_found' as const,
        });
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'login',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'none' },
    });

    expect(started).toEqual({
      ok: false,
      error: {
        code: 'email_otp_challenge_failed',
        message: 'Route not found',
      },
    });
    expect(calls.map((call) => call.type)).toEqual([
      'resolveGoogleEmailOtpProvider',
      'requestEmailOtpChallenge',
    ]);
  });

  test('register path uses the selected offer candidate instead of the provider wallet id', async () => {
    const { deps, calls } = makeDeps({
      resolveGoogleEmailOtpProvider: async (args) => {
        calls.push({ type: 'resolveGoogleEmailOtpProvider', args });
        return makeRegisterResolution({
          walletId: 'stale-wallet.testnet',
          selectedWalletId: 'alice-2.testnet',
        });
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
      resolveGoogleEmailOtpProvider: async (args) => {
        calls.push({ type: 'resolveGoogleEmailOtpProvider', args });
        const { expiresAtMs: _expiresAtMs, ...withoutExpiry } = makeRegisterResolution();
        return withoutExpiry as unknown as GoogleEmailOtpProviderResolution;
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
    expect(started.error.code).toBe('google_verification_failed');
    expect(started.error.message).toContain('expired or missing expiry');
    expect(calls.map((call) => call.type)).toEqual(['resolveGoogleEmailOtpProvider']);
  });

  test('register path fails closed when the offer expiry is malformed', async () => {
    const { deps, calls } = makeDeps({
      resolveGoogleEmailOtpProvider: async (args) => {
        calls.push({ type: 'resolveGoogleEmailOtpProvider', args });
        return {
          ...makeRegisterResolution(),
          expiresAtMs: 'not-a-date',
        } as unknown as GoogleEmailOtpProviderResolution;
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
    expect(started.error.code).toBe('google_verification_failed');
    expect(started.error.message).toContain('expired or missing expiry');
    expect(calls.map((call) => call.type)).toEqual(['resolveGoogleEmailOtpProvider']);
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
      'resolveGoogleEmailOtpProvider',
      'prewarmEmailOtpYao',
      'registerWallet',
    ]);
  });

  test('login path requests a challenge and propagates the exact ECDSA signer selection', async () => {
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
    expect(calls.map((call) => call.type)).toEqual([
      'resolveGoogleEmailOtpProvider',
      'requestEmailOtpChallenge',
    ]);

    const submitted = await started.value.submit({ otpCode: '123456' });

    expect(submitted.ok).toBe(true);
    if (!submitted.ok) throw new Error(submitted.error.message);
    expect(submitted.value.mode).toBe('login');
    const loginCall = calls.find((call) => call.type === 'loginWithEmailOtpEcdsaCapability');
    expect(loginCall?.args).toMatchObject({
      walletAuthMethodId: 'email-otp-method-1',
      chainTarget: TEMPO_TARGET,
      publicationChainTargets: [TEMPO_TARGET],
      keyHandle: 'ecdsa-key-handle-1',
      runtimePolicyScope: TEST_RUNTIME_POLICY_SCOPE,
      providerIdentity: {
        provider: 'google',
        providerSubjectId: 'google-subject-1',
      },
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
      walletAuthMethodId: 'email-otp-method-1',
      keyHandle: 'ecdsa-key-handle-1',
      runtimePolicyScope: TEST_RUNTIME_POLICY_SCOPE,
      challengeId: 'login-challenge-1',
      otpCode: '123456',
    });
  });

  test('login path supports Ed25519-only Email OTP wallets without ECDSA targets', async () => {
    const { deps, calls } = makeDeps({
      requestEmailOtpChallenge: async (args) => {
        calls.push({ type: 'requestEmailOtpChallenge', args });
        return challengeResult({ signerSelection: ED25519_SIGNER_SELECTION });
      },
    });
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
      walletSession: {
        walletId: 'alice.testnet',
        walletSessionUserId: 'alice.testnet',
      },
      authoritySelector: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: 'email-otp-method-1',
      },
      providerSubjectId: 'google-subject-1',
      emailOtpAuthorityEmail: 'alice@example.com',
    });
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
      walletAuthMethodId: 'email-otp-method-1',
      keyHandle: 'ecdsa-key-handle-1',
      runtimePolicyScope: TEST_RUNTIME_POLICY_SCOPE,
      challengeId: 'login-challenge-1',
      otpCode: '123456',
    });
    expect(calls.find((call) => call.type === 'loginWithEmailOtpEd25519YaoCapability')).toBeFalsy();
  });

  test('register request resolving to an existing wallet continues with login', async () => {
    const { deps, calls } = makeDeps({
      resolveGoogleEmailOtpProvider: async (args) => {
        calls.push({ type: 'resolveGoogleEmailOtpProvider', args });
        return makeExistingResolution();
      },
    });

    const started = await beginGoogleEmailOtpWalletAuth(deps, {
      idToken: 'google-id-token',
      mode: 'register',
      relayUrl: 'https://relay.example',
      ecdsaTargets: { kind: 'explicit', targets: [TEMPO_TARGET] },
    });

    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.error.message);
    expect(started.value.requestedMode).toBe('register');
    expect(started.value.mode).toBe('login');
    expect(calls.map((call) => call.type)).toEqual([
      'resolveGoogleEmailOtpProvider',
      'requestEmailOtpChallenge',
    ]);
    expect(calls[0]?.args).toMatchObject({
      idToken: 'google-id-token',
      accountMode: 'register',
      relayUrl: 'https://relay.example',
      restartRegistrationOffer: false,
    });
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
      'resolveGoogleEmailOtpProvider',
      'prewarmEmailOtpYao',
    ]);
    const staleCompletion = await started.value.completeRegistration();
    expect(staleCompletion.ok).toBe(false);
  });

  test('reroll failure leaves the registration flow active when no alternate candidate exists', async () => {
    const { deps } = makeDeps({
      resolveGoogleEmailOtpProvider: async () => ({
        ...makeRegisterResolution(),
        offer: {
          offerId: 'registration-offer-1',
          selectedCandidateId: 'registration-candidate-1',
          candidates: [{ candidateId: 'registration-candidate-1', walletId: 'alice.testnet' }],
        },
      }),
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
    let challengeRequests = 0;
    const { deps, calls } = makeDeps({
      requestEmailOtpChallenge: async (args) => {
        calls.push({ type: 'requestEmailOtpChallenge', args });
        challengeRequests += 1;
        if (challengeRequests > 1) throw new Error('Email OTP rate limit exceeded');
        return challengeResult();
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
      requestEmailOtpChallenge: async () =>
        challengeResult({
          delivery: {
            kind: 'demo_code_response',
            status: 'sent',
            emailHint: 'a***@example.test',
            otpCode: '123456',
          },
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
    let challengeRequests = 0;
    const { deps } = makeDeps({
      requestEmailOtpChallenge: async () => {
        challengeRequests += 1;
        return challengeResult({
          challengeId:
            challengeRequests === 1 ? 'login-challenge-provider' : 'login-challenge-demo-resend',
          delivery:
            challengeRequests === 1
              ? {
                  kind: 'provider',
                  status: 'sent',
                  emailHint: 'alice@example.com',
                }
              : {
                  kind: 'provider_and_demo_code',
                  status: 'sent',
                  emailHint: 'a***@example.test',
                  otpCode: '654321',
                },
        });
      },
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
