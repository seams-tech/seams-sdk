import type {
  EmailOtpAuthPolicy,
  RegistrationResult,
  SeamsConfigsReadonly,
  WalletSession,
} from '@/core/types/seams';
import type {
  RegistrationFlowEvent,
  RegistrationHooksOptions,
  UnlockFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseThresholdRuntimePolicyScopeFromJwt } from '@/core/signingEngine/threshold/sessionPolicy';
import { deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { listThresholdEcdsaProvisionTargets } from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import { buildNearWalletRegistrationSignerSetSelection } from '@/SeamsWeb/operations/registration/registrationSignerSet';
import { sponsoredNamedRegistrationProvisioningFromAccountId } from '@/SeamsWeb/operations/registration/registrationSignerSet';
import {
  disposeWalletRegistrationPrecompute,
  type WalletRegistrationPrecomputeHandle,
} from '@/SeamsWeb/operations/registration/registration';
import type {
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  GoogleEmailOtpSessionExchangeResult,
  GoogleEmailOtpRegistrationCandidate,
  GoogleEmailOtpRegistrationOffer,
  GoogleEmailOtpWalletAuthEcdsaTargets,
  GoogleEmailOtpWalletAuthFailure,
  GoogleEmailOtpWalletAuthFailureCode,
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthPromptCopy,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthRequestedMode,
  GoogleEmailOtpWalletAuthResolvedMode,
  GoogleEmailOtpWalletAuthResult,
  GoogleEmailOtpWalletAuthStartInput,
  GoogleEmailOtpWalletAuthSubmitSuccess,
  RegistrationCapability,
} from '@/SeamsWeb/publicApi/types';
import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import { parseGoogleEmailOtpRegistrationOffer } from './registrationOffer';
import {
  attachEmailOtpPrewarmedRegistrationMaterial,
  disposeEmailOtpPrewarmedRegistrationMaterial,
  type EmailOtpPrewarmedRegistrationMaterial,
  type EmailOtpRegistrationEnrollmentMaterial,
} from './prewarmedRegistrationMaterial';

const DEFAULT_FLOW_TTL_MS = 10 * 60 * 1000;

type GoogleEmailOtpWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0];

type GoogleEmailOtpWalletRegistrationPrecompute =
  | {
      kind: 'started';
      handle: WalletRegistrationPrecomputeHandle;
      unavailableReason?: never;
    }
  | {
      kind: 'unavailable';
      unavailableReason: 'wallet_iframe_registration_domain' | 'policy_disabled';
      handle?: never;
    };

type ActiveChallenge = {
  challengeId: string;
  emailHint: string;
};

type GoogleLoginEmailOtpEcdsaCapabilityArgs = EmailOtpEcdsaCapabilityArgs & {
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
};

type GoogleLoginEmailOtpEd25519CapabilityArgs = {
  walletSession: ReturnType<typeof walletSessionRefFromSession>;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  appSessionJwt?: string;
  onEvent?: (event: UnlockFlowEvent) => void;
};

type GoogleSessionState = {
  idToken: string;
  appSessionJwt?: string;
  walletId: WalletId;
  offer?: GoogleEmailOtpRegistrationOffer;
  loginChallenge?: ActiveChallenge;
  loginChallengeRateLimit?: {
    retryAfterMs?: number;
    resetAtMs?: number;
  };
  walletSessionUserId: string;
  emailHint: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
  registrationAttemptId?: string;
  expiresAtMs: number;
};

export type GoogleEmailOtpWalletAuthDeps = {
  configs: SeamsConfigsReadonly;
  exchangeGoogleEmailOtpSession(
    args: Parameters<RegistrationlessGoogleSessionExchange>[0],
  ): Promise<GoogleEmailOtpSessionExchangeResult>;
  requestEmailOtpChallenge(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult>;
  prepareEmailOtpRegistrationEnrollmentMaterial(args: {
    relayUrl?: string;
    walletId: string;
    userId: string;
    evmFamilySigningKeySlotId: string;
    appSessionJwt: string;
  }): Promise<EmailOtpRegistrationEnrollmentMaterial>;
  registerWallet(args: GoogleEmailOtpWalletRegistrationArgs): Promise<RegistrationResult>;
  startWalletRegistrationPrecompute(
    args: GoogleEmailOtpWalletRegistrationArgs,
  ): GoogleEmailOtpWalletRegistrationPrecompute;
  registerWalletWithStartedPrecompute(args: {
    registration: GoogleEmailOtpWalletRegistrationArgs;
    precompute: Extract<GoogleEmailOtpWalletRegistrationPrecompute, { kind: 'started' }>;
  }): Promise<RegistrationResult>;
  loginWithEmailOtpEcdsaCapability(
    args: GoogleLoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpEcdsaCapabilityResult>;
  loginWithEmailOtpEd25519Capability(
    args: GoogleLoginEmailOtpEd25519CapabilityArgs,
  ): Promise<unknown>;
  getWalletSession(walletId: string): Promise<WalletSession>;
};

type RegistrationlessGoogleSessionExchange = (args: {
  idToken: string;
  accountMode: 'register' | 'login';
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
}) => Promise<GoogleEmailOtpSessionExchangeResult>;

function ok<T>(value: T): GoogleEmailOtpWalletAuthResult<T> {
  return { ok: true, value };
}

function fail<T>(
  code: GoogleEmailOtpWalletAuthFailureCode,
  error: unknown,
): GoogleEmailOtpWalletAuthResult<T> {
  const message = error instanceof Error && error.message ? error.message : String(error || code);
  const retryAfterMs =
    error && typeof error === 'object' && 'retryAfterMs' in error
      ? Number((error as { retryAfterMs?: unknown }).retryAfterMs)
      : NaN;
  const failure: GoogleEmailOtpWalletAuthFailure = {
    code,
    message,
    ...(Number.isFinite(retryAfterMs) && retryAfterMs >= 0
      ? { retryAfterMs: Math.floor(retryAfterMs) }
      : {}),
  };
  return { ok: false, error: failure };
}

function failWithMessage<T>(
  code: GoogleEmailOtpWalletAuthFailureCode,
  message: string,
  error: unknown,
): GoogleEmailOtpWalletAuthResult<T> {
  const base = fail<T>(code, error);
  if (base.ok) return base;
  return {
    ok: false,
    error: {
      ...base.error,
      message,
    },
  };
}

function isEmailOtpDeviceRecoveryRequired(error: unknown): boolean {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '').toLowerCase()
      : '';
  if (code === 'email_otp_device_recovery_required') return true;
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error || '').toLowerCase();
  return (
    message.includes('email otp device-local enc_s(s) is missing') ||
    message.includes('email otp device-local enc_s(s) metadata mismatch')
  );
}

function emailOtpDeviceRecoveryRequiredMessage(): string {
  return 'This Email OTP wallet needs recovery on this device. Restore it with your recovery code to unlock.';
}

function classifyEmailOtpSubmitError(error: unknown): GoogleEmailOtpWalletAuthFailureCode {
  if (isEmailOtpDeviceRecoveryRequired(error)) return 'email_otp_device_recovery_required';
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '')
      : '';
  if (code.includes('rate')) return 'email_otp_rate_limited';
  if (code.includes('expired')) return 'email_otp_expired';
  if (code.includes('invalid') || code.includes('otp')) return 'email_otp_invalid_code';
  const message = error instanceof Error ? error.message.toLowerCase() : '';
  if (message.includes('backup')) return 'recovery_code_backup_incomplete';
  if (message.includes('expired')) return 'email_otp_expired';
  if (message.includes('invalid') || message.includes('code')) return 'email_otp_invalid_code';
  return 'unlock_failed';
}

function classifyRegistrationError(error: unknown): GoogleEmailOtpWalletAuthFailureCode {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '')
      : '';
  if (code === 'already_finalized_restore_required') return 'registration_restore_required';
  const message = error instanceof Error ? error.message.toLowerCase() : '';
  if (message.includes('already finalized') || message.includes('restore or unlock')) {
    return 'registration_restore_required';
  }
  if (message.includes('backup')) return 'recovery_code_backup_incomplete';
  if (message.includes('expired')) return 'flow_expired';
  return 'registration_failed';
}

function requireWalletId(exchange: GoogleEmailOtpSessionExchangeResult): WalletId {
  const walletId = String(exchange.session?.walletId || '').trim();
  if (!walletId) {
    throw new Error('Google session exchange did not return a wallet id');
  }
  return walletIdFromString(walletId);
}

function requireWalletSessionUserId(exchange: GoogleEmailOtpSessionExchangeResult): string {
  const userId = String(exchange.session?.userId || '').trim();
  if (!userId) {
    throw new Error('Google session exchange did not return a wallet session user id');
  }
  return userId;
}

function requireEmail(exchange: GoogleEmailOtpSessionExchangeResult): string {
  const email = String(exchange.session?.email || '').trim();
  if (!email) {
    throw new Error('Google session exchange did not return an email address');
  }
  return email;
}

function parseOptionalExpiresAtMs(value?: number | string): number {
  const parsed =
    typeof value === 'number' ? value : typeof value === 'string' ? Date.parse(value) : NaN;
  return Number.isFinite(parsed) && parsed > Date.now() ? parsed : Date.now() + DEFAULT_FLOW_TTL_MS;
}

function requireRegistrationExpiresAtMs(value: unknown): number {
  const parsed =
    typeof value === 'number' ? value : typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || parsed <= Date.now()) {
    throw new Error('Google Email OTP registration offer is expired or missing expiry');
  }
  return Math.floor(parsed);
}

function buildPrompt(input: {
  mode: GoogleEmailOtpWalletAuthResolvedMode;
  emailHint: string;
}): GoogleEmailOtpWalletAuthPromptCopy {
  if (input.mode === 'register') {
    return {
      title: 'Create your Email OTP wallet',
      description: `Google verified ${input.emailHint}.`,
      submitLabel: 'Create wallet',
      helperText: 'Choose this wallet name or generate another one before creating the wallet.',
    };
  }
  return {
    title: 'Check your email to unlock your wallet',
    description: `Enter the 6-digit code we sent to ${input.emailHint}.`,
    submitLabel: 'Unlock wallet',
    helperText:
      'Google keeps you signed in. The email code unlocks wallet signing for this session.',
  };
}

function resolveGoogleEmailOtpAuthMode(input: {
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  resolutionMode: 'existing_wallet' | 'register_started' | undefined;
}): GoogleEmailOtpWalletAuthResolvedMode {
  if (input.requestedMode === 'register') {
    if (input.resolutionMode === 'register_started') return 'register';
    throw new Error('Google Email OTP registration did not return a registration offer');
  }
  if (input.resolutionMode === 'register_started') {
    throw new Error('Google Email OTP login returned a registration offer');
  }
  return 'login';
}

function resolveSessionState(input: {
  idToken: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  exchange: GoogleEmailOtpSessionExchangeResult;
}): GoogleSessionState {
  const walletId = requireWalletId(input.exchange);
  const emailHint = requireEmail(input.exchange);
  const resolution = input.exchange.session.googleEmailOtpResolution;
  const mode = resolveGoogleEmailOtpAuthMode({
    requestedMode: input.requestedMode,
    resolutionMode: resolution?.mode,
  });
  const offer =
    mode === 'register'
      ? parseGoogleEmailOtpRegistrationOffer({
          kind: 'google_email_otp_registration_offer_v1',
          offerId: resolution?.offer?.offerId,
          expiresAtMs: requireRegistrationExpiresAtMs(
            resolution?.expiresAtMs ?? resolution?.expiresAt,
          ),
          emailHint,
          candidates: resolution?.offer?.candidates,
          selectedCandidateId: resolution?.offer?.selectedCandidateId,
        })
      : undefined;
  const loginChallengeRaw = mode === 'login' ? resolution?.loginChallenge : undefined;
  const loginChallenge =
    loginChallengeRaw?.delivery === 'sent' || loginChallengeRaw?.delivery === 'reused'
      ? {
          challengeId: loginChallengeRaw.challengeId,
          emailHint: loginChallengeRaw.emailHint || emailHint,
        }
      : undefined;
  const loginChallengeRateLimit =
    loginChallengeRaw?.delivery === 'rate_limited'
      ? {
          ...(typeof loginChallengeRaw.retryAfterMs === 'number'
            ? { retryAfterMs: loginChallengeRaw.retryAfterMs }
            : {}),
          ...(typeof loginChallengeRaw.resetAtMs === 'number'
            ? { resetAtMs: loginChallengeRaw.resetAtMs }
            : {}),
        }
      : undefined;
  return {
    idToken: input.idToken,
    walletId,
    ...(offer ? { offer } : {}),
    ...(loginChallenge ? { loginChallenge } : {}),
    ...(loginChallengeRateLimit ? { loginChallengeRateLimit } : {}),
    walletSessionUserId: requireWalletSessionUserId(input.exchange),
    emailHint,
    requestedMode: input.requestedMode,
    mode,
    expiresAtMs:
      mode === 'register'
        ? requireRegistrationExpiresAtMs(resolution?.expiresAtMs ?? resolution?.expiresAt)
        : parseOptionalExpiresAtMs(resolution?.expiresAtMs ?? resolution?.expiresAt),
    ...(input.exchange.jwt ? { appSessionJwt: input.exchange.jwt } : {}),
    ...(resolution?.registrationAttemptId
      ? { registrationAttemptId: resolution.registrationAttemptId }
      : {}),
  };
}

function rotateOfferCandidate(args: {
  offer: GoogleEmailOtpRegistrationOffer;
  currentWalletId: WalletId;
}): GoogleEmailOtpRegistrationCandidate | null {
  const currentIndex = args.offer.candidates.findIndex(
    (candidate) => candidate.walletId === args.currentWalletId,
  );
  if (currentIndex < 0 || args.offer.candidates.length < 2) return null;
  return args.offer.candidates[(currentIndex + 1) % args.offer.candidates.length] || null;
}

async function requestLoginChallenge(args: {
  deps: GoogleEmailOtpWalletAuthDeps;
  state: GoogleSessionState;
  relayUrl?: string;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
}): Promise<ActiveChallenge> {
  const result = await args.deps.requestEmailOtpChallenge({
    walletId: args.state.walletId,
    ...(args.relayUrl ? { relayUrl: args.relayUrl } : {}),
    ...(args.state.appSessionJwt ? { appSessionJwt: args.state.appSessionJwt } : {}),
    ...(args.onEvent ? { onEvent: args.onEvent as (event: UnlockFlowEvent) => void } : {}),
  });
  return {
    challengeId: result.challengeId,
    emailHint: result.emailHint || args.state.emailHint,
  };
}

function resolveEcdsaTargets(args: {
  configs: SeamsConfigsReadonly;
  policy?: GoogleEmailOtpWalletAuthEcdsaTargets;
}): readonly ThresholdEcdsaChainTarget[] {
  const policy = args.policy || { kind: 'configured' as const };
  if (policy.kind === 'none') return [];
  if (policy.kind === 'explicit') return policy.targets;
  return listThresholdEcdsaProvisionTargets({
    signerOptions: args.configs.signing.thresholdEcdsa.provisioningDefaults,
    chains: args.configs.network.chains,
  }).map((target) => target.chainTarget);
}

function eventOnlyRegistrationOptions(args: {
  onEvent?: GoogleEmailOtpWalletAuthStartInput['onEvent'];
}): RegistrationHooksOptions {
  return {
    ...(args.onEvent ? { onEvent: args.onEvent as (event: RegistrationFlowEvent) => void } : {}),
  };
}

async function loginWithConfiguredTargets(args: {
  deps: GoogleEmailOtpWalletAuthDeps;
  state: GoogleSessionState;
  input: GoogleEmailOtpWalletAuthStartInput;
  challenge: ActiveChallenge;
  otpCode: string;
  targets: readonly ThresholdEcdsaChainTarget[];
}): Promise<void> {
  const walletSession = walletSessionRefFromSession({
    walletId: args.state.walletId,
    userId: args.state.walletSessionUserId,
  });
  const common = {
    walletSession,
    challengeId: args.challenge.challengeId,
    otpCode: args.otpCode,
    ...(args.input.relayUrl ? { relayUrl: args.input.relayUrl } : {}),
    ...(args.state.appSessionJwt ? { appSessionJwt: args.state.appSessionJwt } : {}),
    ...(args.input.emailOtpAuthPolicy ? { emailOtpAuthPolicy: args.input.emailOtpAuthPolicy } : {}),
    ...(args.input.onEvent
      ? { onEvent: args.input.onEvent as (event: UnlockFlowEvent) => void }
      : {}),
  };
  const [primaryTarget] = args.targets;
  if (!primaryTarget) {
    await args.deps.loginWithEmailOtpEd25519Capability(common);
    return;
  }
  await args.deps.loginWithEmailOtpEcdsaCapability({
    ...common,
    chainTarget: primaryTarget,
    publicationChainTargets: args.targets,
  });
}

function registrationOptionsForNoEcdsa(args: {
  options: RegistrationHooksOptions;
}): RegistrationHooksOptions {
  return {
    ...args.options,
    signerOptions: {
      tempo: { enabled: false, signingSession: { kind: 'jwt', ttlMs: 0, remainingUses: 0 } },
      evm: { enabled: false, signingSession: { kind: 'jwt', ttlMs: 0, remainingUses: 0 } },
    },
  };
}

async function assertLoggedIn(
  deps: GoogleEmailOtpWalletAuthDeps,
  walletId: WalletId,
): Promise<WalletSession> {
  const session = await deps.getWalletSession(walletId);
  if (!session.login.isLoggedIn) {
    throw new Error('Wallet auth completed, but the local signing session is not ready yet.');
  }
  return session;
}

export async function beginGoogleEmailOtpWalletAuth(
  deps: GoogleEmailOtpWalletAuthDeps,
  input: GoogleEmailOtpWalletAuthStartInput,
): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>> {
  let sessionState: GoogleSessionState;
  try {
    const exchange = await deps.exchangeGoogleEmailOtpSession({
      idToken: input.idToken,
      accountMode: input.mode,
      ...(input.relayUrl ? { relayUrl: input.relayUrl } : {}),
      ...(input.sessionKind ? { sessionKind: input.sessionKind } : {}),
      ...(input.onEvent ? { onEvent: input.onEvent } : {}),
    });
    sessionState = resolveSessionState({
      idToken: input.idToken,
      requestedMode: input.mode,
      exchange,
    });
  } catch (error: unknown) {
    return fail('google_exchange_failed', error);
  }

  if (sessionState.mode === 'register') {
    return ok(createGoogleEmailOtpWalletRegistrationFlow(deps, { state: sessionState, input }));
  }

  try {
    if (sessionState.loginChallengeRateLimit) {
      const error = new Error('Email OTP challenge is rate limited') as Error & {
        retryAfterMs?: number;
      };
      if (typeof sessionState.loginChallengeRateLimit.retryAfterMs === 'number') {
        error.retryAfterMs = sessionState.loginChallengeRateLimit.retryAfterMs;
      }
      return fail('email_otp_rate_limited', error);
    }
    const challenge =
      sessionState.loginChallenge ||
      (await requestLoginChallenge({
        deps,
        state: sessionState,
        ...(input.relayUrl ? { relayUrl: input.relayUrl } : {}),
        ...(input.onEvent ? { onEvent: input.onEvent } : {}),
      }));
    return ok(createGoogleEmailOtpWalletLoginFlow(deps, { state: sessionState, challenge, input }));
  } catch (error: unknown) {
    return fail('email_otp_challenge_failed', error);
  }
}

function createFlowLiveness(args: { state: GoogleSessionState }): {
  ensureActive(): void;
  burn(): void;
} {
  let active = true;
  return {
    ensureActive() {
      if (!active) throw new Error('Google Email OTP wallet auth flow is no longer active');
      if (Date.now() > args.state.expiresAtMs) {
        active = false;
        throw new Error('Google Email OTP wallet auth flow expired');
      }
    },
    burn() {
      active = false;
    },
  };
}

function relayerUrlFromInput(args: {
  deps: GoogleEmailOtpWalletAuthDeps;
  input: GoogleEmailOtpWalletAuthStartInput;
}): string {
  return String(args.input.relayUrl || args.deps.configs.network.relayer?.url || '').trim();
}

function googleEmailOtpRegistrationAppSessionJwt(state: GoogleSessionState): string {
  const appSessionJwt = String(state.appSessionJwt || '').trim();
  if (!appSessionJwt) {
    throw new Error('Google Email OTP registration requires an app session token');
  }
  return appSessionJwt;
}

function googleEmailOtpRegistrationWalletKeyId(args: {
  walletId: WalletId;
  appSessionJwt: string;
}): string {
  const runtimePolicyScope = parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt);
  if (!runtimePolicyScope) {
    throw new Error('Google Email OTP registration prewarm requires runtime policy scope');
  }
  return String(
    deriveEvmFamilySigningKeySlotIdFromRuntimePolicyScope({
      walletId: args.walletId,
      runtimePolicyScope,
    }),
  );
}

function createRegistrationMaterialPrewarm(args: {
  deps: GoogleEmailOtpWalletAuthDeps;
  state: GoogleSessionState;
  input: GoogleEmailOtpWalletAuthStartInput;
  offer: GoogleEmailOtpRegistrationOffer;
}): {
  read(): Promise<Extract<EmailOtpPrewarmedRegistrationMaterial, { state: 'active' }>>;
  dispose(): void;
} {
  let disposed = false;
  let resolved: EmailOtpPrewarmedRegistrationMaterial | null = null;
  const selectedCandidate = args.offer.candidates.find(
    (candidate) => candidate.candidateId === args.offer.selectedCandidateId,
  );
  if (!selectedCandidate) {
    throw new Error('Google Email OTP registration offer selected candidate is missing');
  }
  const appSessionJwt = googleEmailOtpRegistrationAppSessionJwt(args.state);
  const evmFamilySigningKeySlotId = googleEmailOtpRegistrationWalletKeyId({
    walletId: selectedCandidate.walletId,
    appSessionJwt,
  });
  const promise = args.deps
    .prepareEmailOtpRegistrationEnrollmentMaterial({
      relayUrl: relayerUrlFromInput({ deps: args.deps, input: args.input }),
      walletId: selectedCandidate.walletId,
      userId: args.state.walletSessionUserId,
      evmFamilySigningKeySlotId,
      appSessionJwt,
    })
    .then((material) => {
      const prewarmed: EmailOtpPrewarmedRegistrationMaterial = {
        kind: 'email_otp_prewarmed_registration_material_v1',
        state: 'active',
        offerId: args.offer.offerId,
        candidateId: selectedCandidate.candidateId,
        walletId: selectedCandidate.walletId,
        providerSubject: args.state.walletSessionUserId,
        material,
      };
      if (disposed) {
        disposeEmailOtpPrewarmedRegistrationMaterial(prewarmed);
      } else {
        resolved = prewarmed;
      }
      return prewarmed;
    });
  void promise.catch(() => undefined);
  return {
    async read() {
      const prewarmed = await promise;
      if (disposed || prewarmed.state !== 'active') {
        throw new Error('Google Email OTP registration material is no longer active');
      }
      return prewarmed;
    },
    dispose() {
      disposed = true;
      disposeEmailOtpPrewarmedRegistrationMaterial(resolved);
      resolved = null;
    },
  };
}

function createGoogleEmailOtpWalletRegistrationFlow(
  deps: GoogleEmailOtpWalletAuthDeps,
  args: {
    state: GoogleSessionState;
    input: GoogleEmailOtpWalletAuthStartInput;
  },
): GoogleEmailOtpWalletAuthRegistrationFlow {
  const registrationAttemptId = String(args.state.registrationAttemptId || '').trim();
  if (!registrationAttemptId) {
    throw new Error('Google Email OTP registration requires a registration attempt id');
  }
  if (!args.state.offer) {
    throw new Error('Google Email OTP registration requires an offer');
  }
  const offer = args.state.offer;
  const prewarm = createRegistrationMaterialPrewarm({
    deps,
    state: args.state,
    input: args.input,
    offer,
  });
  const requiredTargets = resolveEcdsaTargets({
    configs: deps.configs,
    policy: args.input.ecdsaTargets,
  });
  const eventOptions = eventOnlyRegistrationOptions({ onEvent: args.input.onEvent });
  const registrationOptions = requiredTargets.length
    ? eventOptions
    : registrationOptionsForNoEcdsa({ options: eventOptions });
  const appSessionJwt = (() => {
    const value = String(args.state.appSessionJwt || '').trim();
    if (!value) throw new Error('Google Email OTP registration requires an app session token');
    return value;
  })();
  const registrationAuthMethod = {
    kind: 'email_otp',
    proofKind: 'google_sso_registration',
    email: args.state.emailHint,
    appSessionJwt,
    googleEmailOtpRegistrationAttemptId: registrationAttemptId,
    googleEmailOtpRegistrationOfferId: offer.offerId,
    googleEmailOtpRegistrationCandidateId: offer.selectedCandidateId,
  } satisfies GoogleEmailOtpWalletRegistrationArgs['authMethod'];
  const registrationArgs: GoogleEmailOtpWalletRegistrationArgs = {
    wallet: { kind: 'provided', walletId: args.state.walletId },
    authMethod: registrationAuthMethod,
    signerSelection: buildNearWalletRegistrationSignerSetSelection({
      configs: deps.configs,
      accountProvisioning: sponsoredNamedRegistrationProvisioningFromAccountId(args.state.walletId),
      options: registrationOptions,
      ecdsaChainTargets: requiredTargets,
    }),
    options: registrationOptions,
  };
  const precompute = deps.startWalletRegistrationPrecompute(registrationArgs);
  const disposePrecompute = (): void => {
    if (precompute.kind === 'started') {
      disposeWalletRegistrationPrecompute(precompute.handle);
    }
  };
  const liveness = createFlowLiveness({ state: args.state });
  const flowId = `google-email-otp-registration:${args.state.walletId}:${registrationAttemptId}`;
  return {
    kind: 'google_email_otp_wallet_auth_flow_v1',
    state: 'registration_ready',
    flowId,
    requestedMode: args.state.requestedMode,
    mode: 'register',
    walletId: args.state.walletId,
    emailHint: args.state.emailHint,
    prompt: buildPrompt({ mode: 'register', emailHint: args.state.emailHint }),
    expiresAtMs: args.state.expiresAtMs,
    completeRegistration: async (): Promise<
      GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationCompleted>
    > => {
      try {
        liveness.ensureActive();
        const prewarmed = await prewarm.read();
        const registrationWithPrewarmedMaterial: GoogleEmailOtpWalletRegistrationArgs = {
          ...registrationArgs,
          authMethod: attachEmailOtpPrewarmedRegistrationMaterial({
            authMethod: registrationAuthMethod,
            prewarmed,
          }),
        };
        const result =
          precompute.kind === 'started'
            ? await deps.registerWalletWithStartedPrecompute({
                registration: registrationWithPrewarmedMaterial,
                precompute,
              })
            : await deps.registerWallet(registrationWithPrewarmedMaterial);
        if (!result.success) {
          const error = Object.assign(new Error(result.error || 'Wallet registration failed'), {
            code: result.errorCode,
          });
          return fail(classifyRegistrationError(error), error);
        }
        liveness.burn();
        const session = await assertLoggedIn(deps, args.state.walletId);
        return ok({ walletId: args.state.walletId, mode: 'register', session });
      } catch (error: unknown) {
        return fail(classifyRegistrationError(error), error);
      } finally {
        prewarm.dispose();
        disposePrecompute();
      }
    },
    rerollWalletId: async (): Promise<
      GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationFlow>
    > => {
      try {
        liveness.ensureActive();
        if (!args.state.offer) {
          return fail(
            'google_exchange_failed',
            new Error('Google Email OTP registration offer is missing wallet candidates'),
          );
        }
        const nextCandidate = rotateOfferCandidate({
          offer: args.state.offer,
          currentWalletId: args.state.walletId,
        });
        if (!nextCandidate) {
          return fail(
            'google_exchange_failed',
            new Error('Google Email OTP registration offer has no alternate wallet candidate'),
          );
        }
        prewarm.dispose();
        disposePrecompute();
        liveness.burn();
        return ok(
          createGoogleEmailOtpWalletRegistrationFlow(deps, {
            state: {
              ...args.state,
              walletId: nextCandidate.walletId,
              offer: {
                ...args.state.offer,
                selectedCandidateId: nextCandidate.candidateId,
              },
            },
            input: args.input,
          }),
        );
      } catch (error: unknown) {
        return fail('google_exchange_failed', error);
      }
    },
    cancel: async (): Promise<void> => {
      prewarm.dispose();
      disposePrecompute();
      liveness.burn();
    },
  };
}

function createGoogleEmailOtpWalletLoginFlow(
  deps: GoogleEmailOtpWalletAuthDeps,
  args: {
    state: GoogleSessionState;
    challenge: ActiveChallenge;
    input: GoogleEmailOtpWalletAuthStartInput;
  },
): GoogleEmailOtpWalletAuthFlow {
  const liveness = createFlowLiveness({ state: args.state });
  const flowId = `google-email-otp-login:${args.state.walletId}:${args.challenge.challengeId}`;
  return {
    kind: 'google_email_otp_wallet_auth_flow_v1',
    state: 'challenge_sent',
    flowId,
    requestedMode: args.state.requestedMode,
    mode: 'login',
    walletId: args.state.walletId,
    emailHint: args.challenge.emailHint,
    prompt: buildPrompt({ mode: 'login', emailHint: args.challenge.emailHint }),
    delivery: 'sent',
    expiresAtMs: args.state.expiresAtMs,
    resend: async (): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>> => {
      try {
        liveness.ensureActive();
        const challenge = await requestLoginChallenge({
          deps,
          state: args.state,
          ...(args.input.relayUrl ? { relayUrl: args.input.relayUrl } : {}),
          ...(args.input.onEvent ? { onEvent: args.input.onEvent } : {}),
        });
        liveness.burn();
        return ok(
          createGoogleEmailOtpWalletLoginFlow(deps, {
            state: args.state,
            challenge,
            input: args.input,
          }),
        );
      } catch (error: unknown) {
        return fail('email_otp_challenge_failed', error);
      }
    },
    submit: async (submitInput: {
      otpCode: string;
    }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthSubmitSuccess>> => {
      try {
        liveness.ensureActive();
        const otpCode = String(submitInput.otpCode || '').trim();
        if (!/^\d{6}$/.test(otpCode)) {
          return fail(
            'email_otp_invalid_code',
            new Error('Enter the 6-digit code from your email.'),
          );
        }
        const requiredTargets = resolveEcdsaTargets({
          configs: deps.configs,
          policy: args.input.ecdsaTargets,
        });
        await loginWithConfiguredTargets({
          deps,
          state: args.state,
          input: args.input,
          challenge: args.challenge,
          otpCode,
          targets: requiredTargets,
        });
        liveness.burn();
        const session = await assertLoggedIn(deps, args.state.walletId);
        return ok({ walletId: args.state.walletId, mode: 'login', session });
      } catch (error: unknown) {
        if (isEmailOtpDeviceRecoveryRequired(error)) {
          return failWithMessage(
            'email_otp_device_recovery_required',
            emailOtpDeviceRecoveryRequiredMessage(),
            error,
          );
        }
        return fail(classifyEmailOtpSubmitError(error), error);
      }
    },
    cancel: async (): Promise<void> => {
      liveness.burn();
    },
  };
}

export function googleEmailOtpTargetKeys(
  targets: readonly ThresholdEcdsaChainTarget[],
): readonly string[] {
  return targets.map((target) => thresholdEcdsaChainTargetKey(target));
}
