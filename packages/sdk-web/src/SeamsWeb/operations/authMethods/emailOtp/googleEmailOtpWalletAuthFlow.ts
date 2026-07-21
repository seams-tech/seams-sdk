import type { RegistrationResult, SeamsConfigsReadonly, WalletSession } from '@/core/types/seams';
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
import { DEV_DEFAULT_UNLOCK_REMAINING_USES } from '@/core/signingEngine/session/budget/policy';
import {
  listConfiguredThresholdEcdsaPublicationTargets,
  listThresholdEcdsaProvisionTargets,
} from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import { buildNearWalletRegistrationSignerSetSelection } from '@/SeamsWeb/operations/registration/registrationSignerSet';
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
  EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_CODE,
  EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_MESSAGE,
} from './errors';

const DEFAULT_FLOW_TTL_MS = 10 * 60 * 1000;

type GoogleEmailOtpWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0];

type ActiveChallenge = {
  challengeId: string;
  emailHint: string;
};

type GoogleLoginEmailOtpEcdsaCapabilityArgs = EmailOtpEcdsaCapabilityArgs & {
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
};

type GoogleLoginEmailOtpEd25519YaoCapabilityArgs = {
  walletSession: ReturnType<typeof walletSessionRefFromSession>;
  challengeId: string;
  otpCode: string;
  remainingUses: number;
  appSessionJwt: string;
};

type GoogleEmailOtpSessionExchangeRequest<
  TMode extends GoogleEmailOtpWalletAuthRequestedMode = GoogleEmailOtpWalletAuthRequestedMode,
> = {
  idToken: string;
  accountMode: TMode;
  relayUrl: string | undefined;
  sessionKind: 'jwt' | 'cookie' | undefined;
  onEvent: ((event: RegistrationFlowEvent | UnlockFlowEvent) => void) | undefined;
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
    args: GoogleEmailOtpSessionExchangeRequest,
  ): Promise<GoogleEmailOtpSessionExchangeResult>;
  requestEmailOtpChallenge(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult>;
  registerWallet(args: GoogleEmailOtpWalletRegistrationArgs): Promise<RegistrationResult>;
  loginWithEmailOtpEcdsaCapability(
    args: GoogleLoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpEcdsaCapabilityResult>;
  loginWithEmailOtpEd25519YaoCapability(
    args: GoogleLoginEmailOtpEd25519YaoCapabilityArgs,
  ): Promise<void>;
  getWalletSession(walletId: string): Promise<WalletSession>;
};

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
  if (code === EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_CODE) return true;
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error || '').toLowerCase();
  return (
    message.includes('email otp device-local enc_s(s) is missing') ||
    message.includes('email otp device-local enc_s(s) metadata mismatch')
  );
}

function emailOtpDeviceRecoveryRequiredMessage(): string {
  return EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_MESSAGE;
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
      /* no helper: the field + "Generate another name" + button are self-evident */
      helperText: '',
    };
  }
  return {
    title: 'Check your email to unlock your wallet',
    description: `Enter the 6-digit code we sent to ${input.emailHint}.`,
    submitLabel: 'Unlock wallet',
    /* no helper: the description already explains the code */
    helperText: '',
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
  if (input.resolutionMode === 'register_started') return 'register';
  return 'login';
}

function isMissingGoogleEmailOtpEnrollment(error: unknown): boolean {
  if (!error || typeof error !== 'object' || !('code' in error)) return false;
  return (error as { code?: unknown }).code === 'not_found';
}

function classifyGoogleEmailOtpExchangeError(
  error: unknown,
): GoogleEmailOtpWalletAuthFailureCode {
  if (!error || typeof error !== 'object' || !('code' in error)) {
    return 'google_exchange_failed';
  }
  const code = Reflect.get(error, 'code');
  return code === 'stale_identity_mapping'
    ? 'google_account_registration_required'
    : 'google_exchange_failed';
}

function googleEmailOtpSessionExchangeRequest<
  TMode extends GoogleEmailOtpWalletAuthRequestedMode,
>(
  input: GoogleEmailOtpWalletAuthStartInput,
  accountMode: TMode,
): GoogleEmailOtpSessionExchangeRequest<TMode> {
  return {
    idToken: input.idToken,
    accountMode,
    relayUrl: input.relayUrl,
    sessionKind: input.sessionKind,
    onEvent: input.onEvent,
  };
}

async function exchangeGoogleEmailOtpSessionForAuthFlow(args: {
  deps: GoogleEmailOtpWalletAuthDeps;
  input: GoogleEmailOtpWalletAuthStartInput;
}): Promise<GoogleEmailOtpSessionExchangeResult> {
  try {
    const loginOrRegistrationRequest = googleEmailOtpSessionExchangeRequest(
      args.input,
      args.input.mode,
    );
    return await args.deps.exchangeGoogleEmailOtpSession(loginOrRegistrationRequest);
  } catch (error: unknown) {
    if (args.input.mode !== 'login' || !isMissingGoogleEmailOtpEnrollment(error)) throw error;
    const registrationRequest = googleEmailOtpSessionExchangeRequest(args.input, 'register');
    return await args.deps.exchangeGoogleEmailOtpSession(registrationRequest);
  }
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
  const resolvedWalletId = offer
    ? selectedGoogleEmailOtpRegistrationCandidate(offer).walletId
    : walletId;
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
    walletId: resolvedWalletId,
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

function selectedGoogleEmailOtpRegistrationCandidate(
  offer: GoogleEmailOtpRegistrationOffer,
): GoogleEmailOtpRegistrationCandidate {
  const candidate = offer.candidates.find(
    (entry) => entry.candidateId === offer.selectedCandidateId,
  );
  if (!candidate) {
    throw new Error('Google Email OTP registration offer selected candidate is missing');
  }
  return candidate;
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

function resolveRegistrationEcdsaTargets(args: {
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

function resolveLoginEcdsaTargets(args: {
  configs: SeamsConfigsReadonly;
  policy?: GoogleEmailOtpWalletAuthEcdsaTargets;
}): readonly ThresholdEcdsaChainTarget[] {
  const policy = args.policy || { kind: 'configured' as const };
  if (policy.kind === 'none') return [];
  if (policy.kind === 'explicit') return policy.targets;
  return listConfiguredThresholdEcdsaPublicationTargets(args.configs.network.chains).map(
    (target) => target.chainTarget,
  );
}

function eventOnlyRegistrationOptions(args: {
  onEvent?: GoogleEmailOtpWalletAuthStartInput['onEvent'];
}): RegistrationHooksOptions {
  return {
    ...(args.onEvent ? { onEvent: args.onEvent as (event: RegistrationFlowEvent) => void } : {}),
  };
}

function resolveGoogleEmailOtpEd25519RemainingUses(configs: SeamsConfigsReadonly): number {
  const configured = Math.floor(Number(configs.signing.sessionDefaults?.remainingUses) || 0);
  if (configured <= 0) return DEV_DEFAULT_UNLOCK_REMAINING_USES;
  return Math.min(configured, DEV_DEFAULT_UNLOCK_REMAINING_USES);
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
  const [primaryTarget] = args.targets;
  if (!primaryTarget) {
    await args.deps.loginWithEmailOtpEd25519YaoCapability({
      walletSession,
      challengeId: args.challenge.challengeId,
      otpCode: args.otpCode,
      remainingUses: resolveGoogleEmailOtpEd25519RemainingUses(args.deps.configs),
      appSessionJwt: googleEmailOtpAppSessionJwt(args.state, 'login'),
    });
    return;
  }
  const common = {
    walletSession,
    challengeId: args.challenge.challengeId,
    emailOtpAuthorityEmail: args.challenge.emailHint,
    otpCode: args.otpCode,
    ...(args.input.relayUrl ? { relayUrl: args.input.relayUrl } : {}),
    ...(args.state.appSessionJwt ? { appSessionJwt: args.state.appSessionJwt } : {}),
    ...(args.input.emailOtpAuthPolicy ? { emailOtpAuthPolicy: args.input.emailOtpAuthPolicy } : {}),
    ...(args.input.onEvent
      ? { onEvent: args.input.onEvent as (event: UnlockFlowEvent) => void }
      : {}),
  };
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
    const exchange = await exchangeGoogleEmailOtpSessionForAuthFlow({
      deps,
      input,
    });
    sessionState = resolveSessionState({
      idToken: input.idToken,
      requestedMode: input.mode,
      exchange,
    });
  } catch (error: unknown) {
    return fail(classifyGoogleEmailOtpExchangeError(error), error);
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

function googleEmailOtpAppSessionJwt(
  state: GoogleSessionState,
  purpose: 'registration' | 'login',
): string {
  const appSessionJwt = String(state.appSessionJwt || '').trim();
  if (!appSessionJwt) {
    throw new Error(`Google Email OTP ${purpose} requires an app session token`);
  }
  return appSessionJwt;
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
  const requiredTargets = resolveRegistrationEcdsaTargets({
    configs: deps.configs,
    policy: args.input.ecdsaTargets,
  });
  const eventOptions = eventOnlyRegistrationOptions({ onEvent: args.input.onEvent });
  const registrationOptions = requiredTargets.length
    ? eventOptions
    : registrationOptionsForNoEcdsa({ options: eventOptions });
  const appSessionJwt = googleEmailOtpAppSessionJwt(args.state, 'registration');
  const selectedWalletId = selectedGoogleEmailOtpRegistrationCandidate(offer).walletId;
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
    wallet: { kind: 'provided', walletId: selectedWalletId },
    authMethod: registrationAuthMethod,
    signerSelection: buildNearWalletRegistrationSignerSetSelection({
      configs: deps.configs,
      options: registrationOptions,
      ecdsaChainTargets: requiredTargets,
    }),
    options: registrationOptions,
  };
  const liveness = createFlowLiveness({ state: args.state });
  const flowId = `google-email-otp-registration:${selectedWalletId}:${registrationAttemptId}`;
  return {
    kind: 'google_email_otp_wallet_auth_flow_v1',
    state: 'registration_ready',
    flowId,
    requestedMode: args.state.requestedMode,
    mode: 'register',
    walletId: selectedWalletId,
    emailHint: args.state.emailHint,
    prompt: buildPrompt({ mode: 'register', emailHint: args.state.emailHint }),
    expiresAtMs: args.state.expiresAtMs,
    completeRegistration: async (): Promise<
      GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationCompleted>
    > => {
      try {
        liveness.ensureActive();
        const result = await deps.registerWallet(registrationArgs);
        if (!result.success) {
          const error = Object.assign(new Error(result.error || 'Wallet registration failed'), {
            code: result.errorCode,
          });
          return fail(classifyRegistrationError(error), error);
        }
        liveness.burn();
        const session = await assertLoggedIn(deps, selectedWalletId);
        return ok({ walletId: selectedWalletId, mode: 'register', session });
      } catch (error: unknown) {
        return fail(classifyRegistrationError(error), error);
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
          currentWalletId: selectedWalletId,
        });
        if (!nextCandidate) {
          return fail(
            'google_exchange_failed',
            new Error('Google Email OTP registration offer has no alternate wallet candidate'),
          );
        }
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
        const requiredTargets = resolveLoginEcdsaTargets({
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
