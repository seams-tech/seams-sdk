import type { UiConfirmContext } from '../../uiConfirm.types';
import type { NormalizedConfirmationConfig } from '@/core/types/confirmationConfig';
import type { UserConfirmSecurityContext } from '@/core/types';
import type { ThemeMode } from '@/core/types/seams';
import type {
  NearFundingRequest,
  NearTransactionReadiness,
} from '@/core/signingEngine/nonce/nearTransactionReadiness';
import {
  collectAuthenticationCredentialForChallengeB64u,
  collectAuthenticationCredentialForWalletChallengeB64u,
} from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  UserConfirmationType,
  type TransactionSummary,
  type SigningUserConfirmRequest,
  type IntentDigestUserConfirmRequest,
  type WebAuthnChallenge,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import {
  SigningAuthPlanKind,
  type SigningAuthPlanKind as SigningAuthPlanKindType,
} from '@/core/signingEngine/stepUpConfirmation/types';
import {
  isUserCancelledUserConfirm,
  ERROR_MESSAGES,
  sendConfirmProgress,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmCommon';
import {
  getNearAccountId,
  getIntentDigest,
  getSigningAuthMode,
  getTxCount,
  getSignTransactionPayload,
  getSignIntentDigestSubject,
} from './adapters/request';
import { toError } from '@shared/utils/errors';
import {
  createConfirmSession,
  createConfirmTxFlowAdapters,
  type NearContextFetchResult,
} from './adapters/adapters';
import { computeUiIntentDigestFromNep413 } from '@/utils/intentDigest';
import {
  clearIntentDigestPreparation,
  consumeIntentDigestPreparation,
  PENDING_INTENT_DIGEST,
  type IntentDigestPreparationResult,
} from '@/core/signingEngine/stepUpConfirmation/intentDigestPreparation';
import { consumeConfirmationReadiness } from '@/core/signingEngine/uiConfirm/confirmationReadinessRegistry';
import { formatNearAccountFundingNotice } from '@/core/signingEngine/uiConfirm/nearFundingNotice';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';

const TOUCH_CONFIRM_PROGRESS_PHASE = {
  CONFIRMATION_COMPLETE: 'confirmation.complete',
  PASSKEY_PROMPT_STARTED: 'auth.passkey.prompt.started',
  PASSKEY_PROMPT_SUCCEEDED: 'auth.passkey.prompt.succeeded',
} as const;

function getTransactionSigningAuthMode(request: SigningUserConfirmRequest) {
  if (request.type === UserConfirmationType.SIGN_TRANSACTION) {
    return getSigningAuthMode(request) ?? 'webauthn';
  }
  if (request.type === UserConfirmationType.SIGN_NEP413_MESSAGE) {
    return getSigningAuthMode(request) ?? 'webauthn';
  }
  return 'webauthn';
}

type NearSigningReadinessMode =
  | {
      kind: 'transaction_access_key';
    }
  | {
      kind: 'signature_only';
    };

function resolveNearSigningReadinessMode(args: {
  request: SigningUserConfirmRequest;
  transactionSummary: TransactionSummary;
}): NearSigningReadinessMode {
  if (args.request.type === UserConfirmationType.SIGN_NEP413_MESSAGE) {
    return { kind: 'signature_only' };
  }
  if (
    args.request.type === UserConfirmationType.SIGN_TRANSACTION &&
    args.transactionSummary.type === 'delegateAction'
  ) {
    return { kind: 'signature_only' };
  }
  return { kind: 'transaction_access_key' };
}

function nearRpcFailureMessage(args: Extract<NearContextFetchResult, { kind: 'failed' }>): string {
  if (args.error === 'NEAR_ACCOUNT_LOOKUP_FAILED') {
    return args.details || 'NEAR account access-key lookup failed.';
  }
  return args.details
    ? `${ERROR_MESSAGES.nearRpcFailed}: ${args.details}`
    : ERROR_MESSAGES.nearRpcFailed;
}

function buildNearContextFetchInput(args: {
  request: SigningUserConfirmRequest;
  usesNeeded: number;
  readinessMode: NearSigningReadinessMode;
}): NearFundingRequest | undefined {
  if (args.readinessMode.kind !== 'transaction_access_key') return undefined;
  if (args.request.type !== UserConfirmationType.SIGN_TRANSACTION) {
    throw new Error('NEAR transaction readiness requires a transaction confirmation request');
  }
  const payload = getSignTransactionPayload(args.request);
  if (payload.signingKind !== 'transaction') {
    throw new Error('NEAR transaction readiness cannot use a delegate confirmation payload');
  }
  const fundingRequest = payload.nearFundingRequest;
  if (fundingRequest.signatureUses !== args.usesNeeded) {
    throw new Error('NEAR funding request signature use count does not match confirmation request');
  }
  return fundingRequest;
}

type NearReadinessDecisionFields =
  | {
      nearTransactionReadiness: NearTransactionReadiness;
      transactionContext?: never;
      nonceLeases?: never;
    }
  | {
      nearTransactionReadiness?: never;
      transactionContext?: never;
      nonceLeases?: never;
    };

function nearReadinessDecisionFields(
  readiness: NearTransactionReadiness | undefined,
): NearReadinessDecisionFields {
  return readiness ? { nearTransactionReadiness: readiness } : {};
}

function normalizeSixDigitOtpCode(value: unknown): string {
  const code = String(value || '')
    .replace(/\D/g, '')
    .slice(0, 6);
  if (!/^\d{6}$/.test(code)) {
    throw new Error('Enter the 6-digit Email OTP code to continue');
  }
  return code;
}

export function assertPasskeyCredentialLookupAllowed(args: {
  stage: 'transaction_prompt' | 'intent_digest_prompt';
  subjectId: string;
  requestId: string;
  signingAuthPlanKind: SigningAuthPlanKindType;
}): void {
  if (args.signingAuthPlanKind !== SigningAuthPlanKind.EmailOtpReauth) return;
  console.warn(
    '[SigningEngine][ui-confirm] Email OTP auth plan reached passkey credential lookup',
    {
      stage: args.stage,
      subjectId: args.subjectId,
      requestId: args.requestId,
      signingAuthPlanKind: args.signingAuthPlanKind,
    },
  );
  throw new Error('[SigningEngine] passkey_lookup_for_email_otp');
}

function assertNever(value: never): never {
  throw new Error(`Unsupported WebAuthn challenge branch: ${JSON.stringify(value)}`);
}

function resolveTypedWebAuthnChallenge(args: {
  webauthnChallenge?: WebAuthnChallenge;
  fallbackChallengeB64u: string;
  requireTypedChallenge: boolean;
}): {
  challengeB64u: string;
  challengeKind: WebAuthnChallenge['kind'];
  requestId?: string;
  thresholdSessionId?: string;
  signingGrantId?: string;
} {
  const fallbackChallengeB64u = String(args.fallbackChallengeB64u || '').trim();
  if (!args.webauthnChallenge) {
    if (args.requireTypedChallenge) {
      throw new Error('Missing typed WebAuthn challenge for passkey signing flow');
    }
    return {
      challengeB64u: fallbackChallengeB64u,
      challengeKind: 'intent_digest',
    };
  }

  switch (args.webauthnChallenge.kind) {
    case 'intent_digest':
      return {
        challengeB64u: String(args.webauthnChallenge.challengeB64u || '').trim(),
        challengeKind: args.webauthnChallenge.kind,
      };
    case 'threshold_session_policy':
      return {
        challengeB64u: String(args.webauthnChallenge.digest32B64u || '').trim(),
        challengeKind: args.webauthnChallenge.kind,
      };
    case 'ecdsa_role_local_bootstrap':
      return {
        challengeB64u: String(args.webauthnChallenge.digest32B64u || '').trim(),
        challengeKind: args.webauthnChallenge.kind,
        requestId: args.webauthnChallenge.requestId,
        thresholdSessionId: args.webauthnChallenge.thresholdSessionId,
        signingGrantId: args.webauthnChallenge.signingGrantId,
      };
  }
  return assertNever(args.webauthnChallenge);
}

async function emitWebAuthnChallengeDiagnostic(args: {
  stage: string;
  challengeB64u: string;
  challengeKind: WebAuthnChallenge['kind'];
  requestId?: string;
  thresholdSessionId?: string;
  signingGrantId?: string;
}): Promise<void> {
  try {
    const challengeHash8 = base64UrlEncode(await sha256BytesUtf8(args.challengeB64u)).slice(0, 8);
    console.info('[ui-confirm][webauthn-challenge]', {
      stage: args.stage,
      challengeKind: args.challengeKind,
      challengeHash8,
      ...(args.requestId ? { requestId: args.requestId } : {}),
      ...(args.thresholdSessionId ? { thresholdSessionId: args.thresholdSessionId } : {}),
      ...(args.signingGrantId ? { signingGrantId: args.signingGrantId } : {}),
    });
  } catch {}
}

export async function handleTransactionSigningFlow(
  ctx: UiConfirmContext,
  request: SigningUserConfirmRequest,
  worker: Worker,
  opts: {
    confirmationConfig: NormalizedConfirmationConfig;
    transactionSummary: TransactionSummary;
    theme: ThemeMode;
  },
): Promise<void> {
  const { confirmationConfig, transactionSummary, theme } = opts;
  const adapters = createConfirmTxFlowAdapters(ctx);
  const session = createConfirmSession({
    adapters,
    worker,
    request,
    confirmationConfig,
    transactionSummary,
    theme,
  });
  const nearAccountId = getNearAccountId(request);
  let resolvedIntentDigestForResponse = String(getIntentDigest(request) || '').trim() || undefined;
  if (resolvedIntentDigestForResponse === PENDING_INTENT_DIGEST) {
    resolvedIntentDigestForResponse = undefined;
  }
  try {
    const signingAuthMode = getTransactionSigningAuthMode(request);
    const usesNeeded = getTxCount(request);
    const intentPreparation =
      request.type === UserConfirmationType.SIGN_TRANSACTION
        ? consumeIntentDigestPreparation(request.requestId)
        : undefined;
    let resolvedIntentDigest =
      request.type === UserConfirmationType.SIGN_TRANSACTION
        ? String(getIntentDigest(request) || '').trim() || undefined
        : request.type === UserConfirmationType.SIGN_NEP413_MESSAGE
          ? String(
              await computeUiIntentDigestFromNep413({
                nearAccountId,
                recipient: request.payload.recipient,
                message: request.payload.message,
              }),
            ).trim() || undefined
          : undefined;
    if (resolvedIntentDigest === PENDING_INTENT_DIGEST) {
      resolvedIntentDigest = undefined;
    }
    let resolvedChallengeB64u = resolvedIntentDigest;
    resolvedIntentDigestForResponse = resolvedIntentDigest;
    const readinessMode = resolveNearSigningReadinessMode({ request, transactionSummary });
    const nearContextFetchInput = buildNearContextFetchInput({
      request,
      usesNeeded,
      readinessMode,
    });
    const nearContextPromise = nearContextFetchInput
      ? adapters.near.fetchNearContext(nearContextFetchInput)
      : undefined;

    // 2) Mount confirmer immediately while any required readiness work is in flight.
    const rpId = adapters.security.getRpId();
    const baseSecurityContext: Partial<UserConfirmSecurityContext> | undefined = rpId
      ? { rpId }
      : undefined;
    let resolvePromptReady: (() => void) | undefined;
    const promptReady = new Promise<void>((resolve) => {
      resolvePromptReady = resolve;
    });
    let decisionResolved = false;
    let nearContextReady = readinessMode.kind === 'signature_only';
    let nearContextFailed = false;
    let intentPreparationPending = !!intentPreparation;
    const confirmationReadiness = consumeConfirmationReadiness(request.requestId);
    let confirmationReadinessPending = !!confirmationReadiness;
    let confirmationReadinessError: Error | null = null;
    const originalBody = String(transactionSummary.body || '').trim();
    const confirmationReadinessBody = String(confirmationReadiness?.body || '').trim();
    const isConfirmationLoading = () =>
      !nearContextFailed &&
      (!nearContextReady || intentPreparationPending || confirmationReadinessPending);
    const restoreOriginalBody = () => ({ body: originalBody });
    const confirmationReadinessPromise = confirmationReadiness
      ? Promise.resolve(confirmationReadiness.promise).catch((error: unknown) => {
          confirmationReadinessError =
            error instanceof Error ? error : new Error(String(error || 'Unknown error'));
          throw confirmationReadinessError;
        })
      : undefined;
    const markPromptReady = () => {
      resolvePromptReady?.();
      resolvePromptReady = undefined;
    };
    const promptDecisionPromise = session.promptUser({
      securityContext: baseSecurityContext,
      loading: isConfirmationLoading(),
      onMounted: () => {
        markPromptReady();
        if (confirmationReadinessPending && confirmationReadinessBody) {
          session.updateUI({
            loading: true,
            body: confirmationReadinessBody,
          });
        }
      },
    });
    void promptDecisionPromise.finally(markPromptReady);

    let nearRpcResolved: NearContextFetchResult | undefined;
    const applyPreparedIntentData = (prepared: IntentDigestPreparationResult): void => {
      const preparedIntentDigest = String(prepared.intentDigest || '').trim();
      const preparedChallengeB64u = String(prepared.challengeB64u || '').trim();
      if (preparedIntentDigest) {
        resolvedIntentDigest = preparedIntentDigest;
        resolvedIntentDigestForResponse = preparedIntentDigest;
      }
      if (preparedChallengeB64u) {
        resolvedChallengeB64u = preparedChallengeB64u;
      }
    };
    const applyPreparedIntentToUi = (prepared: IntentDigestPreparationResult): void => {
      applyPreparedIntentData(prepared);
      session.updateUI({
        ...(prepared.displayModel ? { model: prepared.displayModel } : {}),
        ...(prepared.title ? { title: prepared.title } : {}),
        ...(prepared.body ? { body: prepared.body } : {}),
        ...(resolvedIntentDigest ? { intentDigest: resolvedIntentDigest } : {}),
        loading: isConfirmationLoading(),
      });
    };

    const preparedIntentPromise = intentPreparation
      ? (async () => {
          await promptReady;
          return await intentPreparation;
        })()
      : undefined;
    if (preparedIntentPromise) {
      void preparedIntentPromise
        .then((prepared) => {
          intentPreparationPending = false;
          if (decisionResolved) return;
          applyPreparedIntentToUi(prepared);
        })
        .catch((error: unknown) => {
          intentPreparationPending = false;
          if (decisionResolved) return;
          session.updateUI({
            loading: isConfirmationLoading(),
            errorMessage: String(toError(error)?.message || error || 'Failed to prepare intent'),
          });
        });
    }
    if (confirmationReadinessPromise) {
      void confirmationReadinessPromise
        .then(async () => {
          confirmationReadinessPending = false;
          await promptReady;
          if (decisionResolved || nearContextFailed) return;
          session.updateUI({
            ...restoreOriginalBody(),
            loading: isConfirmationLoading(),
            errorMessage: '',
          });
        })
        .catch(async (error: unknown) => {
          confirmationReadinessPending = false;
          await promptReady;
          if (decisionResolved || nearContextFailed) return;
          const message = String(
            toError(error)?.message || 'NEAR signing session could not be finalized',
          );
          session.updateUI({
            ...restoreOriginalBody(),
            loading: false,
            errorMessage: `NEAR signing session could not be finalized: ${message}`,
          });
        });
    }
    if (nearContextPromise) {
      void nearContextPromise.then(async (nearRpc) => {
        nearRpcResolved = nearRpc;
        await promptReady;
        if (nearRpc.kind === 'failed') {
          nearContextFailed = true;
          if (decisionResolved) return;
          session.updateUI({
            loading: false,
            errorMessage: nearRpcFailureMessage(nearRpc),
          });
          return;
        }
        nearContextReady = true;
        nearContextFailed = false;
        if (nearRpc.readiness.kind === 'funding_required') {
          if (decisionResolved) return;
          session.updateUI({
            loading: false,
            body: formatNearAccountFundingNotice(
              String(nearRpc.readiness.request.subject.nearAccountId),
            ),
            errorMessage: '',
            confirmText: 'Fund account',
          });
          return;
        }
        session.setNonceLeases(nearRpc.reservedNonceLeases);
        const transactionContext = nearRpc.readiness.transactionContext;
        const securityContext: Partial<UserConfirmSecurityContext> | undefined = rpId
          ? {
              rpId,
              blockHeight: transactionContext.txBlockHeight,
              blockHash: transactionContext.txBlockHash,
            }
          : undefined;
        if (decisionResolved) return;
        // Keep confirm disabled until intent preparation also completes.
        session.updateUI({
          securityContext,
          loading: isConfirmationLoading(),
        });
      });
    }

    // Ordering matters: resolve user decision first so "Cancel" can close immediately
    // even while context/digest preparation is still running. Confirmed flows wait below.
    const { confirmed, error: uiError, otpCode, emailOtpChallengeId } = await promptDecisionPromise;
    decisionResolved = true;
    if (!confirmed) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigestForResponse,
        confirmed: false,
        error: uiError,
      });
    }

    const nearRpc = nearContextPromise ? nearRpcResolved || (await nearContextPromise) : undefined;
    let nearTransactionReadiness: NearTransactionReadiness | undefined;
    if (nearContextPromise) {
      if (!nearRpc || nearRpc.kind === 'failed') {
        const failure = nearRpc || {
          kind: 'failed' as const,
          error: 'NEAR_CONTEXT_UNAVAILABLE' as const,
          details: 'NEAR transaction readiness did not resolve',
        };
        console.error('[SigningFlow] fetchNearContext failed', failure);
        return session.confirmAndCloseModal({
          requestId: request.requestId,
          intentDigest: resolvedIntentDigestForResponse,
          confirmed: false,
          error: nearRpcFailureMessage(failure),
        });
      }
      nearTransactionReadiness = nearRpc.readiness;
      if (nearRpc.readiness.kind === 'context_ready') {
        session.setNonceLeases(nearRpc.reservedNonceLeases);
      }
    }

    if (preparedIntentPromise) {
      const prepared = await preparedIntentPromise;
      applyPreparedIntentData(prepared);
    }

    if (confirmationReadinessPromise) {
      try {
        await confirmationReadinessPromise;
      } catch (error: unknown) {
        const message = String(
          toError(error)?.message || 'NEAR signing session could not be finalized',
        );
        return session.confirmAndCloseModal({
          requestId: request.requestId,
          intentDigest: resolvedIntentDigestForResponse,
          confirmed: false,
          error: `NEAR signing session could not be finalized: ${message}`,
        });
      }
    }
    if (signingAuthMode === 'emailOtp') {
      session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigestForResponse,
        confirmed: true,
        otpCode: normalizeSixDigitOtpCode(otpCode),
        ...(emailOtpChallengeId ? { emailOtpChallengeId } : {}),
        ...nearReadinessDecisionFields(nearTransactionReadiness),
      });
      return;
    }

    // 4) Warm session: skip WebAuthn (seed/token handled by caller).
    if (signingAuthMode === 'warmSession') {
      session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigestForResponse,
        confirmed: true,
        ...nearReadinessDecisionFields(nearTransactionReadiness),
      });
      return;
    }

    // 5) Collect authentication credential.
    assertPasskeyCredentialLookupAllowed({
      stage: 'transaction_prompt',
      subjectId: nearAccountId,
      requestId: request.requestId,
      signingAuthPlanKind: request.payload.signingAuthPlan.kind,
    });
    const resolvedWebAuthnChallenge = resolveTypedWebAuthnChallenge({
      webauthnChallenge: request.payload.webauthnChallenge,
      fallbackChallengeB64u: String(resolvedChallengeB64u || '').trim(),
      requireTypedChallenge:
        request.payload.signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth &&
        Boolean(request.payload.webauthnChallenge),
    });
    const challengeB64u = resolvedWebAuthnChallenge.challengeB64u;
    if (!challengeB64u) {
      throw new Error('Missing WebAuthn challenge digest for signing flow');
    }
    await emitWebAuthnChallengeDiagnostic({
      stage: 'transaction_prompt',
      challengeB64u,
      challengeKind: resolvedWebAuthnChallenge.challengeKind,
      ...(resolvedWebAuthnChallenge.requestId
        ? { requestId: resolvedWebAuthnChallenge.requestId }
        : {}),
      ...(resolvedWebAuthnChallenge.thresholdSessionId
        ? { thresholdSessionId: resolvedWebAuthnChallenge.thresholdSessionId }
        : {}),
      ...(resolvedWebAuthnChallenge.signingGrantId
        ? { signingGrantId: resolvedWebAuthnChallenge.signingGrantId }
        : {}),
    });
    const serializedCredential = await collectAuthenticationCredentialForChallengeB64u({
      credentialStore: ctx.webauthnCredentialStore,
      touchIdPrompt: ctx.touchIdPrompt,
      nearAccountId,
      challengeB64u,
    });

    // 6) Respond; keep nonces reserved for worker to use
    session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: resolvedIntentDigestForResponse,
      confirmed: true,
      credential: serializedCredential,
      ...nearReadinessDecisionFields(nearTransactionReadiness),
    });
  } catch (err: unknown) {
    // Treat TouchID/FaceID cancellation and related errors as a negative decision
    const cancelled = isUserCancelledUserConfirm(err);
    const msg = String(toError(err)?.message || err || '');
    if (cancelled) {
      window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
    }
    const isWrongPasskeyError = /multiple passkeys \\(devicenumbers\\) for account/i.test(msg);
    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: resolvedIntentDigestForResponse,
      confirmed: false,
      error: cancelled
        ? ERROR_MESSAGES.cancelled
        : isWrongPasskeyError
          ? msg
          : msg || ERROR_MESSAGES.collectCredentialsFailed,
    });
  }
}

function getIntentDigestSigningAuthMode(request: IntentDigestUserConfirmRequest) {
  return getSigningAuthMode(request) ?? 'webauthn';
}

export async function handleIntentDigestSigningFlow(
  ctx: UiConfirmContext,
  request: IntentDigestUserConfirmRequest,
  worker: Worker,
  opts: {
    confirmationConfig: NormalizedConfirmationConfig;
    transactionSummary: TransactionSummary;
    theme: ThemeMode;
  },
): Promise<void> {
  const { confirmationConfig, transactionSummary, theme } = opts;
  const adapters = createConfirmTxFlowAdapters(ctx);
  const session = createConfirmSession({
    adapters,
    worker,
    request,
    confirmationConfig,
    transactionSummary,
    theme,
  });

  const signingSubject = getSignIntentDigestSubject(request);
  const subjectId =
    signingSubject.kind === 'near_wallet' ? signingSubject.nearAccountId : signingSubject.walletId;
  const nearAccountId = signingSubject.kind === 'near_wallet' ? signingSubject.nearAccountId : '';
  const intentPreparation = consumeIntentDigestPreparation(request.requestId);

  try {
    const signingAuthMode = getIntentDigestSigningAuthMode(request);
    let resolvedIntentDigest = String(getIntentDigest(request) || '').trim() || undefined;
    let resolvedChallengeB64u = String(request.payload.challengeB64u || '').trim();
    const requiresExplicitConfirmClick = confirmationConfig.kind === 'interactive';
    const rpId = adapters.security.getRpId();
    const securityContext: Partial<UserConfirmSecurityContext> | undefined = rpId
      ? { rpId }
      : undefined;

    if (requiresExplicitConfirmClick) {
      sendConfirmProgress(worker, {
        requestId: request.requestId,
        step: 2,
        phase: 'intent-confirmation-required',
        status: 'running',
        message: 'Awaiting confirmation click',
      });
    }

    let resolvePromptReady: (() => void) | undefined;
    const promptReady = new Promise<void>((resolve) => {
      resolvePromptReady = resolve;
    });
    const markPromptReady = () => {
      resolvePromptReady?.();
      resolvePromptReady = undefined;
    };
    const promptDecisionPromise = session.promptUser({
      securityContext,
      loading: !!intentPreparation,
      onMounted: () => {
        markPromptReady();
      },
    });
    void promptDecisionPromise.finally(markPromptReady);

    let decisionResolved = false;
    let intentPreparationApplied = false;
    const applyPreparedIntentToUi = (prepared: IntentDigestPreparationResult): void => {
      resolvedIntentDigest = String(prepared.intentDigest || '').trim() || resolvedIntentDigest;
      resolvedChallengeB64u = String(prepared.challengeB64u || '').trim() || resolvedChallengeB64u;
      session.updateUI({
        ...(prepared.displayModel ? { model: prepared.displayModel } : {}),
        ...(prepared.title ? { title: prepared.title } : {}),
        ...(prepared.body ? { body: prepared.body } : {}),
        loading: false,
      });
      intentPreparationApplied = true;
    };
    const preparedIntentPromise = intentPreparation
      ? (async () => {
          // Ensure UI is mounted before applying updates.
          await promptReady;
          return await intentPreparation;
        })()
      : undefined;
    if (preparedIntentPromise) {
      void preparedIntentPromise
        .then((prepared) => {
          if (decisionResolved || intentPreparationApplied) return;
          applyPreparedIntentToUi(prepared);
        })
        .catch((error: unknown) => {
          if (decisionResolved) return;
          session.updateUI({
            loading: false,
            errorMessage: String(toError(error)?.message || error || 'Failed to prepare intent'),
          });
        });
    }

    // Ordering matters: resolve user decision first so "Cancel" can close immediately
    // even while digest/challenge preparation is still running. Only confirmed flows
    // are allowed to wait for prepared intent data.
    const { confirmed, error: uiError, otpCode, emailOtpChallengeId } = await promptDecisionPromise;
    decisionResolved = true;
    if (!confirmed) {
      if (requiresExplicitConfirmClick) {
        sendConfirmProgress(worker, {
          requestId: request.requestId,
          step: 2,
          phase: TOUCH_CONFIRM_PROGRESS_PHASE.CONFIRMATION_COMPLETE,
          status: 'failed',
          message: uiError || ERROR_MESSAGES.cancelled,
        });
      }
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigest,
        confirmed: false,
        error: uiError,
      });
    }

    if (preparedIntentPromise) {
      const prepared = await preparedIntentPromise;
      if (!intentPreparationApplied) {
        applyPreparedIntentToUi(prepared);
      }
    }

    if (signingAuthMode === 'emailOtp') {
      if (requiresExplicitConfirmClick) {
        sendConfirmProgress(worker, {
          requestId: request.requestId,
          step: 2,
          phase: TOUCH_CONFIRM_PROGRESS_PHASE.CONFIRMATION_COMPLETE,
          status: 'succeeded',
          message: 'Email OTP submitted',
        });
      }
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigest,
        confirmed: true,
        otpCode: normalizeSixDigitOtpCode(otpCode),
        ...(emailOtpChallengeId ? { emailOtpChallengeId } : {}),
      });
    }

    if (signingAuthMode === 'warmSession') {
      if (requiresExplicitConfirmClick) {
        sendConfirmProgress(worker, {
          requestId: request.requestId,
          step: 2,
          phase: TOUCH_CONFIRM_PROGRESS_PHASE.CONFIRMATION_COMPLETE,
          status: 'succeeded',
          message: 'Confirmation complete',
        });
      }
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigest,
        confirmed: true,
      });
    }

    assertPasskeyCredentialLookupAllowed({
      stage: 'intent_digest_prompt',
      subjectId,
      requestId: request.requestId,
      signingAuthPlanKind: request.payload.signingAuthPlan.kind,
    });
    const resolvedWebAuthnChallenge = resolveTypedWebAuthnChallenge({
      webauthnChallenge: request.payload.webauthnChallenge,
      fallbackChallengeB64u: String(resolvedChallengeB64u || '').trim(),
      requireTypedChallenge:
        request.payload.signingAuthPlan.kind === SigningAuthPlanKind.PasskeyReauth,
    });
    const challengeB64u = resolvedWebAuthnChallenge.challengeB64u;
    if (!challengeB64u) {
      throw new Error('Missing WebAuthn challenge digest for intent signing flow');
    }
    await emitWebAuthnChallengeDiagnostic({
      stage: 'intent_digest_prompt',
      challengeB64u,
      challengeKind: resolvedWebAuthnChallenge.challengeKind,
      ...(resolvedWebAuthnChallenge.requestId
        ? { requestId: resolvedWebAuthnChallenge.requestId }
        : {}),
      ...(resolvedWebAuthnChallenge.thresholdSessionId
        ? { thresholdSessionId: resolvedWebAuthnChallenge.thresholdSessionId }
        : {}),
      ...(resolvedWebAuthnChallenge.signingGrantId
        ? { signingGrantId: resolvedWebAuthnChallenge.signingGrantId }
        : {}),
    });

    sendConfirmProgress(worker, {
      requestId: request.requestId,
      step: 3,
      phase: TOUCH_CONFIRM_PROGRESS_PHASE.PASSKEY_PROMPT_STARTED,
      status: 'running',
      message: 'Authenticating with passkey...',
    });

    const serializedCredential =
      signingSubject.kind === 'near_wallet'
        ? await collectAuthenticationCredentialForChallengeB64u({
            credentialStore: ctx.webauthnCredentialStore,
            touchIdPrompt: ctx.touchIdPrompt,
            nearAccountId,
            challengeB64u,
          })
        : await collectAuthenticationCredentialForWalletChallengeB64u({
            credentialStore: ctx.webauthnCredentialStore,
            touchIdPrompt: ctx.touchIdPrompt,
            walletId: signingSubject.walletId,
            challengeB64u,
          });

    sendConfirmProgress(worker, {
      requestId: request.requestId,
      step: 4,
      phase: TOUCH_CONFIRM_PROGRESS_PHASE.PASSKEY_PROMPT_SUCCEEDED,
      status: 'succeeded',
      message: 'Authentication complete',
    });

    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: resolvedIntentDigest,
      confirmed: true,
      credential: serializedCredential,
    });
  } catch (err: unknown) {
    clearIntentDigestPreparation(request.requestId);
    sendConfirmProgress(worker, {
      requestId: request.requestId,
      step: 4,
      phase: TOUCH_CONFIRM_PROGRESS_PHASE.PASSKEY_PROMPT_SUCCEEDED,
      status: 'failed',
      message: String(toError(err)?.message || err || ERROR_MESSAGES.collectCredentialsFailed),
    });
    const cancelled = isUserCancelledUserConfirm(err);
    const msg = String(toError(err)?.message || err || '');
    if (cancelled) {
      window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
    }
    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: String(getIntentDigest(request) || '').trim() || undefined,
      confirmed: false,
      error: cancelled ? ERROR_MESSAGES.cancelled : msg || ERROR_MESSAGES.collectCredentialsFailed,
    });
  }
}
