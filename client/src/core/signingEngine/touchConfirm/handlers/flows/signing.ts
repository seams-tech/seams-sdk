import type { TouchConfirmContext } from '../../';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { ActionPhase } from '@/core/types/sdkSentEvents';
import type { UserConfirmSecurityContext, TransactionContext } from '@/core/types';
import type { ThemeName } from '@/core/types/tatchi';
import { collectAuthenticationCredentialForChallengeB64u } from '@/core/signingEngine/signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  UserConfirmationType,
  type TransactionSummary,
  type SigningUserConfirmRequest,
  type IntentDigestUserConfirmRequest,
  type SigningAuthMode,
} from '../../shared/confirmTypes';
import {
  isUserCancelledUserConfirm,
  ERROR_MESSAGES,
  sendConfirmProgress,
} from '../../shared/confirmCommon';
import {
  getNearAccountId,
  getIntentDigest,
  getNearPublicKeyStr,
  getTxCount,
  getSignTransactionPayload,
} from './adapters/request';
import { toError } from '@shared/utils/errors';
import { createConfirmSession, createConfirmTxFlowAdapters } from './adapters/adapters';
import { computeUiIntentDigestFromNep413 } from '@/utils/intentDigest';
import {
  clearIntentDigestPreparation,
  consumeIntentDigestPreparation,
  PENDING_INTENT_DIGEST,
  type IntentDigestPreparationResult,
} from '@/core/signingEngine/touchConfirm/intentDigestPreparationRegistry';

function getTransactionSigningAuthMode(request: SigningUserConfirmRequest): SigningAuthMode {
  if (request.type === UserConfirmationType.SIGN_TRANSACTION) {
    return getSignTransactionPayload(request).signingAuthMode ?? 'webauthn';
  }
  if (request.type === UserConfirmationType.SIGN_NEP413_MESSAGE) {
    return request.payload.signingAuthMode ?? 'webauthn';
  }
  return 'webauthn';
}

export async function handleTransactionSigningFlow(
  ctx: TouchConfirmContext,
  request: SigningUserConfirmRequest,
  worker: Worker,
  opts: {
    confirmationConfig: ConfirmationConfig;
    transactionSummary: TransactionSummary;
    theme: ThemeName;
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
    const sessionPolicyDigest32 = request.payload.sessionPolicyDigest32;

    // 1) Start NEAR context fetch + nonce reservation immediately.
    const nearContextPromise = adapters.near.fetchNearContext({
      nearAccountId,
      nearPublicKeyStr: getNearPublicKeyStr(request),
      txCount: usesNeeded,
      reserveNonces: true,
      allowFallback: false,
    });

    // 2) Mount confirmer immediately (non-blocking) while NEAR context fetch is in flight.
    const rpId = adapters.security.getRpId();
    const baseSecurityContext: Partial<UserConfirmSecurityContext> | undefined = rpId
      ? { rpId }
      : undefined;
    let resolvePromptReady: (() => void) | undefined;
    const promptReady = new Promise<void>((resolve) => {
      resolvePromptReady = resolve;
    });
    const markPromptReady = () => {
      resolvePromptReady?.();
      resolvePromptReady = undefined;
    };
    const promptDecisionPromise = session.promptUser({
      securityContext: baseSecurityContext,
      loading: true,
      onMounted: () => {
        markPromptReady();
      },
    });
    void promptDecisionPromise.finally(markPromptReady);

    let decisionResolved = false;
    let nearContextReady = false;
    let nearContextFailed = false;
    let intentPreparationPending = !!intentPreparation;
    let nearRpcResolved:
      | {
          transactionContext: TransactionContext | null;
          error?: string;
          details?: string;
          reservedNonces?: string[];
        }
      | undefined;
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
        loading: nearContextFailed ? false : !nearContextReady,
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
            loading: nearContextFailed ? false : !nearContextReady,
            errorMessage: String(toError(error)?.message || error || 'Failed to prepare intent'),
          });
        });
    }
    void nearContextPromise.then(async (nearRpc) => {
      nearRpcResolved = nearRpc;
      nearContextReady = true;
      await promptReady;
      if (!nearRpc.transactionContext) {
        nearContextFailed = true;
        if (decisionResolved) return;
        session.updateUI({
          loading: false,
          errorMessage: nearRpc.details
            ? `${ERROR_MESSAGES.nearRpcFailed}: ${nearRpc.details}`
            : ERROR_MESSAGES.nearRpcFailed,
        });
        return;
      }
      session.setReservedNonces(nearRpc.reservedNonces);
      const transactionContext: TransactionContext = nearRpc.transactionContext;
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
        loading: intentPreparationPending,
      });
    });

    // Ordering matters: resolve user decision first so "Cancel" can close immediately
    // even while context/digest preparation is still running. Confirmed flows wait below.
    const { confirmed, error: uiError } = await promptDecisionPromise;
    decisionResolved = true;
    if (!confirmed) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigestForResponse,
        confirmed: false,
        error: uiError,
      });
    }

    const nearRpc = nearRpcResolved || (await nearContextPromise);
    if (!nearRpc.transactionContext) {
      console.error('[SigningFlow] fetchNearContext failed', {
        error: nearRpc.error,
        details: nearRpc.details,
      });
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigestForResponse,
        confirmed: false,
        error: nearRpc.details
          ? `${ERROR_MESSAGES.nearRpcFailed}: ${nearRpc.details}`
          : ERROR_MESSAGES.nearRpcFailed,
      });
    }
    session.setReservedNonces(nearRpc.reservedNonces);
    const transactionContext: TransactionContext = nearRpc.transactionContext;

    if (preparedIntentPromise) {
      const prepared = await preparedIntentPromise;
      applyPreparedIntentData(prepared);
    }

    // 4) Warm session: skip WebAuthn (seed/token handled by caller).
    if (signingAuthMode === 'warmSession') {
      session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigestForResponse,
        confirmed: true,
        transactionContext,
      });
      return;
    }

    // 5) Collect authentication credential.
    const challengeB64u = String(sessionPolicyDigest32 || resolvedChallengeB64u || '').trim();
    if (!challengeB64u) {
      throw new Error('Missing WebAuthn challenge digest for signing flow');
    }
    const serializedCredential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: ctx.indexedDB,
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
      transactionContext,
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

function getIntentDigestSigningAuthMode(request: IntentDigestUserConfirmRequest): SigningAuthMode {
  return request.payload.signingAuthMode ?? 'webauthn';
}

export async function handleIntentDigestSigningFlow(
  ctx: TouchConfirmContext,
  request: IntentDigestUserConfirmRequest,
  worker: Worker,
  opts: {
    confirmationConfig: ConfirmationConfig;
    transactionSummary: TransactionSummary;
    theme: ThemeName;
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
  const intentPreparation = consumeIntentDigestPreparation(request.requestId);

  try {
    const signingAuthMode = getIntentDigestSigningAuthMode(request);
    let resolvedIntentDigest = String(getIntentDigest(request) || '').trim() || undefined;
    let resolvedChallengeB64u = String(request.payload.challengeB64u || '').trim();
    const requiresExplicitConfirmClick =
      confirmationConfig.uiMode !== 'none' && confirmationConfig.behavior === 'requireClick';
    const rpId = adapters.security.getRpId();
    const securityContext: Partial<UserConfirmSecurityContext> | undefined = rpId
      ? { rpId }
      : undefined;

    if (requiresExplicitConfirmClick) {
      sendConfirmProgress(worker, {
        requestId: request.requestId,
        step: 2,
        phase: 'intent-confirmation-required',
        status: 'progress',
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
    const { confirmed, error: uiError } = await promptDecisionPromise;
    decisionResolved = true;
    if (!confirmed) {
      if (requiresExplicitConfirmClick) {
        sendConfirmProgress(worker, {
          requestId: request.requestId,
          step: 2,
          phase: 'user-confirmation-complete',
          status: 'error',
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

    if (signingAuthMode === 'warmSession') {
      if (requiresExplicitConfirmClick) {
        sendConfirmProgress(worker, {
          requestId: request.requestId,
          step: 2,
          phase: 'user-confirmation-complete',
          status: 'success',
          message: 'Confirmation complete',
        });
      }
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: resolvedIntentDigest,
        confirmed: true,
      });
    }

    const challengeB64u = String(resolvedChallengeB64u || '').trim();
    if (!challengeB64u) {
      throw new Error('Missing WebAuthn challenge digest for intent signing flow');
    }

    sendConfirmProgress(worker, {
      requestId: request.requestId,
      step: 3,
      phase: ActionPhase.STEP_3_WEBAUTHN_AUTHENTICATION,
      status: 'progress',
      message: 'Authenticating with passkey...',
    });

    const serializedCredential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: ctx.indexedDB,
      touchIdPrompt: ctx.touchIdPrompt,
      nearAccountId,
      challengeB64u,
    });

    sendConfirmProgress(worker, {
      requestId: request.requestId,
      step: 4,
      phase: ActionPhase.STEP_4_AUTHENTICATION_COMPLETE,
      status: 'success',
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
      phase: ActionPhase.STEP_4_AUTHENTICATION_COMPLETE,
      status: 'error',
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
