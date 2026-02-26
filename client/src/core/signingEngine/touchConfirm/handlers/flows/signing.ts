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
  getTxCount,
  getSignTransactionPayload,
} from './adapters/request';
import { toError } from '@shared/utils/errors';
import { createConfirmSession, createConfirmTxFlowAdapters } from './adapters/adapters';
import { computeUiIntentDigestFromNep413 } from '@/utils/intentDigest';
import {
  clearIntentDigestPreparation,
  consumeIntentDigestPreparation,
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
  try {
    const signingAuthMode = getTransactionSigningAuthMode(request);
    const usesNeeded = getTxCount(request);
    const intentDigestB64u =
      request.type === UserConfirmationType.SIGN_TRANSACTION
        ? getIntentDigest(request)
        : request.type === UserConfirmationType.SIGN_NEP413_MESSAGE
          ? await computeUiIntentDigestFromNep413({
              nearAccountId,
              recipient: request.payload.recipient,
              message: request.payload.message,
            })
          : undefined;
    const sessionPolicyDigest32 = request.payload.sessionPolicyDigest32;

    // 1) Start NEAR context fetch + nonce reservation immediately.
    const nearContextPromise = adapters.near.fetchNearContext({
      nearAccountId,
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

    // Ensure UI is mounted (or already resolved in `uiMode: none`) before updates.
    await promptReady;

    const nearRpc = await nearContextPromise;
    if (!nearRpc.transactionContext) {
      console.error('[SigningFlow] fetchNearContext failed', {
        error: nearRpc.error,
        details: nearRpc.details,
      });
      session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: nearRpc.details
          ? `${ERROR_MESSAGES.nearRpcFailed}: ${nearRpc.details}`
          : ERROR_MESSAGES.nearRpcFailed,
      });
      await promptDecisionPromise.catch(() => undefined);
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

    // 3) Hydrate security context and re-enable confirm action once block metadata is ready.
    session.updateUI({
      securityContext,
      loading: false,
    });

    const { confirmed, error: uiError } = await promptDecisionPromise;
    if (!confirmed) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: uiError,
      });
    }

    // 4) Warm session: skip WebAuthn (seed/token handled by caller).
    if (signingAuthMode === 'warmSession') {
      session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: true,
        transactionContext,
      });
      return;
    }

    // 5) Collect authentication credential.
    const challengeB64u = String(sessionPolicyDigest32 || intentDigestB64u || '').trim();
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
      intentDigest: getIntentDigest(request),
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
      intentDigest: getIntentDigest(request),
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

    if (intentPreparation) {
      // Ensure UI is mounted before applying updates.
      await promptReady;
      const prepared = await intentPreparation;
      resolvedIntentDigest = String(prepared.intentDigest || '').trim() || resolvedIntentDigest;
      resolvedChallengeB64u = String(prepared.challengeB64u || '').trim() || resolvedChallengeB64u;
      session.updateUI({
        ...(prepared.displayModel ? { model: prepared.displayModel } : {}),
        ...(prepared.title ? { title: prepared.title } : {}),
        ...(prepared.body ? { body: prepared.body } : {}),
        loading: false,
      });
    }

    const { confirmed, error: uiError } = await promptDecisionPromise;
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
