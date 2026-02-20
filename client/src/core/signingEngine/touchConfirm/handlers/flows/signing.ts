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
  opts: { confirmationConfig: ConfirmationConfig; transactionSummary: TransactionSummary; theme: ThemeName },
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
    const intentDigestB64u = request.type === UserConfirmationType.SIGN_TRANSACTION
      ? getIntentDigest(request)
      : request.type === UserConfirmationType.SIGN_NEP413_MESSAGE
        ? await computeUiIntentDigestFromNep413({
          nearAccountId,
          recipient: request.payload.recipient,
          message: request.payload.message,
        })
        : undefined;
    const sessionPolicyDigest32 = request.payload.sessionPolicyDigest32;

    // 1) NEAR context + nonce reservation
    const nearRpc = await adapters.near.fetchNearContext({
      nearAccountId,
      txCount: usesNeeded,
      reserveNonces: true,
      allowFallback: false,
    });
    if (!nearRpc.transactionContext) {
      console.error('[SigningFlow] fetchNearContext failed', { error: nearRpc.error, details: nearRpc.details });
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: nearRpc.details ? `${ERROR_MESSAGES.nearRpcFailed}: ${nearRpc.details}` : ERROR_MESSAGES.nearRpcFailed,
      });
    }
    session.setReservedNonces(nearRpc.reservedNonces);
    const transactionContext: TransactionContext = nearRpc.transactionContext;

    // 2) Security context shown in the confirmer (rpId + block height).
    // For warmSession signing we still want to show this context even though
    // we won't collect a WebAuthn credential.
    const rpId = adapters.security.getRpId();
    const securityContext: Partial<UserConfirmSecurityContext> | undefined = rpId
      ? {
          rpId,
          blockHeight: transactionContext.txBlockHeight,
          blockHash: transactionContext.txBlockHash,
        }
      : undefined;

    // 3) UI confirm
    const { confirmed, error: uiError } = await session.promptUser({ securityContext });
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
    const msg = String((toError(err))?.message || err || '');
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
        : (isWrongPasskeyError ? msg : (msg || ERROR_MESSAGES.collectCredentialsFailed)),
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
  opts: { confirmationConfig: ConfirmationConfig; transactionSummary: TransactionSummary; theme: ThemeName },
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
    const signingAuthMode = getIntentDigestSigningAuthMode(request);
    const requiresExplicitConfirmClick =
      confirmationConfig.uiMode !== 'none'
      && confirmationConfig.behavior === 'requireClick';
    const rpId = adapters.security.getRpId();
    const securityContext: Partial<UserConfirmSecurityContext> | undefined = rpId ? { rpId } : undefined;

    if (requiresExplicitConfirmClick) {
      sendConfirmProgress(worker, {
        requestId: request.requestId,
        step: 2,
        phase: 'intent-confirmation-required',
        status: 'progress',
        message: 'Awaiting confirmation click',
      });
    }

    const { confirmed, error: uiError } = await session.promptUser({ securityContext });
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
        intentDigest: getIntentDigest(request),
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
        intentDigest: getIntentDigest(request),
        confirmed: true,
      });
    }

    const challengeB64u = String(request.payload.challengeB64u || '').trim();
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
      intentDigest: getIntentDigest(request),
      confirmed: true,
      credential: serializedCredential,
    });
  } catch (err: unknown) {
    sendConfirmProgress(worker, {
      requestId: request.requestId,
      step: 4,
      phase: ActionPhase.STEP_4_AUTHENTICATION_COMPLETE,
      status: 'error',
      message: String((toError(err))?.message || err || ERROR_MESSAGES.collectCredentialsFailed),
    });
    const cancelled = isUserCancelledUserConfirm(err);
    const msg = String((toError(err))?.message || err || '');
    if (cancelled) {
      window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
    }
    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: false,
      error: cancelled ? ERROR_MESSAGES.cancelled : (msg || ERROR_MESSAGES.collectCredentialsFailed),
    });
  }
}
