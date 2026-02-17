import type { SecureConfirmWorkerManagerContext } from '../../';
import type { ConfirmationConfig } from '../../../../types/signer-worker';
import { ActionPhase } from '../../../../types/sdkSentEvents';
import {
  SecureConfirmationType,
  TransactionSummary,
  type IntentDigestSecureConfirmRequest,
  type SigningAuthMode,
} from '../types';
import type { SecureConfirmSecurityContext } from '../../../../types';
import {
  getNearAccountId,
  getIntentDigest,
  isUserCancelledSecureConfirm,
  ERROR_MESSAGES,
  sendConfirmProgress,
} from './index';
import { toError } from '../../../../../../../shared/src/utils/errors';
import { createConfirmSession } from '../adapters/session';
import { createConfirmTxFlowAdapters } from '../adapters/createAdapters';
import type { ThemeName } from '../../../../types/tatchi';
import { collectAuthenticationCredentialForChallengeB64u } from '../../../webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';

function getSigningAuthMode(request: IntentDigestSecureConfirmRequest): SigningAuthMode {
  return request.payload.signingAuthMode ?? 'webauthn';
}

export async function handleIntentDigestSigningFlow(
  ctx: SecureConfirmWorkerManagerContext,
  request: IntentDigestSecureConfirmRequest,
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
    const signingAuthMode = getSigningAuthMode(request);
    const requiresExplicitConfirmClick =
      confirmationConfig.uiMode !== 'none'
      && confirmationConfig.behavior === 'requireClick';
    const rpId = adapters.security.getRpId();
    const securityContext: Partial<SecureConfirmSecurityContext> | undefined = rpId ? { rpId } : undefined;

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
    const cancelled = isUserCancelledSecureConfirm(err);
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
