import { SigningEventPhase } from '@tatchi-xyz/sdk/react';
import type { SigningFlowEvent } from '@tatchi-xyz/sdk/react';
import { toast } from 'sonner';

type SigningToastChainLabel = 'EVM' | 'Tempo' | 'NEAR';

type SigningToastResult =
  | { status: 'shown' }
  | { status: 'ignored' }
  | { status: 'failed' | 'cancelled' | 'succeeded'; message: string };

type SigningToastOptions = {
  toastId: string;
  chainLabel: SigningToastChainLabel;
  successMessage: string;
};

function signingEventErrorMessage(event: SigningFlowEvent, fallback: string): string {
  const error = event.error as { message?: unknown } | string | undefined;
  if (typeof error === 'string' && error.trim()) return error.trim();
  if (error && typeof error === 'object') {
    const errorMessage = String(error.message || '').trim();
    if (errorMessage) return errorMessage;
  }
  return event.message || fallback;
}

function signingToastMessage(
  event: SigningFlowEvent,
  chainLabel: SigningToastChainLabel,
): { title: string; description?: string } | null {
  switch (event.phase) {
    case SigningEventPhase.STEP_01_STARTED:
      return { title: `Preparing ${chainLabel} transaction` };
    case SigningEventPhase.STEP_02_REQUEST_PREPARED:
      return { title: 'Transaction ready for review' };
    case SigningEventPhase.STEP_03_NONCE_RESERVE_STARTED:
      return { title: 'Checking transaction nonce' };
    case SigningEventPhase.STEP_04_ACCOUNT_READINESS_STARTED: {
      const deploymentMode = String(event.data?.deploymentMode || '').trim();
      return deploymentMode === 'enforce'
        ? {
            title: 'Setting up account',
            description: `Preparing the ${chainLabel} account.`,
          }
        : {
            title: 'Checking account setup',
            description: `Verifying the ${chainLabel} account.`,
          };
    }
    case SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED:
      return { title: 'Review transaction' };
    case SigningEventPhase.STEP_05_CONFIRMATION_APPROVED:
      return { title: 'Transaction approved' };
    case SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED:
      return { title: 'Secure signing session authorized' };
    case SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_STARTED:
      return { title: 'Confirm with passkey' };
    case SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED:
      return { title: 'Sending email code' };
    case SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED:
      return { title: 'Enter the email code' };
    case SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_STARTED:
      return { title: 'Verifying email code' };
    case SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE:
      return { title: 'Authentication complete' };
    case SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED:
      return { title: `Preparing secure ${chainLabel} signer` };
    case SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED:
      return { title: 'Secure signer ready' };
    case SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED:
      return {
        title: 'Loading secure signer',
        description: 'Preparing the threshold signer.',
      };
    case SigningEventPhase.STEP_10_COMMIT_QUEUED:
      return { title: 'Waiting to sign' };
    case SigningEventPhase.STEP_10_COMMIT_STARTED:
      return { title: 'Creating transaction signature' };
    case SigningEventPhase.STEP_11_TRANSACTION_SIGNED:
      return { title: 'Transaction signed' };
    case SigningEventPhase.STEP_12_BROADCAST_STARTED:
      return { title: `Submitting ${chainLabel} transaction` };
    case SigningEventPhase.STEP_12_BROADCAST_ACCEPTED:
      return {
        title: 'Transaction submitted',
        description: 'Waiting for network confirmation.',
      };
    case SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED:
      return { title: 'Checking transaction status' };
    case SigningEventPhase.STEP_13_RECEIPT_FINALIZED:
      return { title: 'Transaction finalized' };
    case SigningEventPhase.STEP_14_APP_STATE_SYNC_STARTED:
      return { title: 'Refreshing app state' };
    case SigningEventPhase.STEP_14_APP_STATE_SYNC_SUCCEEDED:
      return { title: 'App state refreshed' };
    default:
      return null;
  }
}

export function handleSigningToastEvent(
  event: SigningFlowEvent,
  options: SigningToastOptions,
): SigningToastResult {
  if (event.flow !== 'signing') return { status: 'ignored' };

  if (event.status === 'cancelled' || event.phase === SigningEventPhase.CANCELLED) {
    const message = signingEventErrorMessage(event, `${options.chainLabel} transaction cancelled`);
    toast.info(message, { id: options.toastId, description: null });
    return { status: 'cancelled', message };
  }

  if (event.status === 'failed' || event.phase === SigningEventPhase.FAILED) {
    const message = signingEventErrorMessage(event, `${options.chainLabel} transaction failed`);
    toast.error(message, { id: options.toastId, description: null });
    return { status: 'failed', message };
  }

  if (event.phase === SigningEventPhase.STEP_15_COMPLETED && event.status === 'succeeded') {
    toast.success(options.successMessage, { id: options.toastId, description: null });
    return { status: 'succeeded', message: options.successMessage };
  }

  const toastMessage = signingToastMessage(event, options.chainLabel);
  if (!toastMessage) return { status: 'ignored' };

  toast.loading(toastMessage.title, {
    id: options.toastId,
    description: toastMessage.description || null,
  });
  return { status: 'shown' };
}
