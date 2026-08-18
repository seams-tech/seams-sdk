import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { SigningOperationIntent } from '../operationState/types';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type ThresholdEcdsaBootstrapParityArgs = {
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
} & (
  | {
      kind: 'key_enrollment_bootstrap_parity';
    }
  | {
      kind: 'transaction_bootstrap_parity';
      operationIntent: (typeof SigningOperationIntent)['TransactionSign'];
    }
  | {
      kind: 'email_otp_bootstrap_parity';
      authMethod: typeof SIGNER_AUTH_METHODS.emailOtp;
    }
  | {
      kind: 'default_bootstrap_parity';
    }
);

export function isRetryableSealedRefreshCapabilityFetchError(error: unknown): boolean {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '').trim()
      : '';
  if (
    code === 'sealed_refresh_parity_fetch_failed' ||
    code === 'sealed_refresh_parity_http_error' ||
    code === 'sealed_refresh_parity_aborted'
  ) {
    return true;
  }
  const message = String(error instanceof Error ? error.message : error || '');
  return (
    message.includes('Failed to fetch relayer well-known capabilities') ||
    /Well-known endpoint returned HTTP 5\d\d/.test(message)
  );
}

function parityErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'unknown error');
}

export async function ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
  ensureParity: () => Promise<void>,
  args: ThresholdEcdsaBootstrapParityArgs,
): Promise<void> {
  try {
    await ensureParity();
  } catch (error: unknown) {
    if (args.kind === 'key_enrollment_bootstrap_parity') {
      console.warn(
        '[threshold-ecdsa] key enrollment bootstrap skipped sealed-refresh startup parity enforcement',
        {
          walletId: String(args.walletId || '').trim(),
          chainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
          error: parityErrorMessage(error),
        },
      );
      return;
    }
    if (
      args.kind === 'transaction_bootstrap_parity' &&
      isRetryableSealedRefreshCapabilityFetchError(error)
    ) {
      console.warn(
        '[threshold-ecdsa] transaction bootstrap skipped retryable sealed-refresh capability fetch failure',
        {
          walletId: String(args.walletId || '').trim(),
          chainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
          error: parityErrorMessage(error),
        },
      );
      return;
    }
    if (
      args.kind === 'email_otp_bootstrap_parity' &&
      args.authMethod === SIGNER_AUTH_METHODS.emailOtp &&
      isRetryableSealedRefreshCapabilityFetchError(error)
    ) {
      console.warn(
        '[threshold-ecdsa] Email OTP bootstrap skipped retryable sealed-refresh capability fetch failure',
        {
          walletId: String(args.walletId || '').trim(),
          chainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
          error: parityErrorMessage(error),
        },
      );
      return;
    }
    if (
      args.kind === 'default_bootstrap_parity' &&
      isRetryableSealedRefreshCapabilityFetchError(error)
    ) {
      console.warn(
        '[threshold-ecdsa] default bootstrap skipped retryable sealed-refresh capability fetch failure',
        {
          walletId: String(args.walletId || '').trim(),
          chainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
          error: parityErrorMessage(error),
        },
      );
      return;
    }
    throw error;
  }
}

export async function ensureSealedRefreshStartupParityForTransactionSigning(
  ensureParity: () => Promise<void>,
  args: {
    walletId: string;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<void> {
  try {
    await ensureParity();
  } catch (error: unknown) {
    if (!isRetryableSealedRefreshCapabilityFetchError(error)) throw error;
    console.warn(
      '[threshold-ecdsa] transaction signing skipped retryable sealed-refresh capability fetch failure',
      {
        walletId: String(args.walletId || '').trim(),
        chainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
        error: parityErrorMessage(error),
      },
    );
  }
}
