import type { EvmFamilyChain } from './types';

export type EvmFamilySigningCancelledError = Error & { code: 'cancelled' };

export type EvmFamilySigningNonceConflictError = Error & {
  code: 'nonce_conflict_retryable';
  retryable: true;
  details: {
    chain: EvmFamilyChain;
    reason:
      | 'nonce_too_low'
      | 'nonce_too_high'
      | 'already_known'
      | 'replacement_underpriced'
      | 'nonce_conflict';
    networkKey: string;
    chainId: number;
  };
};

export type EvmFamilySigningNonceLaneBlockedError = Error & {
  code: 'nonce_lane_blocked';
  retryable: true;
  details: {
    chain: EvmFamilyChain;
    networkKey: string;
    chainId: number;
    blockedNonce: string;
    ageMs?: number;
  };
};

export function createEvmFamilySigningCancelledError(): EvmFamilySigningCancelledError {
  const err = new Error('Request cancelled') as EvmFamilySigningCancelledError;
  err.code = 'cancelled';
  return err;
}

export function throwIfEvmFamilySigningCancelled(shouldAbort?: () => boolean): void {
  if (typeof shouldAbort === 'function' && shouldAbort()) {
    throw createEvmFamilySigningCancelledError();
  }
}

function normalizeToken(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

export function extractErrorCode(error: unknown): string {
  if (!error || typeof error !== 'object' || !('code' in error)) return '';
  return normalizeToken((error as { code?: unknown }).code);
}

export function extractErrorMessage(error: unknown): string {
  if (!error) return '';
  if (typeof error === 'string') return error.trim();
  if (error instanceof Error) return String(error.message || '').trim();
  if (typeof error === 'object' && 'message' in error) {
    return String((error as { message?: unknown }).message || '').trim();
  }
  return String(error).trim();
}

export function isFreshEmailOtpReauthRequiredError(error: unknown): boolean {
  if (extractErrorCode(error) === 'fresh_email_otp_required') return true;
  const message = extractErrorMessage(error).toLowerCase();
  return (
    message.includes('requires fresh email otp verification') ||
    message.includes('fresh email otp verification is required')
  );
}

function inferNonceConflictReason(args: {
  code: string;
  message: string;
}): EvmFamilySigningNonceConflictError['details']['reason'] | null {
  const haystack = `${args.code} ${args.message}`.toLowerCase();
  if (!haystack.trim()) return null;

  if (haystack.includes('nonce_too_low') || haystack.includes('nonce too low')) {
    return 'nonce_too_low';
  }
  if (haystack.includes('nonce_too_high') || haystack.includes('nonce too high')) {
    return 'nonce_too_high';
  }
  if (haystack.includes('already_known') || haystack.includes('already known')) {
    return 'already_known';
  }
  if (
    haystack.includes('replacement_transaction_underpriced') ||
    haystack.includes('replacement transaction underpriced')
  ) {
    return 'replacement_underpriced';
  }
  if (
    haystack.includes('nonce_conflict') ||
    (haystack.includes('nonce') && haystack.includes('conflict')) ||
    haystack.includes('invalid nonce') ||
    haystack.includes('nonce has already been used')
  ) {
    return 'nonce_conflict';
  }
  return null;
}

export function createEvmFamilySigningNonceConflictError(args: {
  chain: EvmFamilyChain;
  networkKey: string;
  chainId: number;
  reason: EvmFamilySigningNonceConflictError['details']['reason'];
  cause?: unknown;
}): EvmFamilySigningNonceConflictError {
  const chainLabel = args.chain === 'tempo' ? 'Tempo' : 'EVM';
  const err = new Error(
    `[SigningEngine] ${chainLabel} nonce conflict (${args.reason}) on ${args.networkKey}. Refresh nonce context and retry.`,
  ) as EvmFamilySigningNonceConflictError;
  err.code = 'nonce_conflict_retryable';
  err.retryable = true;
  err.details = {
    chain: args.chain,
    reason: args.reason,
    networkKey: args.networkKey,
    chainId: args.chainId,
  };
  if (args.cause !== undefined) {
    try {
      (err as Error & { cause?: unknown }).cause = args.cause;
    } catch {}
  }
  return err;
}

export function createEvmFamilySigningNonceLaneBlockedError(args: {
  chain: EvmFamilyChain;
  networkKey: string;
  chainId: number;
  blockedNonce: string;
  ageMs?: number;
  cause?: unknown;
}): EvmFamilySigningNonceLaneBlockedError {
  const chainLabel = args.chain === 'tempo' ? 'Tempo' : 'EVM';
  const err = new Error(
    `[SigningEngine] ${chainLabel} nonce lane blocked on ${args.networkKey} (nonce=${args.blockedNonce}). Reconcile lane and retry.`,
  ) as EvmFamilySigningNonceLaneBlockedError;
  err.code = 'nonce_lane_blocked';
  err.retryable = true;
  err.details = {
    chain: args.chain,
    networkKey: args.networkKey,
    chainId: args.chainId,
    blockedNonce: args.blockedNonce,
    ...(typeof args.ageMs === 'number' ? { ageMs: args.ageMs } : {}),
  };
  if (args.cause !== undefined) {
    try {
      (err as Error & { cause?: unknown }).cause = args.cause;
    } catch {}
  }
  return err;
}

function mapToRetryableNonceConflictError(args: {
  error: unknown;
  chain: EvmFamilyChain;
  networkKey: string;
  chainId: number;
}): unknown {
  if (!args.error || typeof args.error !== 'object') return args.error;
  const existingCode = extractErrorCode(args.error);
  if (existingCode === 'nonce_conflict_retryable') return args.error;
  const reason = inferNonceConflictReason({
    code: existingCode,
    message: extractErrorMessage(args.error),
  });
  if (!reason) return args.error;
  return createEvmFamilySigningNonceConflictError({
    chain: args.chain,
    networkKey: args.networkKey,
    chainId: args.chainId,
    reason,
    cause: args.error,
  });
}

function mapToRetryableNonceLaneBlockedError(args: {
  error: unknown;
  chain: EvmFamilyChain;
  networkKey: string;
  chainId: number;
}): unknown {
  if (!args.error || typeof args.error !== 'object') return args.error;
  const existingCode = extractErrorCode(args.error);
  if (existingCode === 'nonce_lane_blocked') {
    const details =
      typeof (args.error as { details?: unknown }).details === 'object'
        ? (args.error as { details?: Record<string, unknown> }).details || {}
        : {};
    const blockedNonceRaw = String(details?.blockedNonce || '').trim();
    const ageRaw = Number(details?.ageMs);
    return createEvmFamilySigningNonceLaneBlockedError({
      chain: args.chain,
      networkKey: args.networkKey,
      chainId: args.chainId,
      blockedNonce: blockedNonceRaw || 'unknown',
      ...(Number.isFinite(ageRaw) ? { ageMs: ageRaw } : {}),
      cause: args.error,
    });
  }

  const message = extractErrorMessage(args.error).toLowerCase();
  if (
    message.includes('nonce lane blocked') ||
    (message.includes('nonce') && message.includes('blocked'))
  ) {
    return createEvmFamilySigningNonceLaneBlockedError({
      chain: args.chain,
      networkKey: args.networkKey,
      chainId: args.chainId,
      blockedNonce: 'unknown',
      cause: args.error,
    });
  }
  return args.error;
}

export function mapToRetryableNonceStateError(args: {
  error: unknown;
  chain: EvmFamilyChain;
  networkKey: string;
  chainId: number;
}): unknown {
  const mappedConflict = mapToRetryableNonceConflictError(args);
  return mapToRetryableNonceLaneBlockedError({
    ...args,
    error: mappedConflict,
  });
}

export function isNonceConflictRetryableError(
  error: unknown,
): error is EvmFamilySigningNonceConflictError {
  if (!error || typeof error !== 'object') return false;
  return extractErrorCode(error) === 'nonce_conflict_retryable';
}

export function isNonceLaneBlockedRetryableError(
  error: unknown,
): error is EvmFamilySigningNonceLaneBlockedError {
  if (!error || typeof error !== 'object') return false;
  return extractErrorCode(error) === 'nonce_lane_blocked';
}
