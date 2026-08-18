import type { RouterAbOwnerOperationAuthorizationDecisionV1Wire as RouterAbEcdsaOwnerOperationAuthorizationDecisionV1Wire } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire } from '@shared/utils/routerAbNormalSigningIdentity';

export type RouterAbOwnerOperationAuthorizationDecisionV1Wire =
  | RouterAbEcdsaOwnerOperationAuthorizationDecisionV1Wire
  | RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire;

export const WALLET_SESSION_QUOTA_EXHAUSTED_ERROR =
  '[WalletSessionQuotaAdmission] wallet-session quota is exhausted';
export const WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR =
  '[WalletSessionQuotaAdmission] wallet-session quota is reserved by an in-flight operation';

export type WalletSessionQuotaAdmissionFailureSource =
  | 'local_projection'
  | 'server_prepare'
  | 'trusted_status';

export type WalletSessionQuotaAdmissionRetryReason = 'exhausted' | 'stale_projection';

export type WalletSessionQuotaAdmissionFailure =
  | {
      kind: 'exhausted';
      source: WalletSessionQuotaAdmissionFailureSource;
      detail: string;
      retryAfterMs?: never;
      localProjectionVersion?: never;
      serverProjectionVersion?: never;
    }
  | {
      kind: 'in_flight';
      source: WalletSessionQuotaAdmissionFailureSource;
      detail: string;
      retryAfterMs: number;
      localProjectionVersion?: never;
      serverProjectionVersion?: never;
    }
  | {
      kind: 'stale_projection';
      source: WalletSessionQuotaAdmissionFailureSource;
      detail: string;
      localProjectionVersion: string;
      serverProjectionVersion: string;
      retryAfterMs?: never;
    };

export type WalletSessionQuotaAdmissionDecision =
  | {
      kind: 'request_fresh_step_up';
      reason: WalletSessionQuotaAdmissionRetryReason;
      failure: Extract<WalletSessionQuotaAdmissionFailure, { kind: 'exhausted' | 'stale_projection' }>;
      retryAfterMs?: never;
    }
  | {
      kind: 'wait_and_retry_admission';
      retryAfterMs: number;
      failure: Extract<WalletSessionQuotaAdmissionFailure, { kind: 'in_flight' }>;
      reason?: never;
    };

export type WalletSessionQuotaAdmissionQueueKey = string & {
  readonly __brand: 'WalletSessionQuotaAdmissionQueueKey';
};

export type OperationAuthorizationQueueKey = string & {
  readonly __brand: 'OperationAuthorizationQueueKey';
};

export type SigningAdmissionQueueKey =
  | WalletSessionQuotaAdmissionQueueKey
  | OperationAuthorizationQueueKey;

export class WalletSessionQuotaAdmissionError extends Error {
  readonly failure: WalletSessionQuotaAdmissionFailure;
  readonly authorizationDecision?: RouterAbOwnerOperationAuthorizationDecisionV1Wire;

  constructor(
    failure: WalletSessionQuotaAdmissionFailure,
    authorizationDecision?: RouterAbOwnerOperationAuthorizationDecisionV1Wire,
  ) {
    super(walletSessionQuotaAdmissionFailureMessage(failure));
    this.name = 'WalletSessionQuotaAdmissionError';
    this.failure = failure;
    this.authorizationDecision = authorizationDecision;
  }
}

export function isWalletSessionQuotaAdmissionError(
  error: unknown,
): error is WalletSessionQuotaAdmissionError {
  return error instanceof WalletSessionQuotaAdmissionError;
}

export function walletSessionQuotaAdmissionFailureMessage(
  failure: WalletSessionQuotaAdmissionFailure,
): string {
  switch (failure.kind) {
    case 'exhausted':
      return `${WALLET_SESSION_QUOTA_EXHAUSTED_ERROR}: ${failure.detail}`;
    case 'in_flight':
      return `${WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR}: ${failure.detail}`;
    case 'stale_projection':
      return `${WALLET_SESSION_QUOTA_EXHAUSTED_ERROR}: stale projection ${failure.localProjectionVersion} -> ${failure.serverProjectionVersion}: ${failure.detail}`;
  }
}

export function classifyWalletSessionQuotaAdmissionFailure(
  error: unknown,
): WalletSessionQuotaAdmissionFailure | null {
  if (isWalletSessionQuotaAdmissionError(error)) return error.failure;
  const message = error instanceof Error ? error.message : String(error || '');
  if (message.includes(WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR)) {
    return {
      kind: 'in_flight',
      source: 'local_projection',
      detail: message || WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR,
      retryAfterMs: 150,
    };
  }
  if (message.includes(WALLET_SESSION_QUOTA_EXHAUSTED_ERROR)) {
    return {
      kind: 'exhausted',
      source: 'local_projection',
      detail: message || WALLET_SESSION_QUOTA_EXHAUSTED_ERROR,
    };
  }
  return null;
}

export function decideWalletSessionQuotaAdmissionFailure(
  failure: WalletSessionQuotaAdmissionFailure,
): WalletSessionQuotaAdmissionDecision {
  switch (failure.kind) {
    case 'in_flight':
      return {
        kind: 'wait_and_retry_admission',
        retryAfterMs: failure.retryAfterMs,
        failure,
      };
    case 'exhausted':
      return {
        kind: 'request_fresh_step_up',
        reason: 'exhausted',
        failure,
      };
    case 'stale_projection':
      return {
        kind: 'request_fresh_step_up',
        reason: 'stale_projection',
        failure,
      };
  }
}

export function decideWalletSessionQuotaAdmissionError(
  error: unknown,
): WalletSessionQuotaAdmissionDecision | null {
  const failure = classifyWalletSessionQuotaAdmissionFailure(error);
  return failure ? decideWalletSessionQuotaAdmissionFailure(failure) : null;
}

export function buildWalletSessionQuotaAdmissionQueueKey(args: {
  walletId: string;
  curve: 'ed25519' | 'ecdsa';
  walletSessionId: string;
  quotaId: string;
  projectionVersion: string;
  authorityKey: string;
  targetKey: string;
}): WalletSessionQuotaAdmissionQueueKey {
  const walletId = normalizeQueueKeyPart(args.walletId, 'wallet');
  const walletSessionId = normalizeQueueKeyPart(args.walletSessionId, 'wallet session');
  const quotaId = normalizeQueueKeyPart(args.quotaId, 'quota');
  const projectionVersion = normalizeQueueKeyPart(args.projectionVersion, 'projection');
  const authorityKey = normalizeQueueKeyPart(args.authorityKey, 'authority');
  const targetKey = normalizeQueueKeyPart(args.targetKey, 'target');
  return [
    'wallet-session-quota-admission',
    walletId,
    args.curve,
    walletSessionId,
    quotaId,
    projectionVersion,
    authorityKey,
    targetKey,
  ].join(':') as WalletSessionQuotaAdmissionQueueKey;
}

export function buildOperationAuthorizationQueueKey(args: {
  walletId: string;
  materialActivationId: string;
  authorizationId: string;
  authorityKey: string;
  targetKey: string;
}): OperationAuthorizationQueueKey {
  return [
    'operation-authorization',
    normalizeQueueKeyPart(args.walletId, 'wallet'),
    normalizeQueueKeyPart(args.materialActivationId, 'activation'),
    normalizeQueueKeyPart(args.authorizationId, 'authorization'),
    normalizeQueueKeyPart(args.authorityKey, 'authority'),
    normalizeQueueKeyPart(args.targetKey, 'target'),
  ].join(':') as OperationAuthorizationQueueKey;
}

export async function waitForWalletSessionQuotaAdmissionRetry(retryAfterMs: number): Promise<void> {
  const delayMs = Math.max(0, Math.floor(Number(retryAfterMs) || 0));
  if (delayMs <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

function normalizeQueueKeyPart(value: string, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[WalletSessionQuotaAdmission] ${label} is required for admission queue key`);
  }
  return normalized;
}
