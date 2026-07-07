import {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
  type SigningSessionBudgetReservation,
} from './budget';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type { SelectedLane } from '../identity/laneIdentity';
import type { BudgetAdmittedOperation } from '../operationState/transactionState';

export type SigningGrantAdmissionFailureSource =
  | 'local_projection'
  | 'server_prepare'
  | 'trusted_status';

export type SigningGrantAdmissionRetryReason = 'exhausted' | 'stale_projection';

export type SigningGrantAdmissionFailure =
  | {
      kind: 'exhausted';
      source: SigningGrantAdmissionFailureSource;
      detail: string;
      retryAfterMs?: never;
      localProjectionVersion?: never;
      serverProjectionVersion?: never;
    }
  | {
      kind: 'in_flight';
      source: SigningGrantAdmissionFailureSource;
      detail: string;
      retryAfterMs: number;
      localProjectionVersion?: never;
      serverProjectionVersion?: never;
    }
  | {
      kind: 'stale_projection';
      source: SigningGrantAdmissionFailureSource;
      detail: string;
      localProjectionVersion: string;
      serverProjectionVersion: string;
      retryAfterMs?: never;
    };

export type SigningGrantAdmissionResult =
  | {
      kind: 'admitted';
      operation: BudgetAdmittedOperation<SelectedLane>;
      reservation: SigningSessionBudgetReservation | null;
    }
  | SigningGrantAdmissionFailure;

export type SigningGrantAdmissionDecision =
  | {
      kind: 'request_fresh_step_up';
      reason: SigningGrantAdmissionRetryReason;
      failure: Extract<SigningGrantAdmissionFailure, { kind: 'exhausted' | 'stale_projection' }>;
      retryAfterMs?: never;
    }
  | {
      kind: 'wait_and_retry_admission';
      retryAfterMs: number;
      failure: Extract<SigningGrantAdmissionFailure, { kind: 'in_flight' }>;
      reason?: never;
    };

export type SigningGrantAdmissionQueueKey = string & {
  readonly __brand: 'SigningGrantAdmissionQueueKey';
};

export class SigningGrantAdmissionError extends Error {
  readonly failure: SigningGrantAdmissionFailure;

  constructor(failure: SigningGrantAdmissionFailure) {
    super(signingGrantAdmissionFailureMessage(failure));
    this.name = 'SigningGrantAdmissionError';
    this.failure = failure;
  }
}

export function isSigningGrantAdmissionError(
  error: unknown,
): error is SigningGrantAdmissionError {
  return error instanceof SigningGrantAdmissionError;
}

export function signingGrantAdmissionFailureMessage(
  failure: SigningGrantAdmissionFailure,
): string {
  switch (failure.kind) {
    case 'exhausted':
      return `${SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR}: ${failure.detail}`;
    case 'in_flight':
      return `${SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR}: ${failure.detail}`;
    case 'stale_projection':
      return `${SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR}: stale projection ${failure.localProjectionVersion} -> ${failure.serverProjectionVersion}: ${failure.detail}`;
  }
}

export function routerAbNormalSigningAdmissionErrorFromPayload(args: {
  code: string;
  message: string;
  path: string;
  status: number;
}): SigningGrantAdmissionError | null {
  const code = String(args.code || '').trim();
  const detail = `Router A/B signing ${args.path} returned HTTP ${args.status}: ${
    args.message || code || 'unknown admission failure'
  }`;
  switch (code) {
    case 'wallet_budget_exhausted':
      return new SigningGrantAdmissionError({
        kind: 'exhausted',
        source: 'server_prepare',
        detail,
      });
    case 'wallet_budget_in_flight':
    case 'wallet_budget_reserved':
      return new SigningGrantAdmissionError({
        kind: 'in_flight',
        source: 'server_prepare',
        detail,
        retryAfterMs: 150,
      });
    default:
      return null;
  }
}

export function classifySigningGrantAdmissionFailure(
  error: unknown,
): SigningGrantAdmissionFailure | null {
  if (isSigningGrantAdmissionError(error)) return error.failure;
  const message = error instanceof Error ? error.message : String(error || '');
  if (message.includes(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR)) {
    return {
      kind: 'in_flight',
      source: 'local_projection',
      detail: message || SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
      retryAfterMs: 150,
    };
  }
  if (message.includes(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR)) {
    return {
      kind: 'exhausted',
      source: 'local_projection',
      detail: message || SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
    };
  }
  return null;
}

export function decideSigningGrantAdmissionFailure(
  failure: SigningGrantAdmissionFailure,
): SigningGrantAdmissionDecision {
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

export function decideSigningGrantAdmissionError(
  error: unknown,
): SigningGrantAdmissionDecision | null {
  const failure = classifySigningGrantAdmissionFailure(error);
  return failure ? decideSigningGrantAdmissionFailure(failure) : null;
}

export function buildSigningGrantAdmissionQueueKey(args: {
  walletId: string;
  curve: 'ed25519' | 'ecdsa';
  signingGrantId: string;
  projectionVersion: string;
  authorityKey: string;
  targetKey: string;
}): SigningGrantAdmissionQueueKey {
  const walletId = normalizeQueueKeyPart(args.walletId, 'wallet');
  const signingGrantId = normalizeQueueKeyPart(args.signingGrantId, 'grant');
  const projectionVersion = normalizeQueueKeyPart(args.projectionVersion, 'projection');
  const authorityKey = normalizeQueueKeyPart(args.authorityKey, 'authority');
  const targetKey = normalizeQueueKeyPart(args.targetKey, 'target');
  return [
    'signing-grant-admission',
    walletId,
    args.curve,
    signingGrantId,
    projectionVersion,
    authorityKey,
    targetKey,
  ].join(':') as SigningGrantAdmissionQueueKey;
}

export function signingGrantAdmissionAuthorityKeyFromAuth(
  auth: SigningLaneAuthBinding,
): string {
  switch (auth.kind) {
    case 'passkey': {
      const rpId = normalizeQueueKeyPart(String(auth.rpId), 'passkey rpId');
      const credentialId = normalizeQueueKeyPart(
        auth.credentialIdB64u,
        'passkey credential',
      );
      return ['passkey', rpId, credentialId].join(':');
    }
    case 'email_otp': {
      const providerSubjectId = normalizeQueueKeyPart(
        auth.providerSubjectId,
        'email otp provider subject',
      );
      return ['email_otp', providerSubjectId].join(':');
    }
  }
}

export async function waitForSigningGrantAdmissionRetry(retryAfterMs: number): Promise<void> {
  const delayMs = Math.max(0, Math.floor(Number(retryAfterMs) || 0));
  if (delayMs <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

function normalizeQueueKeyPart(value: string, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningGrantAdmission] ${label} is required for admission queue key`);
  }
  return normalized;
}
