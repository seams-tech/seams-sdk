import type { ParentToChildType } from '../shared/messages';

export type CanonicalWalletSignerErrorCode =
  | 'commit_queue_overflow'
  | 'commit_queue_timeout'
  | 'session_not_ready'
  | 'deployment_in_progress'
  | 'deployment_failed'
  | 'nonce_conflict_retryable'
  | 'nonce_lane_blocked'
  | 'cancelled';

const CANONICAL_SIGNER_CODES = new Set<CanonicalWalletSignerErrorCode>([
  'commit_queue_overflow',
  'commit_queue_timeout',
  'session_not_ready',
  'deployment_in_progress',
  'deployment_failed',
  'nonce_conflict_retryable',
  'nonce_lane_blocked',
  'cancelled',
]);

const SIGNER_BOUNDARY_REQUEST_TYPES = new Set<ParentToChildType>([
  'PM_SIGN_TEMPO',
  'PM_REPORT_TEMPO_BROADCAST_ACCEPTED',
  'PM_REPORT_TEMPO_BROADCAST_REJECTED',
  'PM_REPORT_TEMPO_FINALIZED',
  'PM_REPORT_TEMPO_DROPPED_OR_REPLACED',
  'PM_RECONCILE_TEMPO_NONCE_LANE',
  'PM_SIGN_TXS_WITH_ACTIONS',
  'PM_SIGN_AND_SEND_TXS',
  'PM_SEND_TRANSACTION',
  'PM_EXECUTE_ACTION',
  'PM_SIGN_DELEGATE_ACTION',
  'PM_SIGN_NEP413',
]);

const CANONICAL_SIGNER_ERROR_MESSAGES: Record<CanonicalWalletSignerErrorCode, string> = {
  commit_queue_overflow:
    'Threshold signing commit queue is full. Wait for pending requests and retry.',
  commit_queue_timeout: 'Threshold signing commit request timed out in queue. Retry the request.',
  session_not_ready:
    'Threshold signing session is not ready. Refresh the signing session and retry.',
  deployment_in_progress: 'Smart-account deployment is already in progress.',
  deployment_failed: 'Smart-account deployment failed before signing.',
  nonce_conflict_retryable: 'Nonce conflict detected. Refresh nonce state and retry the request.',
  nonce_lane_blocked:
    'Nonce lane is blocked by unresolved in-flight transaction(s). Reconcile lane state and retry.',
  cancelled: 'Request cancelled.',
};

function normalizeCodeToken(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

function normalizeMessage(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function looksLikeUserCancellationCode(rawCode: string): boolean {
  if (!rawCode) return false;

  return (
    rawCode === 'cancelled' ||
    rawCode === 'canceled' ||
    rawCode === 'cancel' ||
    rawCode === '4001' ||
    rawCode === 'action_rejected' ||
    rawCode === 'user_rejected' ||
    rawCode === 'user_rejected_request' ||
    rawCode === 'request_rejected' ||
    rawCode === 'rejected_by_user' ||
    rawCode === 'user_denied' ||
    rawCode === 'user_denied_request'
  );
}

function looksLikeUserCancellationMessage(message: string): boolean {
  if (!message) return false;

  return (
    message.includes('cancelled') ||
    message.includes('canceled') ||
    message.includes('user rejected') ||
    message.includes('rejected by user') ||
    message.includes('rejected by the user') ||
    message.includes('the user rejected') ||
    message.includes('user denied') ||
    message.includes('denied by user')
  );
}

function inferCanonicalCodeFromRawCode(rawCode: string): CanonicalWalletSignerErrorCode | null {
  if (!rawCode) return null;

  if (CANONICAL_SIGNER_CODES.has(rawCode as CanonicalWalletSignerErrorCode)) {
    return rawCode as CanonicalWalletSignerErrorCode;
  }

  if (looksLikeUserCancellationCode(rawCode)) {
    return 'cancelled';
  }

  if (
    rawCode === 'commit_queue_overflow' ||
    (rawCode.includes('commit') && rawCode.includes('queue') && rawCode.includes('overflow'))
  ) {
    return 'commit_queue_overflow';
  }

  if (
    rawCode === 'commit_queue_timeout' ||
    (rawCode.includes('commit') && rawCode.includes('queue') && rawCode.includes('timeout'))
  ) {
    return 'commit_queue_timeout';
  }

  if (
    rawCode === 'session_not_ready' ||
    (rawCode.includes('session') && rawCode.includes('not_ready')) ||
    (rawCode.includes('session') && rawCode.includes('expired')) ||
    (rawCode.includes('session') && rawCode.includes('invalid'))
  ) {
    return 'session_not_ready';
  }

  if (
    rawCode === 'deployment_in_progress' ||
    ((rawCode.includes('deployment') || rawCode.includes('deploy')) && rawCode.includes('progress'))
  ) {
    return 'deployment_in_progress';
  }

  if (
    rawCode === 'deployment_failed' ||
    rawCode === 'deploy_failed' ||
    ((rawCode.includes('deployment') || rawCode.includes('deploy')) &&
      rawCode.includes('failed')) ||
    ((rawCode.includes('deployment') || rawCode.includes('deploy')) && rawCode.includes('error'))
  ) {
    return 'deployment_failed';
  }

  if (
    rawCode === 'nonce_conflict_retryable' ||
    ((rawCode.includes('nonce') || rawCode.includes('already_known')) &&
      (rawCode.includes('conflict') ||
        rawCode.includes('too_low') ||
        rawCode.includes('too_high') ||
        rawCode.includes('underpriced') ||
        rawCode.includes('already_known')))
  ) {
    return 'nonce_conflict_retryable';
  }

  if (
    rawCode === 'nonce_lane_blocked' ||
    (rawCode.includes('nonce') && rawCode.includes('lane') && rawCode.includes('blocked'))
  ) {
    return 'nonce_lane_blocked';
  }

  return null;
}

function inferCanonicalCodeFromMessage(message: string): CanonicalWalletSignerErrorCode | null {
  if (!message) return null;

  if (looksLikeUserCancellationMessage(message)) {
    return 'cancelled';
  }

  if (
    message.includes('commit queue overflow') &&
    (message.includes('threshold ecdsa') || message.includes('threshold signing'))
  ) {
    return 'commit_queue_overflow';
  }

  if (
    message.includes('commit queue timeout') &&
    (message.includes('threshold ecdsa') || message.includes('threshold signing'))
  ) {
    return 'commit_queue_timeout';
  }

  if (message.includes('smart-account deployment') || message.includes('[deployment]')) {
    if (message.includes('in progress') || message.includes('already in progress')) {
      return 'deployment_in_progress';
    }
    return 'deployment_failed';
  }

  if (
    message.includes('nonce lane blocked') ||
    (message.includes('nonce lane') && message.includes('blocked'))
  ) {
    return 'nonce_lane_blocked';
  }

  if (
    message.includes('nonce conflict') ||
    message.includes('nonce too low') ||
    message.includes('nonce too high') ||
    message.includes('already known') ||
    message.includes('replacement transaction underpriced') ||
    message.includes('invalid nonce')
  ) {
    return 'nonce_conflict_retryable';
  }

  if (
    message.includes('no cached threshold session token') ||
    message.includes('threshold-ecdsa session token unavailable') ||
    message.includes('threshold-ecdsa session record not available') ||
    message.includes('missing canonical threshold ecdsa session') ||
    message.includes('relayer threshold session expired') ||
    message.includes('threshold session exhausted') ||
    message.includes('threshold session expired') ||
    message.includes('missing or invalid threshold session token') ||
    message.includes('invalid session token kind') ||
    message.includes('/authorize http 401') ||
    message.includes('/authorize http 403')
  ) {
    return 'session_not_ready';
  }

  if (
    (message.includes('threshold session') || message.includes('threshold signingsession')) &&
    (message.includes('not ready') ||
      message.includes('not_found') ||
      message.includes('expired') ||
      message.includes('missing') ||
      message.includes('invalid') ||
      message.includes('exhausted'))
  ) {
    return 'session_not_ready';
  }

  return null;
}

export function isWalletSignerBoundaryRequestType(value: unknown): value is ParentToChildType {
  return typeof value === 'string' && SIGNER_BOUNDARY_REQUEST_TYPES.has(value as ParentToChildType);
}

export function resolveCanonicalWalletSignerErrorCode(args: {
  requestType?: unknown;
  rawCode?: unknown;
  message?: unknown;
}): CanonicalWalletSignerErrorCode | null {
  const fromCode = inferCanonicalCodeFromRawCode(normalizeCodeToken(args.rawCode));
  if (fromCode) return fromCode;

  if (!isWalletSignerBoundaryRequestType(args.requestType)) return null;
  return inferCanonicalCodeFromMessage(normalizeMessage(args.message));
}

export function resolveWalletBoundaryErrorCode(args: {
  requestType?: unknown;
  rawCode?: unknown;
  message?: unknown;
  defaultCode?: string;
}): string {
  const canonical = resolveCanonicalWalletSignerErrorCode(args);
  if (canonical) return canonical;

  if (isWalletSignerBoundaryRequestType(args.requestType)) {
    // Signer boundary contract: never leak non-canonical internal codes.
    return 'session_not_ready';
  }

  const rawCode = String(args.rawCode || '').trim();
  if (rawCode) return rawCode;

  const fallback = String(args.defaultCode || 'HOST_ERROR').trim();
  return fallback || 'HOST_ERROR';
}

export function resolveWalletBoundaryErrorMessage(args: {
  requestType?: unknown;
  rawCode?: unknown;
  code?: unknown;
  message?: unknown;
}): string {
  const canonical = resolveCanonicalWalletSignerErrorCode({
    requestType: args.requestType,
    rawCode: args.rawCode ?? args.code,
    message: args.message,
  });
  if (canonical) {
    return CANONICAL_SIGNER_ERROR_MESSAGES[canonical];
  }

  if (isWalletSignerBoundaryRequestType(args.requestType)) {
    return CANONICAL_SIGNER_ERROR_MESSAGES.session_not_ready;
  }

  const fallback = String(args.message || '').trim();
  return fallback || 'Wallet operation failed';
}
