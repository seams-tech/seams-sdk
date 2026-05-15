import type { SignerKind } from '@shared/utils/signerDomain';
import type { ParentToChildType } from '../shared/messages';

export type CanonicalWalletSignerErrorCode =
  | 'commit_queue_overflow'
  | 'commit_queue_timeout'
  | 'threshold_ed25519_session_not_ready'
  | 'threshold_ecdsa_session_not_ready'
  | 'stale_ecdsa_key_identity'
  | 'threshold_session_kind_mismatch'
  | 'session_not_ready'
  | 'fresh_email_otp_required'
  | 'passkey_step_up_required'
  | 'operation_blocked_by_policy'
  | 'deployment_in_progress'
  | 'deployment_failed'
  | 'nonce_conflict_retryable'
  | 'nonce_lane_blocked'
  | 'rpc_request_failed'
  | 'cancelled';

export type WalletSignerBoundaryKind = SignerKind;

const CANONICAL_SIGNER_CODES = new Set<CanonicalWalletSignerErrorCode>([
  'commit_queue_overflow',
  'commit_queue_timeout',
  'threshold_ed25519_session_not_ready',
  'threshold_ecdsa_session_not_ready',
  'stale_ecdsa_key_identity',
  'threshold_session_kind_mismatch',
  'session_not_ready',
  'fresh_email_otp_required',
  'passkey_step_up_required',
  'operation_blocked_by_policy',
  'deployment_in_progress',
  'deployment_failed',
  'nonce_conflict_retryable',
  'nonce_lane_blocked',
  'rpc_request_failed',
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

const THRESHOLD_ECDSA_REQUEST_TYPES = new Set<ParentToChildType>([
  'PM_SIGN_TEMPO',
  'PM_REPORT_TEMPO_BROADCAST_ACCEPTED',
  'PM_REPORT_TEMPO_BROADCAST_REJECTED',
  'PM_REPORT_TEMPO_FINALIZED',
  'PM_REPORT_TEMPO_DROPPED_OR_REPLACED',
  'PM_RECONCILE_TEMPO_NONCE_LANE',
]);

const THRESHOLD_ED25519_REQUEST_TYPES = new Set<ParentToChildType>([
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
  threshold_ed25519_session_not_ready:
    'Threshold Ed25519 signing session is not ready. Refresh the signing session and retry.',
  threshold_ecdsa_session_not_ready:
    'Threshold ECDSA signing session is not ready. Refresh the signing session and retry.',
  stale_ecdsa_key_identity:
    'The ECDSA signer identity is stale. Resync the wallet or relink this device before signing.',
  threshold_session_kind_mismatch:
    'Threshold signing session kind mismatch. Refresh the signing session and retry.',
  session_not_ready:
    'Threshold signing session is not ready. Refresh the signing session and retry.',
  fresh_email_otp_required:
    'Fresh Email OTP verification is required before this operation can continue.',
  passkey_step_up_required:
    'Passkey authentication is required before this operation can continue.',
  operation_blocked_by_policy:
    'This operation is blocked by wallet policy.',
  deployment_in_progress: 'Smart-account deployment is already in progress.',
  deployment_failed: 'Smart-account deployment failed before signing.',
  nonce_conflict_retryable: 'Nonce conflict detected. Refresh nonce state and retry the request.',
  nonce_lane_blocked:
    'Nonce lane is blocked by unresolved in-flight transaction(s). Reconcile lane state and retry.',
  rpc_request_failed: 'RPC request failed. Retry the request or use another RPC endpoint.',
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

export function resolveWalletBoundarySignerKind(requestType: unknown): WalletSignerBoundaryKind | null {
  if (!isWalletSignerBoundaryRequestType(requestType)) return null;
  if (THRESHOLD_ECDSA_REQUEST_TYPES.has(requestType)) return 'threshold-ecdsa';
  if (THRESHOLD_ED25519_REQUEST_TYPES.has(requestType)) return 'threshold-ed25519';
  return null;
}

function defaultSessionNotReadyCanonicalCodeForRequestType(
  requestType: unknown,
): CanonicalWalletSignerErrorCode {
  const signerKind = resolveWalletBoundarySignerKind(requestType);
  if (signerKind === 'threshold-ecdsa') return 'threshold_ecdsa_session_not_ready';
  if (signerKind === 'threshold-ed25519') return 'threshold_ed25519_session_not_ready';
  return 'session_not_ready';
}

export function isCanonicalSignerSessionBoundaryCode(code: unknown): boolean {
  const normalized = normalizeCodeToken(code);
  return (
    normalized === 'session_not_ready' ||
    normalized === 'threshold_ed25519_session_not_ready' ||
    normalized === 'threshold_ecdsa_session_not_ready' ||
    normalized === 'threshold_session_kind_mismatch'
  );
}

function inferCanonicalCodeFromRawCode(args: {
  rawCode: string;
  requestType?: unknown;
}): CanonicalWalletSignerErrorCode | null {
  const { rawCode, requestType } = args;
  if (!rawCode) return null;

  if (CANONICAL_SIGNER_CODES.has(rawCode as CanonicalWalletSignerErrorCode)) {
    return rawCode as CanonicalWalletSignerErrorCode;
  }

  if (looksLikeUserCancellationCode(rawCode)) {
    return 'cancelled';
  }

  if (
    rawCode === 'fresh_email_otp_required' ||
    rawCode === 'email_otp_required' ||
    rawCode === 'email_otp_reauth_required'
  ) {
    return 'fresh_email_otp_required';
  }

  if (
    rawCode === 'passkey_step_up_required' ||
    rawCode === 'passkey_required' ||
    rawCode === 'stronger_auth_required'
  ) {
    return 'passkey_step_up_required';
  }

  if (
    rawCode === 'operation_blocked_by_policy' ||
    rawCode === 'policy_blocked' ||
    (rawCode.includes('operation') && rawCode.includes('blocked') && rawCode.includes('policy'))
  ) {
    return 'operation_blocked_by_policy';
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
    rawCode === 'stale_ecdsa_key_identity' ||
    (rawCode.includes('stale') &&
      rawCode.includes('ecdsa') &&
      (rawCode.includes('identity') || rawCode.includes('key')))
  ) {
    return 'stale_ecdsa_key_identity';
  }

  if (
    rawCode === 'threshold_session_kind_mismatch' ||
    (rawCode.includes('session') && rawCode.includes('kind') && rawCode.includes('mismatch'))
  ) {
    return 'threshold_session_kind_mismatch';
  }

  if (
    rawCode === 'session_not_ready' ||
    (rawCode.includes('session') && rawCode.includes('not_ready')) ||
    (rawCode.includes('session') && rawCode.includes('expired')) ||
    (rawCode.includes('session') && rawCode.includes('invalid'))
  ) {
    return defaultSessionNotReadyCanonicalCodeForRequestType(requestType);
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

  if (
    rawCode === 'rpc_request_failed' ||
    rawCode === 'rpc_error' ||
    rawCode === 'request_timeout' ||
    rawCode === 'timeout'
  ) {
    return 'rpc_request_failed';
  }

  return null;
}

function inferCanonicalCodeFromMessage(args: {
  message: string;
  requestType?: unknown;
}): CanonicalWalletSignerErrorCode | null {
  const { message, requestType } = args;
  if (!message) return null;

  if (looksLikeUserCancellationMessage(message)) {
    return 'cancelled';
  }

  if (
    message.includes('fresh email otp') ||
    message.includes('verify email otp again') ||
    message.includes('requires fresh email otp verification') ||
    (message.includes('email otp') && message.includes('per_operation'))
  ) {
    return 'fresh_email_otp_required';
  }

  if (
    message.includes('passkey step-up') ||
    message.includes('requires fresh passkey authentication') ||
    message.includes('passkey authentication is required') ||
    message.includes('requires passkey authentication after email otp login')
  ) {
    return 'passkey_step_up_required';
  }

  if (
    message.includes('operation blocked by policy') ||
    message.includes('blocked by wallet policy') ||
    (message.includes('operation') && message.includes('blocked') && message.includes('policy'))
  ) {
    return 'operation_blocked_by_policy';
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
    message.includes('rpc request failed') ||
    message.includes('[nearclient] rpc call') ||
    message.includes('request timeout') ||
    message.includes('408')
  ) {
    return 'rpc_request_failed';
  }

  if (
    (message.includes('threshold-ecdsa bootstrap') &&
      message.includes('client verifying share') &&
      message.includes('integrated key record')) ||
    (message.includes('ecdsa') &&
      message.includes('stale') &&
      (message.includes('identity') || message.includes('key')))
  ) {
    return 'stale_ecdsa_key_identity';
  }

  if (
    message.includes('session kind mismatch') ||
    (message.includes('session') && message.includes('kind') && message.includes('mismatch'))
  ) {
    return 'threshold_session_kind_mismatch';
  }

  if (
    message.includes('no cached threshold session token') ||
    message.includes('missing threshold wrapkeysalt') ||
    message.includes('missing threshold wrap key salt') ||
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
    return defaultSessionNotReadyCanonicalCodeForRequestType(requestType);
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
    return defaultSessionNotReadyCanonicalCodeForRequestType(requestType);
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
  const fromCode = inferCanonicalCodeFromRawCode({
    rawCode: normalizeCodeToken(args.rawCode),
    requestType: args.requestType,
  });
  if (fromCode) return fromCode;

  if (!isWalletSignerBoundaryRequestType(args.requestType)) return null;
  return inferCanonicalCodeFromMessage({
    message: normalizeMessage(args.message),
    requestType: args.requestType,
  });
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
    return defaultSessionNotReadyCanonicalCodeForRequestType(args.requestType);
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
    return CANONICAL_SIGNER_ERROR_MESSAGES[
      defaultSessionNotReadyCanonicalCodeForRequestType(args.requestType)
    ];
  }

  const fallback = String(args.message || '').trim();
  return fallback || 'Wallet operation failed';
}
