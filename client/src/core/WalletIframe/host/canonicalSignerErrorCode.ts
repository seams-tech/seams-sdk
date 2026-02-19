import type { ParentToChildType } from '../shared/messages';

export type CanonicalWalletSignerErrorCode =
  | 'signing_in_progress'
  | 'session_not_ready'
  | 'deployment_in_progress'
  | 'deployment_failed'
  | 'cancelled';

const CANONICAL_SIGNER_CODES = new Set<CanonicalWalletSignerErrorCode>([
  'signing_in_progress',
  'session_not_ready',
  'deployment_in_progress',
  'deployment_failed',
  'cancelled',
]);

const SIGNER_BOUNDARY_REQUEST_TYPES = new Set<ParentToChildType>([
  'PM_SIGN_TEMPO',
  'PM_SIGN_TXS_WITH_ACTIONS',
  'PM_SIGN_AND_SEND_TXS',
  'PM_SEND_TRANSACTION',
  'PM_EXECUTE_ACTION',
  'PM_SIGN_DELEGATE_ACTION',
  'PM_SIGN_NEP413',
]);

function normalizeCodeToken(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

function normalizeMessage(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

function inferCanonicalCodeFromRawCode(rawCode: string): CanonicalWalletSignerErrorCode | null {
  if (!rawCode) return null;

  if (CANONICAL_SIGNER_CODES.has(rawCode as CanonicalWalletSignerErrorCode)) {
    return rawCode as CanonicalWalletSignerErrorCode;
  }

  if (rawCode === 'canceled' || rawCode === 'cancel' || rawCode === 'cancelled') {
    return 'cancelled';
  }

  if (rawCode === 'in_flight' || (rawCode.includes('signing') && rawCode.includes('progress'))) {
    return 'signing_in_progress';
  }

  if (
    rawCode === 'session_not_ready'
    || (rawCode.includes('session') && rawCode.includes('not_ready'))
    || (rawCode.includes('session') && rawCode.includes('expired'))
    || (rawCode.includes('session') && rawCode.includes('invalid'))
  ) {
    return 'session_not_ready';
  }

  if (
    rawCode === 'deployment_in_progress'
    || ((rawCode.includes('deployment') || rawCode.includes('deploy')) && rawCode.includes('progress'))
  ) {
    return 'deployment_in_progress';
  }

  if (
    rawCode === 'deployment_failed'
    || rawCode === 'deploy_failed'
    || ((rawCode.includes('deployment') || rawCode.includes('deploy')) && rawCode.includes('failed'))
    || ((rawCode.includes('deployment') || rawCode.includes('deploy')) && rawCode.includes('error'))
  ) {
    return 'deployment_failed';
  }

  return null;
}

function inferCanonicalCodeFromMessage(message: string): CanonicalWalletSignerErrorCode | null {
  if (!message) return null;

  if (message.includes('cancelled') || message.includes('canceled')) {
    return 'cancelled';
  }

  if (
    (message.includes('already in progress') || message.includes('in-flight'))
    && (message.includes('threshold ecdsa') || message.includes('signing'))
  ) {
    return 'signing_in_progress';
  }

  if (message.includes('smart-account deployment') || message.includes('[deployment]')) {
    if (message.includes('in progress') || message.includes('already in progress')) {
      return 'deployment_in_progress';
    }
    return 'deployment_failed';
  }

  if (
    message.includes('no cached threshold session token')
    || message.includes('relayer threshold session expired')
    || message.includes('threshold session exhausted')
    || message.includes('threshold session expired')
    || message.includes('missing or invalid threshold session token')
    || message.includes('invalid session token kind')
    || message.includes('/authorize http 401')
    || message.includes('/authorize http 403')
  ) {
    return 'session_not_ready';
  }

  if (
    message.includes('threshold session')
    && (
      message.includes('not ready')
      || message.includes('expired')
      || message.includes('missing')
      || message.includes('invalid')
      || message.includes('exhausted')
    )
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
