import type { WalletSession } from '@/core/types/seams';
import type { WalletSessionId } from '@/core/types/sdkSentEvents';
import { parseSigningGrantId, parseWalletId, type WalletId } from '@shared/utils/domainIds';
import { isWalletAuthMethod, type WalletAuthMethod } from '@shared/utils/signerDomain';

export type WalletIframeExactSessionIdentity = {
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly authMethod: WalletAuthMethod;
  readonly expiresAtMs: number;
};

export type WalletIframeSessionUnavailableReason =
  | 'exhausted'
  | 'not_found'
  | 'unavailable'
  | 'budget_unknown'
  | 'invalid';

export type WalletIframeExactSessionState =
  | { readonly kind: 'wallet_locked' }
  | {
      readonly kind: 'wallet_unlocked_without_signing_session';
      readonly walletId: WalletId;
      readonly reason: WalletIframeSessionUnavailableReason;
    }
  | ({
      readonly kind: 'active_session';
      readonly status: 'active' | 'active_restorable';
    } & WalletIframeExactSessionIdentity)
  | ({ readonly kind: 'expired_session' } & WalletIframeExactSessionIdentity);

export type WalletIframePendingSessionBinding =
  | { readonly kind: 'unbound' }
  | ({ readonly kind: 'exact_session' } & WalletIframeExactSessionIdentity);

export type WalletIframeSessionExpiredFailure = {
  readonly kind: 'wallet_iframe_request_failure';
  readonly code: 'wallet_session_expired';
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
};

export type WalletIframeExactSessionLockResult =
  | {
      readonly kind: 'locked';
      readonly identity: WalletIframeExactSessionIdentity;
    }
  | {
      readonly kind: 'stale_session';
      readonly expected: WalletIframeExactSessionIdentity;
      readonly current: WalletIframeExactSessionState;
    };

export type WalletIframeMissingSessionIdentity = {
  readonly walletId: WalletId;
  readonly reason: 'not_found';
};

export type WalletIframeMissingSessionLockResult =
  | {
      readonly kind: 'locked';
      readonly identity: WalletIframeMissingSessionIdentity;
    }
  | {
      readonly kind: 'stale_session';
      readonly expected: WalletIframeMissingSessionIdentity;
      readonly current: WalletIframeExactSessionState;
    };

export class WalletIframeSessionExpiredRequestError extends Error {
  readonly failure: WalletIframeSessionExpiredFailure;

  constructor(failure: WalletIframeSessionExpiredFailure) {
    super('Wallet signing session expired');
    this.name = 'WalletIframeSessionExpiredRequestError';
    this.failure = failure;
  }
}

export function exactSessionStateFromWalletSession(
  session: WalletSession,
): WalletIframeExactSessionState {
  if (!session.login.isLoggedIn) return { kind: 'wallet_locked' };
  const walletId = parseWalletId(session.login.walletId);
  if (!walletId.ok) return { kind: 'wallet_locked' };
  const signingSession = session.signingSession;
  if (signingSession === null) {
    return unavailableSession(walletId.value, 'not_found');
  }
  switch (signingSession.status) {
    case 'active':
    case 'active_restorable': {
      const identity = exactIdentity(walletId.value, signingSession);
      if (identity === null) return unavailableSession(walletId.value, 'invalid');
      return { kind: 'active_session', status: signingSession.status, ...identity };
    }
    case 'expired': {
      const identity = exactIdentity(walletId.value, signingSession);
      if (identity === null) return unavailableSession(walletId.value, 'invalid');
      return { kind: 'expired_session', ...identity };
    }
    case 'exhausted':
    case 'not_found':
    case 'unavailable':
    case 'budget_unknown':
      return unavailableSession(walletId.value, signingSession.status);
    default:
      return assertNeverStatus(signingSession.status);
  }
}

export function parseWalletIframeExactSessionState(
  value: unknown,
): WalletIframeExactSessionState {
  if (!isRecord(value)) throw new Error('Wallet iframe exact session state must be an object');
  switch (value.kind) {
    case 'wallet_locked':
      return { kind: 'wallet_locked' };
    case 'wallet_unlocked_without_signing_session': {
      const walletId = requireWalletId(value.walletId);
      const reason = requireUnavailableReason(value.reason);
      return { kind: value.kind, walletId, reason };
    }
    case 'active_session': {
      const identity = parseIdentity(value);
      if (value.status !== 'active' && value.status !== 'active_restorable') {
        throw new Error('Wallet iframe active session status is invalid');
      }
      return { kind: value.kind, status: value.status, ...identity };
    }
    case 'expired_session':
      return { kind: value.kind, ...parseIdentity(value) };
    default:
      throw new Error('Wallet iframe exact session state kind is invalid');
  }
}

export function parseWalletIframeExactSessionIdentity(
  value: unknown,
): WalletIframeExactSessionIdentity {
  if (!isRecord(value)) throw new Error('Wallet iframe exact session identity must be an object');
  return parseIdentity(value);
}

export function parseWalletIframeExactSessionLockResult(
  value: unknown,
): WalletIframeExactSessionLockResult {
  if (!isRecord(value)) throw new Error('Wallet iframe exact session lock result must be an object');
  switch (value.kind) {
    case 'locked':
      return {
        kind: 'locked',
        identity: parseWalletIframeExactSessionIdentity(value.identity),
      };
    case 'stale_session':
      return {
        kind: 'stale_session',
        expected: parseWalletIframeExactSessionIdentity(value.expected),
        current: parseWalletIframeExactSessionState(value.current),
      };
    default:
      throw new Error('Wallet iframe exact session lock result kind is invalid');
  }
}

export function parseWalletIframeMissingSessionIdentity(
  value: unknown,
): WalletIframeMissingSessionIdentity {
  if (!isRecord(value)) throw new Error('Wallet iframe missing session identity must be an object');
  if (value.reason !== 'not_found') {
    throw new Error('Wallet iframe missing session reason must be not_found');
  }
  return {
    walletId: requireWalletId(value.walletId),
    reason: value.reason,
  };
}

export function parseWalletIframeMissingSessionLockResult(
  value: unknown,
): WalletIframeMissingSessionLockResult {
  if (!isRecord(value)) {
    throw new Error('Wallet iframe missing session lock result must be an object');
  }
  switch (value.kind) {
    case 'locked':
      return {
        kind: 'locked',
        identity: parseWalletIframeMissingSessionIdentity(value.identity),
      };
    case 'stale_session':
      return {
        kind: 'stale_session',
        expected: parseWalletIframeMissingSessionIdentity(value.expected),
        current: parseWalletIframeExactSessionState(value.current),
      };
    default:
      throw new Error('Wallet iframe missing session lock result kind is invalid');
  }
}

function exactIdentity(
  walletId: WalletId,
  session: NonNullable<WalletSession['signingSession']>,
): WalletIframeExactSessionIdentity | null {
  const walletSessionId = parseSigningGrantId(session.sessionId);
  if (!walletSessionId.ok || !isWalletAuthMethod(session.authMethod)) return null;
  if (!isPositiveSafeInteger(session.expiresAtMs)) return null;
  return {
    walletId,
    walletSessionId: walletSessionId.value,
    authMethod: session.authMethod,
    expiresAtMs: session.expiresAtMs,
  };
}

export function exactSessionIdentitiesMatch(
  left: WalletIframeExactSessionIdentity,
  right: WalletIframeExactSessionIdentity,
): boolean {
  return left.walletId === right.walletId && left.walletSessionId === right.walletSessionId;
}

function parseIdentity(value: Record<string, unknown>): WalletIframeExactSessionIdentity {
  const walletSessionId = parseSigningGrantId(value.walletSessionId);
  if (!walletSessionId.ok) throw new Error('Wallet iframe walletSessionId is invalid');
  if (!isWalletAuthMethod(value.authMethod)) throw new Error('Wallet iframe authMethod is invalid');
  if (!isPositiveSafeInteger(value.expiresAtMs)) throw new Error('Wallet iframe expiresAtMs is invalid');
  return {
    walletId: requireWalletId(value.walletId),
    walletSessionId: walletSessionId.value,
    authMethod: value.authMethod,
    expiresAtMs: value.expiresAtMs,
  };
}

function unavailableSession(
  walletId: WalletId,
  reason: WalletIframeSessionUnavailableReason,
): WalletIframeExactSessionState {
  return { kind: 'wallet_unlocked_without_signing_session', walletId, reason };
}

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error('Wallet iframe walletId is invalid');
  return parsed.value;
}

function requireUnavailableReason(value: unknown): WalletIframeSessionUnavailableReason {
  switch (value) {
    case 'exhausted':
    case 'not_found':
    case 'unavailable':
    case 'budget_unknown':
    case 'invalid':
      return value;
    default:
      throw new Error('Wallet iframe unavailable reason is invalid');
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function assertNeverStatus(value: never): never {
  throw new Error(`Unhandled signing session status: ${String(value)}`);
}
