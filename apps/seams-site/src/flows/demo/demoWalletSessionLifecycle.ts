export const DEMO_SIGNING_SESSION_EXPIRY_MESSAGE =
  'Your signing session expired. Unlock your wallet to continue.';
export const DEMO_SIGNING_SESSION_MISSING_MESSAGE =
  'Your signing session is no longer available. Unlock your wallet to continue.';

type DemoWalletAuthMethod = 'passkey' | 'email_otp';
export type DemoExactSessionIdentity = {
  readonly walletId: string;
  readonly walletSessionId: string;
  readonly authMethod: DemoWalletAuthMethod;
  readonly expiresAtMs: number;
};
type DemoActiveExactSessionState = DemoExactSessionIdentity & {
  readonly kind: 'active_session';
  readonly status: 'active' | 'active_restorable';
};
type DemoExpiredExactSessionState = DemoExactSessionIdentity & {
  readonly kind: 'expired_session';
};
export type DemoExactSessionState =
  | { readonly kind: 'wallet_locked' }
  | {
      readonly kind: 'wallet_unlocked_without_signing_session';
      readonly walletId: DemoExactSessionIdentity['walletId'];
      readonly reason: 'exhausted' | 'not_found' | 'unavailable' | 'budget_unknown' | 'invalid';
    }
  | DemoActiveExactSessionState
  | DemoExpiredExactSessionState;

export type DemoSigningSessionExpiredEvent = {
  readonly version: 1;
  readonly event: 'signing_session.expired';
  readonly walletId: string;
  readonly walletSessionId: string;
  readonly authMethod: DemoWalletAuthMethod;
  readonly expiresAtMs: number;
  readonly detectedAtMs: number;
  readonly source: 'restore' | 'visibility' | 'focus' | 'operation_preflight' | 'server_rejection';
};

export type DemoSigningSessionStatusSource = 'restore' | 'visibility' | 'focus' | 'poll';
type DemoSigningSessionExpirySource =
  | DemoSigningSessionExpiredEvent['source']
  | DemoSigningSessionStatusSource;

export type DemoWalletSessionLifecycleAction =
  | { readonly kind: 'preserve_unlocked' }
  | {
      readonly kind: 'lock_missing_session';
      readonly identity: {
        readonly walletId: DemoExactSessionIdentity['walletId'];
        readonly reason: 'not_found';
      };
    }
  | {
      readonly kind: 'lock_expired';
      readonly identity: DemoExactSessionIdentity;
      readonly source: DemoSigningSessionExpirySource;
    };

const PRESERVE_UNLOCKED_ACTION: DemoWalletSessionLifecycleAction = {
  kind: 'preserve_unlocked',
};

type DemoExpiredSessionLockState = 'locking' | 'handled';

export class DemoWalletSessionLifecycleController {
  private exactState: DemoExactSessionState = { kind: 'wallet_locked' };
  private readonly expiredSessionLocks = new Map<string, DemoExpiredSessionLockState>();
  private readonly missingSessionLocks = new Map<string, DemoExpiredSessionLockState>();

  observeExactState(
    state: DemoExactSessionState,
    source: DemoSigningSessionStatusSource,
  ): DemoWalletSessionLifecycleAction {
    this.exactState = state;
    switch (state.kind) {
      case 'wallet_locked':
      case 'active_session':
        return PRESERVE_UNLOCKED_ACTION;
      case 'wallet_unlocked_without_signing_session':
        return this.resolveUnavailableSession(state);
      case 'expired_session':
        return this.lockExpired(state, source);
      default:
        return assertNeverExactState(state);
    }
  }

  observeExpiredEvent(
    event: DemoSigningSessionExpiredEvent,
  ): DemoWalletSessionLifecycleAction {
    const state = this.exactState;
    if (state.kind !== 'active_session' && state.kind !== 'expired_session') {
      return PRESERVE_UNLOCKED_ACTION;
    }
    if (state.walletId !== event.walletId || state.walletSessionId !== event.walletSessionId) {
      return PRESERVE_UNLOCKED_ACTION;
    }
    const expiredState: DemoExpiredExactSessionState = {
      kind: 'expired_session',
      walletId: state.walletId,
      walletSessionId: state.walletSessionId,
      authMethod: state.authMethod,
      expiresAtMs: state.expiresAtMs,
    };
    this.exactState = expiredState;
    return this.lockExpired(expiredState, event.source);
  }

  confirmExpiredSessionLocked(identity: DemoExactSessionIdentity): void {
    const key = exactSessionKey(identity);
    if (this.expiredSessionLocks.get(key) !== 'locking') return;
    this.expiredSessionLocks.set(key, 'handled');
    this.exactState = { kind: 'wallet_locked' };
  }

  releaseExpiredSessionLock(identity: DemoExactSessionIdentity): void {
    const key = exactSessionKey(identity);
    if (this.expiredSessionLocks.get(key) === 'locking') {
      this.expiredSessionLocks.delete(key);
    }
  }

  confirmMissingSessionLocked(walletId: string): void {
    if (this.missingSessionLocks.get(walletId) !== 'locking') return;
    this.missingSessionLocks.set(walletId, 'handled');
    this.exactState = { kind: 'wallet_locked' };
  }

  releaseMissingSessionLock(walletId: string): void {
    if (this.missingSessionLocks.get(walletId) === 'locking') {
      this.missingSessionLocks.delete(walletId);
    }
  }

  private resolveUnavailableSession(
    state: Extract<DemoExactSessionState, { kind: 'wallet_unlocked_without_signing_session' }>,
  ): DemoWalletSessionLifecycleAction {
    switch (state.reason) {
      case 'not_found':
        if (this.missingSessionLocks.has(state.walletId)) return PRESERVE_UNLOCKED_ACTION;
        this.missingSessionLocks.set(state.walletId, 'locking');
        return {
          kind: 'lock_missing_session',
          identity: { walletId: state.walletId, reason: state.reason },
        };
      case 'exhausted':
      case 'unavailable':
      case 'budget_unknown':
      case 'invalid':
        return PRESERVE_UNLOCKED_ACTION;
      default:
        return assertNeverUnavailableReason(state.reason);
    }
  }

  private lockExpired(
    state: DemoExpiredExactSessionState,
    source: DemoSigningSessionExpirySource,
  ): DemoWalletSessionLifecycleAction {
    const key = exactSessionKey(state);
    if (this.expiredSessionLocks.has(key)) {
      return PRESERVE_UNLOCKED_ACTION;
    }
    this.expiredSessionLocks.set(key, 'locking');
    return {
      kind: 'lock_expired',
      identity: {
        walletId: state.walletId,
        walletSessionId: state.walletSessionId,
        authMethod: state.authMethod,
        expiresAtMs: state.expiresAtMs,
      },
      source,
    };
  }
}

function exactSessionKey(identity: DemoExactSessionIdentity): string {
  return demoSigningSessionExpiryKey(identity.walletId, identity.walletSessionId);
}

export function demoSigningSessionExpiryKey(
  walletId: string,
  walletSessionId: string,
): string {
  return `${encodeURIComponent(walletId)}:${encodeURIComponent(walletSessionId)}`;
}

function assertNeverExactState(value: never): never {
  throw new Error(`Unhandled exact Wallet Session state: ${String(value)}`);
}

function assertNeverUnavailableReason(value: never): never {
  throw new Error(`Unhandled unavailable Wallet Session reason: ${String(value)}`);
}

export function parseDemoSigningSessionExpiredEvent(
  value: unknown,
): DemoSigningSessionExpiredEvent | null {
  if (!isRecord(value) || value.version !== 1 || value.event !== 'signing_session.expired') {
    return null;
  }
  if (
    typeof value.walletId !== 'string' ||
    typeof value.walletSessionId !== 'string' ||
    !isDemoWalletAuthMethod(value.authMethod) ||
    !isPositiveSafeInteger(value.expiresAtMs) ||
    !isPositiveSafeInteger(value.detectedAtMs) ||
    !isExpiryDetectionSource(value.source)
  ) {
    return null;
  }
  return {
    version: 1,
    event: 'signing_session.expired',
    walletId: value.walletId,
    walletSessionId: value.walletSessionId,
    authMethod: value.authMethod,
    expiresAtMs: value.expiresAtMs,
    detectedAtMs: value.detectedAtMs,
    source: value.source,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDemoWalletAuthMethod(value: unknown): value is DemoWalletAuthMethod {
  return value === 'passkey' || value === 'email_otp';
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isExpiryDetectionSource(
  value: unknown,
): value is DemoSigningSessionExpiredEvent['source'] {
  switch (value) {
    case 'restore':
    case 'visibility':
    case 'focus':
    case 'operation_preflight':
    case 'server_rejection':
      return true;
    default:
      return false;
  }
}
