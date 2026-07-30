import type {
  ClearVolatileWarmSessionMaterialCommand,
  VolatileWarmMaterialPort,
} from '../../uiConfirm/uiConfirm.types';
import type { ExpiredWalletSessionAuthorizationState } from '../identity/clientSessionPersistenceState';
import type { WalletSessionId } from '@shared/authorization/capabilityKinds';
import {
  clearSigningGrant,
  type SigningGrantClearFailure,
  type SigningGrantClearResult,
  type SigningGrantReadinessDeps,
  type SigningGrantStatusOverride,
} from './readiness';

export type ClientWalletSessionInvalidationReadinessDeps = {
  readonly touchConfirm: {
    readonly clearVolatileWarmSessionMaterial: (
      command: ClearVolatileWarmSessionMaterialCommand,
    ) => Promise<void>;
  };
  readonly clearEmailOtpWarmSessionMaterial: (sessionId: string) => Promise<void>;
};

export type ClientWalletSessionExpiryInvalidatorDeps = {
  readonly readiness: ClientWalletSessionInvalidationReadinessDeps;
  readonly statusOverrides: Map<string, SigningGrantStatusOverride>;
};

export type WalletSessionExpiredEvent = {
  readonly kind: 'wallet_session_expired';
  readonly walletId: ExpiredWalletSessionAuthorizationState['walletId'];
  readonly walletSessionId: WalletSessionId;
  readonly authMethod: ExpiredWalletSessionAuthorizationState['authMethod'];
  readonly expiresAtMs: number;
  readonly detectedAtMs: number;
};

export type ClientWalletSessionExpiryInvalidationResult =
  | {
      readonly kind: 'invalidated';
      readonly event: WalletSessionExpiredEvent;
    }
  | {
      readonly kind: 'already_invalidated';
      readonly event: null;
    }
  | {
      readonly kind: 'unavailable';
      readonly failures: readonly SigningGrantClearFailure[];
      readonly event: null;
    };

function walletSessionInvalidationKey(
  state: ExpiredWalletSessionAuthorizationState,
): string {
  return `${String(state.walletId)}:${
    'walletSessionId' in state
      ? `wallet-session:${String(state.walletSessionId)}`
      : `signing-grant:${String(state.signingGrantId)}`
  }`;
}

function walletSessionExpiredEvent(args: {
  readonly state: ExpiredWalletSessionAuthorizationState;
  readonly walletSessionId: WalletSessionId;
}): WalletSessionExpiredEvent {
  const state = args.state;
  return {
    kind: 'wallet_session_expired',
    walletId: state.walletId,
    walletSessionId: args.walletSessionId,
    authMethod: state.authMethod,
    expiresAtMs: state.expiresAtMs,
    detectedAtMs: state.detectedAtMs,
  };
}

export type InvalidateExpiredWalletSessionInput = {
  readonly state: ExpiredWalletSessionAuthorizationState;
  readonly walletSessionId: WalletSessionId;
};

function toSigningGrantReadinessDeps(
  deps: ClientWalletSessionInvalidationReadinessDeps,
): SigningGrantReadinessDeps {
  const touchConfirm: Pick<VolatileWarmMaterialPort, 'clearVolatileWarmSessionMaterial'> = {
    clearVolatileWarmSessionMaterial: deps.touchConfirm.clearVolatileWarmSessionMaterial,
  };
  return {
    touchConfirm,
    clearEmailOtpWarmSessionMaterial: deps.clearEmailOtpWarmSessionMaterial,
  };
}

async function clearExpiredAuthorization(args: {
  readonly deps: ClientWalletSessionExpiryInvalidatorDeps;
  readonly state: ExpiredWalletSessionAuthorizationState;
}): Promise<SigningGrantClearResult> {
  if ('walletSessionId' in args.state) {
    return { kind: 'cleared' };
  }
  return clearSigningGrant({
    deps: toSigningGrantReadinessDeps(args.deps.readiness),
    statusOverrides: args.deps.statusOverrides,
    walletId: args.state.walletId,
    signingGrantId: args.state.signingGrantId,
  });
}

export class ClientWalletSessionExpiryInvalidator {
  readonly #deps: ClientWalletSessionExpiryInvalidatorDeps;
  readonly #cleanupBySession = new Map<string, Promise<SigningGrantClearResult>>();
  readonly #eventDelivered = new Set<string>();

  constructor(deps: ClientWalletSessionExpiryInvalidatorDeps) {
    this.#deps = deps;
  }

  async invalidate(
    input: InvalidateExpiredWalletSessionInput,
  ): Promise<ClientWalletSessionExpiryInvalidationResult> {
    const state = input.state;
    const key = walletSessionInvalidationKey(state);
    let cleanup = this.#cleanupBySession.get(key);
    if (!cleanup) {
      cleanup = clearExpiredAuthorization({ deps: this.#deps, state });
      this.#cleanupBySession.set(key, cleanup);
    }
    const cleanupResult = await cleanup;
    if (cleanupResult.kind === 'unavailable') {
      this.#cleanupBySession.delete(key);
      return {
        kind: 'unavailable',
        failures: cleanupResult.failures,
        event: null,
      };
    }
    if (this.#eventDelivered.has(key)) {
      return { kind: 'already_invalidated', event: null };
    }
    this.#eventDelivered.add(key);
    return {
      kind: 'invalidated',
      event: walletSessionExpiredEvent(input),
    };
  }
}
