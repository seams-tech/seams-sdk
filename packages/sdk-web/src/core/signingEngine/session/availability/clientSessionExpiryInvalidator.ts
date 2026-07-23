import type {
  ClearVolatileWarmSessionMaterialCommand,
  VolatileWarmMaterialPort,
} from '../../uiConfirm/uiConfirm.types';
import type { ExpiredWalletSessionAuthorizationState } from '../identity/clientSessionPersistenceState';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { SigningGrantId } from '../operationState/types';
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
  readonly clearThresholdEcdsaSessionRecordForExactIdentity: (
    identity: ExactEcdsaSigningLaneIdentity,
  ) => void;
};

export type ClientWalletSessionExpiryInvalidatorDeps = {
  readonly readiness: ClientWalletSessionInvalidationReadinessDeps;
  readonly statusOverrides: Map<string, SigningGrantStatusOverride>;
};

export type WalletSessionExpiredEvent = {
  readonly kind: 'wallet_session_expired';
  readonly walletId: ExpiredWalletSessionAuthorizationState['walletId'];
  readonly walletSessionId: SigningGrantId;
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
  return `${String(state.walletId)}:${String(state.walletSessionId)}`;
}

function walletSessionExpiredEvent(
  state: ExpiredWalletSessionAuthorizationState,
): WalletSessionExpiredEvent {
  return {
    kind: 'wallet_session_expired',
    walletId: state.walletId,
    walletSessionId: state.walletSessionId,
    authMethod: state.authMethod,
    expiresAtMs: state.expiresAtMs,
    detectedAtMs: state.detectedAtMs,
  };
}

function toSigningGrantReadinessDeps(
  deps: ClientWalletSessionInvalidationReadinessDeps,
): SigningGrantReadinessDeps {
  const touchConfirm: Pick<VolatileWarmMaterialPort, 'clearVolatileWarmSessionMaterial'> = {
    clearVolatileWarmSessionMaterial: deps.touchConfirm.clearVolatileWarmSessionMaterial,
  };
  return {
    touchConfirm,
    clearEmailOtpWarmSessionMaterial: deps.clearEmailOtpWarmSessionMaterial,
    clearThresholdEcdsaSessionRecordForExactIdentity:
      deps.clearThresholdEcdsaSessionRecordForExactIdentity,
  };
}

export class ClientWalletSessionExpiryInvalidator {
  readonly #deps: ClientWalletSessionExpiryInvalidatorDeps;
  readonly #cleanupBySession = new Map<string, Promise<SigningGrantClearResult>>();
  readonly #eventDelivered = new Set<string>();

  constructor(deps: ClientWalletSessionExpiryInvalidatorDeps) {
    this.#deps = deps;
  }

  async invalidate(
    state: ExpiredWalletSessionAuthorizationState,
  ): Promise<ClientWalletSessionExpiryInvalidationResult> {
    const key = walletSessionInvalidationKey(state);
    let cleanup = this.#cleanupBySession.get(key);
    if (!cleanup) {
      cleanup = clearSigningGrant({
        deps: toSigningGrantReadinessDeps(this.#deps.readiness),
        statusOverrides: this.#deps.statusOverrides,
        walletId: state.walletId,
        signingGrantId: state.walletSessionId,
      });
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
      event: walletSessionExpiredEvent(state),
    };
  }
}
