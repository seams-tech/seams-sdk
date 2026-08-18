import type {
  ClearVolatileWarmSessionMaterialCommand,
} from '../../uiConfirm/uiConfirm.types';
import type { ExpiredWalletSessionAuthorizationState } from '../identity/clientSessionPersistenceState';
import type { WalletSessionId } from '@shared/authorization/capabilityKinds';
import { createClearVolatileWarmSessionMaterialCommand } from '../warmCapabilities/volatileWarmMaterialCommands';
import {
  type WalletSessionClearFailure,
  type WalletSessionClearResult,
  type WalletSessionStatusOverride,
} from './readiness';

export type ClientWalletSessionInvalidationReadinessDeps = {
  readonly touchConfirm: {
    readonly clearVolatileWarmSessionMaterial: (
      command: ClearVolatileWarmSessionMaterialCommand,
    ) => Promise<void>;
  };
  readonly clearEmailOtpWarmSessionMaterial: (thresholdSessionId: string) => Promise<void>;
};

export type ClientWalletSessionExpiryInvalidatorDeps = {
  readonly readiness: ClientWalletSessionInvalidationReadinessDeps;
  readonly statusOverrides: Map<string, WalletSessionStatusOverride>;
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
      readonly failures: readonly WalletSessionClearFailure[];
      readonly event: null;
    };

function walletSessionInvalidationKey(
  state: ExpiredWalletSessionAuthorizationState,
): string {
  return `${String(state.walletId)}:wallet-session:${String(state.walletSessionId)}`;
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

async function clearExpiredAuthorization(args: {
  readonly deps: ClientWalletSessionExpiryInvalidatorDeps;
  readonly state: ExpiredWalletSessionAuthorizationState;
}): Promise<WalletSessionClearResult> {
  const lane = args.state.laneIdentity;
  if (!('thresholdSessionId' in lane)) return { kind: 'cleared' };
  try {
    if (lane.auth.kind === 'email_otp') {
      await args.deps.readiness.clearEmailOtpWarmSessionMaterial(lane.thresholdSessionId);
    } else {
      await args.deps.readiness.touchConfirm.clearVolatileWarmSessionMaterial(
        createClearVolatileWarmSessionMaterialCommand(lane.thresholdSessionId),
      );
    }
    return { kind: 'cleared' };
  } catch {
    return {
      kind: 'unavailable',
      failures: [lane.auth.kind === 'email_otp' ? 'email_otp_material' : 'touch_confirm_material'],
    };
  }
}

export class ClientWalletSessionExpiryInvalidator {
  readonly #deps: ClientWalletSessionExpiryInvalidatorDeps;
  readonly #cleanupBySession = new Map<string, Promise<WalletSessionClearResult>>();
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
