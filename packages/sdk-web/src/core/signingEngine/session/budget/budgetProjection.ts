import type { SigningSessionStatus } from '@/core/types/seams';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
  SigningGrantId,
} from '../operationState/types';

export type TrustedWalletBudgetStatus =
  | {
      source: 'server_status' | 'server_consume';
      signingGrantId: SigningGrantId | string;
      status: 'active';
      remainingUses: number;
      availableUses: number;
      expiresAtMs?: number;
      projectionVersion?: string;
    }
  | {
      source: 'server_status' | 'server_consume';
      signingGrantId: SigningGrantId | string;
      status: 'expired' | 'exhausted' | 'not_found';
      remainingUses?: number;
      expiresAtMs?: number;
      projectionVersion?: string;
    };

export type WalletBudgetUnknownReason =
  | 'adapter_unavailable'
  | 'missing_trusted_status'
  | 'status_unavailable';

export type WalletBudgetUnknown = {
  source: 'budget_unknown';
  signingGrantId: SigningGrantId | string;
  status: 'budget_unknown';
  reason: WalletBudgetUnknownReason;
};

export type WalletBudgetPolicyHint = {
  signingGrantId: SigningGrantId | string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
};

export type WalletBudgetMaterialStatus = {
  signingGrantId: string;
  state: 'available' | 'missing' | 'exhausted' | 'unavailable';
  remainingUses?: number;
  expiresAtMs?: number;
};

export type WalletBudgetReservationProjection = {
  operationId: SigningOperationId | string;
  operationFingerprint: SigningOperationFingerprint | string;
  uses: number;
  reservedAgainstProjectionVersion: string;
  reservedAgainstRemainingUses?: number;
  createdAtMs?: number;
};

type ActiveTrustedWalletBudgetStatus = Extract<TrustedWalletBudgetStatus, { status: 'active' }>;
type InactiveTrustedWalletBudgetStatus = Exclude<
  TrustedWalletBudgetStatus,
  ActiveTrustedWalletBudgetStatus
>;

export type WalletBudgetProjectionState =
  | {
      kind: 'missing';
      trustedStatus?: never;
      unknown?: never;
      effectiveRemainingUses?: never;
      projectionVersion?: never;
    }
  | {
      kind: 'unknown';
      unknown: WalletBudgetUnknown;
      trustedStatus?: never;
      effectiveRemainingUses?: never;
      projectionVersion?: never;
    }
  | {
      kind: 'known';
      trustedStatus: ActiveTrustedWalletBudgetStatus;
      effectiveRemainingUses: number;
      projectionVersion: string;
      unknown?: never;
    }
  | {
      kind: 'expired';
      trustedStatus: InactiveTrustedWalletBudgetStatus;
      unknown?: never;
      effectiveRemainingUses?: never;
      projectionVersion?: string;
    };

export type WalletBudgetProjection = {
  walletId: WalletId;
  signingGrantId: SigningGrantId | string;
  state: WalletBudgetProjectionState;
  reservationsByOperationId: Map<string, WalletBudgetReservationProjection>;
  localReservedUses: number;
};

export type WalletBudgetProjectionEvent =
  | {
      type: 'server_status_observed';
      status: TrustedWalletBudgetStatus;
    }
  | {
      type: 'server_consume_confirmed';
      status: TrustedWalletBudgetStatus;
      operationId: SigningOperationId | string;
    }
  | {
      type: 'reserve_requested';
      reservation: WalletBudgetReservationProjection;
    }
  | {
      type: 'reservation_released';
      operationId: SigningOperationId | string;
    }
  | {
      type: 'zero_spend_recorded';
      operationId: SigningOperationId | string;
    }
  | {
      type: 'budget_unknown_observed';
      unknown: WalletBudgetUnknown;
    };

export function createWalletBudgetProjection(args: {
  walletId: WalletId;
  signingGrantId: SigningGrantId | string;
}): WalletBudgetProjection {
  return {
    walletId: args.walletId,
    signingGrantId: args.signingGrantId,
    state: { kind: 'missing' },
    reservationsByOperationId: new Map(),
    localReservedUses: 0,
  };
}

export function reduceWalletBudgetProjection(
  projection: WalletBudgetProjection,
  event: WalletBudgetProjectionEvent,
): WalletBudgetProjection {
  switch (event.type) {
    case 'server_status_observed':
      return withTrustedStatus(projection, event.status);
    case 'server_consume_confirmed': {
      const reservationsByOperationId = new Map(projection.reservationsByOperationId);
      reservationsByOperationId.delete(String(event.operationId));
      return recalculate({
        ...projection,
        state: trustedStatusProjectionState(event.status),
        reservationsByOperationId,
      });
    }
    case 'reserve_requested': {
      const reservationsByOperationId = new Map(projection.reservationsByOperationId);
      reservationsByOperationId.set(String(event.reservation.operationId), event.reservation);
      return recalculate({ ...projection, reservationsByOperationId });
    }
    case 'reservation_released':
    case 'zero_spend_recorded': {
      const reservationsByOperationId = new Map(projection.reservationsByOperationId);
      reservationsByOperationId.delete(String(event.operationId));
      return recalculate({ ...projection, reservationsByOperationId });
    }
    case 'budget_unknown_observed':
      return recalculate({
        ...projection,
        state: { kind: 'unknown', unknown: event.unknown },
      });
  }
}

export function trustedBudgetStatusFromSigningSessionStatus(args: {
  status: SigningSessionStatus;
  source: TrustedWalletBudgetStatus['source'];
  projectionVersion?: string;
}): TrustedWalletBudgetStatus | null {
  const signingGrantId = String(args.status.sessionId || '').trim();
  if (!signingGrantId) return null;
  if (args.status.status === 'active') {
    const remainingUses = Math.max(0, Math.floor(Number(args.status.remainingUses) || 0));
    const availableUses =
      args.status.availableUses === undefined
        ? remainingUses
        : Math.min(remainingUses, Math.max(0, Math.floor(Number(args.status.availableUses) || 0)));
    return {
      source: args.source,
      signingGrantId,
      status: 'active',
      remainingUses,
      availableUses,
      ...(args.status.expiresAtMs ? { expiresAtMs: Math.floor(args.status.expiresAtMs) } : {}),
      ...(args.projectionVersion ? { projectionVersion: args.projectionVersion } : {}),
    };
  }
  if (
    args.status.status === 'expired' ||
    args.status.status === 'exhausted' ||
    args.status.status === 'not_found'
  ) {
    return {
      source: args.source,
      signingGrantId,
      status: args.status.status,
      ...(args.status.remainingUses !== undefined
        ? { remainingUses: Math.max(0, Math.floor(Number(args.status.remainingUses) || 0)) }
        : {}),
      ...(args.status.expiresAtMs ? { expiresAtMs: Math.floor(args.status.expiresAtMs) } : {}),
      ...(args.projectionVersion ? { projectionVersion: args.projectionVersion } : {}),
    };
  }
  return null;
}

export function budgetUnknownSigningSessionStatus(args: {
  signingGrantId: SigningGrantId | string;
  reason: WalletBudgetUnknownReason;
}): SigningSessionStatus {
  return {
    sessionId: String(args.signingGrantId),
    status: 'budget_unknown',
    statusCode: args.reason,
  };
}

export function projectionToSigningSessionStatus(
  projection: WalletBudgetProjection,
): SigningSessionStatus {
  switch (projection.state.kind) {
    case 'missing':
      return budgetUnknownSigningSessionStatus({
        signingGrantId: projection.signingGrantId,
        reason: 'missing_trusted_status',
      });
    case 'unknown':
      return budgetUnknownSigningSessionStatus({
        signingGrantId: projection.signingGrantId,
        reason: projection.state.unknown.reason,
      });
    case 'expired': {
      const trustedStatus = projection.state.trustedStatus;
      return {
        sessionId: String(trustedStatus.signingGrantId),
        status: trustedStatus.status,
        ...(trustedStatus.remainingUses !== undefined
          ? { remainingUses: trustedStatus.remainingUses }
          : {}),
        ...(trustedStatus.expiresAtMs ? { expiresAtMs: trustedStatus.expiresAtMs } : {}),
      };
    }
    case 'known': {
      const trustedStatus = projection.state.trustedStatus;
      return {
        sessionId: String(trustedStatus.signingGrantId),
        status: 'active',
        remainingUses: Math.max(0, Math.floor(Number(trustedStatus.remainingUses) || 0)),
        inFlightReservedUses: projection.localReservedUses,
        availableUses: Math.max(
          0,
          Math.floor(Number(projection.state.effectiveRemainingUses) || 0),
        ),
        projectionVersion: projection.state.projectionVersion,
        ...(trustedStatus.expiresAtMs ? { expiresAtMs: trustedStatus.expiresAtMs } : {}),
      };
    }
  }
}

function withTrustedStatus(
  projection: WalletBudgetProjection,
  status: TrustedWalletBudgetStatus,
): WalletBudgetProjection {
  return recalculate({
    ...projection,
    state: trustedStatusProjectionState(status),
  });
}

function recalculate(projection: WalletBudgetProjection): WalletBudgetProjection {
  const state = projection.state;
  const projectionVersion = state.kind === 'known' ? state.projectionVersion : '';
  const localReservedUses = projectionVersion
    ? Array.from(projection.reservationsByOperationId.values()).reduce((sum, reservation) => {
        if (
          String(reservation.reservedAgainstProjectionVersion || '').trim() !== projectionVersion
        ) {
          return sum;
        }
        return sum + Math.max(0, Math.floor(Number(reservation.uses) || 0));
      }, 0)
    : 0;
  if (state.kind !== 'known') {
    return {
      ...projection,
      localReservedUses,
    };
  }
  const effectiveRemainingUses = Math.max(
    0,
    Math.floor(Number(state.trustedStatus.remainingUses) || 0) - localReservedUses,
  );
  return {
    ...projection,
    localReservedUses,
    state: {
      ...state,
      effectiveRemainingUses,
    },
  };
}

function trustedStatusProjectionState(
  status: TrustedWalletBudgetStatus,
): WalletBudgetProjectionState {
  if (status.status === 'active') {
    const projectionVersion = String(status.projectionVersion || '').trim();
    if (!projectionVersion) {
      return {
        kind: 'unknown',
        unknown: {
          source: 'budget_unknown',
          signingGrantId: status.signingGrantId,
          status: 'budget_unknown',
          reason: 'status_unavailable',
        },
      };
    }
    return {
      kind: 'known',
      trustedStatus: status,
      effectiveRemainingUses: Math.max(0, Math.floor(Number(status.remainingUses) || 0)),
      projectionVersion,
    };
  }
  return {
    kind: 'expired',
    trustedStatus: status,
    ...(status.projectionVersion ? { projectionVersion: status.projectionVersion } : {}),
  };
}
