import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
  WalletSigningSessionId,
} from '../operationState/types';

export type TrustedWalletBudgetStatus =
  | {
      source: 'server_status' | 'server_consume';
      sessionId: WalletSigningSessionId | string;
      status: 'active';
      remainingUses: number;
      expiresAtMs?: number;
      projectionVersion?: string;
    }
  | {
      source: 'server_status' | 'server_consume';
      sessionId: WalletSigningSessionId | string;
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
  sessionId: WalletSigningSessionId | string;
  status: 'budget_unknown';
  reason: WalletBudgetUnknownReason;
};

export type WalletBudgetPolicyHint = {
  sessionId: WalletSigningSessionId | string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
};

export type WalletBudgetMaterialStatus = {
  sessionId: string;
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

export type WalletBudgetProjection = {
  walletId: AccountId;
  walletSigningSessionId: WalletSigningSessionId | string;
  trustedStatus: TrustedWalletBudgetStatus | null;
  unknown: WalletBudgetUnknown | null;
  reservationsByOperationId: Map<string, WalletBudgetReservationProjection>;
  localReservedUses: number;
  effectiveRemainingUses?: number;
  projectionVersion?: string;
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
  walletId: AccountId;
  walletSigningSessionId: WalletSigningSessionId | string;
}): WalletBudgetProjection {
  return {
    walletId: args.walletId,
    walletSigningSessionId: args.walletSigningSessionId,
    trustedStatus: null,
    unknown: null,
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
        trustedStatus: event.status,
        unknown: null,
        projectionVersion: event.status.projectionVersion,
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
        trustedStatus: null,
        unknown: event.unknown,
        projectionVersion: undefined,
      });
  }
}

export function trustedBudgetStatusFromSigningSessionStatus(args: {
  status: SigningSessionStatus;
  source: TrustedWalletBudgetStatus['source'];
  projectionVersion?: string;
}): TrustedWalletBudgetStatus | null {
  const sessionId = String(args.status.sessionId || '').trim();
  if (!sessionId) return null;
  if (args.status.status === 'active') {
    return {
      source: args.source,
      sessionId,
      status: 'active',
      remainingUses: Math.max(0, Math.floor(Number(args.status.remainingUses) || 0)),
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
      sessionId,
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
  walletSigningSessionId: WalletSigningSessionId | string;
  reason: WalletBudgetUnknownReason;
}): SigningSessionStatus {
  return {
    sessionId: String(args.walletSigningSessionId),
    status: 'budget_unknown',
    statusCode: args.reason,
  };
}

export function projectionToSigningSessionStatus(
  projection: WalletBudgetProjection,
): SigningSessionStatus {
  if (projection.unknown) {
    return budgetUnknownSigningSessionStatus({
      walletSigningSessionId: projection.walletSigningSessionId,
      reason: projection.unknown.reason,
    });
  }
  const trustedStatus = projection.trustedStatus;
  if (!trustedStatus) {
    return budgetUnknownSigningSessionStatus({
      walletSigningSessionId: projection.walletSigningSessionId,
      reason: 'missing_trusted_status',
    });
  }
  if (trustedStatus.status !== 'active') {
    return {
      sessionId: String(trustedStatus.sessionId),
      status: trustedStatus.status,
      ...(trustedStatus.remainingUses !== undefined
        ? { remainingUses: trustedStatus.remainingUses }
        : {}),
      ...(trustedStatus.expiresAtMs ? { expiresAtMs: trustedStatus.expiresAtMs } : {}),
    };
  }
  return {
    sessionId: String(trustedStatus.sessionId),
    status: 'active',
    remainingUses: Math.max(0, Math.floor(Number(trustedStatus.remainingUses) || 0)),
    inFlightReservedUses: projection.localReservedUses,
    availableUses: Math.max(0, Math.floor(Number(projection.effectiveRemainingUses) || 0)),
    ...(trustedStatus.projectionVersion ? { projectionVersion: trustedStatus.projectionVersion } : {}),
    ...(trustedStatus.expiresAtMs ? { expiresAtMs: trustedStatus.expiresAtMs } : {}),
  };
}

function withTrustedStatus(
  projection: WalletBudgetProjection,
  status: TrustedWalletBudgetStatus,
): WalletBudgetProjection {
  return recalculate({
    ...projection,
    trustedStatus: status,
    unknown: null,
    projectionVersion: status.projectionVersion,
  });
}

function recalculate(projection: WalletBudgetProjection): WalletBudgetProjection {
  const trustedStatus = projection.trustedStatus;
  const projectionVersion = String(trustedStatus?.projectionVersion || '').trim();
  const localReservedUses = projectionVersion
    ? Array.from(projection.reservationsByOperationId.values()).reduce((sum, reservation) => {
        if (String(reservation.reservedAgainstProjectionVersion || '').trim() !== projectionVersion) {
          return sum;
        }
        return sum + Math.max(0, Math.floor(Number(reservation.uses) || 0));
      }, 0)
    : 0;
  const effectiveRemainingUses =
    trustedStatus?.status === 'active'
      ? Math.max(0, Math.floor(Number(trustedStatus.remainingUses) || 0) - localReservedUses)
      : undefined;
  return {
    ...projection,
    localReservedUses,
    ...(effectiveRemainingUses !== undefined ? { effectiveRemainingUses } : {}),
  };
}
