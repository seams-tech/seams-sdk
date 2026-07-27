import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningGrantId } from '../operationState/types';
import {
  exactSigningLaneWalletId,
  isExactEcdsaSigningLaneIdentity,
  type ExactSigningLaneIdentity,
} from './exactSigningLaneIdentity';
import { signingLaneAuthMethod } from './signingLaneAuthBinding';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type WalletSessionAuthorizationUnavailableReason =
  | 'network'
  | 'server_unavailable';

export type WalletSessionAuthorizationInvalidReason =
  | 'malformed'
  | 'signature_invalid'
  | 'scope_mismatch'
  | 'authority_mismatch';

type CommonWalletSessionAuthorizationIdentity = {
  readonly walletId: WalletId;
  readonly authMethod: SignerAuthMethod;
  readonly laneIdentity: ExactSigningLaneIdentity;
};

export type WalletSessionAuthorizationIdentity =
  | (CommonWalletSessionAuthorizationIdentity & {
      readonly signingGrantId: SigningGrantId;
      readonly walletSessionId?: never;
      readonly quotaId?: never;
    })
  | (CommonWalletSessionAuthorizationIdentity & {
      readonly signingGrantId?: never;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
    });

export type WalletSessionAuthorizationObservation =
  | {
      readonly kind: 'found';
      readonly identity: ExactSigningLaneIdentity;
      readonly expiresAtMs: unknown;
    }
  | {
      readonly kind: 'missing';
      readonly identity: ExactSigningLaneIdentity;
    }
  | {
      readonly kind: 'unavailable';
      readonly identity: ExactSigningLaneIdentity;
      readonly reason: WalletSessionAuthorizationUnavailableReason;
    }
  | {
      readonly kind: 'invalid';
      readonly identity: ExactSigningLaneIdentity;
      readonly reason: WalletSessionAuthorizationInvalidReason;
    };

type WalletSessionAuthorizationBase = WalletSessionAuthorizationIdentity & {
  readonly expiresAtMs: number;
};

export type ActiveWalletSessionAuthorizationState = WalletSessionAuthorizationBase & {
  readonly kind: 'active';
};

export type ExpiredWalletSessionAuthorizationState = WalletSessionAuthorizationBase & {
  readonly kind: 'expired';
  readonly detectedAtMs: number;
};

export type MissingWalletSessionAuthorizationState = WalletSessionAuthorizationIdentity & {
  readonly kind: 'missing';
};

export type UnavailableWalletSessionAuthorizationState = WalletSessionAuthorizationIdentity & {
  readonly kind: 'unavailable';
  readonly reason: WalletSessionAuthorizationUnavailableReason;
};

export type InvalidWalletSessionAuthorizationState = WalletSessionAuthorizationIdentity & {
  readonly kind: 'invalid';
  readonly reason: WalletSessionAuthorizationInvalidReason;
};

export type WalletSessionAuthorizationState =
  | ActiveWalletSessionAuthorizationState
  | ExpiredWalletSessionAuthorizationState
  | MissingWalletSessionAuthorizationState
  | UnavailableWalletSessionAuthorizationState
  | InvalidWalletSessionAuthorizationState;

function authorizationIdentity(
  laneIdentity: ExactSigningLaneIdentity,
): WalletSessionAuthorizationIdentity {
  const common = {
    walletId: exactSigningLaneWalletId(laneIdentity),
    authMethod: signingLaneAuthMethod(laneIdentity.auth),
    laneIdentity,
  };
  if (isExactEcdsaSigningLaneIdentity(laneIdentity)) {
    return {
      ...common,
      walletSessionId: laneIdentity.authorization.projection.walletSessionId,
      quotaId: laneIdentity.authorization.projection.quotaId,
    };
  }
  return {
    ...common,
    signingGrantId: laneIdentity.signingGrantId,
  };
}

function invalidAuthorization(args: {
  readonly identity: ExactSigningLaneIdentity;
  readonly reason: WalletSessionAuthorizationInvalidReason;
}): InvalidWalletSessionAuthorizationState {
  const identity = authorizationIdentity(args.identity);
  return {
    kind: 'invalid',
    ...identity,
    reason: args.reason,
  };
}

function parseBoundaryTime(value: unknown): number | null {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
  return parsed;
}

export function requireAuthoritativeExpiredWalletSessionAuthorizationBoundary(args: {
  readonly identity: ExactSigningLaneIdentity;
  readonly expiresAtMs: unknown;
  readonly detectedAtMs: unknown;
}): ExpiredWalletSessionAuthorizationState {
  const expiresAtMs = parseBoundaryTime(args.expiresAtMs);
  const detectedAtMs = parseBoundaryTime(args.detectedAtMs);
  if (expiresAtMs === null || expiresAtMs === 0) {
    throw new Error('Authoritative expired Wallet Session expiresAtMs is invalid');
  }
  if (detectedAtMs === null || detectedAtMs === 0) {
    throw new Error('Authoritative expired Wallet Session detectedAtMs is invalid');
  }
  if (expiresAtMs > detectedAtMs) {
    throw new Error('Authoritative expired Wallet Session timeline is invalid');
  }
  const identity = authorizationIdentity(args.identity);
  return {
    kind: 'expired',
    ...identity,
    expiresAtMs,
    detectedAtMs,
  };
}

function parseFoundAuthorization(args: {
  readonly observation: Extract<WalletSessionAuthorizationObservation, { kind: 'found' }>;
  readonly nowMs: number;
}): WalletSessionAuthorizationState {
  const expiresAtMs = parseBoundaryTime(args.observation.expiresAtMs);
  if (expiresAtMs === null || expiresAtMs === 0) {
    return invalidAuthorization({
      identity: args.observation.identity,
      reason: 'malformed',
    });
  }
  const identity = authorizationIdentity(args.observation.identity);
  if (expiresAtMs <= args.nowMs) {
    return {
      kind: 'expired',
      ...identity,
      expiresAtMs,
      detectedAtMs: args.nowMs,
    };
  }
  return {
    kind: 'active',
    ...identity,
    expiresAtMs,
  };
}

export function parseWalletSessionAuthorizationBoundary(args: {
  readonly observation: WalletSessionAuthorizationObservation;
  readonly nowMs: number;
}): WalletSessionAuthorizationState {
  const nowMs = parseBoundaryTime(args.nowMs);
  if (nowMs === null) {
    return invalidAuthorization({
      identity: args.observation.identity,
      reason: 'malformed',
    });
  }
  switch (args.observation.kind) {
    case 'found':
      return parseFoundAuthorization({ observation: args.observation, nowMs });
    case 'missing': {
      const missingIdentity = authorizationIdentity(args.observation.identity);
      return {
        kind: 'missing',
        ...missingIdentity,
      };
    }
    case 'unavailable': {
      const unavailableIdentity = authorizationIdentity(args.observation.identity);
      return {
        kind: 'unavailable',
        ...unavailableIdentity,
        reason: args.observation.reason,
      };
    }
    case 'invalid':
      return invalidAuthorization({
        identity: args.observation.identity,
        reason: args.observation.reason,
      });
    default: {
      const exhaustive: never = args.observation;
      return exhaustive;
    }
  }
}

export function requireActiveWalletSessionAuthorization(
  state: ActiveWalletSessionAuthorizationState,
): ActiveWalletSessionAuthorizationState {
  return state;
}
