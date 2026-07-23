import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningGrantId } from '../operationState/types';
import {
  exactSigningLaneWalletId,
  type ExactSigningLaneIdentity,
} from './exactSigningLaneIdentity';
import { signingLaneAuthMethod } from './signingLaneAuthBinding';

export type WalletSessionAuthorizationUnavailableReason =
  | 'network'
  | 'server_unavailable';

export type WalletSessionAuthorizationInvalidReason =
  | 'malformed'
  | 'signature_invalid'
  | 'scope_mismatch'
  | 'authority_mismatch';

export type WalletSessionAuthorizationIdentity = {
  readonly walletId: WalletId;
  readonly walletSessionId: SigningGrantId;
  readonly authMethod: SignerAuthMethod;
  readonly laneIdentity: ExactSigningLaneIdentity;
};

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
  return {
    walletId: exactSigningLaneWalletId(laneIdentity),
    walletSessionId: laneIdentity.signingGrantId,
    authMethod: signingLaneAuthMethod(laneIdentity.auth),
    laneIdentity,
  };
}

function invalidAuthorization(args: {
  readonly identity: ExactSigningLaneIdentity;
  readonly reason: WalletSessionAuthorizationInvalidReason;
}): InvalidWalletSessionAuthorizationState {
  const identity = authorizationIdentity(args.identity);
  return {
    kind: 'invalid',
    walletId: identity.walletId,
    walletSessionId: identity.walletSessionId,
    authMethod: identity.authMethod,
    laneIdentity: identity.laneIdentity,
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
    walletId: identity.walletId,
    walletSessionId: identity.walletSessionId,
    authMethod: identity.authMethod,
    laneIdentity: identity.laneIdentity,
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
      walletId: identity.walletId,
      walletSessionId: identity.walletSessionId,
      authMethod: identity.authMethod,
      laneIdentity: identity.laneIdentity,
      expiresAtMs,
      detectedAtMs: args.nowMs,
    };
  }
  return {
    kind: 'active',
    walletId: identity.walletId,
    walletSessionId: identity.walletSessionId,
    authMethod: identity.authMethod,
    laneIdentity: identity.laneIdentity,
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
        walletId: missingIdentity.walletId,
        walletSessionId: missingIdentity.walletSessionId,
        authMethod: missingIdentity.authMethod,
        laneIdentity: missingIdentity.laneIdentity,
      };
    }
    case 'unavailable': {
      const unavailableIdentity = authorizationIdentity(args.observation.identity);
      return {
        kind: 'unavailable',
        walletId: unavailableIdentity.walletId,
        walletSessionId: unavailableIdentity.walletSessionId,
        authMethod: unavailableIdentity.authMethod,
        laneIdentity: unavailableIdentity.laneIdentity,
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
