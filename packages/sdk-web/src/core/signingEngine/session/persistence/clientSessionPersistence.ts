import {
  parseWalletSessionAuthorizationBoundary,
  type WalletSessionAuthorizationState,
} from '../identity/clientSessionPersistenceState';
import {
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import { exactSigningLaneWalletId } from '../identity/exactSigningLaneIdentity';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

export type ReadClientWalletSessionAuthorizationRequest =
  | {
      readonly kind: 'ed25519';
      readonly laneIdentity: ExactEd25519SigningLaneIdentity;
      readonly authorization?: never;
      readonly nowMs: number;
    }
  | {
      readonly kind: 'ecdsa';
      readonly laneIdentity: ExactEcdsaSigningLaneIdentity;
      readonly authorization: ActiveEvmFamilyWalletSessionAuthorization;
      readonly nowMs: number;
    };

async function readEd25519ClientWalletSessionAuthorization(
  request: Extract<ReadClientWalletSessionAuthorizationRequest, { kind: 'ed25519' }>,
): Promise<WalletSessionAuthorizationState> {
  const identity = request.laneIdentity;
  const source = { kind: 'ed25519' as const, laneIdentity: identity };
  const authorization = await walletSessionAuthorizations.readActiveForWallet(
    exactSigningLaneWalletId(identity),
  );
  switch (authorization.kind) {
    case 'missing':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'missing', source },
        nowMs: request.nowMs,
      });
    case 'corrupt':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'invalid', source, reason: 'malformed' },
        nowMs: request.nowMs,
      });
    case 'persistence_unavailable':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'unavailable', source, reason: 'persistence_unavailable' },
        nowMs: request.nowMs,
      });
    case 'found':
      break;
  }
  if (
    authorization.projection.walletId !== exactSigningLaneWalletId(identity) ||
    authorization.projection.authMethod !== signingLaneAuthMethod(identity.auth)
  ) {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'invalid', source, reason: 'scope_mismatch' },
      nowMs: request.nowMs,
    });
  }
  return parseWalletSessionAuthorizationBoundary({
    observation: {
      kind: 'found',
      source,
      expiresAtMs: authorization.projection.expiresAtMs,
    },
    nowMs: request.nowMs,
  });
}

function readEcdsaClientWalletSessionAuthorization(
  request: Extract<ReadClientWalletSessionAuthorizationRequest, { kind: 'ecdsa' }>,
): WalletSessionAuthorizationState {
  return parseWalletSessionAuthorizationBoundary({
    observation: {
      kind: 'found',
      source: {
        kind: 'ecdsa',
        laneIdentity: request.laneIdentity,
        authorization: request.authorization,
      },
      expiresAtMs: request.authorization.status.expiresAtMs,
    },
    nowMs: request.nowMs,
  });
}

export async function readClientWalletSessionAuthorization(
  request: ReadClientWalletSessionAuthorizationRequest,
): Promise<WalletSessionAuthorizationState> {
  switch (request.kind) {
    case 'ed25519':
      return await readEd25519ClientWalletSessionAuthorization(request);
    case 'ecdsa':
      return readEcdsaClientWalletSessionAuthorization(request);
  }
}
