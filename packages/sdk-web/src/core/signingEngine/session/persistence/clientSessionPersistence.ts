import {
  parseWalletSessionAuthorizationBoundary,
  type WalletSessionAuthorizationState,
} from '../identity/clientSessionPersistenceState';
import {
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../../flows/signEvmFamily/ecdsaSigningCapability';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import {
  getStoredThresholdEd25519SessionRecordForLane,
} from './records';

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

function readEd25519ClientWalletSessionAuthorization(
  request: Extract<ReadClientWalletSessionAuthorizationRequest, { kind: 'ed25519' }>,
): WalletSessionAuthorizationState {
  const identity = request.laneIdentity;
  const signer = identity.signer;
  const record = getStoredThresholdEd25519SessionRecordForLane({
    walletId: signer.account.wallet.walletId,
    nearAccountId: signer.account.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    authMethod: signingLaneAuthMethod(identity.auth),
    signingGrantId: identity.signingGrantId,
    thresholdSessionId: identity.thresholdSessionId,
    signerSlot: signer.signerSlot,
  });
  if (!record) {
    return parseWalletSessionAuthorizationBoundary({
      observation: {
        kind: 'missing',
        source: { kind: 'ed25519', laneIdentity: identity },
      },
      nowMs: request.nowMs,
    });
  }
  return parseWalletSessionAuthorizationBoundary({
    observation: {
      kind: 'found',
      source: { kind: 'ed25519', laneIdentity: identity },
      expiresAtMs: record.expiresAtMs,
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

export function readClientWalletSessionAuthorization(
  request: ReadClientWalletSessionAuthorizationRequest,
): WalletSessionAuthorizationState {
  switch (request.kind) {
    case 'ed25519':
      return readEd25519ClientWalletSessionAuthorization(request);
    case 'ecdsa':
      return readEcdsaClientWalletSessionAuthorization(request);
  }
}
