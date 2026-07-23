import {
  parseWalletSessionAuthorizationBoundary,
  type WalletSessionAuthorizationState,
} from '../identity/clientSessionPersistenceState';
import {
  isExactEcdsaSigningLaneIdentity,
  type ExactSigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import { signingLaneAuthMethod } from '../identity/signingLaneAuthBinding';
import {
  getStoredThresholdEd25519SessionRecordForLane,
  readExactThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from './records';

export type ReadClientWalletSessionAuthorizationRequest = {
  readonly identity: ExactSigningLaneIdentity;
  readonly ecdsaStore: ThresholdEcdsaSessionStoreDeps;
  readonly nowMs: number;
};

function readEd25519ClientWalletSessionAuthorization(
  request: ReadClientWalletSessionAuthorizationRequest,
): WalletSessionAuthorizationState {
  const identity = request.identity;
  if (identity.signer.kind !== 'near_ed25519_signer') {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'invalid', identity, reason: 'authority_mismatch' },
      nowMs: request.nowMs,
    });
  }
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
      observation: { kind: 'missing', identity },
      nowMs: request.nowMs,
    });
  }
  return parseWalletSessionAuthorizationBoundary({
    observation: {
      kind: 'found',
      identity,
      expiresAtMs: record.expiresAtMs,
    },
    nowMs: request.nowMs,
  });
}

function readEcdsaClientWalletSessionAuthorization(
  request: ReadClientWalletSessionAuthorizationRequest,
): WalletSessionAuthorizationState {
  const identity = request.identity;
  if (!isExactEcdsaSigningLaneIdentity(identity)) {
    return parseWalletSessionAuthorizationBoundary({
      observation: { kind: 'invalid', identity, reason: 'authority_mismatch' },
      nowMs: request.nowMs,
    });
  }
  const result = readExactThresholdEcdsaSessionRecord(request.ecdsaStore, identity);
  switch (result.kind) {
    case 'found':
      return parseWalletSessionAuthorizationBoundary({
        observation: {
          kind: 'found',
          identity,
          expiresAtMs: result.record.expiresAtMs,
        },
        nowMs: request.nowMs,
      });
    case 'not_found':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'missing', identity },
        nowMs: request.nowMs,
      });
    case 'duplicate_records':
      return parseWalletSessionAuthorizationBoundary({
        observation: { kind: 'invalid', identity, reason: 'malformed' },
        nowMs: request.nowMs,
      });
    default: {
      const exhaustive: never = result;
      return exhaustive;
    }
  }
}

export function readClientWalletSessionAuthorization(
  request: ReadClientWalletSessionAuthorizationRequest,
): WalletSessionAuthorizationState {
  switch (request.identity.signer.kind) {
    case 'near_ed25519_signer':
      return readEd25519ClientWalletSessionAuthorization(request);
    case 'evm_family_ecdsa_signer':
      return readEcdsaClientWalletSessionAuthorization(request);
    default: {
      const exhaustive: never = request.identity.signer;
      return exhaustive;
    }
  }
}
