import { alphabetizeStringify } from '@shared/utils/digests';
import type { AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  WalletId,
} from './evmFamilyEcdsaIdentity';
import type { SelectedEcdsaLane, SelectedEd25519Lane, SelectedLane } from './laneIdentity';
import {
  SigningSessionIds,
  type SelectedEcdsaSigningSessionPlanningLane,
  type SelectedEd25519SigningSessionPlanningLane,
  type SelectedSigningSessionPlanningLane,
  type SigningAuthMethod,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
  type ThresholdSessionId,
  type SigningGrantId,
} from '../operationState/types';

export type ExactSigningLaneIdentityKey = string & {
  readonly __brand: 'ExactSigningLaneIdentityKey';
};

export type NonEmptyThresholdSessionIds = readonly [ThresholdSessionId, ...ThresholdSessionId[]];

export type ExactEd25519SigningLaneIdentity = {
  kind: 'exact_ed25519_signing_lane_identity';
  curve: 'ed25519';
  chainFamily: 'near';
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEd25519SessionId;
  walletId?: never;
  chainTarget?: never;
  key?: never;
  subjectId?: never;
};

export type ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane_identity';
  curve: 'ecdsa';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  walletId: WalletId;
  authMethod: SigningAuthMethod;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  accountId?: never;
  subjectId?: never;
};

export type ExactSigningLaneIdentity =
  | ExactEd25519SigningLaneIdentity
  | ExactEcdsaSigningLaneIdentity;

type Ed25519ExactLaneInput = SelectedEd25519Lane | SelectedEd25519SigningSessionPlanningLane;
type EcdsaExactLaneInput = SelectedEcdsaLane | SelectedEcdsaSigningSessionPlanningLane;

type CanonicalExactSigningLaneIdentity =
  | {
      kind: ExactEd25519SigningLaneIdentity['kind'];
      curve: 'ed25519';
      chainFamily: 'near';
      accountId: string;
      authMethod: SigningAuthMethod;
      signingGrantId: string;
      thresholdSessionId: string;
    }
  | {
      kind: ExactEcdsaSigningLaneIdentity['kind'];
      curve: 'ecdsa';
      chainFamily: ThresholdEcdsaChainTarget['kind'];
      walletId: string;
      authMethod: SigningAuthMethod;
      keyHandle: string;
      chainTarget: {
        key: string;
        kind: ThresholdEcdsaChainTarget['kind'];
        namespace?: 'eip155';
        chainId: number;
      };
      key: {
        walletId: string;
        rpId: string;
        keyScope: EvmFamilyEcdsaKeyIdentity['keyScope'];
        ecdsaThresholdKeyId: string;
        signingRootId: string;
        signingRootVersion: string;
        participantIds: readonly number[];
        thresholdOwnerAddress: string;
      };
      signingGrantId: string;
      thresholdSessionId: string;
    };

function canonicalChainTarget(
  target: ThresholdEcdsaChainTarget,
): Extract<CanonicalExactSigningLaneIdentity, { curve: 'ecdsa' }>['chainTarget'] {
  if (target.kind === 'evm') {
    return {
      key: thresholdEcdsaChainTargetKey(target),
      kind: 'evm',
      namespace: 'eip155',
      chainId: target.chainId,
    };
  }
  return {
    key: thresholdEcdsaChainTargetKey(target),
    kind: 'tempo',
    chainId: target.chainId,
  };
}

function canonicalKeyIdentity(
  key: EvmFamilyEcdsaKeyIdentity,
): Extract<CanonicalExactSigningLaneIdentity, { curve: 'ecdsa' }>['key'] {
  return {
    walletId: String(key.walletId),
    rpId: String(key.rpId),
    keyScope: key.keyScope,
    ecdsaThresholdKeyId: String(key.ecdsaThresholdKeyId),
    signingRootId: String(key.signingRootId),
    signingRootVersion: String(key.signingRootVersion),
    participantIds: [...key.participantIds].map((id) => Number(id)),
    thresholdOwnerAddress: String(key.thresholdOwnerAddress).toLowerCase(),
  };
}

function canonicalExactSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): CanonicalExactSigningLaneIdentity {
  if (identity.curve === 'ed25519') {
    return {
      kind: identity.kind,
      curve: 'ed25519',
      chainFamily: 'near',
      accountId: String(identity.accountId),
      authMethod: identity.authMethod,
      signingGrantId: String(identity.signingGrantId),
      thresholdSessionId: String(identity.thresholdSessionId),
    };
  }
  return {
    kind: identity.kind,
    curve: 'ecdsa',
    chainFamily: identity.chainTarget.kind,
    walletId: String(identity.walletId),
    authMethod: identity.authMethod,
    keyHandle: String(identity.keyHandle),
    chainTarget: canonicalChainTarget(identity.chainTarget),
    key: canonicalKeyIdentity(identity.key),
    signingGrantId: String(identity.signingGrantId),
    thresholdSessionId: String(identity.thresholdSessionId),
  };
}

export function exactSigningLaneIdentityKey(
  identity: ExactSigningLaneIdentity,
): ExactSigningLaneIdentityKey {
  return alphabetizeStringify(
    canonicalExactSigningLaneIdentity(identity),
  ) as ExactSigningLaneIdentityKey;
}

export function exactEd25519SigningLaneIdentity(
  lane: Ed25519ExactLaneInput,
): ExactEd25519SigningLaneIdentity {
  return {
    kind: 'exact_ed25519_signing_lane_identity',
    curve: 'ed25519',
    chainFamily: 'near',
    accountId: lane.accountId,
    authMethod: lane.authMethod,
    signingGrantId: SigningSessionIds.signingGrant(lane.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(lane.thresholdSessionId),
  };
}

export function exactEcdsaSigningLaneIdentity(
  lane: EcdsaExactLaneInput,
): ExactEcdsaSigningLaneIdentity {
  if (String(lane.key.walletId) !== String(lane.walletId)) {
    throw new Error('[SigningSession] exact ECDSA lane identity wallet mismatch');
  }
  const laneChainFamily = 'chainFamily' in lane ? lane.chainFamily : lane.chain;
  if (laneChainFamily !== lane.chainTarget.kind) {
    throw new Error('[SigningSession] exact ECDSA lane identity chain target mismatch');
  }
  return {
    kind: 'exact_ecdsa_signing_lane_identity',
    curve: 'ecdsa',
    chainFamily: lane.chainTarget.kind,
    walletId: toWalletId(lane.walletId),
    authMethod: lane.authMethod,
    chainTarget: lane.chainTarget,
    keyHandle: lane.keyHandle,
    key: lane.key,
    signingGrantId: SigningSessionIds.signingGrant(lane.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(lane.thresholdSessionId),
  };
}

export function exactSigningLaneIdentity(
  lane: SelectedLane | SelectedSigningSessionPlanningLane,
): ExactSigningLaneIdentity {
  return lane.curve === 'ecdsa'
    ? exactEcdsaSigningLaneIdentity(lane)
    : exactEd25519SigningLaneIdentity(lane);
}

export function thresholdSessionIdsFromExactSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): NonEmptyThresholdSessionIds {
  return [identity.thresholdSessionId];
}

export function exactSigningLaneIdentityMatches(
  left: ExactSigningLaneIdentity,
  right: ExactSigningLaneIdentity,
): boolean {
  return exactSigningLaneIdentityKey(left) === exactSigningLaneIdentityKey(right);
}
