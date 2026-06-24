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
import type { SigningLaneAuthBinding } from './signingLaneAuthBinding';
import type { Ed25519KeyScopeId } from '@shared/utils/registrationIntent';
import {
  SigningSessionIds,
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
  walletId: WalletId;
  nearAccountId: AccountId;
  ed25519KeyScopeId: Ed25519KeyScopeId;
  auth: SigningLaneAuthBinding;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEd25519SessionId;
  accountId?: never;
  chainTarget?: never;
  key?: never;
  subjectId?: never;
  authMethod?: never;
};

export type ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane_identity';
  curve: 'ecdsa';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  walletId: WalletId;
  auth: SigningLaneAuthBinding;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  accountId?: never;
  subjectId?: never;
  authMethod?: never;
};

export type ExactSigningLaneIdentity =
  | ExactEd25519SigningLaneIdentity
  | ExactEcdsaSigningLaneIdentity;

export type ExactEd25519SigningLaneIdentityInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  ed25519KeyScopeId: Ed25519KeyScopeId;
  auth: SigningLaneAuthBinding;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
};

export type ExactEcdsaSigningLaneIdentityInput = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  auth: SigningLaneAuthBinding;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
};

export type ExactSigningLaneIdentityInput =
  | ({ curve: 'ed25519' } & ExactEd25519SigningLaneIdentityInput)
  | ({ curve: 'ecdsa' } & ExactEcdsaSigningLaneIdentityInput);

type CanonicalExactSigningLaneIdentity =
  | {
      kind: ExactEd25519SigningLaneIdentity['kind'];
      curve: 'ed25519';
      chainFamily: 'near';
      walletId: string;
      nearAccountId: string;
      ed25519KeyScopeId: string;
      auth: CanonicalSigningLaneAuthBinding;
      signingGrantId: string;
      thresholdSessionId: string;
    }
  | {
      kind: ExactEcdsaSigningLaneIdentity['kind'];
      curve: 'ecdsa';
      chainFamily: ThresholdEcdsaChainTarget['kind'];
      walletId: string;
      auth: CanonicalSigningLaneAuthBinding;
      keyHandle: string;
      chainTarget: {
        key: string;
        kind: ThresholdEcdsaChainTarget['kind'];
        namespace?: 'eip155';
        chainId: number;
      };
      key: {
        walletId: string;
        walletKeyId: string;
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

type CanonicalSigningLaneAuthBinding =
  | {
      kind: 'passkey';
      rpId: string;
      credentialIdB64u: string;
    }
  | {
      kind: 'email_otp';
      providerSubjectId: string;
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
    walletKeyId: String(key.walletKeyId),
    keyScope: key.keyScope,
    ecdsaThresholdKeyId: String(key.ecdsaThresholdKeyId),
    signingRootId: String(key.signingRootId),
    signingRootVersion: String(key.signingRootVersion),
    participantIds: [...key.participantIds].map((id) => Number(id)),
    thresholdOwnerAddress: String(key.thresholdOwnerAddress).toLowerCase(),
  };
}

function canonicalAuthBinding(auth: SigningLaneAuthBinding): CanonicalSigningLaneAuthBinding {
  switch (auth.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: String(auth.rpId),
        credentialIdB64u: String(auth.credentialIdB64u),
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: String(auth.providerSubjectId),
      };
  }
  auth satisfies never;
  throw new Error('[SigningSession] unsupported signing lane auth binding');
}

function canonicalExactSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): CanonicalExactSigningLaneIdentity {
  if (identity.curve === 'ed25519') {
    return {
      kind: identity.kind,
      curve: 'ed25519',
      chainFamily: 'near',
      walletId: String(identity.walletId),
      nearAccountId: String(identity.nearAccountId),
      ed25519KeyScopeId: String(identity.ed25519KeyScopeId),
      auth: canonicalAuthBinding(identity.auth),
      signingGrantId: String(identity.signingGrantId),
      thresholdSessionId: String(identity.thresholdSessionId),
    };
  }
  return {
    kind: identity.kind,
    curve: 'ecdsa',
    chainFamily: identity.chainTarget.kind,
    walletId: String(identity.walletId),
    auth: canonicalAuthBinding(identity.auth),
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
  lane: ExactEd25519SigningLaneIdentityInput,
): ExactEd25519SigningLaneIdentity {
  return {
    kind: 'exact_ed25519_signing_lane_identity',
    curve: 'ed25519',
    chainFamily: 'near',
    walletId: toWalletId(lane.walletId),
    nearAccountId: lane.nearAccountId,
    ed25519KeyScopeId: lane.ed25519KeyScopeId,
    auth: lane.auth,
    signingGrantId: SigningSessionIds.signingGrant(lane.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(lane.thresholdSessionId),
  };
}

export function exactEcdsaSigningLaneIdentity(
  lane: ExactEcdsaSigningLaneIdentityInput,
): ExactEcdsaSigningLaneIdentity {
  if (String(lane.key.walletId) !== String(lane.walletId)) {
    throw new Error('[SigningSession] exact ECDSA lane identity wallet mismatch');
  }
  return {
    kind: 'exact_ecdsa_signing_lane_identity',
    curve: 'ecdsa',
    chainFamily: lane.chainTarget.kind,
    walletId: toWalletId(lane.walletId),
    auth: lane.auth,
    chainTarget: lane.chainTarget,
    keyHandle: lane.keyHandle,
    key: lane.key,
    signingGrantId: SigningSessionIds.signingGrant(lane.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(lane.thresholdSessionId),
  };
}

export function exactSigningLaneIdentity(
  lane: ExactSigningLaneIdentityInput,
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
