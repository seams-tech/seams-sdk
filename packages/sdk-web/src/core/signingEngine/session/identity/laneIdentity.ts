import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import {
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SigningSessionIds,
  type SigningAuthMethod,
  type SigningCurve,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
  type ThresholdSessionId,
  type SigningGrantId,
} from '../operationState/types';
import {
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type ResolvedEvmFamilyEcdsaKey,
} from './evmFamilyEcdsaIdentity';
import {
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from './signingLaneAuthBinding';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
  type ExactSigningLaneIdentity,
} from './exactSigningLaneIdentity';
import type { EcdsaThresholdKeyId } from '../keyMaterialBrands';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';

export type { SigningAuthMethod, SigningCurve };
export type { EcdsaThresholdKeyId };
export type SigningRootId = string & { readonly __brand?: 'SigningRootId' };
export type SigningRootVersion = string & { readonly __brand?: 'SigningRootVersion' };

export type ThresholdEcdsaSessionStoreSource =
  | 'login'
  | 'registration'
  | 'manual-bootstrap'
  | 'email_otp';

export const THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES = [
  'login',
  'registration',
  'manual-bootstrap',
] as const satisfies readonly ThresholdEcdsaSessionStoreSource[];

export const THRESHOLD_ECDSA_SESSION_STORE_SOURCES = [
  'email_otp',
  ...THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES,
] as const satisfies readonly ThresholdEcdsaSessionStoreSource[];

export type ThresholdEd25519SessionStoreSource =
  | 'login'
  | 'registration'
  | 'manual-connect'
  | 'bootstrap'
  | 'email_otp';

export type ThresholdEcdsaEmailOtpAuthContext = {
  policy: EmailOtpAuthPolicy;
  retention: 'session' | 'single_use';
  reason: 'login' | 'sign';
  authMethod: 'email_otp';
  authSubjectId?: string;
  consumedAtMs?: number;
};

export type BaseSelectedLane = {
  kind: 'selected_lane';
  identity: ExactSigningLaneIdentity;
  auth: SigningLaneAuthBinding;
  curve: SigningCurve;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdSessionId;
};

export type SelectedEd25519Lane = BaseSelectedLane & {
  identity: ExactEd25519SigningLaneIdentity;
  curve: 'ed25519';
  chain: 'near';
  thresholdSessionId: ThresholdEd25519SessionId;
  accountId?: never;
};

export type SelectedEcdsaLane = BaseSelectedLane & {
  identity: ExactEcdsaSigningLaneIdentity;
  curve: 'ecdsa';
  chain: 'evm' | 'tempo';
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type SelectedLane = SelectedEd25519Lane | SelectedEcdsaLane;

export type SelectedEd25519LaneInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: unknown;
  auth: SigningLaneAuthBinding;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
};

export type SelectedEcdsaLaneInput = {
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: unknown;
  walletId: WalletId;
  auth: SigningLaneAuthBinding;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
  chainTarget: ThresholdEcdsaChainTarget;
};

export function selectedEd25519Lane(input: SelectedEd25519LaneInput): SelectedEd25519Lane {
  const signerSlot = parseSignerSlot(input.signerSlot);
  if (signerSlot == null) {
    throw new Error('[SigningSession] selected Ed25519 lane requires signerSlot >= 1');
  }
  const signingGrantId = SigningSessionIds.signingGrant(input.signingGrantId);
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(input.thresholdSessionId);
  const identity = exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signerSlot,
    }),
    auth: input.auth,
    signingGrantId,
    thresholdSessionId,
  });
  return {
    kind: 'selected_lane',
    identity,
    auth: input.auth,
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId,
  };
}

export function selectedEcdsaLane(input: SelectedEcdsaLaneInput): SelectedEcdsaLane {
  if (!input.key) {
    throw new Error('[SigningSession] selected ECDSA lane requires shared key identity');
  }
  const keyHandle = toEvmFamilyEcdsaKeyHandle(input.keyHandle);
  if (String(input.key.walletId) !== String(input.walletId)) {
    throw new Error('[SigningSession] selected ECDSA lane wallet mismatch');
  }
  const signingGrantId = SigningSessionIds.signingGrant(input.signingGrantId);
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId);
  const identity = exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: input.walletId,
      chainTarget: input.chainTarget,
      keyHandle,
      key: input.key,
    }),
    auth: input.auth,
    signingGrantId,
    thresholdSessionId,
  });
  return {
    kind: 'selected_lane',
    identity,
    auth: input.auth,
    curve: 'ecdsa',
    chain: input.chainTarget.kind,
    signingGrantId,
    thresholdSessionId,
  };
}

export type LaneCandidateState = 'ready' | 'restorable' | 'deferred' | 'expired' | 'exhausted';

export type LaneCandidateSource =
  | 'durable_sealed_record'
  | 'runtime_session_record'
  | 'evm_family_shared_key'
  | 'unknown';

export type BaseLaneCandidate = {
  kind: 'lane_candidate';
  auth: SigningLaneAuthBinding;
  curve: SigningCurve;
  signingGrantId: string;
  thresholdSessionId: string;
  state: LaneCandidateState;
  remainingUses: number | null;
  expiresAtMs: number | null;
  updatedAtMs: number | null;
  source: LaneCandidateSource;
};

export type Ed25519LaneCandidate = BaseLaneCandidate & {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  accountId?: never;
  curve: 'ed25519';
  chain: 'near';
};

type BaseEcdsaLaneCandidate = BaseLaneCandidate & {
  curve: 'ecdsa';
  chain: 'evm' | 'tempo';
  walletId: WalletId;
  key: EvmFamilyEcdsaKeyIdentity;
  resolvedKey?: ResolvedEvmFamilyEcdsaKey;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EcdsaLaneCandidate =
  | (BaseEcdsaLaneCandidate & {
      source: 'evm_family_shared_key';
      sourceChainTarget: ThresholdEcdsaChainTarget;
    })
  | (BaseEcdsaLaneCandidate & {
      source: Exclude<LaneCandidateSource, 'evm_family_shared_key'>;
      sourceChainTarget?: never;
    });

export type LaneCandidate = Ed25519LaneCandidate | EcdsaLaneCandidate;

export function selectedLaneAuthMethod(lane: SelectedLane): SigningAuthMethod {
  return signingLaneAuthMethod(lane.auth);
}

export function laneCandidateAuthMethod(candidate: LaneCandidate): SigningAuthMethod {
  return signingLaneAuthMethod(candidate.auth);
}
