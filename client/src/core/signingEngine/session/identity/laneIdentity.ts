import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import {
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SigningSessionIds,
  type SigningAuthMethod,
  type SigningCurve,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
  type ThresholdSessionId,
  type WalletSigningSessionId,
} from '../signingSession/types';

export type { SigningAuthMethod, SigningCurve };
export type EcdsaThresholdKeyId = string & { readonly __brand?: 'EcdsaThresholdKeyId' };
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
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdSessionId;
};

export type SelectedEd25519Lane = BaseSelectedLane & {
  curve: 'ed25519';
  chain: 'near';
  thresholdSessionId: ThresholdEd25519SessionId;
};

export type SelectedEcdsaLane = BaseSelectedLane & {
  curve: 'ecdsa';
  chain: 'evm' | 'tempo';
  subjectId: WalletSubjectId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
};

export type SelectedLane = SelectedEd25519Lane | SelectedEcdsaLane;

export type SelectedEd25519LaneInput = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  walletSigningSessionId: unknown;
  thresholdSessionId: unknown;
};

export type SelectedEcdsaLaneInput = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  walletSigningSessionId: unknown;
  thresholdSessionId: unknown;
  subjectId: unknown;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
};

function requireSelectedLaneString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`[SigningSession] ${field} is required`);
  return normalized;
}

export function selectedEd25519Lane(input: SelectedEd25519LaneInput): SelectedEd25519Lane {
  return {
    kind: 'selected_lane',
    accountId: input.accountId,
    authMethod: input.authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(input.walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(input.thresholdSessionId),
  };
}

export function selectedEcdsaLane(input: SelectedEcdsaLaneInput): SelectedEcdsaLane {
  return {
    kind: 'selected_lane',
    accountId: input.accountId,
    authMethod: input.authMethod,
    curve: 'ecdsa',
    chain: input.chainTarget.kind,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(input.walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
    subjectId: toWalletSubjectId(input.subjectId),
    chainTarget: input.chainTarget,
    ecdsaThresholdKeyId: requireSelectedLaneString(
      input.ecdsaThresholdKeyId,
      'ecdsaThresholdKeyId',
    ) as EcdsaThresholdKeyId,
    signingRootId: requireSelectedLaneString(input.signingRootId, 'signingRootId') as SigningRootId,
    signingRootVersion: requireSelectedLaneString(
      input.signingRootVersion,
      'signingRootVersion',
    ) as SigningRootVersion,
  };
}

export type LaneCandidateState = 'ready' | 'restorable' | 'deferred' | 'expired' | 'exhausted';

export type LaneCandidateSource =
  | 'durable_sealed_record'
  | 'runtime_session_record'
  | 'runtime_and_durable'
  | 'unknown';

export type BaseLaneCandidate = {
  kind: 'lane_candidate';
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  state: LaneCandidateState;
  remainingUses: number | null;
  expiresAtMs: number | null;
  updatedAtMs: number | null;
  source: LaneCandidateSource;
};

export type Ed25519LaneCandidate = BaseLaneCandidate & {
  curve: 'ed25519';
  chain: 'near';
};

export type EcdsaLaneCandidate = BaseLaneCandidate & {
  curve: 'ecdsa';
  chain: 'evm' | 'tempo';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
};

export type LaneCandidate = Ed25519LaneCandidate | EcdsaLaneCandidate;
