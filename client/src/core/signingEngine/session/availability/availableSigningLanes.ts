import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import {
  decodeJwtPayloadRecord,
  THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND,
} from '@shared/utils/sessionTokens';
import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';
import { normalizeSealedRecoveryRecord } from '../sealedRecovery/recoveryRecord';
import type {
  EmailOtpEcdsaSealedRecoveryRecord,
  PasskeyEcdsaSealedRecoveryRecord,
  SealedRecoveryRecord,
} from '../sealedRecovery/recoveryRecord';
import type {
  EcdsaLaneCandidate,
  Ed25519LaneCandidate,
  LaneCandidateSource,
  LaneCandidateState,
} from '../identity/laneIdentity';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaLaneKey,
  toWalletSubjectId,
  type ThresholdEcdsaSessionRecordKey,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type AvailableSigningLaneState =
  | 'ready'
  | 'restorable'
  | 'deferred'
  | 'expired'
  | 'exhausted'
  | 'missing';

export type AvailableSigningLanePolicyHint = {
  remainingUses?: number;
  expiresAtMs?: number;
};

export type MissingAvailableEcdsaSigningLane = {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: 'missing';
};

export type ConcreteAvailableEcdsaSigningLane = {
  subjectId: WalletSubjectId;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  state: AvailableSigningLaneState;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
  source?: 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable';
};

export type AvailableEcdsaSigningLane =
  | MissingAvailableEcdsaSigningLane
  | ConcreteAvailableEcdsaSigningLane;

export type AvailableEd25519SigningLane = {
  authMethod?: 'email_otp' | 'passkey';
  curve: 'ed25519';
  chain: 'near';
  state: AvailableSigningLaneState;
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
  source?: 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable';
};

export type AvailableSigningLanesRuntimeClaim = {
  state: 'warm' | 'missing' | 'expired' | 'exhausted' | 'unavailable';
  sessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  code?: string;
};

export type AvailableSigningLanesRuntimeEcdsaRecord = {
  subjectId: WalletSubjectId;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
};

export type AvailableSigningLanesRuntimeEd25519Record = {
  authMethod: 'email_otp' | 'passkey';
  curve: 'ed25519';
  chain: 'near';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
};

export type AvailableSigningLanes = {
  walletId: AccountId;
  generation: number;
  ecdsa: {
    targets: ThresholdEcdsaChainTarget[];
    lanesByTarget: Record<string, AvailableEcdsaSigningLane>;
    candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
  };
  lanes: {
    ed25519: {
      near: AvailableEd25519SigningLane;
    };
  };
  candidates: {
    ed25519: {
      near: AvailableEd25519SigningLane[];
    };
  };
};

export type ConcreteAvailableSigningLane =
  | ConcreteAvailableEcdsaSigningLane
  | (AvailableEd25519SigningLane & {
      authMethod: 'email_otp' | 'passkey';
      thresholdSessionId: string;
      walletSigningSessionId: string;
    });

export type ReadAvailableSigningLanesInput = {
  walletId: AccountId | string;
  subjectId: WalletSubjectId;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  authMethod?: 'email_otp' | 'passkey';
  nowMs?: number;
};

export type ReadAvailableSigningLanesForSigningInput =
  | {
      walletId: AccountId | string;
      subjectId: WalletSubjectId;
      curve: 'ed25519';
      authMethod?: 'email_otp' | 'passkey';
    }
  | {
      walletId: AccountId | string;
      subjectId: WalletSubjectId;
      curve: 'ecdsa';
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
      authMethod?: 'email_otp' | 'passkey';
    };

export type ReadAvailableSigningLanesPorts = {
  listSealedRecordsForWallet: (args: {
    walletId: string;
    filter:
      | {
          authMethod?: 'email_otp' | 'passkey';
          curve: 'ed25519';
        }
      | {
          authMethod?: 'email_otp' | 'passkey';
          curve: 'ecdsa';
          chainTarget: ThresholdEcdsaChainTarget;
        };
  }) => Promise<SigningSessionSealedStoreRecord[]>;
  listRuntimeEcdsaLanesForSubject?: (args: {
    subjectId: WalletSubjectId;
  }) => Promise<AvailableSigningLanesRuntimeEcdsaRecord[]>;
  listRuntimeEd25519RecordsForAccount?: (args: {
    accountId: string;
  }) => Promise<AvailableSigningLanesRuntimeEd25519Record[]>;
  readRuntimeClaimsForSessions?: (
    sessionIds: string[],
  ) => Promise<Map<string, AvailableSigningLanesRuntimeClaim | null>>;
};

export function isConcreteAvailableSigningLane(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): lane is ConcreteAvailableSigningLane {
  if (!('authMethod' in lane)) return false;
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
  if (lane.thresholdSessionId !== thresholdSessionId) return false;
  if (lane.walletSigningSessionId !== walletSigningSessionId) return false;
  const baseConcrete =
    (lane.authMethod === 'email_otp' || lane.authMethod === 'passkey') &&
    Boolean(thresholdSessionId) &&
    Boolean(walletSigningSessionId);
  if (!baseConcrete) return false;
  if (lane.curve !== 'ecdsa') return true;
  return Boolean(
    String(lane.subjectId || '').trim() &&
    String(lane.ecdsaThresholdKeyId || '').trim() &&
    String(lane.signingRootId || '').trim() &&
    String(lane.signingRootVersion || '').trim(),
  );
}

function laneCandidateStateFromAvailableLaneState(
  state: AvailableSigningLaneState,
): LaneCandidateState | null {
  return state === 'missing' ? null : state;
}

function laneCandidateSourceFromAvailableLaneSource(
  source: ConcreteAvailableSigningLane['source'],
): LaneCandidateSource {
  return source || 'unknown';
}

function nullablePositiveInteger(value: unknown): number | null {
  const normalized = Math.floor(Number(value));
  return Number.isFinite(normalized) && normalized > 0 ? normalized : null;
}

function nullableNonNegativeInteger(value: unknown): number | null {
  const normalized = Math.max(0, Math.floor(Number(value)));
  return Number.isFinite(normalized) ? normalized : null;
}

export function ed25519LaneCandidateFromAvailableLane(args: {
  walletId: AccountId | string;
  lane: AvailableEd25519SigningLane;
}): Ed25519LaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ed25519') {
    return null;
  }
  const state = laneCandidateStateFromAvailableLaneState(args.lane.state);
  if (!state) return null;
  return {
    kind: 'lane_candidate',
    accountId: toAccountId(args.walletId),
    authMethod: args.lane.authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: args.lane.walletSigningSessionId,
    thresholdSessionId: args.lane.thresholdSessionId,
    state,
    remainingUses: nullableNonNegativeInteger(args.lane.remainingUses),
    expiresAtMs: nullablePositiveInteger(args.lane.expiresAtMs),
    updatedAtMs: nullablePositiveInteger(args.lane.updatedAtMs),
    source: laneCandidateSourceFromAvailableLaneSource(args.lane.source),
  };
}

export function ecdsaLaneCandidateFromAvailableLane(args: {
  walletId: AccountId | string;
  lane: AvailableEcdsaSigningLane;
}): EcdsaLaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ecdsa') {
    return null;
  }
  const state = laneCandidateStateFromAvailableLaneState(args.lane.state);
  if (!state) return null;
  return {
    kind: 'lane_candidate',
    walletId: toAccountId(args.walletId),
    authMethod: args.lane.authMethod,
    curve: 'ecdsa',
    chain: args.lane.chainTarget.kind,
    subjectId: args.lane.subjectId,
    chainTarget: args.lane.chainTarget,
    ecdsaThresholdKeyId: args.lane.ecdsaThresholdKeyId,
    signingRootId: args.lane.signingRootId,
    signingRootVersion: args.lane.signingRootVersion,
    walletSigningSessionId: args.lane.walletSigningSessionId,
    thresholdSessionId: args.lane.thresholdSessionId,
    state,
    remainingUses: nullableNonNegativeInteger(args.lane.remainingUses),
    expiresAtMs: nullablePositiveInteger(args.lane.expiresAtMs),
    updatedAtMs: nullablePositiveInteger(args.lane.updatedAtMs),
    source: laneCandidateSourceFromAvailableLaneSource(args.lane.source),
  };
}

type EcdsaAvailableLaneIdentityInput = Pick<
  ConcreteAvailableEcdsaSigningLane,
  | 'authMethod'
  | 'curve'
  | 'chainTarget'
  | 'subjectId'
  | 'ecdsaThresholdKeyId'
  | 'signingRootId'
  | 'signingRootVersion'
  | 'walletSigningSessionId'
  | 'thresholdSessionId'
>;

type Ed25519AvailableLaneIdentityInput = Pick<
  AvailableEd25519SigningLane,
  'authMethod' | 'curve' | 'chain' | 'walletSigningSessionId' | 'thresholdSessionId'
>;

export function ecdsaAvailableLaneIdentityKey(
  lane: EcdsaAvailableLaneIdentityInput | MissingAvailableEcdsaSigningLane | null | undefined,
): string | null {
  if (!lane || lane.curve !== 'ecdsa') return null;
  if (!('authMethod' in lane)) return null;
  if (!lane.chainTarget) return null;
  const authMethod =
    lane.authMethod === 'email_otp' || lane.authMethod === 'passkey' ? lane.authMethod : '';
  const subjectId = String(lane.subjectId || '').trim();
  const ecdsaThresholdKeyId = String(lane.ecdsaThresholdKeyId || '').trim();
  const signingRootId = String(lane.signingRootId || '').trim();
  const signingRootVersion = String(lane.signingRootVersion || '').trim();
  const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (
    !authMethod ||
    !subjectId ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !walletSigningSessionId ||
    !thresholdSessionId
  ) {
    return null;
  }
  const identity: ThresholdEcdsaSessionRecordKey = {
    subjectId: toWalletSubjectId(subjectId),
    authMethod,
    curve: 'ecdsa',
    chainTarget: lane.chainTarget,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    walletSigningSessionId,
    thresholdSessionId,
  };
  return thresholdEcdsaLaneKey(identity);
}

export function ed25519AvailableLaneIdentityKey(
  lane: Ed25519AvailableLaneIdentityInput | null | undefined,
): string | null {
  if (!lane || lane.curve !== 'ed25519' || lane.chain !== 'near') return null;
  const authMethod =
    lane.authMethod === 'email_otp' || lane.authMethod === 'passkey' ? lane.authMethod : '';
  const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (!authMethod || !walletSigningSessionId || !thresholdSessionId) return null;
  return [authMethod, 'ed25519', 'near', walletSigningSessionId, thresholdSessionId].join(':');
}

function emptyEcdsaLane(args: {
  chainTarget: ThresholdEcdsaChainTarget;
}): MissingAvailableEcdsaSigningLane {
  return {
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    state: 'missing',
  };
}

export function ecdsaAvailableLaneForTarget(
  availableLanes: AvailableSigningLanes,
  chainTarget: ThresholdEcdsaChainTarget,
): AvailableEcdsaSigningLane {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return availableLanes.ecdsa.lanesByTarget[targetKey] || emptyEcdsaLane({ chainTarget });
}

export function ecdsaAvailableLaneTargets(
  availableLanes: AvailableSigningLanes,
): ThresholdEcdsaChainTarget[] {
  return availableLanes.ecdsa.targets;
}

export function ecdsaAvailableLaneCandidatesForTarget(
  availableLanes: AvailableSigningLanes,
  chainTarget: ThresholdEcdsaChainTarget,
): AvailableEcdsaSigningLane[] {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return availableLanes.ecdsa.candidatesByTarget[targetKey] || [];
}

function emptyEd25519Lane(): AvailableEd25519SigningLane {
  return {
    curve: 'ed25519',
    chain: 'near',
    state: 'missing',
  };
}

function durablePolicyHint(
  record: SigningSessionSealedStoreRecord,
): AvailableSigningLanePolicyHint | undefined {
  const remainingUses = Math.floor(Number(record.remainingUses));
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  const hint: AvailableSigningLanePolicyHint = {};
  if (Number.isFinite(remainingUses) && remainingUses >= 0) {
    hint.remainingUses = remainingUses;
  }
  if (Number.isFinite(expiresAtMs) && expiresAtMs > 0) {
    hint.expiresAtMs = expiresAtMs;
  }
  return Object.keys(hint).length ? hint : undefined;
}

function ecdsaRecoveryRecordForDurableLane(
  record: SealedRecoveryRecord,
): EmailOtpEcdsaSealedRecoveryRecord | PasskeyEcdsaSealedRecoveryRecord | undefined {
  if (record.curve === 'ecdsa') return record;
  if (record.authMethod === 'email_otp') return record.companionEcdsaRecovery;
  return undefined;
}

function durableEcdsaJwtMatchesRecord(args: {
  record: SigningSessionSealedStoreRecord;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  subjectId: string;
  ecdsaThresholdKeyId: string;
}): boolean {
  const jwt = String(args.record.ecdsaRestore?.thresholdSessionAuthToken || '').trim();
  if (!jwt) return true;
  const payload = decodeJwtPayloadRecord(jwt);
  if (!payload || payload.kind !== THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND) return false;
  let jwtChainTarget: ThresholdEcdsaChainTarget;
  try {
    jwtChainTarget = thresholdEcdsaChainTargetFromRequest(
      payload.chainTarget &&
        typeof payload.chainTarget === 'object' &&
        !Array.isArray(payload.chainTarget)
        ? (payload.chainTarget as Record<string, unknown>)
        : {},
    );
  } catch {
    return false;
  }
  return (
    String(payload.subjectId || '').trim() === args.subjectId &&
    String(payload.ecdsaThresholdKeyId || '').trim() === args.ecdsaThresholdKeyId &&
    thresholdEcdsaChainTargetKey(jwtChainTarget) ===
      thresholdEcdsaChainTargetKey(args.chainTarget) &&
    String(payload.sessionId || '').trim() === args.thresholdSessionId &&
    String(payload.walletSigningSessionId || '').trim() === args.record.walletSigningSessionId
  );
}

function recordToEcdsaLane(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  record: SigningSessionSealedStoreRecord;
}): AvailableEcdsaSigningLane | null {
  const normalized = normalizeSealedRecoveryRecord(args.record);
  if (normalized.kind !== 'accepted') return null;
  const recoveryRecord = ecdsaRecoveryRecordForDurableLane(normalized.record);
  if (!recoveryRecord) return null;
  if (recoveryRecord.authMethod !== args.record.authMethod) return null;
  if (
    thresholdEcdsaChainTargetKey(recoveryRecord.chainTarget) !==
    thresholdEcdsaChainTargetKey(args.chainTarget)
  ) {
    return null;
  }

  const thresholdSessionId = recoveryRecord.thresholdSessionId;
  const policyHint = durablePolicyHint(args.record);
  const subjectId = String(recoveryRecord.subjectId || '').trim();
  if (
    !thresholdSessionId ||
    !subjectId ||
    !recoveryRecord.ecdsaThresholdKeyId ||
    !recoveryRecord.signingRootId ||
    !recoveryRecord.signingRootVersion
  ) {
    return null;
  }
  if (
    !durableEcdsaJwtMatchesRecord({
      record: args.record,
      chainTarget: args.chainTarget,
      thresholdSessionId,
      subjectId,
      ecdsaThresholdKeyId: String(recoveryRecord.ecdsaThresholdKeyId || '').trim(),
    })
  ) {
    return null;
  }

  return {
    subjectId: toWalletSubjectId(subjectId),
    authMethod: args.record.authMethod,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    ecdsaThresholdKeyId: recoveryRecord.ecdsaThresholdKeyId,
    signingRootId: recoveryRecord.signingRootId,
    signingRootVersion: recoveryRecord.signingRootVersion,
    // IndexedDB policy fields are lookup hints until authenticated sealed
    // payload metadata or trusted runtime/server status confirms them.
    state: 'restorable',
    source: 'durable_sealed_record',
    walletSigningSessionId: args.record.walletSigningSessionId,
    thresholdSessionId,
    updatedAtMs: Math.floor(Number(args.record.updatedAtMs) || 0),
    ...(policyHint ? { policyHint } : {}),
  };
}

function recordToEd25519Lane(args: {
  record: SigningSessionSealedStoreRecord;
}): AvailableEd25519SigningLane {
  const thresholdSessionId = String(args.record.thresholdSessionIds.ed25519 || '').trim();
  const policyHint = durablePolicyHint(args.record);

  return {
    authMethod: args.record.authMethod,
    curve: 'ed25519',
    chain: 'near',
    // IndexedDB policy fields are lookup hints until authenticated sealed
    // payload metadata or trusted runtime/server status confirms them.
    state: thresholdSessionId ? 'restorable' : 'deferred',
    source: 'durable_sealed_record',
    walletSigningSessionId: args.record.walletSigningSessionId,
    updatedAtMs: Math.floor(Number(args.record.updatedAtMs) || 0),
    ...(thresholdSessionId ? { thresholdSessionId } : {}),
    ...(policyHint ? { policyHint } : {}),
  };
}

export function warmStatusToAvailableSigningLanesRuntimeClaim(args: {
  sessionId: string;
  status: { ok: true; remainingUses: number; expiresAtMs: number } | { ok: false; code: string };
}): AvailableSigningLanesRuntimeClaim {
  if (args.status.ok) {
    return {
      state: 'warm',
      sessionId: args.sessionId,
      remainingUses: args.status.remainingUses,
      expiresAtMs: args.status.expiresAtMs,
    };
  }
  if (args.status.code === 'expired') return { state: 'expired', sessionId: args.sessionId };
  if (args.status.code === 'exhausted') {
    return { state: 'exhausted', sessionId: args.sessionId, remainingUses: 0 };
  }
  if (args.status.code === 'not_found') return { state: 'missing', sessionId: args.sessionId };
  return {
    state: 'unavailable',
    sessionId: args.sessionId,
    code: args.status.code,
  };
}

function runtimeClaimToLaneState(
  claim: AvailableSigningLanesRuntimeClaim | null,
  durableLane?: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): AvailableSigningLaneState {
  if (!claim) return durableLane?.state || 'deferred';
  if (claim.state === 'warm') return 'ready';
  if (claim.state === 'expired') return 'expired';
  if (claim.state === 'exhausted') return 'exhausted';
  if (claim.state === 'missing') return durableLane?.state || 'missing';
  return durableLane?.state || 'deferred';
}

function runtimeRecordToEcdsaLane(args: {
  record: AvailableSigningLanesRuntimeEcdsaRecord;
  claim: AvailableSigningLanesRuntimeClaim | null;
  durableLane: AvailableEcdsaSigningLane;
}): ConcreteAvailableEcdsaSigningLane {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const claim = args.claim;
  const runtimeLaneKey = ecdsaAvailableLaneIdentityKey(args.record);
  const durableLaneKey = ecdsaAvailableLaneIdentityKey(args.durableLane);
  const hasMatchingDurableLane =
    isConcreteAvailableSigningLane(args.durableLane) &&
    args.durableLane.source === 'durable_sealed_record' &&
    Boolean(runtimeLaneKey) &&
    durableLaneKey === runtimeLaneKey;
  const remainingUses = nullableNonNegativeInteger(
    claim?.remainingUses ?? args.record.remainingUses,
  );
  const expiresAtMs = nullablePositiveInteger(claim?.expiresAtMs ?? args.record.expiresAtMs);
  const runtimeUpdatedAtMs = nullablePositiveInteger(args.record.updatedAtMs) || 0;
  const durableUpdatedAtMs =
    hasMatchingDurableLane && isConcreteAvailableSigningLane(args.durableLane)
      ? nullablePositiveInteger(args.durableLane.updatedAtMs) || 0
      : 0;
  const updatedAtMs = Math.max(runtimeUpdatedAtMs, durableUpdatedAtMs);

  return {
    subjectId: args.record.subjectId,
    authMethod: args.record.authMethod,
    curve: 'ecdsa',
    chainTarget: args.record.chainTarget,
    ecdsaThresholdKeyId: args.record.ecdsaThresholdKeyId,
    signingRootId: args.record.signingRootId,
    signingRootVersion: args.record.signingRootVersion,
    state: runtimeClaimToLaneState(claim, hasMatchingDurableLane ? args.durableLane : undefined),
    source: hasMatchingDurableLane ? 'runtime_and_durable' : 'runtime_session_record',
    walletSigningSessionId: args.record.walletSigningSessionId,
    thresholdSessionId,
    ...(remainingUses == null ? {} : { remainingUses }),
    ...(expiresAtMs == null ? {} : { expiresAtMs }),
    ...(updatedAtMs > 0 ? { updatedAtMs } : {}),
  };
}

function runtimeRecordToEd25519Lane(args: {
  record: AvailableSigningLanesRuntimeEd25519Record;
  claim: AvailableSigningLanesRuntimeClaim | null;
  durableLane: AvailableEd25519SigningLane;
}): AvailableEd25519SigningLane {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(args.record.walletSigningSessionId || '').trim();
  const durableWalletSigningSessionId = String(
    args.durableLane.walletSigningSessionId || '',
  ).trim();
  const claim = args.claim;
  const hasMatchingDurableLane =
    args.durableLane.source === 'durable_sealed_record' &&
    args.durableLane.authMethod === args.record.authMethod &&
    durableWalletSigningSessionId === walletSigningSessionId &&
    String(args.durableLane.thresholdSessionId || '').trim() === thresholdSessionId;
  const remainingUses = nullableNonNegativeInteger(
    claim?.remainingUses ?? args.record.remainingUses,
  );
  const expiresAtMs = nullablePositiveInteger(claim?.expiresAtMs ?? args.record.expiresAtMs);
  const runtimeUpdatedAtMs = nullablePositiveInteger(args.record.updatedAtMs) || 0;
  const durableUpdatedAtMs = hasMatchingDurableLane
    ? nullablePositiveInteger(args.durableLane.updatedAtMs) || 0
    : 0;
  const updatedAtMs = Math.max(runtimeUpdatedAtMs, durableUpdatedAtMs);

  return {
    authMethod: args.record.authMethod,
    curve: 'ed25519',
    chain: 'near',
    state: runtimeClaimToLaneState(claim, hasMatchingDurableLane ? args.durableLane : undefined),
    source: hasMatchingDurableLane ? 'runtime_and_durable' : 'runtime_session_record',
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    ...(thresholdSessionId ? { thresholdSessionId } : {}),
    ...(remainingUses == null ? {} : { remainingUses }),
    ...(expiresAtMs == null ? {} : { expiresAtMs }),
    ...(updatedAtMs > 0 ? { updatedAtMs } : {}),
  };
}

function isRuntimeOwnedAvailableLane(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): boolean {
  const source = 'source' in lane ? lane.source : undefined;
  return (
    lane.state === 'ready' ||
    source === 'runtime_and_durable' ||
    source === 'runtime_session_record'
  );
}

function availableLaneUpdatedAtMs(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  return Math.floor(Number('updatedAtMs' in lane ? lane.updatedAtMs : 0) || 0);
}

function isAvailableSigningLaneDiagnosticsEnabled(): boolean {
  try {
    const storage = (globalThis as { localStorage?: Storage }).localStorage;
    return storage?.getItem('seams:debug:signing-session') === '1';
  } catch {
    return false;
  }
}

function summarizeEcdsaLaneForDiagnostics(
  lane: AvailableEcdsaSigningLane | null | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  if (!isConcreteAvailableSigningLane(lane)) {
    return {
      present: true,
      curve: lane.curve,
      chainTarget: lane.chainTarget,
      state: lane.state,
    };
  }
  return {
    present: true,
    authMethod: lane.authMethod,
    curve: lane.curve,
    subjectId: lane.subjectId,
    chainTarget: lane.chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(lane.chainTarget),
    state: lane.state,
    source: lane.source,
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
    ecdsaThresholdKeyId: lane.ecdsaThresholdKeyId,
    signingRootId: lane.signingRootId,
    signingRootVersion: lane.signingRootVersion,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
  };
}

function summarizeSealedEcdsaRecordForDiagnostics(
  record: SigningSessionSealedStoreRecord,
): Record<string, unknown> {
  const restore = record.ecdsaRestore;
  const normalized = normalizeSealedRecoveryRecord(record);
  const recoveryRecord =
    normalized.kind === 'accepted' ? ecdsaRecoveryRecordForDurableLane(normalized.record) : null;
  return {
    storeKey: record.storeKey,
    authMethod: record.authMethod,
    curve: record.curve,
    subjectId: String(record.subjectId || '').trim() || null,
    walletSigningSessionId: String(record.walletSigningSessionId || '').trim() || null,
    thresholdSessionId: String(record.thresholdSessionIds?.ecdsa || '').trim() || null,
    restoreSubjectId: String(recoveryRecord?.subjectId || '').trim() || null,
    restoreThresholdSessionId: String(recoveryRecord?.thresholdSessionId || '').trim() || null,
    restoreChainTarget: restore?.chainTarget || null,
    restoreTargetKey: restore?.chainTarget
      ? thresholdEcdsaChainTargetKey(restore.chainTarget)
      : null,
    ecdsaThresholdKeyId: String(restore?.ecdsaThresholdKeyId || '').trim() || null,
    signingRootId: String(recoveryRecord?.signingRootId || '').trim() || null,
    signingRootVersion: String(recoveryRecord?.signingRootVersion || '').trim() || null,
    normalizedRecoveryKind: normalized.kind,
    updatedAtMs: Math.floor(Number(record.updatedAtMs) || 0),
  };
}

function collapseExactDuplicateAvailableLanes<
  TLane extends AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
>(lanes: TLane[], laneIdentityKey: (lane: TLane) => string | null): TLane[] {
  const keyedGroups = new Map<string, TLane[]>();
  const unkeyed: TLane[] = [];
  for (const lane of lanes) {
    const key = laneIdentityKey(lane);
    if (!key) {
      unkeyed.push(lane);
      continue;
    }
    keyedGroups.set(key, [...(keyedGroups.get(key) || []), lane]);
  }
  const normalized = [...keyedGroups.values()].map(
    (group) =>
      [...group].sort((left, right) => {
        const runtimeDelta =
          Number(isRuntimeOwnedAvailableLane(right)) - Number(isRuntimeOwnedAvailableLane(left));
        if (runtimeDelta) return runtimeDelta;
        return availableLaneUpdatedAtMs(right) - availableLaneUpdatedAtMs(left);
      })[0]!,
  );
  return [...normalized, ...unkeyed];
}

export async function readAvailableSigningLanes(
  input: ReadAvailableSigningLanesInput,
  ports: ReadAvailableSigningLanesPorts,
): Promise<AvailableSigningLanes> {
  const walletId = toAccountId(input.walletId);
  const subjectId = String(input.subjectId || '').trim();
  const ecdsaTargetsByKey = new Map<string, ThresholdEcdsaChainTarget>();
  for (const chainTarget of input.ecdsaChainTargets) {
    ecdsaTargetsByKey.set(thresholdEcdsaChainTargetKey(chainTarget), chainTarget);
  }
  const ecdsaChainTargets = [...ecdsaTargetsByKey.values()];
  const ecdsaRecordsByTarget = await Promise.all(
    ecdsaChainTargets.map((chainTarget) =>
      ports.listSealedRecordsForWallet({
        walletId,
        filter: {
          ...(input.authMethod ? { authMethod: input.authMethod } : {}),
          curve: 'ecdsa',
          chainTarget,
        },
      }),
    ),
  );
  const ecdsaRecords = ecdsaRecordsByTarget.flat();
  const ed25519Records = await ports.listSealedRecordsForWallet({
    walletId,
    filter: {
      ...(input.authMethod ? { authMethod: input.authMethod } : {}),
      curve: 'ed25519',
    },
  });

  const ecdsaTargets = [...ecdsaChainTargets];
  const ecdsaLanesByTarget: Record<string, AvailableEcdsaSigningLane> = {};
  const ecdsaCandidatesByTarget: Record<string, AvailableEcdsaSigningLane[]> = {};
  const ecdsaLaneUpdatedAtMsByTarget: Record<string, number> = {};
  for (const chainTarget of ecdsaTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    ecdsaLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
    ecdsaCandidatesByTarget[targetKey] = [];
    ecdsaLaneUpdatedAtMsByTarget[targetKey] = 0;
  }
  const ed25519Candidates: AvailableEd25519SigningLane[] = [];
  let ed25519Lane = emptyEd25519Lane();
  let ed25519LaneUpdatedAtMs = 0;
  let generation = 0;
  const collectDiagnostics = isAvailableSigningLaneDiagnosticsEnabled();
  const durableEcdsaDiscovery: Record<string, unknown>[] = [];
  const runtimeEcdsaDiscovery: Record<string, unknown>[] = [];
  const recordDurableEcdsaDiscovery = (
    record: SigningSessionSealedStoreRecord,
    result: Record<string, unknown>,
  ): void => {
    durableEcdsaDiscovery.push({
      ...summarizeSealedEcdsaRecordForDiagnostics(record),
      ...result,
    });
  };

  for (const record of ecdsaRecords) {
    if (!record.thresholdSessionIds.ecdsa) {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'missing_ecdsa_threshold_session_id',
      });
      continue;
    }
    if (String(record.subjectId || '').trim() !== subjectId) {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'subject_mismatch',
        requestedSubjectId: subjectId,
      });
      continue;
    }
    const chainTarget = record.ecdsaRestore?.chainTarget;
    if (!chainTarget) {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'missing_ecdsa_restore_chain_target',
      });
      continue;
    }
    const chain = chainTarget.kind;
    if (chain !== 'tempo' && chain !== 'evm') {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'unsupported_ecdsa_chain_target',
        chainTarget,
      });
      continue;
    }
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const updatedAtMs = Math.floor(Number(record.updatedAtMs) || 0);
    generation = Math.max(generation, updatedAtMs);
    const lane = recordToEcdsaLane({
      chainTarget,
      record,
    });
    if (!lane) {
      recordDurableEcdsaDiscovery(record, {
        result: 'rejected',
        reason: 'record_to_ecdsa_lane_rejected',
        requestedTargetKeys: [...ecdsaTargetsByKey.keys()],
        recordTargetKey: targetKey,
      });
      continue;
    }
    recordDurableEcdsaDiscovery(record, {
      result: 'accepted',
      targetKey,
      lane: summarizeEcdsaLaneForDiagnostics(lane),
    });
    ecdsaCandidatesByTarget[targetKey] ||= [];
    ecdsaCandidatesByTarget[targetKey].push(lane);
    if (updatedAtMs < (ecdsaLaneUpdatedAtMsByTarget[targetKey] || 0)) continue;
    ecdsaLaneUpdatedAtMsByTarget[targetKey] = updatedAtMs;
    ecdsaLanesByTarget[targetKey] = lane;
  }

  for (const record of ed25519Records) {
    if (!record.thresholdSessionIds.ed25519) continue;
    const updatedAtMs = Math.floor(Number(record.updatedAtMs) || 0);
    generation = Math.max(generation, updatedAtMs);
    const lane = recordToEd25519Lane({ record });
    ed25519Candidates.push(lane);
    if (updatedAtMs < ed25519LaneUpdatedAtMs) continue;
    ed25519Lane = lane;
    ed25519LaneUpdatedAtMs = updatedAtMs;
  }

  const runtimeEcdsaRecords = ports.listRuntimeEcdsaLanesForSubject
    ? (await ports.listRuntimeEcdsaLanesForSubject({ subjectId: input.subjectId })).filter(
        (record) => !input.authMethod || record.authMethod === input.authMethod,
      )
    : [];
  const runtimeEd25519Records = ports.listRuntimeEd25519RecordsForAccount
    ? (await ports.listRuntimeEd25519RecordsForAccount({ accountId: walletId })).filter(
        (record) => !input.authMethod || record.authMethod === input.authMethod,
      )
    : [];
  const runtimeSessionIds = [...runtimeEcdsaRecords, ...runtimeEd25519Records]
    .map((record) => String(record.thresholdSessionId || '').trim())
    .filter(Boolean);
  const claimsBySessionId =
    runtimeSessionIds.length && ports.readRuntimeClaimsForSessions
      ? await ports.readRuntimeClaimsForSessions(runtimeSessionIds)
      : new Map<string, AvailableSigningLanesRuntimeClaim | null>();

  for (const runtimeRecord of runtimeEcdsaRecords) {
    const chain = runtimeRecord.chainTarget.kind;
    if (chain !== 'tempo' && chain !== 'evm') {
      runtimeEcdsaDiscovery.push({
        result: 'rejected',
        reason: 'unsupported_ecdsa_chain_target',
        record: runtimeRecord,
      });
      continue;
    }
    const thresholdSessionId = String(runtimeRecord.thresholdSessionId || '').trim();
    if (!thresholdSessionId) {
      runtimeEcdsaDiscovery.push({
        result: 'rejected',
        reason: 'missing_runtime_threshold_session_id',
        record: runtimeRecord,
      });
      continue;
    }
    const runtimeLaneKey = ecdsaAvailableLaneIdentityKey(runtimeRecord);
    const targetKey = thresholdEcdsaChainTargetKey(runtimeRecord.chainTarget);
    const targetCandidates = ecdsaCandidatesByTarget[targetKey] || [];
    const targetLane =
      ecdsaLanesByTarget[targetKey] || emptyEcdsaLane({ chainTarget: runtimeRecord.chainTarget });
    const durableLane =
      (runtimeLaneKey
        ? targetCandidates.find((lane) => ecdsaAvailableLaneIdentityKey(lane) === runtimeLaneKey)
        : undefined) || targetLane;
    const runtimeLane = runtimeRecordToEcdsaLane({
      record: runtimeRecord,
      claim: claimsBySessionId.get(thresholdSessionId) || null,
      durableLane,
    });
    runtimeEcdsaDiscovery.push({
      result: 'accepted',
      targetKey,
      runtimeLaneKey,
      claim: claimsBySessionId.get(thresholdSessionId) || null,
      lane: summarizeEcdsaLaneForDiagnostics(runtimeLane),
    });
    const candidateIndex = runtimeLaneKey
      ? targetCandidates.findIndex((lane) => ecdsaAvailableLaneIdentityKey(lane) === runtimeLaneKey)
      : -1;
    if (candidateIndex >= 0) {
      targetCandidates[candidateIndex] = runtimeLane;
    } else {
      targetCandidates.push(runtimeLane);
    }
    ecdsaCandidatesByTarget[targetKey] = targetCandidates;
    const runtimeUpdatedAtMs = availableLaneUpdatedAtMs(runtimeLane);
    if (runtimeUpdatedAtMs >= (ecdsaLaneUpdatedAtMsByTarget[targetKey] || 0)) {
      ecdsaLaneUpdatedAtMsByTarget[targetKey] = runtimeUpdatedAtMs;
      ecdsaLanesByTarget[targetKey] = runtimeLane;
    }
  }

  for (const runtimeRecord of runtimeEd25519Records) {
    const thresholdSessionId = String(runtimeRecord.thresholdSessionId || '').trim();
    if (!thresholdSessionId) continue;
    const runtimeLaneKey = ed25519AvailableLaneIdentityKey(runtimeRecord);
    const durableLane =
      (runtimeLaneKey
        ? ed25519Candidates.find((lane) => ed25519AvailableLaneIdentityKey(lane) === runtimeLaneKey)
        : undefined) || ed25519Lane;
    const runtimeLane = runtimeRecordToEd25519Lane({
      record: runtimeRecord,
      claim: claimsBySessionId.get(thresholdSessionId) || null,
      durableLane,
    });
    const candidateIndex = runtimeLaneKey
      ? ed25519Candidates.findIndex(
          (lane) => ed25519AvailableLaneIdentityKey(lane) === runtimeLaneKey,
        )
      : -1;
    if (candidateIndex >= 0) {
      ed25519Candidates[candidateIndex] = runtimeLane;
    } else {
      ed25519Candidates.push(runtimeLane);
    }
    const runtimeUpdatedAtMs = availableLaneUpdatedAtMs(runtimeLane);
    if (runtimeUpdatedAtMs >= ed25519LaneUpdatedAtMs) {
      ed25519LaneUpdatedAtMs = runtimeUpdatedAtMs;
      ed25519Lane = runtimeLane;
    }
  }

  const byNewestCandidate = (
    left: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
    right: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
  ): number =>
    Math.floor(Number('updatedAtMs' in right ? right.updatedAtMs : 0) || 0) -
    Math.floor(Number('updatedAtMs' in left ? left.updatedAtMs : 0) || 0);

  const availableLanes: AvailableSigningLanes = {
    walletId,
    generation,
    ecdsa: {
      targets: ecdsaTargets,
      lanesByTarget: ecdsaLanesByTarget,
      candidatesByTarget: Object.fromEntries(
        Object.entries(ecdsaCandidatesByTarget).map(([targetKey, candidates]) => [
          targetKey,
          collapseExactDuplicateAvailableLanes(candidates, ecdsaAvailableLaneIdentityKey).sort(
            byNewestCandidate,
          ),
        ]),
      ),
    },
    lanes: {
      ed25519: {
        near: ed25519Lane,
      },
    },
    candidates: {
      ed25519: {
        near: collapseExactDuplicateAvailableLanes(
          ed25519Candidates,
          ed25519AvailableLaneIdentityKey,
        ).sort(byNewestCandidate),
      },
    },
  };
  const missingEcdsaTargets = ecdsaTargets
    .map((target) => {
      const targetKey = thresholdEcdsaChainTargetKey(target);
      const candidates = availableLanes.ecdsa.candidatesByTarget[targetKey] || [];
      const selectedLane = availableLanes.ecdsa.lanesByTarget[targetKey];
      const selectedLaneState = selectedLane?.state || 'missing';
      if (candidates.length > 0 && selectedLaneState !== 'missing') return null;
      return {
        chainTarget: target,
        targetKey,
        candidateCount: candidates.length,
        selectedLane: summarizeEcdsaLaneForDiagnostics(selectedLane),
      };
    })
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));
  const laneDiagnosticPayload = {
    walletId,
    subjectId,
    authMethod: input.authMethod || 'any',
    requestedTargets: ecdsaTargets.map((target) => ({
      chainTarget: target,
      targetKey: thresholdEcdsaChainTargetKey(target),
    })),
    sealedRecordCount: ecdsaRecords.length,
    runtimeRecordCount: runtimeEcdsaRecords.length,
    durableDiscovery: durableEcdsaDiscovery,
    runtimeDiscovery: runtimeEcdsaDiscovery,
    resultSelectedLanesByTarget: Object.fromEntries(
      Object.entries(availableLanes.ecdsa.lanesByTarget).map(([targetKey, lane]) => [
        targetKey,
        summarizeEcdsaLaneForDiagnostics(lane),
      ]),
    ),
    resultCandidatesByTarget: Object.fromEntries(
      Object.entries(availableLanes.ecdsa.candidatesByTarget).map(([targetKey, lanes]) => [
        targetKey,
        lanes.map((lane) => summarizeEcdsaLaneForDiagnostics(lane)),
      ]),
    ),
  };
  if (collectDiagnostics && missingEcdsaTargets.length > 0) {
    try {
      console.warn('[SigningLanes][available][ecdsa][missing-candidates]', {
        ...laneDiagnosticPayload,
        missingEcdsaTargets,
      });
    } catch {}
  }
  if (collectDiagnostics) {
    try {
      console.info('[SigningLanes][available][ecdsa]', laneDiagnosticPayload);
    } catch {}
  }
  return availableLanes;
}
