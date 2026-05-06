import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { decodeJwtPayloadRecord, THRESHOLD_ECDSA_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import type { SigningSessionSealedStoreRecord } from './sealedSessionStore';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaLaneKey,
  toWalletSubjectId,
  type EcdsaLaneIdentity,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from './signingSession/ecdsaChainTarget';
import { normalizeThresholdRuntimePolicyScope } from '../threshold/session/sessionPolicy';

export type SigningSessionSnapshotLaneState =
  | 'ready'
  | 'restorable'
  | 'deferred'
  | 'expired'
  | 'exhausted'
  | 'missing';

export type SigningSessionSnapshotPolicyHint = {
  remainingUses?: number;
  expiresAtMs?: number;
};

export type SigningSessionSnapshotMissingEcdsaLane = {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: 'missing';
};

export type SigningSessionSnapshotConcreteEcdsaLane = {
  subjectId: WalletSubjectId;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  state: SigningSessionSnapshotLaneState;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: SigningSessionSnapshotPolicyHint;
  updatedAtMs?: number;
  source?: 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable';
};

export type SigningSessionSnapshotEcdsaLane =
  | SigningSessionSnapshotMissingEcdsaLane
  | SigningSessionSnapshotConcreteEcdsaLane;

export type SigningSessionSnapshotEd25519Lane = {
  authMethod?: 'email_otp' | 'passkey';
  curve: 'ed25519';
  chain: 'near';
  state: SigningSessionSnapshotLaneState;
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: SigningSessionSnapshotPolicyHint;
  updatedAtMs?: number;
  source?: 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable';
};

export type SigningSessionSnapshotRuntimeClaim = {
  state: 'warm' | 'missing' | 'expired' | 'exhausted' | 'unavailable';
  sessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  code?: string;
};

export type SigningSessionSnapshotRuntimeEcdsaRecord = {
  subjectId: WalletSubjectId;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdSessionId: string;
  walletSigningSessionId: string;
};

export type SigningSessionSnapshotRuntimeEd25519Record = {
  authMethod: 'email_otp' | 'passkey';
  curve: 'ed25519';
  chain: 'near';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
};

export type SigningSessionSnapshot = {
  walletId: AccountId;
  generation: number;
  ecdsa: {
    targets: ThresholdEcdsaChainTarget[];
    lanesByTarget: Record<string, SigningSessionSnapshotEcdsaLane>;
    candidatesByTarget: Record<string, SigningSessionSnapshotEcdsaLane[]>;
  };
  lanes: {
    ed25519: {
      near: SigningSessionSnapshotEd25519Lane;
    };
  };
  candidates: {
    ed25519: {
      near: SigningSessionSnapshotEd25519Lane[];
    };
  };
};

export type ConcreteSigningSessionSnapshotLane =
  | SigningSessionSnapshotConcreteEcdsaLane
  | (SigningSessionSnapshotEd25519Lane & {
  authMethod: 'email_otp' | 'passkey';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  });

export type ReadSigningSessionSnapshotInput = {
  walletId: AccountId | string;
  subjectId: WalletSubjectId;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  authMethod?: 'email_otp' | 'passkey';
  nowMs?: number;
};

export type ReadSigningSessionSnapshotForSigningInput =
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

export type ReadSigningSessionSnapshotPorts = {
  listSealedRecordsForAccount: (args: {
    accountId: string;
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
  }) => Promise<SigningSessionSnapshotRuntimeEcdsaRecord[]>;
  listRuntimeEd25519RecordsForAccount?: (args: {
    accountId: string;
  }) => Promise<SigningSessionSnapshotRuntimeEd25519Record[]>;
  readRuntimeClaimsForSessions?: (
    sessionIds: string[],
  ) => Promise<Map<string, SigningSessionSnapshotRuntimeClaim | null>>;
};

export function isConcreteSigningSessionSnapshotLane(
  lane: SigningSessionSnapshotEcdsaLane | SigningSessionSnapshotEd25519Lane,
): lane is ConcreteSigningSessionSnapshotLane {
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

type EcdsaSnapshotLaneIdentityInput = Pick<
  SigningSessionSnapshotConcreteEcdsaLane,
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

type Ed25519SnapshotLaneIdentityInput = Pick<
  SigningSessionSnapshotEd25519Lane,
  'authMethod' | 'curve' | 'chain' | 'walletSigningSessionId' | 'thresholdSessionId'
>;

export function ecdsaSnapshotLaneIdentityKey(
  lane:
    | EcdsaSnapshotLaneIdentityInput
    | SigningSessionSnapshotMissingEcdsaLane
    | null
    | undefined,
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
  const identity: EcdsaLaneIdentity = {
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

export function ed25519SnapshotLaneIdentityKey(
  lane: Ed25519SnapshotLaneIdentityInput | null | undefined,
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
}): SigningSessionSnapshotMissingEcdsaLane {
  return {
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    state: 'missing',
  };
}

export function ecdsaSnapshotLaneForTarget(
  snapshot: SigningSessionSnapshot,
  chainTarget: ThresholdEcdsaChainTarget,
): SigningSessionSnapshotEcdsaLane {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return snapshot.ecdsa.lanesByTarget[targetKey] || emptyEcdsaLane({ chainTarget });
}

export function ecdsaSnapshotTargets(
  snapshot: SigningSessionSnapshot,
): ThresholdEcdsaChainTarget[] {
  return snapshot.ecdsa.targets;
}

export function ecdsaSnapshotCandidatesForTarget(
  snapshot: SigningSessionSnapshot,
  chainTarget: ThresholdEcdsaChainTarget,
): SigningSessionSnapshotEcdsaLane[] {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return snapshot.ecdsa.candidatesByTarget[targetKey] || [];
}

function emptyEd25519Lane(): SigningSessionSnapshotEd25519Lane {
  return {
    curve: 'ed25519',
    chain: 'near',
    state: 'missing',
  };
}

function durablePolicyHint(
  record: SigningSessionSealedStoreRecord,
): SigningSessionSnapshotPolicyHint | undefined {
  const remainingUses = Math.floor(Number(record.remainingUses));
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  const hint: SigningSessionSnapshotPolicyHint = {};
  if (Number.isFinite(remainingUses) && remainingUses >= 0) {
    hint.remainingUses = remainingUses;
  }
  if (Number.isFinite(expiresAtMs) && expiresAtMs > 0) {
    hint.expiresAtMs = expiresAtMs;
  }
  return Object.keys(hint).length ? hint : undefined;
}

function durableEcdsaSigningRoot(
  record: SigningSessionSealedStoreRecord,
): { signingRootId: string; signingRootVersion: string } | null {
  const explicitSigningRootId = String(record.signingRootId || '').trim();
  const explicitSigningRootVersion = String(record.signingRootVersion || '').trim();
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    record.ecdsaRestore?.runtimePolicyScope,
  );
  const scope = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const signingRootId = explicitSigningRootId || String(scope?.signingRootId || '').trim();
  const signingRootVersion =
    explicitSigningRootVersion || String(scope?.signingRootVersion || 'default').trim();
  if (!signingRootId || !signingRootVersion) return null;
  return { signingRootId, signingRootVersion };
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
  if (!payload || payload.kind !== THRESHOLD_ECDSA_SESSION_JWT_KIND) return false;
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
    thresholdEcdsaChainTargetKey(jwtChainTarget) === thresholdEcdsaChainTargetKey(args.chainTarget) &&
    String(payload.sessionId || '').trim() === args.thresholdSessionId &&
    String(payload.walletSigningSessionId || '').trim() === args.record.walletSigningSessionId
  );
}

function recordToEcdsaLane(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  record: SigningSessionSealedStoreRecord;
}): SigningSessionSnapshotEcdsaLane | null {
  const thresholdSessionId = String(args.record.thresholdSessionIds.ecdsa || '').trim();
  const policyHint = durablePolicyHint(args.record);
  const ecdsaRestore = args.record.ecdsaRestore;
  const subjectId = String(args.record.subjectId || '').trim();
  const signingRoot = durableEcdsaSigningRoot(args.record);
  if (!thresholdSessionId || !subjectId || !ecdsaRestore?.ecdsaThresholdKeyId || !signingRoot) {
    return null;
  }
  if (
    !durableEcdsaJwtMatchesRecord({
      record: args.record,
      chainTarget: args.chainTarget,
      thresholdSessionId,
      subjectId,
      ecdsaThresholdKeyId: String(ecdsaRestore.ecdsaThresholdKeyId || '').trim(),
    })
  ) {
    return null;
  }

  return {
    subjectId: toWalletSubjectId(subjectId),
    authMethod: args.record.authMethod,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    ecdsaThresholdKeyId: ecdsaRestore.ecdsaThresholdKeyId,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
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
}): SigningSessionSnapshotEd25519Lane {
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

export function warmStatusToSigningSessionSnapshotRuntimeClaim(args: {
  sessionId: string;
  status: { ok: true; remainingUses: number; expiresAtMs: number } | { ok: false; code: string };
}): SigningSessionSnapshotRuntimeClaim {
  if (args.status.ok) {
    return {
      state: 'warm',
      sessionId: args.sessionId,
      remainingUses: args.status.remainingUses,
      expiresAtMs: args.status.expiresAtMs,
    };
  }
  if (args.status.code === 'expired') return { state: 'expired', sessionId: args.sessionId };
  if (args.status.code === 'exhausted') return { state: 'exhausted', sessionId: args.sessionId };
  if (args.status.code === 'not_found') return { state: 'missing', sessionId: args.sessionId };
  return {
    state: 'unavailable',
    sessionId: args.sessionId,
    code: args.status.code,
  };
}

function runtimeClaimToLaneState(
  claim: SigningSessionSnapshotRuntimeClaim | null,
  durableLane?: SigningSessionSnapshotEcdsaLane | SigningSessionSnapshotEd25519Lane,
): SigningSessionSnapshotLaneState {
  if (!claim) return durableLane?.state || 'deferred';
  if (claim.state === 'warm') return 'ready';
  if (claim.state === 'expired') return 'expired';
  if (claim.state === 'exhausted') return 'exhausted';
  if (claim.state === 'missing') return durableLane?.state || 'missing';
  return durableLane?.state || 'deferred';
}

function runtimeRecordToEcdsaLane(args: {
  record: SigningSessionSnapshotRuntimeEcdsaRecord;
  claim: SigningSessionSnapshotRuntimeClaim | null;
  durableLane: SigningSessionSnapshotEcdsaLane;
}): SigningSessionSnapshotConcreteEcdsaLane {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const claim = args.claim;
  const runtimeLaneKey = ecdsaSnapshotLaneIdentityKey(args.record);
  const durableLaneKey = ecdsaSnapshotLaneIdentityKey(args.durableLane);
  const hasMatchingDurableLane =
    isConcreteSigningSessionSnapshotLane(args.durableLane) &&
    args.durableLane.source === 'durable_sealed_record' &&
    Boolean(runtimeLaneKey) &&
    durableLaneKey === runtimeLaneKey;

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
    ...(claim?.remainingUses ? { remainingUses: claim.remainingUses } : {}),
    ...(claim?.expiresAtMs ? { expiresAtMs: claim.expiresAtMs } : {}),
    ...(hasMatchingDurableLane &&
    isConcreteSigningSessionSnapshotLane(args.durableLane) &&
    args.durableLane.updatedAtMs
      ? { updatedAtMs: args.durableLane.updatedAtMs }
      : {}),
  };
}

function runtimeRecordToEd25519Lane(args: {
  record: SigningSessionSnapshotRuntimeEd25519Record;
  claim: SigningSessionSnapshotRuntimeClaim | null;
  durableLane: SigningSessionSnapshotEd25519Lane;
}): SigningSessionSnapshotEd25519Lane {
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

  return {
    authMethod: args.record.authMethod,
    curve: 'ed25519',
    chain: 'near',
    state: runtimeClaimToLaneState(claim, hasMatchingDurableLane ? args.durableLane : undefined),
    source: hasMatchingDurableLane ? 'runtime_and_durable' : 'runtime_session_record',
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    ...(thresholdSessionId ? { thresholdSessionId } : {}),
    ...(claim?.remainingUses ? { remainingUses: claim.remainingUses } : {}),
    ...(claim?.expiresAtMs ? { expiresAtMs: claim.expiresAtMs } : {}),
    ...(hasMatchingDurableLane && args.durableLane.updatedAtMs
      ? { updatedAtMs: args.durableLane.updatedAtMs }
      : {}),
  };
}

function isRuntimeOwnedSnapshotLane(
  lane: SigningSessionSnapshotEcdsaLane | SigningSessionSnapshotEd25519Lane,
): boolean {
  const source = 'source' in lane ? lane.source : undefined;
  return (
    lane.state === 'ready' ||
    source === 'runtime_and_durable' ||
    source === 'runtime_session_record'
  );
}

function snapshotLaneUpdatedAtMs(
  lane: SigningSessionSnapshotEcdsaLane | SigningSessionSnapshotEd25519Lane,
): number {
  return Math.floor(Number('updatedAtMs' in lane ? lane.updatedAtMs : 0) || 0);
}

function collapseExactDuplicateSnapshotLanes<TLane extends SigningSessionSnapshotEcdsaLane | SigningSessionSnapshotEd25519Lane>(
  lanes: TLane[],
  laneIdentityKey: (lane: TLane) => string | null,
): TLane[] {
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
  const normalized = [...keyedGroups.values()].map((group) =>
    [...group].sort((left, right) => {
      const runtimeDelta =
        Number(isRuntimeOwnedSnapshotLane(right)) - Number(isRuntimeOwnedSnapshotLane(left));
      if (runtimeDelta) return runtimeDelta;
      return snapshotLaneUpdatedAtMs(right) - snapshotLaneUpdatedAtMs(left);
    })[0]!,
  );
  return [...normalized, ...unkeyed];
}

export async function readSigningSessionSnapshot(
  input: ReadSigningSessionSnapshotInput,
  ports: ReadSigningSessionSnapshotPorts,
): Promise<SigningSessionSnapshot> {
  const walletId = toAccountId(input.walletId);
  const subjectId = String(input.subjectId || '').trim();
  const ecdsaTargetsByKey = new Map<string, ThresholdEcdsaChainTarget>();
  for (const chainTarget of input.ecdsaChainTargets) {
    ecdsaTargetsByKey.set(thresholdEcdsaChainTargetKey(chainTarget), chainTarget);
  }
  const ecdsaChainTargets = [...ecdsaTargetsByKey.values()];
  const ecdsaRecordsByTarget = await Promise.all(
    ecdsaChainTargets.map((chainTarget) =>
      ports.listSealedRecordsForAccount({
        accountId: walletId,
        filter: {
          ...(input.authMethod ? { authMethod: input.authMethod } : {}),
          curve: 'ecdsa',
          chainTarget,
        },
      }),
    ),
  );
  const ecdsaRecords = ecdsaRecordsByTarget.flat();
  const ed25519Records = await ports.listSealedRecordsForAccount({
    accountId: walletId,
    filter: {
      ...(input.authMethod ? { authMethod: input.authMethod } : {}),
      curve: 'ed25519',
    },
  });

  const ecdsaTargets = [...ecdsaChainTargets];
  const ecdsaLanesByTarget: Record<string, SigningSessionSnapshotEcdsaLane> = {};
  const ecdsaCandidatesByTarget: Record<string, SigningSessionSnapshotEcdsaLane[]> = {};
  const ecdsaLaneUpdatedAtMsByTarget: Record<string, number> = {};
  for (const chainTarget of ecdsaTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    ecdsaLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
    ecdsaCandidatesByTarget[targetKey] = [];
    ecdsaLaneUpdatedAtMsByTarget[targetKey] = 0;
  }
  const ed25519Candidates: SigningSessionSnapshotEd25519Lane[] = [];
  let ed25519Lane = emptyEd25519Lane();
  let ed25519LaneUpdatedAtMs = 0;
  let generation = 0;

  for (const record of ecdsaRecords) {
    if (!record.thresholdSessionIds.ecdsa) continue;
    if (String(record.subjectId || '').trim() !== subjectId) continue;
    const chainTarget = record.ecdsaRestore?.chainTarget;
    if (!chainTarget) continue;
    const chain = chainTarget.kind;
    if (chain !== 'tempo' && chain !== 'evm') continue;
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const updatedAtMs = Math.floor(Number(record.updatedAtMs) || 0);
    generation = Math.max(generation, updatedAtMs);
    const lane = recordToEcdsaLane({
      chainTarget,
      record,
    });
    if (!lane) continue;
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
      : new Map<string, SigningSessionSnapshotRuntimeClaim | null>();

  for (const runtimeRecord of runtimeEcdsaRecords) {
    const chain = runtimeRecord.chainTarget.kind;
    if (chain !== 'tempo' && chain !== 'evm') continue;
    const thresholdSessionId = String(runtimeRecord.thresholdSessionId || '').trim();
    if (!thresholdSessionId) continue;
    const runtimeLaneKey = ecdsaSnapshotLaneIdentityKey(runtimeRecord);
    const targetKey = thresholdEcdsaChainTargetKey(runtimeRecord.chainTarget);
    const targetCandidates = ecdsaCandidatesByTarget[targetKey] || [];
    const targetLane = ecdsaLanesByTarget[targetKey] || emptyEcdsaLane({ chainTarget: runtimeRecord.chainTarget });
    const durableLane =
      (runtimeLaneKey
        ? targetCandidates.find(
            (lane) => ecdsaSnapshotLaneIdentityKey(lane) === runtimeLaneKey,
          )
        : undefined) || targetLane;
    const runtimeLane = runtimeRecordToEcdsaLane({
      record: runtimeRecord,
      claim: claimsBySessionId.get(thresholdSessionId) || null,
      durableLane,
    });
    const candidateIndex = runtimeLaneKey
      ? targetCandidates.findIndex(
          (lane) => ecdsaSnapshotLaneIdentityKey(lane) === runtimeLaneKey,
        )
      : -1;
    if (candidateIndex >= 0) {
      targetCandidates[candidateIndex] = runtimeLane;
    } else {
      targetCandidates.push(runtimeLane);
    }
    ecdsaCandidatesByTarget[targetKey] = targetCandidates;
    ecdsaLanesByTarget[targetKey] = runtimeLane;
  }

  for (const runtimeRecord of runtimeEd25519Records) {
    const thresholdSessionId = String(runtimeRecord.thresholdSessionId || '').trim();
    if (!thresholdSessionId) continue;
    const runtimeLaneKey = ed25519SnapshotLaneIdentityKey(runtimeRecord);
    const durableLane =
      (runtimeLaneKey
        ? ed25519Candidates.find(
            (lane) => ed25519SnapshotLaneIdentityKey(lane) === runtimeLaneKey,
          )
        : undefined) || ed25519Lane;
    const runtimeLane = runtimeRecordToEd25519Lane({
      record: runtimeRecord,
      claim: claimsBySessionId.get(thresholdSessionId) || null,
      durableLane,
    });
    const candidateIndex = runtimeLaneKey
      ? ed25519Candidates.findIndex(
          (lane) => ed25519SnapshotLaneIdentityKey(lane) === runtimeLaneKey,
        )
      : -1;
    if (candidateIndex >= 0) {
      ed25519Candidates[candidateIndex] = runtimeLane;
    } else {
      ed25519Candidates.push(runtimeLane);
    }
    ed25519Lane = runtimeLane;
  }

  const byNewestCandidate = (
    left: SigningSessionSnapshotEcdsaLane | SigningSessionSnapshotEd25519Lane,
    right: SigningSessionSnapshotEcdsaLane | SigningSessionSnapshotEd25519Lane,
  ): number =>
    Math.floor(Number('updatedAtMs' in right ? right.updatedAtMs : 0) || 0) -
    Math.floor(Number('updatedAtMs' in left ? left.updatedAtMs : 0) || 0);

  return {
    walletId,
    generation,
    ecdsa: {
      targets: ecdsaTargets,
      lanesByTarget: ecdsaLanesByTarget,
      candidatesByTarget: Object.fromEntries(
        Object.entries(ecdsaCandidatesByTarget).map(([targetKey, candidates]) => [
          targetKey,
          collapseExactDuplicateSnapshotLanes(
            candidates,
            ecdsaSnapshotLaneIdentityKey,
          ).sort(byNewestCandidate),
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
        near: collapseExactDuplicateSnapshotLanes(
          ed25519Candidates,
          ed25519SnapshotLaneIdentityKey,
        ).sort(byNewestCandidate),
      },
    },
  };
}
