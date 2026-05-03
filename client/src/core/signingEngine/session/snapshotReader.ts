import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { SigningSessionSealedStoreRecord } from './sealedSessionStore';

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

export type SigningSessionSnapshotEcdsaLane = {
  authMethod?: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chain: 'tempo' | 'evm';
  state: SigningSessionSnapshotLaneState;
  walletSigningSessionId?: string;
  thresholdSessionId?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: SigningSessionSnapshotPolicyHint;
  updatedAtMs?: number;
  source?: 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable';
};

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
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chain: 'tempo' | 'evm';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
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
  lanes: {
    ed25519: {
      near: SigningSessionSnapshotEd25519Lane;
    };
    ecdsa: {
      tempo: SigningSessionSnapshotEcdsaLane;
      evm: SigningSessionSnapshotEcdsaLane;
    };
  };
  candidates: {
    ed25519: {
      near: SigningSessionSnapshotEd25519Lane[];
    };
    ecdsa: {
      tempo: SigningSessionSnapshotEcdsaLane[];
      evm: SigningSessionSnapshotEcdsaLane[];
    };
  };
};

export type ConcreteSigningSessionSnapshotLane = (
  | SigningSessionSnapshotEcdsaLane
  | SigningSessionSnapshotEd25519Lane
) & {
  authMethod: 'email_otp' | 'passkey';
  thresholdSessionId: string;
  walletSigningSessionId: string;
};

export type ReadSigningSessionSnapshotInput = {
  walletId: AccountId | string;
  authMethod?: 'email_otp' | 'passkey';
  nowMs?: number;
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
          chain: 'tempo' | 'evm';
        };
  }) => Promise<SigningSessionSealedStoreRecord[]>;
  listRuntimeEcdsaRecordsForAccount?: (args: {
    accountId: string;
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
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
  if (lane.thresholdSessionId !== thresholdSessionId) return false;
  if (lane.walletSigningSessionId !== walletSigningSessionId) return false;
  return (
    (lane.authMethod === 'email_otp' || lane.authMethod === 'passkey') &&
    Boolean(thresholdSessionId) &&
    Boolean(walletSigningSessionId)
  );
}

type EcdsaSnapshotLaneIdentityInput = Pick<
  SigningSessionSnapshotEcdsaLane,
  'authMethod' | 'curve' | 'chain' | 'walletSigningSessionId' | 'thresholdSessionId'
>;

type Ed25519SnapshotLaneIdentityInput = Pick<
  SigningSessionSnapshotEd25519Lane,
  'authMethod' | 'curve' | 'chain' | 'walletSigningSessionId' | 'thresholdSessionId'
>;

export function ecdsaSnapshotLaneIdentityKey(
  lane: EcdsaSnapshotLaneIdentityInput | null | undefined,
): string | null {
  if (!lane || lane.curve !== 'ecdsa') return null;
  if (lane.chain !== 'tempo' && lane.chain !== 'evm') return null;
  const authMethod =
    lane.authMethod === 'email_otp' || lane.authMethod === 'passkey' ? lane.authMethod : '';
  const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (!authMethod || !walletSigningSessionId || !thresholdSessionId) return null;
  return [authMethod, 'ecdsa', lane.chain, walletSigningSessionId, thresholdSessionId].join(':');
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

function emptyEcdsaLane(chain: 'tempo' | 'evm'): SigningSessionSnapshotEcdsaLane {
  return {
    curve: 'ecdsa',
    chain,
    state: 'missing',
  };
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

function recordToEcdsaLane(args: {
  chain: 'tempo' | 'evm';
  record: SigningSessionSealedStoreRecord;
}): SigningSessionSnapshotEcdsaLane {
  const thresholdSessionId = String(args.record.thresholdSessionIds.ecdsa || '').trim();
  const policyHint = durablePolicyHint(args.record);

  return {
    authMethod: args.record.authMethod,
    curve: 'ecdsa',
    chain: args.chain,
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
}): SigningSessionSnapshotEcdsaLane {
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const claim = args.claim;
  const runtimeLaneKey = ecdsaSnapshotLaneIdentityKey(args.record);
  const durableLaneKey = ecdsaSnapshotLaneIdentityKey(args.durableLane);
  const hasMatchingDurableLane =
    args.durableLane.source === 'durable_sealed_record' &&
    Boolean(runtimeLaneKey) &&
    durableLaneKey === runtimeLaneKey;

  return {
    authMethod: args.record.authMethod,
    curve: 'ecdsa',
    chain: args.record.chain,
    state: runtimeClaimToLaneState(claim, hasMatchingDurableLane ? args.durableLane : undefined),
    source: hasMatchingDurableLane ? 'runtime_and_durable' : 'runtime_session_record',
    ...(args.record.walletSigningSessionId
      ? { walletSigningSessionId: args.record.walletSigningSessionId }
      : {}),
    ...(thresholdSessionId ? { thresholdSessionId } : {}),
    ...(claim?.remainingUses ? { remainingUses: claim.remainingUses } : {}),
    ...(claim?.expiresAtMs ? { expiresAtMs: claim.expiresAtMs } : {}),
    ...(hasMatchingDurableLane && args.durableLane.updatedAtMs
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
  const claim = args.claim;
  const hasMatchingDurableLane =
    args.durableLane.source === 'durable_sealed_record' &&
    String(args.durableLane.thresholdSessionId || '').trim() === thresholdSessionId;

  return {
    authMethod: args.record.authMethod,
    curve: 'ed25519',
    chain: 'near',
    state: runtimeClaimToLaneState(claim, hasMatchingDurableLane ? args.durableLane : undefined),
    source: hasMatchingDurableLane ? 'runtime_and_durable' : 'runtime_session_record',
    ...(args.record.walletSigningSessionId
      ? { walletSigningSessionId: args.record.walletSigningSessionId }
      : {}),
    ...(thresholdSessionId ? { thresholdSessionId } : {}),
    ...(claim?.remainingUses ? { remainingUses: claim.remainingUses } : {}),
    ...(claim?.expiresAtMs ? { expiresAtMs: claim.expiresAtMs } : {}),
    ...(hasMatchingDurableLane && args.durableLane.updatedAtMs
      ? { updatedAtMs: args.durableLane.updatedAtMs }
      : {}),
  };
}

export async function readSigningSessionSnapshot(
  input: ReadSigningSessionSnapshotInput,
  ports: ReadSigningSessionSnapshotPorts,
): Promise<SigningSessionSnapshot> {
  const walletId = toAccountId(input.walletId);
  const [tempoEcdsaRecords, evmEcdsaRecords] = await Promise.all([
    ports.listSealedRecordsForAccount({
      accountId: walletId,
      filter: {
        ...(input.authMethod ? { authMethod: input.authMethod } : {}),
        curve: 'ecdsa',
        chain: 'tempo',
      },
    }),
    ports.listSealedRecordsForAccount({
      accountId: walletId,
      filter: {
        ...(input.authMethod ? { authMethod: input.authMethod } : {}),
        curve: 'ecdsa',
        chain: 'evm',
      },
    }),
  ]);
  const ecdsaRecords = [...tempoEcdsaRecords, ...evmEcdsaRecords];
  const ed25519Records = await ports.listSealedRecordsForAccount({
    accountId: walletId,
    filter: {
      ...(input.authMethod ? { authMethod: input.authMethod } : {}),
      curve: 'ed25519',
    },
  });

  const ecdsaLanes = {
    tempo: emptyEcdsaLane('tempo'),
    evm: emptyEcdsaLane('evm'),
  };
  const ecdsaCandidates: {
    tempo: SigningSessionSnapshotEcdsaLane[];
    evm: SigningSessionSnapshotEcdsaLane[];
  } = {
    tempo: [],
    evm: [],
  };
  const ed25519Candidates: SigningSessionSnapshotEd25519Lane[] = [];
  let ed25519Lane = emptyEd25519Lane();
  const laneUpdatedAtMs = {
    tempo: 0,
    evm: 0,
  };
  let ed25519LaneUpdatedAtMs = 0;
  let generation = 0;

  for (const record of ecdsaRecords) {
    if (!record.thresholdSessionIds.ecdsa) continue;
    const chain = record.ecdsaRestore?.chain;
    if (chain !== 'tempo' && chain !== 'evm') continue;
    const updatedAtMs = Math.floor(Number(record.updatedAtMs) || 0);
    generation = Math.max(generation, updatedAtMs);
    const lane = recordToEcdsaLane({ chain, record });
    ecdsaCandidates[chain].push(lane);
    if (updatedAtMs < laneUpdatedAtMs[chain]) continue;
    ecdsaLanes[chain] = lane;
    laneUpdatedAtMs[chain] = updatedAtMs;
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

  const runtimeEcdsaRecords = ports.listRuntimeEcdsaRecordsForAccount
    ? (await ports.listRuntimeEcdsaRecordsForAccount({ accountId: walletId })).filter(
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
    const chain = runtimeRecord.chain;
    if (chain !== 'tempo' && chain !== 'evm') continue;
    const thresholdSessionId = String(runtimeRecord.thresholdSessionId || '').trim();
    if (!thresholdSessionId) continue;
    const runtimeLaneKey = ecdsaSnapshotLaneIdentityKey(runtimeRecord);
    const durableLane =
      (runtimeLaneKey
        ? ecdsaCandidates[chain].find(
            (lane) => ecdsaSnapshotLaneIdentityKey(lane) === runtimeLaneKey,
          )
        : undefined) || ecdsaLanes[chain];
    const runtimeLane = runtimeRecordToEcdsaLane({
      record: runtimeRecord,
      claim: claimsBySessionId.get(thresholdSessionId) || null,
      durableLane,
    });
    const candidateIndex = runtimeLaneKey
      ? ecdsaCandidates[chain].findIndex(
          (lane) => ecdsaSnapshotLaneIdentityKey(lane) === runtimeLaneKey,
        )
      : -1;
    if (candidateIndex >= 0) {
      ecdsaCandidates[chain][candidateIndex] = runtimeLane;
    } else {
      ecdsaCandidates[chain].push(runtimeLane);
    }
    ecdsaLanes[chain] = runtimeLane;
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
  ): number => Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0);

  return {
    walletId,
    generation,
    lanes: {
      ed25519: {
        near: ed25519Lane,
      },
      ecdsa: ecdsaLanes,
    },
    candidates: {
      ed25519: {
        near: ed25519Candidates.sort(byNewestCandidate),
      },
      ecdsa: ecdsaCandidates,
    },
  };
}
