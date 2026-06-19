import type { SigningSessionStatus } from '@/core/types/seams';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import {
  assertBudgetStatusCheckHasConcreteLaneIdentity,
  buildWalletBudgetStatusCheck,
  isEcdsaLaneBudgetStatusCheck,
  ownerForBudgetStatusCheck,
  thresholdSessionIdsForBudgetStatusCheck,
  type AuthenticatedEcdsaLaneBudgetStatusCheck,
  type EcdsaLaneBudgetStatusCheck,
  type SigningSessionBudgetStatusAuth,
  type SigningSessionBudgetStatusCheck,
  type WalletBudgetOwner,
} from './budget';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmFamilyEcdsaKeyIdentity } from '../identity/evmFamilyEcdsaIdentity';
import { budgetUnknownSigningSessionStatus } from './budgetProjection';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../warmCapabilities/routerAbEcdsaWalletSessionAuth';
import { walletSessionJwtFromPersistedEd25519Record } from '../walletSessionAuthBoundary';

export type WalletSigningBudgetAvailableStatusDeps = {
  getAvailableStatus: (
    args: SigningSessionBudgetStatusCheck,
  ) => Promise<SigningSessionStatus | null>;
};

export type TrustedWalletSigningBudgetStatusDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
};

type ThresholdScopedBudgetStatusAuth = {
  kind: 'threshold_scoped';
  relayerUrl: string;
  thresholdSessionId: string;
  walletSessionJwt: string;
  curve?: 'ecdsa' | 'ed25519';
  chainTarget?: ThresholdEcdsaChainTarget;
  key?: EvmFamilyEcdsaKeyIdentity;
};

type TrustedBudgetStatusAuth = ThresholdScopedBudgetStatusAuth;

type TrustedBudgetStatusFetchResult = {
  status: SigningSessionStatus | null;
  authRejected: boolean;
};

function walletSessionJwtFromTrustedEcdsaBudgetRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): string {
  if (!record) return '';
  const resolved = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  return resolved.kind === 'ready' ? resolved.walletSessionJwt : '';
}

const inFlightTrustedBudgetStatusFetches = new Map<
  string,
  Promise<TrustedBudgetStatusFetchResult>
>();

type TrustedBudgetStatusPayload =
  | {
      kind: 'not_found';
      status: SigningSessionStatus & { status: 'not_found' };
    }
  | {
      kind: 'budget_unknown';
      status: SigningSessionStatus & { status: 'budget_unknown' };
    }
  | {
      kind: 'current';
      status: SigningSessionStatus & {
        status: 'active' | 'exhausted' | 'expired';
      };
    };

export async function getWalletSigningBudgetAvailableStatus(
  deps: WalletSigningBudgetAvailableStatusDeps,
  args: SigningSessionBudgetStatusCheck,
): Promise<SigningSessionStatus | null> {
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return null;
  return await deps
    .getAvailableStatus({ ...args, walletSigningSessionId })
    .catch(() => null);
}

export async function readTrustedWalletSigningBudgetStatus(
  deps: TrustedWalletSigningBudgetStatusDeps,
  args: SigningSessionBudgetStatusCheck,
): Promise<SigningSessionStatus | null> {
  assertBudgetStatusCheckHasConcreteLaneIdentity(args);
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return null;
  const targetThresholdSessionIds = thresholdSessionIdsForBudgetStatusCheck(args);
  const ecdsaLaneCheck = isEcdsaLaneBudgetStatusCheck(args) ? args : undefined;
  const providedAuth =
    args.kind === 'authenticated_threshold_budget_status_check' ||
    args.kind === 'authenticated_ecdsa_lane_budget_status_check'
      ? normalizeBudgetStatusAuth(args.trustedStatusAuth, ecdsaLaneCheck)
      : null;
  const resolvedAuth =
    providedAuth ||
    resolveWalletSigningBudgetStatusAuth(deps, {
      owner: ownerForBudgetStatusCheck(args),
      walletSigningSessionId,
      targetThresholdSessionIds,
      ecdsaLaneCheck,
    });
  if (!resolvedAuth?.relayerUrl) return null;

  const initial = await fetchTrustedWalletSigningBudgetStatus({
    auth: resolvedAuth,
    walletSigningSessionId,
  });
  if (!providedAuth || !initial.authRejected) {
    return initial.status;
  }

  const fallbackAuth = resolveWalletSigningBudgetStatusAuth(deps, {
    owner: ownerForBudgetStatusCheck(args),
    walletSigningSessionId,
    targetThresholdSessionIds,
    ecdsaLaneCheck,
  });
  if (!fallbackAuth?.relayerUrl || sameBudgetStatusAuth(providedAuth, fallbackAuth)) {
    return initial.status;
  }
  const fallback = await fetchTrustedWalletSigningBudgetStatus({
    auth: fallbackAuth,
    walletSigningSessionId,
  });
  return fallback.status;
}

function normalizeBudgetStatusAuth(
  trustedStatusAuth: SigningSessionBudgetStatusAuth | undefined,
  ecdsaLaneCheck?: EcdsaLaneBudgetStatusCheck | AuthenticatedEcdsaLaneBudgetStatusCheck,
): ThresholdScopedBudgetStatusAuth | null {
  const relayerUrl = String(trustedStatusAuth?.relayerUrl || '').trim();
  const thresholdSessionId = String(trustedStatusAuth?.thresholdSessionId || '').trim();
  if (!relayerUrl || !thresholdSessionId) return null;
  if (
    ecdsaLaneCheck &&
    thresholdSessionId !== String(ecdsaLaneCheck.thresholdSessionId || '').trim()
  ) {
    return null;
  }
  const walletSessionJwt = String(trustedStatusAuth?.walletSessionJwt || '').trim();
  if (!walletSessionJwt) return null;
  return {
    kind: 'threshold_scoped',
    relayerUrl,
    thresholdSessionId,
    walletSessionJwt,
    ...(ecdsaLaneCheck
      ? {
          curve: 'ecdsa' as const,
          chainTarget: ecdsaLaneCheck.chainTarget,
          key: ecdsaLaneCheck.key,
        }
      : {}),
  };
}

function sameBudgetStatusAuth(left: TrustedBudgetStatusAuth, right: TrustedBudgetStatusAuth): boolean {
  return (
    left.kind === right.kind &&
    left.relayerUrl === right.relayerUrl &&
    left.thresholdSessionId === right.thresholdSessionId &&
    left.walletSessionJwt === right.walletSessionJwt
  );
}

function parseTrustedBudgetStatusPayload(args: {
  body: unknown;
  walletSigningSessionId: string;
  auth: TrustedBudgetStatusAuth;
}): TrustedBudgetStatusPayload | null {
  const record = (args.body || {}) as Record<string, unknown>;
  if (record.ok !== true) return null;
  const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
  if (walletSigningSessionId !== args.walletSigningSessionId) return null;
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  if (args.auth.thresholdSessionId !== thresholdSessionId) {
    return null;
  }

  const status = String(record.status || '').trim();
  if (status === 'not_found') {
    const statusCode = String(record.statusCode || '').trim();
    if (statusCode === 'unauthorized') {
      return {
        kind: 'budget_unknown',
        status: budgetUnknownSigningSessionStatus({
          walletSigningSessionId,
          reason: 'status_unavailable',
        }) as SigningSessionStatus & { status: 'budget_unknown' },
      };
    }
    return {
      kind: 'not_found',
      status: {
        sessionId: walletSigningSessionId,
        status: 'not_found',
        ...(statusCode ? { statusCode } : {}),
      },
    };
  }

  if (status !== 'active' && status !== 'exhausted' && status !== 'expired') {
    return null;
  }

  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;

  if (status === 'expired') {
    return {
      kind: 'current',
      status: {
        sessionId: walletSigningSessionId,
        status,
        expiresAtMs,
      },
    };
  }

  const remainingUses = Math.floor(Number(record.remainingUses));
  if (!Number.isFinite(remainingUses) || remainingUses < 0) return null;
  const committedRemainingUses = Math.max(
    0,
    Math.floor(Number(record.committedRemainingUses ?? record.remainingUses) || 0),
  );
  const inFlightReservedUses = Math.max(
    0,
    Math.floor(Number(record.reservedUses ?? record.inFlightReservedUses) || 0),
  );
  const availableUses = Math.max(
    0,
    Math.floor(Number(record.availableUses ?? record.remainingUses) || 0),
  );
  const projectionVersion = String(record.projectionVersion || '').trim();
  if (!projectionVersion) return null;
  return {
    kind: 'current',
    status: {
      sessionId: walletSigningSessionId,
      status,
      remainingUses,
      committedRemainingUses,
      inFlightReservedUses,
      availableUses,
      expiresAtMs,
      projectionVersion,
    },
  };
}

async function fetchTrustedWalletSigningBudgetStatus(args: {
  auth: TrustedBudgetStatusAuth;
  walletSigningSessionId: string;
}): Promise<TrustedBudgetStatusFetchResult> {
  const key = trustedBudgetStatusFetchKey(args);
  const inFlight = inFlightTrustedBudgetStatusFetches.get(key);
  if (inFlight) return await inFlight;

  const fetchPromise = fetchTrustedWalletSigningBudgetStatusOnce(args);
  inFlightTrustedBudgetStatusFetches.set(key, fetchPromise);
  try {
    return await fetchPromise;
  } finally {
    if (inFlightTrustedBudgetStatusFetches.get(key) === fetchPromise) {
      inFlightTrustedBudgetStatusFetches.delete(key);
    }
  }
}

function trustedBudgetStatusFetchKey(args: {
  auth: TrustedBudgetStatusAuth;
  walletSigningSessionId: string;
}): string {
  return [
    args.auth.kind,
    args.auth.relayerUrl,
    args.auth.thresholdSessionId,
    args.auth.walletSessionJwt,
    args.walletSigningSessionId,
  ].join('\x1f');
}

async function fetchTrustedWalletSigningBudgetStatusOnce(args: {
  auth: TrustedBudgetStatusAuth;
  walletSigningSessionId: string;
}): Promise<TrustedBudgetStatusFetchResult> {
  const response = await fetch(
    joinNormalizedUrl(args.auth.relayerUrl, '/session/signing-budget/status'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${args.auth.walletSessionJwt}`,
      },
      credentials: 'omit',
      body: JSON.stringify({
        walletSigningSessionId: args.walletSigningSessionId,
        thresholdSessionId: args.auth.thresholdSessionId,
        ...(args.auth.curve ? { curve: args.auth.curve } : {}),
        ...(args.auth.chainTarget ? { chainTarget: args.auth.chainTarget } : {}),
      }),
    },
  );
  const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok || !json || json.ok === false) {
    if (response.status === 401 || response.status === 403) {
      return {
        status: budgetUnknownSigningSessionStatus({
          walletSigningSessionId: args.walletSigningSessionId,
          reason: 'status_unavailable',
        }),
        authRejected: true,
      };
    }
    if (response.status === 404) {
      return {
        status: {
          sessionId: args.walletSigningSessionId,
          status: 'not_found',
          ...(typeof json?.code === 'string' ? { statusCode: json.code } : {}),
        },
        authRejected: true,
      };
    }
    return { status: null, authRejected: false };
  }
  const parsed = parseTrustedBudgetStatusPayload({
    body: json,
    walletSigningSessionId: args.walletSigningSessionId,
    auth: args.auth,
  });
  if (!parsed) return { status: null, authRejected: false };
  return {
    status: parsed.status,
    authRejected: false,
  };
}

function resolveWalletSigningBudgetStatusAuth(
  deps: TrustedWalletSigningBudgetStatusDeps,
  args: {
    owner: WalletBudgetOwner;
    walletSigningSessionId: string;
    targetThresholdSessionIds?: string[];
    ecdsaLaneCheck?: EcdsaLaneBudgetStatusCheck | AuthenticatedEcdsaLaneBudgetStatusCheck;
  },
): TrustedBudgetStatusAuth | null {
  const owner = args.owner;
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return null;
  const targetThresholdIds = new Set(
    (args.targetThresholdSessionIds || [])
      .map((value) => String(value || '').trim())
      .filter(Boolean),
  );
  const candidates: Array<ThresholdScopedBudgetStatusAuth & { exactTarget: boolean }> = [];
  const pushCandidate = (
    record:
      | {
          relayerUrl?: unknown;
          thresholdSessionId?: unknown;
          walletSigningSessionId?: unknown;
        }
      | null
      | undefined,
    walletSessionJwtInput: unknown,
  ): void => {
    if (!record) return;
    if (String(record.walletSigningSessionId || '').trim() !== walletSigningSessionId) return;
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    const relayerUrl = String(record.relayerUrl || '').trim();
    if (!thresholdSessionId || !relayerUrl) return;
    const exactTarget = targetThresholdIds.size === 0 || targetThresholdIds.has(thresholdSessionId);
    if (!exactTarget && targetThresholdIds.size > 0) return;
    const walletSessionJwt = String(walletSessionJwtInput || '').trim();
    if (!walletSessionJwt) return;
    candidates.push({
      kind: 'threshold_scoped',
      relayerUrl,
      thresholdSessionId,
      walletSessionJwt,
      ...(args.ecdsaLaneCheck
        ? {
            curve: 'ecdsa' as const,
            chainTarget: args.ecdsaLaneCheck.chainTarget,
            key: args.ecdsaLaneCheck.key,
          }
        : {}),
      exactTarget,
    });
  };
  if (args.ecdsaLaneCheck) {
    if (targetThresholdIds.size !== 1) return null;
    for (const targetThresholdSessionId of targetThresholdIds) {
      const record = getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
        thresholdSessionId: targetThresholdSessionId,
        chainTarget: args.ecdsaLaneCheck.chainTarget,
      });
      if (record && ecdsaRecordMatchesBudgetLane(record, args.ecdsaLaneCheck)) {
        pushCandidate(record, walletSessionJwtFromTrustedEcdsaBudgetRecord(record));
      }
    }
    return candidates.find((candidate) => candidate.exactTarget) || null;
  }
  for (const targetThresholdSessionId of targetThresholdIds) {
    const ed25519Record =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(targetThresholdSessionId);
    pushCandidate(ed25519Record, walletSessionJwtFromPersistedEd25519Record(ed25519Record));
    const ecdsaRecord =
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(targetThresholdSessionId);
    pushCandidate(ecdsaRecord, walletSessionJwtFromTrustedEcdsaBudgetRecord(ecdsaRecord));
  }
  if (owner.curve === 'ed25519') {
    const ed25519Record = getStoredThresholdEd25519SessionRecordForAccount(owner.accountId);
    pushCandidate(ed25519Record, walletSessionJwtFromPersistedEd25519Record(ed25519Record));
  }
  return candidates.find((candidate) => candidate.exactTarget) || candidates[0] || null;
}

function ecdsaRecordMatchesBudgetLane(
  record: ThresholdEcdsaSessionRecord,
  lane: EcdsaLaneBudgetStatusCheck | AuthenticatedEcdsaLaneBudgetStatusCheck,
): boolean {
  return (
    String(record.walletId) === String(lane.key.walletId) &&
    String(record.walletSigningSessionId) === String(lane.walletSigningSessionId) &&
    String(record.thresholdSessionId) === String(lane.thresholdSessionId) &&
    record.keyHandle === lane.keyHandle &&
    thresholdEcdsaChainTargetsEqual(record.chainTarget, lane.chainTarget)
  );
}

export function mergeWalletSigningBudgetStatus<TStatus extends SigningSessionStatus>(
  status: TStatus,
  budgetStatus: SigningSessionStatus | null,
): TStatus {
  if (!budgetStatus) return status;
  if (budgetStatus.status === 'budget_unknown') return status;
  if (budgetStatus.status !== 'active') {
    return {
      ...status,
      ...budgetStatus,
      sessionId: status.sessionId,
    };
  }
  const budgetRemainingUses = Math.max(0, Math.floor(Number(budgetStatus.remainingUses) || 0));
  const statusExpiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
  const budgetExpiresAtMs = Math.floor(Number(budgetStatus.expiresAtMs) || 0);
  return {
    ...status,
    status: 'active',
    remainingUses: budgetRemainingUses,
    expiresAtMs:
      statusExpiresAtMs > 0 && budgetExpiresAtMs > 0
        ? Math.min(statusExpiresAtMs, budgetExpiresAtMs)
        : statusExpiresAtMs || budgetExpiresAtMs,
    ...(budgetStatus.authMethod ? { authMethod: budgetStatus.authMethod } : {}),
    ...(budgetStatus.retention ? { retention: budgetStatus.retention } : {}),
  };
}

export function buildWalletBudgetStatusCheckForSession(args: {
  owner: WalletBudgetOwner;
  walletSigningSessionId: string;
}): SigningSessionBudgetStatusCheck | null {
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return null;
  return buildWalletBudgetStatusCheck({
    owner: args.owner,
    walletSigningSessionId,
  });
}
