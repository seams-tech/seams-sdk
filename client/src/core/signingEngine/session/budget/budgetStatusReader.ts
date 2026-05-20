import type { SigningSessionStatus } from '@/core/types/seams';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEcdsaSessionStoreDeps,
  type ThresholdEcdsaSessionRecord,
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

export type WalletSigningBudgetAvailableStatusDeps = {
  getAvailableStatus: (
    args: SigningSessionBudgetStatusCheck,
  ) => Promise<SigningSessionStatus | null>;
};

export type TrustedWalletSigningBudgetStatusDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
};

type BudgetStatusAuth = {
  kind: 'wallet_scoped';
  relayerUrl: string;
};

type ThresholdScopedBudgetStatusAuth = {
  kind: 'threshold_scoped';
  relayerUrl: string;
  thresholdSessionId: string;
  thresholdSessionAuthToken?: string;
  curve?: 'ecdsa' | 'ed25519';
  chainTarget?: ThresholdEcdsaChainTarget;
  key?: EvmFamilyEcdsaKeyIdentity;
};

type TrustedBudgetStatusAuth = BudgetStatusAuth | ThresholdScopedBudgetStatusAuth;

type TrustedBudgetStatusFetchResult = {
  status: SigningSessionStatus | null;
  authRejected: boolean;
};

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
  const thresholdSessionAuthToken = String(
    trustedStatusAuth?.thresholdSessionAuthToken || '',
  ).trim();
  return {
    kind: 'threshold_scoped',
    relayerUrl,
    thresholdSessionId,
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
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
    (left.kind === 'threshold_scoped' && right.kind === 'threshold_scoped'
      ? left.thresholdSessionId === right.thresholdSessionId &&
        String(left.thresholdSessionAuthToken || '') === String(right.thresholdSessionAuthToken || '')
      : true)
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
  if (args.auth.kind === 'threshold_scoped' && args.auth.thresholdSessionId !== thresholdSessionId) {
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
  const projectionVersion = String(record.projectionVersion || '').trim();
  if (!projectionVersion) return null;
  return {
    kind: 'current',
    status: {
      sessionId: walletSigningSessionId,
      status,
      remainingUses,
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
  if (args.auth.kind === 'threshold_scoped') {
    return [
      args.auth.kind,
      args.auth.relayerUrl,
      args.auth.thresholdSessionId,
      args.auth.thresholdSessionAuthToken || '',
      args.walletSigningSessionId,
    ].join('\x1f');
  }
  return [args.auth.kind, args.auth.relayerUrl, args.walletSigningSessionId].join('\x1f');
}

async function fetchTrustedWalletSigningBudgetStatusOnce(args: {
  auth: TrustedBudgetStatusAuth;
  walletSigningSessionId: string;
}): Promise<TrustedBudgetStatusFetchResult> {
  const thresholdSessionAuthToken =
    args.auth.kind === 'threshold_scoped' ? args.auth.thresholdSessionAuthToken : undefined;
  const response = await fetch(
    joinNormalizedUrl(args.auth.relayerUrl, '/session/signing-budget/status'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(thresholdSessionAuthToken ? { Authorization: `Bearer ${thresholdSessionAuthToken}` } : {}),
      },
      credentials: thresholdSessionAuthToken ? 'omit' : 'include',
      body: JSON.stringify({
        walletSigningSessionId: args.walletSigningSessionId,
        ...(args.auth.kind === 'threshold_scoped'
          ? {
              thresholdSessionId: args.auth.thresholdSessionId,
              ...(args.auth.curve ? { curve: args.auth.curve } : {}),
              ...(args.auth.chainTarget ? { chainTarget: args.auth.chainTarget } : {}),
            }
          : {}),
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
  const candidates: Array<ThresholdScopedBudgetStatusAuth & { exactTarget: boolean }> =
    [];
  const pushCandidate = (
    record:
      | {
          relayerUrl?: unknown;
          thresholdSessionId?: unknown;
          thresholdSessionAuthToken?: unknown;
          walletSigningSessionId?: unknown;
          thresholdSessionKind?: unknown;
        }
      | null
      | undefined,
  ): void => {
    if (!record) return;
    if (String(record.walletSigningSessionId || '').trim() !== walletSigningSessionId) return;
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    const relayerUrl = String(record.relayerUrl || '').trim();
    if (!thresholdSessionId || !relayerUrl) return;
    const exactTarget = targetThresholdIds.size === 0 || targetThresholdIds.has(thresholdSessionId);
    if (!exactTarget && targetThresholdIds.size > 0) return;
    const thresholdSessionAuthToken = String(record.thresholdSessionAuthToken || '').trim();
    if (!thresholdSessionAuthToken && record.thresholdSessionKind !== 'cookie') return;
    candidates.push({
      kind: 'threshold_scoped',
      relayerUrl,
      thresholdSessionId,
      ...(args.ecdsaLaneCheck
        ? {
            curve: 'ecdsa' as const,
            chainTarget: args.ecdsaLaneCheck.chainTarget,
            key: args.ecdsaLaneCheck.key,
          }
        : {}),
      ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
      exactTarget,
    });
  };
  if (args.ecdsaLaneCheck) {
    if (targetThresholdIds.size !== 1) return null;
    for (const targetThresholdSessionId of targetThresholdIds) {
      const record = getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
        targetThresholdSessionId,
      );
      if (record && ecdsaRecordMatchesBudgetLane(record, args.ecdsaLaneCheck)) {
        pushCandidate(record);
      }
    }
    return (
      candidates.find((candidate) => candidate.exactTarget && candidate.thresholdSessionAuthToken) ||
      candidates.find((candidate) => candidate.exactTarget) ||
      null
    );
  }
  for (const targetThresholdSessionId of targetThresholdIds) {
    pushCandidate(
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(targetThresholdSessionId),
    );
    pushCandidate(
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(targetThresholdSessionId),
    );
  }
  if (owner.curve === 'ed25519') {
    pushCandidate(getStoredThresholdEd25519SessionRecordForAccount(owner.accountId));
  }
  return (
    candidates.find((candidate) => candidate.exactTarget && candidate.thresholdSessionAuthToken) ||
    candidates.find((candidate) => candidate.exactTarget) ||
    candidates.find((candidate) => candidate.thresholdSessionAuthToken) ||
    candidates[0] ||
    null
  );
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
