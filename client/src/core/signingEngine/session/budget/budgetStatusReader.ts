import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  getThresholdEcdsaSessionRecordByThresholdSessionId,
  listThresholdEcdsaRuntimeLanesForSubject,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import { toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionBudgetStatusAuth } from './budget';

export type WalletSigningBudgetAvailableStatusDeps = {
  getAvailableStatus: (args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId: string;
    targetThresholdSessionIds?: string[];
    targetBackingMaterialSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  }) => Promise<SigningSessionStatus | null>;
};

export type TrustedWalletSigningBudgetStatusDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
};

type BudgetStatusAuth = {
  relayerUrl: string;
  thresholdSessionId?: string;
  thresholdSessionAuthToken?: string;
};

type TrustedBudgetStatusFetchResult = {
  status: SigningSessionStatus | null;
  authRejected: boolean;
};

export async function getWalletSigningBudgetAvailableStatus(
  deps: WalletSigningBudgetAvailableStatusDeps,
  args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetThresholdSessionIds?: string[];
    targetBackingMaterialSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  },
): Promise<SigningSessionStatus | null> {
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return null;
  return await deps
    .getAvailableStatus({
      nearAccountId: args.nearAccountId,
      walletSigningSessionId,
      targetThresholdSessionIds: args.targetThresholdSessionIds,
      targetBackingMaterialSessionIds: args.targetBackingMaterialSessionIds,
      trustedStatusAuth: args.trustedStatusAuth,
    })
    .catch(() => null);
}

export async function readTrustedWalletSigningBudgetStatus(
  deps: TrustedWalletSigningBudgetStatusDeps,
  args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetThresholdSessionIds?: string[];
    trustedStatusAuth?: SigningSessionBudgetStatusAuth;
  },
): Promise<SigningSessionStatus | null> {
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return null;
  const providedAuth = normalizeBudgetStatusAuth(args.trustedStatusAuth);
  const resolvedAuth =
    providedAuth ||
    resolveWalletSigningBudgetStatusAuth(deps, {
      nearAccountId: args.nearAccountId,
      walletSigningSessionId,
      targetThresholdSessionIds: args.targetThresholdSessionIds,
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
    nearAccountId: args.nearAccountId,
    walletSigningSessionId,
    targetThresholdSessionIds: args.targetThresholdSessionIds,
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
): BudgetStatusAuth | null {
  const relayerUrl = String(trustedStatusAuth?.relayerUrl || '').trim();
  const thresholdSessionId = String(trustedStatusAuth?.thresholdSessionId || '').trim();
  if (!relayerUrl || !thresholdSessionId) return null;
  const thresholdSessionAuthToken = String(
    trustedStatusAuth?.thresholdSessionAuthToken || '',
  ).trim();
  return {
    relayerUrl,
    thresholdSessionId,
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
  };
}

function sameBudgetStatusAuth(left: BudgetStatusAuth, right: BudgetStatusAuth): boolean {
  return (
    left.relayerUrl === right.relayerUrl &&
    String(left.thresholdSessionId || '') === String(right.thresholdSessionId || '') &&
    String(left.thresholdSessionAuthToken || '') === String(right.thresholdSessionAuthToken || '')
  );
}

async function fetchTrustedWalletSigningBudgetStatus(args: {
  auth: BudgetStatusAuth;
  walletSigningSessionId: string;
}): Promise<TrustedBudgetStatusFetchResult> {
  const response = await fetch(
    joinNormalizedUrl(args.auth.relayerUrl, '/session/signing-budget/status'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(args.auth.thresholdSessionAuthToken
          ? { Authorization: `Bearer ${args.auth.thresholdSessionAuthToken}` }
          : {}),
      },
      credentials: args.auth.thresholdSessionAuthToken ? 'omit' : 'include',
      body: JSON.stringify({
        walletSigningSessionId: args.walletSigningSessionId,
        ...(args.auth.thresholdSessionId
          ? { thresholdSessionId: args.auth.thresholdSessionId }
          : {}),
      }),
    },
  );
  const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok || !json || json.ok === false) {
    if (response.status === 401 || response.status === 403 || response.status === 404) {
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
  const status = String(json.status || '').trim();
  if (status === 'not_found') {
    return {
      status: {
        sessionId: args.walletSigningSessionId,
        status,
        ...(typeof json.statusCode === 'string' ? { statusCode: json.statusCode } : {}),
      },
      authRejected: false,
    };
  }
  if (status !== 'active' && status !== 'exhausted' && status !== 'expired') {
    return { status: null, authRejected: false };
  }
  const remainingUses = Math.max(0, Math.floor(Number(json.remainingUses) || 0));
  const expiresAtMs = Math.floor(Number(json.expiresAtMs) || 0);
  const projectionVersion = String(json.projectionVersion || '').trim();
  return {
    status: {
      sessionId: args.walletSigningSessionId,
      status,
      ...(status === 'active' || status === 'exhausted' ? { remainingUses } : {}),
      ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
      ...(projectionVersion ? { projectionVersion } : {}),
    },
    authRejected: false,
  };
}

function resolveWalletSigningBudgetStatusAuth(
  deps: TrustedWalletSigningBudgetStatusDeps,
  args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId: string;
    targetThresholdSessionIds?: string[];
  },
): BudgetStatusAuth | null {
  const accountId = toAccountId(args.nearAccountId);
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!accountId || !walletSigningSessionId) return null;
  const targetThresholdIds = new Set(
    (args.targetThresholdSessionIds || [])
      .map((value) => String(value || '').trim())
      .filter(Boolean),
  );
  const candidates: Array<BudgetStatusAuth & { thresholdSessionId: string; exactTarget: boolean }> =
    [];
  const pushCandidate = (
    record:
      | {
          relayerUrl?: string;
          thresholdSessionId?: string;
          thresholdSessionAuthToken?: string;
          walletSigningSessionId?: string;
          thresholdSessionKind?: string;
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
      relayerUrl,
      thresholdSessionId,
      ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
      exactTarget,
    });
  };
  for (const targetThresholdSessionId of targetThresholdIds) {
    pushCandidate(
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(targetThresholdSessionId),
    );
    pushCandidate(
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(targetThresholdSessionId),
    );
  }
  pushCandidate(getStoredThresholdEd25519SessionRecordForAccount(accountId));
  for (const runtimeLane of listThresholdEcdsaRuntimeLanesForSubject(deps.ecdsaSessions, {
    subjectId: toWalletSubjectId(accountId),
  })) {
    pushCandidate(
      getThresholdEcdsaSessionRecordByThresholdSessionId(
        deps.ecdsaSessions,
        runtimeLane.thresholdSessionId,
      ),
    );
  }
  return (
    candidates.find((candidate) => candidate.exactTarget && candidate.thresholdSessionAuthToken) ||
    candidates.find((candidate) => candidate.exactTarget) ||
    candidates.find((candidate) => candidate.thresholdSessionAuthToken) ||
    candidates[0] ||
    null
  );
}

export function mergeWalletSigningBudgetStatus<TStatus extends SigningSessionStatus>(
  status: TStatus,
  budgetStatus: SigningSessionStatus | null,
): TStatus {
  if (!budgetStatus) return status;
  if (budgetStatus.status === 'not_found') return status;
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
