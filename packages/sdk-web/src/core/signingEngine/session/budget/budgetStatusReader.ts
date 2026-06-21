import type { SigningSessionStatus } from '@/core/types/seams';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
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
  walletBudgetOwnerId,
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

type NonEmptyReadonlyArray<TValue> = readonly [TValue, ...TValue[]];

type BudgetStatusAuthRequest =
  | {
      kind: 'use_provided_auth';
      auth: ThresholdScopedBudgetStatusAuth;
    }
  | {
      kind: 'derive_from_record';
      owner: WalletBudgetOwner;
      signingGrantId: string;
      targetThresholdSessionIds: NonEmptyReadonlyArray<string>;
      ecdsaLaneCheck?: EcdsaLaneBudgetStatusCheck | AuthenticatedEcdsaLaneBudgetStatusCheck;
    }
  | {
      kind: 'no_auth_available';
      reason: 'missing_auth' | 'missing_record' | 'binding_mismatch';
    };

type BudgetStatusAuthResolution =
  | {
      kind: 'provided_auth';
      auth: ThresholdScopedBudgetStatusAuth;
    }
  | {
      kind: 'record_derived_auth';
      auth: ThresholdScopedBudgetStatusAuth;
    }
  | {
      kind: 'unavailable';
      reason: 'missing_auth' | 'missing_record' | 'binding_mismatch';
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
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  return await deps
    .getAvailableStatus({ ...args, signingGrantId })
    .catch(() => null);
}

export async function readTrustedWalletSigningBudgetStatus(
  deps: TrustedWalletSigningBudgetStatusDeps,
  args: SigningSessionBudgetStatusCheck,
): Promise<SigningSessionStatus | null> {
  assertBudgetStatusCheckHasConcreteLaneIdentity(args);
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  const authResolution = resolveBudgetStatusAuthForRequest(
    deps,
    buildBudgetStatusAuthRequest(args, signingGrantId),
  );
  if (authResolution.kind === 'unavailable') return null;

  const initial = await fetchTrustedWalletSigningBudgetStatus({
    auth: authResolution.auth,
    signingGrantId,
  });
  return initial.status;
}

function buildBudgetStatusAuthRequest(
  args: SigningSessionBudgetStatusCheck,
  signingGrantId: string,
): BudgetStatusAuthRequest {
  const ecdsaLaneCheck = isEcdsaLaneBudgetStatusCheck(args) ? args : undefined;
  if (
    args.kind === 'authenticated_threshold_budget_status_check' ||
    args.kind === 'authenticated_ecdsa_lane_budget_status_check'
  ) {
    const auth = normalizeBudgetStatusAuth(args.trustedStatusAuth, ecdsaLaneCheck);
    return auth
      ? { kind: 'use_provided_auth', auth }
      : { kind: 'no_auth_available', reason: 'missing_auth' };
  }
  const targetThresholdSessionIds = nonEmptyThresholdSessionIdsForBudgetStatusCheck(args);
  if (!targetThresholdSessionIds) {
    return { kind: 'no_auth_available', reason: 'binding_mismatch' };
  }
  return {
    kind: 'derive_from_record',
    owner: ownerForBudgetStatusCheck(args),
    signingGrantId,
    targetThresholdSessionIds,
    ...(ecdsaLaneCheck ? { ecdsaLaneCheck } : {}),
  };
}

function nonEmptyThresholdSessionIdsForBudgetStatusCheck(
  args: SigningSessionBudgetStatusCheck,
): NonEmptyReadonlyArray<string> | null {
  const normalized = thresholdSessionIdsForBudgetStatusCheck(args)
    .map((value) => String(value || '').trim())
    .filter(Boolean);
  return buildNonEmptyReadonlyArray(normalized);
}

function buildNonEmptyReadonlyArray(values: string[]): NonEmptyReadonlyArray<string> | null {
  const [first, ...rest] = values;
  return first ? [first, ...rest] : null;
}

function parseSafeInteger(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function parsePositiveSafeInteger(value: unknown): number | null {
  const parsed = parseSafeInteger(value);
  return parsed !== null && parsed > 0 ? parsed : null;
}

function parseNonNegativeSafeInteger(value: unknown): number | null {
  const parsed = parseSafeInteger(value);
  return parsed !== null && parsed >= 0 ? parsed : null;
}

function resolveBudgetStatusAuthForRequest(
  deps: TrustedWalletSigningBudgetStatusDeps,
  request: BudgetStatusAuthRequest,
): BudgetStatusAuthResolution {
  switch (request.kind) {
    case 'use_provided_auth':
      return { kind: 'provided_auth', auth: request.auth };
    case 'derive_from_record': {
      const auth = resolveWalletSigningBudgetStatusAuth(deps, request);
      return auth
        ? { kind: 'record_derived_auth', auth }
        : { kind: 'unavailable', reason: 'missing_record' };
    }
    case 'no_auth_available':
      return { kind: 'unavailable', reason: request.reason };
  }
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

function parseTrustedBudgetStatusPayload(args: {
  body: unknown;
  signingGrantId: string;
  auth: TrustedBudgetStatusAuth;
}): TrustedBudgetStatusPayload | null {
  const record = (args.body || {}) as Record<string, unknown>;
  if (record.ok !== true) return null;
  const signingGrantId = String(record.signingGrantId || '').trim();
  if (signingGrantId !== args.signingGrantId) return null;
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
          signingGrantId,
          reason: 'status_unavailable',
        }) as SigningSessionStatus & { status: 'budget_unknown' },
      };
    }
    return {
      kind: 'not_found',
      status: {
        sessionId: signingGrantId,
        status: 'not_found',
        ...(statusCode ? { statusCode } : {}),
      },
    };
  }

  if (status !== 'active' && status !== 'exhausted' && status !== 'expired') {
    return null;
  }

  const expiresAtMs = parsePositiveSafeInteger(record.expiresAtMs);
  if (expiresAtMs === null) return null;

  if (status === 'expired') {
    return {
      kind: 'current',
      status: {
        sessionId: signingGrantId,
        status,
        expiresAtMs,
      },
    };
  }

  const remainingUses = parseNonNegativeSafeInteger(record.remainingUses);
  if (remainingUses === null) return null;
  const committedRemainingUses = parseNonNegativeSafeInteger(
    record.committedRemainingUses ?? record.remainingUses,
  );
  const inFlightReservedUses = parseNonNegativeSafeInteger(
    record.reservedUses ?? record.inFlightReservedUses ?? 0,
  );
  const availableUses = parseNonNegativeSafeInteger(record.availableUses ?? record.remainingUses);
  if (
    committedRemainingUses === null ||
    inFlightReservedUses === null ||
    availableUses === null
  ) {
    return null;
  }
  const projectionVersion = String(record.projectionVersion || '').trim();
  if (!projectionVersion) return null;
  return {
    kind: 'current',
    status: {
      sessionId: signingGrantId,
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
  signingGrantId: string;
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
  signingGrantId: string;
}): string {
  return [
    args.auth.kind,
    args.auth.relayerUrl,
    args.auth.thresholdSessionId,
    args.auth.walletSessionJwt,
    args.signingGrantId,
  ].join('\x1f');
}

async function fetchTrustedWalletSigningBudgetStatusOnce(args: {
  auth: TrustedBudgetStatusAuth;
  signingGrantId: string;
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
        signingGrantId: args.signingGrantId,
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
          signingGrantId: args.signingGrantId,
          reason: 'status_unavailable',
        }),
        authRejected: true,
      };
    }
    if (response.status === 404) {
      return {
        status: {
          sessionId: args.signingGrantId,
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
    signingGrantId: args.signingGrantId,
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
    signingGrantId: string;
    targetThresholdSessionIds: NonEmptyReadonlyArray<string>;
    ecdsaLaneCheck?: EcdsaLaneBudgetStatusCheck | AuthenticatedEcdsaLaneBudgetStatusCheck;
  },
): TrustedBudgetStatusAuth | null {
  const ownerWalletId = String(walletBudgetOwnerId(args.owner)).trim();
  if (!ownerWalletId) return null;
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  const targetThresholdIds = new Set(
    args.targetThresholdSessionIds.map((value) => String(value || '').trim()).filter(Boolean),
  );
  if (targetThresholdIds.size === 0) return null;
  const candidates: Array<ThresholdScopedBudgetStatusAuth & { exactTarget: boolean }> = [];
  const pushCandidate = (
    record:
      | {
          walletId?: unknown;
          nearAccountId?: unknown;
          relayerUrl?: unknown;
          thresholdSessionId?: unknown;
          signingGrantId?: unknown;
        }
      | null
      | undefined,
    walletSessionJwtInput: unknown,
  ): void => {
    if (!record) return;
    if (walletIdFromBudgetAuthRecord(record) !== ownerWalletId) return;
    if (String(record.signingGrantId || '').trim() !== signingGrantId) return;
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    const relayerUrl = String(record.relayerUrl || '').trim();
    if (!thresholdSessionId || !relayerUrl) return;
    const exactTarget = targetThresholdIds.has(thresholdSessionId);
    if (!exactTarget) return;
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
  return candidates.find((candidate) => candidate.exactTarget) || null;
}

function walletIdFromBudgetAuthRecord(record: {
  walletId?: unknown;
  nearAccountId?: unknown;
}): string {
  return String(record.walletId ?? record.nearAccountId ?? '').trim();
}

function ecdsaRecordMatchesBudgetLane(
  record: ThresholdEcdsaSessionRecord,
  lane: EcdsaLaneBudgetStatusCheck | AuthenticatedEcdsaLaneBudgetStatusCheck,
): boolean {
  return (
    String(record.walletId) === String(lane.key.walletId) &&
    String(record.signingGrantId) === String(lane.signingGrantId) &&
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
  signingGrantId: string;
}): SigningSessionBudgetStatusCheck | null {
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  return buildWalletBudgetStatusCheck({
    owner: args.owner,
    signingGrantId,
  });
}
