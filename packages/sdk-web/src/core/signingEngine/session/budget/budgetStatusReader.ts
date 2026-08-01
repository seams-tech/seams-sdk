import type { SigningSessionStatus } from '@/core/types/seams';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  buildWalletBudgetStatusCheck,
  walletBudgetOwnerId,
  type SigningSessionBudgetStatusAuth,
  type SigningSessionBudgetStatusCheck,
  type WalletBudgetOwner,
} from './budget';

export function budgetUnknownSigningSessionStatus(args: {
  signingGrantId: string;
  reason: string;
}): SigningSessionStatus & { status: 'budget_unknown' } {
  return {
    sessionId: args.signingGrantId,
    status: 'budget_unknown',
    statusCode: args.reason,
  };
}

export type WalletSigningBudgetAvailableStatusDeps = {
  getAvailableStatus: (
    args: SigningSessionBudgetStatusCheck,
  ) => Promise<SigningSessionStatus | null>;
};

export type TrustedWalletSigningBudgetStatusDeps = Record<never, never>;

type ThresholdScopedBudgetStatusAuth = {
  kind: 'threshold_scoped';
  relayerUrl: string;
  thresholdSessionId: string;
  walletSessionJwt: string;
};

type TrustedBudgetStatusAuth = ThresholdScopedBudgetStatusAuth;

type TrustedBudgetStatusFetchResult = {
  status: SigningSessionStatus | null;
  authRejected: boolean;
};

type BudgetStatusAuthRequest =
  | {
      kind: 'use_provided_auth';
      auth: ThresholdScopedBudgetStatusAuth;
    }
  | {
      kind: 'no_auth_available';
      reason: 'missing_auth' | 'binding_mismatch';
    };

type BudgetStatusAuthResolution =
  | {
      kind: 'provided_auth';
      auth: ThresholdScopedBudgetStatusAuth;
    }
  | {
      kind: 'unavailable';
      reason: 'missing_auth' | 'binding_mismatch';
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
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  return await deps.getAvailableStatus({ ...args, signingGrantId }).catch(() => null);
}

export async function readTrustedWalletSigningBudgetStatus(
  _deps: TrustedWalletSigningBudgetStatusDeps,
  args: SigningSessionBudgetStatusCheck,
): Promise<SigningSessionStatus | null> {
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  const authResolution = resolveBudgetStatusAuthForRequest(
    _deps,
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
  if (args.kind === 'authenticated_threshold_budget_status_check') {
    const auth = normalizeBudgetStatusAuth(args.trustedStatusAuth);
    return auth
      ? { kind: 'use_provided_auth', auth }
      : { kind: 'no_auth_available', reason: 'missing_auth' };
  }
  return { kind: 'no_auth_available', reason: 'missing_auth' };
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
  _deps: TrustedWalletSigningBudgetStatusDeps,
  request: BudgetStatusAuthRequest,
): BudgetStatusAuthResolution {
  switch (request.kind) {
    case 'use_provided_auth':
      return { kind: 'provided_auth', auth: request.auth };
    case 'no_auth_available':
      return { kind: 'unavailable', reason: request.reason };
  }
}

function normalizeBudgetStatusAuth(
  trustedStatusAuth: SigningSessionBudgetStatusAuth | undefined,
): ThresholdScopedBudgetStatusAuth | null {
  const relayerUrl = String(trustedStatusAuth?.relayerUrl || '').trim();
  const thresholdSessionId = String(trustedStatusAuth?.thresholdSessionId || '').trim();
  if (!relayerUrl || !thresholdSessionId) return null;
  const walletSessionJwt = String(trustedStatusAuth?.walletSessionJwt || '').trim();
  if (!walletSessionJwt) return null;
  return {
    kind: 'threshold_scoped',
    relayerUrl,
    thresholdSessionId,
    walletSessionJwt,
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
  if (committedRemainingUses === null || inFlightReservedUses === null || availableUses === null) {
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
    joinNormalizedUrl(args.auth.relayerUrl, '/router-ab/wallet-budget/status'),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${args.auth.walletSessionJwt}`,
      },
      credentials: 'omit',
      body: '{}',
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
