import type { SigningSessionStatus } from '@/core/types/seams';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  BackingMaterialSessionId,
  SelectedEd25519SigningSessionPlanningLane,
  SigningGrantId,
  ThresholdSessionId,
} from '../operationState/types';

export type Ed25519WalletSessionStatusOwner = {
  curve: 'ed25519';
  walletId: WalletId;
  accountId?: never;
};

export type WalletSessionStatusOwner = Ed25519WalletSessionStatusOwner;

export type WalletSessionStatusCheck = {
  kind: 'wallet_session_status_check';
  owner: WalletSessionStatusOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds?: never;
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type BackingMaterialSessionStatusCheck = {
  kind: 'backing_material_session_status_check';
  owner: WalletSessionStatusOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds: readonly [
    BackingMaterialSessionId | string,
    ...(BackingMaterialSessionId | string)[],
  ];
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type ThresholdSessionStatusCheck = {
  kind: 'threshold_session_status_check';
  owner: WalletSessionStatusOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly [
    ThresholdSessionId | string,
    ...(ThresholdSessionId | string)[],
  ];
  targetBackingMaterialSessionIds?: never;
  trustedStatusAuth?: never;
};

export type WalletSessionStatusAuth = {
  relayerUrl: string;
  thresholdSessionId: string;
  walletSessionJwt: string;
};

export type AuthenticatedThresholdSessionStatusCheck = {
  kind: 'authenticated_threshold_session_status_check';
  owner: WalletSessionStatusOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly [
    ThresholdSessionId | string,
    ...(ThresholdSessionId | string)[],
  ];
  trustedStatusAuth: WalletSessionStatusAuth;
  targetBackingMaterialSessionIds?: never;
};

export type SigningSessionStatusCheck =
  | WalletSessionStatusCheck
  | BackingMaterialSessionStatusCheck
  | ThresholdSessionStatusCheck
  | AuthenticatedThresholdSessionStatusCheck;

export type SigningSessionStatusReader = (
  args: SigningSessionStatusCheck,
) => Promise<SigningSessionStatus | null>;

export type WalletSigningSessionStatusDeps = {
  getAvailableStatus: (
    args: SigningSessionStatusCheck,
  ) => Promise<SigningSessionStatus | null>;
};

export type TrustedWalletSessionStatusDeps = Record<never, never>;

export function normalizeSessionStatusRequired(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[WalletSessionStatus] ${label} is required`);
  }
  return normalized;
}

function normalizeStatusStringList(values: readonly string[] | undefined): string[] | undefined {
  const normalized = (values || []).map((value) => String(value || '').trim()).filter(Boolean);
  return normalized.length ? normalized : undefined;
}

export function buildWalletSessionStatusCheck(args: {
  owner: WalletSessionStatusOwner;
  signingGrantId: SigningGrantId | string;
}): WalletSessionStatusCheck {
  return {
    kind: 'wallet_session_status_check',
    owner: args.owner,
    signingGrantId: normalizeSessionStatusRequired(args.signingGrantId, 'signingGrantId') as SigningGrantId,
  };
}

export function buildBackingMaterialSessionStatusCheck(args: {
  owner: WalletSessionStatusOwner;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds: readonly (BackingMaterialSessionId | string)[];
}): BackingMaterialSessionStatusCheck {
  const targetBackingMaterialSessionIds = normalizeStatusStringList(
    args.targetBackingMaterialSessionIds,
  ) as BackingMaterialSessionId[] | undefined;
  if (!targetBackingMaterialSessionIds?.length) {
    throw new Error('[WalletSessionStatus] targetBackingMaterialSessionIds are required');
  }
  return {
    kind: 'backing_material_session_status_check',
    owner: args.owner,
    signingGrantId: normalizeSessionStatusRequired(args.signingGrantId, 'signingGrantId') as SigningGrantId,
    targetBackingMaterialSessionIds: [
      targetBackingMaterialSessionIds[0],
      ...targetBackingMaterialSessionIds.slice(1),
    ],
  };
}

export function buildThresholdSessionStatusCheck(args: {
  owner: WalletSessionStatusOwner;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
}): ThresholdSessionStatusCheck {
  const targetThresholdSessionIds = normalizeStatusStringList(args.targetThresholdSessionIds) as
    | ThresholdSessionId[]
    | undefined;
  if (!targetThresholdSessionIds?.length) {
    throw new Error('[WalletSessionStatus] targetThresholdSessionIds are required');
  }
  return {
    kind: 'threshold_session_status_check',
    owner: args.owner,
    signingGrantId: normalizeSessionStatusRequired(args.signingGrantId, 'signingGrantId') as SigningGrantId,
    targetThresholdSessionIds: [
      targetThresholdSessionIds[0],
      ...targetThresholdSessionIds.slice(1),
    ],
  };
}

export function buildAuthenticatedThresholdSessionStatusCheck(args: {
  owner: WalletSessionStatusOwner;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
  trustedStatusAuth: WalletSessionStatusAuth;
}): AuthenticatedThresholdSessionStatusCheck {
  const thresholdCheck = buildThresholdSessionStatusCheck(args);
  return {
    kind: 'authenticated_threshold_session_status_check',
    owner: thresholdCheck.owner,
    signingGrantId: thresholdCheck.signingGrantId,
    targetThresholdSessionIds: thresholdCheck.targetThresholdSessionIds,
    trustedStatusAuth: args.trustedStatusAuth,
  };
}

export function ed25519WalletSessionStatusOwner(
  walletId: WalletId | string,
): Ed25519WalletSessionStatusOwner {
  return { curve: 'ed25519', walletId: toWalletId(walletId) };
}

export function walletSessionStatusOwnerForLane(
  lane: SelectedEd25519SigningSessionPlanningLane,
): WalletSessionStatusOwner {
  return ed25519WalletSessionStatusOwner(lane.identity.signer.account.wallet.walletId);
}

export function walletSessionStatusOwnerId(owner: WalletSessionStatusOwner): WalletId {
  return owner.walletId;
}

export function walletSessionStatusOwnerKey(owner: WalletSessionStatusOwner): string {
  return `${owner.curve}:${walletSessionStatusOwnerId(owner)}`;
}

export function thresholdSessionIdsForSessionStatusCheck(
  args: SigningSessionStatusCheck,
): string[] {
  return args.kind === 'threshold_session_status_check' ||
    args.kind === 'authenticated_threshold_session_status_check'
    ? [...args.targetThresholdSessionIds].map((value) =>
        normalizeSessionStatusRequired(value, 'thresholdSessionId'),
      )
    : [];
}

export function unknownSigningSessionStatus(args: {
  signingGrantId: string;
  reason: string;
}): SigningSessionStatus & { status: 'status_unknown' } {
  return {
    sessionId: args.signingGrantId,
    status: 'status_unknown',
    statusCode: args.reason,
  };
}

type ThresholdScopedSessionStatusAuth = {
  kind: 'threshold_scoped';
  relayerUrl: string;
  thresholdSessionId: string;
  walletSessionJwt: string;
};

type TrustedSessionStatusAuth = ThresholdScopedSessionStatusAuth;

type TrustedSessionStatusFetchResult = {
  status: SigningSessionStatus | null;
  authRejected: boolean;
};

type SessionStatusAuthRequest =
  | {
      kind: 'use_provided_auth';
      auth: ThresholdScopedSessionStatusAuth;
    }
  | {
      kind: 'no_auth_available';
      reason: 'missing_auth' | 'binding_mismatch';
    };

type SessionStatusAuthResolution =
  | {
      kind: 'provided_auth';
      auth: ThresholdScopedSessionStatusAuth;
    }
  | {
      kind: 'unavailable';
      reason: 'missing_auth' | 'binding_mismatch';
    };

const inFlightTrustedSessionStatusFetches = new Map<
  string,
  Promise<TrustedSessionStatusFetchResult>
>();

type TrustedSessionStatusPayload =
  | {
      kind: 'not_found';
      status: SigningSessionStatus & { status: 'not_found' };
    }
  | {
      kind: 'status_unknown';
      status: SigningSessionStatus & { status: 'status_unknown' };
    }
  | {
      kind: 'current';
      status: SigningSessionStatus & {
        status: 'active' | 'exhausted' | 'expired';
      };
    };

export async function getWalletSessionStatus(
  deps: WalletSigningSessionStatusDeps,
  args: SigningSessionStatusCheck,
): Promise<SigningSessionStatus | null> {
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  return await deps.getAvailableStatus({ ...args, signingGrantId }).catch(() => null);
}

export async function readTrustedWalletSigningSessionStatus(
  _deps: TrustedWalletSessionStatusDeps,
  args: SigningSessionStatusCheck,
): Promise<SigningSessionStatus | null> {
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  const authResolution = resolveSessionStatusAuthForRequest(
    _deps,
    buildSessionStatusAuthRequest(args, signingGrantId),
  );
  if (authResolution.kind === 'unavailable') return null;

  const initial = await fetchTrustedWalletSigningSessionStatus({
    auth: authResolution.auth,
    signingGrantId,
  });
  return initial.status;
}

function buildSessionStatusAuthRequest(
  args: SigningSessionStatusCheck,
  signingGrantId: string,
): SessionStatusAuthRequest {
  if (args.kind === 'authenticated_threshold_session_status_check') {
    const auth = normalizeSessionStatusAuth(args.trustedStatusAuth);
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

function resolveSessionStatusAuthForRequest(
  _deps: TrustedWalletSessionStatusDeps,
  request: SessionStatusAuthRequest,
): SessionStatusAuthResolution {
  switch (request.kind) {
    case 'use_provided_auth':
      return { kind: 'provided_auth', auth: request.auth };
    case 'no_auth_available':
      return { kind: 'unavailable', reason: request.reason };
  }
}

function normalizeSessionStatusAuth(
  trustedStatusAuth: WalletSessionStatusAuth | undefined,
): ThresholdScopedSessionStatusAuth | null {
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

function parseTrustedSessionStatusPayload(args: {
  body: unknown;
  signingGrantId: string;
  auth: TrustedSessionStatusAuth;
}): TrustedSessionStatusPayload | null {
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
        kind: 'status_unknown',
        status: unknownSigningSessionStatus({
          signingGrantId,
          reason: 'status_unavailable',
        }) as SigningSessionStatus & { status: 'status_unknown' },
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

async function fetchTrustedWalletSigningSessionStatus(args: {
  auth: TrustedSessionStatusAuth;
  signingGrantId: string;
}): Promise<TrustedSessionStatusFetchResult> {
  const key = trustedSessionStatusFetchKey(args);
  const inFlight = inFlightTrustedSessionStatusFetches.get(key);
  if (inFlight) return await inFlight;

  const fetchPromise = fetchTrustedWalletSigningSessionStatusOnce(args);
  inFlightTrustedSessionStatusFetches.set(key, fetchPromise);
  try {
    return await fetchPromise;
  } finally {
    if (inFlightTrustedSessionStatusFetches.get(key) === fetchPromise) {
      inFlightTrustedSessionStatusFetches.delete(key);
    }
  }
}

function trustedSessionStatusFetchKey(args: {
  auth: TrustedSessionStatusAuth;
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

async function fetchTrustedWalletSigningSessionStatusOnce(args: {
  auth: TrustedSessionStatusAuth;
  signingGrantId: string;
}): Promise<TrustedSessionStatusFetchResult> {
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
        status: unknownSigningSessionStatus({
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
  const parsed = parseTrustedSessionStatusPayload({
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

export function mergeWalletSigningSessionStatus<TStatus extends SigningSessionStatus>(
  status: TStatus,
  sessionStatus: SigningSessionStatus | null,
): TStatus {
  if (!sessionStatus) return status;
  if (sessionStatus.status === 'status_unknown') return status;
  if (sessionStatus.status !== 'active') {
    return {
      ...status,
      ...sessionStatus,
      sessionId: status.sessionId,
    };
  }
  const sessionRemainingUses = Math.max(0, Math.floor(Number(sessionStatus.remainingUses) || 0));
  const statusExpiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
  const sessionExpiresAtMs = Math.floor(Number(sessionStatus.expiresAtMs) || 0);
  return {
    ...status,
    status: 'active',
    remainingUses: sessionRemainingUses,
    expiresAtMs:
      statusExpiresAtMs > 0 && sessionExpiresAtMs > 0
        ? Math.min(statusExpiresAtMs, sessionExpiresAtMs)
        : statusExpiresAtMs || sessionExpiresAtMs,
    ...(sessionStatus.authMethod ? { authMethod: sessionStatus.authMethod } : {}),
    ...(sessionStatus.retention ? { retention: sessionStatus.retention } : {}),
  };
}

export function buildWalletSessionStatusCheckForSession(args: {
  owner: WalletSessionStatusOwner;
  signingGrantId: string;
}): SigningSessionStatusCheck | null {
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!signingGrantId) return null;
  return buildWalletSessionStatusCheck({
    owner: args.owner,
    signingGrantId,
  });
}
