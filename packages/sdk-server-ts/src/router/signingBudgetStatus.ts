import {
  parseRouterAbEcdsaHssWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  type RouterAbEcdsaHssWalletSessionClaims,
  type RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import { hashEmailOtpSigningSessionClaims } from './emailOtpSessionRouteHelpers';
import type {
  SigningSessionSealRouteHeaders,
  SigningSessionSealSessionAdapter,
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealWalletBudgetStatus,
} from '../threshold/session/signingSessionSeal/types';

type BaseVerifiedWalletSessionAuth = {
  kind: 'wallet_session';
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  expiresAtMs: number;
};

export type VerifiedEcdsaWalletSessionAuth = BaseVerifiedWalletSessionAuth & {
  curve: 'ecdsa';
  keyHandle: string;
  ed25519RelayerKeyId?: never;
};

export type VerifiedEd25519WalletSessionAuth = BaseVerifiedWalletSessionAuth & {
  curve: 'ed25519';
  ed25519RelayerKeyId: string;
  keyHandle?: never;
  ecdsaThresholdKeyId?: never;
};

export type VerifiedWalletSessionAuth =
  | VerifiedEcdsaWalletSessionAuth
  | VerifiedEd25519WalletSessionAuth;

export type EcdsaWalletSigningBudgetStatusRequest = {
  kind: 'ecdsa_wallet_budget_status';
  auth: VerifiedEcdsaWalletSessionAuth;
  thresholdSessionId: string;
  walletSigningSessionId: string;

  // Curve-specific fields.
  keyHandle: string;
  ed25519RelayerKeyId?: never;
};

export type Ed25519WalletSigningBudgetStatusRequest = {
  kind: 'ed25519_wallet_budget_status';
  auth: VerifiedEd25519WalletSessionAuth;
  thresholdSessionId: string;
  walletSigningSessionId: string;

  // Curve-specific fields.
  ed25519RelayerKeyId: string;
  keyHandle?: never;
};

export type WalletSigningBudgetStatusRequest =
  | EcdsaWalletSigningBudgetStatusRequest
  | Ed25519WalletSigningBudgetStatusRequest;

export type ParseWalletSigningBudgetStatusResult =
  | {
      ok: true;
      claims: Record<string, unknown>;
      userId: string;
      appSessionVersion: string;
      sessionHash: string;
      request: WalletSigningBudgetStatusRequest;
      walletBudgetStatus: {
        expiresAtMs: number;
        committedRemainingUses: number;
        reservedUses: number;
        availableUses: number;
        remainingUses: number;
      };
    }
  | {
      ok: false;
      status: number;
      body: {
        authenticated: false;
        code: string;
        message: string;
      };
    };

export type WalletSigningBudgetStatusExpectations = {
  walletSigningSessionId: string;
  thresholdSessionId: string | null;
};

export function parseWalletSigningBudgetStatusExpectations(
  body: unknown,
): WalletSigningBudgetStatusExpectations {
  const record = (body || {}) as Record<string, unknown>;
  const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim() || null;
  return {
    walletSigningSessionId,
    thresholdSessionId,
  };
}

function sameParticipants(expected: readonly number[], actual: unknown): boolean {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  return actual.every((value, index) => Number(value) === Number(expected[index]));
}

function selectMatchingCurveStatus(
  statuses: SigningSessionSealThresholdSessionStatus[],
  auth: BaseVerifiedWalletSessionAuth,
): SigningSessionSealThresholdSessionStatus | null {
  return (
    statuses.find((status) => {
      return (
        status.kind === 'wallet_session' &&
        status.curve === auth.curve &&
        status.thresholdSessionId === auth.thresholdSessionId &&
        status.userId === auth.userId &&
        status.rpId === auth.rpId &&
        status.relayerKeyId === auth.relayerKeyId &&
        sameParticipants(auth.participantIds, status.participantIds)
      );
    }) || null
  );
}

function walletBudgetMatches(
  auth: BaseVerifiedWalletSessionAuth,
  status: SigningSessionSealWalletBudgetStatus | null,
): boolean {
  return Boolean(
    status &&
      status.kind === 'wallet_budget' &&
      status.curve === auth.curve &&
      status.thresholdSessionId === auth.thresholdSessionId &&
      status.walletSigningSessionId === auth.walletSigningSessionId &&
      status.userId === auth.userId &&
      status.rpId === auth.rpId &&
      sameParticipants(auth.participantIds, status.participantIds),
  );
}

function buildVerifiedEcdsaWalletSessionAuth(
  claims: RouterAbEcdsaHssWalletSessionClaims,
): VerifiedEcdsaWalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ecdsa',
    thresholdSessionId: claims.sessionId,
    walletSigningSessionId: claims.walletSigningSessionId,
    userId: claims.walletId,
    rpId: claims.rpId,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    keyHandle: claims.keyHandle,
  };
}

function buildVerifiedEd25519WalletSessionAuth(
  claims: RouterAbEd25519WalletSessionClaims,
): VerifiedEd25519WalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ed25519',
    thresholdSessionId: claims.sessionId,
    walletSigningSessionId: claims.walletSigningSessionId,
    userId: claims.walletId,
    rpId: claims.rpId,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    ed25519RelayerKeyId: claims.relayerKeyId,
  };
}

function unauthorized(message: string): ParseWalletSigningBudgetStatusResult {
  return {
    ok: false,
    status: 401,
    body: {
      authenticated: false,
      code: 'unauthorized',
      message,
    },
  };
}

export async function parseEcdsaWalletSigningBudgetStatusRequest(args: {
  rawClaims: Record<string, unknown>;
  claims: RouterAbEcdsaHssWalletSessionClaims;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy | null | undefined;
  nowMs?: () => number;
}): Promise<ParseWalletSigningBudgetStatusResult> {
  const auth = buildVerifiedEcdsaWalletSessionAuth(args.claims);
  return await parseCurveBoundWalletSigningBudgetStatus({
    rawClaims: args.rawClaims,
    sessionPolicy: args.sessionPolicy,
    auth,
    request: {
      kind: 'ecdsa_wallet_budget_status',
      auth,
      thresholdSessionId: args.claims.sessionId,
      walletSigningSessionId: args.claims.walletSigningSessionId,
      keyHandle: auth.keyHandle,
    },
    claimsKind: args.claims.kind,
    nowMs: args.nowMs,
  });
}

export async function parseEd25519WalletSigningBudgetStatusRequest(args: {
  rawClaims: Record<string, unknown>;
  claims: RouterAbEd25519WalletSessionClaims;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy | null | undefined;
  nowMs?: () => number;
}): Promise<ParseWalletSigningBudgetStatusResult> {
  const auth = buildVerifiedEd25519WalletSessionAuth(args.claims);
  return await parseCurveBoundWalletSigningBudgetStatus({
    rawClaims: args.rawClaims,
    sessionPolicy: args.sessionPolicy,
    auth,
    request: {
      kind: 'ed25519_wallet_budget_status',
      auth,
      thresholdSessionId: args.claims.sessionId,
      walletSigningSessionId: args.claims.walletSigningSessionId,
      ed25519RelayerKeyId: args.claims.relayerKeyId,
    },
    claimsKind: args.claims.kind,
    nowMs: args.nowMs,
  });
}

export async function parseWalletSigningBudgetStatusRequest(args: {
  headers: SigningSessionSealRouteHeaders;
  session: SigningSessionSealSessionAdapter | null | undefined;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy | null | undefined;
  nowMs?: () => number;
}): Promise<ParseWalletSigningBudgetStatusResult> {
  if (!args.session) {
    return {
      ok: false,
      status: 501,
      body: {
        authenticated: false,
        code: 'sessions_disabled',
        message: 'Sessions are not configured',
      },
    };
  }
  const parsed = await args.session.parse(args.headers);
  if (!parsed.ok) {
    return unauthorized('Missing or invalid Wallet Session JWT');
  }
  const rawClaims = ((parsed as { claims?: Record<string, unknown> }).claims || {}) as Record<
    string,
    unknown
  >;
  const ecdsaClaims = parseRouterAbEcdsaHssWalletSessionClaims(rawClaims);
  if (ecdsaClaims) {
    return await parseEcdsaWalletSigningBudgetStatusRequest({
      rawClaims,
      claims: ecdsaClaims,
      sessionPolicy: args.sessionPolicy,
      nowMs: args.nowMs,
    });
  }
  const ed25519Claims = parseRouterAbEd25519WalletSessionClaims(rawClaims);
  if (ed25519Claims) {
    return await parseEd25519WalletSigningBudgetStatusRequest({
      rawClaims,
      claims: ed25519Claims,
      sessionPolicy: args.sessionPolicy,
      nowMs: args.nowMs,
    });
  }
  return unauthorized('Invalid Wallet Session claims');
}

function hasCompleteCurveSpecificAuth(auth: VerifiedWalletSessionAuth): boolean {
  switch (auth.curve) {
    case 'ecdsa':
      return Boolean(auth.keyHandle);
    case 'ed25519':
      return Boolean(auth.ed25519RelayerKeyId);
  }
}

async function parseCurveBoundWalletSigningBudgetStatus(args: {
  rawClaims: Record<string, unknown>;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy | null | undefined;
  auth: VerifiedWalletSessionAuth;
  request: WalletSigningBudgetStatusRequest;
  claimsKind: string;
  nowMs?: () => number;
}): Promise<ParseWalletSigningBudgetStatusResult> {
  const nowMs = args.nowMs || Date.now;
  if (
    !args.auth.userId ||
    !args.auth.thresholdSessionId ||
    !args.auth.walletSigningSessionId ||
    !hasCompleteCurveSpecificAuth(args.auth) ||
    args.auth.expiresAtMs <= nowMs()
  ) {
    return unauthorized('Expired or incomplete Wallet Session claims');
  }
  const sessionPolicy = args.sessionPolicy;
  if (!sessionPolicy?.getWalletBudgetStatus) {
    return {
      ok: false,
      status: 501,
      body: {
        authenticated: false,
        code: 'sessions_disabled',
        message: 'Wallet Session status reads are not configured',
      },
    };
  }
  const curveStatuses = await sessionPolicy.getThresholdSessionStatuses({
    curve: args.auth.curve,
    thresholdSessionId: args.auth.thresholdSessionId,
  });
  const curveStatus = selectMatchingCurveStatus(curveStatuses, args.auth);
  const walletBudgetStatus = await sessionPolicy.getWalletBudgetStatus({
    curve: args.auth.curve,
    walletSigningSessionId: args.auth.walletSigningSessionId,
    thresholdSessionId: args.auth.thresholdSessionId,
  });
  if (!curveStatus || !walletBudgetStatus || !walletBudgetMatches(args.auth, walletBudgetStatus)) {
    return unauthorized('Wallet Session is no longer active');
  }
  return {
    ok: true,
    claims: args.rawClaims,
    userId: args.auth.userId,
    appSessionVersion: `signing-session:${args.claimsKind}:${args.auth.walletSigningSessionId}:${args.auth.thresholdSessionId}`,
    sessionHash: await hashEmailOtpSigningSessionClaims(args.rawClaims),
    request: args.request,
    walletBudgetStatus: {
      expiresAtMs: walletBudgetStatus.expiresAtMs,
      committedRemainingUses: Math.max(
        0,
        Math.floor(Number(walletBudgetStatus.committedRemainingUses) || 0),
      ),
      reservedUses: Math.max(0, Math.floor(Number(walletBudgetStatus.reservedUses) || 0)),
      availableUses: Math.max(0, Math.floor(Number(walletBudgetStatus.availableUses) || 0)),
      remainingUses: Math.max(0, Math.floor(Number(walletBudgetStatus.remainingUses) || 0)),
    },
  };
}
