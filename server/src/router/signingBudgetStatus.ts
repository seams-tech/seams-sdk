import {
  parseThresholdEcdsaSessionClaims,
  parseThresholdEd25519SessionClaims,
  type ThresholdEcdsaSessionClaims,
  type ThresholdEd25519SessionClaims,
} from '../core/ThresholdService/validation';
import { hashEmailOtpSigningSessionClaims } from './emailOtpSessionRouteHelpers';
import type {
  SigningSessionSealRouteHeaders,
  SigningSessionSealSessionAdapter,
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealWalletBudgetStatus,
} from '../threshold/session/signingSessionSeal/types';

type BaseVerifiedThresholdSessionAuth = {
  kind: 'threshold_session';
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  expiresAtMs: number;
};

export type VerifiedEcdsaThresholdSessionAuth = BaseVerifiedThresholdSessionAuth & {
  curve: 'ecdsa';
  ecdsaThresholdKeyId: string;
  ed25519RelayerKeyId?: never;
};

export type VerifiedEd25519ThresholdSessionAuth = BaseVerifiedThresholdSessionAuth & {
  curve: 'ed25519';
  ed25519RelayerKeyId: string;
  ecdsaThresholdKeyId?: never;
};

export type VerifiedThresholdSessionAuth =
  | VerifiedEcdsaThresholdSessionAuth
  | VerifiedEd25519ThresholdSessionAuth;

export type EcdsaWalletSigningBudgetStatusRequest = {
  kind: 'ecdsa_wallet_budget_status';
  auth: VerifiedEcdsaThresholdSessionAuth;
  thresholdSessionId: string;
  walletSigningSessionId: string;

  // Curve-specific fields.
  ecdsaThresholdKeyId: string;
  ed25519RelayerKeyId?: never;
};

export type Ed25519WalletSigningBudgetStatusRequest = {
  kind: 'ed25519_wallet_budget_status';
  auth: VerifiedEd25519ThresholdSessionAuth;
  thresholdSessionId: string;
  walletSigningSessionId: string;

  // Curve-specific fields.
  ed25519RelayerKeyId: string;
  ecdsaThresholdKeyId?: never;
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
  auth: BaseVerifiedThresholdSessionAuth,
): SigningSessionSealThresholdSessionStatus | null {
  return (
    statuses.find((status) => {
      return (
        status.kind === 'threshold_session' &&
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
  auth: BaseVerifiedThresholdSessionAuth,
  status: SigningSessionSealWalletBudgetStatus | null,
): boolean {
  return Boolean(
    status &&
      status.kind === 'wallet_budget' &&
      status.curve === auth.curve &&
      status.walletSigningSessionId === auth.walletSigningSessionId &&
      status.userId === auth.userId &&
      status.rpId === auth.rpId &&
      sameParticipants(auth.participantIds, status.participantIds),
  );
}

function buildVerifiedEcdsaThresholdSessionAuth(
  claims: ThresholdEcdsaSessionClaims,
): VerifiedEcdsaThresholdSessionAuth {
  return {
    kind: 'threshold_session',
    curve: 'ecdsa',
    thresholdSessionId: claims.sessionId,
    walletSigningSessionId: claims.walletSigningSessionId,
    userId: claims.walletId,
    rpId: claims.rpId,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    ecdsaThresholdKeyId: claims.ecdsaThresholdKeyId,
  };
}

function buildVerifiedEd25519ThresholdSessionAuth(
  claims: ThresholdEd25519SessionClaims,
): VerifiedEd25519ThresholdSessionAuth {
  return {
    kind: 'threshold_session',
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
  claims: ThresholdEcdsaSessionClaims;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy | null | undefined;
  nowMs?: () => number;
}): Promise<ParseWalletSigningBudgetStatusResult> {
  const auth = buildVerifiedEcdsaThresholdSessionAuth(args.claims);
  return await parseCurveBoundWalletSigningBudgetStatus({
    rawClaims: args.rawClaims,
    sessionPolicy: args.sessionPolicy,
    auth,
    request: {
      kind: 'ecdsa_wallet_budget_status',
      auth,
      thresholdSessionId: args.claims.sessionId,
      walletSigningSessionId: args.claims.walletSigningSessionId,
      ecdsaThresholdKeyId: args.claims.ecdsaThresholdKeyId,
    },
    claimsKind: args.claims.kind,
    nowMs: args.nowMs,
  });
}

export async function parseEd25519WalletSigningBudgetStatusRequest(args: {
  rawClaims: Record<string, unknown>;
  claims: ThresholdEd25519SessionClaims;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy | null | undefined;
  nowMs?: () => number;
}): Promise<ParseWalletSigningBudgetStatusResult> {
  const auth = buildVerifiedEd25519ThresholdSessionAuth(args.claims);
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
    return unauthorized('Missing or invalid threshold session token');
  }
  const rawClaims = ((parsed as { claims?: Record<string, unknown> }).claims || {}) as Record<
    string,
    unknown
  >;
  const ecdsaClaims = parseThresholdEcdsaSessionClaims(rawClaims);
  if (ecdsaClaims) {
    return await parseEcdsaWalletSigningBudgetStatusRequest({
      rawClaims,
      claims: ecdsaClaims,
      sessionPolicy: args.sessionPolicy,
      nowMs: args.nowMs,
    });
  }
  const ed25519Claims = parseThresholdEd25519SessionClaims(rawClaims);
  if (ed25519Claims) {
    return await parseEd25519WalletSigningBudgetStatusRequest({
      rawClaims,
      claims: ed25519Claims,
      sessionPolicy: args.sessionPolicy,
      nowMs: args.nowMs,
    });
  }
  return unauthorized('Invalid threshold session token claims');
}

async function parseCurveBoundWalletSigningBudgetStatus(args: {
  rawClaims: Record<string, unknown>;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy | null | undefined;
  auth: VerifiedThresholdSessionAuth;
  request: WalletSigningBudgetStatusRequest;
  claimsKind: string;
  nowMs?: () => number;
}): Promise<ParseWalletSigningBudgetStatusResult> {
  const nowMs = args.nowMs || Date.now;
  if (
    !args.auth.userId ||
    !args.auth.thresholdSessionId ||
    !args.auth.walletSigningSessionId ||
    args.auth.expiresAtMs <= nowMs()
  ) {
    return unauthorized('Expired or incomplete threshold session token');
  }
  const sessionPolicy = args.sessionPolicy;
  if (!sessionPolicy?.getWalletBudgetStatus) {
    return {
      ok: false,
      status: 501,
      body: {
        authenticated: false,
        code: 'sessions_disabled',
        message: 'Threshold session status reads are not configured',
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
  });
  if (!curveStatus || !walletBudgetStatus || !walletBudgetMatches(args.auth, walletBudgetStatus)) {
    return unauthorized('Threshold session is no longer active');
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
      remainingUses: Math.max(0, Math.floor(Number(walletBudgetStatus.remainingUses) || 0)),
    },
  };
}
