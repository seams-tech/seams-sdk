import {
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
  thresholdEd25519AuthorityScopesMatch,
  type RouterAbEcdsaDerivationWalletSessionClaims,
  type RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import { hashEmailOtpSigningSessionClaims } from './emailOtpSessionRouteHelpers';
import {
  buildVerifiedEcdsaWalletSessionAuth,
  buildVerifiedEd25519WalletSessionAuth,
  type VerifiedEcdsaWalletSessionAuth,
  type VerifiedEd25519WalletSessionAuth,
  type VerifiedWalletSessionAuth,
} from './verifiedWalletSessionAuth';
import type {
  SigningSessionSealRouteHeaders,
  SigningSessionSealSessionAdapter,
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealWalletBudgetStatus,
} from '../threshold/session/signingSessionSeal/signingSessionSeal.types';
import {
  walletSessionFailureCodeFromParseReason,
  walletSessionFailureMessage,
  walletSessionFailureStatus,
  type WalletSessionFailureCode,
} from './walletSessionFailure';

export type EcdsaWalletSigningBudgetStatusRequest = {
  kind: 'ecdsa_wallet_budget_status';
  auth: VerifiedEcdsaWalletSessionAuth;
  thresholdSessionId: string;
  signingGrantId: string;

  // Curve-specific fields.
  keyHandle: string;
  ed25519RelayerKeyId?: never;
};

export type Ed25519WalletSigningBudgetStatusRequest = {
  kind: 'ed25519_wallet_budget_status';
  auth: VerifiedEd25519WalletSessionAuth;
  thresholdSessionId: string;
  signingGrantId: string;

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
  signingGrantId: string;
  thresholdSessionId: string | null;
};

const BUDGET_STATUS_FAILURE_STATUS = {
  sessions_disabled: 501,
  wallet_session_missing: walletSessionFailureStatus('wallet_session_missing'),
  wallet_session_signature_invalid: walletSessionFailureStatus('wallet_session_signature_invalid'),
  wallet_session_claims_invalid: walletSessionFailureStatus('wallet_session_claims_invalid'),
  wallet_session_expired: walletSessionFailureStatus('wallet_session_expired'),
  wallet_session_scope_mismatch: walletSessionFailureStatus('wallet_session_scope_mismatch'),
  wallet_session_unavailable: walletSessionFailureStatus('wallet_session_unavailable'),
  wallet_budget_exhausted: walletSessionFailureStatus('wallet_budget_exhausted'),
} as const;

type WalletSigningBudgetStatusFailureCode = 'sessions_disabled' | WalletSessionFailureCode;

export function parseWalletSigningBudgetStatusExpectations(
  body: unknown,
): WalletSigningBudgetStatusExpectations {
  const record = (body || {}) as Record<string, unknown>;
  const signingGrantId = String(record.signingGrantId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim() || null;
  return {
    signingGrantId,
    thresholdSessionId,
  };
}

function sameParticipants(expected: readonly number[], actual: unknown): boolean {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  return actual.every((value, index) => Number(value) === Number(expected[index]));
}

function statusMatchesAuthScope(
  auth: VerifiedWalletSessionAuth,
  status: SigningSessionSealThresholdSessionStatus,
): boolean {
  switch (auth.curve) {
    case 'ecdsa':
      return (
        status.curve === 'ecdsa' &&
        status.evmFamilySigningKeySlotId === auth.evmFamilySigningKeySlotId
      );
    case 'ed25519':
      return (
        status.curve === 'ed25519' &&
        thresholdEd25519AuthorityScopesMatch(
          status.authorityScope,
          thresholdEd25519AuthorityScopeFromWalletAuthAuthority(auth.authority),
        )
      );
  }
}

function selectMatchingCurveStatus(
  statuses: SigningSessionSealThresholdSessionStatus[],
  auth: VerifiedWalletSessionAuth,
): SigningSessionSealThresholdSessionStatus | null {
  return (
    statuses.find((status) => {
      return (
        status.kind === 'wallet_session' &&
        status.curve === auth.curve &&
        status.thresholdSessionId === auth.thresholdSessionId &&
        status.userId === auth.userId &&
        statusMatchesAuthScope(auth, status) &&
        status.relayerKeyId === auth.relayerKeyId &&
        sameParticipants(auth.participantIds, status.participantIds)
      );
    }) || null
  );
}

function walletBudgetMatches(
  auth: VerifiedWalletSessionAuth,
  status: SigningSessionSealWalletBudgetStatus | null,
): boolean {
  if (
    !status ||
    status.kind !== 'wallet_budget' ||
    status.signingGrantId !== auth.signingGrantId ||
    status.userId !== auth.userId
  ) {
    return false;
  }
  switch (auth.curve) {
    case 'ed25519': {
      if (status.bindings.kind === 'ecdsa_only') return false;
      const binding = status.bindings.ed25519;
      return (
        binding.thresholdSessionId === auth.thresholdSessionId &&
        thresholdEd25519AuthorityScopesMatch(
          binding.authorityScope,
          thresholdEd25519AuthorityScopeFromWalletAuthAuthority(auth.authority),
        ) &&
        sameParticipants(auth.participantIds, binding.participantIds)
      );
    }
    case 'ecdsa': {
      if (status.bindings.kind === 'ed25519_only') return false;
      for (const binding of status.bindings.ecdsa) {
        if (
          binding.thresholdSessionId === auth.thresholdSessionId &&
          binding.evmFamilySigningKeySlotId === auth.evmFamilySigningKeySlotId &&
          sameParticipants(auth.participantIds, binding.participantIds)
        ) {
          return true;
        }
      }
      return false;
    }
  }
}

function budgetStatusFailure(
  code: WalletSigningBudgetStatusFailureCode,
  message: string,
): ParseWalletSigningBudgetStatusResult {
  return {
    ok: false,
    status: BUDGET_STATUS_FAILURE_STATUS[code],
    body: {
      authenticated: false,
      code,
      message,
    },
  };
}

export async function parseEcdsaWalletSigningBudgetStatusRequest(args: {
  rawClaims: Record<string, unknown>;
  claims: RouterAbEcdsaDerivationWalletSessionClaims;
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
      thresholdSessionId: args.claims.thresholdSessionId,
      signingGrantId: args.claims.signingGrantId,
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
      thresholdSessionId: args.claims.thresholdSessionId,
      signingGrantId: args.claims.signingGrantId,
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
    return budgetStatusFailure('sessions_disabled', 'Sessions are not configured');
  }
  let parsed: Awaited<ReturnType<SigningSessionSealSessionAdapter['parse']>>;
  try {
    parsed = await args.session.parse(args.headers);
  } catch {
    return budgetStatusFailure(
      'wallet_session_unavailable',
      walletSessionFailureMessage('wallet_session_unavailable'),
    );
  }
  if (!parsed.ok) {
    const code = walletSessionFailureCodeFromParseReason(parsed.reason);
    return budgetStatusFailure(code, walletSessionFailureMessage(code));
  }
  const rawClaims = ((parsed as { claims?: Record<string, unknown> }).claims || {}) as Record<
    string,
    unknown
  >;
  const ecdsaClaims = parseRouterAbEcdsaDerivationWalletSessionClaims(rawClaims);
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
  return budgetStatusFailure(
    'wallet_session_claims_invalid',
    walletSessionFailureMessage('wallet_session_claims_invalid'),
  );
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
    !args.auth.signingGrantId ||
    !hasCompleteCurveSpecificAuth(args.auth)
  ) {
    return budgetStatusFailure(
      'wallet_session_claims_invalid',
      walletSessionFailureMessage('wallet_session_claims_invalid'),
    );
  }
  const checkedAtMs = nowMs();
  if (args.auth.expiresAtMs <= checkedAtMs) {
    return budgetStatusFailure(
      'wallet_session_expired',
      walletSessionFailureMessage('wallet_session_expired'),
    );
  }
  const sessionPolicy = args.sessionPolicy;
  if (!sessionPolicy?.getWalletBudgetStatus) {
    return budgetStatusFailure(
      'sessions_disabled',
      'Wallet Session status reads are not configured',
    );
  }
  let curveStatuses: SigningSessionSealThresholdSessionStatus[];
  let walletBudgetStatus: SigningSessionSealWalletBudgetStatus | null;
  try {
    curveStatuses = await sessionPolicy.getThresholdSessionStatuses({
      curve: args.auth.curve,
      thresholdSessionId: args.auth.thresholdSessionId,
    });
    walletBudgetStatus = await sessionPolicy.getWalletBudgetStatus({
      signingGrantId: args.auth.signingGrantId,
    });
  } catch {
    return budgetStatusFailure(
      'wallet_session_unavailable',
      walletSessionFailureMessage('wallet_session_unavailable'),
    );
  }
  if (curveStatuses.length === 0) {
    return budgetStatusFailure(
      'wallet_session_missing',
      walletSessionFailureMessage('wallet_session_missing'),
    );
  }
  const curveStatus = selectMatchingCurveStatus(curveStatuses, args.auth);
  if (!curveStatus) {
    return budgetStatusFailure(
      'wallet_session_scope_mismatch',
      walletSessionFailureMessage('wallet_session_scope_mismatch'),
    );
  }
  if (Math.floor(Number(curveStatus.expiresAtMs) || 0) <= checkedAtMs) {
    return budgetStatusFailure(
      'wallet_session_expired',
      walletSessionFailureMessage('wallet_session_expired'),
    );
  }
  if (!walletBudgetStatus) {
    return budgetStatusFailure(
      'wallet_session_missing',
      walletSessionFailureMessage('wallet_session_missing'),
    );
  }
  if (!walletBudgetMatches(args.auth, walletBudgetStatus)) {
    return budgetStatusFailure(
      'wallet_session_scope_mismatch',
      walletSessionFailureMessage('wallet_session_scope_mismatch'),
    );
  }
  if (Math.floor(Number(walletBudgetStatus.expiresAtMs) || 0) <= checkedAtMs) {
    return budgetStatusFailure(
      'wallet_session_expired',
      walletSessionFailureMessage('wallet_session_expired'),
    );
  }
  return {
    ok: true,
    claims: args.rawClaims,
    userId: args.auth.userId,
    appSessionVersion: `signing-session:${args.claimsKind}:${args.auth.signingGrantId}:${args.auth.thresholdSessionId}`,
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
