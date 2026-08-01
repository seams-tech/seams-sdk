import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  decodeJwtPayloadRecord,
} from '@shared/utils/sessionTokens';
import {
  parseSigningGrantId,
  parseThresholdEd25519SessionId,
  type SigningGrantId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseWalletSessionId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type RouterAbSigningWalletSessionAuth = {
  kind: 'wallet_session_jwt';
  walletSessionJwt: string;
  credential: RouterAbWalletSessionCredential;
};

export type RouterAbEd25519SigningWalletSession = {
  curve: 'ed25519';
  auth: RouterAbSigningWalletSessionAuth;
  walletSessionId: WalletSessionId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingGrantId: SigningGrantId;
  remainingUses: number;
  expiresAtMs: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type RouterAbSigningWalletSessionParseFailureReason =
  | 'missing_record'
  | 'cookie_session'
  | 'missing_session_identity'
  | 'missing_wallet_session_jwt'
  | 'missing_signing_grant_id'
  | 'missing_threshold_session_id'
  | 'missing_signing_root'
  | 'signing_root_mismatch'
  | 'missing_client_verifying_share'
  | 'material_identity_mismatch'
  | 'wallet_binding_mismatch'
  | 'missing_runtime_policy_scope'
  | 'missing_router_ab_state'
  | 'invalid_router_ab_state'
  | 'invalid_budget'
  | 'expired'
  | 'exhausted';

export type RouterAbSigningWalletSessionResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: RouterAbSigningWalletSessionParseFailureReason };

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function normalizeActiveSessionNowMs(nowMs: number): number | null {
  const normalized = Math.floor(Number(nowMs));
  return Number.isSafeInteger(normalized) && normalized >= 0 ? normalized : null;
}

function inactiveSigningSessionState(args: {
  remainingUses: number;
  expiresAtMs: number;
  nowMs: number;
}): { kind: 'expired'; expiresAtMs: number } | { kind: 'exhausted'; remainingUses: number } | null {
  if (args.expiresAtMs <= args.nowMs) return { kind: 'expired', expiresAtMs: args.expiresAtMs };
  if (args.remainingUses <= 0) return { kind: 'exhausted', remainingUses: args.remainingUses };
  return null;
}

function buildWalletSessionJwtAuth(jwtRaw: unknown): RouterAbSigningWalletSessionAuth | null {
  const walletSessionJwt = nonEmptyString(jwtRaw);
  if (!walletSessionJwt) return null;
  return {
    kind: 'wallet_session_jwt',
    walletSessionJwt,
    credential: {
      kind: 'wallet_session_jwt',
      walletSessionJwt,
    },
  };
}

export type RouterAbEd25519WalletSessionIdentityClaims = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  walletSessionId: WalletSessionId;
  quotaId: string;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingGrantId: SigningGrantId;
};

export function parseRouterAbEd25519WalletSessionIdentityClaims(
  walletSessionJwt: string,
): RouterAbEd25519WalletSessionIdentityClaims | null {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND) return null;
  const walletId = nonEmptyString(payload.walletId);
  const nearAccountId = nonEmptyString(payload.nearAccountId);
  const nearEd25519SigningKeyId = nonEmptyString(payload.nearEd25519SigningKeyId);
  const walletSessionId = parseWalletSessionId(payload.walletSessionId);
  const quotaId = nonEmptyString(payload.quotaId);
  const thresholdSessionId = parseThresholdEd25519SessionId(payload.thresholdSessionId);
  const signingGrantId = parseSigningGrantId(payload.signingGrantId);
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !walletSessionId.ok ||
    !quotaId ||
    !thresholdSessionId.ok ||
    !signingGrantId.ok
  ) {
    return null;
  }
  return {
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    walletSessionId: walletSessionId.value,
    quotaId,
    thresholdSessionId: thresholdSessionId.value,
    signingGrantId: signingGrantId.value,
  };
}

export type BuildRouterAbEd25519SigningWalletSessionInput = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  walletSessionId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses: number;
  expiresAtMs: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  walletSessionJwt: string;
  nowMs: number;
};

export function buildRouterAbEd25519SigningWalletSession(
  input: BuildRouterAbEd25519SigningWalletSessionInput,
): RouterAbSigningWalletSessionResult<RouterAbEd25519SigningWalletSession> {
  const auth = buildWalletSessionJwtAuth(input.walletSessionJwt);
  if (!auth) return { ok: false, reason: 'missing_wallet_session_jwt' };
  const walletId = nonEmptyString(input.walletId);
  const nearAccountId = nonEmptyString(input.nearAccountId);
  const nearEd25519SigningKeyId = nonEmptyString(input.nearEd25519SigningKeyId);
  const walletSessionId = parseWalletSessionId(input.walletSessionId);
  const thresholdSessionId = parseThresholdEd25519SessionId(input.thresholdSessionId);
  const signingGrantId = parseSigningGrantId(input.signingGrantId);
  if (!walletSessionId.ok) return { ok: false, reason: 'missing_session_identity' };
  if (!thresholdSessionId.ok) return { ok: false, reason: 'missing_threshold_session_id' };
  if (!signingGrantId.ok) return { ok: false, reason: 'missing_signing_grant_id' };
  const claims = parseRouterAbEd25519WalletSessionIdentityClaims(auth.walletSessionJwt);
  if (
    !claims ||
    claims.walletId !== walletId ||
    claims.nearAccountId !== nearAccountId ||
    claims.nearEd25519SigningKeyId !== nearEd25519SigningKeyId ||
    claims.walletSessionId !== walletSessionId.value ||
    claims.thresholdSessionId !== thresholdSessionId.value ||
    claims.signingGrantId !== signingGrantId.value
  ) {
    return { ok: false, reason: 'wallet_binding_mismatch' };
  }
  const operationNowMs = normalizeActiveSessionNowMs(input.nowMs);
  const remainingUses = positiveInteger(input.remainingUses);
  const expiresAtMs = positiveInteger(input.expiresAtMs);
  if (
    operationNowMs == null ||
    !Number.isSafeInteger(input.remainingUses) ||
    !Number.isSafeInteger(input.expiresAtMs) ||
    input.remainingUses < 0 ||
    input.expiresAtMs <= 0
  ) {
    return { ok: false, reason: 'invalid_budget' };
  }
  const lifecycle = inactiveSigningSessionState({
    remainingUses: Math.max(0, Math.floor(input.remainingUses)),
    expiresAtMs: Math.max(0, Math.floor(input.expiresAtMs)),
    nowMs: operationNowMs,
  });
  if (lifecycle?.kind === 'expired') return { ok: false, reason: 'expired' };
  if (lifecycle?.kind === 'exhausted') return { ok: false, reason: 'exhausted' };
  let signingRoot: { signingRootId: string; signingRootVersion?: string };
  try {
    signingRoot = signingRootScopeFromRuntimePolicyScope(input.runtimePolicyScope);
  } catch {
    return { ok: false, reason: 'missing_signing_root' };
  }
  if (
    signingRoot.signingRootId !== nonEmptyString(input.signingRootId) ||
    signingRoot.signingRootVersion !== nonEmptyString(input.signingRootVersion)
  ) {
    return { ok: false, reason: 'signing_root_mismatch' };
  }
  return {
    ok: true,
    value: {
      curve: 'ed25519',
      auth,
      walletSessionId: walletSessionId.value,
      thresholdSessionId: thresholdSessionId.value,
      signingGrantId: signingGrantId.value,
      remainingUses,
      expiresAtMs,
      runtimePolicyScope: input.runtimePolicyScope,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: nonEmptyString(signingRoot.signingRootVersion),
      routerAbNormalSigning: input.routerAbNormalSigning,
    },
  };
}
