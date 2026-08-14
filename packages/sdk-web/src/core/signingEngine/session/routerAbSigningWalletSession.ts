import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { requireOpaqueWalletSessionToken } from '@shared/utils/sessionTokens';
import {
  parseThresholdEd25519SessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type RouterAbSigningWalletSessionAuth = {
  kind: 'wallet_session_opaque';
  walletSessionToken: string;
  credential: RouterAbWalletSessionCredential;
};

export type RouterAbEd25519SigningWalletSession = {
  curve: 'ed25519';
  auth: RouterAbSigningWalletSessionAuth;
  walletSessionId: WalletSessionId;
  authorizationId: WalletSessionAuthorizationId;
  quotaId: MpcWalletSigningQuotaId;
  thresholdSessionId: ThresholdEd25519SessionId;
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
  | 'missing_wallet_session_token'
  | 'missing_quota_id'
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

function buildWalletSessionOpaqueAuth(tokenRaw: unknown): RouterAbSigningWalletSessionAuth | null {
  const walletSessionToken = nonEmptyString(tokenRaw);
  if (!walletSessionToken) return null;
  return {
    kind: 'wallet_session_opaque',
    walletSessionToken,
    credential: {
      kind: 'wallet_session_opaque',
      walletSessionToken,
    },
  };
}

export type BuildRouterAbEd25519SigningWalletSessionInput = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  walletSessionId: string;
  authorizationId: string;
  quotaId: string;
  thresholdSessionId: string;
  remainingUses: number;
  expiresAtMs: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  walletSessionToken: string;
  nowMs: number;
};

export function buildRouterAbEd25519SigningWalletSession(
  input: BuildRouterAbEd25519SigningWalletSessionInput,
): RouterAbSigningWalletSessionResult<RouterAbEd25519SigningWalletSession> {
  let walletSessionToken: string;
  try {
    walletSessionToken = requireOpaqueWalletSessionToken(input.walletSessionToken);
  } catch {
    return { ok: false, reason: 'missing_wallet_session_token' };
  }
  const auth = buildWalletSessionOpaqueAuth(walletSessionToken);
  if (!auth) return { ok: false, reason: 'missing_wallet_session_token' };
  const walletId = nonEmptyString(input.walletId);
  const nearAccountId = nonEmptyString(input.nearAccountId);
  const nearEd25519SigningKeyId = nonEmptyString(input.nearEd25519SigningKeyId);
  if (!walletId || !nearAccountId || !nearEd25519SigningKeyId) {
    return { ok: false, reason: 'wallet_binding_mismatch' };
  }
  const walletSessionId = parseWalletSessionId(input.walletSessionId);
  const authorizationId = parseWalletSessionAuthorizationId(input.authorizationId);
  const quotaId = parseMpcWalletSigningQuotaId(input.quotaId);
  const thresholdSessionId = parseThresholdEd25519SessionId(input.thresholdSessionId);
  if (!walletSessionId.ok) return { ok: false, reason: 'missing_session_identity' };
  if (!authorizationId.ok) return { ok: false, reason: 'missing_session_identity' };
  if (!quotaId.ok) return { ok: false, reason: 'missing_quota_id' };
  if (!thresholdSessionId.ok) return { ok: false, reason: 'missing_threshold_session_id' };
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
      authorizationId: authorizationId.value,
      quotaId: quotaId.value,
      thresholdSessionId: thresholdSessionId.value,
      remainingUses,
      expiresAtMs,
      runtimePolicyScope: input.runtimePolicyScope,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: nonEmptyString(signingRoot.signingRootVersion),
      routerAbNormalSigning: input.routerAbNormalSigning,
    },
  };
}
