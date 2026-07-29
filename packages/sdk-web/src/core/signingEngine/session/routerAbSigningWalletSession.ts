import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { ThresholdEd25519SessionRecord } from './persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  decodeJwtPayloadRecord,
} from '@shared/utils/sessionTokens';
import { clearEcdsaRoleLocalWorkerRuntimeState } from './material/ecdsaRoleLocalMaterialResolver';

export type RouterAbSigningWalletSessionAuth = {
  kind: 'wallet_session_jwt';
  walletSessionJwt: string;
  credential: RouterAbWalletSessionCredential;
};

export type RouterAbEd25519SigningWalletSession = {
  curve: 'ed25519';
  auth: RouterAbSigningWalletSessionAuth;
  thresholdSessionId: string;
  signingGrantId: string;
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

export type RouterAbEd25519WalletSessionAuthorityFailureReason =
  | 'missing_record'
  | 'cookie_session'
  | 'missing_wallet_session_jwt'
  | 'missing_threshold_session_id'
  | 'missing_signing_grant_id'
  | 'wallet_binding_mismatch';

export type RouterAbEd25519WalletSessionAuthority = {
  kind: 'router_ab_ed25519_wallet_session_authority_v1';
  auth: RouterAbSigningWalletSessionAuth;
  claims: RouterAbEd25519WalletSessionIdentityClaims;
  thresholdSessionId: string;
  signingGrantId: string;
};

export type RouterAbEd25519WalletSessionAuthorityResult =
  | { ok: true; value: RouterAbEd25519WalletSessionAuthority }
  | { ok: false; reason: RouterAbEd25519WalletSessionAuthorityFailureReason };

export type RouterAbEd25519PersistedSigningRecordState =
  | {
      kind: 'ready';
      record: ThresholdEd25519SessionRecord;
      value: RouterAbEd25519SigningWalletSession;
      reason?: never;
    }
  | {
      kind: 'expired';
      record: ThresholdEd25519SessionRecord;
      reason: 'expired';
      expiresAtMs: number;
      value?: never;
    }
  | {
      kind: 'exhausted';
      record: ThresholdEd25519SessionRecord;
      reason: 'exhausted';
      remainingUses: number;
      value?: never;
    }
  | {
      kind: 'non_signing';
      record: ThresholdEd25519SessionRecord;
      reason: 'cookie_session';
      value?: never;
    }
  | {
      kind: 'invalid';
      record: ThresholdEd25519SessionRecord | null;
      reason: RouterAbSigningWalletSessionParseFailureReason;
      value?: never;
    };

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function currentActiveSessionNowMs(): number {
  return Date.now();
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
  thresholdSessionId: string;
  signingGrantId: string;
};

export function parseRouterAbEd25519WalletSessionIdentityClaims(
  walletSessionJwt: string,
): RouterAbEd25519WalletSessionIdentityClaims | null {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND) return null;
  const walletId = nonEmptyString(payload.walletId);
  const nearAccountId = nonEmptyString(payload.nearAccountId);
  const nearEd25519SigningKeyId = nonEmptyString(payload.nearEd25519SigningKeyId);
  const thresholdSessionId = nonEmptyString(payload.thresholdSessionId);
  const signingGrantId = nonEmptyString(payload.signingGrantId);
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !thresholdSessionId ||
    !signingGrantId
  ) {
    return null;
  }
  return {
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    thresholdSessionId,
    signingGrantId,
  };
}

function routerAbEd25519WalletSessionClaimsMatchRecord(args: {
  record: ThresholdEd25519SessionRecord;
  claims: RouterAbEd25519WalletSessionIdentityClaims | null;
}): boolean {
  const claims = args.claims;
  if (!claims) return false;
  const record = args.record;
  return (
    claims.walletId === nonEmptyString(record.walletId) &&
    claims.nearAccountId === nonEmptyString(record.nearAccountId) &&
    claims.nearEd25519SigningKeyId === nonEmptyString(record.nearEd25519SigningKeyId) &&
    claims.thresholdSessionId === nonEmptyString(record.thresholdSessionId) &&
    claims.signingGrantId === nonEmptyString(record.signingGrantId)
  );
}

export function parseRouterAbEd25519WalletSessionAuthorityFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): RouterAbEd25519WalletSessionAuthorityResult {
  if (!record) return { ok: false, reason: 'missing_record' };
  if (record.thresholdSessionKind !== 'jwt') return { ok: false, reason: 'cookie_session' };
  const auth = buildWalletSessionJwtAuth(record.walletSessionJwt);
  if (!auth) return { ok: false, reason: 'missing_wallet_session_jwt' };
  const thresholdSessionId = nonEmptyString(record.thresholdSessionId);
  if (!thresholdSessionId) return { ok: false, reason: 'missing_threshold_session_id' };
  const signingGrantId = nonEmptyString(record.signingGrantId);
  if (!signingGrantId) return { ok: false, reason: 'missing_signing_grant_id' };
  const claims = parseRouterAbEd25519WalletSessionIdentityClaims(auth.walletSessionJwt);
  if (!claims) return { ok: false, reason: 'wallet_binding_mismatch' };
  if (!routerAbEd25519WalletSessionClaimsMatchRecord({ record, claims })) {
    return { ok: false, reason: 'wallet_binding_mismatch' };
  }
  return {
    ok: true,
    value: {
      kind: 'router_ab_ed25519_wallet_session_authority_v1',
      auth,
      claims,
      thresholdSessionId,
      signingGrantId,
    },
  };
}

export function clearRouterAbEcdsaDerivationWorkerMaterialRuntimeValidation(): void {
  clearEcdsaRoleLocalWorkerRuntimeState();
}

export function resolveRouterAbEd25519SigningRootFromRecord(
  record: Pick<
    ThresholdEd25519SessionRecord,
    'runtimePolicyScope' | 'signingRootId' | 'signingRootVersion'
  >,
): RouterAbSigningWalletSessionResult<{
  signingRootId: string;
  signingRootVersion: string;
}> {
  if (!record.runtimePolicyScope) {
    return { ok: false, reason: 'missing_runtime_policy_scope' };
  }
  let derived: { signingRootId: string; signingRootVersion?: string };
  try {
    derived = signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope);
  } catch {
    return { ok: false, reason: 'missing_signing_root' };
  }
  const derivedSigningRootId = nonEmptyString(derived.signingRootId);
  const derivedSigningRootVersion = nonEmptyString(derived.signingRootVersion);
  if (!derivedSigningRootId || !derivedSigningRootVersion) {
    return { ok: false, reason: 'missing_signing_root' };
  }
  const persistedSigningRootId = nonEmptyString(record.signingRootId);
  const persistedSigningRootVersion = nonEmptyString(record.signingRootVersion);
  if (
    (persistedSigningRootId && persistedSigningRootId !== derivedSigningRootId) ||
    (persistedSigningRootVersion && persistedSigningRootVersion !== derivedSigningRootVersion)
  ) {
    return { ok: false, reason: 'signing_root_mismatch' };
  }
  return {
    ok: true,
    value: {
      signingRootId: derivedSigningRootId,
      signingRootVersion: derivedSigningRootVersion,
    },
  };
}

export function parseRouterAbEd25519SigningWalletSessionFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
  nowMs: number = currentActiveSessionNowMs(),
): RouterAbSigningWalletSessionResult<RouterAbEd25519SigningWalletSession> {
  const operationNowMs = normalizeActiveSessionNowMs(nowMs);
  if (operationNowMs == null) return { ok: false, reason: 'invalid_budget' };
  const authority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
  if (!authority.ok) return authority;
  const sessionRecord = record;
  if (!sessionRecord) return { ok: false, reason: 'missing_record' };
  const signingRoot = resolveRouterAbEd25519SigningRootFromRecord(sessionRecord);
  if (!signingRoot.ok) return signingRoot;
  const runtimePolicyScope = sessionRecord.runtimePolicyScope;
  if (!runtimePolicyScope) return { ok: false, reason: 'missing_runtime_policy_scope' };
  if (!sessionRecord.routerAbNormalSigning) {
    return { ok: false, reason: 'missing_router_ab_state' };
  }
  const remainingUses = positiveInteger(sessionRecord.remainingUses);
  const expiresAtMs = positiveInteger(sessionRecord.expiresAtMs);
  if (
    !Number.isSafeInteger(sessionRecord.remainingUses) ||
    !Number.isSafeInteger(sessionRecord.expiresAtMs) ||
    sessionRecord.remainingUses < 0 ||
    sessionRecord.expiresAtMs <= 0
  ) {
    return { ok: false, reason: 'invalid_budget' };
  }
  const inactive = inactiveSigningSessionState({
    remainingUses: Math.max(0, Math.floor(Number(sessionRecord.remainingUses) || 0)),
    expiresAtMs: Math.max(0, Math.floor(Number(sessionRecord.expiresAtMs) || 0)),
    nowMs: operationNowMs,
  });
  if (inactive?.kind === 'exhausted') return { ok: false, reason: 'exhausted' };
  if (inactive?.kind === 'expired') return { ok: false, reason: 'expired' };
  if (!remainingUses || !expiresAtMs) return { ok: false, reason: 'invalid_budget' };
  return {
    ok: true,
    value: {
      curve: 'ed25519',
      auth: authority.value.auth,
      thresholdSessionId: authority.value.thresholdSessionId,
      signingGrantId: authority.value.signingGrantId,
      remainingUses,
      expiresAtMs,
      runtimePolicyScope,
      signingRootId: signingRoot.value.signingRootId,
      signingRootVersion: signingRoot.value.signingRootVersion,
      routerAbNormalSigning: sessionRecord.routerAbNormalSigning,
    },
  };
}

export function classifyRouterAbEd25519PersistedSigningRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
  nowMs: number = currentActiveSessionNowMs(),
): RouterAbEd25519PersistedSigningRecordState {
  if (!record) {
    return {
      kind: 'invalid',
      record: null,
      reason: 'missing_record',
    };
  }
  const operationNowMs = normalizeActiveSessionNowMs(nowMs);
  if (operationNowMs == null) {
    return {
      kind: 'invalid',
      record,
      reason: 'invalid_budget',
    };
  }
  const parsed = parseRouterAbEd25519SigningWalletSessionFromRecord(record, operationNowMs);
  if (parsed.ok) {
    return {
      kind: 'ready',
      record,
      value: parsed.value,
    };
  }
  if (parsed.reason === 'expired') {
    return {
      kind: 'expired',
      record,
      reason: 'expired',
      expiresAtMs: Math.max(0, Math.floor(Number(record.expiresAtMs) || 0)),
    };
  }
  if (parsed.reason === 'exhausted') {
    return {
      kind: 'exhausted',
      record,
      reason: 'exhausted',
      remainingUses: Math.max(0, Math.floor(Number(record.remainingUses) || 0)),
    };
  }
  if (parsed.reason === 'cookie_session') {
    return {
      kind: 'non_signing',
      record,
      reason: 'cookie_session',
    };
  }
  return {
    kind: 'invalid',
    record,
    reason: parsed.reason,
  };
}
