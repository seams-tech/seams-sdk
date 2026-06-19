import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from './persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  resolveRouterAbEcdsaWalletSessionAuthFromRecord,
} from './warmCapabilities/routerAbEcdsaWalletSessionAuth';
import {
  buildRouterAbEd25519SigningMaterialRef,
  type RouterAbEd25519SigningMaterialRef,
} from '../threshold/ed25519/hssMaterialBinding';
import {
  buildRouterAbEcdsaHssSigningMaterialRef,
  type RouterAbEcdsaHssSigningMaterialRef,
} from '../routerAb/ecdsaHss/signingMaterialRef';

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
  signingMaterial: RouterAbEd25519SigningMaterialRef;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type RouterAbEcdsaHssSigningWalletSession = {
  curve: 'ecdsa';
  auth: RouterAbSigningWalletSessionAuth;
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses: number;
  expiresAtMs: number;
  signingMaterial: RouterAbEcdsaHssSigningMaterialRef;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbEcdsaHssNormalSigning: RouterAbEcdsaHssNormalSigningStateV1;
  clientVerifyingShareB64u?: never;
  clientSigningShare32?: never;
};

export type RouterAbSigningWalletSessionParseFailureReason =
  | 'missing_record'
  | 'cookie_session'
  | 'missing_wallet_session_jwt'
  | 'missing_signing_grant_id'
  | 'missing_threshold_session_id'
  | 'missing_signing_root'
  | 'signing_root_mismatch'
  | 'missing_material_handle'
  | 'missing_material_binding_digest'
  | 'missing_client_verifying_share'
  | 'material_identity_mismatch'
  | 'raw_material_without_handle'
  | 'missing_runtime_policy_scope'
  | 'missing_router_ab_state'
  | 'invalid_router_ab_state'
  | 'invalid_budget';

export type RouterAbSigningWalletSessionResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: RouterAbSigningWalletSessionParseFailureReason };

export type RouterAbEd25519PendingMaterialReason =
  | 'missing_material_handle'
  | 'missing_material_binding_digest'
  | 'missing_client_verifying_share';

type RouterAbPersistedSigningRecordState<TRecord, TSession> =
  | {
      kind: 'signable';
      record: TRecord;
      value: TSession;
      reason?: never;
    }
  | {
      kind: 'pending_material';
      record: TRecord;
      reason: RouterAbEd25519PendingMaterialReason;
      value?: never;
    }
  | {
      kind: 'non_signing';
      record: TRecord;
      reason: 'cookie_session';
      value?: never;
    }
  | {
      kind: 'invalid';
      record: TRecord | null;
      reason: RouterAbSigningWalletSessionParseFailureReason;
      value?: never;
    };

export type RouterAbEd25519PersistedSigningRecordState =
  RouterAbPersistedSigningRecordState<
    ThresholdEd25519SessionRecord,
    RouterAbEd25519SigningWalletSession
  >;

export type RouterAbEcdsaHssPersistedSigningRecordState =
  RouterAbPersistedSigningRecordState<
    ThresholdEcdsaSessionRecord,
    RouterAbEcdsaHssSigningWalletSession
  >;

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function buildWalletSessionJwtAuth(jwtRaw: unknown): RouterAbSigningWalletSessionAuth | null {
  const walletSessionJwt = nonEmptyString(jwtRaw);
  if (!walletSessionJwt) return null;
  return {
    kind: 'wallet_session_jwt',
    walletSessionJwt,
    credential: {
      kind: 'jwt',
      walletSessionJwt,
    },
  };
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
): RouterAbSigningWalletSessionResult<RouterAbEd25519SigningWalletSession> {
  if (!record) return { ok: false, reason: 'missing_record' };
  if (record.thresholdSessionKind !== 'jwt') return { ok: false, reason: 'cookie_session' };
  const auth = buildWalletSessionJwtAuth(record.walletSessionJwt);
  if (!auth) return { ok: false, reason: 'missing_wallet_session_jwt' };
  const thresholdSessionId = nonEmptyString(record.thresholdSessionId);
  if (!thresholdSessionId) return { ok: false, reason: 'missing_threshold_session_id' };
  const signingGrantId = nonEmptyString(record.signingGrantId);
  if (!signingGrantId) {
    return { ok: false, reason: 'missing_signing_grant_id' };
  }
  const signingRoot = resolveRouterAbEd25519SigningRootFromRecord(record);
  if (!signingRoot.ok) return signingRoot;
  const runtimePolicyScope = record.runtimePolicyScope;
  if (!runtimePolicyScope) return { ok: false, reason: 'missing_runtime_policy_scope' };
  const ed25519HssMaterialHandle = nonEmptyString(record.ed25519HssMaterialHandle);
  if (!ed25519HssMaterialHandle) {
    if (nonEmptyString(record.xClientBaseB64u)) {
      return { ok: false, reason: 'raw_material_without_handle' };
    }
    return { ok: false, reason: 'missing_material_handle' };
  }
  const ed25519HssMaterialBindingDigest = nonEmptyString(
    record.ed25519HssMaterialBindingDigest,
  );
  if (!ed25519HssMaterialBindingDigest) {
    return { ok: false, reason: 'missing_material_binding_digest' };
  }
  const clientVerifyingShareB64u = nonEmptyString(record.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, reason: 'missing_client_verifying_share' };
  }
  const signingMaterial = buildRouterAbEd25519SigningMaterialRef({
    materialHandle: ed25519HssMaterialHandle,
    bindingDigest: ed25519HssMaterialBindingDigest,
    clientVerifyingShareB64u,
  });
  if (!record.routerAbNormalSigning) return { ok: false, reason: 'missing_router_ab_state' };
  const remainingUses = positiveInteger(record.remainingUses);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (!remainingUses || !expiresAtMs) return { ok: false, reason: 'invalid_budget' };
  return {
    ok: true,
    value: {
      curve: 'ed25519',
      auth,
      thresholdSessionId,
      signingGrantId,
      remainingUses,
      expiresAtMs,
      signingMaterial,
      runtimePolicyScope,
      signingRootId: signingRoot.value.signingRootId,
      signingRootVersion: signingRoot.value.signingRootVersion,
      routerAbNormalSigning: record.routerAbNormalSigning,
    },
  };
}

export function parseRouterAbEcdsaHssSigningWalletSessionFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): RouterAbSigningWalletSessionResult<RouterAbEcdsaHssSigningWalletSession> {
  if (!record) return { ok: false, reason: 'missing_record' };
  if (record.thresholdSessionKind !== 'jwt') return { ok: false, reason: 'cookie_session' };
  const resolvedAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  if (resolvedAuth.kind !== 'ready') {
    return { ok: false, reason: resolvedAuth.reason };
  }
  const auth = buildWalletSessionJwtAuth(resolvedAuth.walletSessionJwt);
  if (!auth) return { ok: false, reason: 'missing_wallet_session_jwt' };
  const thresholdSessionId = nonEmptyString(record.thresholdSessionId);
  if (!thresholdSessionId) return { ok: false, reason: 'missing_threshold_session_id' };
  const signingGrantId = nonEmptyString(record.signingGrantId);
  if (!signingGrantId) {
    return { ok: false, reason: 'missing_signing_grant_id' };
  }
  if (!record.runtimePolicyScope) return { ok: false, reason: 'missing_runtime_policy_scope' };
  if (!record.routerAbEcdsaHssNormalSigning) {
    return { ok: false, reason: 'missing_router_ab_state' };
  }
  let signingMaterial: RouterAbEcdsaHssSigningMaterialRef;
  try {
    signingMaterial = buildRouterAbEcdsaHssSigningMaterialRef({
      routerAbState: record.routerAbEcdsaHssNormalSigning,
    });
  } catch {
    return { ok: false, reason: 'invalid_router_ab_state' };
  }
  const clientVerifyingShareB64u = nonEmptyString(record.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, reason: 'missing_client_verifying_share' };
  }
  if (clientVerifyingShareB64u !== signingMaterial.clientVerifier33B64u) {
    return { ok: false, reason: 'material_identity_mismatch' };
  }
  const remainingUses = positiveInteger(record.remainingUses);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (!remainingUses || !expiresAtMs) return { ok: false, reason: 'invalid_budget' };
  return {
    ok: true,
    value: {
      curve: 'ecdsa',
      auth,
      thresholdSessionId,
      signingGrantId,
      remainingUses,
      expiresAtMs,
      signingMaterial,
      runtimePolicyScope: record.runtimePolicyScope,
      routerAbEcdsaHssNormalSigning: record.routerAbEcdsaHssNormalSigning,
    },
  };
}

function isEd25519PendingMaterialReason(
  reason: RouterAbSigningWalletSessionParseFailureReason,
): reason is RouterAbEd25519PendingMaterialReason {
  return (
    reason === 'missing_material_handle' ||
    reason === 'missing_material_binding_digest' ||
    reason === 'missing_client_verifying_share'
  );
}

export function classifyRouterAbEd25519PersistedSigningRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): RouterAbEd25519PersistedSigningRecordState {
  if (!record) {
    return {
      kind: 'invalid',
      record: null,
      reason: 'missing_record',
    };
  }
  const parsed = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (parsed.ok) {
    return {
      kind: 'signable',
      record,
      value: parsed.value,
    };
  }
  if (parsed.reason === 'cookie_session') {
    return {
      kind: 'non_signing',
      record,
      reason: 'cookie_session',
    };
  }
  if (isEd25519PendingMaterialReason(parsed.reason)) {
    return {
      kind: 'pending_material',
      record,
      reason: parsed.reason,
    };
  }
  return {
    kind: 'invalid',
    record,
    reason: parsed.reason,
  };
}

export function classifyRouterAbEcdsaHssPersistedSigningRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): RouterAbEcdsaHssPersistedSigningRecordState {
  if (!record) {
    return {
      kind: 'invalid',
      record: null,
      reason: 'missing_record',
    };
  }
  const parsed = parseRouterAbEcdsaHssSigningWalletSessionFromRecord(record);
  if (parsed.ok) {
    return {
      kind: 'signable',
      record,
      value: parsed.value,
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

export function requireRouterAbEd25519SigningWalletSessionFromRecord(
  record: ThresholdEd25519SessionRecord | null | undefined,
): RouterAbEd25519SigningWalletSession {
  const parsed = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (parsed.ok) return parsed.value;
  throw new Error(`[wallet-session] Ed25519 signing Wallet Session is invalid: ${parsed.reason}`);
}

export function requireRouterAbEcdsaHssSigningWalletSessionFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): RouterAbEcdsaHssSigningWalletSession {
  const parsed = parseRouterAbEcdsaHssSigningWalletSessionFromRecord(record);
  if (parsed.ok) return parsed.value;
  throw new Error(`[wallet-session] ECDSA-HSS signing Wallet Session is invalid: ${parsed.reason}`);
}
