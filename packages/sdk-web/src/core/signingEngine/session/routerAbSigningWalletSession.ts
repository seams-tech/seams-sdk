import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from './persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from './warmCapabilities/routerAbEcdsaWalletSessionAuth';
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
  | 'missing_runtime_policy_scope'
  | 'missing_router_ab_state'
  | 'invalid_router_ab_state'
  | 'invalid_budget';

export type RouterAbSigningWalletSessionResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: RouterAbSigningWalletSessionParseFailureReason };

export type RouterAbEd25519AuthReadyMaterialPendingReason =
  | 'missing_material_handle'
  | 'missing_material_binding_digest'
  | 'missing_client_verifying_share';

export type RouterAbEd25519MaterialHintUnvalidatedReason = 'worker_material_unvalidated';

type RouterAbEd25519PersistedSigningRecordStateBase<TRecord, TSession> =
  | {
      kind: 'runtime_validated';
      record: TRecord;
      value: TSession;
      reason?: never;
    }
  | {
      kind: 'restore_available';
      record: TRecord;
      reason: 'loaded_material_missing';
      value?: never;
    }
  | {
      kind: 'material_hint_unvalidated';
      record: TRecord;
      reason: RouterAbEd25519MaterialHintUnvalidatedReason;
      value?: never;
    }
  | {
      kind: 'auth_ready_material_pending';
      record: TRecord;
      reason: RouterAbEd25519AuthReadyMaterialPendingReason;
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
  RouterAbEd25519PersistedSigningRecordStateBase<
  ThresholdEd25519SessionRecord,
  RouterAbEd25519SigningWalletSession
>;

export type RouterAbEcdsaHssPersistedSigningRecordState =
  | {
      kind: 'signable';
      record: ThresholdEcdsaSessionRecord;
      value: RouterAbEcdsaHssSigningWalletSession;
      reason?: never;
    }
  | {
      kind: 'non_signing';
      record: ThresholdEcdsaSessionRecord;
      reason: 'cookie_session';
      value?: never;
    }
  | {
      kind: 'invalid';
      record: ThresholdEcdsaSessionRecord | null;
      reason: RouterAbSigningWalletSessionParseFailureReason;
      value?: never;
    };

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

const routerAbEd25519RuntimeValidatedMaterialKeys = new Set<string>();

function routerAbEd25519RuntimeMaterialKey(session: RouterAbEd25519SigningWalletSession): string {
  return [
    session.thresholdSessionId,
    session.signingGrantId,
    session.auth.walletSessionJwt,
    session.signingMaterial.materialHandle,
    session.signingMaterial.bindingDigest,
    session.signingMaterial.clientVerifierB64u,
    session.signingRootId,
    session.signingRootVersion,
    session.routerAbNormalSigning.signingWorkerId,
  ].join('\x1f');
}

export function markRouterAbEd25519WorkerMaterialRuntimeValidated(
  record: ThresholdEd25519SessionRecord | null | undefined,
): boolean {
  const parsed = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (!parsed.ok) return false;
  routerAbEd25519RuntimeValidatedMaterialKeys.add(routerAbEd25519RuntimeMaterialKey(parsed.value));
  return true;
}

export function isRouterAbEd25519WorkerMaterialRuntimeValidated(
  record: ThresholdEd25519SessionRecord | null | undefined,
): boolean {
  const parsed = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (!parsed.ok) return false;
  return routerAbEd25519RuntimeValidatedMaterialKeys.has(
    routerAbEd25519RuntimeMaterialKey(parsed.value),
  );
}

export function clearRouterAbEd25519WorkerMaterialRuntimeValidation(): void {
  routerAbEd25519RuntimeValidatedMaterialKeys.clear();
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

function resolveRouterAbEcdsaHssSigningIdentityFromRecord(
  record: Pick<
    ThresholdEcdsaSessionRecord,
    'ecdsaThresholdKeyId' | 'runtimePolicyScope' | 'signingRootId' | 'signingRootVersion'
  >,
): RouterAbSigningWalletSessionResult<{
  ecdsaThresholdKeyId: string;
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

  const ecdsaThresholdKeyId = nonEmptyString(record.ecdsaThresholdKeyId);
  if (!ecdsaThresholdKeyId) {
    return { ok: false, reason: 'material_identity_mismatch' };
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
      ecdsaThresholdKeyId,
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
  const ed25519WorkerMaterialHandle = nonEmptyString(record.ed25519WorkerMaterialHandle);
  if (!ed25519WorkerMaterialHandle) {
    return { ok: false, reason: 'missing_material_handle' };
  }
  const ed25519WorkerMaterialBindingDigest = nonEmptyString(record.ed25519WorkerMaterialBindingDigest);
  if (!ed25519WorkerMaterialBindingDigest) {
    return { ok: false, reason: 'missing_material_binding_digest' };
  }
  const clientVerifyingShareB64u = nonEmptyString(record.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, reason: 'missing_client_verifying_share' };
  }
  const signingMaterial = buildRouterAbEd25519SigningMaterialRef({
    materialHandle: ed25519WorkerMaterialHandle,
    bindingDigest: ed25519WorkerMaterialBindingDigest,
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
  const identity = resolveRouterAbEcdsaHssSigningIdentityFromRecord(record);
  if (!identity.ok) return identity;
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
  if (identity.value.ecdsaThresholdKeyId !== signingMaterial.ecdsaThresholdKeyId) {
    return { ok: false, reason: 'material_identity_mismatch' };
  }
  if (
    identity.value.signingRootId !== signingMaterial.signingRootId ||
    identity.value.signingRootVersion !== signingMaterial.signingRootVersion
  ) {
    return { ok: false, reason: 'signing_root_mismatch' };
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

function isEd25519AuthReadyMaterialPendingReason(
  reason: RouterAbSigningWalletSessionParseFailureReason,
): reason is RouterAbEd25519AuthReadyMaterialPendingReason {
  return (
    reason === 'missing_material_handle' ||
    reason === 'missing_material_binding_digest' ||
    reason === 'missing_client_verifying_share'
  );
}

function hasEd25519SealedWorkerMaterial(record: ThresholdEd25519SessionRecord): boolean {
  return Boolean(
    record.thresholdSessionKind === 'jwt' &&
    nonEmptyString(record.thresholdSessionId) &&
    nonEmptyString(record.signingGrantId) &&
    nonEmptyString(record.walletSessionJwt) &&
    nonEmptyString(record.sealedWorkerMaterialRef) &&
    nonEmptyString(record.ed25519WorkerMaterialBindingDigest) &&
    nonEmptyString(record.clientVerifyingShareB64u) &&
    nonEmptyString(record.materialFormatVersion) &&
    nonEmptyString(record.materialKeyId) &&
    positiveInteger(record.signerSlot) &&
    nonEmptyString(record.keyVersion),
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
    if (isRouterAbEd25519WorkerMaterialRuntimeValidated(record)) {
      return {
        kind: 'runtime_validated',
        record,
        value: parsed.value,
      };
    }
    if (hasEd25519SealedWorkerMaterial(record)) {
      return {
        kind: 'restore_available',
        record,
        reason: 'loaded_material_missing',
      };
    }
    return {
      kind: 'material_hint_unvalidated',
      record,
      reason: 'worker_material_unvalidated',
    };
  }
  if (parsed.reason === 'cookie_session') {
    return {
      kind: 'non_signing',
      record,
      reason: 'cookie_session',
    };
  }
  if (parsed.reason === 'missing_material_handle' && hasEd25519SealedWorkerMaterial(record)) {
    return {
      kind: 'restore_available',
      record,
      reason: 'loaded_material_missing',
    };
  }
  if (isEd25519AuthReadyMaterialPendingReason(parsed.reason)) {
    return {
      kind: 'auth_ready_material_pending',
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

export function requireRouterAbEcdsaHssSigningWalletSessionFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): RouterAbEcdsaHssSigningWalletSession {
  const parsed = parseRouterAbEcdsaHssSigningWalletSessionFromRecord(record);
  if (parsed.ok) return parsed.value;
  throw new Error(`[wallet-session] ECDSA-HSS signing Wallet Session is invalid: ${parsed.reason}`);
}
