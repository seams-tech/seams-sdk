import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from './persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import {
  routerAbEcdsaHssActiveStateSessionId,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  decodeJwtPayloadRecord,
} from '@shared/utils/sessionTokens';
import { sha256 } from '@noble/hashes/sha2';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from './warmCapabilities/routerAbEcdsaWalletSessionAuth';
import { buildEcdsaRoleLocalSigningMaterialHandle } from './identity/ecdsaHssSigningMaterialHandle';
import {
  buildRouterAbEd25519SigningMaterialRef,
  buildRouterAbEd25519WorkerMaterialSessionBinding,
  type RouterAbEd25519SigningMaterialRef,
} from '../threshold/ed25519/workerMaterialBinding';
import {
  parseEd25519RelayerKeyId,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  type Ed25519ClientVerifyingShareB64u,
  type Ed25519WorkerMaterialBindingDigest,
  type Ed25519WorkerMaterialHandle,
} from './keyMaterialBrands';
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
  | 'wallet_binding_mismatch'
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

export type RouterAbEd25519WalletSessionCredentialFingerprint = {
  kind: 'router_ab_ed25519_wallet_session_credential_fingerprint_v1';
  payloadKind: typeof ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND;
  payloadDigestB64u: string;
};

export type RouterAbEcdsaHssWalletSessionCredentialFingerprint = {
  kind: 'router_ab_ecdsa_hss_wallet_session_credential_fingerprint_v1';
  payloadKind: typeof ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND;
  payloadDigestB64u: string;
};

export type Ed25519WorkerMaterialValidationKey = {
  kind: 'ed25519_worker_material_validation_key_v1';
  materialHandle: Ed25519WorkerMaterialHandle;
  materialBindingDigest: Ed25519WorkerMaterialBindingDigest;
  sessionBindingDigest: string;
  thresholdSessionId: string;
  signingGrantId: string;
  walletSessionCredentialFingerprint: RouterAbEd25519WalletSessionCredentialFingerprint;
  clientVerifierB64u: Ed25519ClientVerifyingShareB64u;
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingWorkerId: string;
  expiresAtMs: number;
};

export type Ed25519WorkerMaterialRuntimeValidationFailureReason =
  | 'worker_material_missing'
  | 'binding_digest_mismatch'
  | 'session_binding_mismatch'
  | 'signing_root_mismatch'
  | 'signing_worker_mismatch'
  | 'verifier_mismatch'
  | 'expired'
  | 'credential_mismatch';

export type Ed25519WorkerMaterialRuntimeValidationResult =
  | {
      ok: true;
      key: Ed25519WorkerMaterialValidationKey;
    }
  | {
      ok: false;
      reason: Ed25519WorkerMaterialRuntimeValidationFailureReason;
      parseReason?: RouterAbSigningWalletSessionParseFailureReason;
    };

export type EcdsaHssRuntimeMaterialValidationKey = {
  kind: 'ecdsa_hss_runtime_material_validation_key_v1';
  materialHandle: string;
  materialBindingDigest: string;
  thresholdSessionId: string;
  signingGrantId: string;
  walletSessionCredentialFingerprint: RouterAbEcdsaHssWalletSessionCredentialFingerprint;
  routerAbStateSessionId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  activationEpoch: string;
  keyHandle: string;
  chainTarget: ThresholdEcdsaSessionRecord['chainTarget'];
  participantIds: readonly number[];
  clientVerifier33B64u: string;
  serverVerifier33B64u: string;
  thresholdVerifier33B64u: string;
  signingWorkerId: string;
  expiresAtMs: number;
};

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
      kind: 'runtime_validated';
      record: ThresholdEcdsaSessionRecord;
      value: RouterAbEcdsaHssSigningWalletSession;
      reason?: never;
    }
  | {
      kind: 'restore_available';
      record: ThresholdEcdsaSessionRecord;
      reason: 'loaded_material_missing';
      value?: never;
    }
  | {
      kind: 'material_hint_unvalidated';
      record: ThresholdEcdsaSessionRecord;
      reason: 'worker_material_unvalidated';
      value?: never;
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
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function sha256CanonicalB64uSync(input: unknown): string {
  return base64UrlEncode(sha256(new TextEncoder().encode(alphabetizeStringify(input))));
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

export type RouterAbEd25519WalletSessionIdentityClaims = {
  walletId: string;
  nearAccountId: string;
  ed25519KeyScopeId: string;
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
  const ed25519KeyScopeId = nonEmptyString(payload.ed25519KeyScopeId);
  const thresholdSessionId = nonEmptyString(payload.thresholdSessionId);
  const signingGrantId = nonEmptyString(payload.signingGrantId);
  if (!walletId || !nearAccountId || !ed25519KeyScopeId || !thresholdSessionId || !signingGrantId) {
    return null;
  }
  return {
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
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
    claims.ed25519KeyScopeId === nonEmptyString(record.ed25519KeyScopeId) &&
    claims.thresholdSessionId === nonEmptyString(record.thresholdSessionId) &&
    claims.signingGrantId === nonEmptyString(record.signingGrantId)
  );
}

const routerAbEd25519RuntimeValidatedMaterialKeys = new Set<string>();
const routerAbEcdsaHssRuntimeValidatedMaterialKeys = new Set<string>();

function buildRouterAbEd25519WalletSessionCredentialFingerprint(
  walletSessionJwt: string,
): RouterAbEd25519WalletSessionCredentialFingerprint | null {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND) {
    return null;
  }
  return {
    kind: 'router_ab_ed25519_wallet_session_credential_fingerprint_v1',
    payloadKind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    payloadDigestB64u: sha256CanonicalB64uSync(payload),
  };
}

function buildRouterAbEcdsaHssWalletSessionCredentialFingerprint(
  walletSessionJwt: string,
): RouterAbEcdsaHssWalletSessionCredentialFingerprint | null {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND) {
    return null;
  }
  return {
    kind: 'router_ab_ecdsa_hss_wallet_session_credential_fingerprint_v1',
    payloadKind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    payloadDigestB64u: sha256CanonicalB64uSync(payload),
  };
}

function buildRouterAbEd25519WorkerMaterialSessionBindingDigest(input: {
  record: ThresholdEd25519SessionRecord;
  session: RouterAbEd25519SigningWalletSession;
}): string | null {
  const nearAccountId = nonEmptyString(input.record.nearAccountId);
  const signerSlot = positiveInteger(input.record.signerSlot);
  const relayerKeyIdRaw = nonEmptyString(input.record.relayerKeyId);
  const participantIds = Array.isArray(input.record.participantIds)
    ? input.record.participantIds
    : [];
  if (!nearAccountId || !signerSlot || !relayerKeyIdRaw || participantIds.length === 0) {
    return null;
  }
  const relayerKeyId = parseEd25519RelayerKeyId(relayerKeyIdRaw);
  try {
    return sha256CanonicalB64uSync(
      buildRouterAbEd25519WorkerMaterialSessionBinding({
        materialBindingDigest: input.session.signingMaterial.bindingDigest,
        nearAccountId,
        signerSlot,
        thresholdSessionId: input.session.thresholdSessionId,
        signingGrantId: input.session.signingGrantId,
        signingRootId: input.session.signingRootId,
        signingRootVersion: input.session.signingRootVersion,
        runtimePolicyScope: input.session.runtimePolicyScope,
        relayerKeyId,
        participantIds,
        signingWorkerId: input.session.routerAbNormalSigning.signingWorkerId,
        expiresAtMs: input.session.expiresAtMs,
      }),
    );
  } catch {
    return null;
  }
}

function buildEd25519WorkerMaterialValidationKey(input: {
  record: ThresholdEd25519SessionRecord;
  session: RouterAbEd25519SigningWalletSession;
}): Ed25519WorkerMaterialValidationKey | null {
  const sessionBindingDigest = buildRouterAbEd25519WorkerMaterialSessionBindingDigest(input);
  const walletSessionCredentialFingerprint =
    buildRouterAbEd25519WalletSessionCredentialFingerprint(input.session.auth.walletSessionJwt);
  if (!sessionBindingDigest || !walletSessionCredentialFingerprint) {
    return null;
  }
  return {
    kind: 'ed25519_worker_material_validation_key_v1',
    materialHandle: input.session.signingMaterial.materialHandle,
    materialBindingDigest: input.session.signingMaterial.bindingDigest,
    sessionBindingDigest,
    thresholdSessionId: input.session.thresholdSessionId,
    signingGrantId: input.session.signingGrantId,
    walletSessionCredentialFingerprint,
    clientVerifierB64u: input.session.signingMaterial.clientVerifierB64u,
    signingRootId: input.session.signingRootId,
    signingRootVersion: input.session.signingRootVersion,
    runtimePolicyScope: input.session.runtimePolicyScope,
    signingWorkerId: input.session.routerAbNormalSigning.signingWorkerId,
    expiresAtMs: input.session.expiresAtMs,
  };
}

function serializeEd25519WorkerMaterialValidationKey(
  key: Ed25519WorkerMaterialValidationKey,
): string {
  return alphabetizeStringify(key);
}

function ed25519WorkerMaterialValidationFailureFromParseReason(
  reason: RouterAbSigningWalletSessionParseFailureReason,
): Ed25519WorkerMaterialRuntimeValidationFailureReason {
  switch (reason) {
    case 'missing_material_handle':
      return 'worker_material_missing';
    case 'missing_material_binding_digest':
      return 'binding_digest_mismatch';
    case 'missing_client_verifying_share':
    case 'material_identity_mismatch':
      return 'verifier_mismatch';
    case 'missing_signing_root':
    case 'signing_root_mismatch':
      return 'signing_root_mismatch';
    case 'missing_router_ab_state':
    case 'invalid_router_ab_state':
      return 'signing_worker_mismatch';
    case 'invalid_budget':
      return 'expired';
    case 'missing_record':
    case 'cookie_session':
    case 'missing_wallet_session_jwt':
    case 'wallet_binding_mismatch':
    case 'missing_signing_grant_id':
    case 'missing_threshold_session_id':
    case 'missing_runtime_policy_scope':
      return 'credential_mismatch';
  }
}

export function resolveRouterAbEd25519WorkerMaterialRuntimeValidation(
  record: ThresholdEd25519SessionRecord | null | undefined,
): Ed25519WorkerMaterialRuntimeValidationResult {
  if (!record) {
    return { ok: false, reason: 'credential_mismatch', parseReason: 'missing_record' };
  }
  const parsed = parseRouterAbEd25519SigningWalletSessionFromRecord(record);
  if (!parsed.ok) {
    return {
      ok: false,
      reason: ed25519WorkerMaterialValidationFailureFromParseReason(parsed.reason),
      parseReason: parsed.reason,
    };
  }
  const key = buildEd25519WorkerMaterialValidationKey({
    record,
    session: parsed.value,
  });
  if (!key) {
    return { ok: false, reason: 'session_binding_mismatch' };
  }
  return { ok: true, key };
}

function buildEcdsaHssRoleLocalMaterialHandleFromRecord(input: {
  record: ThresholdEcdsaSessionRecord;
  signingMaterial: RouterAbEcdsaHssSigningMaterialRef;
}): ReturnType<typeof buildEcdsaRoleLocalSigningMaterialHandle> | null {
  const routerAbState = input.record.routerAbEcdsaHssNormalSigning;
  if (!routerAbState) return null;
  try {
    return buildEcdsaRoleLocalSigningMaterialHandle({
      thresholdSessionId: input.record.thresholdSessionId,
      signingGrantId: input.record.signingGrantId,
      keyHandle: parseEcdsaKeyHandle(input.record.keyHandle),
      routerAbStateSessionId: input.signingMaterial.routerAbStateSessionId,
      chainTarget: input.record.chainTarget,
      clientVerifyingShareB64u: input.signingMaterial.clientVerifier33B64u,
      ecdsaThresholdKeyId: input.signingMaterial.ecdsaThresholdKeyId,
      participantIds: input.record.participantIds,
      relayerKeyId: parseEcdsaRelayerKeyId(input.record.relayerKeyId),
    });
  } catch {
    return null;
  }
}

function buildEcdsaHssRuntimeMaterialValidationKey(input: {
  record: ThresholdEcdsaSessionRecord;
  session: RouterAbEcdsaHssSigningWalletSession;
}): EcdsaHssRuntimeMaterialValidationKey | null {
  const state = input.session.routerAbEcdsaHssNormalSigning;
  const signingMaterial = input.session.signingMaterial;
  const materialHandle = buildEcdsaHssRoleLocalMaterialHandleFromRecord({
    record: input.record,
    signingMaterial,
  });
  const walletSessionCredentialFingerprint =
    buildRouterAbEcdsaHssWalletSessionCredentialFingerprint(input.session.auth.walletSessionJwt);
  if (!materialHandle || !walletSessionCredentialFingerprint) return null;
  const activationEpoch = nonEmptyString(state.scope.activation_epoch);
  const keyHandle = nonEmptyString(input.record.keyHandle);
  const signingWorkerId = signingMaterial.signingWorkerId;
  if (!activationEpoch || !keyHandle || !signingWorkerId) return null;
  return {
    kind: 'ecdsa_hss_runtime_material_validation_key_v1',
    materialHandle: materialHandle.materialHandle,
    materialBindingDigest: materialHandle.bindingDigest,
    thresholdSessionId: input.session.thresholdSessionId,
    signingGrantId: input.session.signingGrantId,
    walletSessionCredentialFingerprint,
    routerAbStateSessionId: routerAbEcdsaHssActiveStateSessionId(state),
    ecdsaThresholdKeyId: signingMaterial.ecdsaThresholdKeyId,
    signingRootId: signingMaterial.signingRootId,
    signingRootVersion: signingMaterial.signingRootVersion,
    activationEpoch,
    keyHandle,
    chainTarget: input.record.chainTarget,
    participantIds: input.record.participantIds.map((participantId) => Number(participantId)),
    clientVerifier33B64u: signingMaterial.clientVerifier33B64u,
    serverVerifier33B64u: signingMaterial.serverVerifier33B64u,
    thresholdVerifier33B64u: signingMaterial.thresholdVerifier33B64u,
    signingWorkerId,
    expiresAtMs: input.session.expiresAtMs,
  };
}

function serializeEcdsaHssRuntimeMaterialValidationKey(
  key: EcdsaHssRuntimeMaterialValidationKey,
): string {
  return alphabetizeStringify(key);
}

export function markRouterAbEd25519WorkerMaterialRuntimeValidated(
  record: ThresholdEd25519SessionRecord | null | undefined,
): boolean {
  const validation = resolveRouterAbEd25519WorkerMaterialRuntimeValidation(record);
  if (!validation.ok) return false;
  routerAbEd25519RuntimeValidatedMaterialKeys.add(
    serializeEd25519WorkerMaterialValidationKey(validation.key),
  );
  return true;
}

export function isRouterAbEd25519WorkerMaterialRuntimeValidated(
  record: ThresholdEd25519SessionRecord | null | undefined,
): boolean {
  const validation = resolveRouterAbEd25519WorkerMaterialRuntimeValidation(record);
  return validation.ok
    ? routerAbEd25519RuntimeValidatedMaterialKeys.has(
        serializeEd25519WorkerMaterialValidationKey(validation.key),
      )
    : false;
}

export function clearRouterAbEd25519WorkerMaterialRuntimeValidation(): void {
  routerAbEd25519RuntimeValidatedMaterialKeys.clear();
}

export function markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): boolean {
  if (!record) return false;
  const parsed = parseRouterAbEcdsaHssSigningWalletSessionFromRecord(record);
  if (!parsed.ok) return false;
  const key = buildEcdsaHssRuntimeMaterialValidationKey({
    record,
    session: parsed.value,
  });
  if (!key) return false;
  routerAbEcdsaHssRuntimeValidatedMaterialKeys.add(
    serializeEcdsaHssRuntimeMaterialValidationKey(key),
  );
  return true;
}

export function isRouterAbEcdsaHssWorkerMaterialRuntimeValidated(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): boolean {
  if (!record) return false;
  const parsed = parseRouterAbEcdsaHssSigningWalletSessionFromRecord(record);
  if (!parsed.ok) return false;
  const key = buildEcdsaHssRuntimeMaterialValidationKey({
    record,
    session: parsed.value,
  });
  return key
    ? routerAbEcdsaHssRuntimeValidatedMaterialKeys.has(
        serializeEcdsaHssRuntimeMaterialValidationKey(key),
      )
    : false;
}

export function clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation(): void {
  routerAbEcdsaHssRuntimeValidatedMaterialKeys.clear();
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
  const identityClaims = parseRouterAbEd25519WalletSessionIdentityClaims(auth.walletSessionJwt);
  if (!routerAbEd25519WalletSessionClaimsMatchRecord({ record, claims: identityClaims })) {
    return { ok: false, reason: 'wallet_binding_mismatch' };
  }
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
  if (!positiveInteger(record.signerSlot)) {
    return { ok: false, reason: 'material_identity_mismatch' };
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
    positiveInteger(record.signerSlot),
  );
}

export function hasRouterAbEd25519LoadedMaterialHint(
  state: RouterAbEd25519PersistedSigningRecordState,
): boolean {
  switch (state.kind) {
    case 'runtime_validated':
    case 'material_hint_unvalidated':
      return true;
    case 'restore_available':
      return Boolean(nonEmptyString(state.record.ed25519WorkerMaterialHandle));
    case 'auth_ready_material_pending':
    case 'non_signing':
    case 'invalid':
      return false;
    default: {
      const exhaustive: never = state;
      return exhaustive;
    }
  }
}

// Persisted records are durable hints. Only runtime_validated proves the current
// worker has loaded material for this exact session/grant/material binding.
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
    if (isRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)) {
      return {
        kind: 'runtime_validated',
        record,
        value: parsed.value,
      };
    }
    if (!record.clientAdditiveShareHandle) {
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
