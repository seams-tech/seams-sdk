import type { RouterAbWalletSessionCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from './persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import {
  routerAbEcdsaDerivationActiveStateSessionId,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  decodeJwtPayloadRecord,
} from '@shared/utils/sessionTokens';
import { sha256 } from '@noble/hashes/sha2.js';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from './warmCapabilities/routerAbEcdsaWalletSessionAuth';
import { buildEcdsaRoleLocalSigningMaterialHandle } from './identity/ecdsaDerivationSigningMaterialHandle';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
} from './keyMaterialBrands';
import {
  buildRouterAbEcdsaDerivationSigningMaterialRef,
  type RouterAbEcdsaDerivationSigningMaterialRef,
} from '../routerAb/ecdsaDerivation/signingMaterialRef';

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

export type RouterAbEcdsaDerivationSigningWalletSession = {
  curve: 'ecdsa';
  auth: RouterAbSigningWalletSessionAuth;
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses: number;
  expiresAtMs: number;
  signingMaterial: RouterAbEcdsaDerivationSigningMaterialRef;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  clientVerifyingShareB64u?: never;
  clientSigningShare32?: never;
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

export type RouterAbEcdsaDerivationWalletSessionCredentialFingerprint = {
  kind: 'router_ab_ecdsa_derivation_wallet_session_credential_fingerprint_v1';
  payloadKind: typeof ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND;
  payloadDigestB64u: string;
};

export type EcdsaDerivationRuntimeMaterialValidationKey = {
  kind: 'ecdsa_derivation_runtime_material_validation_key_v1';
  materialHandle: string;
  materialBindingDigest: string;
  thresholdSessionId: string;
  signingGrantId: string;
  walletSessionCredentialFingerprint: RouterAbEcdsaDerivationWalletSessionCredentialFingerprint;
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

export type RouterAbEcdsaDerivationPersistedSigningRecordState =
  | {
      kind: 'runtime_validated';
      record: ThresholdEcdsaSessionRecord;
      value: RouterAbEcdsaDerivationSigningWalletSession;
      reason?: never;
    }
  | {
      kind: 'restore_available';
      record: ThresholdEcdsaSessionRecord;
      reason: 'loaded_material_missing';
      value?: never;
    }
  | {
      kind: 'expired';
      record: ThresholdEcdsaSessionRecord;
      reason: 'expired';
      expiresAtMs: number;
      value?: never;
    }
  | {
      kind: 'exhausted';
      record: ThresholdEcdsaSessionRecord;
      reason: 'exhausted';
      remainingUses: number;
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
  if (!walletId || !nearAccountId || !nearEd25519SigningKeyId || !thresholdSessionId || !signingGrantId) {
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

const routerAbEcdsaDerivationRuntimeValidatedMaterialKeys = new Set<string>();

function buildRouterAbEcdsaDerivationWalletSessionCredentialFingerprint(
  walletSessionJwt: string,
): RouterAbEcdsaDerivationWalletSessionCredentialFingerprint | null {
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND) {
    return null;
  }
  return {
    kind: 'router_ab_ecdsa_derivation_wallet_session_credential_fingerprint_v1',
    payloadKind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    payloadDigestB64u: sha256CanonicalB64uSync(payload),
  };
}


function buildEcdsaDerivationRoleLocalMaterialHandleFromRecord(input: {
  record: ThresholdEcdsaSessionRecord;
  signingMaterial: RouterAbEcdsaDerivationSigningMaterialRef;
}): ReturnType<typeof buildEcdsaRoleLocalSigningMaterialHandle> | null {
  const routerAbState = input.record.routerAbEcdsaDerivationNormalSigning;
  if (!routerAbState) return null;
  try {
    return buildEcdsaRoleLocalSigningMaterialHandle({
      thresholdSessionId: input.record.thresholdSessionId,
      signingGrantId: input.record.signingGrantId,
      keyHandle: parseEcdsaKeyHandle(input.record.keyHandle),
      routerAbStateSessionId: input.signingMaterial.routerAbStateSessionId,
      chainTarget: input.record.chainTarget,
      clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(
        input.signingMaterial.clientVerifier33B64u,
      ),
      ecdsaThresholdKeyId: input.signingMaterial.ecdsaThresholdKeyId,
      participantIds: input.record.participantIds,
      relayerKeyId: parseEcdsaRelayerKeyId(input.record.relayerKeyId),
    });
  } catch {
    return null;
  }
}

function buildEcdsaDerivationRuntimeMaterialValidationKey(input: {
  record: ThresholdEcdsaSessionRecord;
  session: RouterAbEcdsaDerivationSigningWalletSession;
}): EcdsaDerivationRuntimeMaterialValidationKey | null {
  const state = input.session.routerAbEcdsaDerivationNormalSigning;
  const signingMaterial = input.session.signingMaterial;
  const materialHandle = buildEcdsaDerivationRoleLocalMaterialHandleFromRecord({
    record: input.record,
    signingMaterial,
  });
  const walletSessionCredentialFingerprint =
    buildRouterAbEcdsaDerivationWalletSessionCredentialFingerprint(input.session.auth.walletSessionJwt);
  if (!materialHandle || !walletSessionCredentialFingerprint) return null;
  const activationEpoch = nonEmptyString(state.scope.activation_epoch);
  const keyHandle = nonEmptyString(input.record.keyHandle);
  const signingWorkerId = signingMaterial.signingWorkerId;
  if (!activationEpoch || !keyHandle || !signingWorkerId) return null;
  return {
    kind: 'ecdsa_derivation_runtime_material_validation_key_v1',
    materialHandle: materialHandle.materialHandle,
    materialBindingDigest: materialHandle.bindingDigest,
    thresholdSessionId: input.session.thresholdSessionId,
    signingGrantId: input.session.signingGrantId,
    walletSessionCredentialFingerprint,
    routerAbStateSessionId: routerAbEcdsaDerivationActiveStateSessionId(state),
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

function serializeEcdsaDerivationRuntimeMaterialValidationKey(
  key: EcdsaDerivationRuntimeMaterialValidationKey,
): string {
  return alphabetizeStringify(key);
}

export function markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): boolean {
  if (!record) return false;
  const parsed = parseRouterAbEcdsaDerivationSigningWalletSessionFromRecord(record);
  if (!parsed.ok) return false;
  const key = buildEcdsaDerivationRuntimeMaterialValidationKey({
    record,
    session: parsed.value,
  });
  if (!key) return false;
  routerAbEcdsaDerivationRuntimeValidatedMaterialKeys.add(
    serializeEcdsaDerivationRuntimeMaterialValidationKey(key),
  );
  return true;
}

export function isRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): boolean {
  if (!record) return false;
  const parsed = parseRouterAbEcdsaDerivationSigningWalletSessionFromRecord(record);
  if (!parsed.ok) return false;
  const key = buildEcdsaDerivationRuntimeMaterialValidationKey({
    record,
    session: parsed.value,
  });
  return key
    ? routerAbEcdsaDerivationRuntimeValidatedMaterialKeys.has(
        serializeEcdsaDerivationRuntimeMaterialValidationKey(key),
      )
    : false;
}

export function clearRouterAbEcdsaDerivationWorkerMaterialRuntimeValidation(): void {
  routerAbEcdsaDerivationRuntimeValidatedMaterialKeys.clear();
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

function resolveRouterAbEcdsaDerivationSigningIdentityFromRecord(
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

export function parseRouterAbEcdsaDerivationSigningWalletSessionFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
  nowMs: number = currentActiveSessionNowMs(),
): RouterAbSigningWalletSessionResult<RouterAbEcdsaDerivationSigningWalletSession> {
  const operationNowMs = normalizeActiveSessionNowMs(nowMs);
  if (operationNowMs == null) return { ok: false, reason: 'invalid_budget' };
  if (!record) return { ok: false, reason: 'missing_record' };
  if (record.thresholdSessionKind !== 'jwt') return { ok: false, reason: 'cookie_session' };
  const resolvedAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  if (resolvedAuth.kind !== 'ready') {
    return { ok: false, reason: resolvedAuth.reason };
  }
  const auth = buildWalletSessionJwtAuth(resolvedAuth.walletSessionJwt);
  if (!auth) return { ok: false, reason: 'missing_wallet_session_jwt' };
  const { thresholdSessionId, signingGrantId } = resolvedAuth.identity;
  if (!record.runtimePolicyScope) return { ok: false, reason: 'missing_runtime_policy_scope' };
  if (!record.routerAbEcdsaDerivationNormalSigning) {
    return { ok: false, reason: 'missing_router_ab_state' };
  }
  const remainingUses = positiveInteger(record.remainingUses);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (
    !Number.isSafeInteger(record.remainingUses) ||
    !Number.isSafeInteger(record.expiresAtMs) ||
    record.remainingUses < 0 ||
    record.expiresAtMs <= 0
  ) {
    return { ok: false, reason: 'invalid_budget' };
  }
  const inactive = inactiveSigningSessionState({
    remainingUses: Math.max(0, Math.floor(Number(record.remainingUses) || 0)),
    expiresAtMs: Math.max(0, Math.floor(Number(record.expiresAtMs) || 0)),
    nowMs: operationNowMs,
  });
  if (inactive?.kind === 'exhausted') return { ok: false, reason: 'exhausted' };
  if (inactive?.kind === 'expired') return { ok: false, reason: 'expired' };
  const identity = resolveRouterAbEcdsaDerivationSigningIdentityFromRecord(record);
  if (!identity.ok) return identity;
  let signingMaterial: RouterAbEcdsaDerivationSigningMaterialRef;
  try {
    signingMaterial = buildRouterAbEcdsaDerivationSigningMaterialRef({
      routerAbState: record.routerAbEcdsaDerivationNormalSigning,
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
      routerAbEcdsaDerivationNormalSigning: record.routerAbEcdsaDerivationNormalSigning,
    },
  };
}

export function buildActiveRouterAbEcdsaDerivationSigningWalletSessionFromRecord(args: {
  record: ThresholdEcdsaSessionRecord | null | undefined;
  nowMs: number;
}): RouterAbSigningWalletSessionResult<RouterAbEcdsaDerivationSigningWalletSession> {
  return parseRouterAbEcdsaDerivationSigningWalletSessionFromRecord(args.record, args.nowMs);
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

export function classifyRouterAbEcdsaDerivationPersistedSigningRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
  nowMs: number = currentActiveSessionNowMs(),
): RouterAbEcdsaDerivationPersistedSigningRecordState {
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
  const parsed = buildActiveRouterAbEcdsaDerivationSigningWalletSessionFromRecord({
    record,
    nowMs: operationNowMs,
  });
  if (parsed.ok) {
    if (isRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) {
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

export function requireRouterAbEcdsaDerivationSigningWalletSessionFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): RouterAbEcdsaDerivationSigningWalletSession {
  const parsed = parseRouterAbEcdsaDerivationSigningWalletSessionFromRecord(record);
  if (parsed.ok) return parsed.value;
  throw new Error(`[wallet-session] Router A/B ECDSA derivation signing Wallet Session is invalid: ${parsed.reason}`);
}
