import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../authorization/capabilityKinds';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '../authorization/capabilityKinds';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseWalletId as parseWalletIdResult,
  parseMpcMaterialActivationRef,
  mpcMaterialActivationRefsEqual,
  type WalletId,
} from './domainIds';
import type {
  MpcMaterialActivationRef,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
} from './domainIds';
import {
  parseThresholdEcdsaKeyHandle,
  type ThresholdEcdsaKeyHandle,
} from './thresholdEcdsaKeyHandle';
import { parseNearAccountId, type NearAccountId } from './near';
import { parseNearEd25519SigningKeyId, type NearEd25519SigningKeyId } from './registrationIntent';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '../threshold/signingRootScope';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from './signingSessionSeal';
import {
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from './routerAbEcdsaDerivation';
import { routerAbMpcMaterialActivationRefFromWire } from './routerAbNormalSigningIdentity';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '../device-linking/contracts';
import {
  parseActiveWalletSessionV1,
  parseWalletSessionOperationCredentialV1,
} from '../device-linking/parsers';

/**
 * Registration establishes one reusable authorization identity. Each curve
 * receives its own opaque bearer token and server-validated material binding.
 */
export type RegistrationEstablishedEcdsaSession = {
  readonly sessionKind: 'opaque';
  readonly walletSessionToken: string;
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly keyHandle: ThresholdEcdsaKeyHandle;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};

export type RegistrationEstablishedEd25519Session = {
  readonly sessionKind: 'opaque';
  readonly walletSessionToken: string;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly nearAccountId: NearAccountId;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type RegistrationEstablishedSessionTokens =
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly ecdsa: RegistrationEstablishedEcdsaSession;
      readonly ed25519?: never;
    }
  | {
      readonly kind: 'near_ed25519';
      readonly ed25519: RegistrationEstablishedEd25519Session;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'near_ed25519_and_evm_family_ecdsa';
      readonly ecdsa: RegistrationEstablishedEcdsaSession;
      readonly ed25519: RegistrationEstablishedEd25519Session;
    };

export type RegistrationEstablishedSession = {
  readonly kind: 'registration_established_wallet_session_v1';
  readonly walletId: WalletId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly tokens: RegistrationEstablishedSessionTokens;
};

/**
 * The registration journal's durable session projection. It keeps the
 * identities and signing context needed to rebuild a legacy response while
 * excluding every bearer credential.
 */
export type RegistrationEstablishedEcdsaSessionProjectionV2 = {
  readonly sessionKind: 'credential_free_projection_v2';
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly keyHandle: ThresholdEcdsaKeyHandle;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};

export type RegistrationEstablishedEd25519SessionProjectionV2 = {
  readonly sessionKind: 'credential_free_projection_v2';
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly nearAccountId: NearAccountId;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type RegistrationEstablishedSessionProjectionTokensV2 =
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly ecdsa: RegistrationEstablishedEcdsaSessionProjectionV2;
      readonly ed25519?: never;
    }
  | {
      readonly kind: 'near_ed25519';
      readonly ed25519: RegistrationEstablishedEd25519SessionProjectionV2;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'near_ed25519_and_evm_family_ecdsa';
      readonly ecdsa: RegistrationEstablishedEcdsaSessionProjectionV2;
      readonly ed25519: RegistrationEstablishedEd25519SessionProjectionV2;
    };

export type RegistrationEstablishedSessionProjectionV2 = {
  readonly kind: 'registration_established_wallet_session_projection_v2';
  readonly walletId: WalletId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly tokens: RegistrationEstablishedSessionProjectionTokensV2;
};

/**
 * The direct registration response keeps the primary credential beside the
 * exact browser record. Its runtime projection is shared with the receipt so
 * replay can return the same identity without recreating plaintext.
 */
export type RegistrationEstablishedSessionV2 = {
  readonly kind: 'registration_established_wallet_session_v2';
  readonly walletId: WalletId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly walletSession: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly tokens: RegistrationEstablishedSessionProjectionTokensV2;
};

export type RegistrationEstablishedSessionResultV2 =
  | {
      readonly kind: 'issued';
      readonly session: RegistrationEstablishedSessionV2;
    }
  | {
      readonly kind: 'already_committed';
      readonly session: RegistrationEstablishedSessionProjectionV2;
      readonly next: 'unlock_exact_method';
    };

export function parseRegistrationEstablishedSessionResultV2(
  raw: unknown,
): RegistrationEstablishedSessionResultV2 | null {
  if (!isRecord(raw) || typeof raw.kind !== 'string') return null;
  switch (raw.kind) {
    case 'issued': {
      if (!hasExactKeys(raw, ['kind', 'session'])) return null;
      const session = parseRegistrationEstablishedSessionV2(raw.session);
      return session === null ? null : { kind: 'issued', session };
    }
    case 'already_committed': {
      if (!hasExactKeys(raw, ['kind', 'session', 'next'])) return null;
      if (raw.next !== 'unlock_exact_method') return null;
      const session = parseRegistrationEstablishedSessionProjectionV2(raw.session);
      return session === null ? null : { kind: 'already_committed', session, next: raw.next };
    }
    default:
      return null;
  }
}

export function parseRegistrationEstablishedSessionV2(
  raw: unknown,
): RegistrationEstablishedSessionV2 | null {
  try {
    if (
      !isRecord(raw) ||
      !hasExactKeys(raw, [
        'kind',
        'walletId',
        'authorizationId',
        'walletSessionId',
        'quotaId',
        'expiresAtMs',
        'remainingUses',
        'walletSession',
        'operationCredential',
        'tokens',
      ]) ||
      raw.kind !== 'registration_established_wallet_session_v2'
    ) {
      return null;
    }
    const walletId = parseWalletIdResult(raw.walletId);
    const walletSessionId = parseWalletSessionId(raw.walletSessionId);
    const authorizationId = parseWalletSessionAuthorizationId(raw.authorizationId);
    const quotaId = parseMpcWalletSigningQuotaId(raw.quotaId);
    if (!walletId.ok || !authorizationId.ok || !walletSessionId.ok || !quotaId.ok) return null;
    const expiresAtMs = parseNonNegativeSafeInteger(raw.expiresAtMs);
    const remainingUses = parseNonNegativeSafeInteger(raw.remainingUses);
    if (expiresAtMs === null || expiresAtMs <= 0 || remainingUses === null || remainingUses <= 0) {
      return null;
    }
    const walletSession = parseActiveWalletSessionV1(raw.walletSession);
    const operationCredential = parseWalletSessionOperationCredentialV1(raw.operationCredential);
    if (
      walletSession.walletId !== walletId.value ||
      walletSession.authorizationId !== authorizationId.value ||
      walletSession.expiresAtMs !== expiresAtMs ||
      operationCredential.walletSessionId !== walletSessionId.value
    ) {
      return null;
    }
    const tokens = parseRegistrationEstablishedSessionProjectionTokensV2(raw.tokens);
    if (tokens === null) return null;
    if (!registrationSessionTokensMatchCapabilities(walletSession, tokens)) return null;
    return {
      kind: 'registration_established_wallet_session_v2',
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
      remainingUses,
      walletSession,
      operationCredential,
      tokens,
    };
  } catch {
    return null;
  }
}

function registrationSessionTokensMatchCapabilities(
  walletSession: ActiveWalletSessionV1,
  tokens: RegistrationEstablishedSessionProjectionTokensV2,
): boolean {
  switch (tokens.kind) {
    case 'evm_family_ecdsa':
      return hasRegistrationSigningCapability(
        walletSession,
        'ecdsa_secp256k1',
        tokens.ecdsa.materialActivation,
      ) && !hasUnexpectedRegistrationSigningFamily(walletSession, 'ecdsa_secp256k1');
    case 'near_ed25519':
      return hasRegistrationSigningCapability(
        walletSession,
        'ed25519',
        tokens.ed25519.materialActivation,
      ) && !hasUnexpectedRegistrationSigningFamily(walletSession, 'ed25519');
    case 'near_ed25519_and_evm_family_ecdsa':
      return (
        hasRegistrationSigningCapability(
          walletSession,
          'ecdsa_secp256k1',
          tokens.ecdsa.materialActivation,
        ) &&
        hasRegistrationSigningCapability(
          walletSession,
          'ed25519',
          tokens.ed25519.materialActivation,
        ) &&
        !hasUnexpectedRegistrationSigningFamily(walletSession, 'ed25519', 'ecdsa_secp256k1')
      );
    default:
      return false;
  }
}

function hasRegistrationSigningCapability(
  walletSession: ActiveWalletSessionV1,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  materialActivation: MpcMaterialActivationRef,
): boolean {
  return walletSession.capabilitySubjects.some(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === keyFamily &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, materialActivation),
  );
}

function hasUnexpectedRegistrationSigningFamily(
  walletSession: ActiveWalletSessionV1,
  ...allowedFamilies: readonly ('ed25519' | 'ecdsa_secp256k1')[]
): boolean {
  return walletSession.capabilitySubjects.some(
    (subject) =>
      subject.kind === 'sign' && !allowedFamilies.includes(subject.keyFamily),
  );
}

export function parseRegistrationEstablishedSessionProjectionV2(
  raw: unknown,
): RegistrationEstablishedSessionProjectionV2 | null {
  try {
    if (
      !isRecord(raw) ||
      !hasExactKeys(raw, [
        'kind',
        'walletId',
        'authorizationId',
        'walletSessionId',
        'quotaId',
        'expiresAtMs',
        'remainingUses',
        'tokens',
      ]) ||
      raw.kind !== 'registration_established_wallet_session_projection_v2'
    ) {
      return null;
    }
    const walletId = parseWalletIdResult(raw.walletId);
    const authorizationId = parseWalletSessionAuthorizationId(raw.authorizationId);
    const walletSessionId = parseWalletSessionId(raw.walletSessionId);
    const quotaId = parseMpcWalletSigningQuotaId(raw.quotaId);
    if (!walletId.ok || !authorizationId.ok || !walletSessionId.ok || !quotaId.ok) return null;
    if (new Set<string>([authorizationId.value, walletSessionId.value, quotaId.value]).size !== 3) {
      return null;
    }
    const expiresAtMs = parseNonNegativeSafeInteger(raw.expiresAtMs);
    const remainingUses = parseNonNegativeSafeInteger(raw.remainingUses);
    const tokens = parseRegistrationEstablishedSessionProjectionTokensV2(raw.tokens);
    if (
      expiresAtMs === null ||
      expiresAtMs <= 0 ||
      remainingUses === null ||
      remainingUses <= 0 ||
      tokens === null
    ) {
      return null;
    }
    return {
      kind: 'registration_established_wallet_session_projection_v2',
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
      remainingUses,
      tokens,
    };
  } catch {
    return null;
  }
}

function parseRegistrationEstablishedSessionProjectionTokensV2(
  raw: unknown,
): RegistrationEstablishedSessionProjectionTokensV2 | null {
  if (!isRecord(raw) || typeof raw.kind !== 'string') return null;
  switch (raw.kind) {
    case 'evm_family_ecdsa': {
      if (!hasExactKeys(raw, ['kind', 'ecdsa'])) return null;
      const ecdsa = parseRegistrationEstablishedEcdsaSessionProjectionV2(raw.ecdsa);
      return ecdsa === null ? null : { kind: 'evm_family_ecdsa', ecdsa };
    }
    case 'near_ed25519': {
      if (!hasExactKeys(raw, ['kind', 'ed25519'])) return null;
      const ed25519 = parseRegistrationEstablishedEd25519SessionProjectionV2(raw.ed25519);
      return ed25519 === null ? null : { kind: 'near_ed25519', ed25519 };
    }
    case 'near_ed25519_and_evm_family_ecdsa': {
      if (!hasExactKeys(raw, ['kind', 'ecdsa', 'ed25519'])) return null;
      const ecdsa = parseRegistrationEstablishedEcdsaSessionProjectionV2(raw.ecdsa);
      const ed25519 = parseRegistrationEstablishedEd25519SessionProjectionV2(raw.ed25519);
      return ecdsa === null || ed25519 === null
        ? null
        : { kind: 'near_ed25519_and_evm_family_ecdsa', ecdsa, ed25519 };
    }
    default:
      return null;
  }
}

function parseRegistrationEstablishedEcdsaSessionProjectionV2(
  raw: unknown,
): RegistrationEstablishedEcdsaSessionProjectionV2 | null {
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, [
      'sessionKind',
      'thresholdSessionId',
      'keyHandle',
      'runtimePolicyScope',
      'materialActivation',
      'routerAbEcdsaDerivationNormalSigning',
    ]) ||
    raw.sessionKind !== 'credential_free_projection_v2'
  ) {
    return null;
  }
  const thresholdSessionId = parseThresholdEcdsaSessionId(raw.thresholdSessionId);
  if (!thresholdSessionId.ok) return null;
  try {
    const keyHandle = parseThresholdEcdsaKeyHandle(raw.keyHandle);
    const runtimePolicyScope = parseRuntimePolicyScopeProjection(raw.runtimePolicyScope);
    const materialActivation = parseMpcMaterialActivationRef(raw.materialActivation);
    if (!materialActivation.ok) return null;
    const routerAbEcdsaDerivationNormalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1(
      raw.routerAbEcdsaDerivationNormalSigning,
    );
    if (!routerAbEcdsaDerivationNormalSigning) return null;
    const scopeMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
      routerAbEcdsaDerivationNormalSigning.scope.material_activation,
    );
    if (!mpcMaterialActivationRefsEqual(materialActivation.value, scopeMaterialActivation)) {
      return null;
    }
    return {
      sessionKind: 'credential_free_projection_v2',
      thresholdSessionId: thresholdSessionId.value,
      keyHandle,
      runtimePolicyScope,
      materialActivation: materialActivation.value,
      routerAbEcdsaDerivationNormalSigning,
    };
  } catch {
    return null;
  }
}

function parseRegistrationEstablishedEd25519SessionProjectionV2(
  raw: unknown,
): RegistrationEstablishedEd25519SessionProjectionV2 | null {
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, [
      'sessionKind',
      'thresholdSessionId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'runtimePolicyScope',
      'materialActivation',
      'routerAbNormalSigning',
    ]) ||
    raw.sessionKind !== 'credential_free_projection_v2'
  ) {
    return null;
  }
  const thresholdSessionId = parseThresholdEd25519SessionId(raw.thresholdSessionId);
  const nearAccountId = parseNearAccountId(raw.nearAccountId);
  if (!thresholdSessionId.ok || !nearAccountId.ok) return null;
  try {
    const nearEd25519SigningKeyId = parseNearEd25519SigningKeyId(raw.nearEd25519SigningKeyId);
    const runtimePolicyScope = parseRuntimePolicyScopeProjection(raw.runtimePolicyScope);
    const materialActivation = parseMpcMaterialActivationRef(raw.materialActivation);
    if (!materialActivation.ok) return null;
    const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
    if (!routerAbNormalSigning) return null;
    return {
      sessionKind: 'credential_free_projection_v2',
      thresholdSessionId: thresholdSessionId.value,
      nearAccountId: nearAccountId.value,
      nearEd25519SigningKeyId,
      runtimePolicyScope,
      materialActivation: materialActivation.value,
      routerAbNormalSigning,
    };
  } catch {
    return null;
  }
}

function parseRuntimePolicyScopeProjection(raw: unknown): RuntimePolicyScope {
  if (!isRecord(raw) || !hasExactKeys(raw, ['orgId', 'projectId', 'envId', 'signingRootVersion'])) {
    throw new Error('runtime policy scope projection is invalid');
  }
  return normalizeRuntimePolicyScope(raw);
}

function parseNonNegativeSafeInteger(raw: unknown): number | null {
  return typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
  const actualKeys = Object.keys(record);
  return (
    actualKeys.length === expectedKeys.length &&
    expectedKeys.every((key) => Object.prototype.hasOwnProperty.call(record, key))
  );
}
