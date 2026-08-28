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
  type WalletId,
} from './domainIds';
import type { ThresholdEcdsaSessionId, ThresholdEd25519SessionId } from './domainIds';
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
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};

export type RegistrationEstablishedEd25519SessionProjectionV2 = {
  readonly sessionKind: 'credential_free_projection_v2';
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly nearAccountId: NearAccountId;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly runtimePolicyScope: RuntimePolicyScope;
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
      'routerAbEcdsaDerivationNormalSigning',
    ]) ||
    raw.sessionKind !== 'credential_free_projection_v2'
  ) {
    return null;
  }
  const thresholdSessionId = parseThresholdEcdsaSessionId(raw.thresholdSessionId);
  if (!thresholdSessionId.ok) return null;
  let keyHandle: ThresholdEcdsaKeyHandle;
  let runtimePolicyScope: RuntimePolicyScope;
  let routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1 | null;
  try {
    keyHandle = parseThresholdEcdsaKeyHandle(raw.keyHandle);
    runtimePolicyScope = parseRuntimePolicyScopeProjection(raw.runtimePolicyScope);
    routerAbEcdsaDerivationNormalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1(
      raw.routerAbEcdsaDerivationNormalSigning,
    );
  } catch {
    return null;
  }
  if (routerAbEcdsaDerivationNormalSigning === null) return null;
  return {
    sessionKind: 'credential_free_projection_v2',
    thresholdSessionId: thresholdSessionId.value,
    keyHandle,
    runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning,
  };
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
      'routerAbNormalSigning',
    ]) ||
    raw.sessionKind !== 'credential_free_projection_v2'
  ) {
    return null;
  }
  const thresholdSessionId = parseThresholdEd25519SessionId(raw.thresholdSessionId);
  const nearAccountId = parseNearAccountId(raw.nearAccountId);
  if (!thresholdSessionId.ok || !nearAccountId.ok) return null;
  let nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  let runtimePolicyScope: RuntimePolicyScope;
  let routerAbNormalSigning: RouterAbEd25519NormalSigningState | null;
  try {
    nearEd25519SigningKeyId = parseNearEd25519SigningKeyId(raw.nearEd25519SigningKeyId);
    runtimePolicyScope = parseRuntimePolicyScopeProjection(raw.runtimePolicyScope);
    routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  } catch {
    return null;
  }
  if (routerAbNormalSigning === null) return null;
  return {
    sessionKind: 'credential_free_projection_v2',
    thresholdSessionId: thresholdSessionId.value,
    nearAccountId: nearAccountId.value,
    nearEd25519SigningKeyId,
    runtimePolicyScope,
    routerAbNormalSigning,
  };
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
