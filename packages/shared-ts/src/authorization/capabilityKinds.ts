import type { DomainId } from '../utils/domainIds';
import { hasWhitespaceOrControlCharacters } from '../utils/domainIds';

export type AuthorizationParseError = {
  readonly code: 'missing' | 'invalid';
  readonly message: string;
};

export type AuthorizationParseResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: AuthorizationParseError };

export const CAPABILITY_KINDS = {
  vaultAccess: 'vault_access',
  nearEd25519MpcSigning: 'near_ed25519_mpc_signing',
  evmEcdsaMpcSigning: 'evm_ecdsa_mpc_signing',
} as const;

export type CapabilityKind = (typeof CAPABILITY_KINDS)[keyof typeof CAPABILITY_KINDS];

export const VAULT_OPERATION_KINDS = {
  proxyUse: 'vault.proxy_use',
  reveal: 'vault.reveal',
} as const;

export type VaultOperationKind = (typeof VAULT_OPERATION_KINDS)[keyof typeof VAULT_OPERATION_KINDS];

export const NEAR_ED25519_MPC_OPERATION_KINDS = {
  signTransaction: 'near.sign_transaction',
  signDelegateAction: 'near.sign_delegate_action',
  signNep413Message: 'near.sign_nep413_message',
  exportKey: 'near.export_key',
} as const;

export type NearEd25519MpcOperationKind =
  (typeof NEAR_ED25519_MPC_OPERATION_KINDS)[keyof typeof NEAR_ED25519_MPC_OPERATION_KINDS];

export const EVM_ECDSA_MPC_OPERATION_KINDS = {
  signTransaction: 'evm.sign_transaction',
  exportKey: 'evm.export_key',
} as const;

export type EvmEcdsaMpcOperationKind =
  (typeof EVM_ECDSA_MPC_OPERATION_KINDS)[keyof typeof EVM_ECDSA_MPC_OPERATION_KINDS];

export type CapabilityOperationKind =
  | VaultOperationKind
  | NearEd25519MpcOperationKind
  | EvmEcdsaMpcOperationKind;

export type CapabilityOperationKindByCapability = {
  readonly vault_access: VaultOperationKind;
  readonly near_ed25519_mpc_signing: NearEd25519MpcOperationKind;
  readonly evm_ecdsa_mpc_signing: EvmEcdsaMpcOperationKind;
};

export type CapabilityOperationRef = {
  [K in CapabilityKind]: {
    readonly capabilityKind: K;
    readonly operationKind: CapabilityOperationKindByCapability[K];
  };
}[CapabilityKind];

export const AUTH_FACTOR_KINDS = {
  passkey: 'passkey',
  emailOtp: 'email_otp',
} as const;

export type AuthFactorKind = (typeof AUTH_FACTOR_KINDS)[keyof typeof AUTH_FACTOR_KINDS];

export const AUTHORIZATION_EVIDENCE_KINDS = {
  seamsSession: 'seams_session',
  passkeyAssertion: 'passkey_assertion',
  emailOtp: 'email_otp',
} as const;

export type SessionAuthorizationEvidenceKind = typeof AUTHORIZATION_EVIDENCE_KINDS.seamsSession;
export type InteractiveAuthorizationEvidenceKind =
  | typeof AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion
  | typeof AUTHORIZATION_EVIDENCE_KINDS.emailOtp;
export type AuthorizationEvidenceKind =
  | SessionAuthorizationEvidenceKind
  | InteractiveAuthorizationEvidenceKind;

export type AuthorizationEvidenceRequirement = {
  readonly mode: 'all' | 'any';
  readonly evidenceKinds: readonly [AuthorizationEvidenceKind, ...AuthorizationEvidenceKind[]];
};

export type TenantId = DomainId<'TenantId'>;
export type PrincipalId = DomainId<'PrincipalId'>;
export type EcdsaAuthorizationSessionId = DomainId<'EcdsaAuthorizationSessionId'>;
export type SeamsSession = DomainId<'SeamsSession'>;
export type HostedWalletSessionExchangeCodeId = DomainId<'HostedWalletSessionExchangeCodeId'>;
export type SessionClientId = DomainId<'SessionClientId'>;
export type DeviceId = DomainId<'DeviceId'>;
export type AuthFactorId = DomainId<'AuthFactorId'>;
export type CapabilityId = DomainId<'CapabilityId'>;
export type CapabilityBindingId = DomainId<'CapabilityBindingId'>;
export type CapabilityOperationId = DomainId<'CapabilityOperationId'>;
export type WalletSessionAuthorizationId = DomainId<'WalletSessionAuthorizationId'>;
export type LinkedDeviceWalletSessionAuthorizationId =
  DomainId<'LinkedDeviceWalletSessionAuthorizationId'>;
export type ReusableWalletSessionAuthorizationId =
  | WalletSessionAuthorizationId
  | LinkedDeviceWalletSessionAuthorizationId;

export const AUTHORIZATION_GRANT_KINDS = {
  walletSession: 'wallet_session_authorization',
  linkedDeviceWalletSession: 'linked_device_wallet_session_authorization_v1',
} as const;

export type AuthorizationGrantKind =
  (typeof AUTHORIZATION_GRANT_KINDS)[keyof typeof AUTHORIZATION_GRANT_KINDS];

export type WalletSessionAuthorizationRef = {
  readonly kind: 'wallet_session_authorization';
  readonly authorizationId: WalletSessionAuthorizationId;
};

export type LinkedDeviceWalletSessionAuthorizationRefV1 = {
  readonly kind: 'linked_device_wallet_session_authorization_v1';
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
};
export type LinkedDeviceWalletSessionAuthorizationRef = LinkedDeviceWalletSessionAuthorizationRefV1;

/** Each reusable authorization branch carries exactly one authorization identity. */
export type AuthorizationGrantRef =
  | WalletSessionAuthorizationRef
  | LinkedDeviceWalletSessionAuthorizationRefV1;
export type AuthorizedOperationId = DomainId<'AuthorizedOperationId'>;
export type WalletSessionId = DomainId<'WalletSessionId'>;
export type MpcWalletSigningQuotaId = DomainId<'MpcWalletSigningQuotaId'>;
export type ReusableWalletSessionMintId = DomainId<'ReusableWalletSessionMintId'>;
export type AuthorizationEvidenceId = DomainId<'AuthorizationEvidenceId'>;
export type AuthorizationEvidenceSetId = DomainId<'AuthorizationEvidenceSetId'>;
export type GrantChallengeId = DomainId<'GrantChallengeId'>;
export type PolicyId = DomainId<'PolicyId'>;
export type AuthorizationAuditEventId = DomainId<'AuthorizationAuditEventId'>;
export type VaultId = DomainId<'VaultId'>;
export type VaultItemId = DomainId<'VaultItemId'>;
export type CapabilityOperationResultStorageRef = DomainId<'CapabilityOperationResultStorageRef'>;

const CAPABILITY_KIND_VALUES = Object.values(CAPABILITY_KINDS) as readonly CapabilityKind[];
const VAULT_OPERATION_KIND_VALUES = Object.values(
  VAULT_OPERATION_KINDS,
) as readonly VaultOperationKind[];
const NEAR_ED25519_MPC_OPERATION_KIND_VALUES = Object.values(
  NEAR_ED25519_MPC_OPERATION_KINDS,
) as readonly NearEd25519MpcOperationKind[];
const EVM_ECDSA_MPC_OPERATION_KIND_VALUES = Object.values(
  EVM_ECDSA_MPC_OPERATION_KINDS,
) as readonly EvmEcdsaMpcOperationKind[];
const AUTHORIZATION_EVIDENCE_KIND_VALUES = Object.values(
  AUTHORIZATION_EVIDENCE_KINDS,
) as readonly AuthorizationEvidenceKind[];

export function isCapabilityKind(value: unknown): value is CapabilityKind {
  return typeof value === 'string' && CAPABILITY_KIND_VALUES.includes(value as CapabilityKind);
}

export function isAuthorizationEvidenceKind(value: unknown): value is AuthorizationEvidenceKind {
  return (
    typeof value === 'string' &&
    AUTHORIZATION_EVIDENCE_KIND_VALUES.includes(value as AuthorizationEvidenceKind)
  );
}

export function buildVaultOperationRef<TOperationKind extends VaultOperationKind>(
  operationKind: TOperationKind,
): Extract<CapabilityOperationRef, { readonly capabilityKind: 'vault_access' }> & {
  readonly operationKind: TOperationKind;
} {
  return {
    capabilityKind: CAPABILITY_KINDS.vaultAccess,
    operationKind,
  };
}

export function buildNearEd25519MpcOperationRef<TOperationKind extends NearEd25519MpcOperationKind>(
  operationKind: TOperationKind,
): Extract<CapabilityOperationRef, { readonly capabilityKind: 'near_ed25519_mpc_signing' }> & {
  readonly operationKind: TOperationKind;
} {
  return {
    capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
    operationKind,
  };
}

export function buildEvmEcdsaMpcOperationRef<TOperationKind extends EvmEcdsaMpcOperationKind>(
  operationKind: TOperationKind,
): Extract<CapabilityOperationRef, { readonly capabilityKind: 'evm_ecdsa_mpc_signing' }> & {
  readonly operationKind: TOperationKind;
} {
  return {
    capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
    operationKind,
  };
}

export function parseCapabilityOperationRef(
  value: unknown,
): AuthorizationParseResult<CapabilityOperationRef> {
  if (!isExactOperationRefRecord(value)) {
    return invalidResult(
      'capability operation must contain exact capabilityKind and operationKind',
    );
  }
  switch (value.capabilityKind) {
    case CAPABILITY_KINDS.vaultAccess:
      if (isVaultOperationKind(value.operationKind)) {
        return { ok: true, value: buildVaultOperationRef(value.operationKind) };
      }
      return invalidResult('vault capability operation is unsupported');
    case CAPABILITY_KINDS.nearEd25519MpcSigning:
      if (isNearEd25519MpcOperationKind(value.operationKind)) {
        return { ok: true, value: buildNearEd25519MpcOperationRef(value.operationKind) };
      }
      return invalidResult('NEAR Ed25519 MPC capability operation is unsupported');
    case CAPABILITY_KINDS.evmEcdsaMpcSigning:
      if (isEvmEcdsaMpcOperationKind(value.operationKind)) {
        return { ok: true, value: buildEvmEcdsaMpcOperationRef(value.operationKind) };
      }
      return invalidResult('EVM ECDSA MPC capability operation is unsupported');
  }
  return invalidResult('capability kind is unsupported');
}

export function buildAuthorizationEvidenceRequirement(input: {
  readonly mode: AuthorizationEvidenceRequirement['mode'];
  readonly evidenceKinds: readonly [AuthorizationEvidenceKind, ...AuthorizationEvidenceKind[]];
}): AuthorizationEvidenceRequirement {
  const canonicalKinds = [...new Set(input.evidenceKinds)].sort();
  const [firstKind, ...remainingKinds] = canonicalKinds;
  if (!firstKind) {
    throw new Error('authorization evidence requirement must contain at least one evidence kind');
  }
  return {
    mode: input.mode,
    evidenceKinds: [firstKind, ...remainingKinds],
  };
}

export function parseTenantId(value: unknown): AuthorizationParseResult<TenantId> {
  return parseAuthorizationId(value, 'tenantId');
}

export function parsePrincipalId(value: unknown): AuthorizationParseResult<PrincipalId> {
  return parseAuthorizationId(value, 'principalId');
}

export function parseEcdsaAuthorizationSessionId(
  value: unknown,
): AuthorizationParseResult<EcdsaAuthorizationSessionId> {
  return parseAuthorizationId(value, 'ecdsaAuthorizationSessionId');
}

export function parseSeamsSession(value: unknown): AuthorizationParseResult<SeamsSession> {
  return parseAuthorizationId(value, 'seamsSession');
}

export function parseHostedWalletSessionExchangeCodeId(
  value: unknown,
): AuthorizationParseResult<HostedWalletSessionExchangeCodeId> {
  return parseAuthorizationId(value, 'hostedWalletSessionExchangeCodeId');
}

export function parseSessionClientId(value: unknown): AuthorizationParseResult<SessionClientId> {
  return parseAuthorizationId(value, 'sessionClientId');
}

export function parseDeviceId(value: unknown): AuthorizationParseResult<DeviceId> {
  return parseAuthorizationId(value, 'deviceId');
}

export function parseAuthFactorId(value: unknown): AuthorizationParseResult<AuthFactorId> {
  return parseAuthorizationId(value, 'authFactorId');
}

export function parseCapabilityId(value: unknown): AuthorizationParseResult<CapabilityId> {
  return parseAuthorizationId(value, 'capabilityId');
}

export function parseCapabilityBindingId(
  value: unknown,
): AuthorizationParseResult<CapabilityBindingId> {
  return parseAuthorizationId(value, 'capabilityBindingId');
}

export function parseCapabilityOperationId(
  value: unknown,
): AuthorizationParseResult<CapabilityOperationId> {
  return parseAuthorizationId(value, 'capabilityOperationId');
}

export function parseAuthorizationGrantRef(
  value: unknown,
): AuthorizationParseResult<AuthorizationGrantRef> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return invalidResult('authorizationGrantRef must be an object');
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 2 || !keys.includes('kind') || !keys.includes('authorizationId')) {
    return invalidResult('authorizationGrantRef contains unexpected fields');
  }
  switch (record.kind) {
    case AUTHORIZATION_GRANT_KINDS.walletSession: {
      const authorizationId = parseWalletSessionAuthorizationId(record.authorizationId);
      if (!authorizationId.ok) return authorizationId;
      return {
        ok: true,
        value: {
          kind: AUTHORIZATION_GRANT_KINDS.walletSession,
          authorizationId: authorizationId.value,
        },
      };
    }
    case AUTHORIZATION_GRANT_KINDS.linkedDeviceWalletSession: {
      const authorizationId = parseLinkedDeviceWalletSessionAuthorizationId(record.authorizationId);
      if (!authorizationId.ok) return authorizationId;
      return {
        ok: true,
        value: {
          kind: AUTHORIZATION_GRANT_KINDS.linkedDeviceWalletSession,
          authorizationId: authorizationId.value,
        },
      };
    }
    default:
      return invalidResult('authorizationGrantRef.kind is unsupported');
  }
}

export function buildAuthorizationGrantRef(
  authorizationId: WalletSessionAuthorizationId,
): WalletSessionAuthorizationRef {
  return { kind: AUTHORIZATION_GRANT_KINDS.walletSession, authorizationId };
}

export function buildLinkedDeviceWalletSessionAuthorizationRef(
  authorizationId: LinkedDeviceWalletSessionAuthorizationId,
): LinkedDeviceWalletSessionAuthorizationRefV1 {
  return {
    kind: AUTHORIZATION_GRANT_KINDS.linkedDeviceWalletSession,
    authorizationId,
  };
}

export function parseWalletSessionAuthorizationId(
  value: unknown,
): AuthorizationParseResult<WalletSessionAuthorizationId> {
  return parseAuthorizationId(value, 'walletSessionAuthorizationId');
}

export function parseLinkedDeviceWalletSessionAuthorizationId(
  value: unknown,
): AuthorizationParseResult<LinkedDeviceWalletSessionAuthorizationId> {
  return parseAuthorizationId(value, 'linkedDeviceWalletSessionAuthorizationId');
}

export function parseReusableWalletSessionAuthorizationId(
  value: unknown,
): AuthorizationParseResult<ReusableWalletSessionAuthorizationId> {
  return parseAuthorizationId(value, 'reusableWalletSessionAuthorizationId');
}

export function parseAuthorizedOperationId(
  value: unknown,
): AuthorizationParseResult<AuthorizedOperationId> {
  return parseAuthorizationId(value, 'authorizedOperationId');
}

export function parseWalletSessionId(value: unknown): AuthorizationParseResult<WalletSessionId> {
  return parseAuthorizationId(value, 'walletSessionId');
}

export function parseMpcWalletSigningQuotaId(
  value: unknown,
): AuthorizationParseResult<MpcWalletSigningQuotaId> {
  return parseAuthorizationId(value, 'mpcWalletSigningQuotaId');
}

export function parseReusableWalletSessionMintId(
  value: unknown,
): AuthorizationParseResult<ReusableWalletSessionMintId> {
  return parseAuthorizationId(value, 'reusableWalletSessionMintId');
}

export function parseAuthorizationEvidenceId(
  value: unknown,
): AuthorizationParseResult<AuthorizationEvidenceId> {
  return parseAuthorizationId(value, 'authorizationEvidenceId');
}

export function parseAuthorizationEvidenceSetId(
  value: unknown,
): AuthorizationParseResult<AuthorizationEvidenceSetId> {
  return parseAuthorizationId(value, 'authorizationEvidenceSetId');
}

export function parseGrantChallengeId(value: unknown): AuthorizationParseResult<GrantChallengeId> {
  return parseAuthorizationId(value, 'grantChallengeId');
}

export function parsePolicyId(value: unknown): AuthorizationParseResult<PolicyId> {
  return parseAuthorizationId(value, 'policyId');
}

export function parseAuthorizationAuditEventId(
  value: unknown,
): AuthorizationParseResult<AuthorizationAuditEventId> {
  return parseAuthorizationId(value, 'authorizationAuditEventId');
}

export function parseVaultId(value: unknown): AuthorizationParseResult<VaultId> {
  return parseAuthorizationId(value, 'vaultId');
}

export function parseVaultItemId(value: unknown): AuthorizationParseResult<VaultItemId> {
  return parseAuthorizationId(value, 'vaultItemId');
}

export function parseCapabilityOperationResultStorageRef(
  value: unknown,
): AuthorizationParseResult<CapabilityOperationResultStorageRef> {
  return parseAuthorizationId(value, 'capabilityOperationResultStorageRef');
}

function isVaultOperationKind(value: unknown): value is VaultOperationKind {
  return (
    typeof value === 'string' && VAULT_OPERATION_KIND_VALUES.includes(value as VaultOperationKind)
  );
}

function isNearEd25519MpcOperationKind(value: unknown): value is NearEd25519MpcOperationKind {
  return (
    typeof value === 'string' &&
    NEAR_ED25519_MPC_OPERATION_KIND_VALUES.includes(value as NearEd25519MpcOperationKind)
  );
}

function isEvmEcdsaMpcOperationKind(value: unknown): value is EvmEcdsaMpcOperationKind {
  return (
    typeof value === 'string' &&
    EVM_ECDSA_MPC_OPERATION_KIND_VALUES.includes(value as EvmEcdsaMpcOperationKind)
  );
}

function isExactOperationRefRecord(
  value: unknown,
): value is { readonly capabilityKind: CapabilityKind; readonly operationKind: unknown } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes('capabilityKind') || !keys.includes('operationKind')) {
    return false;
  }
  return isCapabilityKind((value as { readonly capabilityKind?: unknown }).capabilityKind);
}

function parseAuthorizationId<T>(value: unknown, fieldName: string): AuthorizationParseResult<T> {
  if (typeof value !== 'string') {
    return {
      ok: false,
      error: {
        code: value == null ? 'missing' : 'invalid',
        message: `${fieldName} must be a nonempty string`,
      },
    };
  }
  const normalized = value.trim();
  if (!normalized) {
    return {
      ok: false,
      error: {
        code: 'missing',
        message: `${fieldName} is required`,
      },
    };
  }
  if (normalized.length > 512 || hasWhitespaceOrControlCharacters(normalized)) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: `${fieldName} must be a compact opaque identifier`,
      },
    };
  }
  return { ok: true, value: normalized as T };
}

function invalidResult<T>(message: string): AuthorizationParseResult<T> {
  return {
    ok: false,
    error: {
      code: 'invalid',
      message,
    },
  };
}
