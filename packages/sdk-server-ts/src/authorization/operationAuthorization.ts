import type {
  AuthorizationGrantRef,
  AuthorizationAuditEventId,
  AuthorizedOperationId,
  CapabilityKind,
  CapabilityOperationResultStorageRef,
  CapabilityOperationRef,
  MpcWalletSigningQuotaId,
  PrincipalId,
  TenantId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  CapabilityOperationEnvelope,
  CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import { computeCapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletId } from '@shared/utils/domainIds';

/** The only grant branch implemented by Refactor 90. */
export type WalletSessionAuthorization = {
  readonly kind: 'wallet_session_authorization';
  readonly authorizationGrantRef: AuthorizationGrantRef;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly revocationEpoch: number;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

/**
 * This union is intentionally WalletSession-only. Linked-device and delegated-spend
 * branches belong to their owning follow-on refactors.
 */
export type AuthorizationGrant = WalletSessionAuthorization;

export type OperationAuthorizationSource =
  | {
      readonly kind: 'authorization_grant';
      readonly authorizationGrantRef: AuthorizationGrantRef;
      readonly evidenceSetDigest?: never;
    }
  | {
      readonly kind: 'verified_step_up';
      readonly authorizationGrantRef?: never;
      readonly evidenceSetDigest: DigestB64u;
    };

export type AuthorizedOperationResult =
  | 'succeeded'
  | 'failed_before_side_effect'
  | 'failed_after_side_effect';

export type AuthorizedOperationResultRef = {
  readonly resultDigest: DigestB64u;
  readonly resultStorageRef: CapabilityOperationResultStorageRef;
};

type AuthorizedOperationIdentity = {
  readonly kind: 'authorized_operation';
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly tenantId: TenantId;
  readonly operation: CapabilityOperationEnvelope;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly capabilityKind: CapabilityKind;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly claimedAtMs: number;
};

type AuthorizedOperationLifecycle =
  | {
      readonly lifecycle: 'claimed';
      readonly result?: never;
      readonly resultRef?: never;
      readonly completedAtMs?: never;
    }
  | {
      readonly lifecycle: 'completed';
      readonly result: AuthorizedOperationResult;
      readonly resultRef: AuthorizedOperationResultRef;
      readonly completedAtMs: number;
    };

type AuthorizedOperationQuota =
  | {
      readonly kind: 'consume_reusable_wallet_session';
      readonly quotaId: MpcWalletSigningQuotaId;
    }
  | {
      readonly kind: 'quota_neutral';
      readonly quotaId?: never;
    };

export type AuthorizedOperation =
  | AuthorizedOperationGrant
  | AuthorizedOperationStepUp;

type AuthorizedOperationGrant = AuthorizedOperationIdentity &
  AuthorizedOperationLifecycle & {
    readonly authorization: Extract<
      OperationAuthorizationSource,
      { readonly kind: 'authorization_grant' }
    >;
    readonly authorizationGrantRevocationEpoch: number;
    readonly quota: AuthorizedOperationQuota;
  };

type AuthorizedOperationStepUp = AuthorizedOperationIdentity &
  AuthorizedOperationLifecycle & {
    readonly authorization: Extract<
      OperationAuthorizationSource,
      { readonly kind: 'verified_step_up' }
    >;
    readonly authorizationGrantRevocationEpoch?: never;
    readonly quota: Extract<AuthorizedOperationQuota, { readonly kind: 'quota_neutral' }>;
  };

type AuthorizedOperationInputBase = Omit<
  AuthorizedOperationIdentity,
  'kind' | 'operationFingerprintDigest' | 'capabilityKind'
>;

export type AuthorizedOperationInput =
  | (AuthorizedOperationInputBase & {
      readonly authorization: Extract<
        OperationAuthorizationSource,
        { readonly kind: 'authorization_grant' }
      >;
      readonly authorizationGrantRevocationEpoch: number;
      readonly quota: AuthorizedOperationQuota;
    })
  | (AuthorizedOperationInputBase & {
      readonly authorization: Extract<
        OperationAuthorizationSource,
        { readonly kind: 'verified_step_up' }
      >;
      readonly authorizationGrantRevocationEpoch?: never;
      readonly quota: Extract<AuthorizedOperationQuota, { readonly kind: 'quota_neutral' }>;
    });

export function buildWalletSessionAuthorization(
  input: Omit<WalletSessionAuthorization, 'kind'>,
): WalletSessionAuthorization {
  requirePositiveSafeInteger(input.revocationEpoch, 'authorization revocation epoch');
  requireOrderedTimes(input.createdAtMs, input.expiresAtMs, 'Wallet Session authorization');
  return { kind: 'wallet_session_authorization', ...input };
}

export async function buildAuthorizedOperation(
  input: AuthorizedOperationInput,
): Promise<AuthorizedOperation> {
  if (input.tenantId !== input.operation.tenantId) {
    throw new Error('authorized operation tenant must match its operation envelope');
  }
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    input.operation,
  );
  const capabilityKind = input.operation.operation.capabilityKind;
  if (isGrantAuthorizedOperationInput(input)) {
    return buildGrantAuthorizedOperation({
      input,
      capabilityKind,
      operationFingerprintDigest,
    });
  }
  return buildStepUpAuthorizedOperation({
    input,
    capabilityKind,
    operationFingerprintDigest,
  });
}

function isGrantAuthorizedOperationInput(
  input: AuthorizedOperationInput,
): input is Extract<
  AuthorizedOperationInput,
  { readonly authorization: { readonly kind: 'authorization_grant' } }
> {
  return input.authorization.kind === 'authorization_grant';
}

function buildGrantAuthorizedOperation(input: {
  readonly input: Extract<
    AuthorizedOperationInput,
    { readonly authorization: { readonly kind: 'authorization_grant' } }
  >;
  readonly capabilityKind: CapabilityKind;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
}): AuthorizedOperationGrant {
  requirePositiveSafeInteger(
    input.input.authorizationGrantRevocationEpoch,
    'authorization revocation epoch',
  );
  return {
    kind: 'authorized_operation',
    authorizedOperationId: input.input.authorizedOperationId,
    tenantId: input.input.tenantId,
    operation: input.input.operation,
    operationFingerprintDigest: input.operationFingerprintDigest,
    capabilityKind: input.capabilityKind,
    auditEventId: input.input.auditEventId,
    claimedAtMs: input.input.claimedAtMs,
    authorization: input.input.authorization,
    authorizationGrantRevocationEpoch: input.input.authorizationGrantRevocationEpoch,
    quota: input.input.quota,
    lifecycle: 'claimed',
  };
}

function buildStepUpAuthorizedOperation(input: {
  readonly input: Extract<
    AuthorizedOperationInput,
    { readonly authorization: { readonly kind: 'verified_step_up' } }
  >;
  readonly capabilityKind: CapabilityKind;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
}): AuthorizedOperationStepUp {
  return {
    kind: 'authorized_operation',
    authorizedOperationId: input.input.authorizedOperationId,
    tenantId: input.input.tenantId,
    operation: input.input.operation,
    operationFingerprintDigest: input.operationFingerprintDigest,
    capabilityKind: input.capabilityKind,
    auditEventId: input.input.auditEventId,
    claimedAtMs: input.input.claimedAtMs,
    authorization: input.input.authorization,
    quota: input.input.quota,
    lifecycle: 'claimed',
  };
}

export function operationConsumesWalletSessionQuota(operation: CapabilityOperationRef): boolean {
  switch (operation.capabilityKind) {
    case 'vault_access':
      return false;
    case 'near_ed25519_mpc_signing':
      return operation.operationKind !== 'near.export_key';
    case 'evm_ecdsa_mpc_signing':
      return operation.operationKind !== 'evm.export_key';
  }
}

function requirePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
}

function requireOrderedTimes(createdAtMs: number, expiresAtMs: number, label: string): void {
  requirePositiveSafeInteger(createdAtMs, `${label} creation`);
  requirePositiveSafeInteger(expiresAtMs, `${label} expiry`);
  if (expiresAtMs <= createdAtMs) {
    throw new Error(`${label} expiry must follow creation`);
  }
}
