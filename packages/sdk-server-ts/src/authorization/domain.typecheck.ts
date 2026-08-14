import type {
  AuthorizationAuditEventId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  CapabilityId,
  CapabilityOperationId,
  CapabilityOperationRef,
  MpcWalletSigningQuotaId,
  TenantId,
  WalletSessionAuthorizationId,
  LinkedDeviceWalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId, WalletId } from '@shared/utils/domainIds';
import type { CapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  AuthorizedOperation,
  AuthorizedOperationInput,
  OperationAuthorizationSource,
  OwnerOperationAuthorizationDecision,
  VerifiedOwnerProof,
} from './domain';

declare const tenantId: TenantId;
declare const authorizedOperationId: AuthorizedOperationId;
declare const auditEventId: AuthorizationAuditEventId;
declare const capabilityId: CapabilityId;
declare const operationId: CapabilityOperationId;
declare const operation: CapabilityOperationEnvelope;
declare const signingOperation: CapabilityOperationEnvelope<
  Extract<CapabilityOperationRef, { readonly capabilityKind: 'evm_ecdsa_mpc_signing' }> & {
    readonly operationKind: 'evm.sign_transaction';
  }
>;
declare const exportOperation: CapabilityOperationEnvelope<
  Extract<CapabilityOperationRef, { readonly capabilityKind: 'evm_ecdsa_mpc_signing' }> & {
    readonly operationKind: 'evm.export_key';
  }
>;
declare const evidenceSetDigest: DigestB64u;
declare const authorizationId: WalletSessionAuthorizationId;
declare const linkedAuthorizationId: LinkedDeviceWalletSessionAuthorizationId;
declare const linkedTenantId: TenantId;
declare const linkedDeviceId: LinkedDeviceId;
declare const linkedWalletId: WalletId;
declare const linkedEnrollmentId: LinkedDeviceEnrollmentId;
declare const linkedWalletSessionId: WalletSessionId;
declare const linkedQuotaId: MpcWalletSigningQuotaId;
declare const quotaId: MpcWalletSigningQuotaId;
declare const authorizationGrantRef: AuthorizationGrantRef;
declare const claimedOperation: AuthorizedOperation & { readonly lifecycle: 'claimed' };
declare const ownerWalletProof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
declare const ownerOperationProof: Extract<VerifiedOwnerProof, { readonly purpose: 'operation' }>;

const reusableSource: Extract<
  OperationAuthorizationSource,
  { readonly kind: 'authorization_grant' }
> = {
  kind: 'authorization_grant',
  authorizationGrantRef,
};
const stepUpSource: Extract<OperationAuthorizationSource, { readonly kind: 'verified_step_up' }> = {
  kind: 'verified_step_up',
  evidenceSetDigest,
};
void reusableSource;
void stepUpSource;

const linkedSource: Extract<
  OperationAuthorizationSource,
  { readonly kind: 'authorization_grant' }
> = {
  kind: 'authorization_grant',
  authorizationGrantRef: {
    kind: 'linked_device_wallet_session_authorization_v1',
    authorizationId: linkedAuthorizationId,
  },
};
void linkedSource;

// @ts-expect-error Linked authorization identities cannot carry owner grant references.
const invalidLinkedOwnerRef: AuthorizationGrantRef = {
  kind: 'linked_device_wallet_session_authorization_v1',
  authorizationId,
};
void invalidLinkedOwnerRef;

void linkedTenantId;
void linkedDeviceId;
void linkedWalletId;
void linkedEnrollmentId;
void linkedWalletSessionId;
void linkedQuotaId;

const validInput: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation: signingOperation,
  authorization: reusableSource,
  quota: { kind: 'consume_reusable_wallet_session', quotaId },
  claimedAtMs: 1,
};
void validInput;

const validExportInput: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation: exportOperation,
  authorization: reusableSource,
  quota: { kind: 'quota_neutral' },
  claimedAtMs: 1,
};
void validExportInput;

const validStepUpInput: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation,
  authorization: stepUpSource,
  quota: { kind: 'quota_neutral' },
  claimedAtMs: 1,
};
void validStepUpInput;

// @ts-expect-error reusable signing authorization must consume its quota.
const invalidReusableSigningQuota: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation: signingOperation,
  authorization: reusableSource,
  quota: { kind: 'quota_neutral' },
  claimedAtMs: 1,
};
void invalidReusableSigningQuota;

// @ts-expect-error export authorization is quota-neutral.
const invalidReusableExportQuota: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation: exportOperation,
  authorization: reusableSource,
  quota: { kind: 'consume_reusable_wallet_session', quotaId },
  claimedAtMs: 1,
};
void invalidReusableExportQuota;

// @ts-expect-error verified step-up authorization cannot consume a reusable quota.
const invalidStepUpQuota: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation,
  authorization: stepUpSource,
  quota: { kind: 'consume_reusable_wallet_session', quotaId },
  claimedAtMs: 1,
};
void invalidStepUpQuota;

// @ts-expect-error reusable authorization sources cannot carry step-up evidence.
const invalidReusableSource: OperationAuthorizationSource = {
  kind: 'authorization_grant',
  authorizationGrantRef: { kind: 'wallet_session_authorization', authorizationId },
  evidenceSetDigest,
};
void invalidReusableSource;

const authorizedDecision: OwnerOperationAuthorizationDecision<{ readonly kind: 'step_up' }> = {
  kind: 'authorized',
  operation: claimedOperation,
  source: {
    kind: 'authorization_grant',
    authorizationGrantRef: { kind: 'wallet_session_authorization', authorizationId },
  },
};
void authorizedDecision;

// @ts-expect-error one authorization decision cannot both admit and request step-up
const invalidMixedDecision: OwnerOperationAuthorizationDecision<{ readonly kind: 'step_up' }> = {
  kind: 'authorized',
  operation: claimedOperation,
  source: {
    kind: 'authorization_grant',
    authorizationGrantRef: { kind: 'wallet_session_authorization', authorizationId },
  },
  stepUp: { kind: 'step_up' as const },
};
void invalidMixedDecision;

const invalidLinkedOwnerDecision: OwnerOperationAuthorizationDecision<{
  readonly kind: 'step_up';
}> = {
  kind: 'authorized',
  operation: claimedOperation,
  // @ts-expect-error linked-device grants cannot enter the owner authorization decision
  source: linkedSource,
};
void invalidLinkedOwnerDecision;

function acceptWalletSessionProof(
  proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>,
): void {
  void proof;
}
function acceptOperationProof(
  proof: Extract<VerifiedOwnerProof, { readonly purpose: 'operation' }>,
): void {
  void proof.operation;
}
acceptWalletSessionProof(ownerWalletProof);
acceptOperationProof(ownerOperationProof);
// @ts-expect-error a wallet-session proof cannot enter the operation branch.
acceptOperationProof(ownerWalletProof);

// Keep operation identity declarations live so this fixture checks imported brands.
void capabilityId;
void operationId;
