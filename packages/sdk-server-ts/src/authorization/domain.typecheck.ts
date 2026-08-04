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
} from '@shared/authorization/capabilityKinds';
import type { CapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { AuthorizedOperationInput, OperationAuthorizationSource } from './domain';

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
declare const quotaId: MpcWalletSigningQuotaId;
declare const authorizationGrantRef: AuthorizationGrantRef;

const reusableSource: Extract<
  OperationAuthorizationSource,
  { readonly kind: 'authorization_grant' }
> = {
  kind: 'authorization_grant',
  authorizationGrantRef,
};
const stepUpSource: Extract<
  OperationAuthorizationSource,
  { readonly kind: 'verified_step_up' }
> = {
  kind: 'verified_step_up',
  evidenceSetDigest,
};
void reusableSource;
void stepUpSource;

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

// Keep operation identity declarations live so this fixture checks imported brands.
void capabilityId;
void operationId;
