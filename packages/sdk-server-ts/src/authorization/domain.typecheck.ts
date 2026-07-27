import type {
  CapabilityGrantUseId,
  CapabilityGrantId,
  AuthorizationAuditEventId,
  TenantId,
} from '@shared/authorization/capabilityKinds';
import type {
  CapabilityOperationEnvelope,
  CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  ActiveCapabilityGrant,
  CapabilityOperationClaim,
  CapabilityOperationClaimInput,
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from './domain';

declare const tenantId: TenantId;
declare const useId: CapabilityGrantUseId;
declare const auditEventId: AuthorizationAuditEventId;
declare const grantId: CapabilityGrantId;
declare const operation: CapabilityOperationEnvelope;
declare const operationFingerprintDigest: CapabilityOperationFingerprintDigest;
declare const evidenceSetDigest: DigestB64u;
declare const walletSessionId: WalletSessionId;
declare const quotaId: MpcWalletSigningQuotaId;
declare const reusableGrant: Extract<
  ActiveCapabilityGrant,
  { readonly authority: { readonly kind: 'reusable_wallet_session' } }
>;

// @ts-expect-error claims can only be created through the quota-deriving builder
const directClaim: CapabilityOperationClaim = {
  tenantId,
  useId,
  auditEventId,
  grantId,
  operation,
  operationFingerprintDigest,
  evidenceSetDigest,
  claimedAtMs: 1,
  authorization: { kind: 'operation_step_up' },
  quota: { kind: 'quota_neutral' },
};

void directClaim;

const invalidStepUpInput = {
  tenantId,
  useId,
  auditEventId,
  grantId,
  operation,
  operationFingerprintDigest,
  evidenceSetDigest,
  claimedAtMs: 1,
  authorization: {
    kind: 'operation_step_up',
    walletSessionId,
    quotaId,
  },
};

// @ts-expect-error operation step-up cannot carry reusable Wallet Session identity
invalidStepUpInput satisfies CapabilityOperationClaimInput;

// @ts-expect-error step-up grants are structurally limited to one use
const invalidStepUpGrant: ActiveCapabilityGrant = {
  ...reusableGrant,
  authority: { kind: 'operation_step_up' },
  remainingUses: 2,
};

void invalidStepUpGrant;
