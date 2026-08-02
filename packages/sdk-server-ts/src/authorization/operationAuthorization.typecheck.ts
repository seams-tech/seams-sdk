import type {
  AuthorizationAuditEventId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  MpcWalletSigningQuotaId,
  TenantId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { CapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletId } from '@shared/utils/domainIds';
import type {
  AuthorizedOperationInput,
  OperationAuthorizationSource,
  WalletSessionAuthorization,
} from './operationAuthorization';

declare const authorizationGrantRef: AuthorizationGrantRef;
declare const authorizedOperationId: AuthorizedOperationId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const walletSessionId: WalletSessionId;
declare const quotaId: MpcWalletSigningQuotaId;
declare const tenantId: TenantId;
declare const walletId: WalletId;
declare const operation: CapabilityOperationEnvelope;
declare const auditEventId: AuthorizationAuditEventId;
declare const evidenceSetDigest: DigestB64u;

const reusableSource: OperationAuthorizationSource = {
  kind: 'authorization_grant',
  authorizationGrantRef,
};
const stepUpSource: OperationAuthorizationSource = {
  kind: 'verified_step_up',
  evidenceSetDigest,
};
void reusableSource;
void stepUpSource;

// @ts-expect-error reusable authorization cannot carry raw step-up evidence.
const invalidReusableSource: OperationAuthorizationSource = {
  kind: 'authorization_grant',
  authorizationGrantRef,
  evidenceSetDigest,
};
void invalidReusableSource;

// @ts-expect-error step-up cannot carry a reusable grant reference.
const invalidStepUpSource: OperationAuthorizationSource = {
  kind: 'verified_step_up',
  authorizationGrantRef,
  evidenceSetDigest,
};
void invalidStepUpSource;

declare const reusableGrant: WalletSessionAuthorization;
const grantHasIndependentIdentities: WalletSessionAuthorization = {
  ...reusableGrant,
  authorizationId,
  walletSessionId,
  quotaId,
};
void grantHasIndependentIdentities;

const stepUpInput: AuthorizedOperationInput = {
  authorizedOperationId,
  tenantId,
  operation,
  auditEventId,
  claimedAtMs: 1,
  authorization: stepUpSource,
  quota: { kind: 'quota_neutral' },
};
void stepUpInput;

// @ts-expect-error step-up cannot consume reusable Wallet Session quota.
const invalidStepUpInput: AuthorizedOperationInput = {
  ...stepUpInput,
  quota: { kind: 'consume_reusable_wallet_session', quotaId },
};
void invalidStepUpInput;

const reusableInput: AuthorizedOperationInput = {
  authorizedOperationId,
  tenantId,
  operation,
  auditEventId,
  claimedAtMs: 1,
  authorization: reusableSource,
  authorizationGrantRevocationEpoch: 1,
  walletSessionId,
  quotaId,
  quota: { kind: 'consume_reusable_wallet_session', quotaId },
};
void reusableInput;

// @ts-expect-error reusable operation claims require the grant revocation epoch.
const missingRevocationEpoch: AuthorizedOperationInput = {
  ...reusableInput,
  authorizationGrantRevocationEpoch: undefined,
};
void missingRevocationEpoch;

const invalidWalletIdentity: WalletSessionAuthorization = {
  ...reusableGrant,
  // @ts-expect-error wallet and material/session identity values are not interchangeable.
  walletId: walletSessionId,
};
void invalidWalletIdentity;
