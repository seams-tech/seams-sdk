import type {
  AuthorizationAuditEventId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  CapabilityId,
  CapabilityOperationId,
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
declare const evidenceSetDigest: DigestB64u;
declare const authorizationId: WalletSessionAuthorizationId;
declare const authorizationGrantRef: AuthorizationGrantRef;

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

const validInput: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation,
  authorization: reusableSource,
  quota: { kind: 'quota_neutral' },
  claimedAtMs: 1,
};
void validInput;

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
