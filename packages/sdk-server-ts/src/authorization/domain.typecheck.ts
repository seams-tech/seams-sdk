import type {
  CapabilityGrantUseId,
  CapabilityGrantId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  AuthorizationAuditEventId,
  TenantId,
} from '@shared/authorization/capabilityKinds';
import type {
  CapabilityOperationEnvelope,
  CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  ActiveAuthorizationSession,
  ActiveCapabilityGrant,
  CapabilityOperationClaim,
  CapabilityOperationClaimInput,
  CapabilityOperationCompletionClaimRef,
  AuthorizedOperationInput,
  OperationAuthorizationSource,
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from './domain';

declare const tenantId: TenantId;
declare const useId: CapabilityGrantUseId;
declare const authorizedOperationId: AuthorizedOperationId;
declare const authorizationGrantRef: AuthorizationGrantRef;
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

type CompletionClaimInput = CapabilityOperationClaim | CapabilityOperationCompletionClaimRef;
declare const builtClaim: CapabilityOperationClaim;
const fullClaimRemainsAccepted: CompletionClaimInput = builtClaim;
void fullClaimRemainsAccepted;

// @ts-expect-error completion references can only be created through their builder
const directCompletionRef: CapabilityOperationCompletionClaimRef = {
  tenantId,
  useId,
  grantId,
  operationFingerprintDigest,
};

void directCompletionRef;

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

const invalidStepUpGrant: ActiveCapabilityGrant = {
  ...reusableGrant,
  authority: { kind: 'operation_step_up' },
  // @ts-expect-error capability grants are structurally limited to one use
  remainingUses: 2,
};

void invalidStepUpGrant;

declare const normalizedSession: ActiveAuthorizationSession;

const invalidSessionVersion = {
  ...normalizedSession,
  appSessionVersion: 'raw-session-version',
};

// @ts-expect-error normalized sessions require the branded app-session version
invalidSessionVersion satisfies ActiveAuthorizationSession;

const invalidProvider = {
  ...normalizedSession,
  authSource: {
    kind: 'oidc_provider',
    providerId: 'future-provider',
    providerSubject: 'raw-provider-subject',
  },
};

// @ts-expect-error normalized sessions require a closed provider and branded subject
invalidProvider satisfies ActiveAuthorizationSession;

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

// @ts-expect-error Authorization-grant operations cannot carry step-up evidence.
const mixedAuthorizationSource: OperationAuthorizationSource = {
  kind: 'authorization_grant',
  authorizationGrantRef,
  evidenceSetDigest,
};
void mixedAuthorizationSource;

const authorizedOperationInput: AuthorizedOperationInput = {
  tenantId,
  authorizedOperationId,
  auditEventId,
  operation,
  authorization: stepUpSource,
  quota: { kind: 'quota_neutral' },
  claimedAtMs: 1,
};
void authorizedOperationInput;

const substitutedOperationId: AuthorizedOperationInput = {
  ...authorizedOperationInput,
  // @ts-expect-error A Wallet Session authorization ref cannot be used as an operation id.
  authorizedOperationId: authorizationGrantRef,
};
void substitutedOperationId;
