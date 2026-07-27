import type {
  ActiveAuthorizationSession,
  ActiveCapabilityGrant,
  ActiveWalletSessionQuota,
  AuthorizationAuditEvent,
  CapabilityOperationClaim,
  CapabilityOperationResultRef,
  ClaimCapabilityOperationResult,
  CompleteCapabilityOperationResult,
  CompletedCapabilityOperationResult,
  VerifiedGrantEvidenceSet,
} from './domain';

export interface AuthorizationStore {
  putActiveSession(session: ActiveAuthorizationSession): Promise<void>;
  putVerifiedEvidenceSet(evidenceSet: VerifiedGrantEvidenceSet): Promise<void>;
  putActiveGrant(grant: ActiveCapabilityGrant): Promise<void>;
  putActiveWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void>;
  claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult>;
  completeOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult>;
  readAuditEvent(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly eventId: CapabilityOperationClaim['auditEventId'];
  }): Promise<AuthorizationAuditEvent | null>;
}

export class AuthorizationService {
  constructor(private readonly store: AuthorizationStore) {}

  async recordActiveSession(session: ActiveAuthorizationSession): Promise<void> {
    await this.store.putActiveSession(session);
  }

  async recordVerifiedEvidenceSet(evidenceSet: VerifiedGrantEvidenceSet): Promise<void> {
    await this.store.putVerifiedEvidenceSet(evidenceSet);
  }

  async issueGrant(grant: ActiveCapabilityGrant): Promise<void> {
    await this.store.putActiveGrant(grant);
  }

  async recordWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void> {
    await this.store.putActiveWalletSessionQuota(quota);
  }

  async claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult> {
    return await this.store.claimOperation(claim);
  }

  async completeOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult> {
    return await this.store.completeOperation(input);
  }

  async readAuditEvent(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly eventId: CapabilityOperationClaim['auditEventId'];
  }): Promise<AuthorizationAuditEvent | null> {
    return await this.store.readAuditEvent(input);
  }
}
