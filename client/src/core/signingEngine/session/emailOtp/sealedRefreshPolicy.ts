import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/types';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type {
  deleteExactSealedSession,
  updateExactSealedSessionPolicy,
  SigningSessionSealedRecordFilter,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';

export type EmailOtpSigningSessionCleanupReason =
  | 'explicit_clear'
  | 'expired'
  | 'exhausted'
  | 'invalid_persisted_record';

export type EmailOtpSealedRefreshPolicyPorts = {
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  deleteExactSealedSession: typeof deleteExactSealedSession;
  updateExactSealedSessionPolicy: typeof updateExactSealedSessionPolicy;
  clearEcdsaRestoreCaches: () => void;
};

export class EmailOtpSealedRefreshPolicy {
  constructor(private readonly ports: EmailOtpSealedRefreshPolicyPorts) {}

  async cleanupSigningSession(args: {
    sessionId: string;
    chainTarget?: ThresholdEcdsaChainTarget;
    reason: EmailOtpSigningSessionCleanupReason;
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const filter = this.resolveEmailOtpEcdsaSealedRecordFilter(sessionId, args.chainTarget);
    if (filter) {
      // Expiry/exhaustion removes the refresh seal while preserving active lane identity.
      const preserveResolvedIdentity = args.reason === 'expired' || args.reason === 'exhausted';
      await this.ports.deleteExactSealedSession(sessionId, filter, {
        deleteResolvedIdentity: !preserveResolvedIdentity,
      }).catch(() => undefined);
    }
    this.ports.clearEcdsaRestoreCaches();
  }

  async recordSessionMaterialClaimed(
    sessionId: string,
    result: WarmSessionClaimResult,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result });
  }

  async recordSessionUseConsumed(
    sessionId: string,
    result: WarmSessionStatusResult,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result });
  }

  async recordSessionMaterialRestored(
    sessionId: string,
    result: WarmSessionStatusResult,
  ): Promise<void> {
    await this.recordSessionPolicyResult({ sessionId, result });
  }

  private async recordSessionPolicyResult(args: {
    sessionId: string;
    result: WarmSessionStatusResult | WarmSessionClaimResult;
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const result = args.result;
    if (result.ok) {
      if (result.remainingUses <= 0 || Date.now() >= result.expiresAtMs) {
        await this.cleanupSigningSession({
          sessionId,
          reason: result.remainingUses <= 0 ? 'exhausted' : 'expired',
        });
        return;
      }
      const filter = this.resolveEmailOtpEcdsaSealedRecordFilter(sessionId);
      if (filter) {
        await this.ports.updateExactSealedSessionPolicy({
          thresholdSessionId: sessionId,
          filter,
          expiresAtMs: result.expiresAtMs,
          remainingUses: result.remainingUses,
          updatedAtMs: Date.now(),
        }).catch(() => undefined);
      }
      this.ports.clearEcdsaRestoreCaches();
      return;
    }
    if (result.code === 'expired' || result.code === 'exhausted') {
      await this.cleanupSigningSession({
        sessionId,
        reason: result.code,
      });
    }
  }

  private resolveEmailOtpEcdsaSealedRecordFilter(
    sessionId: string,
    explicitChainTarget?: ThresholdEcdsaChainTarget,
  ): SigningSessionSealedRecordFilter | null {
    const record = this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
    const chainTarget = record?.chainTarget;
    if (
      !chainTarget ||
      (explicitChainTarget && !thresholdEcdsaChainTargetsEqual(chainTarget, explicitChainTarget))
    ) {
      return null;
    }
    return { authMethod: 'email_otp', curve: 'ecdsa', chainTarget };
  }
}
