import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type {
  deleteDurableSealedSessionRecord,
  updateExactSealedSessionPolicy,
  SigningSessionSealedRecordFilter,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  createDeleteDurableSealedSessionCommand,
  type DurableSealedSessionDeleteReason,
} from '@/core/signingEngine/session/persistence/durableSealedSessionCommands';

export type EmailOtpDurableSealedSessionDeleteReason = Extract<
  DurableSealedSessionDeleteReason,
  'expired' | 'exhausted' | 'invalid_persisted_record'
>;

export type EmailOtpSealedRefreshPolicyPorts = {
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  deleteDurableSealedSessionRecord: typeof deleteDurableSealedSessionRecord;
  updateExactSealedSessionPolicy: typeof updateExactSealedSessionPolicy;
  clearEcdsaRestoreCaches: () => void;
};

export class EmailOtpSealedRefreshPolicy {
  constructor(private readonly ports: EmailOtpSealedRefreshPolicyPorts) {}

  async deleteEmailOtpDurableSealedSessionRecord(args: {
    sessionId: string;
    deleteReason: EmailOtpDurableSealedSessionDeleteReason;
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const record = this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
    if (!record?.chainTarget) {
      this.ports.clearEcdsaRestoreCaches();
      return;
    }
    const command = createDeleteDurableSealedSessionCommand({
      durableRecord: {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        thresholdSessionId: sessionId,
        chainTarget: record.chainTarget,
      },
      deleteReason: args.deleteReason,
      preserveResolvedIdentity:
        args.deleteReason === 'expired' || args.deleteReason === 'exhausted',
    });
    await this.ports.deleteDurableSealedSessionRecord(command).catch(() => undefined);
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
        await this.deleteEmailOtpDurableSealedSessionRecord({
          sessionId,
          deleteReason: result.remainingUses <= 0 ? 'exhausted' : 'expired',
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
      await this.deleteEmailOtpDurableSealedSessionRecord({
        sessionId,
        deleteReason: result.code,
      });
    }
  }

  private resolveEmailOtpEcdsaSealedRecordFilter(
    sessionId: string,
  ): SigningSessionSealedRecordFilter | null {
    const record = this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId(sessionId);
    const chainTarget = record?.chainTarget;
    if (!chainTarget) return null;
    return { authMethod: 'email_otp', curve: 'ecdsa', chainTarget };
  }
}
