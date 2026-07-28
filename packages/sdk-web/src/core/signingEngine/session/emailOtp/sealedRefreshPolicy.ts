import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  deleteDurableSealedSessionRecord,
  updateExactSealedSessionPolicy,
  readExactSealedSession,
  SigningSessionSealedRecordFilter,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  createDeleteDurableSealedSessionCommand,
  type DurableSealedSessionDeleteReason,
} from '@/core/signingEngine/session/persistence/durableSealedSessionCommands';
import type { ExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';

/** Only invalid persisted state justifies destroying sealed material. Expiry
 * and exhaustion are Refactor 92 authorization states: they compose with an
 * unchanged material hydration result and cannot remove its activation, so the
 * sealed secret survives them for rehydration after re-authorization. */
export type EmailOtpDurableSealedSessionDeleteReason = Extract<
  DurableSealedSessionDeleteReason,
  'invalid_persisted_record'
>;

export type EmailOtpSealedRefreshPolicyPorts = {
  /** Resolves the exact sealed runtime for a signing session. Chain target,
   * allowance, expiry and the exact sealed-record identity all come from it. */
  resolveSealedRuntimeForSession: (
    thresholdSessionId: string,
  ) => Promise<ExactEcdsaSealedRuntime | null>;
  deleteDurableSealedSessionRecord: typeof deleteDurableSealedSessionRecord;
  updateExactSealedSessionPolicy: typeof updateExactSealedSessionPolicy;
  readExactSealedSession: typeof readExactSealedSession;
  clearEcdsaRestoreCaches: () => void;
};

export class EmailOtpSealedRefreshPolicy {
  constructor(private readonly ports: EmailOtpSealedRefreshPolicyPorts) {}

  private async sealedRecordFilter(
    thresholdSessionId: string,
  ): Promise<{ filter: SigningSessionSealedRecordFilter; runtime: ExactEcdsaSealedRuntime } | null> {
    const runtime = await this.ports.resolveSealedRuntimeForSession(thresholdSessionId);
    if (!runtime) return null;
    return {
      runtime,
      filter: { authMethod: 'email_otp', curve: 'ecdsa', chainTarget: runtime.chainTarget },
    };
  }

  /** Corrupt persisted state only. Expiry and exhaustion never reach here. */
  async deleteEmailOtpDurableSealedSessionRecord(args: {
    sessionId: string;
    deleteReason: EmailOtpDurableSealedSessionDeleteReason;
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const resolved = await this.sealedRecordFilter(sessionId);
    if (!resolved) {
      this.ports.clearEcdsaRestoreCaches();
      return;
    }
    const command = createDeleteDurableSealedSessionCommand({
      durableRecord: {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        thresholdSessionId: resolved.runtime.sealedRecord.thresholdSessionId,
        chainTarget: resolved.runtime.chainTarget,
      },
      deleteReason: args.deleteReason,
      preserveResolvedIdentity: false,
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

  /** Writes the observed allowance and expiry to the exact sealed record this
   * session resolved to. Expiry and exhaustion are written the same way as any
   * other use: the reusable Wallet Session stops authorizing new operations,
   * and the caller requests step-up, while the sealed material and its
   * activation stay intact for rehydration afterwards. */
  private async recordSessionPolicyResult(args: {
    sessionId: string;
    result: WarmSessionStatusResult | WarmSessionClaimResult;
  }): Promise<void> {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) return;
    const result = args.result;
    if (!result.ok) {
      // expired / exhausted invalidate the authorization projection and the
      // restore caches. They deliberately do not touch sealed material.
      this.ports.clearEcdsaRestoreCaches();
      return;
    }
    const resolved = await this.sealedRecordFilter(sessionId);
    if (resolved) {
      await this.ports
        .updateExactSealedSessionPolicy({
          thresholdSessionId: resolved.runtime.sealedRecord.thresholdSessionId,
          filter: resolved.filter,
          expiresAtMs: result.expiresAtMs,
          remainingUses: result.remainingUses,
          updatedAtMs: Date.now(),
        })
        .catch(() => undefined);
    }
    this.ports.clearEcdsaRestoreCaches();
  }
}
