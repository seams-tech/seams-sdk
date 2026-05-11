import type { AccountId } from '@/core/types/accountIds';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import { WalletAuthPolicyError } from '../../walletAuth';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EcdsaPostSignPolicyMaterialClearer = (args: {
  record: ThresholdEcdsaSessionRecord;
  thresholdSessionId: string;
}) => Promise<void>;

export type EcdsaPostSignPolicySession = {
  nearAccountId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  thresholdSessionId: string;
  emailOtpRetention: 'session' | 'single_use' | null;
  emailOtpConsumedAtMs: number | null;
};

export type EcdsaPostSignPolicyMaterial = {
  session: EcdsaPostSignPolicySession;
  clearEphemeralMaterial: () => Promise<void>;
};

export function ecdsaPostSignPolicySessionFromRecord(
  record: ThresholdEcdsaSessionRecord,
): EcdsaPostSignPolicySession {
  const consumedAtMs = Math.floor(Number(record.emailOtpAuthContext?.consumedAtMs));
  return {
    nearAccountId: record.nearAccountId,
    chainTarget: record.chainTarget,
    source: record.source,
    thresholdSessionId: String(record.thresholdSessionId || '').trim(),
    emailOtpRetention: record.emailOtpAuthContext?.retention || null,
    emailOtpConsumedAtMs: Number.isFinite(consumedAtMs) && consumedAtMs > 0 ? consumedAtMs : null,
  };
}

export function ecdsaPostSignPolicyMaterialFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  clearEcdsaEphemeralMaterial: EcdsaPostSignPolicyMaterialClearer;
}): EcdsaPostSignPolicyMaterial {
  const session = ecdsaPostSignPolicySessionFromRecord(args.record);
  return {
    session,
    clearEphemeralMaterial: async () => {
      await args.clearEcdsaEphemeralMaterial({
        record: args.record,
        thresholdSessionId: session.thresholdSessionId,
      });
    },
  };
}

export async function applyEcdsaPostSignPolicy(args: {
  thresholdSessionId: string | null;
  source: ThresholdEcdsaSessionStoreSource | null;
  selectedMaterial: EcdsaPostSignPolicyMaterial | null;
  secondaryMaterial: EcdsaPostSignPolicyMaterial | null;
  markEmailOtpSessionConsumed?: (args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  }) => void;
}): Promise<void> {
  const selectedMaterial = args.selectedMaterial;
  const secondaryMaterial = args.source ? null : args.secondaryMaterial;
  const effectiveEmailOtpMaterial =
    selectedMaterial?.session.source === 'email_otp'
      ? selectedMaterial
      : !args.source && secondaryMaterial?.session.source === 'email_otp'
        ? secondaryMaterial
        : null;
  if (!effectiveEmailOtpMaterial) return;

  if (args.thresholdSessionId && selectedMaterial?.session.source === 'email_otp') {
    const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
    const actualThresholdSessionId = selectedMaterial.session.thresholdSessionId;
    if (
      expectedThresholdSessionId &&
      actualThresholdSessionId &&
      expectedThresholdSessionId !== actualThresholdSessionId
    ) {
      return;
    }
  }

  if (effectiveEmailOtpMaterial.session.emailOtpRetention !== 'single_use') return;
  args.markEmailOtpSessionConsumed?.({
    nearAccountId: effectiveEmailOtpMaterial.session.nearAccountId,
    chainTarget: effectiveEmailOtpMaterial.session.chainTarget,
    uses: 1,
  });
  await effectiveEmailOtpMaterial.clearEphemeralMaterial();
}

export function formatEmailOtpSensitiveOperationError(args: {
  operationLabel: string;
  mode: 'passkey' | 'per_operation';
}): Error {
  if (args.mode === 'per_operation') {
    return new WalletAuthPolicyError({
      code: 'fresh_email_otp_required',
      policy: 'sensitive_operation_requires_fresh_email_otp',
      operationLabel: args.operationLabel,
      message: `[SigningEngine] ${args.operationLabel} requires fresh Email OTP verification with per_operation policy`,
    });
  }
  return new WalletAuthPolicyError({
    code: 'passkey_step_up_required',
    policy: 'sensitive_operation_requires_passkey',
    operationLabel: args.operationLabel,
    message: `[SigningEngine] ${args.operationLabel} requires fresh passkey authentication after Email OTP login`,
  });
}

export function assertEcdsaOperationAllowed(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  operationLabel: string;
  thresholdSessionId: string | null;
  source: ThresholdEcdsaSessionStoreSource | null;
  selectedSession: EcdsaPostSignPolicySession | null;
  secondarySession: EcdsaPostSignPolicySession | null;
  sensitivePolicy?: SensitiveOperationPolicy;
}): void {
  const selectedSession = args.selectedSession;
  const secondarySession = args.source ? null : args.secondarySession;
  const effectiveSession =
    selectedSession?.source === 'email_otp'
      ? selectedSession
      : !args.source && secondarySession?.source === 'email_otp'
        ? secondarySession
        : null;
  if (!effectiveSession) return;

  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const actualThresholdSessionId = effectiveSession.thresholdSessionId;
  if (
    thresholdSessionId &&
    actualThresholdSessionId &&
    thresholdSessionId !== actualThresholdSessionId
  ) {
    return;
  }
  if (
    effectiveSession.emailOtpRetention === 'single_use' &&
    Number(effectiveSession.emailOtpConsumedAtMs) > 0
  ) {
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: args.operationLabel,
      mode: 'per_operation',
    });
  }
  const sensitivePolicy = args.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy;
  if (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy) return;
  if (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.requireFreshSameMethod) {
    if (effectiveSession.emailOtpRetention === 'single_use') return;
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: args.operationLabel,
      mode: 'per_operation',
    });
  }
  if (
    sensitivePolicy === SENSITIVE_OPERATION_POLICIES.requirePasskey ||
    sensitivePolicy === SENSITIVE_OPERATION_POLICIES.denyEmailOtp
  ) {
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: args.operationLabel,
      mode: 'passkey',
    });
  }
}
