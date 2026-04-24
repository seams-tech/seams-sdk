import type { AccountId } from '@/core/types/accountIds';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import { WalletAuthPolicyError } from '../auth';
import type { ThresholdEcdsaActivationChain } from '../orchestration/thresholdActivation';

export type EcdsaPostSignPolicyMaterialClearer = (args: {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  thresholdSessionId: string;
  source?: ThresholdEcdsaSessionStoreSource;
}) => Promise<void>;

export async function applyEcdsaPostSignPolicy(args: {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  thresholdSessionId?: string;
  source?: ThresholdEcdsaSessionStoreSource;
  selectedRecord?: ThresholdEcdsaSessionRecord | null;
  secondaryRecord?: ThresholdEcdsaSessionRecord | null;
  markEmailOtpSessionConsumed?: (args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
  }) => void;
  clearEcdsaEphemeralMaterial: EcdsaPostSignPolicyMaterialClearer;
}): Promise<void> {
  const selectedRecord = args.selectedRecord || null;
  const secondaryRecord = args.source ? null : args.secondaryRecord || null;
  const effectiveEmailOtpRecord =
    selectedRecord?.source === 'email_otp'
      ? selectedRecord
      : !args.source && secondaryRecord?.source === 'email_otp'
        ? secondaryRecord
        : null;
  const effectiveEmailOtpRecordChain: ThresholdEcdsaActivationChain | null =
    selectedRecord?.source === 'email_otp'
      ? args.chain
      : !args.source && secondaryRecord?.source === 'email_otp'
        ? args.chain === 'tempo'
          ? 'evm'
          : 'tempo'
        : null;
  if (!effectiveEmailOtpRecord) return;

  if (args.thresholdSessionId && selectedRecord?.source === 'email_otp') {
    const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
    const actualThresholdSessionId = String(selectedRecord.thresholdSessionId || '').trim();
    if (
      expectedThresholdSessionId &&
      actualThresholdSessionId &&
      expectedThresholdSessionId !== actualThresholdSessionId
    ) {
      return;
    }
  }

  if (effectiveEmailOtpRecord.emailOtpAuthContext?.retention !== 'single_use') return;
  args.markEmailOtpSessionConsumed?.({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
  });

  const selectedThresholdSessionId = String(
    selectedRecord?.thresholdSessionId || args.thresholdSessionId || '',
  ).trim();
  await args.clearEcdsaEphemeralMaterial({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    thresholdSessionId: selectedThresholdSessionId,
    ...(effectiveEmailOtpRecord.source ? { source: effectiveEmailOtpRecord.source } : {}),
  });

  if (
    effectiveEmailOtpRecordChain !== args.chain ||
    String(effectiveEmailOtpRecord.thresholdSessionId || '').trim() !== selectedThresholdSessionId
  ) {
    await args.clearEcdsaEphemeralMaterial({
      nearAccountId: args.nearAccountId,
      chain: effectiveEmailOtpRecordChain || args.chain,
      thresholdSessionId: effectiveEmailOtpRecord.thresholdSessionId,
      source: effectiveEmailOtpRecord.source,
    });
  }
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
  chain: ThresholdEcdsaActivationChain;
  operationLabel: string;
  thresholdSessionId?: string;
  source?: ThresholdEcdsaSessionStoreSource;
  selectedRecord?: ThresholdEcdsaSessionRecord | null;
  secondaryRecord?: ThresholdEcdsaSessionRecord | null;
  sensitivePolicy?: SensitiveOperationPolicy;
}): void {
  const selectedRecord = args.selectedRecord || null;
  const secondaryRecord = args.source ? null : args.secondaryRecord || null;
  const effectiveRecord =
    selectedRecord?.source === 'email_otp'
      ? selectedRecord
      : !args.source && secondaryRecord?.source === 'email_otp'
        ? secondaryRecord
        : null;
  if (!effectiveRecord) return;

  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const actualThresholdSessionId = String(effectiveRecord.thresholdSessionId || '').trim();
  if (
    thresholdSessionId &&
    actualThresholdSessionId &&
    thresholdSessionId !== actualThresholdSessionId
  ) {
    return;
  }
  if (
    effectiveRecord.emailOtpAuthContext?.retention === 'single_use' &&
    Number(effectiveRecord.emailOtpAuthContext.consumedAtMs) > 0
  ) {
    throw formatEmailOtpSensitiveOperationError({
      operationLabel: args.operationLabel,
      mode: 'per_operation',
    });
  }
  const sensitivePolicy =
    args.sensitivePolicy || SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy;
  if (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.inheritSessionPolicy) return;
  if (sensitivePolicy === SENSITIVE_OPERATION_POLICIES.requireFreshSameMethod) {
    if (effectiveRecord.emailOtpAuthContext?.retention === 'single_use') return;
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
