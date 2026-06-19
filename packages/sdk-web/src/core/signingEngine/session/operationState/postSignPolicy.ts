import type { AccountId } from '@/core/types/accountIds';
import {
  SENSITIVE_OPERATION_POLICIES,
  type SensitiveOperationPolicy,
} from '@shared/utils/signerDomain';
import {
  emailOtpEcdsaPostSignMaterialFromRecord,
  type ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  type ConsumeSingleUseEmailOtpEcdsaLaneResult,
  type EmailOtpEcdsaPostSignMaterial,
  type ThresholdEcdsaSessionRecord,
} from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import { WalletAuthPolicyError } from '../../stepUpConfirmation/walletAuthModeResolver';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EcdsaPostSignPolicyMaterialClearer = (args: {
  record: ThresholdEcdsaSessionRecord;
  thresholdSessionId: string;
}) => Promise<void>;

export type EcdsaPostSignPolicySession = {
  walletId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  signingGrantId: string;
  thresholdSessionId: string;
  emailOtpRetention: 'session' | 'single_use' | null;
  emailOtpConsumedAtMs: number | null;
};

type EcdsaPostSignPolicyMaterialBase = {
  session: EcdsaPostSignPolicySession;
  clearEphemeralMaterial: () => Promise<void>;
};

export type SelectedEcdsaPostSignPolicyMaterial = EcdsaPostSignPolicyMaterialBase & {
  role: 'selected';
  emailOtpPostSignMaterial: EmailOtpEcdsaPostSignMaterial | null;
};

export type SecondaryEcdsaPostSignPolicyMaterial = EcdsaPostSignPolicyMaterialBase & {
  role: 'secondary';
  emailOtpPostSignMaterial?: never;
};

export function ecdsaPostSignPolicySessionFromRecord(
  record: ThresholdEcdsaSessionRecord,
): EcdsaPostSignPolicySession {
  const emailOtpAuthContext = record.source === 'email_otp' ? record.emailOtpAuthContext : null;
  const consumedAtMs = Math.floor(Number(emailOtpAuthContext?.consumedAtMs));
  return {
    walletId: record.walletId,
    chainTarget: record.chainTarget,
    source: record.source,
    signingGrantId: String(record.signingGrantId || '').trim(),
    thresholdSessionId: String(record.thresholdSessionId || '').trim(),
    emailOtpRetention: emailOtpAuthContext?.retention || null,
    emailOtpConsumedAtMs: Number.isFinite(consumedAtMs) && consumedAtMs > 0 ? consumedAtMs : null,
  };
}

function ecdsaPostSignPolicyMaterialBaseFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  clearEcdsaEphemeralMaterial: EcdsaPostSignPolicyMaterialClearer;
}): EcdsaPostSignPolicyMaterialBase {
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

export function selectedEcdsaPostSignPolicyMaterialFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  clearEcdsaEphemeralMaterial: EcdsaPostSignPolicyMaterialClearer;
}): SelectedEcdsaPostSignPolicyMaterial {
  return {
    ...ecdsaPostSignPolicyMaterialBaseFromRecord(args),
    role: 'selected',
    emailOtpPostSignMaterial: emailOtpEcdsaPostSignMaterialFromRecord(args.record),
  };
}

export function secondaryEcdsaPostSignPolicyMaterialFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  clearEcdsaEphemeralMaterial: EcdsaPostSignPolicyMaterialClearer;
}): SecondaryEcdsaPostSignPolicyMaterial {
  return {
    ...ecdsaPostSignPolicyMaterialBaseFromRecord(args),
    role: 'secondary',
  };
}

export async function applyEcdsaPostSignPolicy(args: {
  thresholdSessionId: string | null;
  source: ThresholdEcdsaSessionStoreSource | null;
  selectedMaterial: SelectedEcdsaPostSignPolicyMaterial | null;
  secondaryMaterial: SecondaryEcdsaPostSignPolicyMaterial | null;
  consumeSingleUseEmailOtpEcdsaLane?: (
    command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ) => ConsumeSingleUseEmailOtpEcdsaLaneResult;
}): Promise<void> {
  const selectedMaterial = args.selectedMaterial;
  if (selectedMaterial?.session.source !== 'email_otp') return;

  if (args.thresholdSessionId) {
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

  const emailOtpPostSignMaterial = selectedMaterial.emailOtpPostSignMaterial;
  if (emailOtpPostSignMaterial?.kind !== 'consumable_email_otp_ecdsa_lane') return;
  args.consumeSingleUseEmailOtpEcdsaLane?.({
    kind: 'consume_single_use_email_otp_ecdsa_lane',
    lane: emailOtpPostSignMaterial,
    uses: 1,
  });
  await selectedMaterial.clearEphemeralMaterial();
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
