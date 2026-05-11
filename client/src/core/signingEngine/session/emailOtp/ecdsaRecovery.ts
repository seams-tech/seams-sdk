import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { upsertStoredThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { EmailOtpEcdsaSealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import { requestRehydrateEmailOtpEcdsaWarmSessionMaterial } from './workerRequests';

export type EmailOtpThresholdEcdsaRehydrateResult = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  remainingUses: number;
  expiresAtMs: number;
  ed25519RestoreSeedB64u?: string;
};

export type EmailOtpEcdsaSealedRecoveryRecordInput = {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  ecdsaRecord?: ThresholdEcdsaSessionRecord | null;
  ed25519Record?: ThresholdEd25519SessionRecord | null;
};

export type EmailOtpEcdsaSealedRecoveryInput = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    nearAccountId: string;
    primaryChain: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionAuthToken?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }) => Promise<void>;
  requireRpId: (operation: string) => string;
} & EmailOtpEcdsaSealedRecoveryRecordInput & {
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

export async function restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord(
  args: EmailOtpEcdsaSealedRecoveryInput,
): Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
  const sealedRecord = args.sealedRecord;
  const ecdsaRecord = args.ecdsaRecord || null;
  if (sealedRecord.authMethod !== 'email_otp' || sealedRecord.curve !== 'ecdsa') {
    return null;
  }
  if (ecdsaRecord && ecdsaRecord.source !== 'email_otp') return null;
  const emailOtpAuthContext =
    ecdsaRecord?.emailOtpAuthContext ||
    ({
      policy: 'session',
      retention: 'session',
      reason: 'login',
      authMethod: 'email_otp',
    } satisfies ThresholdEcdsaEmailOtpAuthContext);
  if (emailOtpAuthContext.retention !== 'session') return null;

  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP sealed refresh requires the dedicated emailOtp worker');
  }

  const thresholdSessionId = String(
    ecdsaRecord?.thresholdSessionId || sealedRecord.thresholdSessionId || '',
  ).trim();
  const walletSigningSessionId = String(
    ecdsaRecord?.walletSigningSessionId || sealedRecord.walletSigningSessionId || '',
  ).trim();
  const relayerUrl = String(ecdsaRecord?.relayerUrl || sealedRecord.relayerUrl || '').trim();
  const shamirPrimeB64u = String(
    ecdsaRecord?.signingSessionSealShamirPrimeB64u ||
      sealedRecord.shamirPrimeB64u ||
      args.configs.signing.sessionSeal?.shamirPrimeB64u ||
      '',
  ).trim();
  const thresholdSessionAuthToken = String(
    ecdsaRecord?.thresholdSessionAuthToken || sealedRecord.thresholdSessionAuthToken || '',
  ).trim();
  const keyVersion = String(
    sealedRecord.keyVersion ||
      ecdsaRecord?.signingSessionSealKeyVersion ||
      args.configs.signing.sessionSeal?.keyVersion ||
      '',
  ).trim();
  if (sealedRecord.expiresAtMs <= Date.now()) {
    throw new Error('Email OTP sealed refresh expired sealed record');
  }
  if (sealedRecord.remainingUses <= 0) {
    throw new Error('Email OTP sealed refresh exhausted sealed record');
  }
  if (!thresholdSessionId || !walletSigningSessionId || !relayerUrl || !shamirPrimeB64u) {
    throw new Error('Email OTP sealed refresh is missing threshold-session restore metadata');
  }
  if (
    ecdsaRecord?.thresholdSessionId &&
    ecdsaRecord.thresholdSessionId !== sealedRecord.thresholdSessionId
  ) {
    throw new Error('Email OTP sealed refresh threshold-session id mismatch');
  }
  if (
    ecdsaRecord?.walletSigningSessionId &&
    ecdsaRecord.walletSigningSessionId !== sealedRecord.walletSigningSessionId
  ) {
    throw new Error('Email OTP sealed refresh wallet signing-session id mismatch');
  }
  if (
    sealedRecord.signingRootId &&
    ecdsaRecord?.signingRootId &&
    sealedRecord.signingRootId !== ecdsaRecord.signingRootId
  ) {
    throw new Error('Email OTP sealed refresh signing-root id mismatch');
  }
  if (
    sealedRecord.signingRootVersion &&
    ecdsaRecord?.signingRootVersion &&
    sealedRecord.signingRootVersion !== ecdsaRecord.signingRootVersion
  ) {
    throw new Error('Email OTP sealed refresh signing-root version mismatch');
  }
  if (
    ecdsaRecord?.chainTarget &&
    !thresholdEcdsaChainTargetsEqual(ecdsaRecord.chainTarget, sealedRecord.chainTarget)
  ) {
    throw new Error('Email OTP sealed refresh chain target mismatch');
  }
  const restoreChainTarget = ecdsaRecord?.chainTarget || sealedRecord.chainTarget;
  const restoreSigningRootId = ecdsaRecord?.signingRootId || sealedRecord.signingRootId;
  const restoreEcdsaThresholdKeyId =
    ecdsaRecord?.ecdsaThresholdKeyId || sealedRecord.ecdsaThresholdKeyId;
  const restoreRelayerKeyId = ecdsaRecord?.relayerKeyId || sealedRecord.relayerKeyId;
  const restoreParticipantIds = ecdsaRecord?.participantIds || sealedRecord.participantIds;
  const restoreSubjectId = toWalletSubjectId(ecdsaRecord?.subjectId || sealedRecord.subjectId);
  const restoreSessionKind = ecdsaRecord?.thresholdSessionKind || sealedRecord.sessionKind || 'jwt';
  const restoreRuntimePolicyScope =
    ecdsaRecord?.runtimePolicyScope || sealedRecord.runtimePolicyScope;
  if (
    !restoreChainTarget ||
    !restoreSigningRootId ||
    !restoreEcdsaThresholdKeyId ||
    !restoreRelayerKeyId ||
    !restoreParticipantIds?.length ||
    (restoreSessionKind === 'jwt' && !thresholdSessionAuthToken)
  ) {
    throw new Error('Email OTP sealed refresh is missing durable ECDSA restore metadata');
  }
  const ed25519Record =
    args.ed25519Record &&
    args.ed25519Record.source === 'email_otp' &&
    args.ed25519Record.emailOtpAuthContext?.retention === 'session' &&
    args.ed25519Record.walletSigningSessionId === walletSigningSessionId
      ? args.ed25519Record
      : null;

  const restored = await requestRehydrateEmailOtpEcdsaWarmSessionMaterial({
    workerCtx,
    sealedSecretB64u: sealedRecord.sealedSecretB64u,
    remainingUses: sealedRecord.remainingUses,
    expiresAtMs: sealedRecord.expiresAtMs,
    transport: {
      relayerUrl,
      ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
      ...(keyVersion ? { keyVersion } : {}),
      shamirPrimeB64u,
    },
    restore: {
      sessionId: thresholdSessionId,
      walletId: sealedRecord.walletId,
      subjectId: restoreSubjectId,
      userId: sealedRecord.walletId,
      rpId: args.requireRpId('Email OTP sealed refresh'),
      chainTarget: restoreChainTarget,
      walletSigningSessionId,
      signingRootId: restoreSigningRootId,
      ...(ecdsaRecord?.signingRootVersion || sealedRecord.signingRootVersion
        ? {
            signingRootVersion:
              ecdsaRecord?.signingRootVersion || sealedRecord.signingRootVersion,
          }
        : {}),
      ecdsaThresholdKeyId: restoreEcdsaThresholdKeyId,
      relayerKeyId: restoreRelayerKeyId,
      participantIds: [...restoreParticipantIds],
      sessionKind: restoreSessionKind,
      ...(restoreRuntimePolicyScope ? { runtimePolicyScope: restoreRuntimePolicyScope } : {}),
      ...(ed25519Record
        ? {
            ed25519: {
              sessionId: ed25519Record.thresholdSessionId,
              relayerKeyId: ed25519Record.relayerKeyId,
              participantIds: ed25519Record.participantIds,
            },
          }
        : {}),
    },
  });
  if (!restored.ok) {
    throw new Error(restored.message || restored.code || 'Email OTP sealed refresh failed');
  }

  const { bootstrap, warmCapability } = await args.commitEvmFamilyThresholdEcdsaSessions({
    nearAccountId: ecdsaRecord?.nearAccountId || sealedRecord.walletId,
    primaryChain: restoreChainTarget,
    bootstrap: restored.bootstrap,
    source: 'email_otp',
    emailOtpAuthContext,
    ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
  });
  if (ed25519Record) {
    upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: ed25519Record.nearAccountId,
      rpId: ed25519Record.rpId,
      relayerUrl: ed25519Record.relayerUrl,
      relayerKeyId: ed25519Record.relayerKeyId,
      participantIds: [...ed25519Record.participantIds],
      ...(ed25519Record.runtimePolicyScope
        ? { runtimePolicyScope: ed25519Record.runtimePolicyScope }
        : {}),
      ...(ed25519Record.xClientBaseB64u
        ? { xClientBaseB64u: ed25519Record.xClientBaseB64u }
        : {}),
      thresholdSessionKind: ed25519Record.thresholdSessionKind,
      thresholdSessionId: ed25519Record.thresholdSessionId,
      ...(ed25519Record.walletSigningSessionId
        ? { walletSigningSessionId: ed25519Record.walletSigningSessionId }
        : {}),
      thresholdSessionAuthToken: ed25519Record.thresholdSessionAuthToken,
      expiresAtMs: restored.expiresAtMs,
      remainingUses: restored.remainingUses,
      ...(ed25519Record.emailOtpAuthContext
        ? { emailOtpAuthContext: ed25519Record.emailOtpAuthContext }
        : {}),
      updatedAtMs: Date.now(),
      source: ed25519Record.source,
    });
    if (restored.ed25519RestoreSeedB64u) {
      await args.hydrateSigningSession({
        sessionId: ed25519Record.thresholdSessionId,
        prfFirstB64u: restored.ed25519RestoreSeedB64u,
        expiresAtMs: restored.expiresAtMs,
        remainingUses: restored.remainingUses,
        transport: {
          curve: 'ed25519',
          relayerUrl: ed25519Record.relayerUrl,
          ...(ed25519Record.thresholdSessionAuthToken
            ? { thresholdSessionAuthToken: ed25519Record.thresholdSessionAuthToken }
            : {}),
        },
      });
    }
  }
  return {
    bootstrap,
    warmCapability,
    remainingUses: restored.remainingUses,
    expiresAtMs: restored.expiresAtMs,
    ...(restored.ed25519RestoreSeedB64u
      ? { ed25519RestoreSeedB64u: restored.ed25519RestoreSeedB64u }
      : {}),
  };
}
