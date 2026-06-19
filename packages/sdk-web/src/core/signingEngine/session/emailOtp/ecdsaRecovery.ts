import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '@/core/signingEngine/session/warmCapabilities/routerAbEcdsaWalletSessionAuth';
import {
  sealedRecoverySessionKind,
  sealedRecoveryWalletSessionJwt,
  type EmailOtpEcdsaSealedRecoveryRecord,
  type SealedRecoveryWalletSessionAuth,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import { walletSessionAuthFromPersistedEd25519Record } from '@/core/signingEngine/session/walletSessionAuthBoundary';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
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

export type EmailOtpEcdsaSealedRecoveryPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    walletId: WalletId;
    primaryChain: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }) => Promise<void>;
  requireRpId: (operation: string) => string;
};

export type EmailOtpEcdsaSealedRecoveryInput = EmailOtpEcdsaSealedRecoveryPorts &
  EmailOtpEcdsaSealedRecoveryRecordInput;

type EmailOtpCompanionEd25519Session = {
  nearAccountId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  runtimePolicyScope?: ThresholdEd25519SessionRecord['runtimePolicyScope'];
  routerAbNormalSigning?: ThresholdEd25519SessionRecord['routerAbNormalSigning'];
  walletSessionAuth: SealedRecoveryWalletSessionAuth;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

function restoreBootstrapWithDurableEcdsaFacts(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
}): ThresholdEcdsaSessionBootstrapResult {
  const ethereumAddress = String(args.sealedRecord.ethereumAddress || '').trim();
  const thresholdEcdsaPublicKeyB64u = String(
    args.sealedRecord.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  return {
    keygen: {
      ...args.bootstrap.keygen,
      ...(ethereumAddress ? { ethereumAddress } : {}),
      ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
    },
    session: args.bootstrap.session,
    thresholdEcdsaKeyRef: {
      ...args.bootstrap.thresholdEcdsaKeyRef,
      ...(ethereumAddress ? { ethereumAddress } : {}),
      ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
    },
  };
}

function defaultEmailOtpSessionAuthContext(): ThresholdEcdsaEmailOtpAuthContext {
  return {
    policy: 'session',
    retention: 'session',
    reason: 'login',
    authMethod: 'email_otp',
  };
}

function resolveEmailOtpCompanionEd25519Session(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  walletSigningSessionId: string;
  ed25519Record?: ThresholdEd25519SessionRecord | null;
}): EmailOtpCompanionEd25519Session | null {
  const sealedCompanion =
    args.sealedRecord.companionEd25519Recovery &&
    args.sealedRecord.companionEd25519Recovery.walletSigningSessionId ===
      args.walletSigningSessionId
      ? args.sealedRecord.companionEd25519Recovery
      : null;
  const ed25519Record =
    args.ed25519Record &&
    args.ed25519Record.source === 'email_otp' &&
    args.ed25519Record.emailOtpAuthContext?.retention === 'session' &&
    args.ed25519Record.walletSigningSessionId === args.walletSigningSessionId
      ? args.ed25519Record
      : null;
  if (ed25519Record) {
    const walletSessionAuth = walletSessionAuthFromPersistedEd25519Record(ed25519Record);
    if (!walletSessionAuth) return null;
    const matchingSealedCompanion =
      sealedCompanion?.thresholdSessionId === ed25519Record.thresholdSessionId
        ? sealedCompanion
        : null;
    return {
      nearAccountId: String(ed25519Record.nearAccountId),
      rpId: ed25519Record.rpId,
      relayerUrl: ed25519Record.relayerUrl,
      relayerKeyId: ed25519Record.relayerKeyId,
      participantIds: [...ed25519Record.participantIds],
      ...(ed25519Record.runtimePolicyScope
        ? { runtimePolicyScope: ed25519Record.runtimePolicyScope }
        : {}),
      ...(ed25519Record.routerAbNormalSigning
        ? { routerAbNormalSigning: ed25519Record.routerAbNormalSigning }
        : matchingSealedCompanion?.routerAbNormalSigning
          ? { routerAbNormalSigning: matchingSealedCompanion.routerAbNormalSigning }
          : {}),
      walletSessionAuth,
      thresholdSessionId: ed25519Record.thresholdSessionId,
      walletSigningSessionId: args.walletSigningSessionId,
      emailOtpAuthContext: ed25519Record.emailOtpAuthContext || defaultEmailOtpSessionAuthContext(),
    };
  }

  const companion = sealedCompanion;
  if (!companion) return null;
  return {
    nearAccountId: args.sealedRecord.walletId,
    rpId: companion.rpId,
    relayerUrl: companion.relayerUrl,
    relayerKeyId: companion.relayerKeyId,
    participantIds: [...companion.participantIds],
    ...(companion.runtimePolicyScope ? { runtimePolicyScope: companion.runtimePolicyScope } : {}),
    walletSessionAuth: companion.walletSessionAuth,
    thresholdSessionId: companion.thresholdSessionId,
    walletSigningSessionId: companion.walletSigningSessionId,
    emailOtpAuthContext: defaultEmailOtpSessionAuthContext(),
    ...(companion.routerAbNormalSigning
      ? { routerAbNormalSigning: companion.routerAbNormalSigning }
      : {}),
  };
}

export function createEmailOtpEcdsaSigningSessionMaterialRestorer(
  ports: EmailOtpEcdsaSealedRecoveryPorts,
): (args: EmailOtpEcdsaSealedRecoveryRecordInput) => Promise<EmailOtpThresholdEcdsaRehydrateResult | null> {
  return async (args) =>
    await restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
      ...ports,
      ...args,
    });
}

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
  const ecdsaWalletSessionAuth = ecdsaRecord
    ? resolveRouterAbEcdsaWalletSessionAuthFromRecord(ecdsaRecord)
    : null;
  const walletSessionJwt = String(
    (ecdsaWalletSessionAuth?.kind === 'ready' ? ecdsaWalletSessionAuth.walletSessionJwt : '') ||
      sealedRecoveryWalletSessionJwt(sealedRecord.walletSessionAuth) ||
      '',
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
    ecdsaRecord?.chainTarget &&
    !thresholdEcdsaChainTargetsEqual(ecdsaRecord.chainTarget, sealedRecord.chainTarget)
  ) {
    throw new Error('Email OTP sealed refresh chain target mismatch');
  }
  if (ecdsaRecord?.signingRootId || ecdsaRecord?.signingRootVersion) {
    if (
      ecdsaRecord.signingRootId &&
      ecdsaRecord.signingRootId !== sealedRecord.signingRootId
    ) {
      throw new Error('Email OTP sealed refresh signing-root id mismatch');
    }
    if (
      ecdsaRecord.signingRootVersion &&
      ecdsaRecord.signingRootVersion !== sealedRecord.signingRootVersion
    ) {
      throw new Error('Email OTP sealed refresh signing-root version mismatch');
    }
  }
  const restoreChainTarget = ecdsaRecord?.chainTarget || sealedRecord.chainTarget;
  const restoreKeyHandle = ecdsaRecord?.keyHandle || sealedRecord.keyHandle;
  const restoreRelayerKeyId = ecdsaRecord?.relayerKeyId || sealedRecord.relayerKeyId;
  const restoreParticipantIds = ecdsaRecord?.participantIds || sealedRecord.participantIds;
  const restoreSessionKind =
    ecdsaRecord?.thresholdSessionKind || sealedRecoverySessionKind(sealedRecord.walletSessionAuth);
  const restoreRuntimePolicyScope =
    ecdsaRecord?.runtimePolicyScope || sealedRecord.runtimePolicyScope;
  if (restoreSessionKind !== 'jwt') {
    throw new Error('Email OTP sealed refresh requires JWT Wallet Session restore metadata');
  }
  if (
    !restoreChainTarget ||
    !restoreKeyHandle ||
    !restoreRelayerKeyId ||
    !restoreParticipantIds?.length ||
    !walletSessionJwt
  ) {
    throw new Error('Email OTP sealed refresh is missing durable ECDSA restore metadata');
  }
  const ed25519Session = resolveEmailOtpCompanionEd25519Session({
    sealedRecord,
    walletSigningSessionId,
    ed25519Record: args.ed25519Record,
  });
  if (ed25519Session) {
    throw new Error(
      'Email OTP sealed refresh companion Ed25519 recovery requires worker-owned material restore',
    );
  }

  const restored = await requestRehydrateEmailOtpEcdsaWarmSessionMaterial({
    workerCtx,
    sealedSecretB64u: sealedRecord.sealedSecretB64u,
    remainingUses: sealedRecord.remainingUses,
    expiresAtMs: sealedRecord.expiresAtMs,
    transport: {
      relayerUrl,
      ...(walletSessionJwt ? { walletSessionJwt } : {}),
      ...(keyVersion ? { keyVersion } : {}),
      shamirPrimeB64u,
    },
    restore: {
      sessionId: thresholdSessionId,
      walletId: sealedRecord.walletId,
      rpId: args.requireRpId('Email OTP sealed refresh'),
      chainTarget: restoreChainTarget,
      walletSigningSessionId,
      keyHandle: restoreKeyHandle,
      relayerKeyId: restoreRelayerKeyId,
      participantIds: [...restoreParticipantIds],
      sessionKind: restoreSessionKind,
      ...(restoreRuntimePolicyScope ? { runtimePolicyScope: restoreRuntimePolicyScope } : {}),
    },
  });
  if (!restored.ok) {
    throw new Error(restored.message || restored.code || 'Email OTP sealed refresh failed');
  }

  const restoredBootstrap = restoreBootstrapWithDurableEcdsaFacts({
    bootstrap: restored.bootstrap,
    sealedRecord,
  });
  const { bootstrap, warmCapability } = await args.commitEvmFamilyThresholdEcdsaSessions({
    walletId: toWalletId(ecdsaRecord?.walletId || sealedRecord.walletId),
    primaryChain: restoreChainTarget,
    bootstrap: restoredBootstrap,
    source: 'email_otp',
    emailOtpAuthContext,
  });
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
