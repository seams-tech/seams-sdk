import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextRetention,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
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
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { requestRehydrateEmailOtpEcdsaWarmSessionMaterial } from './workerRequests';
import { parseSigningSessionSealKeyVersion } from '../keyMaterialBrands';
import { requireEvmFamilySigningKeySlotId, type EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

export type EmailOtpThresholdEcdsaRehydrateResult = {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
  remainingUses: number;
  expiresAtMs: number;
};

export type EmailOtpEcdsaSealedRecoveryRecordInput = {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  ecdsaRecord?: ThresholdEcdsaSessionRecord | null;
};

export type EmailOtpEcdsaSealedRecoveryPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  commitEvmFamilyThresholdEcdsaSessions: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
};

export type EmailOtpEcdsaSealedRecoveryInput = EmailOtpEcdsaSealedRecoveryPorts &
  EmailOtpEcdsaSealedRecoveryRecordInput;

type EmailOtpEcdsaCurrentRestoreRecord = ThresholdEcdsaSessionRecord & {
  source: 'email_otp';
  thresholdSessionKind: 'jwt';
  signingRootVersion: string;
  participantIds: [number, ...number[]];
};

// Restore sources are intentionally disjoint. Current-record restore may use
// persisted lane identity; sealed-record restore must carry its full identity.
export type EmailOtpEcdsaRestoreSource =
  | {
      kind: 'sealed_record_restore';
      sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
      ecdsaRecord?: never;
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      walletSessionJwt: string;
      thresholdSessionId: string;
      signingGrantId: string;
      relayerUrl: string;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      relayerKeyId: string;
      participantIds: readonly number[];
      sessionKind: 'jwt';
      signingSessionSealKeyVersion: string;
      signingSessionSealShamirPrimeB64u: string;
      runtimePolicyScope?: EmailOtpEcdsaSealedRecoveryRecord['runtimePolicyScope'];
    }
  | {
      kind: 'current_record_restore';
      sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
      ecdsaRecord: EmailOtpEcdsaCurrentRestoreRecord;
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      walletSessionJwt: string;
      thresholdSessionId: string;
      signingGrantId: string;
      relayerUrl: string;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      relayerKeyId: string;
      participantIds: readonly number[];
      sessionKind: 'jwt';
      signingSessionSealKeyVersion: string;
      signingSessionSealShamirPrimeB64u: string;
      runtimePolicyScope?: ThresholdEcdsaSessionRecord['runtimePolicyScope'];
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

function sealedRecordEmailOtpSessionAuthContext(
  authority: EmailOtpWalletAuthAuthority,
): ThresholdEcdsaEmailOtpAuthContext {
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy: 'session',
    walletId: toWalletId(authority.walletId),
    emailHashHex: authority.verifier.emailHashHex,
    retention: 'session',
    reason: 'login',
    provider: authority.factor.provider,
    providerUserId: authority.factor.providerUserId,
  });
}

function requireEmailOtpEcdsaSealedTransportSource(
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord,
): {
  signingSessionSealKeyVersion: string;
  signingSessionSealShamirPrimeB64u: string;
} {
  const signingSessionSealKeyVersion = String(sealedRecord.keyVersion || '').trim();
  const signingSessionSealShamirPrimeB64u = String(sealedRecord.shamirPrimeB64u || '').trim();
  if (!signingSessionSealKeyVersion || !signingSessionSealShamirPrimeB64u) {
    throw new Error('Email OTP sealed refresh is missing normalized seal transport metadata');
  }
  return {
    signingSessionSealKeyVersion,
    signingSessionSealShamirPrimeB64u,
  };
}

function requireEmailOtpSealedWalletSessionJwt(
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord,
): string {
  const walletSessionJwt = sealedRecoveryWalletSessionJwt(sealedRecord.walletSessionAuth);
  if (!walletSessionJwt) {
    throw new Error('Email OTP sealed refresh is missing sealed Wallet Session JWT');
  }
  return walletSessionJwt;
}

function requireEmailOtpCurrentWalletSessionJwt(record: ThresholdEcdsaSessionRecord): string {
  const ecdsaWalletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  const walletSessionJwt =
    ecdsaWalletSessionAuth?.kind === 'ready' ? ecdsaWalletSessionAuth.walletSessionJwt : '';
  if (!walletSessionJwt) {
    throw new Error('Email OTP sealed refresh current record is missing Wallet Session JWT');
  }
  return walletSessionJwt;
}

function runtimePolicyScopesMatch(
  left: ThresholdEcdsaSessionRecord['runtimePolicyScope'] | undefined,
  right: EmailOtpEcdsaSealedRecoveryRecord['runtimePolicyScope'] | undefined,
): boolean {
  return JSON.stringify(left ?? null) === JSON.stringify(right ?? null);
}

function participantIdsMatch(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function verifyEmailOtpEcdsaCurrentRecordMatchesSealedRecord(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  ecdsaRecord: ThresholdEcdsaSessionRecord;
}): asserts args is {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  ecdsaRecord: EmailOtpEcdsaCurrentRestoreRecord;
} {
  const { sealedRecord, ecdsaRecord } = args;
  if (ecdsaRecord.source !== 'email_otp') {
    throw new Error('Email OTP sealed refresh requires an Email OTP current ECDSA record');
  }
  if (ecdsaRecord.walletId !== sealedRecord.walletId) {
    throw new Error('Email OTP sealed refresh wallet id mismatch');
  }
  if (ecdsaRecord.thresholdSessionKind !== 'jwt') {
    throw new Error('Email OTP sealed refresh requires JWT Wallet Session restore metadata');
  }
  if (ecdsaRecord.thresholdSessionId !== sealedRecord.thresholdSessionId) {
    throw new Error('Email OTP sealed refresh threshold-session id mismatch');
  }
  if (ecdsaRecord.signingGrantId !== sealedRecord.signingGrantId) {
    throw new Error('Email OTP sealed refresh signing grant id mismatch');
  }
  if (!thresholdEcdsaChainTargetsEqual(ecdsaRecord.chainTarget, sealedRecord.chainTarget)) {
    throw new Error('Email OTP sealed refresh chain target mismatch');
  }
  if (ecdsaRecord.signingRootId !== sealedRecord.signingRootId) {
    throw new Error('Email OTP sealed refresh signing-root id mismatch');
  }
  if (!ecdsaRecord.signingRootVersion) {
    throw new Error('Email OTP sealed refresh current record is missing signing-root version');
  }
  if (ecdsaRecord.signingRootVersion !== sealedRecord.signingRootVersion) {
    throw new Error('Email OTP sealed refresh signing-root version mismatch');
  }
  if (ecdsaRecord.relayerUrl !== sealedRecord.relayerUrl) {
    throw new Error('Email OTP sealed refresh relayer URL mismatch');
  }
  if (ecdsaRecord.keyHandle !== sealedRecord.keyHandle) {
    throw new Error('Email OTP sealed refresh key handle mismatch');
  }
  if (ecdsaRecord.relayerKeyId !== sealedRecord.relayerKeyId) {
    throw new Error('Email OTP sealed refresh relayer key id mismatch');
  }
  if (!participantIdsMatch(ecdsaRecord.participantIds, sealedRecord.participantIds)) {
    throw new Error('Email OTP sealed refresh participant ids mismatch');
  }
  if (!runtimePolicyScopesMatch(ecdsaRecord.runtimePolicyScope, sealedRecord.runtimePolicyScope)) {
    throw new Error('Email OTP sealed refresh runtime-policy scope mismatch');
  }
  if (
    ecdsaRecord.signingSessionSealKeyVersion &&
    ecdsaRecord.signingSessionSealKeyVersion !== sealedRecord.keyVersion
  ) {
    throw new Error('Email OTP sealed refresh seal key version mismatch');
  }
  if (
    ecdsaRecord.signingSessionSealShamirPrimeB64u &&
    ecdsaRecord.signingSessionSealShamirPrimeB64u !== sealedRecord.shamirPrimeB64u
  ) {
    throw new Error('Email OTP sealed refresh Shamir prime mismatch');
  }
}

function buildSealedRecordEmailOtpEcdsaRestoreSource(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
}): EmailOtpEcdsaRestoreSource {
  const { sealedRecord } = args;
  const transport = requireEmailOtpEcdsaSealedTransportSource(sealedRecord);
  const sessionKind = sealedRecoverySessionKind(sealedRecord.walletSessionAuth);
  if (sessionKind !== 'jwt') {
    throw new Error('Email OTP sealed refresh requires JWT Wallet Session restore metadata');
  }
  const walletSessionJwt = requireEmailOtpSealedWalletSessionJwt(sealedRecord);
  if (
    !sealedRecord.thresholdSessionId ||
    !sealedRecord.signingGrantId ||
    !sealedRecord.relayerUrl ||
    !sealedRecord.keyHandle ||
    !sealedRecord.relayerKeyId ||
    !sealedRecord.participantIds.length
  ) {
    throw new Error('Email OTP sealed refresh is missing durable ECDSA restore metadata');
  }
  return {
    kind: 'sealed_record_restore',
    sealedRecord,
    emailOtpAuthContext: sealedRecordEmailOtpSessionAuthContext(sealedRecord.authority),
    walletSessionJwt,
    thresholdSessionId: sealedRecord.thresholdSessionId,
    signingGrantId: sealedRecord.signingGrantId,
    relayerUrl: sealedRecord.relayerUrl,
    chainTarget: sealedRecord.chainTarget,
    keyHandle: sealedRecord.keyHandle,
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(sealedRecord.evmFamilySigningKeySlotId),
    relayerKeyId: sealedRecord.relayerKeyId,
    participantIds: [...sealedRecord.participantIds],
    sessionKind,
    ...transport,
    ...(sealedRecord.runtimePolicyScope
      ? { runtimePolicyScope: sealedRecord.runtimePolicyScope }
      : {}),
  };
}

function buildCurrentRecordEmailOtpEcdsaRestoreSource(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  ecdsaRecord: ThresholdEcdsaSessionRecord;
}): EmailOtpEcdsaRestoreSource {
  verifyEmailOtpEcdsaCurrentRecordMatchesSealedRecord(args);
  const { sealedRecord, ecdsaRecord } = args;
  const transport = requireEmailOtpEcdsaSealedTransportSource(sealedRecord);
  const walletSessionJwt = requireEmailOtpCurrentWalletSessionJwt(ecdsaRecord);
  if (
    !ecdsaRecord.relayerUrl ||
    !ecdsaRecord.keyHandle ||
    !ecdsaRecord.relayerKeyId ||
    !ecdsaRecord.participantIds.length
  ) {
    throw new Error('Email OTP sealed refresh current record is missing ECDSA restore metadata');
  }
  return {
    kind: 'current_record_restore',
    sealedRecord,
    ecdsaRecord,
    emailOtpAuthContext: ecdsaRecord.emailOtpAuthContext,
    walletSessionJwt,
    thresholdSessionId: ecdsaRecord.thresholdSessionId,
    signingGrantId: ecdsaRecord.signingGrantId,
    relayerUrl: ecdsaRecord.relayerUrl,
    chainTarget: ecdsaRecord.chainTarget,
    keyHandle: ecdsaRecord.keyHandle,
    evmFamilySigningKeySlotId: ecdsaRecord.evmFamilySigningKeySlotId,
    relayerKeyId: ecdsaRecord.relayerKeyId,
    participantIds: [...ecdsaRecord.participantIds],
    sessionKind: 'jwt',
    ...transport,
    ...(ecdsaRecord.runtimePolicyScope
      ? { runtimePolicyScope: ecdsaRecord.runtimePolicyScope }
      : {}),
  };
}

function buildEmailOtpEcdsaRestoreSource(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  ecdsaRecord?: ThresholdEcdsaSessionRecord | null;
}): EmailOtpEcdsaRestoreSource {
  if (args.ecdsaRecord) {
    return buildCurrentRecordEmailOtpEcdsaRestoreSource({
      sealedRecord: args.sealedRecord,
      ecdsaRecord: args.ecdsaRecord,
    });
  }
  return buildSealedRecordEmailOtpEcdsaRestoreSource({ sealedRecord: args.sealedRecord });
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
  if (sealedRecord.authMethod !== 'email_otp' || sealedRecord.curve !== 'ecdsa') {
    return null;
  }
  const restoreSource = buildEmailOtpEcdsaRestoreSource({
    sealedRecord,
    ecdsaRecord: args.ecdsaRecord,
  });
  if (emailOtpAuthContextRetention(restoreSource.emailOtpAuthContext) !== 'session') return null;

  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP sealed refresh requires the dedicated emailOtp worker');
  }

  if (sealedRecord.expiresAtMs <= Date.now()) {
    throw new Error('Email OTP sealed refresh expired sealed record');
  }
  if (sealedRecord.remainingUses <= 0) {
    throw new Error('Email OTP sealed refresh exhausted sealed record');
  }
  const restored = await requestRehydrateEmailOtpEcdsaWarmSessionMaterial({
    workerCtx,
    sealedSecretB64u: sealedRecord.sealedSecretB64u,
    remainingUses: sealedRecord.remainingUses,
    expiresAtMs: sealedRecord.expiresAtMs,
    transport: {
      relayerUrl: restoreSource.relayerUrl,
      walletSessionJwt: restoreSource.walletSessionJwt,
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
        restoreSource.signingSessionSealKeyVersion,
      ),
      shamirPrimeB64u: restoreSource.signingSessionSealShamirPrimeB64u,
    },
    restore: {
      sessionId: restoreSource.thresholdSessionId,
      walletId: sealedRecord.walletId,
      evmFamilySigningKeySlotId: String(restoreSource.evmFamilySigningKeySlotId),
      chainTarget: restoreSource.chainTarget,
      signingGrantId: restoreSource.signingGrantId,
      keyHandle: restoreSource.keyHandle,
      relayerKeyId: restoreSource.relayerKeyId,
      participantIds: [...restoreSource.participantIds],
      sessionKind: restoreSource.sessionKind,
      ...(restoreSource.runtimePolicyScope
        ? { runtimePolicyScope: restoreSource.runtimePolicyScope }
        : {}),
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
    walletId: toWalletId(sealedRecord.walletId),
    chainTarget: restoreSource.chainTarget,
    bootstrap: restoredBootstrap,
    source: 'email_otp',
    emailOtpAuthContext: restoreSource.emailOtpAuthContext,
  });
  return {
    bootstrap,
    warmCapability,
    remainingUses: restored.remainingUses,
    expiresAtMs: restored.expiresAtMs,
  };
}
