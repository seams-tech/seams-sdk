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
import { parseSigningSessionSealKeyVersion } from '../keyMaterialBrands';

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
  signingGrantId: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

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

function defaultEmailOtpSessionAuthContext(): ThresholdEcdsaEmailOtpAuthContext {
  return {
    policy: 'session',
    retention: 'session',
    reason: 'login',
    authMethod: 'email_otp',
  };
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
    emailOtpAuthContext: defaultEmailOtpSessionAuthContext(),
    walletSessionJwt,
    thresholdSessionId: sealedRecord.thresholdSessionId,
    signingGrantId: sealedRecord.signingGrantId,
    relayerUrl: sealedRecord.relayerUrl,
    chainTarget: sealedRecord.chainTarget,
    keyHandle: sealedRecord.keyHandle,
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

function resolveEmailOtpCompanionEd25519Session(args: {
  sealedRecord: EmailOtpEcdsaSealedRecoveryRecord;
  signingGrantId: string;
  ed25519Record?: ThresholdEd25519SessionRecord | null;
}): EmailOtpCompanionEd25519Session | null {
  const sealedCompanion =
    args.sealedRecord.companionEd25519Recovery &&
    args.sealedRecord.companionEd25519Recovery.signingGrantId ===
      args.signingGrantId
      ? args.sealedRecord.companionEd25519Recovery
      : null;
  const ed25519Record =
    args.ed25519Record &&
    args.ed25519Record.source === 'email_otp' &&
    args.ed25519Record.emailOtpAuthContext?.retention === 'session' &&
    args.ed25519Record.signingGrantId === args.signingGrantId
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
      signingGrantId: args.signingGrantId,
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
    signingGrantId: companion.signingGrantId,
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
  if (sealedRecord.authMethod !== 'email_otp' || sealedRecord.curve !== 'ecdsa') {
    return null;
  }
  const restoreSource = buildEmailOtpEcdsaRestoreSource({
    sealedRecord,
    ecdsaRecord: args.ecdsaRecord,
  });
  if (restoreSource.emailOtpAuthContext.retention !== 'session') return null;

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
  const ed25519Session = resolveEmailOtpCompanionEd25519Session({
    sealedRecord,
    signingGrantId: restoreSource.signingGrantId,
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
      rpId: args.requireRpId('Email OTP sealed refresh'),
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
    primaryChain: restoreSource.chainTarget,
    bootstrap: restoredBootstrap,
    source: 'email_otp',
    emailOtpAuthContext: restoreSource.emailOtpAuthContext,
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
