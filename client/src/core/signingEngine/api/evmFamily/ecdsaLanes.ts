import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '../../session/signingSession/lanes';
import type {
  ThresholdEcdsaKeyRefLookupResult,
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type { EmailOtpAuthLane } from '../../emailOtp/authLane';
import {
  createSigningCapabilityReader,
  type SigningCapabilityReadError,
} from '../../session/signingSession/lanes';
import {
  SigningSessionIds,
  summarizeSigningLane,
  type ResolvedEcdsaSigningSessionIdentity,
  type ThresholdEcdsaSessionId,
  type SigningLaneContext,
  type WalletSigningSessionId,
} from '../../session/signingSession/types';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EvmFamilyChain } from './types';
import {
  thresholdEcdsaChainTargetsEqual,
  type EcdsaLaneIdentity,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '../../session/signingSession/ecdsaChainTarget';

export type PasskeyEcdsaSessionStoreSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

export type EcdsaSigningLookupArgs = {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  signingRootId?: string;
  signingRootVersion?: string;
};

export type EcdsaSigningListLookupArgs = {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
};

export type PasskeyEcdsaSigningLookupArgs = EcdsaSigningLookupArgs & {
  source: PasskeyEcdsaSessionStoreSource;
};

export type EvmFamilyEcdsaSessionReaderDeps = {
  getEmailOtpThresholdEcdsaKeyRefForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
  getEmailOtpThresholdEcdsaSessionRecordForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
  getPasskeyThresholdEcdsaKeyRefForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
  getPasskeyThresholdEcdsaSessionRecordForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
  listThresholdEcdsaSessionRecordsForSigning: (
    args: EcdsaSigningListLookupArgs,
  ) => ThresholdEcdsaSessionRecord[];
  listThresholdEcdsaKeyRefsForSigning: (
    args: EcdsaSigningListLookupArgs,
  ) => ThresholdEcdsaKeyRefLookupResult[];
  getThresholdEcdsaSessionRecordByIdentity: (
    identity: EcdsaLaneIdentity,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEcdsaKeyRefByIdentity: (
    identity: EcdsaLaneIdentity,
  ) => ThresholdEcdsaKeyRefLookupResult | null;
};

export type EvmFamilyEcdsaAuthMethod =
  | typeof SIGNER_AUTH_METHODS.emailOtp
  | typeof SIGNER_AUTH_METHODS.passkey;

export type ResolvedEvmFamilyEcdsaSigningLane = SigningLaneContext & {
  authMethod: EvmFamilyEcdsaAuthMethod;
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
} & ResolvedEcdsaSigningSessionIdentity;

export function summarizeEvmFamilyEcdsaSessionRecord(
  record: ThresholdEcdsaSessionRecord | undefined,
): Record<string, unknown> {
  if (!record) return { present: false };
  return {
    present: true,
    source: record.source,
    chain: record.chainTarget.kind,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    remainingUses: record.remainingUses,
    expiresAtMs: record.expiresAtMs,
    emailOtpRetention: record.emailOtpAuthContext?.retention,
    emailOtpReason: record.emailOtpAuthContext?.reason,
    thresholdSessionKind: record.thresholdSessionKind,
    hasThresholdSessionAuthToken: !!record.thresholdSessionAuthToken,
    hasRelayerKeyId: !!record.relayerKeyId,
    participantCount: Array.isArray(record.participantIds) ? record.participantIds.length : 0,
  };
}

export function summarizeEvmFamilyEcdsaKeyRef(
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined,
): Record<string, unknown> {
  if (!keyRef) return { present: false };
  return {
    present: true,
    thresholdSessionId: keyRef.thresholdSessionId,
    walletSigningSessionId: keyRef.walletSigningSessionId,
    signingRootId: keyRef.signingRootId,
    signingRootVersion: keyRef.signingRootVersion,
    ecdsaThresholdKeyId: keyRef.ecdsaThresholdKeyId,
    thresholdSessionKind: keyRef.thresholdSessionKind,
    hasThresholdSessionAuthToken: !!keyRef.thresholdSessionAuthToken,
    hasBackendBinding: !!keyRef.backendBinding,
    hasRelayerKeyId: !!keyRef.backendBinding?.relayerKeyId,
    participantCount: Array.isArray(keyRef.participantIds) ? keyRef.participantIds.length : 0,
  };
}

export function summarizeEvmFamilyEcdsaLane(
  lane: SigningLaneContext | undefined,
): Record<string, unknown> {
  return lane ? summarizeSigningLane(lane) : { present: false };
}

export function logEvmFamilyEcdsaLaneDiagnostic(
  message: string,
  details: Record<string, unknown>,
): void {
  try {
    console.warn(`[SigningEngine][ecdsa] ${message}`, details);
  } catch {}
}

export function requireResolvedEvmFamilyEcdsaSigningLane(args: {
  lane: SigningLaneContext | undefined;
  chain: EvmFamilyChain;
  context: string;
  diagnostics?: Record<string, unknown>;
}): ResolvedEvmFamilyEcdsaSigningLane {
  const lane = args.lane;
  if (!lane) {
    logEvmFamilyEcdsaLaneDiagnostic('missing selected signing lane', {
      context: args.context,
      chain: args.chain,
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing selected signing lane for ${args.context}`);
  }
  if (lane.curve !== 'ecdsa' || lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane is not ECDSA', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} requires an ECDSA signing lane`);
  }
  if (
    lane.authMethod !== SIGNER_AUTH_METHODS.emailOtp &&
    lane.authMethod !== SIGNER_AUTH_METHODS.passkey
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane has no concrete auth method', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} requires a concrete ECDSA auth method`);
  }
  if (lane.chainFamily !== args.chain) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane chain mismatch', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] ${args.context} chain does not match selected lane`);
  }

  const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing wallet session id', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing wallet signing session id for ${args.context}`);
  }
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing threshold session id', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      walletSigningSessionId,
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing threshold session id for ${args.context}`);
  }
  const chainTarget = (lane as { chainTarget?: ThresholdEcdsaChainTarget }).chainTarget;
  if (!chainTarget || chainTarget.kind !== args.chain) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing concrete chain target', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing concrete chain target for ${args.context}`);
  }
  const subjectId = String(lane.subjectId || '').trim();
  const ecdsaThresholdKeyId = String(lane.ecdsaThresholdKeyId || '').trim();
  const signingRootId = String(lane.signingRootId || '').trim();
  const signingRootVersion = String(lane.signingRootVersion || '').trim();
  if (!subjectId || !ecdsaThresholdKeyId || !signingRootId || !signingRootVersion) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing full ECDSA identity', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] incomplete ECDSA lane identity for ${args.context}`);
  }

  return {
    ...lane,
    authMethod: lane.authMethod,
    curve: 'ecdsa',
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: args.chain,
    chainTarget,
    subjectId: subjectId as WalletSubjectId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId),
  };
}

export function updateResolvedEvmFamilyEcdsaSigningLaneIdentity(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  chain: EvmFamilyChain;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  context: string;
  diagnostics?: Record<string, unknown>;
}): ResolvedEvmFamilyEcdsaSigningLane {
  const lane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: args.lane,
    chain: args.chain,
    context: args.context,
    diagnostics: args.diagnostics,
  });
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId || !thresholdSessionId) {
    logEvmFamilyEcdsaLaneDiagnostic('updated ECDSA lane identity is incomplete', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      thresholdSessionId,
      walletSigningSessionId,
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] incomplete updated signing lane identity for ${args.context}`);
  }
  return {
    ...lane,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId),
  };
}

export function requireEvmFamilyEcdsaAuthMethod(
  authMethod: EvmFamilyEcdsaAuthMethod | undefined,
): EvmFamilyEcdsaAuthMethod {
  if (!authMethod) {
    throw new Error('[SigningEngine] ECDSA auth method is required for transaction auth planning');
  }
  return authMethod;
}

export function buildEvmFamilyEcdsaSigningLaneContext(args: {
  nearAccountId: string;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): SigningLaneContext | undefined {
  const recordThresholdSessionId = String(args.record?.thresholdSessionId || '').trim();
  const keyRefThresholdSessionId = String(args.keyRef?.thresholdSessionId || '').trim();
  const recordWalletSigningSessionId = String(args.record?.walletSigningSessionId || '').trim();
  const keyRefWalletSigningSessionId = String(args.keyRef?.walletSigningSessionId || '').trim();
  const recordSigningRootId = String(args.record?.signingRootId || '').trim();
  const keyRefSigningRootId = String(args.keyRef?.signingRootId || '').trim();
  const recordSigningRootVersion = String(args.record?.signingRootVersion || '').trim();
  const keyRefSigningRootVersion = String(args.keyRef?.signingRootVersion || '').trim();
  const recordSubjectId = String(args.record?.subjectId || '').trim();
  const keyRefSubjectId = String(args.keyRef?.subjectId || '').trim();
  const recordThresholdKeyId = String(args.record?.ecdsaThresholdKeyId || '').trim();
  const keyRefThresholdKeyId = String(args.keyRef?.ecdsaThresholdKeyId || '').trim();
  if (
    recordThresholdSessionId &&
    keyRefThresholdSessionId &&
    recordThresholdSessionId !== keyRefThresholdSessionId
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched record/keyRef threshold ids', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }
  if (
    recordWalletSigningSessionId &&
    keyRefWalletSigningSessionId &&
    recordWalletSigningSessionId !== keyRefWalletSigningSessionId
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched record/keyRef wallet session ids', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }
  if (recordSubjectId && keyRefSubjectId && recordSubjectId !== keyRefSubjectId) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched record/keyRef subject ids', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }
  if (
    recordThresholdKeyId &&
    keyRefThresholdKeyId &&
    recordThresholdKeyId !== keyRefThresholdKeyId
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched record/keyRef threshold key ids', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }
  if (recordSigningRootId && keyRefSigningRootId && recordSigningRootId !== keyRefSigningRootId) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched record/keyRef signing roots', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }
  if (
    recordSigningRootVersion &&
    keyRefSigningRootVersion &&
    recordSigningRootVersion !== keyRefSigningRootVersion
  ) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane from mismatched record/keyRef signing root versions', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      chainTarget: args.chainTarget,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }
  const walletSigningSessionId = String(
    recordWalletSigningSessionId || keyRefWalletSigningSessionId,
  ).trim();
  if (!walletSigningSessionId) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane without wallet session id', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      authMethod: args.authMethod,
      source: args.source,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }

  const thresholdSessionId = String(
    recordThresholdSessionId || keyRefThresholdSessionId,
  ).trim();
  if (!thresholdSessionId) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane without threshold session id', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      authMethod: args.authMethod,
      source: args.source,
      walletSigningSessionId,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }
  const subjectId = String(recordSubjectId || keyRefSubjectId).trim();
  const ecdsaThresholdKeyId = String(recordThresholdKeyId || keyRefThresholdKeyId).trim();
  const signingRootId = String(recordSigningRootId || keyRefSigningRootId).trim();
  const signingRootVersion = String(
    recordSigningRootVersion || keyRefSigningRootVersion || 'default',
  ).trim();
  if (!subjectId || !ecdsaThresholdKeyId || !signingRootId || !signingRootVersion) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane without full ECDSA material identity', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      authMethod: args.authMethod,
      source: args.source,
      walletSigningSessionId,
      thresholdSessionId,
      record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
    });
    return undefined;
  }

  const base = {
    accountId: toAccountId(args.nearAccountId),
    subjectId: subjectId as WalletSubjectId,
    ecdsaThresholdKeyId,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId),
    signingRootId,
    signingRootVersion,
  };
  const buildLane =
    args.chainTarget.kind === 'tempo' ? buildTempoTransactionSigningLane : buildEvmTransactionSigningLane;

  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    return {
      ...buildLane({
        ...base,
        chainTarget: args.chainTarget,
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
        retention: args.record?.emailOtpAuthContext?.retention || 'session',
        sessionOrigin:
          args.record?.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
      }),
      chainTarget: args.chainTarget,
    } as SigningLaneContext;
  }

  if (args.source === SIGNER_AUTH_METHODS.emailOtp) return undefined;
  return {
    ...buildLane({
      ...base,
      chainTarget: args.chainTarget,
      authMethod: SIGNER_AUTH_METHODS.passkey,
      storageSource: args.source,
    }),
    chainTarget: args.chainTarget,
  } as SigningLaneContext;
}

export function getThresholdEcdsaSessionRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSessionRecord {
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) {
    return args.deps.getEmailOtpThresholdEcdsaSessionRecordForSigning({
      subjectId: args.subjectId,
      chainTarget: args.chainTarget,
      ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
      ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
    });
  }
  const passkeySource = args.source as PasskeyEcdsaSessionStoreSource;
  return args.deps.getPasskeyThresholdEcdsaSessionRecordForSigning({
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    source: passkeySource,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
  });
}

export function getThresholdEcdsaKeyRefForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSecp256k1KeyRef {
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) {
    return args.deps.getEmailOtpThresholdEcdsaKeyRefForSigning({
      subjectId: args.subjectId,
      chainTarget: args.chainTarget,
      ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
      ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
    });
  }
  const passkeySource = args.source as PasskeyEcdsaSessionStoreSource;
  return args.deps.getPasskeyThresholdEcdsaKeyRefForSigning({
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    source: passkeySource,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
  });
}

export function tryGetThresholdEcdsaSessionRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSessionRecord | undefined {
  try {
    return getThresholdEcdsaSessionRecordForLane(args);
  } catch {
    return undefined;
  }
}

export function tryGetThresholdEcdsaKeyRefForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  try {
    return getThresholdEcdsaKeyRefForLane(args);
  } catch {
    return undefined;
  }
}

export function tryGetEmailOtpThresholdEcdsaSessionRecordForSigning(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSessionRecord | undefined {
  return tryGetThresholdEcdsaSessionRecordForLane({
    ...args,
    source: SIGNER_AUTH_METHODS.emailOtp,
  });
}

export function tryGetEmailOtpThresholdEcdsaKeyRefForSigning(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  return tryGetThresholdEcdsaKeyRefForLane({
    ...args,
    source: SIGNER_AUTH_METHODS.emailOtp,
  });
}

export function tryGetPasskeyThresholdEcdsaSessionRecordForSigning(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: PasskeyEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSessionRecord | undefined {
  const candidate = tryGetThresholdEcdsaSessionRecordForLane({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    source: args.source,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
  });
  return candidate && !isEmailOtpThresholdEcdsaSigningContext({ record: candidate })
    ? candidate
    : undefined;
}

export function tryGetPasskeyThresholdEcdsaKeyRefForSigning(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: PasskeyEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  return tryGetThresholdEcdsaKeyRefForLane({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    source: args.source,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
  });
}

export function isEmailOtpThresholdEcdsaSigningContext(args: {
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): boolean {
  if (args.record?.source === SIGNER_AUTH_METHODS.emailOtp) return true;
  if (args.record?.emailOtpAuthContext?.authMethod === SIGNER_AUTH_METHODS.emailOtp) return true;
  if (args.record?.clientAdditiveShareHandle?.kind === 'email_otp_worker_session') return true;
  return (
    args.keyRef?.backendBinding?.clientAdditiveShareHandle?.kind === 'email_otp_worker_session'
  );
}

export function emailOtpEcdsaAuthLaneFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): EmailOtpAuthLane | undefined {
  const jwt = String(record?.thresholdSessionAuthToken || '').trim();
  const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  if (
    record?.source !== SIGNER_AUTH_METHODS.emailOtp ||
    !jwt ||
    !thresholdSessionId ||
    !walletSigningSessionId
  ) {
    return undefined;
  }
  return {
    kind: 'signing_session',
    jwt,
    thresholdSessionId,
    walletSigningSessionId,
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
  };
}

export function isSingleUseEmailOtpEcdsaRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): boolean {
  return (
    record?.source === SIGNER_AUTH_METHODS.emailOtp &&
    record.emailOtpAuthContext?.retention === 'single_use'
  );
}

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function ecdsaSessionIdentityMatches(args: {
  thresholdSessionId: unknown;
  walletSigningSessionId: unknown;
  expectedThresholdSessionId: unknown;
  expectedWalletSigningSessionId: unknown;
}): boolean {
  return (
    nonEmptyString(args.thresholdSessionId) === nonEmptyString(args.expectedThresholdSessionId) &&
    nonEmptyString(args.walletSigningSessionId) ===
      nonEmptyString(args.expectedWalletSigningSessionId)
  );
}

function ecdsaMaterialSourceMatchesAuth(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): boolean {
  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    if (args.source === SIGNER_AUTH_METHODS.emailOtp) return true;
    return isEmailOtpThresholdEcdsaSigningContext({
      ...(args.record ? { record: args.record } : {}),
      ...(args.keyRef ? { keyRef: args.keyRef } : {}),
    });
  }
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) return false;
  return !isEmailOtpThresholdEcdsaSigningContext({
    ...(args.record ? { record: args.record } : {}),
    ...(args.keyRef ? { keyRef: args.keyRef } : {}),
  });
}

function sortExactEcdsaRecords(
  records: ThresholdEcdsaSessionRecord[],
): ThresholdEcdsaSessionRecord[] {
  return [...records].sort((a, b) => {
    const updatedDiff = Number(b.updatedAtMs || 0) - Number(a.updatedAtMs || 0);
    if (updatedDiff) return updatedDiff;
    return `${a.source}:${a.thresholdSessionId}:${a.walletSigningSessionId}`.localeCompare(
      `${b.source}:${b.thresholdSessionId}:${b.walletSigningSessionId}`,
    );
  });
}

export function findExactEcdsaSessionRecordForCandidate(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  candidate: EcdsaLaneIdentity;
}): ThresholdEcdsaSessionRecord | undefined {
  return args.deps.getThresholdEcdsaSessionRecordByIdentity(args.candidate) || undefined;
}

export function findExactEcdsaKeyRefForCandidate(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  candidate: EcdsaLaneIdentity;
}): { source: ThresholdEcdsaSessionStoreSource; keyRef: ThresholdEcdsaSecp256k1KeyRef } | undefined {
  return args.deps.getThresholdEcdsaKeyRefByIdentity(args.candidate) || undefined;
}

export function createEvmFamilySigningCapabilityReader(deps: EvmFamilyEcdsaSessionReaderDeps) {
  return createSigningCapabilityReader({
    readEmailOtpEcdsaSessionRecord: ({ subjectId, chainTarget, signingRootId, signingRootVersion }) =>
      tryGetThresholdEcdsaSessionRecordForLane({
        deps,
        subjectId,
        chainTarget,
        source: SIGNER_AUTH_METHODS.emailOtp,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
      }) || null,
    readPasskeyEcdsaSessionRecord: ({
      subjectId,
      chainTarget,
      storageSource,
      signingRootId,
      signingRootVersion,
    }) =>
      tryGetThresholdEcdsaSessionRecordForLane({
        deps,
        subjectId,
        chainTarget,
        source: storageSource,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
      }) || null,
    readEmailOtpEcdsaKeyRef: ({ subjectId, chainTarget, signingRootId, signingRootVersion }) =>
      tryGetThresholdEcdsaKeyRefForLane({
        deps,
        subjectId,
        chainTarget,
        source: SIGNER_AUTH_METHODS.emailOtp,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
      }) || null,
    readPasskeyEcdsaKeyRef: ({
      subjectId,
      chainTarget,
      storageSource,
      signingRootId,
      signingRootVersion,
    }) =>
      tryGetThresholdEcdsaKeyRefForLane({
        deps,
        subjectId,
        chainTarget,
        source: storageSource,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
      }) || null,
  });
}

function throwForSigningCapabilityReadError(error: SigningCapabilityReadError): never {
  throw new Error(`[SigningEngine][ecdsa] ${error.message}`);
}

export function readSelectedEcdsaRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane?: SigningLaneContext;
}): ThresholdEcdsaSessionRecord | undefined {
  if (!args.lane) return undefined;
  const result = createEvmFamilySigningCapabilityReader(args.deps).readRecord(args.lane);
  if (result.ok) {
    return result.capability.curve === 'ecdsa' ? result.capability.record : undefined;
  }
  if (result.code === 'missing_record' || result.code === 'missing_reader') {
    return undefined;
  }
  return throwForSigningCapabilityReadError(result);
}

export function validateSelectedEcdsaRecordCandidateForLane(args: {
  lane?: SigningLaneContext;
  record?: ThresholdEcdsaSessionRecord;
  context: string;
}): ThresholdEcdsaSessionRecord | undefined {
  if (!args.lane || !args.record) return undefined;
  const lane = args.lane;
  const record = args.record;
  const mismatchReason = getSelectedEcdsaRecordLaneMismatchReason({ lane, record });
  if (!mismatchReason) return record;
  logEvmFamilyEcdsaLaneDiagnostic('selected ECDSA record candidate does not match resolved lane', {
    context: args.context,
    reason: mismatchReason,
    lane: summarizeEvmFamilyEcdsaLane(lane),
    record: summarizeEvmFamilyEcdsaSessionRecord(record),
  });
  throw new Error(
    `[SigningEngine][ecdsa] selected ECDSA record candidate does not match resolved lane for ${args.context}`,
  );
}

export function readSelectedEcdsaKeyRefForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane?: SigningLaneContext;
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  if (!args.lane) return undefined;
  const result = createEvmFamilySigningCapabilityReader(args.deps).readEcdsaKeyRef(args.lane);
  if (result.ok) return result.keyRef;
  if (result.code === 'missing_key_ref' || result.code === 'missing_reader') {
    return undefined;
  }
  return throwForSigningCapabilityReadError(result);
}

export function validateSelectedEcdsaKeyRefCandidateForLane(args: {
  lane?: SigningLaneContext;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  context: string;
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  if (!args.lane || !args.keyRef) return undefined;
  const lane = args.lane;
  const keyRef = args.keyRef;
  const mismatchReason = getSelectedEcdsaKeyRefLaneMismatchReason({ lane, keyRef });
  if (!mismatchReason) return keyRef;
  logEvmFamilyEcdsaLaneDiagnostic('selected ECDSA keyRef candidate does not match resolved lane', {
    context: args.context,
    reason: mismatchReason,
    lane: summarizeEvmFamilyEcdsaLane(lane),
    keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
  });
  throw new Error(
    `[SigningEngine][ecdsa] selected ECDSA keyRef candidate does not match resolved lane for ${args.context}`,
  );
}

function getSelectedEcdsaRecordLaneMismatchReason(args: {
  lane: SigningLaneContext;
  record: ThresholdEcdsaSessionRecord;
}): string | null {
  const { lane, record } = args;
  if (lane.curve !== 'ecdsa' || lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    return 'lane is not an ECDSA transaction lane';
  }
  if (lane.chainFamily !== 'tempo' && lane.chainFamily !== 'evm') {
    return 'lane chain is not an EVM-family chain';
  }
  if (String(record.nearAccountId || '') !== String(lane.accountId)) {
    return 'account id mismatch';
  }
  if (record.source !== lane.storageSource) {
    return 'storage source mismatch';
  }
  if (
    lane.thresholdSessionId &&
    String(record.thresholdSessionId || '') !== String(lane.thresholdSessionId)
  ) {
    return 'threshold session id mismatch';
  }
  if (
    lane.walletSigningSessionId &&
    String(record.walletSigningSessionId || '') !== String(lane.walletSigningSessionId)
  ) {
    return 'wallet signing session id mismatch';
  }
  if (record.chainTarget.kind !== lane.chainFamily) {
    return 'chain mismatch';
  }
  if (
    lane.signingRootId &&
    String(record.signingRootId || '') !== String(lane.signingRootId)
  ) {
    return 'signing root id mismatch';
  }
  if (
    normalizedOptionalString(lane.signingRootVersion) !==
    normalizedOptionalString(record.signingRootVersion)
  ) {
    return 'signing root version mismatch';
  }
  return null;
}

function getSelectedEcdsaKeyRefLaneMismatchReason(args: {
  lane: SigningLaneContext;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
}): string | null {
  const { lane, keyRef } = args;
  if (lane.curve !== 'ecdsa' || lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    return 'lane is not an ECDSA transaction lane';
  }
  if (String(keyRef.userId || '') !== String(lane.accountId)) {
    return 'account id mismatch';
  }
  if (
    lane.thresholdSessionId &&
    String(keyRef.thresholdSessionId || '') !== String(lane.thresholdSessionId)
  ) {
    return 'threshold session id mismatch';
  }
  if (
    lane.walletSigningSessionId &&
    String(keyRef.walletSigningSessionId || '') !== String(lane.walletSigningSessionId)
  ) {
    return 'wallet signing session id mismatch';
  }
  if (
    lane.signingRootId &&
    String(keyRef.signingRootId || '') !== String(lane.signingRootId)
  ) {
    return 'signing root id mismatch';
  }
  if (
    normalizedOptionalString(lane.signingRootVersion) !==
    normalizedOptionalString(keyRef.signingRootVersion)
  ) {
    return 'signing root version mismatch';
  }
  return null;
}

function normalizedOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}
