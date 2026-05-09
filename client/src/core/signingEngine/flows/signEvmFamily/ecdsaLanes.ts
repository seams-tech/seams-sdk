import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  EcdsaSigningListLookupArgs,
  EcdsaSigningLookupArgs,
  EvmFamilyChain,
  EvmFamilyEcdsaSessionReaderDeps,
  PasskeyEcdsaSessionStoreSource,
  PasskeyEcdsaSigningLookupArgs,
} from '../../interfaces/operationDeps';
import {
  selectedEcdsaLane,
  type SelectedEcdsaLane,
  type ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
  type EcdsaTransactionSigningLane,
} from '../../session/operationState/lanes';
import type {
  ThresholdEcdsaKeyRefLookupResult,
  ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  SigningSessionIds,
  type ResolvedEcdsaSigningSessionIdentity,
  type ThresholdEcdsaSessionId,
  type WalletSigningSessionId,
} from '../../session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EvmFamilyEcdsaAuthMethod =
  | typeof SIGNER_AUTH_METHODS.emailOtp
  | typeof SIGNER_AUTH_METHODS.passkey;

export type ResolvedEvmFamilyEcdsaSigningLane = EcdsaTransactionSigningLane & {
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
  lane: EcdsaTransactionSigningLane | SelectedEcdsaLane | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  return {
    present: true,
    accountId: lane.accountId,
    authMethod: lane.authMethod,
    curve: lane.curve,
    chain: lane.chain,
    chainFamily: 'chainFamily' in lane ? lane.chainFamily : lane.chain,
    keyKind: 'keyKind' in lane ? lane.keyKind : 'threshold_ecdsa_secp256k1',
    sessionOrigin: 'sessionOrigin' in lane ? lane.sessionOrigin : undefined,
    storageSource: 'storageSource' in lane ? lane.storageSource : undefined,
    retention: 'retention' in lane ? lane.retention : undefined,
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
    subjectId: lane.subjectId,
    chainTarget: lane.chainTarget,
    ecdsaThresholdKeyId: lane.ecdsaThresholdKeyId,
    signingRootId: lane.signingRootId,
    signingRootVersion: lane.signingRootVersion,
  };
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
  lane: EcdsaTransactionSigningLane | undefined;
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

  const selectedLane = selectedEcdsaLane({
    accountId: lane.accountId,
    authMethod: lane.authMethod,
    walletSigningSessionId,
    thresholdSessionId,
    subjectId: subjectId as WalletSubjectId,
    chainTarget,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
  });

  return {
    ...lane,
    ...selectedLane,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: args.chain,
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
    throw new Error(
      `[SigningEngine][ecdsa] incomplete updated signing lane identity for ${args.context}`,
    );
  }
  return {
    ...lane,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId),
  };
}

export function selectedEvmFamilyEcdsaLaneForMaterialIdentity(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  identity: ThresholdEcdsaSessionRecord | ThresholdEcdsaSecp256k1KeyRef;
  context: string;
}): SelectedEcdsaLane {
  const subjectId = String(args.identity.subjectId || '').trim();
  const ecdsaThresholdKeyId = String(args.identity.ecdsaThresholdKeyId || '').trim();
  const signingRootId = String(args.identity.signingRootId || '').trim();
  const signingRootVersion = String(args.identity.signingRootVersion || 'default').trim();
  if (!subjectId || !ecdsaThresholdKeyId || !signingRootId || !signingRootVersion) {
    throw new Error(
      `[SigningEngine][ecdsa] ${args.context} received incomplete ECDSA material identity`,
    );
  }
  return selectedEcdsaLane({
    accountId: args.lane.accountId,
    subjectId,
    authMethod: args.lane.authMethod,
    chainTarget: args.chainTarget,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    walletSigningSessionId: args.lane.walletSigningSessionId,
    thresholdSessionId: args.lane.thresholdSessionId,
  });
}

export function requireEvmFamilyEcdsaAuthMethod(
  authMethod: EvmFamilyEcdsaAuthMethod | undefined,
): EvmFamilyEcdsaAuthMethod {
  if (!authMethod) {
    throw new Error('[SigningEngine] ECDSA auth method is required for transaction auth planning');
  }
  return authMethod;
}

export type EvmFamilyEcdsaSigningLaneMaterial =
  | {
      material: 'record';
      record: ThresholdEcdsaSessionRecord;
    }
  | {
      material: 'key_ref';
      keyRef: ThresholdEcdsaSecp256k1KeyRef;
    }
  | {
      material: 'record_and_key_ref';
      record: ThresholdEcdsaSessionRecord;
      keyRef: ThresholdEcdsaSecp256k1KeyRef;
    };

export function buildEvmFamilyEcdsaSigningLaneContext(
  args: {
    nearAccountId: string;
    chain: EvmFamilyChain;
    chainTarget: ThresholdEcdsaChainTarget;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
  } & EvmFamilyEcdsaSigningLaneMaterial,
): ResolvedEvmFamilyEcdsaSigningLane | undefined {
  const record =
    args.material === 'record' || args.material === 'record_and_key_ref'
      ? args.record
      : undefined;
  const keyRef =
    args.material === 'key_ref' || args.material === 'record_and_key_ref'
      ? args.keyRef
      : undefined;
  const recordThresholdSessionId = String(record?.thresholdSessionId || '').trim();
  const keyRefThresholdSessionId = String(keyRef?.thresholdSessionId || '').trim();
  const recordWalletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  const keyRefWalletSigningSessionId = String(keyRef?.walletSigningSessionId || '').trim();
  const recordSigningRootId = String(record?.signingRootId || '').trim();
  const keyRefSigningRootId = String(keyRef?.signingRootId || '').trim();
  const recordSigningRootVersion = String(record?.signingRootVersion || '').trim();
  const keyRefSigningRootVersion = String(keyRef?.signingRootVersion || '').trim();
  const recordSubjectId = String(record?.subjectId || '').trim();
  const keyRefSubjectId = String(keyRef?.subjectId || '').trim();
  const recordThresholdKeyId = String(record?.ecdsaThresholdKeyId || '').trim();
  const keyRefThresholdKeyId = String(keyRef?.ecdsaThresholdKeyId || '').trim();
  if (
    recordThresholdSessionId &&
    keyRefThresholdSessionId &&
    recordThresholdSessionId !== keyRefThresholdSessionId
  ) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched record/keyRef threshold ids',
      {
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
      },
    );
    return undefined;
  }
  if (
    recordWalletSigningSessionId &&
    keyRefWalletSigningSessionId &&
    recordWalletSigningSessionId !== keyRefWalletSigningSessionId
  ) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched record/keyRef wallet session ids',
      {
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
      },
    );
    return undefined;
  }
  if (recordSubjectId && keyRefSubjectId && recordSubjectId !== keyRefSubjectId) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched record/keyRef subject ids',
      {
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
      },
    );
    return undefined;
  }
  if (
    recordThresholdKeyId &&
    keyRefThresholdKeyId &&
    recordThresholdKeyId !== keyRefThresholdKeyId
  ) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched record/keyRef threshold key ids',
      {
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
      },
    );
    return undefined;
  }
  if (recordSigningRootId && keyRefSigningRootId && recordSigningRootId !== keyRefSigningRootId) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched record/keyRef signing roots',
      {
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
      },
    );
    return undefined;
  }
  if (
    recordSigningRootVersion &&
    keyRefSigningRootVersion &&
    recordSigningRootVersion !== keyRefSigningRootVersion
  ) {
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane from mismatched record/keyRef signing root versions',
      {
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        chainTarget: args.chainTarget,
        authMethod: args.authMethod,
        source: args.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
      },
    );
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
      record: summarizeEvmFamilyEcdsaSessionRecord(record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
    });
    return undefined;
  }

  const thresholdSessionId = String(recordThresholdSessionId || keyRefThresholdSessionId).trim();
  if (!thresholdSessionId) {
    logEvmFamilyEcdsaLaneDiagnostic('cannot build signing lane without threshold session id', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      authMethod: args.authMethod,
      source: args.source,
      walletSigningSessionId,
      record: summarizeEvmFamilyEcdsaSessionRecord(record),
      keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
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
    logEvmFamilyEcdsaLaneDiagnostic(
      'cannot build signing lane without full ECDSA material identity',
      {
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        authMethod: args.authMethod,
        source: args.source,
        walletSigningSessionId,
        thresholdSessionId,
        record: summarizeEvmFamilyEcdsaSessionRecord(record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(keyRef),
      },
    );
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
    args.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;

  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    const lane = buildLane({
      ...base,
      chainTarget: args.chainTarget,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      retention: record?.emailOtpAuthContext?.retention || 'session',
      sessionOrigin: record?.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
    });
    return requireResolvedEvmFamilyEcdsaSigningLane({
      lane,
      chain: args.chain,
      context: 'build EVM-family ECDSA signing lane',
    });
  }

  if (args.source === SIGNER_AUTH_METHODS.emailOtp) return undefined;
  const lane = buildLane({
    ...base,
    chainTarget: args.chainTarget,
    authMethod: SIGNER_AUTH_METHODS.passkey,
    storageSource: args.source,
  });
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane,
    chain: args.chain,
    context: 'build EVM-family ECDSA signing lane',
  });
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

export function findExactEcdsaSessionRecordForSelectedLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane: SelectedEcdsaLane;
}): ThresholdEcdsaSessionRecord | undefined {
  return args.deps.getThresholdEcdsaSessionRecordByKey(args.lane) || undefined;
}

export function findExactEcdsaKeyRefForSelectedLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane: SelectedEcdsaLane;
}):
  | { source: ThresholdEcdsaSessionStoreSource; keyRef: ThresholdEcdsaSecp256k1KeyRef }
  | undefined {
  return args.deps.getThresholdEcdsaKeyRefByKey(args.lane) || undefined;
}

export function readSelectedEcdsaRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  lane?: SelectedEcdsaLane;
}): ThresholdEcdsaSessionRecord | undefined {
  if (!args.lane) return undefined;
  const record = findExactEcdsaSessionRecordForSelectedLane({
    deps: args.deps,
    lane: args.lane,
  });
  if (!record) return undefined;
  if (
    ecdsaMaterialSourceMatchesAuth({
      authMethod: args.lane.authMethod,
      source: record.source,
      record,
    })
  ) {
    return record;
  }
  throw new Error('[SigningEngine][ecdsa] selected ECDSA record auth source mismatch');
}

export function validateSelectedEcdsaRecordCandidateForLane(args: {
  lane?: SelectedEcdsaLane;
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
  lane?: SelectedEcdsaLane;
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  if (!args.lane) return undefined;
  const result = findExactEcdsaKeyRefForSelectedLane({
    deps: args.deps,
    lane: args.lane,
  });
  if (!result) return undefined;
  if (
    ecdsaMaterialSourceMatchesAuth({
      authMethod: args.lane.authMethod,
      source: result.source,
      keyRef: result.keyRef,
    })
  ) {
    return result.keyRef;
  }
  throw new Error('[SigningEngine][ecdsa] selected ECDSA keyRef auth source mismatch');
}

export function validateSelectedEcdsaKeyRefCandidateForLane(args: {
  lane?: SelectedEcdsaLane;
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
  lane: SelectedEcdsaLane;
  record: ThresholdEcdsaSessionRecord;
}): string | null {
  const { lane, record } = args;
  if (lane.curve !== 'ecdsa') {
    return 'lane is not an ECDSA transaction lane';
  }
  if (lane.chain !== 'tempo' && lane.chain !== 'evm') {
    return 'lane chain is not an EVM-family chain';
  }
  if (String(record.nearAccountId || '') !== String(lane.accountId)) {
    return 'account id mismatch';
  }
  if (
    !ecdsaMaterialSourceMatchesAuth({
      authMethod: lane.authMethod,
      source: record.source,
      record,
    })
  ) {
    return 'auth source mismatch';
  }
  if (String(record.thresholdSessionId || '') !== String(lane.thresholdSessionId)) {
    return 'threshold session id mismatch';
  }
  if (String(record.walletSigningSessionId || '') !== String(lane.walletSigningSessionId)) {
    return 'wallet signing session id mismatch';
  }
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, lane.chainTarget)) {
    return 'chain mismatch';
  }
  if (String(record.signingRootId || '') !== String(lane.signingRootId)) {
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
  lane: SelectedEcdsaLane;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
}): string | null {
  const { lane, keyRef } = args;
  if (lane.curve !== 'ecdsa') {
    return 'lane is not an ECDSA transaction lane';
  }
  if (String(keyRef.userId || '') !== String(lane.accountId)) {
    return 'account id mismatch';
  }
  if (String(keyRef.thresholdSessionId || '') !== String(lane.thresholdSessionId)) {
    return 'threshold session id mismatch';
  }
  if (String(keyRef.walletSigningSessionId || '') !== String(lane.walletSigningSessionId)) {
    return 'wallet signing session id mismatch';
  }
  if (!thresholdEcdsaChainTargetsEqual(keyRef.chainTarget, lane.chainTarget)) {
    return 'chain mismatch';
  }
  if (String(keyRef.signingRootId || '') !== String(lane.signingRootId)) {
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
