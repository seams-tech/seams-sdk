import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '../../session/signingSession/lanes';
import type {
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
  type ThresholdEcdsaSessionId,
  type SigningLaneContext,
  type WalletSigningSessionId,
} from '../../session/signingSession/types';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EvmFamilyChain } from './types';

export type PasskeyEcdsaSessionStoreSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

export type EcdsaSigningLookupArgs = {
  nearAccountId: string;
  chain: EvmFamilyChain;
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
};

export type EvmFamilyEcdsaAuthMethod =
  | typeof SIGNER_AUTH_METHODS.emailOtp
  | typeof SIGNER_AUTH_METHODS.passkey;

export type ResolvedEvmFamilyEcdsaSigningLane = SigningLaneContext & {
  authMethod: EvmFamilyEcdsaAuthMethod;
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: EvmFamilyChain;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export function summarizeEvmFamilyEcdsaSessionRecord(
  record: ThresholdEcdsaSessionRecord | undefined,
): Record<string, unknown> {
  if (!record) return { present: false };
  return {
    present: true,
    source: record.source,
    chain: record.chain,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    remainingUses: record.remainingUses,
    expiresAtMs: record.expiresAtMs,
    emailOtpRetention: record.emailOtpAuthContext?.retention,
    emailOtpReason: record.emailOtpAuthContext?.reason,
    thresholdSessionKind: record.thresholdSessionKind,
    hasThresholdSessionJwt: !!record.thresholdSessionJwt,
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
    hasThresholdSessionJwt: !!keyRef.thresholdSessionJwt,
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
  thresholdSessionId?: string;
  walletSigningSessionId?: string;
  context: string;
  diagnostics?: Record<string, unknown>;
}): ResolvedEvmFamilyEcdsaSigningLane {
  // ECDSA auth may refresh the threshold session after pre-confirm planning.
  // Callers pass the fresh ids here so downstream budget/cleanup code never
  // falls back to a generic account lookup or a stale selected lane.
  const lane = args.lane;
  if (!lane) {
    logEvmFamilyEcdsaLaneDiagnostic('missing selected signing lane', {
      context: args.context,
      chain: args.chain,
      thresholdSessionId: args.thresholdSessionId,
      walletSigningSessionId: args.walletSigningSessionId,
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

  const walletSigningSessionId = String(
    args.walletSigningSessionId || lane.walletSigningSessionId || '',
  ).trim();
  if (!walletSigningSessionId) {
    logEvmFamilyEcdsaLaneDiagnostic('selected signing lane missing wallet session id', {
      context: args.context,
      expectedChain: args.chain,
      lane: summarizeEvmFamilyEcdsaLane(lane),
      thresholdSessionId: args.thresholdSessionId,
      ...args.diagnostics,
    });
    throw new Error(`[SigningEngine][ecdsa] missing wallet signing session id for ${args.context}`);
  }
  const thresholdSessionId = String(
    args.thresholdSessionId || lane.thresholdSessionId || '',
  ).trim();
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

  return {
    ...lane,
    authMethod: lane.authMethod,
    curve: 'ecdsa',
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: args.chain,
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
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): SigningLaneContext | undefined {
  const walletSigningSessionId = String(
    args.record?.walletSigningSessionId || args.keyRef?.walletSigningSessionId || '',
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
    args.record?.thresholdSessionId || args.keyRef?.thresholdSessionId || '',
  ).trim();
  const base = {
    accountId: toAccountId(args.nearAccountId),
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    ...(thresholdSessionId
      ? { thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(thresholdSessionId) }
      : {}),
    ...(args.record?.signingRootId || args.keyRef?.signingRootId
      ? { signingRootId: String(args.record?.signingRootId || args.keyRef?.signingRootId) }
      : {}),
    ...(args.record?.signingRootVersion || args.keyRef?.signingRootVersion
      ? {
          signingRootVersion: String(
            args.record?.signingRootVersion || args.keyRef?.signingRootVersion,
          ),
        }
      : {}),
  };
  const buildLane =
    args.chain === 'tempo' ? buildTempoTransactionSigningLane : buildEvmTransactionSigningLane;

  if (args.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
    return buildLane({
      ...base,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      retention: args.record?.emailOtpAuthContext?.retention || 'session',
      sessionOrigin:
        args.record?.emailOtpAuthContext?.reason === 'login' ? 'login' : 'per_operation',
    });
  }

  if (args.source === SIGNER_AUTH_METHODS.emailOtp) return undefined;
  return buildLane({
    ...base,
    authMethod: SIGNER_AUTH_METHODS.passkey,
    storageSource: args.source,
  });
}

export function getThresholdEcdsaSessionRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  source: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSessionRecord {
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) {
    return args.deps.getEmailOtpThresholdEcdsaSessionRecordForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
      ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
    });
  }
  const passkeySource = args.source as PasskeyEcdsaSessionStoreSource;
  return args.deps.getPasskeyThresholdEcdsaSessionRecordForSigning({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    source: passkeySource,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
  });
}

export function getThresholdEcdsaKeyRefForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  source: ThresholdEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSecp256k1KeyRef {
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) {
    return args.deps.getEmailOtpThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
      ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
    });
  }
  const passkeySource = args.source as PasskeyEcdsaSessionStoreSource;
  return args.deps.getPasskeyThresholdEcdsaKeyRefForSigning({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    source: passkeySource,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
  });
}

export function tryGetThresholdEcdsaSessionRecordForLane(args: {
  deps: EvmFamilyEcdsaSessionReaderDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
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
  nearAccountId: string;
  chain: EvmFamilyChain;
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
  nearAccountId: string;
  chain: EvmFamilyChain;
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
  nearAccountId: string;
  chain: EvmFamilyChain;
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
  nearAccountId: string;
  chain: EvmFamilyChain;
  source: PasskeyEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSessionRecord | undefined {
  const candidate = tryGetThresholdEcdsaSessionRecordForLane({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    chain: args.chain,
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
  nearAccountId: string;
  chain: EvmFamilyChain;
  source: PasskeyEcdsaSessionStoreSource;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdEcdsaSecp256k1KeyRef | undefined {
  return tryGetThresholdEcdsaKeyRefForLane({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    chain: args.chain,
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
  chain: EvmFamilyChain,
): EmailOtpAuthLane | undefined {
  const jwt = String(record?.thresholdSessionJwt || '').trim();
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
    chain,
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

export function createEvmFamilySigningCapabilityReader(deps: EvmFamilyEcdsaSessionReaderDeps) {
  return createSigningCapabilityReader({
    readEmailOtpEcdsaSessionRecord: ({ accountId, chain, signingRootId, signingRootVersion }) =>
      tryGetThresholdEcdsaSessionRecordForLane({
        deps,
        nearAccountId: String(accountId),
        chain,
        source: SIGNER_AUTH_METHODS.emailOtp,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
      }) || null,
    readPasskeyEcdsaSessionRecord: ({
      accountId,
      chain,
      storageSource,
      signingRootId,
      signingRootVersion,
    }) =>
      tryGetThresholdEcdsaSessionRecordForLane({
        deps,
        nearAccountId: String(accountId),
        chain,
        source: storageSource,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
      }) || null,
    readEmailOtpEcdsaKeyRef: ({ accountId, chain, signingRootId, signingRootVersion }) =>
      tryGetThresholdEcdsaKeyRefForLane({
        deps,
        nearAccountId: String(accountId),
        chain,
        source: SIGNER_AUTH_METHODS.emailOtp,
        ...(signingRootId ? { signingRootId } : {}),
        ...(signingRootVersion ? { signingRootVersion } : {}),
      }) || null,
    readPasskeyEcdsaKeyRef: ({
      accountId,
      chain,
      storageSource,
      signingRootId,
      signingRootVersion,
    }) =>
      tryGetThresholdEcdsaKeyRefForLane({
        deps,
        nearAccountId: String(accountId),
        chain,
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
