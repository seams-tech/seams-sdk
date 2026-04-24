import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '../../session/SigningLaneBuilders';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type { EmailOtpAuthLane } from '../../emailOtp/authLane';
import {
  createSigningCapabilityReader,
  type SigningCapabilityReadError,
} from '../../session/SigningCapabilityReader';
import {
  SigningSessionIds,
  type SigningLaneContext,
} from '../../session/signingSessionTypes';
import { toAccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { EvmFamilyChain } from './types';

export type PasskeyEcdsaSessionStoreSource = Exclude<
  ThresholdEcdsaSessionStoreSource,
  'email_otp'
>;

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

export function requireEvmFamilyEcdsaSigningLane(
  lane: SigningLaneContext | undefined,
): SigningLaneContext {
  if (!lane) {
    throw new Error('[SigningEngine] ECDSA signing lane is required for transaction auth planning');
  }
  return lane;
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
  if (!walletSigningSessionId) return undefined;

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
  if (record?.source !== SIGNER_AUTH_METHODS.emailOtp || !jwt || !thresholdSessionId) {
    return undefined;
  }
  return {
    kind: 'signing_session',
    jwt,
    thresholdSessionId,
    ...(record.walletSigningSessionId
      ? { walletSigningSessionId: record.walletSigningSessionId }
      : {}),
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

export function createEvmFamilySigningCapabilityReader(
  deps: EvmFamilyEcdsaSessionReaderDeps,
) {
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
