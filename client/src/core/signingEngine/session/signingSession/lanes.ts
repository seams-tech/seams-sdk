import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention } from '@/core/types/tatchi';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionRecord,
  ThresholdEd25519SessionStoreSource,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdEcdsaActivationChain } from '../../orchestration/thresholdActivation';
import type {
  BackingMaterialSessionId,
  SigningLaneContext,
  SigningSessionOrigin,
  SigningSessionStorageSource,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  WalletSigningSessionId,
} from './types';

export type Ed25519PasskeySigningLaneSource = Exclude<
  ThresholdEd25519SessionStoreSource,
  'email_otp'
>;
export type EcdsaPasskeySigningLaneSource = Exclude<
  ThresholdEcdsaSessionStoreSource,
  'email_otp'
>;

type BaseSigningLaneInput = {
  accountId: AccountId;
  walletSigningSessionId: WalletSigningSessionId;
  backingMaterialSessionId?: BackingMaterialSessionId;
  retention?: SigningSessionRetention;
  activeSignerSlot?: number;
  signingRootId?: string;
  signingRootVersion?: string;
};
type BuildSigningLaneInput = Omit<SigningLaneContext, 'retention'> & {
  retention?: SigningSessionRetention;
};

export type Ed25519PasskeySigningLaneInput = BaseSigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  storageSource: Ed25519PasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type Ed25519EmailOtpSigningLaneInput = BaseSigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaPasskeySigningLaneInput = BaseSigningLaneInput & {
  chainFamily: ThresholdEcdsaActivationChain;
  thresholdSessionId?: ThresholdEcdsaSessionId;
  storageSource: EcdsaPasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaEmailOtpSigningLaneInput = BaseSigningLaneInput & {
  chainFamily: ThresholdEcdsaActivationChain;
  thresholdSessionId?: ThresholdEcdsaSessionId;
  sessionOrigin?: SigningSessionOrigin;
};

export type NearTransactionSigningLaneInput =
  | ({ authMethod: 'passkey' } & Ed25519PasskeySigningLaneInput)
  | ({ authMethod: 'email_otp' } & Ed25519EmailOtpSigningLaneInput);

export type EcdsaTransactionSigningLaneInput =
  | ({ authMethod: 'passkey' } & Omit<EcdsaPasskeySigningLaneInput, 'chainFamily'>)
  | ({ authMethod: 'email_otp' } & Omit<EcdsaEmailOtpSigningLaneInput, 'chainFamily'>);

export function buildEd25519PasskeySigningLane(
  input: Ed25519PasskeySigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'passkey',
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    sessionOrigin: input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEd25519EmailOtpSigningLane(
  input: Ed25519EmailOtpSigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'email_otp',
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
  });
}

export function buildEcdsaPasskeySigningLane(
  input: EcdsaPasskeySigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'passkey',
    curve: 'ecdsa',
    keyKind: 'threshold_ecdsa_secp256k1',
    sessionOrigin: input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEcdsaEmailOtpSigningLane(
  input: EcdsaEmailOtpSigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'email_otp',
    curve: 'ecdsa',
    keyKind: 'threshold_ecdsa_secp256k1',
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
  });
}

export function buildNearTransactionSigningLane(
  input: NearTransactionSigningLaneInput,
): SigningLaneContext {
  return input.authMethod === 'email_otp'
    ? buildEd25519EmailOtpSigningLane(input)
    : buildEd25519PasskeySigningLane(input);
}

export function buildTempoTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): SigningLaneContext {
  return buildEcdsaTransactionSigningLane({
    ...input,
    chainFamily: 'tempo',
  });
}

export function buildEvmTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): SigningLaneContext {
  return buildEcdsaTransactionSigningLane({
    ...input,
    chainFamily: 'evm',
  });
}

function buildEcdsaTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput & { chainFamily: ThresholdEcdsaActivationChain },
): SigningLaneContext {
  return input.authMethod === 'email_otp'
    ? buildEcdsaEmailOtpSigningLane(input)
    : buildEcdsaPasskeySigningLane(input);
}

function buildSigningLane(input: BuildSigningLaneInput): SigningLaneContext {
  return {
    ...input,
    retention: input.retention || 'session',
  };
}

function signingSessionOriginFromStorageSource(
  source: Ed25519PasskeySigningLaneSource | EcdsaPasskeySigningLaneSource,
): SigningSessionOrigin {
  switch (source) {
    case 'login':
      return 'login';
    case 'registration':
      return 'registration';
    case 'manual-bootstrap':
      return 'manual_bootstrap';
    case 'manual-connect':
      return 'manual_connect';
    case 'bootstrap':
      return 'bootstrap';
  }
}
type EcdsaPasskeyStorageSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

export type SigningCapabilityReaderDeps = {
  readEd25519SessionRecordByThresholdSessionId?: (args: {
    thresholdSessionId: string;
  }) => ThresholdEd25519SessionRecord | null;
  readEmailOtpEcdsaSessionRecord?: (args: {
    accountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
  }) => ThresholdEcdsaSessionRecord | null;
  readPasskeyEcdsaSessionRecord?: (args: {
    accountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    storageSource: EcdsaPasskeyStorageSource;
    signingRootId?: string;
    signingRootVersion?: string;
  }) => ThresholdEcdsaSessionRecord | null;
  readEmailOtpEcdsaKeyRef?: (args: {
    accountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
  }) => ThresholdEcdsaSecp256k1KeyRef | null;
  readPasskeyEcdsaKeyRef?: (args: {
    accountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    storageSource: EcdsaPasskeyStorageSource;
    signingRootId?: string;
    signingRootVersion?: string;
  }) => ThresholdEcdsaSecp256k1KeyRef | null;
};

export type SigningCapabilityReadErrorCode =
  | 'missing_reader'
  | 'missing_record'
  | 'record_mismatch'
  | 'missing_key_ref'
  | 'key_ref_mismatch'
  | 'unsupported_curve';

export type SigningCapabilityReadError = {
  ok: false;
  lane: SigningLaneContext;
  code: SigningCapabilityReadErrorCode;
  message: string;
};

export type SigningCapabilityRecord =
  | {
      curve: 'ed25519';
      record: ThresholdEd25519SessionRecord;
    }
  | {
      curve: 'ecdsa';
      record: ThresholdEcdsaSessionRecord;
    };

export type SigningCapabilityRecordResult =
  | {
      ok: true;
      lane: SigningLaneContext;
      capability: SigningCapabilityRecord;
    }
  | SigningCapabilityReadError;

export type SigningCapabilityKeyRefResult =
  | {
      ok: true;
      lane: SigningLaneContext;
      keyRef: ThresholdEcdsaSecp256k1KeyRef;
    }
  | SigningCapabilityReadError;

export type SigningCapabilityResult =
  | {
      ok: true;
      lane: SigningLaneContext;
      capability: SigningCapabilityRecord;
      keyRef?: ThresholdEcdsaSecp256k1KeyRef;
    }
  | SigningCapabilityReadError;

export type SigningCapabilityReader = {
  readRecord(lane: SigningLaneContext): SigningCapabilityRecordResult;
  readEcdsaKeyRef(lane: SigningLaneContext): SigningCapabilityKeyRefResult;
  readCapability(lane: SigningLaneContext): SigningCapabilityResult;
};

export function createSigningCapabilityReader(
  deps: SigningCapabilityReaderDeps,
): SigningCapabilityReader {
  return {
    readRecord(lane) {
      return readSigningCapabilityRecord(deps, lane);
    },
    readEcdsaKeyRef(lane) {
      return readSigningCapabilityEcdsaKeyRef(deps, lane);
    },
    readCapability(lane) {
      return readSigningCapability(deps, lane);
    },
  };
}

export function readSigningCapability(
  deps: SigningCapabilityReaderDeps,
  lane: SigningLaneContext,
): SigningCapabilityResult {
  const recordResult = readSigningCapabilityRecord(deps, lane);
  if (!recordResult.ok) return recordResult;
  if (lane.curve !== 'ecdsa') {
    return {
      ...recordResult,
      capability: recordResult.capability,
    };
  }

  const keyRefResult = readSigningCapabilityEcdsaKeyRef(deps, lane);
  if (!keyRefResult.ok) return keyRefResult;
  return {
    ...recordResult,
    capability: recordResult.capability,
    keyRef: keyRefResult.keyRef,
  };
}

export function readSigningCapabilityRecord(
  deps: SigningCapabilityReaderDeps,
  lane: SigningLaneContext,
): SigningCapabilityRecordResult {
  if (lane.curve === 'ed25519') {
    return readEd25519CapabilityRecord(deps, lane);
  }
  if (lane.curve === 'ecdsa') {
    return readEcdsaCapabilityRecord(deps, lane);
  }
  return readError(lane, 'unsupported_curve', 'Unsupported signing lane curve');
}

export function readSigningCapabilityEcdsaKeyRef(
  deps: SigningCapabilityReaderDeps,
  lane: SigningLaneContext,
): SigningCapabilityKeyRefResult {
  if (lane.curve !== 'ecdsa') {
    return readError(lane, 'unsupported_curve', 'ECDSA key refs require an ECDSA signing lane');
  }
  const chain = ecdsaChainFromLane(lane);
  if (!chain) {
    return readError(lane, 'record_mismatch', 'ECDSA signing lane must target EVM or Tempo');
  }

  const keyRef =
    lane.authMethod === 'email_otp'
      ? deps.readEmailOtpEcdsaKeyRef?.({
          accountId: lane.accountId,
          chain,
          ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
          ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
        })
      : readPasskeyEcdsaKeyRef(deps, lane, chain);
  if (!keyRef) {
    return readError(lane, 'missing_key_ref', 'Missing selected-lane ECDSA key ref');
  }
  return validateEcdsaKeyRefForLane(lane, keyRef);
}

function readEd25519CapabilityRecord(
  deps: SigningCapabilityReaderDeps,
  lane: SigningLaneContext,
): SigningCapabilityRecordResult {
  if (lane.chainFamily !== 'near' || lane.keyKind !== 'threshold_ed25519') {
    return readError(lane, 'record_mismatch', 'Ed25519 signing lane must target NEAR threshold signing');
  }

  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    return readError(lane, 'record_mismatch', 'Ed25519 signing lane requires threshold session id');
  }
  const record = deps.readEd25519SessionRecordByThresholdSessionId?.({
    thresholdSessionId,
  });
  if (!record) {
    return readError(lane, 'missing_record', 'Missing selected-lane Ed25519 session record');
  }

  const mismatch = validateThresholdRecordForLane(lane, {
    accountId: record.nearAccountId,
    source: record.source,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
  });
  if (mismatch) return mismatch;

  return {
    ok: true,
    lane,
    capability: {
      curve: 'ed25519',
      record,
    },
  };
}

function readEcdsaCapabilityRecord(
  deps: SigningCapabilityReaderDeps,
  lane: SigningLaneContext,
): SigningCapabilityRecordResult {
  if (lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    return readError(lane, 'record_mismatch', 'ECDSA signing lane must target threshold secp256k1 signing');
  }
  const chain = ecdsaChainFromLane(lane);
  if (!chain) {
    return readError(lane, 'record_mismatch', 'ECDSA signing lane must target EVM or Tempo');
  }

  const record =
    lane.authMethod === 'email_otp'
      ? deps.readEmailOtpEcdsaSessionRecord?.({
          accountId: lane.accountId,
          chain,
          ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
          ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
        })
      : readPasskeyEcdsaRecord(deps, lane, chain);
  if (!record) {
    return readError(lane, 'missing_record', 'Missing selected-lane ECDSA session record');
  }

  const mismatch = validateThresholdRecordForLane(lane, {
    accountId: record.nearAccountId,
    source: record.source,
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
    chain: record.chain,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
  });
  if (mismatch) return mismatch;

  return {
    ok: true,
    lane,
    capability: {
      curve: 'ecdsa',
      record,
    },
  };
}

function readPasskeyEcdsaRecord(
  deps: SigningCapabilityReaderDeps,
  lane: SigningLaneContext,
  chain: ThresholdEcdsaActivationChain,
): ThresholdEcdsaSessionRecord | null | undefined {
  if (!isEcdsaPasskeyStorageSource(lane.storageSource)) return null;
  return deps.readPasskeyEcdsaSessionRecord?.({
    accountId: lane.accountId,
    chain,
    storageSource: lane.storageSource,
    ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
    ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
  });
}

function readPasskeyEcdsaKeyRef(
  deps: SigningCapabilityReaderDeps,
  lane: SigningLaneContext,
  chain: ThresholdEcdsaActivationChain,
): ThresholdEcdsaSecp256k1KeyRef | null | undefined {
  if (!isEcdsaPasskeyStorageSource(lane.storageSource)) return null;
  return deps.readPasskeyEcdsaKeyRef?.({
    accountId: lane.accountId,
    chain,
    storageSource: lane.storageSource,
    ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
    ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
  });
}

function validateEcdsaKeyRefForLane(
  lane: SigningLaneContext,
  keyRef: ThresholdEcdsaSecp256k1KeyRef,
): SigningCapabilityKeyRefResult {
  if (String(keyRef.userId || '') !== String(lane.accountId)) {
    return readError(lane, 'key_ref_mismatch', 'ECDSA key ref account does not match selected lane');
  }
  if (
    lane.thresholdSessionId &&
    String(keyRef.thresholdSessionId || '') !== String(lane.thresholdSessionId)
  ) {
    return readError(
      lane,
      'key_ref_mismatch',
      'ECDSA key ref threshold session does not match selected lane',
    );
  }
  if (
    lane.walletSigningSessionId &&
    String(keyRef.walletSigningSessionId || '') !== String(lane.walletSigningSessionId)
  ) {
    return readError(
      lane,
      'key_ref_mismatch',
      'ECDSA key ref wallet signing session does not match selected lane',
    );
  }
  if (lane.signingRootId && String(keyRef.signingRootId || '') !== String(lane.signingRootId)) {
    return readError(lane, 'key_ref_mismatch', 'ECDSA key ref signing root does not match selected lane');
  }
  if (
    normalizedOptionalString(lane.signingRootVersion) !==
    normalizedOptionalString(keyRef.signingRootVersion)
  ) {
    return readError(
      lane,
      'key_ref_mismatch',
      'ECDSA key ref signing root version does not match selected lane',
    );
  }
  return {
    ok: true,
    lane,
    keyRef,
  };
}

function validateThresholdRecordForLane(
  lane: SigningLaneContext,
  record: {
    accountId: AccountId;
    source: SigningSessionStorageSource;
    thresholdSessionId?: string;
    walletSigningSessionId?: string;
    chain?: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
  },
): SigningCapabilityReadError | null {
  if (String(record.accountId) !== String(lane.accountId)) {
    return readError(lane, 'record_mismatch', 'Session record account does not match selected lane');
  }
  if (record.source !== lane.storageSource) {
    return readError(lane, 'record_mismatch', 'Session record source does not match selected lane');
  }
  if (
    lane.thresholdSessionId &&
    String(record.thresholdSessionId || '') !== String(lane.thresholdSessionId)
  ) {
    return readError(
      lane,
      'record_mismatch',
      'Session record threshold session does not match selected lane',
    );
  }
  if (
    lane.walletSigningSessionId &&
    String(record.walletSigningSessionId || '') !== String(lane.walletSigningSessionId)
  ) {
    return readError(
      lane,
      'record_mismatch',
      'Session record wallet signing session does not match selected lane',
    );
  }
  if (record.chain && record.chain !== lane.chainFamily) {
    return readError(lane, 'record_mismatch', 'Session record chain does not match selected lane');
  }
  if (
    record.signingRootId !== undefined &&
    lane.signingRootId &&
    String(record.signingRootId || '') !== String(lane.signingRootId)
  ) {
    return readError(lane, 'record_mismatch', 'Session record signing root does not match selected lane');
  }
  if (
    record.signingRootId !== undefined &&
    normalizedOptionalString(lane.signingRootVersion) !==
      normalizedOptionalString(record.signingRootVersion)
  ) {
    return readError(
      lane,
      'record_mismatch',
      'Session record signing root version does not match selected lane',
    );
  }
  return null;
}

function ecdsaChainFromLane(lane: SigningLaneContext): ThresholdEcdsaActivationChain | null {
  return lane.chainFamily === 'evm' || lane.chainFamily === 'tempo' ? lane.chainFamily : null;
}

function isEcdsaPasskeyStorageSource(
  source: SigningSessionStorageSource,
): source is EcdsaPasskeyStorageSource {
  return source === 'login' || source === 'registration' || source === 'manual-bootstrap';
}

function normalizedOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function readError(
  lane: SigningLaneContext,
  code: SigningCapabilityReadErrorCode,
  message: string,
): SigningCapabilityReadError {
  return {
    ok: false,
    lane,
    code,
    message,
  };
}
