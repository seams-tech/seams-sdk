import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention } from '@/core/types/seams';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../persistence/records';
import {
  thresholdEcdsaLaneCandidateFromSessionRecord,
  thresholdEd25519LaneCandidateFromSessionRecord,
} from '../persistence/records';
import {
  selectedEcdsaLane,
  selectedEd25519Lane,
  type EcdsaLaneCandidate,
  type Ed25519LaneCandidate,
  type SelectedEcdsaLane,
  type SelectedEd25519Lane,
  type ThresholdEcdsaSessionStoreSource,
  type ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaChainTarget, WalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  BackingMaterialSessionId,
  SelectedEcdsaSigningSessionPlanningLane,
  SelectedSigningSessionPlanningLane,
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
export type EcdsaPasskeySigningLaneSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

type BaseSigningLaneInput = {
  walletSigningSessionId: WalletSigningSessionId;
  backingMaterialSessionId?: BackingMaterialSessionId;
  retention?: SigningSessionRetention;
  activeSignerSlot?: number;
};
type BaseEd25519SigningLaneInput = BaseSigningLaneInput & {
  accountId: AccountId;
};
type BaseEcdsaSigningLaneInput = BaseSigningLaneInput & {
  walletId: AccountId;
};
export type NearTransactionSigningLane = SelectedEd25519Lane & SelectedSigningSessionPlanningLane;
export type EcdsaTransactionSigningLane = SelectedEcdsaLane & SelectedSigningSessionPlanningLane;
type OptionalRetention<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane> =
  Omit<TLane, 'retention'> & {
    retention?: SigningSessionRetention;
  };
type BuildSigningLaneInput<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane> =
  OptionalRetention<TLane>;

export type Ed25519PasskeySigningLaneInput = BaseEd25519SigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  storageSource: Ed25519PasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type Ed25519EmailOtpSigningLaneInput = BaseEd25519SigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaPasskeySigningLaneInput = BaseEcdsaSigningLaneInput & {
  subjectId: WalletSubjectId;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  storageSource: EcdsaPasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaEmailOtpSigningLaneInput = BaseEcdsaSigningLaneInput & {
  subjectId: WalletSubjectId;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  sessionOrigin?: SigningSessionOrigin;
};

export type NearTransactionSigningLaneInput =
  | ({ authMethod: 'passkey' } & Ed25519PasskeySigningLaneInput)
  | ({ authMethod: 'email_otp' } & Ed25519EmailOtpSigningLaneInput);

export type EcdsaTransactionSigningLaneInput =
  | ({ authMethod: 'passkey' } & EcdsaPasskeySigningLaneInput)
  | ({ authMethod: 'email_otp' } & EcdsaEmailOtpSigningLaneInput);

export function buildEd25519PasskeySigningLane(
  input: Ed25519PasskeySigningLaneInput,
): NearTransactionSigningLane {
  return buildSigningLane<NearTransactionSigningLane>({
    ...input,
    ...selectedEd25519Lane({
      accountId: input.accountId,
      authMethod: 'passkey',
      walletSigningSessionId: input.walletSigningSessionId,
      thresholdSessionId: input.thresholdSessionId,
    }),
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    sessionOrigin:
      input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEd25519EmailOtpSigningLane(
  input: Ed25519EmailOtpSigningLaneInput,
): NearTransactionSigningLane {
  return buildSigningLane<NearTransactionSigningLane>({
    ...input,
    ...selectedEd25519Lane({
      accountId: input.accountId,
      authMethod: 'email_otp',
      walletSigningSessionId: input.walletSigningSessionId,
      thresholdSessionId: input.thresholdSessionId,
    }),
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
  });
}

export function buildEcdsaPasskeySigningLane(
  input: EcdsaPasskeySigningLaneInput,
): EcdsaTransactionSigningLane {
  return buildSigningLane<EcdsaTransactionSigningLane>({
    ...input,
    ...selectedEcdsaLane({
      walletId: input.walletId,
      authMethod: 'passkey',
      walletSigningSessionId: input.walletSigningSessionId,
      thresholdSessionId: input.thresholdSessionId,
      subjectId: input.subjectId,
      chainTarget: input.chainTarget,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: input.chainTarget.kind,
    sessionOrigin:
      input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEcdsaEmailOtpSigningLane(
  input: EcdsaEmailOtpSigningLaneInput,
): EcdsaTransactionSigningLane {
  return buildSigningLane<EcdsaTransactionSigningLane>({
    ...input,
    ...selectedEcdsaLane({
      walletId: input.walletId,
      authMethod: 'email_otp',
      walletSigningSessionId: input.walletSigningSessionId,
      thresholdSessionId: input.thresholdSessionId,
      subjectId: input.subjectId,
      chainTarget: input.chainTarget,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: input.chainTarget.kind,
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
  });
}

export function buildNearTransactionSigningLane(
  input: NearTransactionSigningLaneInput,
): NearTransactionSigningLane {
  return input.authMethod === 'email_otp'
    ? buildEd25519EmailOtpSigningLane(input)
    : buildEd25519PasskeySigningLane(input);
}

export function buildTempoTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): EcdsaTransactionSigningLane {
  if (input.chainTarget.kind !== 'tempo') {
    throw new Error('Tempo ECDSA transaction lane requires a Tempo chain target');
  }
  return buildEcdsaTransactionSigningLane(input);
}

export function buildEvmTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): EcdsaTransactionSigningLane {
  if (input.chainTarget.kind !== 'evm') {
    throw new Error('EVM ECDSA transaction lane requires an EIP-155 chain target');
  }
  return buildEcdsaTransactionSigningLane(input);
}

function buildEcdsaTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): EcdsaTransactionSigningLane {
  return input.authMethod === 'email_otp'
    ? buildEcdsaEmailOtpSigningLane(input)
    : buildEcdsaPasskeySigningLane(input);
}

function buildSigningLane<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane>(
  input: BuildSigningLaneInput<TLane>,
): TLane {
  return {
    ...input,
    retention: input.retention || 'session',
  } as TLane;
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
    walletId: AccountId;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
  }) => ThresholdEcdsaSessionRecord | null;
  readPasskeyEcdsaSessionRecord?: (args: {
    walletId: AccountId;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    storageSource: EcdsaPasskeyStorageSource;
    signingRootId?: string;
    signingRootVersion?: string;
  }) => ThresholdEcdsaSessionRecord | null;
  readEmailOtpEcdsaKeyRef?: (args: {
    walletId: AccountId;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
  }) => ThresholdEcdsaSecp256k1KeyRef | null;
  readPasskeyEcdsaKeyRef?: (args: {
    walletId: AccountId;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
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
  lane: SelectedSigningSessionPlanningLane;
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
      lane: SelectedSigningSessionPlanningLane;
      capability: SigningCapabilityRecord;
    }
  | SigningCapabilityReadError;

export type SigningCapabilityKeyRefResult =
  | {
      ok: true;
      lane: SelectedSigningSessionPlanningLane;
      keyRef: ThresholdEcdsaSecp256k1KeyRef;
    }
  | SigningCapabilityReadError;

export type SigningCapabilityResult =
  | {
      ok: true;
      lane: SelectedSigningSessionPlanningLane;
      capability: SigningCapabilityRecord;
      keyRef?: ThresholdEcdsaSecp256k1KeyRef;
    }
  | SigningCapabilityReadError;

export type SigningCapabilityReader = {
  readRecord(lane: SelectedSigningSessionPlanningLane): SigningCapabilityRecordResult;
  readEcdsaKeyRef(lane: SelectedSigningSessionPlanningLane): SigningCapabilityKeyRefResult;
  readCapability(lane: SelectedSigningSessionPlanningLane): SigningCapabilityResult;
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
  lane: SelectedSigningSessionPlanningLane,
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
  lane: SelectedSigningSessionPlanningLane,
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
  lane: SelectedSigningSessionPlanningLane,
): SigningCapabilityKeyRefResult {
  if (lane.curve !== 'ecdsa') {
    return readError(lane, 'unsupported_curve', 'ECDSA key refs require an ECDSA signing lane');
  }
  const chainTarget = ecdsaChainTargetFromLane(lane);
  if (!chainTarget) {
    return readError(
      lane,
      'record_mismatch',
      'ECDSA signing lane must carry a concrete chain target',
    );
  }
  const subjectId = ecdsaSubjectIdFromLane(lane);
  if (!subjectId) {
    return readError(lane, 'record_mismatch', 'ECDSA signing lane must carry a wallet subject id');
  }

  const keyRef =
    lane.authMethod === 'email_otp'
      ? deps.readEmailOtpEcdsaKeyRef?.({
          walletId: lane.walletId,
          subjectId,
          chainTarget,
          ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
          ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
        })
      : readPasskeyEcdsaKeyRef(deps, lane, chainTarget, subjectId);
  if (!keyRef) {
    return readError(lane, 'missing_key_ref', 'Missing selected-lane ECDSA key ref');
  }
  return validateEcdsaKeyRefForLane(lane, keyRef);
}

function readEd25519CapabilityRecord(
  deps: SigningCapabilityReaderDeps,
  lane: SelectedSigningSessionPlanningLane,
): SigningCapabilityRecordResult {
  if (lane.chainFamily !== 'near' || lane.keyKind !== 'threshold_ed25519') {
    return readError(
      lane,
      'record_mismatch',
      'Ed25519 signing lane must target NEAR threshold signing',
    );
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

  const candidate = thresholdEd25519LaneCandidateFromSessionRecord({ record });
  if (!candidate) {
    return readError(
      lane,
      'record_mismatch',
      'Selected Ed25519 session record has no lane candidate',
    );
  }
  const mismatch =
    validateLaneCandidateForSigningLane(lane, candidate) ||
    validateThresholdRecordStorageSourceForLane(lane, record.source);
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
  lane: SelectedSigningSessionPlanningLane,
): SigningCapabilityRecordResult {
  if (lane.keyKind !== 'threshold_ecdsa_secp256k1') {
    return readError(
      lane,
      'record_mismatch',
      'ECDSA signing lane must target threshold secp256k1 signing',
    );
  }
  const chainTarget = ecdsaChainTargetFromLane(lane);
  if (!chainTarget) {
    return readError(
      lane,
      'record_mismatch',
      'ECDSA signing lane must carry a concrete chain target',
    );
  }
  const subjectId = ecdsaSubjectIdFromLane(lane);
  if (!subjectId) {
    return readError(lane, 'record_mismatch', 'ECDSA signing lane must carry a wallet subject id');
  }

  const record =
    lane.authMethod === 'email_otp'
      ? deps.readEmailOtpEcdsaSessionRecord?.({
          walletId: lane.walletId,
          subjectId,
          chainTarget,
          ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
          ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
        })
      : readPasskeyEcdsaRecord(deps, lane, chainTarget, subjectId);
  if (!record) {
    return readError(lane, 'missing_record', 'Missing selected-lane ECDSA session record');
  }

  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record });
  const mismatch =
    validateLaneCandidateForSigningLane(lane, candidate) ||
    validateThresholdRecordStorageSourceForLane(lane, record.source);
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
  lane: SelectedEcdsaSigningSessionPlanningLane,
  chainTarget: ThresholdEcdsaChainTarget,
  subjectId: WalletSubjectId,
): ThresholdEcdsaSessionRecord | null | undefined {
  if (!isEcdsaPasskeyStorageSource(lane.storageSource)) return null;
  return deps.readPasskeyEcdsaSessionRecord?.({
    walletId: lane.walletId,
    subjectId,
    chainTarget,
    storageSource: lane.storageSource,
    ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
    ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
  });
}

function readPasskeyEcdsaKeyRef(
  deps: SigningCapabilityReaderDeps,
  lane: SelectedEcdsaSigningSessionPlanningLane,
  chainTarget: ThresholdEcdsaChainTarget,
  subjectId: WalletSubjectId,
): ThresholdEcdsaSecp256k1KeyRef | null | undefined {
  if (!isEcdsaPasskeyStorageSource(lane.storageSource)) return null;
  return deps.readPasskeyEcdsaKeyRef?.({
    walletId: lane.walletId,
    subjectId,
    chainTarget,
    storageSource: lane.storageSource,
    ...(lane.signingRootId ? { signingRootId: lane.signingRootId } : {}),
    ...(lane.signingRootVersion ? { signingRootVersion: lane.signingRootVersion } : {}),
  });
}

function validateEcdsaKeyRefForLane(
  lane: SelectedSigningSessionPlanningLane,
  keyRef: ThresholdEcdsaSecp256k1KeyRef,
): SigningCapabilityKeyRefResult {
  if (String(keyRef.userId || '') !== String(lane.walletId)) {
    return readError(
      lane,
      'key_ref_mismatch',
      'ECDSA key ref account does not match selected lane',
    );
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
    return readError(
      lane,
      'key_ref_mismatch',
      'ECDSA key ref signing root does not match selected lane',
    );
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

function validateLaneCandidateForSigningLane(
  lane: SelectedSigningSessionPlanningLane,
  candidate: Ed25519LaneCandidate | EcdsaLaneCandidate,
): SigningCapabilityReadError | null {
  if (candidate.curve === 'ecdsa') {
    if (lane.curve !== 'ecdsa' || String(candidate.walletId) !== String(lane.walletId)) {
      return readError(
        lane,
        'record_mismatch',
        'Session record wallet does not match selected lane',
      );
    }
  } else if (String(candidate.accountId) !== String(lane.accountId)) {
    return readError(
      lane,
      'record_mismatch',
      'Session record account does not match selected lane',
    );
  }
  if (candidate.authMethod !== lane.authMethod) {
    return readError(
      lane,
      'record_mismatch',
      'Session record auth method does not match selected lane',
    );
  }
  if (candidate.curve !== lane.curve) {
    return readError(lane, 'record_mismatch', 'Session record curve does not match selected lane');
  }
  if (
    lane.thresholdSessionId &&
    String(candidate.thresholdSessionId || '') !== String(lane.thresholdSessionId)
  ) {
    return readError(
      lane,
      'record_mismatch',
      'Session record threshold session does not match selected lane',
    );
  }
  if (
    lane.walletSigningSessionId &&
    String(candidate.walletSigningSessionId || '') !== String(lane.walletSigningSessionId)
  ) {
    return readError(
      lane,
      'record_mismatch',
      'Session record wallet signing session does not match selected lane',
    );
  }
  if (candidate.curve === 'ecdsa') {
    if (lane.curve !== 'ecdsa') {
      return readError(lane, 'record_mismatch', 'ECDSA session record requires an ECDSA lane');
    }
    if (!thresholdEcdsaChainTargetsEqual(candidate.chainTarget, lane.chainTarget)) {
      return readError(
        lane,
        'record_mismatch',
        'Session record chain target does not match selected lane',
      );
    }
    if (String(candidate.subjectId) !== String(lane.subjectId)) {
      return readError(
        lane,
        'record_mismatch',
        'Session record wallet subject does not match selected lane',
      );
    }
    if (String(candidate.ecdsaThresholdKeyId) !== String(lane.ecdsaThresholdKeyId)) {
      return readError(
        lane,
        'record_mismatch',
        'Session record ECDSA key does not match selected lane',
      );
    }
    if (String(candidate.signingRootId) !== String(lane.signingRootId)) {
      return readError(
        lane,
        'record_mismatch',
        'Session record signing root does not match selected lane',
      );
    }
    if (
      normalizedOptionalString(candidate.signingRootVersion) !==
      normalizedOptionalString(lane.signingRootVersion)
    ) {
      return readError(
        lane,
        'record_mismatch',
        'Session record signing root version does not match selected lane',
      );
    }
  }
  return null;
}

function validateThresholdRecordStorageSourceForLane(
  lane: SelectedSigningSessionPlanningLane,
  source: SigningSessionStorageSource,
): SigningCapabilityReadError | null {
  if (source !== lane.storageSource) {
    return readError(lane, 'record_mismatch', 'Session record source does not match selected lane');
  }
  return null;
}

function ecdsaChainTargetFromLane(
  lane: SelectedSigningSessionPlanningLane,
): ThresholdEcdsaChainTarget | null {
  const chainTarget = lane.chainTarget;
  if (!chainTarget || lane.chainFamily !== chainTarget.kind) return null;
  return chainTarget;
}

function ecdsaSubjectIdFromLane(lane: SelectedSigningSessionPlanningLane): WalletSubjectId | null {
  const subjectId = String(lane.subjectId || '').trim();
  return subjectId ? (subjectId as WalletSubjectId) : null;
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
  lane: SelectedSigningSessionPlanningLane,
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
