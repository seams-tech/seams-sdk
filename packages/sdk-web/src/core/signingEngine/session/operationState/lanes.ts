import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention } from '@/core/types/seams';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '../persistence/records';
import {
  thresholdEcdsaLaneCandidateFromSessionRecord,
  thresholdEd25519LaneCandidateFromSessionRecord,
} from '../persistence/records';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  classifyRouterAbEd25519PersistedSigningRecord,
} from '../routerAbSigningWalletSession';
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
import {
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from '../identity/signingLaneAuthBinding';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmFamilyEcdsaKeyIdentity } from '../identity/evmFamilyEcdsaIdentity';
import type {
  BackingMaterialSessionId,
  SelectedEcdsaSigningSessionPlanningLane,
  SelectedSigningSessionPlanningLane,
  SigningSessionOrigin,
  SigningSessionStorageSource,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  SigningGrantId,
} from './types';

export type Ed25519PasskeySigningLaneSource = Exclude<
  ThresholdEd25519SessionStoreSource,
  'email_otp'
>;
export type EcdsaPasskeySigningLaneSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

type BaseSigningLaneInput = {
  signingGrantId: SigningGrantId;
  backingMaterialSessionId?: BackingMaterialSessionId;
  retention?: SigningSessionRetention;
  activeSignerSlot?: number;
};
type BaseEd25519SigningLaneInput = BaseSigningLaneInput & {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
};
type BaseEcdsaSigningLaneInput = BaseSigningLaneInput & {
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: string;
  walletId: WalletId;
};
export type NearTransactionSigningLane = SelectedEd25519Lane & SelectedSigningSessionPlanningLane;
export type EcdsaTransactionSigningLane = SelectedEcdsaLane & SelectedSigningSessionPlanningLane;
type OptionalRetention<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane> =
  Omit<TLane, 'retention' | 'runtimeState'> & {
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
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  storageSource: EcdsaPasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaEmailOtpSigningLaneInput = BaseEcdsaSigningLaneInput & {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  sessionOrigin?: SigningSessionOrigin;
};

type PasskeySigningLaneAuthInput = {
  auth: Extract<SigningLaneAuthBinding, { kind: 'passkey' }>;
};

type EmailOtpSigningLaneAuthInput = {
  auth: Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;
};

export type Ed25519PasskeyTransactionSigningLaneInput =
  PasskeySigningLaneAuthInput & Ed25519PasskeySigningLaneInput;
export type Ed25519EmailOtpTransactionSigningLaneInput =
  EmailOtpSigningLaneAuthInput & Ed25519EmailOtpSigningLaneInput;
export type NearTransactionSigningLaneInput =
  | Ed25519PasskeyTransactionSigningLaneInput
  | Ed25519EmailOtpTransactionSigningLaneInput;

export type EcdsaPasskeyTransactionSigningLaneInput =
  PasskeySigningLaneAuthInput & EcdsaPasskeySigningLaneInput;
export type EcdsaEmailOtpTransactionSigningLaneInput =
  EmailOtpSigningLaneAuthInput & EcdsaEmailOtpSigningLaneInput;
export type EcdsaTransactionSigningLaneInput =
  | EcdsaPasskeyTransactionSigningLaneInput
  | EcdsaEmailOtpTransactionSigningLaneInput;

export function buildEd25519PasskeySigningLane(
  input: PasskeySigningLaneAuthInput & Ed25519PasskeySigningLaneInput,
): NearTransactionSigningLane {
  return buildSigningLane<NearTransactionSigningLane>({
    ...input,
    ...selectedEd25519Lane({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signerSlot: input.signerSlot,
      auth: input.auth,
      signingGrantId: input.signingGrantId,
      thresholdSessionId: input.thresholdSessionId,
    }),
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    sessionOrigin:
      input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEd25519EmailOtpSigningLane(
  input: EmailOtpSigningLaneAuthInput & Ed25519EmailOtpSigningLaneInput,
): NearTransactionSigningLane {
  return buildSigningLane<NearTransactionSigningLane>({
    ...input,
    ...selectedEd25519Lane({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signerSlot: input.signerSlot,
      auth: input.auth,
      signingGrantId: input.signingGrantId,
      thresholdSessionId: input.thresholdSessionId,
    }),
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
  });
}

export function buildEcdsaPasskeySigningLane(
  input: PasskeySigningLaneAuthInput & EcdsaPasskeySigningLaneInput,
): EcdsaTransactionSigningLane {
  return buildSigningLane<EcdsaTransactionSigningLane>({
    ...input,
    ...selectedEcdsaLane({
      key: input.key,
      keyHandle: input.keyHandle,
      walletId: input.walletId,
      auth: input.auth,
      signingGrantId: input.signingGrantId,
      thresholdSessionId: input.thresholdSessionId,
      chainTarget: input.chainTarget,
    }),
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: input.chainTarget.kind,
    sessionOrigin:
      input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEcdsaEmailOtpSigningLane(
  input: EmailOtpSigningLaneAuthInput & EcdsaEmailOtpSigningLaneInput,
): EcdsaTransactionSigningLane {
  return buildSigningLane<EcdsaTransactionSigningLane>({
    ...input,
    ...selectedEcdsaLane({
      key: input.key,
      keyHandle: input.keyHandle,
      walletId: input.walletId,
      auth: input.auth,
      signingGrantId: input.signingGrantId,
      thresholdSessionId: input.thresholdSessionId,
      chainTarget: input.chainTarget,
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
  if (isEd25519EmailOtpTransactionSigningLaneInput(input)) {
    return buildEd25519EmailOtpSigningLane(input);
  }
  if (isEd25519PasskeyTransactionSigningLaneInput(input)) {
    return buildEd25519PasskeySigningLane(input);
  }
  input satisfies never;
  throw new Error('[SigningSession] unsupported NEAR lane auth');
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
  if (isEcdsaEmailOtpTransactionSigningLaneInput(input)) {
    return buildEcdsaEmailOtpSigningLane(input);
  }
  if (isEcdsaPasskeyTransactionSigningLaneInput(input)) {
    return buildEcdsaPasskeySigningLane(input);
  }
  input satisfies never;
  throw new Error('[SigningSession] unsupported ECDSA lane auth');
}

function isEd25519PasskeyTransactionSigningLaneInput(
  input: NearTransactionSigningLaneInput,
): input is Ed25519PasskeyTransactionSigningLaneInput {
  return input.auth.kind === 'passkey';
}

function isEd25519EmailOtpTransactionSigningLaneInput(
  input: NearTransactionSigningLaneInput,
): input is Ed25519EmailOtpTransactionSigningLaneInput {
  return input.auth.kind === 'email_otp';
}

function isEcdsaPasskeyTransactionSigningLaneInput(
  input: EcdsaTransactionSigningLaneInput,
): input is EcdsaPasskeyTransactionSigningLaneInput {
  return input.auth.kind === 'passkey';
}

function isEcdsaEmailOtpTransactionSigningLaneInput(
  input: EcdsaTransactionSigningLaneInput,
): input is EcdsaEmailOtpTransactionSigningLaneInput {
  return input.auth.kind === 'email_otp';
}

function buildSigningLane<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane>(
  input: BuildSigningLaneInput<TLane>,
): TLane {
  return {
    ...input,
    ...runtimeStateFromLaneInput(input),
    retention: input.retention || 'session',
  } as TLane;
}

function runtimeStateFromLaneInput(input: {
  backingMaterialSessionId?: BackingMaterialSessionId;
  activeSignerSlot?: number;
}):
  | { runtimeState: 'no_runtime_material' }
  | { runtimeState: 'backing_material'; backingMaterialSessionId: BackingMaterialSessionId }
  | { runtimeState: 'active_signer'; activeSignerSlot: number }
  | {
      runtimeState: 'backing_material_with_active_signer';
      backingMaterialSessionId: BackingMaterialSessionId;
      activeSignerSlot: number;
    } {
  const backingMaterialSessionId = input.backingMaterialSessionId;
  const activeSignerSlot = Math.floor(Number(input.activeSignerSlot) || 0);
  if (backingMaterialSessionId && activeSignerSlot > 0) {
    return {
      runtimeState: 'backing_material_with_active_signer',
      backingMaterialSessionId,
      activeSignerSlot,
    };
  }
  if (backingMaterialSessionId) {
    return { runtimeState: 'backing_material', backingMaterialSessionId };
  }
  if (activeSignerSlot > 0) {
    return { runtimeState: 'active_signer', activeSignerSlot };
  }
  return { runtimeState: 'no_runtime_material' };
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

type EcdsaCapabilityLookupArgs = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  thresholdSessionId: string;
  signingGrantId: string;
};

export type SigningCapabilityReaderDeps = {
  readEd25519SessionRecordByThresholdSessionId?: (args: {
    thresholdSessionId: string;
  }) => ThresholdEd25519SessionRecord | null;
  readEmailOtpEcdsaSessionRecord?: (
    args: EcdsaCapabilityLookupArgs,
  ) => ThresholdEcdsaSessionRecord | null;
  readPasskeyEcdsaSessionRecord?: (
    args: EcdsaCapabilityLookupArgs & {
      storageSource: EcdsaPasskeyStorageSource;
    },
  ) => ThresholdEcdsaSessionRecord | null;
};

export type SigningCapabilityReadErrorCode =
  | 'missing_reader'
  | 'missing_record'
  | 'record_mismatch'
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

export type SigningCapabilityResult =
  | {
      ok: true;
      lane: SelectedSigningSessionPlanningLane;
      capability: Extract<SigningCapabilityRecord, { curve: 'ed25519' }>;
    }
  | {
      ok: true;
      lane: SelectedSigningSessionPlanningLane;
      capability: Extract<SigningCapabilityRecord, { curve: 'ecdsa' }>;
      keyRef?: never;
    }
  | SigningCapabilityReadError;

export type SigningCapabilityReader = {
  readRecord(lane: SelectedSigningSessionPlanningLane): SigningCapabilityRecordResult;
  readCapability(lane: SelectedSigningSessionPlanningLane): SigningCapabilityResult;
};

export function createSigningCapabilityReader(
  deps: SigningCapabilityReaderDeps,
): SigningCapabilityReader {
  return {
    readRecord(lane) {
      return readSigningCapabilityRecord(deps, lane);
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
  if (recordResult.capability.curve === 'ed25519') {
    return {
      ok: true,
      lane: recordResult.lane,
      capability: recordResult.capability,
    };
  }
  if (recordResult.capability.curve !== 'ecdsa') {
    return readError(
      lane,
      'unsupported_curve',
      'Signing capability record resolved to an unsupported curve',
    );
  }

  return {
    ok: true,
    lane: recordResult.lane,
    capability: recordResult.capability,
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

  const signableSession = classifyRouterAbEd25519PersistedSigningRecord(record);
  if (signableSession.kind !== 'runtime_validated') {
    return readError(
      lane,
      'record_mismatch',
      `Selected Ed25519 session record is not Router A/B signable: ${signableSession.reason}`,
    );
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
  const signer = lane.identity.signer;
  if (signer.kind !== 'evm_family_ecdsa_signer' || lane.chainFamily !== signer.chainTarget.kind) {
    return readError(
      lane,
      'record_mismatch',
      'ECDSA signing lane must carry a concrete chain target',
    );
  }

  const record =
    signingLaneAuthMethod(lane.auth) === 'email_otp'
      ? deps.readEmailOtpEcdsaSessionRecord?.({
          walletId: signer.walletId,
          chainTarget: signer.chainTarget,
          keyHandle: signer.keyHandle,
          thresholdSessionId: lane.thresholdSessionId,
          signingGrantId: lane.signingGrantId,
        })
      : readPasskeyEcdsaRecord(deps, lane, signer);
  if (!record) {
    return readError(lane, 'missing_record', 'Missing selected-lane ECDSA session record');
  }

  const signableSession = classifyRouterAbEcdsaHssPersistedSigningRecord(record);
  if (signableSession.kind !== 'runtime_validated') {
    return readError(
      lane,
      'record_mismatch',
      `Selected ECDSA session record is not Router A/B runtime-validated: ${signableSession.reason}`,
    );
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
  signer: Extract<SelectedEcdsaSigningSessionPlanningLane['identity']['signer'], { kind: 'evm_family_ecdsa_signer' }>,
): ThresholdEcdsaSessionRecord | null | undefined {
  if (!isEcdsaPasskeyStorageSource(lane.storageSource)) return null;
  return deps.readPasskeyEcdsaSessionRecord?.({
    walletId: signer.walletId,
    chainTarget: signer.chainTarget,
    storageSource: lane.storageSource,
    keyHandle: signer.keyHandle,
    thresholdSessionId: lane.thresholdSessionId,
    signingGrantId: lane.signingGrantId,
  });
}

function validateLaneCandidateForSigningLane(
  lane: SelectedSigningSessionPlanningLane,
  candidate: Ed25519LaneCandidate | EcdsaLaneCandidate,
): SigningCapabilityReadError | null {
  if (candidate.curve === 'ecdsa') {
    const signer = lane.identity.signer;
    if (
      signer.kind !== 'evm_family_ecdsa_signer' ||
      String(candidate.walletId) !== String(signer.walletId) ||
      String(candidate.keyHandle || '').trim() !== String(signer.keyHandle || '').trim() ||
      !thresholdEcdsaChainTargetsEqual(candidate.chainTarget, signer.chainTarget)
    ) {
      return readError(
        lane,
        'record_mismatch',
        'Session record signer does not match selected lane',
      );
    }
  } else {
    const signer = lane.identity.signer;
    if (
      signer.kind !== 'near_ed25519_signer' ||
      String(candidate.walletId) !== String(signer.account.wallet.walletId) ||
      String(candidate.nearAccountId) !== String(signer.account.nearAccountId) ||
      String(candidate.nearEd25519SigningKeyId) !== String(signer.nearEd25519SigningKeyId) ||
      Number(candidate.signerSlot) !== Number(signer.signerSlot)
    ) {
      return readError(
        lane,
        'record_mismatch',
        'Session record signer does not match selected lane',
      );
    }
  }
  if (signingLaneAuthMethod(candidate.auth) !== signingLaneAuthMethod(lane.identity.auth)) {
    return readError(
      lane,
      'record_mismatch',
      'Session record auth method does not match selected lane',
    );
  }
  if (candidate.curve !== lane.curve) {
    return readError(lane, 'record_mismatch', 'Session record curve does not match selected lane');
  }
  if (String(candidate.thresholdSessionId || '') !== String(lane.identity.thresholdSessionId)) {
    return readError(
      lane,
      'record_mismatch',
      'Session record threshold session does not match selected lane',
    );
  }
  if (String(candidate.signingGrantId || '') !== String(lane.identity.signingGrantId)) {
    return readError(
      lane,
      'record_mismatch',
      'Session record signing grant does not match selected lane',
    );
  }
  if (candidate.curve === 'ecdsa') {
    const signer = lane.identity.signer;
    if (signer.kind !== 'evm_family_ecdsa_signer') {
      return readError(lane, 'record_mismatch', 'ECDSA session record requires an ECDSA lane');
    }
    if (!thresholdEcdsaChainTargetsEqual(candidate.chainTarget, signer.chainTarget)) {
      return readError(
        lane,
        'record_mismatch',
        'Session record chain target does not match selected lane',
      );
    }
    if (String(candidate.keyHandle || '').trim() !== String(signer.keyHandle || '').trim()) {
      return readError(
        lane,
        'record_mismatch',
        'Session record key handle does not match selected lane',
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

function isEcdsaPasskeyStorageSource(
  source: SigningSessionStorageSource,
): source is EcdsaPasskeyStorageSource {
  return source === 'login' || source === 'registration' || source === 'manual-bootstrap';
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
