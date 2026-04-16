import type { onProgressEvents } from '@/core/types/sdkSentEvents';
import {
  type WorkerRequestTypeMap,
  type WorkerResponseForRequest,
  WorkerRequestType,
} from '@/core/types/signer-worker';
import type { MultichainWorkerKind } from '@/core/walletRuntimePaths/multichainWorkers';
import type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/thresholdActivation';

/**
 * Control messages exchanged between worker shims and the main thread.
 *
 * These messages are JS-only and do NOT go through the Rust WASM JSON request/response pipeline.
 * They are used for:
 * - Readiness signals for persisted signer-worker availability.
 */
export const WorkerControlMessage = {
  WORKER_READY: 'WORKER_READY',
} as const;

export type WorkerControlMessageType =
  (typeof WorkerControlMessage)[keyof typeof WorkerControlMessage];

export type ThresholdEcdsaPresignStage = 'triples' | 'triples_done' | 'presign' | 'done';
export type ThresholdEcdsaPresignEvent = 'none' | 'triples_done' | 'presign_done';

export type ThresholdEcdsaPresignProgressResult = {
  stage: ThresholdEcdsaPresignStage;
  event: ThresholdEcdsaPresignEvent;
  outgoingMessages: ArrayBuffer[];
  presignature97?: ArrayBuffer;
};

export interface EthSignerWorkerOperationMap {
  computeEip1559TxHash: {
    payload: { tx: unknown };
    result: ArrayBuffer;
  };
  encodeEip1559SignedTxFromSignature65: {
    payload: { tx: unknown; signature65: ArrayBuffer };
    result: ArrayBuffer;
  };
  signSecp256k1Recoverable: {
    payload: { digest32: ArrayBuffer; privateKey32: ArrayBuffer };
    result: ArrayBuffer;
  };
  secp256k1PrivateKey32ToPublicKey33: {
    payload: { privateKey32: ArrayBuffer };
    result: ArrayBuffer;
  };
  deriveSecp256k1KeypairFromPrfSecond: {
    payload: { prfSecond: ArrayBuffer; nearAccountId: string };
    result: {
      privateKey32: ArrayBuffer;
      publicKey33: ArrayBuffer;
      ethereumAddress20: ArrayBuffer;
    };
  };
  mapAdditiveShareToThresholdSignaturesShare2p: {
    payload: { additiveShare32: ArrayBuffer; participantId: number };
    result: ArrayBuffer;
  };
  validateSecp256k1PublicKey33: {
    payload: { publicKey33: ArrayBuffer };
    result: ArrayBuffer;
  };
  addSecp256k1PublicKeys33: {
    payload: { left33: ArrayBuffer; right33: ArrayBuffer };
    result: ArrayBuffer;
  };
  buildWebauthnP256Signature: {
    payload: {
      challenge32: ArrayBuffer;
      authenticatorData: ArrayBuffer;
      clientDataJSON: ArrayBuffer;
      signatureDer: ArrayBuffer;
      pubKeyX32: ArrayBuffer;
      pubKeyY32: ArrayBuffer;
    };
    result: ArrayBuffer;
  };
  thresholdEcdsaPresignSessionInit: {
    payload: {
      sessionId: string;
      participantIds: number[];
      clientParticipantId: number;
      threshold: number;
      clientThresholdSigningShare32: ArrayBuffer;
      groupPublicKey33: ArrayBuffer;
    };
    result: ThresholdEcdsaPresignProgressResult;
  };
  thresholdEcdsaPresignSessionStep: {
    payload: {
      sessionId: string;
      relayerParticipantId: number;
      stage: 'triples' | 'presign';
      incomingMessages?: ArrayBuffer[];
    };
    result: ThresholdEcdsaPresignProgressResult;
  };
  thresholdEcdsaPresignSessionAbort: {
    payload: { sessionId: string };
    result: { ok: boolean };
  };
  thresholdEcdsaComputeSignatureShare: {
    payload: {
      participantIds: number[];
      clientParticipantId: number;
      groupPublicKey33: ArrayBuffer;
      presignBigR33: ArrayBuffer;
      presignKShare32: ArrayBuffer;
      presignSigmaShare32: ArrayBuffer;
      digest32: ArrayBuffer;
      entropy32: ArrayBuffer;
    };
    result: ArrayBuffer;
  };
}

export interface TempoSignerWorkerOperationMap {
  computeTempoSenderHash: {
    payload: { tx: unknown };
    result: ArrayBuffer;
  };
  encodeTempoSignedTx: {
    payload: { tx: unknown; senderSignature: ArrayBuffer };
    result: ArrayBuffer;
  };
}

export interface EmailOtpWorkerOperationMap {
  requestEmailOtpChallenge: {
    payload: {
      relayUrl: string;
      walletId: string;
      appSessionJwt?: string;
      otpChannel?: 'email_otp';
    };
    result: {
      challengeId: string;
      otpChannel: 'email_otp';
    };
  };
  requestEmailOtpEnrollmentChallenge: {
    payload: {
      relayUrl: string;
      walletId: string;
      appSessionJwt?: string;
      otpChannel?: 'email_otp';
    };
    result: {
      challengeId: string;
      otpChannel: 'email_otp';
    };
  };
  enrollEmailOtpWallet: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId?: string;
      challengeId?: string;
      otpCode: string;
      shamirPrimeB64u: string;
      appSessionJwt?: string;
      otpChannel?: 'email_otp';
      clientSecret32?: ArrayBuffer;
    };
    result: {
      thresholdEcdsaClientVerifyingShareB64u: string;
      challengeId: string;
      otpChannel: 'email_otp';
      emailOtpKeyVersion: string;
      unlockPublicKeyB64u: string;
      unlockKeyVersion: string;
    };
  };
  verifyEmailOtpCode: {
    payload: {
      relayUrl: string;
      walletId: string;
      challengeId: string;
      otpCode: string;
      appSessionJwt?: string;
      otpChannel?: 'email_otp';
    };
    result: {
      loginGrant: string;
      otpChannel: 'email_otp';
      emailOtpEscrowBlob: string;
    };
  };
  loginWithEmailOtpAndBootstrapEcdsaSession: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId?: string;
      challengeId?: string;
      otpCode: string;
      shamirPrimeB64u: string;
      appSessionJwt?: string;
      otpChannel?: 'email_otp';
      rpId: string;
      ecdsaThresholdKeyId?: string;
      participantIds?: number[];
      sessionKind?: 'jwt' | 'cookie';
      sessionId?: string;
      authorizationJwt: string;
      ttlMs?: number;
      remainingUses?: number;
    };
    result: {
      recovery: {
        loginGrant: string;
        challengeId: string;
        emailOtpKeyVersion: string;
        unlockChallengeId: string;
        unlockChallengeB64u: string;
        unlockPublicKeyB64u: string;
        unlockSignatureB64u: string;
      };
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
    };
  };
  getEmailOtpWarmSessionStatus: {
    payload: {
      sessionId: string;
    };
    result:
      | { ok: true; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
  };
  claimEmailOtpWarmSessionMaterial: {
    payload: {
      sessionId: string;
      uses?: number;
    };
    result:
      | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
  };
  clearEmailOtpWarmSessionMaterial: {
    payload: {
      sessionId: string;
    };
    result: {
      ok: true;
      cleared: true;
    };
  };
}

export interface MultichainSignerWorkerOperationMapByKind {
  ethSigner: EthSignerWorkerOperationMap;
  tempoSigner: TempoSignerWorkerOperationMap;
}

export type MultichainOperationType<K extends MultichainWorkerKind> =
  keyof MultichainSignerWorkerOperationMapByKind[K];

type MultichainWorkerOperationEntry<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
> = MultichainSignerWorkerOperationMapByKind[K][T] extends {
  payload: infer P;
  result: infer R;
}
  ? { payload: P; result: R }
  : never;

export type MultichainWorkerOperationRequest<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
> = {
  type: T;
  payload: MultichainWorkerOperationEntry<K, T>['payload'];
  timeoutMs?: number;
  transfer?: Transferable[];
};

export type MultichainWorkerOperationResult<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
> = MultichainWorkerOperationEntry<K, T>['result'];

export type WithOptionalSessionId<T> = T extends { sessionId: string }
  ? Omit<T, 'sessionId'> & { sessionId?: string }
  : T;

export type NearSignerWorkerOperationMap = {
  [T in keyof WorkerRequestTypeMap]: {
    payload: WithOptionalSessionId<WorkerRequestTypeMap[T]['request']>;
    result: WorkerResponseForRequest<T>;
  };
};

export type NearWorkerOperationType = keyof NearSignerWorkerOperationMap;

type NearWorkerOperationEntry<T extends NearWorkerOperationType> = NearSignerWorkerOperationMap[T];

export type NearWorkerOperationRequest<T extends NearWorkerOperationType> = {
  sessionId?: string;
  type: T;
  payload: NearWorkerOperationEntry<T>['payload'];
  onEvent?: (update: onProgressEvents) => void;
  timeoutMs?: number;
  transfer?: Transferable[];
};

export type NearWorkerOperationResult<T extends NearWorkerOperationType> =
  NearWorkerOperationEntry<T>['result'];

export type HssWorkerOperationType =
  | typeof WorkerRequestType.DeriveThresholdEd25519HssClientInputs
  | typeof WorkerRequestType.PrepareThresholdEd25519HssSession
  | typeof WorkerRequestType.PrepareThresholdEd25519HssClientRequest
  | typeof WorkerRequestType.OpenThresholdEd25519HssClientOutput
  | typeof WorkerRequestType.OpenThresholdEd25519HssSeedOutput
  | typeof WorkerRequestType.BuildThresholdEd25519SeedExportArtifact
  | typeof WorkerRequestType.PrepareThresholdEcdsaHssSession
  | typeof WorkerRequestType.PrepareThresholdEcdsaHssClientRequest
  | typeof WorkerRequestType.FinalizeThresholdEcdsaHssClientRequest;

type HssWorkerOperationEntry<T extends HssWorkerOperationType> = WorkerRequestTypeMap[T] extends {
  request: infer P;
  result: infer R;
}
  ? { payload: P; result: WorkerResponseForRequest<T> }
  : never;

export type HssWorkerOperationRequest<T extends HssWorkerOperationType> = {
  sessionId?: string;
  type: T;
  payload: WithOptionalSessionId<HssWorkerOperationEntry<T>['payload']>;
  timeoutMs?: number;
  transfer?: Transferable[];
};

export type HssWorkerOperationResult<T extends HssWorkerOperationType> =
  HssWorkerOperationEntry<T>['result'];

export type HssSignerWorkerOperationMap = {
  [T in HssWorkerOperationType]: {
    payload: HssWorkerOperationEntry<T>['payload'];
    result: HssWorkerOperationEntry<T>['result'];
  };
};

export interface SignerWorkerOperationMapByKind {
  nearSigner: NearSignerWorkerOperationMap;
  hssClient: HssSignerWorkerOperationMap;
  ethSigner: EthSignerWorkerOperationMap;
  tempoSigner: TempoSignerWorkerOperationMap;
  emailOtp: EmailOtpWorkerOperationMap;
}

export type SignerWorkerKind = keyof SignerWorkerOperationMapByKind;

export type SignerWorkerOperationType<K extends SignerWorkerKind> =
  keyof SignerWorkerOperationMapByKind[K];

type SignerWorkerOperationEntry<
  K extends SignerWorkerKind,
  T extends SignerWorkerOperationType<K>,
> = SignerWorkerOperationMapByKind[K][T] extends { payload: infer P; result: infer R }
  ? { payload: P; result: R }
  : never;

export type SignerWorkerOperationRequest<
  K extends SignerWorkerKind,
  T extends SignerWorkerOperationType<K>,
> = K extends 'nearSigner'
  ? NearWorkerOperationRequest<Extract<T, NearWorkerOperationType>>
  : K extends 'hssClient'
    ? HssWorkerOperationRequest<Extract<T, HssWorkerOperationType>>
    : {
        type: T;
        payload: SignerWorkerOperationEntry<K, T>['payload'];
        timeoutMs?: number;
        transfer?: Transferable[];
      };

export type SignerWorkerOperationResult<
  K extends SignerWorkerKind,
  T extends SignerWorkerOperationType<K>,
> = SignerWorkerOperationEntry<K, T>['result'];

export interface SignerWorkerTransportProtocol {
  setWorkerBaseOrigin(origin: string | undefined): void;
  prewarmWorkers(): Promise<void>;
  requestOperation<K extends SignerWorkerKind, T extends SignerWorkerOperationType<K>>(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
}

export type SignerHostErrorCode =
  | 'SIGNER_INVALID_INPUT'
  | 'SIGNER_INVALID_LENGTH'
  | 'SIGNER_DECODE_ERROR'
  | 'SIGNER_ENCODE_ERROR'
  | 'SIGNER_KDF_ERROR'
  | 'SIGNER_CRYPTO_ERROR'
  | 'SIGNER_UTF8_ERROR'
  | 'SIGNER_UNSUPPORTED'
  | 'SIGNER_INTERNAL'
  | 'WORKER_RUNTIME_ERROR'
  | 'WORKER_POSTMESSAGE_ERROR'
  | 'WORKER_PROTOCOL_ERROR'
  | 'TIMEOUT';

export const DEFAULT_SIGNER_HOST_ERROR_CODE: SignerHostErrorCode = 'SIGNER_INTERNAL';

export class SignerWorkerOperationError extends Error {
  readonly code: string;
  readonly coreCode?: string;
  readonly workerKind?: SignerWorkerKind;

  constructor(args: {
    message: string;
    code?: string | null;
    coreCode?: string | null;
    workerKind?: SignerWorkerKind;
  }) {
    super(args.message);
    this.name = 'SignerWorkerOperationError';
    this.code = (args.code || DEFAULT_SIGNER_HOST_ERROR_CODE).trim();
    this.coreCode = args.coreCode?.trim() || undefined;
    this.workerKind = args.workerKind;
  }
}

export function getSignerWorkerOperationErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const code = (error as { code?: unknown }).code;
  if (typeof code !== 'string') return undefined;
  const trimmed = code.trim();
  return trimmed.length ? trimmed : undefined;
}
