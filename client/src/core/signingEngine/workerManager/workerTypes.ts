import {
  type NearWorkerProgressEvent,
  type WorkerRequestTypeMap,
  type WorkerResponseForRequest,
  WorkerRequestType,
} from '@/core/types/signer-worker';
import type { MultichainWorkerKind } from '@/core/walletRuntimePaths/multichainWorkers';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/thresholdActivation';
import type { ThresholdRuntimePolicyScope } from '../threshold/session/sessionPolicy';
import type {
  WalletEmailOtpChannel,
  WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';

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
      otpChannel?: WalletEmailOtpChannel;
      operation?: WalletEmailOtpLoginOperation;
    };
    result: {
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      emailHint?: string;
      expiresAtMs?: number;
    };
  };
  requestEmailOtpEnrollmentChallenge: {
    payload: {
      relayUrl: string;
      walletId: string;
      appSessionJwt?: string;
      otpChannel?: WalletEmailOtpChannel;
    };
    result: {
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      emailHint?: string;
      expiresAtMs?: number;
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
      otpChannel?: WalletEmailOtpChannel;
      clientSecret32?: ArrayBuffer;
    };
    result: {
      thresholdEcdsaClientVerifyingShareB64u: string;
      thresholdEd25519PrfFirstB64u: string;
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
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
      otpChannel?: WalletEmailOtpChannel;
      operation?: WalletEmailOtpLoginOperation;
    };
    result: {
      loginGrant: string;
      otpChannel: WalletEmailOtpChannel;
      emailOtpEscrowBlob: string;
    };
  };
  loginWithEmailOtpWallet: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId?: string;
      challengeId?: string;
      otpCode: string;
      shamirPrimeB64u: string;
      appSessionJwt?: string;
      otpChannel?: WalletEmailOtpChannel;
      operation?: WalletEmailOtpLoginOperation;
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
        thresholdEd25519PrfFirstB64u: string;
      };
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
      otpChannel?: WalletEmailOtpChannel;
      operation?: WalletEmailOtpLoginOperation;
      rpId: string;
      ecdsaThresholdKeyId?: string;
      participantIds?: number[];
      sessionKind?: 'jwt' | 'cookie';
      sessionId?: string;
      walletSigningSessionId?: string;
      thresholdRouteAuth?: AppOrThresholdSessionAuth;
      ttlMs?: number;
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
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
        thresholdEd25519PrfFirstB64u: string;
      };
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
    };
  };
  enrollEmailOtpWalletAndBootstrapEcdsaSession: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId?: string;
      challengeId?: string;
      otpCode: string;
      shamirPrimeB64u: string;
      appSessionJwt?: string;
      otpChannel?: WalletEmailOtpChannel;
      clientSecret32?: ArrayBuffer;
      rpId: string;
      ecdsaThresholdKeyId?: string;
      participantIds?: number[];
      sessionKind?: 'jwt' | 'cookie';
      sessionId?: string;
      walletSigningSessionId?: string;
      thresholdRouteAuth?: AppOrThresholdSessionAuth;
      ttlMs?: number;
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
    };
    result: {
      enrollment: {
        thresholdEcdsaClientVerifyingShareB64u: string;
        thresholdEd25519PrfFirstB64u: string;
        challengeId: string;
        otpChannel: WalletEmailOtpChannel;
        emailOtpKeyVersion: string;
        unlockPublicKeyB64u: string;
        unlockKeyVersion: string;
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
  sealEmailOtpWarmSessionMaterial: {
    payload: {
      sessionId: string;
      transport: {
        relayerUrl: string;
        thresholdSessionJwt?: string;
        keyVersion?: string;
        shamirPrimeB64u?: string;
      };
    };
    result:
      | {
          ok: true;
          sealedSecretB64u: string;
          keyVersion?: string;
          remainingUses: number;
          expiresAtMs: number;
        }
      | { ok: false; code: string; message: string };
  };
  rehydrateEmailOtpEcdsaWarmSessionMaterial: {
    payload: {
      sealedSecretB64u: string;
      remainingUses: number;
      expiresAtMs: number;
      transport: {
        relayerUrl: string;
        thresholdSessionJwt?: string;
        keyVersion?: string;
        shamirPrimeB64u?: string;
      };
      restore: {
        sessionId: string;
        walletId: string;
        userId?: string;
        rpId: string;
        chain?: ThresholdEcdsaActivationChain;
        walletSigningSessionId: string;
        signingRootId: string;
        signingRootVersion?: string;
        ecdsaThresholdKeyId: string;
        relayerKeyId: string;
        participantIds?: number[];
        derivationPath?: string;
        sessionKind?: 'jwt' | 'cookie';
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
        ed25519?: {
          sessionId: string;
          relayerKeyId: string;
          participantIds?: number[];
        };
      };
    };
    result:
      | {
          ok: true;
          remainingUses: number;
          expiresAtMs: number;
          bootstrap: ThresholdEcdsaSessionBootstrapResult;
          ed25519RestoreSeedB64u?: string;
        }
      | { ok: false; code: string; message: string };
  };
  claimEmailOtpEcdsaSigningShare: {
    payload: {
      sessionId: string;
    };
    result:
      | { ok: true; clientSigningShare32: ArrayBuffer; remainingUses: number; expiresAtMs: number }
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
  exportThresholdEcdsaHssKeyFromEmailOtpWarmSession: {
    payload: {
      relayUrl: string;
      userId: string;
      rpId: string;
      sessionId: string;
      thresholdSessionJwt?: string;
      sessionKind?: 'jwt' | 'cookie';
      ecdsaThresholdKeyId: string;
      chain: 'evm' | 'tempo';
    };
    result: {
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
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
  onEvent?: (update: NearWorkerProgressEvent) => void;
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
