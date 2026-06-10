import {
  type NearWorkerProgressEvent,
  NearSignerWorkerCustomRequestType,
  type ThresholdEd25519ClientPresignCreateRequest,
  type ThresholdEd25519ClientPresignCreateResult,
  type ThresholdEd25519ClientPresignBurnRequest,
  type ThresholdEd25519ClientPresignBurnResult,
  type ThresholdEd25519ClientPresignSignRequest,
  type ThresholdEd25519ClientPresignSignResult,
  type ThresholdEd25519ComputeNep413SigningDigestRequest,
  type ThresholdEd25519ComputeSigningDigestResult,
  type ThresholdEd25519FinalizeDelegateFromSignatureRequest,
  type ThresholdEd25519BuildNearTxUnsignedBorshRequest,
  type ThresholdEd25519NearTxUnsignedBorsh,
  type ThresholdEd25519DecodeSignedNearTxBorshRequest,
  type ThresholdEd25519DecodeSignedNearTxBorshResult,
  type WorkerRequestTypeMap,
  type WorkerResponseForRequest,
  WorkerRequestType,
  type DelegatePayload,
  type WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { MultichainWorkerKind } from '@/core/walletRuntimePaths/multichainWorkers';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpRoutePlan } from '../stepUpConfirmation/otpPrompt/authLane';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { EcdsaPreparePublicFacts, EcdsaRoleLocalPendingStateBlob } from '@/core/platform';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type {
  GeneratedPrepareEcdsaClientBootstrapCommand,
  GeneratedPrepareEcdsaClientBootstrapOutput,
} from '@/core/platform/signerCoreCommandAdapters';
import type {
  ClearThresholdEd25519PresignPoolWorkerContract,
  GetThresholdEd25519PresignPoolStatusWorkerContract,
  PrepareThresholdEd25519PresignPoolWorkerContract,
} from '../threshold/ed25519/presignPool';

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

export type ThresholdEcdsaPresignAbortResult = {
  kind: 'threshold_ecdsa_presign_session_aborted';
  sessionId: string;
};

export type RpcSignerWorkerProgressEvent = {
  phase: string;
  status: 'running' | 'succeeded' | 'failed';
  message: string;
  data?: Record<string, unknown>;
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
    payload: { prfSecond: ArrayBuffer; walletSessionUserId: string };
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
  decodeCoseP256PublicKey: {
    payload: { cosePublicKey: ArrayBuffer };
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
      incomingMessages: ArrayBuffer[];
    };
    result: ThresholdEcdsaPresignProgressResult;
  };
  thresholdEcdsaPresignSessionAbort: {
    payload: { sessionId: string };
    result: ThresholdEcdsaPresignAbortResult;
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

export type EmailOtpWorkerProgressCode =
  | 'otp.verify.succeeded'
  | 'signer.email_otp.enroll.started'
  | 'signer.email_otp.enroll.succeeded'
  | 'signer.ecdsa.bootstrap.started'
  | 'signer.ecdsa.bootstrap.prepared'
  | 'signer.ecdsa.bootstrap.responded'
  | 'signer.ecdsa.bootstrap.succeeded';

export type EmailOtpWorkerProgressEvent = {
  code: EmailOtpWorkerProgressCode;
};

export type EmailOtpEcdsaBootstrapRoleLocalKeyIdentity = {
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
};

export type EmailOtpWorkerSessionHandleOperation =
  | 'registration'
  | 'wallet_unlock'
  | 'sign'
  | 'export';

export type EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1';
  sessionId: string;
  walletId: string;
  rpId: string;
  authSubjectId: string;
  action: 'threshold_ecdsa_bootstrap';
  operation: EmailOtpWorkerSessionHandleOperation;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EmailOtpWalletRegistrationEcdsaPrepareHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1';
  sessionId: string;
  walletId: string;
  rpId: string;
  authSubjectId: string;
  action: 'wallet_registration_ecdsa_prepare';
  operation: 'registration';
  keyScope: 'evm-family';
  chainTarget?: never;
};

export type EmailOtpWorkerIssuedSessionHandlePayload =
  | EmailOtpEcdsaSessionBootstrapHandlePayload
  | EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;

export type EmailOtpEcdsaSessionBootstrapHandleBinding = {
  rpId: string;
  authSubjectId: string;
  action?: 'threshold_ecdsa_bootstrap';
  operation: EmailOtpWorkerSessionHandleOperation;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EmailOtpWalletRegistrationEcdsaPrepareHandleBinding = {
  rpId: string;
  authSubjectId: string;
  action: 'wallet_registration_ecdsa_prepare';
  operation: 'registration';
  keyScope: 'evm-family';
  chainTarget?: never;
};

export type EmailOtpEcdsaClientRootHandleBinding =
  | EmailOtpEcdsaSessionBootstrapHandleBinding
  | EmailOtpWalletRegistrationEcdsaPrepareHandleBinding;

type EmailOtpEcdsaBootstrapBasePayload = {
  relayUrl: string;
  walletId: string;
  walletSessionUserId: string;
  userId: string;
  rpId: string;
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  chainTarget: ThresholdEcdsaChainTarget;
  publicationChainTargets: ThresholdEcdsaChainTarget[];
  roleLocalKeyIdentity: EmailOtpEcdsaBootstrapRoleLocalKeyIdentity;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionId?: string;
  walletSigningSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  includeEcdsaExportArtifact?: boolean;
};

type EmailOtpEcdsaBootstrapJwtPayload = {
  sessionKind: 'jwt';
  routeAuth: AppOrThresholdSessionAuth;
};

type EmailOtpEcdsaBootstrapCookiePayload = {
  sessionKind: 'cookie';
  routeAuth?: never;
};

type EmailOtpEcdsaBootstrapNewKeyPayload = {
  keyHandle?: never;
};

type EmailOtpEcdsaBootstrapExistingKeyPayload = {
  keyHandle: string;
};

export type EmailOtpEcdsaBootstrapStrictPayload = EmailOtpEcdsaBootstrapBasePayload &
  (EmailOtpEcdsaBootstrapJwtPayload | EmailOtpEcdsaBootstrapCookiePayload) &
  (EmailOtpEcdsaBootstrapNewKeyPayload | EmailOtpEcdsaBootstrapExistingKeyPayload);

export interface EmailOtpWorkerOperationMap {
  requestEmailOtpChallenge: {
    payload: {
      relayUrl: string;
      walletId: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
    };
    result: {
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      emailHint?: string;
      expiresAtMs?: number;
      appSessionVersion?: string;
    };
  };
  requestEmailOtpEnrollmentChallenge: {
    payload: {
      relayUrl: string;
      walletId: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
    };
    result: {
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      emailHint?: string;
      expiresAtMs?: number;
      appSessionVersion?: string;
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
      routePlan: EmailOtpRoutePlan;
      googleEmailOtpRegistrationAttemptId?: string;
      otpChannel?: WalletEmailOtpChannel;
      clientSecret32?: ArrayBuffer;
      ecdsaClientRootHandleBinding?: EmailOtpEcdsaSessionBootstrapHandleBinding;
    };
    result: {
      thresholdEcdsaClientVerifyingShareB64u: string;
      thresholdEd25519PrfFirstB64u: string;
      recoveryKeys: EmailOtpRecoveryCodeSet;
      recoveryCodesIssuedAtMs: number;
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      clientRootShareHandle?: EmailOtpEcdsaSessionBootstrapHandlePayload;
    };
  };
  prepareEmailOtpRegistrationEnrollmentMaterial: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId?: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      clientSecret32?: ArrayBuffer;
      ecdsaClientRootHandleBinding: EmailOtpWalletRegistrationEcdsaPrepareHandleBinding;
    };
    result: {
      thresholdEcdsaClientVerifyingShareB64u: string;
      thresholdEd25519PrfFirstB64u: string;
      recoveryKeys: EmailOtpRecoveryCodeSet;
      recoveryCodesIssuedAtMs: number;
      otpChannel: WalletEmailOtpChannel;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      clientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows: unknown[];
        enrollmentSealKeyVersion: string;
        clientUnlockPublicKeyB64u: string;
        unlockKeyVersion: string;
        thresholdEcdsaClientVerifyingShareB64u: string;
      };
    };
  };
  prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle: {
    payload: {
      prepare: WalletRegistrationEcdsaPrepareContext;
      clientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
      chainTarget: ThresholdEcdsaChainTarget;
    };
    result: {
      clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
      pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
      preparePublicFacts: EcdsaPreparePublicFacts;
    };
  };
  prepareEcdsaClientBootstrapFromEmailOtpHandle: {
    payload: {
      command: GeneratedPrepareEcdsaClientBootstrapCommand;
    };
    result: GeneratedPrepareEcdsaClientBootstrapOutput;
  };
  verifyEmailOtpCode: {
    payload: {
      relayUrl: string;
      walletId: string;
      challengeId: string;
      otpCode: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
    };
    result: {
      loginGrant: string;
      otpChannel: WalletEmailOtpChannel;
      enrollmentSealKeyVersion?: string;
    };
  };
  restoreEmailOtpDeviceEnrollmentEscrow: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId?: string;
      challengeId: string;
      otpCode: string;
      recoveryKey: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
    };
    result: {
      walletId: string;
      userId: string;
      authSubjectId: string;
      enrollmentId: string;
      enrollmentVersion: string;
      enrollmentSealKeyVersion: string;
      signingRootId: string;
      signingRootVersion: string;
      recoveryKeyId: string;
      activeRecoveryWrappedEnrollmentEscrowCount: number;
    };
  };
  rotateEmailOtpRecoveryCodes: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId?: string;
      routePlan: EmailOtpRoutePlan;
    };
    result: {
      walletId: string;
      userId: string;
      authSubjectId: string;
      enrollmentId: string;
      enrollmentVersion: string;
      enrollmentSealKeyVersion: string;
      signingRootId: string;
      signingRootVersion: string;
      recoveryKeys: EmailOtpRecoveryCodeSet;
      recoveryCodesIssuedAtMs: number;
      activeRecoveryCodeCount: number;
      revokedRecoveryCodeCount: number;
      totalRecoveryCodeCount: number;
    };
  };
  removeEmailOtpDeviceEnrollmentEscrowFromDevice: {
    payload: {
      walletId: string;
      userId?: string;
      enrollmentId?: string;
    };
    result: {
      walletId: string;
      authSubjectId: string;
      enrollmentId: string;
      removed: true;
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
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      ecdsaClientRootHandleBinding?: EmailOtpEcdsaSessionBootstrapHandleBinding;
    };
    result: {
      recovery: {
        challengeId: string;
        enrollmentSealKeyVersion: string;
        unlockChallengeId: string;
        unlockChallengeB64u: string;
        clientUnlockPublicKeyB64u: string;
        unlockSignatureB64u: string;
        thresholdEd25519PrfFirstB64u: string;
      };
      clientRootShareHandle?: EmailOtpEcdsaSessionBootstrapHandlePayload;
    };
  };
  bootstrapEmailOtpEcdsaSessionsFromWorkerHandle: {
    payload: EmailOtpEcdsaBootstrapStrictPayload;
    result: {
      bootstraps: ThresholdEcdsaSessionBootstrapResult[];
      ecdsaHssExportArtifact?: {
        artifactKind: 'ecdsa-hss-secp256k1-export';
        chainTarget: ThresholdEcdsaChainTarget;
        signingRootId: string;
        signingRootVersion?: string;
        publicKeyHex: string;
        privateKeyHex: string;
        ethereumAddress: string;
      };
    };
  };
  exportEmailOtpEd25519SeedWithAuthorization: {
    payload: {
      relayUrl: string;
      walletId: string;
      nearAccountId: string;
      userId?: string;
      challengeId: string;
      otpCode: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      signingRootId: string;
      keyVersion: string;
      participantIds: number[];
      thresholdSessionId: string;
      thresholdSessionAuthToken: string;
      relayerKeyId: string;
      expectedPublicKey: string;
    };
    result: {
      publicKey: string;
      privateKey: string;
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
      consume?: boolean;
    };
    result:
      | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
  };
  consumeEmailOtpWarmSessionUses: {
    payload: {
      sessionId: string;
      uses?: number;
    };
    result:
      | { ok: true; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
  };
  sealEmailOtpWarmSessionMaterial: {
    payload: {
      sessionId: string;
      transport: {
        relayerUrl: string;
        thresholdSessionAuthToken?: string;
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
        thresholdSessionAuthToken?: string;
        keyVersion?: string;
        shamirPrimeB64u?: string;
      };
      restore: {
        sessionId: string;
        walletId: string;
        rpId: string;
        chainTarget: ThresholdEcdsaChainTarget;
        walletSigningSessionId: string;
        keyHandle: string;
        relayerKeyId: string;
        participantIds: number[];
        sessionKind?: 'jwt' | 'cookie';
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
        ed25519?: {
          sessionId: string;
          signingRootId: string;
          signingRootVersion?: string;
          relayerKeyId: string;
          participantIds: number[];
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
  exportThresholdEcdsaHssKeyWithEmailOtpAuthorization: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId: string;
      challengeId: string;
      otpCode: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      rpId: string;
      thresholdSessionAuthToken?: string;
      sessionKind?: 'jwt' | 'cookie';
      ecdsaThresholdKeyId: string;
      signingRootId: string;
      signingRootVersion?: string;
      relayerKeyId: string;
      readyRecord: EcdsaRoleLocalReadyRecord;
      thresholdSessionId: string;
      walletSigningSessionId: string;
      thresholdExpiresAtMs: number;
      participantIds: number[];
      keyHandle: string;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
    };
    result: {
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    };
  };
}

type EmailOtpWorkerOperationRequestEnvelopeFor<T extends keyof EmailOtpWorkerOperationMap> = {
  id: string;
  type: T;
  payload: EmailOtpWorkerOperationMap[T]['payload'];
};

export type EmailOtpWorkerOperationRequestEnvelope = {
  [T in keyof EmailOtpWorkerOperationMap]: EmailOtpWorkerOperationRequestEnvelopeFor<T>;
}[keyof EmailOtpWorkerOperationMap];

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
  onEvent?: (update: RpcSignerWorkerProgressEvent) => void;
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

export type NearSignerWorkerWasmOperationMap = {
  [T in keyof WorkerRequestTypeMap]: {
    payload: WithOptionalSessionId<WorkerRequestTypeMap[T]['request']>;
    result: WorkerResponseForRequest<T>;
  };
};

export type NearSignerWorkerCustomOperationMap = {
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate]: {
    payload: ThresholdEd25519ClientPresignCreateRequest;
    result: ThresholdEd25519ClientPresignCreateResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign]: {
    payload: ThresholdEd25519ClientPresignSignRequest;
    result: ThresholdEd25519ClientPresignSignResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn]: {
    payload: ThresholdEd25519ClientPresignBurnRequest;
    result: ThresholdEd25519ClientPresignBurnResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest]: {
    payload: ThresholdEd25519ComputeNep413SigningDigestRequest;
    result: ThresholdEd25519ComputeSigningDigestResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeDelegateSigningDigest]: {
    payload: { delegate: DelegatePayload };
    result: ThresholdEd25519ComputeSigningDigestResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature]: {
    payload: ThresholdEd25519FinalizeDelegateFromSignatureRequest;
    result: WasmSignedDelegate;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh]: {
    payload: ThresholdEd25519BuildNearTxUnsignedBorshRequest;
    result: readonly ThresholdEd25519NearTxUnsignedBorsh[];
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh]: {
    payload: ThresholdEd25519DecodeSignedNearTxBorshRequest;
    result: ThresholdEd25519DecodeSignedNearTxBorshResult;
  };
};

export type NearSignerWorkerOperationMap =
  NearSignerWorkerWasmOperationMap & NearSignerWorkerCustomOperationMap;

export type NearSignerWorkerPresignPoolOperationMap = {
  prepareThresholdEd25519PresignPool: PrepareThresholdEd25519PresignPoolWorkerContract;
  getThresholdEd25519PresignPoolStatus: GetThresholdEd25519PresignPoolStatusWorkerContract;
  clearThresholdEd25519PresignPool: ClearThresholdEd25519PresignPoolWorkerContract;
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
  | typeof WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask
  | typeof WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
  | typeof WorkerRequestType.OpenThresholdEd25519HssClientOutput
  | typeof WorkerRequestType.OpenThresholdEd25519HssSeedOutput
  | typeof WorkerRequestType.BuildThresholdEd25519SeedExportArtifact
  | typeof WorkerRequestType.OpenThresholdEcdsaHssRoleLocalSigningShare
  | typeof WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap
  | typeof WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap
  | typeof WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact;

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

export type SignerWorkerProgressEvent<K extends SignerWorkerKind> = K extends 'nearSigner'
  ? NearWorkerProgressEvent
  : K extends 'ethSigner' | 'tempoSigner'
    ? RpcSignerWorkerProgressEvent
    : K extends 'emailOtp'
      ? EmailOtpWorkerProgressEvent
      : never;

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
    : K extends 'emailOtp' | 'ethSigner' | 'tempoSigner'
      ? {
          type: T;
          payload: SignerWorkerOperationEntry<K, T>['payload'];
          onEvent?: (update: SignerWorkerProgressEvent<K>) => void;
          timeoutMs?: number;
          transfer?: Transferable[];
        }
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

export function getSignerWorkerOperationCoreCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const code = (error as { coreCode?: unknown }).coreCode;
  if (typeof code !== 'string') return undefined;
  const trimmed = code.trim();
  return trimmed.length ? trimmed : undefined;
}
