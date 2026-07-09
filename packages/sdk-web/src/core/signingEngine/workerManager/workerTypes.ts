import {
  type NearWorkerProgressEvent,
  NearSignerWorkerCustomRequestType,
  type ThresholdEd25519ClientPresignCreateFromMaterialHandleRequest,
  type ThresholdEd25519ClientPresignCreateResult,
  type ThresholdEd25519ClientPresignBurnRequest,
  type ThresholdEd25519ClientPresignBurnResult,
  type ThresholdEd25519ClientPresignSignFromMaterialHandleRequest,
  type ThresholdEd25519ClientPresignSignResult,
  type ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleRequest as ThresholdEd25519WorkerMaterialRoleSeparatedNormalSigningClientShareFromMaterialHandleRequest,
  type ThresholdEd25519RoleSeparatedNormalSigningClientShareResult as ThresholdEd25519WorkerMaterialRoleSeparatedNormalSigningClientShareResult,
  type ThresholdEd25519DeleteSealedWorkerMaterialRequest,
  type ThresholdEd25519DeleteSealedWorkerMaterialResult,
  type ThresholdEd25519PrepareHssClientOutputMaskHandleRequest,
  type ThresholdEd25519PrepareHssClientOutputMaskHandleResult,
  type ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest,
  type ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest,
  type ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest,
  type ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest,
  type ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult,
  type ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult,
  type ThresholdEd25519PutSealedWorkerMaterialRequest,
  type ThresholdEd25519PutSealedWorkerMaterialResult,
  type ThresholdEd25519ReadSealedWorkerMaterialRequest,
  type ThresholdEd25519ReadSealedWorkerMaterialResult,
  type ThresholdEd25519RestoreWorkerMaterialRequest,
  type ThresholdEd25519RestoreWorkerMaterialResult,
  type ThresholdEd25519StoreWorkerMaterialFromHssOutputRequest,
  type ThresholdEd25519StoreWorkerMaterialFromHssOutputResult,
  type ThresholdEd25519ValidateWorkerMaterialRequest,
  type ThresholdEd25519ValidateWorkerMaterialResult,
  type ThresholdEd25519ComputeNep413SigningDigestRequest,
  type ThresholdEd25519ComputeSigningDigestResult,
  type ThresholdEd25519BuildDelegateSigningPayloadRequest,
  type ThresholdEd25519BuildDelegateSigningPayloadResult,
  type ThresholdEd25519FinalizeDelegateFromSignatureRequest,
  type ThresholdEd25519FinalizeNearTxFromSignatureRequest,
  type ThresholdEd25519FinalizeNearTxFromSignatureResult,
  type ThresholdEd25519BuildNearTxUnsignedBorshRequest,
  type ThresholdEd25519NearTxUnsignedBorsh,
  type ThresholdEd25519DecodeSignedNearTxBorshRequest,
  type ThresholdEd25519DecodeSignedNearTxBorshResult,
  type WorkerRequestTypeMap,
  type WorkerResponseDiagnostics,
  type WorkerResponseForRequest,
  WorkerRequestType,
  type DelegatePayload,
  type WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { MultichainWorkerKind } from '@/core/walletRuntimePaths/multichainWorkers';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpRoutePlan } from '../stepUpConfirmation/otpPrompt/authLane';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
} from '@/core/rpcClients/relayer/walletRegistration';
import type {
  EcdsaPreparePublicFacts,
  EcdsaRoleLocalPendingStateBlob,
  EcdsaRoleLocalReadyStateBlob,
  PrepareEcdsaClientBootstrapInput,
} from '@/core/platform';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type { GeneratedPrepareEcdsaClientBootstrapOutput } from '@/core/platform/signerCoreCommandAdapters';

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
  presignatureHandle?: string;
  presignatureBigR33?: ArrayBuffer;
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
  thresholdEcdsaComputeSignatureShareFromPresignatureHandle: {
    payload: {
      materialHandle: string;
      participantIds: number[];
      clientParticipantId: number;
      groupPublicKey33: ArrayBuffer;
      expectedPresignBigR33: ArrayBuffer;
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

export type EmailOtpWorkerSessionHandleOperation =
  | 'registration'
  | 'wallet_unlock'
  | 'sign'
  | 'export';

export type EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1';
  sessionId: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  authSubjectId: string;
  action: 'threshold_ecdsa_bootstrap';
  operation: EmailOtpWorkerSessionHandleOperation;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EmailOtpWalletRegistrationEcdsaPrepareHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1';
  sessionId: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  authSubjectId: string;
  action: 'wallet_registration_ecdsa_prepare';
  operation: 'registration';
  keyScope: 'evm-family';
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EmailOtpWorkerIssuedSessionHandlePayload =
  | EmailOtpEcdsaSessionBootstrapHandlePayload
  | EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;

export type EmailOtpPrepareEcdsaClientBootstrapInput = Omit<
  PrepareEcdsaClientBootstrapInput,
  'secretSource'
> & {
  secretSource: Extract<
    PrepareEcdsaClientBootstrapInput['secretSource'],
    { kind: 'email_otp_worker_session' }
  >;
};

export type EmailOtpEcdsaSessionBootstrapHandleBinding = {
  evmFamilySigningKeySlotId: string;
  authSubjectId: string;
  action?: 'threshold_ecdsa_bootstrap';
  operation: EmailOtpWorkerSessionHandleOperation;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EmailOtpWalletRegistrationEcdsaPrepareHandleBinding = {
  evmFamilySigningKeySlotId: string;
  authSubjectId: string;
  action: 'wallet_registration_ecdsa_prepare';
  operation: 'registration';
  keyScope: 'evm-family';
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EmailOtpWalletRegistrationEcdsaPrepareHandleBindings = readonly [
  EmailOtpWalletRegistrationEcdsaPrepareHandleBinding,
  ...EmailOtpWalletRegistrationEcdsaPrepareHandleBinding[],
];

export type EmailOtpWalletRegistrationEcdsaPrepareHandlePayloads = readonly [
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  ...EmailOtpWalletRegistrationEcdsaPrepareHandlePayload[],
];

export type EmailOtpWalletRegistrationEcdsaPrepareHandleRequest =
  | {
      kind: 'requested';
      bindings: EmailOtpWalletRegistrationEcdsaPrepareHandleBindings;
      handle?: never;
    }
  | {
      kind: 'not_requested';
      bindings?: never;
      handle?: never;
    };

export type EmailOtpWalletRegistrationEcdsaPrepareHandleResult =
  | {
      kind: 'available';
      handles: EmailOtpWalletRegistrationEcdsaPrepareHandlePayloads;
    }
  | {
      kind: 'not_requested';
      handles?: never;
    };

export type EmailOtpEcdsaClientRootHandleBinding =
  | EmailOtpEcdsaSessionBootstrapHandleBinding
  | EmailOtpWalletRegistrationEcdsaPrepareHandleBinding;

export type EmailOtpEcdsaPublicationTargetPlan =
  | {
      kind: 'new_key_publication_target';
      chainTarget: ThresholdEcdsaChainTarget;
      evmFamilySigningKeySlotId: string;
      keyHandle?: never;
    }
  | {
      kind: 'existing_key_publication_target';
      chainTarget: ThresholdEcdsaChainTarget;
      evmFamilySigningKeySlotId: string;
      keyHandle: string;
    };

type EmailOtpEcdsaBootstrapBasePayload = {
  relayUrl: string;
  walletId: string;
  walletSessionUserId: string;
  userId: string;
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  chainTarget: ThresholdEcdsaChainTarget;
  publicationTargetPlans: EmailOtpEcdsaPublicationTargetPlan[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionId?: string;
  signingGrantId?: string;
  ttlMs?: number;
  remainingUses?: number;
  includeEcdsaExportArtifact?: boolean;
};

type EmailOtpEcdsaBootstrapJwtPayload = {
  sessionKind: 'jwt';
  routeAuth: AppOrWalletSessionAuth;
};

export type EmailOtpEcdsaBootstrapStrictPayload = EmailOtpEcdsaBootstrapBasePayload &
  EmailOtpEcdsaBootstrapJwtPayload;

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
      userId: string;
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
      thresholdEd25519RecoveryCodeSecret32B64u: string;
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
      userId: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      clientSecret32?: ArrayBuffer;
      ecdsaClientRootHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleRequest;
    };
    result: {
      thresholdEcdsaClientVerifyingShareB64u: string;
      thresholdEd25519RecoveryCodeSecret32B64u: string;
      recoveryKeys: EmailOtpRecoveryCodeSet;
      recoveryCodesIssuedAtMs: number;
      otpChannel: WalletEmailOtpChannel;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      clientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleResult;
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
      input: EmailOtpPrepareEcdsaClientBootstrapInput;
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
      userId: string;
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
      recoveryKeyId: string;
      activeRecoveryWrappedEnrollmentEscrowCount: number;
    };
  };
  rotateEmailOtpRecoveryCodes: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId: string;
      routePlan: EmailOtpRoutePlan;
    };
    result: {
      walletId: string;
      userId: string;
      authSubjectId: string;
      enrollmentId: string;
      enrollmentVersion: string;
      enrollmentSealKeyVersion: string;
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
      userId: string;
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
      userId: string;
      challengeId?: string;
      otpCode: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
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
        thresholdEd25519RecoveryCodeSecret32B64u: string;
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
      nearEd25519SigningKeyId: string;
      userId: string;
      challengeId: string;
      otpCode: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      participantIds: number[];
      thresholdSessionId: string;
      walletSessionJwt: string;
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
        walletSessionJwt?: string;
        signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
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
        walletSessionJwt?: string;
        signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
        shamirPrimeB64u?: string;
      };
      restore: {
        sessionId: string;
        walletId: string;
        evmFamilySigningKeySlotId: string;
        chainTarget: ThresholdEcdsaChainTarget;
        signingGrantId: string;
        keyHandle: string;
        relayerKeyId: string;
        participantIds: number[];
        sessionKind: 'jwt';
        runtimePolicyScope?: ThresholdRuntimePolicyScope;
        ed25519?: {
          sessionId: string;
          runtimePolicyScope: ThresholdRuntimePolicyScope;
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
      evmFamilySigningKeySlotId: string;
      walletSessionJwt: string;
      ecdsaThresholdKeyId: string;
      relayerKeyId: string;
      readyRecord: EcdsaRoleLocalReadyRecord;
      thresholdSessionId: string;
      signingGrantId: string;
      thresholdExpiresAtMs: number;
      participantIds: number[];
      keyHandle: string;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
    };
    result: {
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    };
  };
}

export type EmailOtpWorkerOperationRequestEnvelopeFor<T extends keyof EmailOtpWorkerOperationMap> =
  {
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

export type EthSignerTransactionOperationType =
  | 'computeEip1559TxHash'
  | 'encodeEip1559SignedTxFromSignature65';
export type EthSignerLocalSecp256k1OperationType =
  | 'signSecp256k1Recoverable'
  | 'secp256k1PrivateKey32ToPublicKey33'
  | 'deriveSecp256k1KeypairFromPrfSecond'
  | 'validateSecp256k1PublicKey33'
  | 'addSecp256k1PublicKeys33'
  | 'buildWebauthnP256Signature'
  | 'decodeCoseP256PublicKey';
export type EthSignerThresholdEcdsaPresignOperationType =
  | 'mapAdditiveShareToThresholdSignaturesShare2p'
  | 'thresholdEcdsaPresignSessionInit'
  | 'thresholdEcdsaPresignSessionStep'
  | 'thresholdEcdsaPresignSessionAbort'
  | 'thresholdEcdsaComputeSignatureShareFromPresignatureHandle';
export type EthSignerDomainOperationType =
  | EthSignerTransactionOperationType
  | EthSignerLocalSecp256k1OperationType
  | EthSignerThresholdEcdsaPresignOperationType;

export type EthSignerTransactionOperationRequest<T extends EthSignerTransactionOperationType> =
  MultichainWorkerOperationRequest<'ethSigner', T>;
export type EthSignerLocalSecp256k1OperationRequest<
  T extends EthSignerLocalSecp256k1OperationType,
> = MultichainWorkerOperationRequest<'ethSigner', T>;
export type EthSignerThresholdEcdsaPresignOperationRequest<
  T extends EthSignerThresholdEcdsaPresignOperationType,
> = MultichainWorkerOperationRequest<'ethSigner', T>;

export type TempoSignerTransactionOperationType = 'computeTempoSenderHash' | 'encodeTempoSignedTx';
export type TempoSignerTransactionOperationRequest<T extends TempoSignerTransactionOperationType> =
  MultichainWorkerOperationRequest<'tempoSigner', T>;

export type EmailOtpChallengeOperationType =
  | 'requestEmailOtpChallenge'
  | 'requestEmailOtpEnrollmentChallenge'
  | 'verifyEmailOtpCode';
export type EmailOtpEnrollmentOperationType =
  | 'enrollEmailOtpWallet'
  | 'prepareEmailOtpRegistrationEnrollmentMaterial'
  | 'prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle'
  | 'prepareEcdsaClientBootstrapFromEmailOtpHandle';
export type EmailOtpRestoreOperationType =
  | 'restoreEmailOtpDeviceEnrollmentEscrow'
  | 'rotateEmailOtpRecoveryCodes'
  | 'removeEmailOtpDeviceEnrollmentEscrowFromDevice';
export type EmailOtpWarmSessionOperationType =
  | 'loginWithEmailOtpWallet'
  | 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle'
  | 'getEmailOtpWarmSessionStatus'
  | 'claimEmailOtpWarmSessionMaterial'
  | 'consumeEmailOtpWarmSessionUses'
  | 'sealEmailOtpWarmSessionMaterial'
  | 'rehydrateEmailOtpEcdsaWarmSessionMaterial'
  | 'claimEmailOtpEcdsaSigningShare'
  | 'clearEmailOtpWarmSessionMaterial';
export type EmailOtpExportOperationType =
  | 'exportEmailOtpEd25519SeedWithAuthorization'
  | 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization';
export type EmailOtpDomainOperationType =
  | EmailOtpChallengeOperationType
  | EmailOtpEnrollmentOperationType
  | EmailOtpRestoreOperationType
  | EmailOtpWarmSessionOperationType
  | EmailOtpExportOperationType;

export type EmailOtpChallengeOperationRequest<T extends EmailOtpChallengeOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;
export type EmailOtpEnrollmentOperationRequest<T extends EmailOtpEnrollmentOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;
export type EmailOtpRestoreOperationRequest<T extends EmailOtpRestoreOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;
export type EmailOtpWarmSessionOperationRequest<T extends EmailOtpWarmSessionOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;
export type EmailOtpExportOperationRequest<T extends EmailOtpExportOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;

export type WithOptionalSessionId<T> = T extends { sessionId: string }
  ? Omit<T, 'sessionId'> & { sessionId?: string }
  : T;

type NearSignerWorkerPublicWasmOperationType = keyof WorkerRequestTypeMap;

export type NearSignerWorkerWasmOperationMap = {
  [T in NearSignerWorkerPublicWasmOperationType]: {
    payload: WithOptionalSessionId<WorkerRequestTypeMap[T]['request']>;
    result: WorkerResponseForRequest<T>;
  };
};

export type NearSignerWorkerCustomOperationMap = {
  [NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareHssClientOutputMaskHandle]: {
    payload: ThresholdEd25519PrepareHssClientOutputMaskHandleRequest;
    result: ThresholdEd25519PrepareHssClientOutputMaskHandleResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519StoreWorkerMaterialFromHssOutput]: {
    payload: ThresholdEd25519StoreWorkerMaterialFromHssOutputRequest;
    result: ThresholdEd25519StoreWorkerMaterialFromHssOutputResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization]: {
    payload: ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest;
    result: ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization]: {
    payload: ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest;
    result: ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization]: {
    payload: ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest;
    result: ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization]: {
    payload: ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest;
    result: ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519RestoreWorkerMaterial]: {
    payload: ThresholdEd25519RestoreWorkerMaterialRequest;
    result: ThresholdEd25519RestoreWorkerMaterialResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ValidateWorkerMaterial]: {
    payload: ThresholdEd25519ValidateWorkerMaterialRequest;
    result: ThresholdEd25519ValidateWorkerMaterialResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519PutSealedWorkerMaterial]: {
    payload: ThresholdEd25519PutSealedWorkerMaterialRequest;
    result: ThresholdEd25519PutSealedWorkerMaterialResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ReadSealedWorkerMaterial]: {
    payload: ThresholdEd25519ReadSealedWorkerMaterialRequest;
    result: ThresholdEd25519ReadSealedWorkerMaterialResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519DeleteSealedWorkerMaterial]: {
    payload: ThresholdEd25519DeleteSealedWorkerMaterialRequest;
    result: ThresholdEd25519DeleteSealedWorkerMaterialResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreateFromMaterialHandle]: {
    payload: ThresholdEd25519ClientPresignCreateFromMaterialHandleRequest;
    result: ThresholdEd25519ClientPresignCreateResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSignFromMaterialHandle]: {
    payload: ThresholdEd25519ClientPresignSignFromMaterialHandleRequest;
    result: ThresholdEd25519ClientPresignSignResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle]: {
    payload: ThresholdEd25519WorkerMaterialRoleSeparatedNormalSigningClientShareFromMaterialHandleRequest;
    result: ThresholdEd25519WorkerMaterialRoleSeparatedNormalSigningClientShareResult;
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
  [NearSignerWorkerCustomRequestType.ThresholdEd25519BuildDelegateSigningPayload]: {
    payload: ThresholdEd25519BuildDelegateSigningPayloadRequest;
    result: ThresholdEd25519BuildDelegateSigningPayloadResult;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature]: {
    payload: ThresholdEd25519FinalizeDelegateFromSignatureRequest;
    result: WasmSignedDelegate;
  };
  [NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeNearTxFromSignature]: {
    payload: ThresholdEd25519FinalizeNearTxFromSignatureRequest;
    result: ThresholdEd25519FinalizeNearTxFromSignatureResult;
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

export type NearSignerWorkerOperationMap = NearSignerWorkerWasmOperationMap &
  NearSignerWorkerCustomOperationMap;

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

export type NearEd25519MaterialOperationType =
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519StoreWorkerMaterialFromHssOutput
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519RestoreWorkerMaterial
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519PutSealedWorkerMaterial
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ReadSealedWorkerMaterial
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519DeleteSealedWorkerMaterial
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ValidateWorkerMaterial;
export type NearEd25519PresignOperationType =
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreateFromMaterialHandle
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSignFromMaterialHandle
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn;
export type NearEd25519DigestOperationType =
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeDelegateSigningDigest
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519BuildDelegateSigningPayload;
export type NearEd25519FinalizeOperationType =
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeNearTxFromSignature
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh;

export type NearEd25519MaterialOperationRequest<T extends NearEd25519MaterialOperationType> =
  NearWorkerOperationRequest<T>;
export type NearEd25519PresignOperationRequest<T extends NearEd25519PresignOperationType> =
  NearWorkerOperationRequest<T>;
export type NearEd25519DigestOperationRequest<T extends NearEd25519DigestOperationType> =
  NearWorkerOperationRequest<T>;
export type NearEd25519FinalizeOperationRequest<T extends NearEd25519FinalizeOperationType> =
  NearWorkerOperationRequest<T>;

export const HssClientCustomRequestType = {
  PrepareThresholdEd25519HssClientOutputMaskHandle: 70_002,
  BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle: 70_003,
  StoreThresholdEcdsaRoleLocalSigningMaterial: 70_004,
  OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandle: 70_005,
  ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle: 70_008,
  ThresholdEcdsaRoleLocalPresignSessionStep: 70_009,
  ThresholdEcdsaRoleLocalPresignSessionAbort: 70_010,
  ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle: 70_011,
  PrepareThresholdEd25519HssAddStageRequestMessage: 70_012,
} as const;

export type HssClientCustomRequestType =
  (typeof HssClientCustomRequestType)[keyof typeof HssClientCustomRequestType];

export const HssClientCustomResponseType = {
  PrepareThresholdEd25519HssClientOutputMaskHandleSuccess: 70_102,
  BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleSuccess: 70_103,
  StoreThresholdEcdsaRoleLocalSigningMaterialSuccess: 70_104,
  OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleSuccess: 70_105,
  ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleSuccess: 70_108,
  ThresholdEcdsaRoleLocalPresignSessionStepSuccess: 70_109,
  ThresholdEcdsaRoleLocalPresignSessionAbortSuccess: 70_110,
  ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleSuccess: 70_111,
  PrepareThresholdEd25519HssAddStageRequestMessageSuccess: 70_112,
} as const;

export type HssClientCustomResponseType =
  (typeof HssClientCustomResponseType)[keyof typeof HssClientCustomResponseType];

export type PrepareThresholdEd25519HssClientOutputMaskHandleRequest = {
  applicationBindingDigestB64u: string;
  participantIds: number[];
  contextBindingB64u: string;
  operation: string;
  relayerKeyId: string;
  clientRecoverableSecretB64u: string;
  expiresAtMs: number;
};

export type PrepareThresholdEd25519HssClientOutputMaskHandleResult = {
  clientOutputMaskHandle: string;
  contextBindingB64u: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type PrepareThresholdEd25519HssClientOutputMaskHandleResponse = {
  type: typeof HssClientCustomResponseType.PrepareThresholdEd25519HssClientOutputMaskHandleSuccess;
  payload: PrepareThresholdEd25519HssClientOutputMaskHandleResult;
  diagnostics?: WorkerResponseDiagnostics;
};

type BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSessionSource =
  | {
      sessionSource: 'worker_handle';
      workerSessionHandle: string;
      evaluatorDriverStateB64u?: never;
    }
  | {
      sessionSource: 'serialized_state';
      evaluatorDriverStateB64u: string;
      workerSessionHandle?: never;
    };

export type ThresholdEd25519HssAddStageBinding =
  | {
      kind: 'prepared_request';
      expectedAddStageRequestMessageB64u: string;
    }
  | {
      kind: 'generated_request';
      expectedAddStageRequestMessageB64u?: never;
    };

export type BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleRequest =
  BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSessionSource & {
    clientRequestMessageB64u: string;
    evaluatorOtStateB64u: string;
    serverInputDeliveryB64u: string;
    clientOutputMaskHandle: string;
    expectedContextBindingB64u: string;
    addStageBinding: ThresholdEd25519HssAddStageBinding;
  };

export type PrepareThresholdEd25519HssAddStageRequestMessageRequest =
  BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSessionSource & {
    clientRequestMessageB64u: string;
    evaluatorOtStateB64u: string;
    serverInputDeliveryB64u: string;
    expectedContextBindingB64u: string;
  };

export type PrepareThresholdEd25519HssAddStageRequestMessageResponse = {
  type: typeof HssClientCustomResponseType.PrepareThresholdEd25519HssAddStageRequestMessageSuccess;
  payload: {
    contextBindingB64u: string;
    addStageRequestMessageB64u: string;
    timings?: Record<string, number>;
  };
  diagnostics?: WorkerResponseDiagnostics;
};

export type BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleResponse = {
  type: typeof HssClientCustomResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleSuccess;
  payload: {
    contextBindingB64u: string;
    stagedEvaluatorArtifactB64u: string;
    addStageRequestMessageB64u: string;
    timings?: Record<string, number>;
  };
  diagnostics?: WorkerResponseDiagnostics;
};

export type StoreThresholdEcdsaRoleLocalSigningMaterialRequest = {
  materialHandle: string;
  bindingDigest: string;
  stateBlob: EcdsaRoleLocalReadyStateBlob;
};

export type StoreThresholdEcdsaRoleLocalSigningMaterialResult = {
  materialHandle: string;
  bindingDigest: string;
};

export type StoreThresholdEcdsaRoleLocalSigningMaterialResponse = {
  type: typeof HssClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess;
  payload: StoreThresholdEcdsaRoleLocalSigningMaterialResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleRequest = {
  materialHandle: string;
  expectedBindingDigest: string;
};

export type OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleResult = {
  signingShare32B64u: string;
};

export type OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleResponse = {
  type: typeof HssClientCustomResponseType.OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleSuccess;
  payload: OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleRequest = {
  materialHandle: string;
  expectedBindingDigest: string;
  sessionId: string;
  participantIds: number[];
  clientParticipantId: number;
  threshold: number;
  groupPublicKey33: ArrayBuffer;
};

export type ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleResponse = {
  type: typeof HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleSuccess;
  payload: ThresholdEcdsaPresignProgressResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type ThresholdEcdsaRoleLocalPresignSessionStepRequest = {
  sessionId: string;
  relayerParticipantId: number;
  stage: 'triples' | 'presign';
  incomingMessages: ArrayBuffer[];
};

export type ThresholdEcdsaRoleLocalPresignSessionStepResponse = {
  type: typeof HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionStepSuccess;
  payload: ThresholdEcdsaPresignProgressResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type ThresholdEcdsaRoleLocalPresignSessionAbortRequest = {
  sessionId: string;
};

export type ThresholdEcdsaRoleLocalPresignSessionAbortResponse = {
  type: typeof HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionAbortSuccess;
  payload: ThresholdEcdsaPresignAbortResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleRequest = {
  materialHandle: string;
  participantIds: number[];
  clientParticipantId: number;
  groupPublicKey33: ArrayBuffer;
  expectedPresignBigR33: ArrayBuffer;
  digest32: ArrayBuffer;
  entropy32: ArrayBuffer;
};

export type ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleResponse = {
  type: typeof HssClientCustomResponseType.ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleSuccess;
  payload: ArrayBuffer;
  diagnostics?: WorkerResponseDiagnostics;
};

type HssClientCustomOperationMap = {
  [HssClientCustomRequestType.PrepareThresholdEd25519HssClientOutputMaskHandle]: {
    payload: PrepareThresholdEd25519HssClientOutputMaskHandleRequest;
    result: PrepareThresholdEd25519HssClientOutputMaskHandleResponse;
  };
  [HssClientCustomRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle]: {
    payload: BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleRequest;
    result: BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleResponse;
  };
  [HssClientCustomRequestType.PrepareThresholdEd25519HssAddStageRequestMessage]: {
    payload: PrepareThresholdEd25519HssAddStageRequestMessageRequest;
    result: PrepareThresholdEd25519HssAddStageRequestMessageResponse;
  };
  [HssClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial]: {
    payload: StoreThresholdEcdsaRoleLocalSigningMaterialRequest;
    result: StoreThresholdEcdsaRoleLocalSigningMaterialResponse;
  };
  [HssClientCustomRequestType.OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandle]: {
    payload: OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleRequest;
    result: OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleResponse;
  };
  [HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle]: {
    payload: ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleRequest;
    result: ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleResponse;
  };
  [HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionStep]: {
    payload: ThresholdEcdsaRoleLocalPresignSessionStepRequest;
    result: ThresholdEcdsaRoleLocalPresignSessionStepResponse;
  };
  [HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionAbort]: {
    payload: ThresholdEcdsaRoleLocalPresignSessionAbortRequest;
    result: ThresholdEcdsaRoleLocalPresignSessionAbortResponse;
  };
  [HssClientCustomRequestType.ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle]: {
    payload: ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleRequest;
    result: ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleResponse;
  };
};

export type HssWorkerOperationType =
  | typeof WorkerRequestType.DeriveThresholdEd25519HssClientInputs
  | typeof WorkerRequestType.PrepareThresholdEd25519HssSession
  | typeof WorkerRequestType.PrepareThresholdEd25519HssClientRequest
  | typeof WorkerRequestType.OpenThresholdEd25519HssSeedOutput
  | typeof WorkerRequestType.BuildThresholdEd25519SeedExportArtifact
  | typeof WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap
  | typeof WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap
  | typeof WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact
  | keyof HssClientCustomOperationMap;

type HssWorkerOperationEntry<T extends HssWorkerOperationType> =
  T extends keyof WorkerRequestTypeMap
    ? WorkerRequestTypeMap[T] extends {
        request: infer P;
        result: infer R;
      }
      ? { payload: P; result: WorkerResponseForRequest<T> }
      : never
    : T extends keyof HssClientCustomOperationMap
      ? HssClientCustomOperationMap[T]
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

export type HssEd25519ProtocolOperationType =
  | typeof WorkerRequestType.DeriveThresholdEd25519HssClientInputs
  | typeof WorkerRequestType.PrepareThresholdEd25519HssSession
  | typeof WorkerRequestType.PrepareThresholdEd25519HssClientRequest
  | typeof WorkerRequestType.OpenThresholdEd25519HssSeedOutput
  | typeof WorkerRequestType.BuildThresholdEd25519SeedExportArtifact
  | typeof HssClientCustomRequestType.PrepareThresholdEd25519HssClientOutputMaskHandle
  | typeof HssClientCustomRequestType.PrepareThresholdEd25519HssAddStageRequestMessage
  | typeof HssClientCustomRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle;
export type HssEcdsaRoleLocalMaterialOperationType =
  | typeof WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap
  | typeof WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap
  | typeof WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact
  | typeof HssClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial
  | typeof HssClientCustomRequestType.OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandle;
export type HssEcdsaRoleLocalPresignOperationType =
  | typeof HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle
  | typeof HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionStep
  | typeof HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionAbort
  | typeof HssClientCustomRequestType.ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle;

export type HssEd25519ProtocolOperationRequest<T extends HssEd25519ProtocolOperationType> =
  HssWorkerOperationRequest<T>;
export type HssEcdsaRoleLocalMaterialOperationRequest<
  T extends HssEcdsaRoleLocalMaterialOperationType,
> = HssWorkerOperationRequest<T>;
export type HssEcdsaRoleLocalPresignOperationRequest<
  T extends HssEcdsaRoleLocalPresignOperationType,
> = HssWorkerOperationRequest<T>;

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
