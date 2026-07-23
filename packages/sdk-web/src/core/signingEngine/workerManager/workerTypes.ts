import {
  type NearWorkerProgressEvent,
  NearSignerWorkerCustomRequestType,
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
  type DelegatePayload,
  type WasmSignedDelegate,
  type WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapRequest,
  type WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
  type WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapRequest,
  type WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult,
  type WasmBuildThresholdEcdsaDerivationRoleLocalExportArtifactRequest,
  type WasmBuildThresholdEcdsaDerivationRoleLocalExportArtifactResult,
} from '@/core/types/signer-worker';
import type { MultichainWorkerKind } from '@/core/walletRuntimePaths/multichainWorkers';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import type { EcdsaClientPresignPoolIdentity } from './ecdsaPresignPoolIdentity';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import type { EmailOtpChallengeDelivery } from '../session/emailOtp/publicTypes';
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
  EmailOtpWorkerSessionSecretSource,
  PrepareEcdsaClientBootstrapInput,
} from '@/core/platform';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type { GeneratedPrepareEcdsaClientBootstrapOutput } from '@/core/platform/signerCoreCommandAdapters';
import type {
  CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaPostRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaPostRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaExplicitExportRequestV1,
  FinalizeRouterAbEcdsaExplicitExportResultV1,
  RehydrateEcdsaRoleLocalSigningMaterialRequestV1,
  RehydrateEcdsaRoleLocalSigningMaterialResultV1,
  VerifyRouterAbEcdsaRefreshClientProofsRequestV1,
  VerifyRouterAbEcdsaRefreshClientProofsResultV1,
} from '@/core/signingEngine/workerManager/ecdsaClientWorkerChannels';
import type {
  CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  VerifyRouterAbEcdsaRegistrationClientProofsResultV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import type {
  EmailOtpEd25519YaoPendingFactorHandle,
  EmailOtpEd25519YaoRootHandle,
  EmailOtpEd25519YaoRootScope,
} from '../session/emailOtp/ed25519YaoRootVault';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '../threshold/ed25519/yaoClient';
import {
  ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoBytes32V1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { NearResolvedEd25519SigningSessionState } from '../interfaces/near';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '@/core/rpcClients/relayer/walletRegistration';

export type EmailOtpEd25519YaoFactorRequest =
  | { kind: 'requested'; providerSubject: string }
  | { kind: 'not_requested'; providerSubject?: never };

export type EmailOtpEd25519YaoFactorResult =
  | {
      kind: 'issued';
      pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
    }
  | {
      kind: 'not_requested';
      pendingFactorHandle?: never;
    };

export type EmailOtpMixedWalletSigningBudgetV1 = {
  readonly kind: 'email_otp_mixed_wallet_signing_budget_v1';
  readonly signingGrantId: string;
  readonly ttlMs: number;
  readonly remainingUses: number;
};

export type EmailOtpEd25519YaoRecoveryAugmentationV1 = {
  readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1;
  readonly signerSlot: number;
  readonly remainingUses: number;
  readonly orgId: string;
};

export type EmailOtpEd25519YaoExactLocalSessionRequestV1 = {
  readonly kind: 'exact_local_material_session_v1';
  readonly signerSlot: number;
  readonly remainingUses: number;
  readonly orgId: string;
};

export type EmailOtpEd25519YaoActiveCapabilityDescriptorV1 = {
  readonly kind: 'router_ab_ed25519_yao_active_capability_v1';
  readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
  readonly registeredPublicKey: RouterAbEd25519YaoBytes32V1;
  readonly nearAccountId: string;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
  readonly participantIds: readonly [number, number];
  readonly lifecycle: {
    readonly lifecycleId: string;
    readonly rootShareEpoch: string;
    readonly accountId: string;
    readonly walletSessionId: string;
    readonly signerSetId: string;
    readonly signingWorkerId: string;
  };
  readonly stateEpoch: number;
};

export type EmailOtpEd25519YaoRecoveryBootstrapV1 = {
  readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1;
  readonly session: WalletRegistrationEd25519YaoBootstrapSession;
  readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
};

export type EmailOtpEd25519YaoExactLocalSessionBootstrapV1 = {
  readonly kind: 'exact_local_material_session_v1';
  readonly session: WalletRegistrationEd25519YaoBootstrapSession;
  readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
};

export type EmailOtpWalletUnlockMaterialRequest =
  | {
      readonly kind: 'ecdsa';
      readonly ecdsaClientRootHandleBinding: EmailOtpEcdsaSessionBootstrapHandleBinding;
      readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
      readonly walletSessionAuth?: never;
      readonly ed25519YaoRecovery?: never;
      readonly ed25519YaoSession?: never;
      readonly providerSubject?: never;
    }
  | {
      readonly kind: 'ed25519_yao_exact_local_session';
      readonly ed25519YaoSession: EmailOtpEd25519YaoExactLocalSessionRequestV1;
      readonly providerSubject: string;
      readonly nearAccountId: string;
      readonly expectedOperationalPublicKey: string;
      readonly expectedThresholdSessionId: string;
      readonly walletSessionAuth?: never;
      readonly ecdsaClientRootHandleBinding?: never;
      readonly runtimePolicyScope?: never;
      readonly ed25519YaoRecovery?: never;
    }
  | {
      readonly kind: 'ed25519_yao_recovery';
      readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryAugmentationV1;
      readonly providerSubject: string;
      readonly nearAccountId: string;
      readonly expectedOperationalPublicKey: string;
      readonly expectedThresholdSessionId: string;
      readonly walletSessionAuth?: never;
      readonly ecdsaClientRootHandleBinding?: never;
      readonly runtimePolicyScope?: never;
      readonly ed25519YaoSession?: never;
    }
  | {
      readonly kind: 'ecdsa_and_ed25519_yao_recovery';
      readonly ecdsaClientRootHandleBinding: EmailOtpEcdsaSessionBootstrapHandleBinding;
      readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
      readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryAugmentationV1;
      readonly providerSubject: string;
      readonly nearAccountId: string;
      readonly expectedOperationalPublicKey: string;
      readonly expectedThresholdSessionId: string;
      readonly walletSessionAuth?: never;
      readonly ed25519YaoSession?: never;
    };

export type EmailOtpWalletUnlockMaterialResult =
  | {
      readonly kind: 'ecdsa';
      readonly clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      readonly pendingFactorHandle?: never;
      readonly ed25519YaoRecovery?: never;
    }
  | {
      readonly kind: 'ed25519_yao_recovery';
      readonly pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
      readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
      readonly clientRootShareHandle?: never;
    }
  | {
      readonly kind: 'ed25519_yao_local_session';
      readonly activeClientHandle: string;
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      readonly ed25519YaoSession: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
      readonly clientRootShareHandle?: never;
      readonly pendingFactorHandle?: never;
      readonly ed25519YaoRecovery?: never;
    }
  | {
      readonly kind: 'ecdsa_and_ed25519_yao_recovery';
      readonly clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      readonly pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
      readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      readonly kind: 'ecdsa_and_ed25519_yao_local_session';
      readonly clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      readonly activeClientHandle: string;
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      readonly ed25519YaoSession: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
      readonly pendingFactorHandle?: never;
      readonly ed25519YaoRecovery?: never;
    };

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

export interface EvmCryptoWorkerOperationMap {
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
  verifySecp256k1RecoverableSignatureAgainstPublicKey33: {
    payload: { digest32: ArrayBuffer; signature65: ArrayBuffer; publicKey33: ArrayBuffer };
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
  secretSource: EmailOtpWorkerSessionSecretSource;
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

export type EmailOtpEcdsaPublicationTargetPlan = {
  kind: 'new_key_publication_target';
  chainTarget: ThresholdEcdsaChainTarget;
  evmFamilySigningKeySlotId: string;
  keyHandle?: never;
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
};

type EmailOtpEcdsaBootstrapJwtPayload = {
  sessionKind: 'jwt';
  routeAuth: AppOrWalletSessionAuth;
};

export type EmailOtpEcdsaBootstrapStrictPayload = EmailOtpEcdsaBootstrapBasePayload &
  EmailOtpEcdsaBootstrapJwtPayload;

export type EmailOtpYaoPrewarmFailureStage = 'worker_ready' | 'yao_wasm_init';

export type EmailOtpYaoPrewarmRequest =
  | { kind: 'not_requested' }
  | { kind: 'requested' };

export type EmailOtpYaoPrewarmWorkerResult =
  | {
      kind: 'succeeded';
      elapsedMs: number;
      failureStage?: never;
    }
  | {
      kind: 'failed';
      elapsedMs: number;
      failureStage: 'yao_wasm_init';
    };

export interface EmailOtpWorkerOperationMap {
  prewarmEmailOtpRegistrationCrypto: {
    payload: Record<string, never>;
    result: EmailOtpYaoPrewarmWorkerResult;
  };
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
      delivery: EmailOtpChallengeDelivery;
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
      delivery: EmailOtpChallengeDelivery;
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
      ed25519YaoFactor: EmailOtpEd25519YaoFactorRequest;
    };
    result: {
      thresholdEcdsaClientVerifyingShareB64u: string;
      recoveryKeys: EmailOtpRecoveryCodeSet;
      recoveryCodesIssuedAtMs: number;
      otpChannel: WalletEmailOtpChannel;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      clientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleResult;
      ed25519YaoFactor: EmailOtpEd25519YaoFactorResult;
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows: unknown[];
        enrollmentSealKeyVersion: string;
        clientUnlockPublicKeyB64u: string;
        unlockKeyVersion: string;
        thresholdEcdsaClientVerifyingShareB64u: string;
      };
    };
  };
  bindEmailOtpEd25519YaoRoot: {
    payload: {
      pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
      scope: EmailOtpEd25519YaoRootScope;
    };
    result: { rootHandle: EmailOtpEd25519YaoRootHandle };
  };
  disposeEmailOtpEd25519YaoPendingFactor: {
    payload: { pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle };
    result: { removed: boolean };
  };
  disposeEmailOtpEd25519YaoRoot: {
    payload: { rootHandle: EmailOtpEd25519YaoRootHandle };
    result: { removed: boolean };
  };
  disposeEmailOtpEcdsaClientRootHandle: {
    payload: { clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload };
    result: { removed: boolean };
  };
  startEmailOtpEd25519YaoRegistration: {
    payload: {
      rootHandle: EmailOtpEd25519YaoRootHandle;
      admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
      walletId: string;
      providerSubject: string;
      registrationAuthorityId: string;
      bearerToken: string;
      routerOrigin: string;
    };
    result: {
      pendingHandle: string;
      operationalPublicKey: string;
      activationReference: {
        kind: 'router_ab_ed25519_yao_activation_reference_v1';
        lifecycle_id: string;
        session_id: readonly number[];
      };
    };
  };
  commitEmailOtpEd25519YaoRegistration: {
    payload: {
      pendingHandle: string;
      walletSessionState: NearResolvedEd25519SigningSessionState;
    };
    result: {
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    };
  };
  disposeEmailOtpEd25519YaoRegistration: {
    payload: { pendingHandle: string };
    result: { removed: boolean };
  };
  recoverEmailOtpEd25519Yao: {
    payload: {
      rootHandle: EmailOtpEd25519YaoRootHandle;
      admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
      walletId: string;
      nearAccountId: string;
      signingRootVersion: string;
      providerSubject: string;
      registrationAuthorityId: string;
      bearerToken: string;
      routerOrigin: string;
      sessionPolicy: {
        thresholdSessionId: string;
        expiresAtMs: number;
        remainingUses: number;
      };
    };
    result: {
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      activation: RouterAbEd25519YaoRecoveryActivationReceiptV1;
    };
  };
  createEmailOtpEd25519YaoSigningShare: {
    payload: {
      activeClientHandle: string;
      input: RouterAbEd25519YaoClientSigningInputV1;
    };
    result: RouterAbEd25519YaoClientSigningShareV1;
  };
  disposeEmailOtpEd25519YaoActiveClient: {
    payload: { activeClientHandle: string };
    result: { removed: boolean };
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
      retainedClientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
    };
  };
  commitEmailOtpEcdsaRegistrationWarmMaterial: {
    payload: {
      walletId: string;
      chainTarget: ThresholdEcdsaChainTarget;
      retainedClientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
      thresholdSessionId: string;
      expiresAtMs: number;
      remainingUses: number;
    };
    result: { committed: true };
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
      material: EmailOtpWalletUnlockMaterialRequest;
    };
    result: {
      recovery: {
        challengeId: string;
        enrollmentSealKeyVersion: string;
        unlockChallengeId: string;
        unlockChallengeB64u: string;
        clientUnlockPublicKeyB64u: string;
        unlockSignatureB64u: string;
      };
    } & EmailOtpWalletUnlockMaterialResult;
  };
  bootstrapEmailOtpEcdsaSessionsFromWorkerHandle: {
    payload: EmailOtpEcdsaBootstrapStrictPayload;
    result: {
      bootstraps: ThresholdEcdsaSessionBootstrapResult[];
      ecdsaDerivationExportArtifact?: {
        artifactKind: 'ecdsa-derivation-secp256k1-export';
        chainTarget: ThresholdEcdsaChainTarget;
        signingRootId: string;
        signingRootVersion?: string;
        publicKeyHex: string;
        privateKeyHex: string;
        ethereumAddress: string;
      };
    };
  };
  bindEmailOtpEcdsaWarmSessionFromWorkerHandle: {
    payload: {
      clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      thresholdSessionId: string;
      remainingUses: number;
      expiresAtMs: number;
    };
    result:
      | { ok: true; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
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
        authSubjectId: string;
      };
    };
    result:
      | {
          ok: true;
          remainingUses: number;
          expiresAtMs: number;
          clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
        }
      | { ok: false; code: string; message: string };
  };
  rehydrateEmailOtpEd25519YaoLocalMaterial: {
    payload: {
      sealedSecretB64u: string;
      remainingUses: number;
      expiresAtMs: number;
      transport: {
        relayerUrl: string;
        walletSessionJwt: string;
        signingSessionSealKeyVersion: SigningSessionSealKeyVersion;
        shamirPrimeB64u: string;
      };
      restore: {
        session: WalletRegistrationEd25519YaoBootstrapSession;
        providerSubject: string;
        signerSlot: number;
        expectedOperationalPublicKey: string;
      };
    };
    result:
      | {
          ok: true;
          activeClientHandle: string;
          metadata: RouterAbEd25519YaoActiveClientMetadataV1;
          ed25519YaoSession: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
        }
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
  exportEmailOtpEd25519YaoSeedWithAuthorization: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId: string;
      challengeId: string;
      otpCode: string;
      shamirPrimeB64u: string;
      routePlan: EmailOtpRoutePlan;
      walletSessionJwt: string;
      nearAccountId: string;
      nearEd25519SigningKeyId: string;
      signerSlot: number;
      thresholdSessionId: string;
      signingGrantId: string;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
    };
    result: {
      artifactKind: 'near-ed25519-seed-v1';
      publicKey: string;
      privateKey: string;
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
  evmCrypto: EvmCryptoWorkerOperationMap;
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

export type EvmCryptoTransactionOperationType =
  | 'computeEip1559TxHash'
  | 'encodeEip1559SignedTxFromSignature65';
export type EvmCryptoLocalSecp256k1OperationType =
  | 'signSecp256k1Recoverable'
  | 'verifySecp256k1RecoverableSignatureAgainstPublicKey33'
  | 'secp256k1PrivateKey32ToPublicKey33'
  | 'deriveSecp256k1KeypairFromPrfSecond'
  | 'validateSecp256k1PublicKey33'
  | 'addSecp256k1PublicKeys33'
  | 'buildWebauthnP256Signature'
  | 'decodeCoseP256PublicKey';
export type EvmCryptoDomainOperationType =
  | EvmCryptoTransactionOperationType
  | EvmCryptoLocalSecp256k1OperationType;

export type EvmCryptoTransactionOperationRequest<T extends EvmCryptoTransactionOperationType> =
  MultichainWorkerOperationRequest<'evmCrypto', T>;
export type EvmCryptoLocalSecp256k1OperationRequest<
  T extends EvmCryptoLocalSecp256k1OperationType,
> = MultichainWorkerOperationRequest<'evmCrypto', T>;

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
  | 'prepareEcdsaClientBootstrapFromEmailOtpHandle'
  | 'bindEmailOtpEd25519YaoRoot'
  | 'disposeEmailOtpEd25519YaoPendingFactor'
  | 'disposeEmailOtpEd25519YaoRoot'
  | 'startEmailOtpEd25519YaoRegistration'
  | 'commitEmailOtpEd25519YaoRegistration'
  | 'disposeEmailOtpEd25519YaoRegistration'
  | 'recoverEmailOtpEd25519Yao'
  | 'createEmailOtpEd25519YaoSigningShare'
  | 'disposeEmailOtpEd25519YaoActiveClient';
export type EmailOtpRestoreOperationType =
  | 'restoreEmailOtpDeviceEnrollmentEscrow'
  | 'rotateEmailOtpRecoveryCodes'
  | 'removeEmailOtpDeviceEnrollmentEscrowFromDevice';
export type EmailOtpWarmSessionOperationType =
  | 'loginWithEmailOtpWallet'
  | 'bootstrapEmailOtpEcdsaSessionsFromWorkerHandle'
  | 'bindEmailOtpEcdsaWarmSessionFromWorkerHandle'
  | 'getEmailOtpWarmSessionStatus'
  | 'claimEmailOtpWarmSessionMaterial'
  | 'consumeEmailOtpWarmSessionUses'
  | 'sealEmailOtpWarmSessionMaterial'
  | 'rehydrateEmailOtpEcdsaWarmSessionMaterial'
  | 'rehydrateEmailOtpEd25519YaoLocalMaterial'
  | 'clearEmailOtpWarmSessionMaterial';
export type EmailOtpExportOperationType =
  | 'disposeEmailOtpEcdsaClientRootHandle'
  | 'exportEmailOtpEd25519YaoSeedWithAuthorization';
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

export type NearEd25519DigestOperationType =
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeDelegateSigningDigest
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519BuildDelegateSigningPayload;
export type NearEd25519FinalizeOperationType =
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeNearTxFromSignature
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh
  | typeof NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh;

export type NearEd25519DigestOperationRequest<T extends NearEd25519DigestOperationType> =
  NearWorkerOperationRequest<T>;
export type NearEd25519FinalizeOperationRequest<T extends NearEd25519FinalizeOperationType> =
  NearWorkerOperationRequest<T>;

export const EcdsaDerivationClientCustomRequestType = {
  PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap: 70_000,
  FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap: 70_001,
  BuildThresholdEcdsaDerivationRoleLocalExportArtifact: 70_002,
  CreateRouterAbEcdsaRegistrationCeremony: 70_005,
  VerifyRouterAbEcdsaRegistrationClientProofs: 70_006,
  CloseRouterAbEcdsaRegistrationCeremony: 70_007,
  FinalizeRouterAbEcdsaRegistrationActivation: 70_008,
  CreateRouterAbEcdsaPostRegistrationCeremony: 70_009,
  FinalizeRouterAbEcdsaExplicitExport: 70_010,
  CloseRouterAbEcdsaPostRegistrationCeremony: 70_011,
  VerifyRouterAbEcdsaRefreshClientProofs: 70_014,
  StoreThresholdEcdsaRoleLocalSigningMaterial: 70_004,
  RehydrateEcdsaRoleLocalSigningMaterial: 70_015,
} as const;

export type EcdsaDerivationClientCustomRequestType =
  (typeof EcdsaDerivationClientCustomRequestType)[keyof typeof EcdsaDerivationClientCustomRequestType];

export const EcdsaDerivationClientCustomResponseType = {
  PrepareThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess: 70_100,
  FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess: 70_101,
  BuildThresholdEcdsaDerivationRoleLocalExportArtifactSuccess: 70_102,
  CreateRouterAbEcdsaRegistrationCeremonySuccess: 70_105,
  VerifyRouterAbEcdsaRegistrationClientProofsSuccess: 70_106,
  CloseRouterAbEcdsaRegistrationCeremonySuccess: 70_107,
  FinalizeRouterAbEcdsaRegistrationActivationSuccess: 70_108,
  CreateRouterAbEcdsaPostRegistrationCeremonySuccess: 70_109,
  FinalizeRouterAbEcdsaExplicitExportSuccess: 70_110,
  CloseRouterAbEcdsaPostRegistrationCeremonySuccess: 70_111,
  VerifyRouterAbEcdsaRefreshClientProofsSuccess: 70_114,
  StoreThresholdEcdsaRoleLocalSigningMaterialSuccess: 70_104,
  RehydrateEcdsaRoleLocalSigningMaterialSuccess: 70_115,
} as const;

export type EcdsaDerivationClientCustomResponseType =
  (typeof EcdsaDerivationClientCustomResponseType)[keyof typeof EcdsaDerivationClientCustomResponseType];

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
  type: typeof EcdsaDerivationClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess;
  payload: StoreThresholdEcdsaRoleLocalSigningMaterialResult;
  diagnostics?: WorkerResponseDiagnostics;
};

type EcdsaPresignClientSessionParameters = {
  sessionId: string;
  groupPublicKey33: ArrayBuffer;
  materialExpiresAtMs: number;
  poolIdentity: EcdsaClientPresignPoolIdentity;
};

export type EcdsaPresignClientSessionInitRequest = EcdsaPresignClientSessionParameters &
  (
    | {
        authority: {
          kind: 'role_local_derivation_handle';
          materialHandle: string;
          durableMaterialRef: string;
          expectedBindingDigest: string;
          emailOtpSessionId?: never;
        };
      }
    | {
        authority: {
          kind: 'email_otp_worker_session';
          emailOtpSessionId: string;
          materialHandle?: never;
          durableMaterialRef?: never;
          expectedBindingDigest?: never;
        };
      }
  );

export type EcdsaPresignClientSessionInitResult =
  | {
      authority: { kind: 'role_local_derivation_handle' };
      progress: ThresholdEcdsaPresignProgressResult;
    }
  | {
      authority: {
        kind: 'email_otp_worker_session';
        remainingUses: number;
        expiresAtMs: number;
      };
      progress: ThresholdEcdsaPresignProgressResult;
    };

export type EcdsaPresignClientSessionInitResponse = {
  type: typeof EcdsaPresignClientResponseType.SessionInitSuccess;
  payload: EcdsaPresignClientSessionInitResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaPresignClientSessionStepRequest = {
  sessionId: string;
  stage: 'triples' | 'presign';
  incomingMessages: ArrayBuffer[];
};

export type EcdsaPresignClientSessionStepResponse = {
  type: typeof EcdsaPresignClientResponseType.SessionStepSuccess;
  payload: ThresholdEcdsaPresignProgressResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaPresignClientSessionAbortRequest = {
  sessionId: string;
};

export type EcdsaPresignClientSessionAbortResponse = {
  type: typeof EcdsaPresignClientResponseType.SessionAbortSuccess;
  payload: ThresholdEcdsaPresignAbortResult;
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaPresignClientAdmitRequest = {
  materialHandle: string;
  expectedPresignatureId: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
};

export type EcdsaPresignClientAdmitResponse = {
  type: typeof EcdsaPresignClientResponseType.AdmitSuccess;
  payload: {
    kind: 'ecdsa_client_presignature_admitted_v1';
    materialHandle: string;
    presignatureId: string;
  };
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaPresignClientDestroyRequest = {
  materialHandle: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
};

export type EcdsaPresignClientDestroyResponse = {
  type: typeof EcdsaPresignClientResponseType.DestroySuccess;
  payload: {
    kind: 'ecdsa_client_presignature_destroyed_v1';
    materialHandle: string;
  };
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaPresignClientUseBinding = {
  materialHandle: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  requestBinding: string;
  reservationId: string;
};

export type EcdsaPresignClientReserveRequest = EcdsaPresignClientUseBinding & {
  leaseExpiresAtMs: number;
};

export type EcdsaPresignClientLifecycleResponse = {
  type:
    | typeof EcdsaPresignClientResponseType.ReserveSuccess
    | typeof EcdsaPresignClientResponseType.CommitSuccess;
  payload: {
    kind: 'ecdsa_client_presignature_lifecycle_advanced_v1';
    materialHandle: string;
  };
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaPresignClientListAvailableRequest = {
  poolIdentity: EcdsaClientPresignPoolIdentity;
};

export type EcdsaPresignClientListAvailableResponse = {
  type: typeof EcdsaPresignClientResponseType.ListAvailableSuccess;
  payload: Array<{
    presignatureId: string;
    materialHandle: string;
    bigR33: ArrayBuffer;
    createdAtMs: number;
    expiresAtMs: number;
  }>;
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaOnlineClientComputeSignatureShareRequest = {
  materialHandle: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  requestBinding: string;
  reservationId: string;
  groupPublicKey33: ArrayBuffer;
  expectedPresignBigR33: ArrayBuffer;
  digest32: ArrayBuffer;
  clientRerandomizationContribution32: ArrayBuffer;
  signingWorkerRerandomizationContribution32: ArrayBuffer;
};

export type EcdsaOnlineClientComputeSignatureShareResponse = {
  type: typeof EcdsaOnlineClientResponseType.ComputeSignatureShareSuccess;
  payload: ArrayBuffer;
  diagnostics?: WorkerResponseDiagnostics;
};

export type EcdsaOnlineClientRetirePoolRequest = {
  poolIdentity: EcdsaClientPresignPoolIdentity;
  reason: 'key_epoch_retired' | 'activation_epoch_retired';
};

export type EcdsaOnlineClientRetirePoolResponse = {
  type: typeof EcdsaOnlineClientResponseType.RetirePoolSuccess;
  payload: {
    kind: 'ecdsa_client_presignature_pool_retired_v1';
    poolIdentity: EcdsaClientPresignPoolIdentity;
    reason: EcdsaOnlineClientRetirePoolRequest['reason'];
    retiredCount: number;
  };
  diagnostics?: WorkerResponseDiagnostics;
};

type EcdsaDerivationClientCustomOperationMap = {
  [EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony]: {
    payload: CreateRouterAbEcdsaRegistrationCeremonyRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.CreateRouterAbEcdsaRegistrationCeremonySuccess;
      payload: CreateRouterAbEcdsaRegistrationCeremonyResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs]: {
    payload: VerifyRouterAbEcdsaRegistrationClientProofsRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRegistrationClientProofsSuccess;
      payload: VerifyRouterAbEcdsaRegistrationClientProofsResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation]: {
    payload: FinalizeRouterAbEcdsaRegistrationActivationRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaRegistrationActivationSuccess;
      payload: FinalizeRouterAbEcdsaRegistrationActivationResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony]: {
    payload: CloseRouterAbEcdsaRegistrationCeremonyRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.CloseRouterAbEcdsaRegistrationCeremonySuccess;
      payload: CloseRouterAbEcdsaRegistrationCeremonyResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony]: {
    payload: CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.CreateRouterAbEcdsaPostRegistrationCeremonySuccess;
      payload: CreateRouterAbEcdsaPostRegistrationCeremonyResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport]: {
    payload: FinalizeRouterAbEcdsaExplicitExportRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaExplicitExportSuccess;
      payload: FinalizeRouterAbEcdsaExplicitExportResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony]: {
    payload: CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.CloseRouterAbEcdsaPostRegistrationCeremonySuccess;
      payload: CloseRouterAbEcdsaPostRegistrationCeremonyResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRefreshClientProofs]: {
    payload: VerifyRouterAbEcdsaRefreshClientProofsRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRefreshClientProofsSuccess;
      payload: VerifyRouterAbEcdsaRefreshClientProofsResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap]: {
    payload: WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapRequest;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess;
      payload: WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap]: {
    payload: WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapRequest;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess;
      payload: WasmFinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapResult;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact]: {
    payload: WasmBuildThresholdEcdsaDerivationRoleLocalExportArtifactRequest;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.BuildThresholdEcdsaDerivationRoleLocalExportArtifactSuccess;
      payload: WasmBuildThresholdEcdsaDerivationRoleLocalExportArtifactResult;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial]: {
    payload: StoreThresholdEcdsaRoleLocalSigningMaterialRequest;
    result: StoreThresholdEcdsaRoleLocalSigningMaterialResponse;
  };
  [EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial]: {
    payload: RehydrateEcdsaRoleLocalSigningMaterialRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess;
      payload: RehydrateEcdsaRoleLocalSigningMaterialResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
};

export const EcdsaPresignClientRequestType = {
  SessionInit: 71_000,
  SessionStep: 71_001,
  SessionAbort: 71_002,
  Admit: 71_003,
  Destroy: 71_004,
  Reserve: 71_005,
  Commit: 71_006,
  ListAvailable: 71_007,
} as const;

export const EcdsaPresignClientResponseType = {
  SessionInitSuccess: 71_100,
  SessionStepSuccess: 71_101,
  SessionAbortSuccess: 71_102,
  AdmitSuccess: 71_103,
  DestroySuccess: 71_104,
  ReserveSuccess: 71_105,
  CommitSuccess: 71_106,
  ListAvailableSuccess: 71_107,
} as const;

export type EcdsaPresignClientOperationMap = {
  [EcdsaPresignClientRequestType.SessionInit]: {
    payload: EcdsaPresignClientSessionInitRequest;
    result: EcdsaPresignClientSessionInitResponse;
  };
  [EcdsaPresignClientRequestType.SessionStep]: {
    payload: EcdsaPresignClientSessionStepRequest;
    result: EcdsaPresignClientSessionStepResponse;
  };
  [EcdsaPresignClientRequestType.SessionAbort]: {
    payload: EcdsaPresignClientSessionAbortRequest;
    result: EcdsaPresignClientSessionAbortResponse;
  };
  [EcdsaPresignClientRequestType.Admit]: {
    payload: EcdsaPresignClientAdmitRequest;
    result: EcdsaPresignClientAdmitResponse;
  };
  [EcdsaPresignClientRequestType.Destroy]: {
    payload: EcdsaPresignClientDestroyRequest;
    result: EcdsaPresignClientDestroyResponse;
  };
  [EcdsaPresignClientRequestType.Reserve]: {
    payload: EcdsaPresignClientReserveRequest;
    result: EcdsaPresignClientLifecycleResponse;
  };
  [EcdsaPresignClientRequestType.Commit]: {
    payload: EcdsaPresignClientUseBinding;
    result: EcdsaPresignClientLifecycleResponse;
  };
  [EcdsaPresignClientRequestType.ListAvailable]: {
    payload: EcdsaPresignClientListAvailableRequest;
    result: EcdsaPresignClientListAvailableResponse;
  };
};

export const EcdsaOnlineClientRequestType = {
  ComputeSignatureShare: 72_000,
  RetirePool: 72_001,
} as const;

export const EcdsaOnlineClientResponseType = {
  ComputeSignatureShareSuccess: 72_100,
  RetirePoolSuccess: 72_101,
} as const;

export type EcdsaOnlineClientOperationMap = {
  [EcdsaOnlineClientRequestType.ComputeSignatureShare]: {
    payload: EcdsaOnlineClientComputeSignatureShareRequest;
    result: EcdsaOnlineClientComputeSignatureShareResponse;
  };
  [EcdsaOnlineClientRequestType.RetirePool]: {
    payload: EcdsaOnlineClientRetirePoolRequest;
    result: EcdsaOnlineClientRetirePoolResponse;
  };
};

export type EcdsaDerivationWorkerOperationType = keyof EcdsaDerivationClientCustomOperationMap;

type EcdsaDerivationWorkerOperationEntry<T extends EcdsaDerivationWorkerOperationType> =
  EcdsaDerivationClientCustomOperationMap[T];

export type EcdsaDerivationWorkerOperationRequest<T extends EcdsaDerivationWorkerOperationType> = {
  sessionId?: string;
  type: T;
  payload: WithOptionalSessionId<EcdsaDerivationWorkerOperationEntry<T>['payload']>;
  timeoutMs?: number;
  transfer?: Transferable[];
};

export type EcdsaDerivationWorkerOperationResult<T extends EcdsaDerivationWorkerOperationType> =
  EcdsaDerivationWorkerOperationEntry<T>['result'];

export type DerivationSignerWorkerOperationMap = {
  [T in EcdsaDerivationWorkerOperationType]: {
    payload: EcdsaDerivationWorkerOperationEntry<T>['payload'];
    result: EcdsaDerivationWorkerOperationEntry<T>['result'];
  };
};

export type EcdsaDerivationRoleLocalMaterialOperationType =
  | typeof EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony
  | typeof EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs
  | typeof EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation
  | typeof EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony
  | typeof EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony
  | typeof EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport
  | typeof EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony
  | typeof EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRefreshClientProofs
  | typeof EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap
  | typeof EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap
  | typeof EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact
  | typeof EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial
  | typeof EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial;

export type EcdsaDerivationRoleLocalMaterialOperationRequest<
  T extends EcdsaDerivationRoleLocalMaterialOperationType,
> = EcdsaDerivationWorkerOperationRequest<T>;
export interface SignerWorkerOperationMapByKind {
  nearSigner: NearSignerWorkerOperationMap;
  ecdsaDerivationClient: DerivationSignerWorkerOperationMap;
  ecdsaPresignClient: EcdsaPresignClientOperationMap;
  ecdsaOnlineClient: EcdsaOnlineClientOperationMap;
  evmCrypto: EvmCryptoWorkerOperationMap;
  tempoSigner: TempoSignerWorkerOperationMap;
  emailOtp: EmailOtpWorkerOperationMap;
}

export type SignerWorkerKind = keyof SignerWorkerOperationMapByKind;

export type SignerWorkerOperationType<K extends SignerWorkerKind> =
  keyof SignerWorkerOperationMapByKind[K];

export type SignerWorkerProgressEvent<K extends SignerWorkerKind> = K extends 'nearSigner'
  ? NearWorkerProgressEvent
  : K extends 'evmCrypto' | 'tempoSigner'
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
  : K extends 'ecdsaDerivationClient'
    ? EcdsaDerivationWorkerOperationRequest<Extract<T, EcdsaDerivationWorkerOperationType>>
    : K extends 'emailOtp' | 'evmCrypto' | 'tempoSigner'
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

export type EmailOtpYaoPrewarmDiagnostics = {
  workerPrewarmMs: number;
  yaoWasmInitMs: number;
};

export type EmailOtpYaoPrewarmOutcome =
  | (EmailOtpYaoPrewarmDiagnostics & {
      kind: 'not_requested';
      elapsedMs: 0;
      failureStage?: never;
    })
  | (EmailOtpYaoPrewarmDiagnostics & {
      kind: 'succeeded';
      elapsedMs: number;
      failureStage?: never;
    })
  | (EmailOtpYaoPrewarmDiagnostics & {
      kind: 'failed';
      elapsedMs: number;
      failureStage: EmailOtpYaoPrewarmFailureStage;
    });

export interface SignerWorkerTransportProtocol {
  setWorkerBaseOrigin(origin: string | undefined): void;
  prewarmWorkers(): Promise<void>;
  prewarmEmailOtpYao(request?: EmailOtpYaoPrewarmRequest): Promise<EmailOtpYaoPrewarmOutcome>;
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
