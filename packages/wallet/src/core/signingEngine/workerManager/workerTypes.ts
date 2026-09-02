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
} from '@/core/types/signer-worker';
import type { MultichainWorkerKind } from '@/core/walletRuntimePaths/multichainWorkers';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  MpcMaterialActivationRef,
  ThresholdEd25519SessionId,
  WebAuthnRpId,
  WalletAuthMethodId,
} from '@shared/utils/domainIds';
import type {
  PasskeyCustodyEnvelopeRecord,
  WalletCustodyCeremonyCommitPayload,
  WalletCustodyEvmFamilyActivationCompletion,
  WalletCustodyEvmFamilyPublicFacts,
  WalletCustodyKeySetKind,
} from '@shared/passkey-custody';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  SigningSessionSealKeyVersion,
} from '@/core/signingEngine/session/keyMaterialBrands';
import type { EcdsaClientPresignPoolIdentity } from './ecdsaPresignPoolIdentity';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpChallengeDelivery,
  EmailOtpUnlockSignerSelection,
  EmailOtpVerifiedAuthorityProjection,
} from '../session/emailOtp/publicTypes';
import type { EmailOtpRoutePlan } from '../stepUpConfirmation/otpPrompt/authLane';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { EcdsaRoleLocalReadyStateBlob } from '@/core/platform';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type {
  CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaPostRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaPostRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaExplicitExportRequestV1,
  FinalizeRouterAbEcdsaExplicitExportResultV1,
  RehydrateEcdsaRoleLocalSigningMaterialRequestV1,
  RehydrateEcdsaRoleLocalSigningMaterialResultV1,
  VerifyRouterAbEcdsaPostRegistrationProofsRequestV1,
  VerifyRouterAbEcdsaPostRegistrationProofsResultV1,
  SignWalletRecoveryEcdsaMaterialPossessionProofRequestV1,
  SignWalletRecoveryEcdsaMaterialPossessionProofResultV1,
  PrepareEcdsaAdditiveLaneHolderRequestV1,
  PrepareEcdsaAdditiveLaneHolderResultV1,
  PrepareLinkedDeviceEcdsaSourceContributionRequestV1,
  PrepareLinkedDeviceEcdsaSourceContributionResultV1,
  CreateEcdsaHolderOrdinaryExportRequestV1,
  CreateEcdsaHolderOrdinaryExportResultV1,
  FinalizeEcdsaHolderOrdinaryExportRequestV1,
  FinalizeEcdsaHolderOrdinaryExportResultV1,
} from '@/core/signingEngine/workerManager/ecdsaClientWorkerChannels';
import type {
  Ed25519OperationStepUpProof,
  IssuedEd25519OperationStepUpAuthorization,
} from '../threshold/ed25519/walletSession';
import type {
  CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  PersistInitialCanonicalEcdsaActivationRequestV1,
  PersistInitialCanonicalEcdsaActivationResultV1,
  ReconcileCanonicalEcdsaActivationRequestV1,
  ReconcileCanonicalEcdsaActivationWorkerResultV1,
  VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  VerifyRouterAbEcdsaRegistrationClientProofsResultV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '../threshold/ed25519/yaoClient';

export type EmailOtpAuthoritySelector =
  | { readonly kind: 'wallet' }
  | {
      readonly kind: 'wallet_auth_method';
      readonly walletAuthMethodId: string;
    };
import {
  ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoBytes32V1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  Ed25519YaoLaneClientCompletionV1,
  Ed25519YaoLaneJobV1,
} from '@shared/signing-lanes/rotation';
import type { NearResolvedEd25519SigningSessionState } from '../interfaces/near';
import type { ExactWalletSessionAuthorization } from '../session/persistence/walletSessionAuthorizationProjection';
import type { WalletRegistrationEd25519YaoSignerRuntimeBootstrap } from '@/core/rpcClients/relayer/walletRegistration';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { WalletRecoverySetRotationWorkerResultV1 } from '@shared/wallet-recovery/walletRecoveryRotation';
import type {
  RouterAbEcdsaCredentialFreeSessionActivationResponseV1,
  RouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { LoadedWalletCustodyEd25519MaterialV1 } from '../walletCustody/ed25519SeedMaterial';
import type { WalletCustodyCacheEnvelopeV1 } from '../walletCustody/openCustodyCache';
import type { RouterAbNormalSigningPrepareRequestV2Wire } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking';

export type EmailOtpEd25519YaoRecoveryAugmentationV1 = {
  readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1;
  readonly signerSlot: number;
  readonly remainingUses: number;
  readonly orgId: string;
};

export type EmailOtpEd25519YaoActiveCapabilityDescriptorV1 = {
  readonly kind: 'router_ab_ed25519_yao_active_capability_v1';
  readonly materialActivation: MpcMaterialActivationRef;
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
    readonly thresholdSessionId: ThresholdEd25519SessionId;
    readonly signerSetId: string;
    readonly signingWorkerId: string;
  };
  readonly stateEpoch: number;
  readonly registrationContinuity:
    | {
        readonly kind: 'registration';
        readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
        readonly admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
        readonly activationTranscript: readonly number[];
      }
    | {
        readonly kind: 'recovery';
        readonly activationTranscript: readonly number[];
      };
};

export type EmailOtpEd25519YaoExportMaterialV1 =
  | {
      readonly kind: 'active_capability';
      readonly materialActivation: MpcMaterialActivationRef;
      readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
    }
  | {
      readonly kind: 'sealed_custody';
      readonly materialActivation: MpcMaterialActivationRef;
      readonly walletCustodyEd25519Material: LoadedWalletCustodyEd25519MaterialV1;
      readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      readonly kind: 'sealed_export_root';
      readonly materialActivation: MpcMaterialActivationRef;
      readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
      readonly exportRootEnvelope: PasskeyCustodyEnvelopeRecord;
    };

export type EmailOtpEd25519YaoWorkerActivationResult = {
  readonly activeClientHandle: string;
  readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
};

export type EmailOtpWalletCustodyEd25519MaterialRequest =
  | { readonly kind: 'found'; readonly material: LoadedWalletCustodyEd25519MaterialV1 }
  | { readonly kind: 'absent' };

export type EmailOtpEd25519YaoRecoveryBootstrapV1 = {
  readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1;
  readonly session: WalletRegistrationEd25519YaoSignerRuntimeBootstrap;
  readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
};

export type EmailOtpEcdsaCustodySignerV1 = {
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly walletKey: {
    readonly walletId: string;
    readonly keyHandle: string;
    readonly ecdsaThresholdKeyId: string;
    readonly signingRootId: string;
    readonly signingRootVersion: string;
    readonly relayerKeyId: string;
    readonly contextBinding32B64u: string;
    readonly derivationClientSharePublicKey33B64u: string;
    readonly participantIds: readonly [number, number];
    readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  };
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type EmailOtpEcdsaCustodyContinuityV1 = {
  readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
  readonly signers: readonly EmailOtpEcdsaCustodySignerV1[];
};

export type EmailOtpEcdsaCustodyRestoreV1 = {
  readonly continuity: EmailOtpEcdsaCustodyContinuityV1;
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

export type EmailOtpWalletUnlockMaterialRequest =
  | ({
      readonly kind: 'ecdsa';
      readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
      readonly walletSessionAuth?: never;
      readonly ed25519YaoRecovery?: never;
      readonly ed25519YaoCapability?: never;
      readonly providerSubject?: never;
    } & (
      | {
          readonly ecdsaSessionHandleBinding: Extract<
            EmailOtpEcdsaSessionBootstrapHandleBinding,
            { operation: 'wallet_unlock' }
          >;
          readonly ecdsaSessionPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
        }
      | {
          readonly ecdsaSessionHandleBinding: Exclude<
            EmailOtpEcdsaSessionBootstrapHandleBinding,
            { operation: 'wallet_unlock' }
          >;
          readonly ecdsaSessionPolicy?: never;
        }
    ))
  | {
      readonly kind: 'ed25519_yao_recovery';
      readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryAugmentationV1;
      readonly providerSubject: string;
      readonly nearAccountId: string;
      readonly expectedOperationalPublicKey: string;
      readonly expectedThresholdSessionId: string;
      readonly walletCustodyEd25519Material: EmailOtpWalletCustodyEd25519MaterialRequest;
      readonly ecdsaSessionPolicy?: never;
      readonly walletSessionAuth?: never;
      readonly ecdsaSessionHandleBinding?: never;
      readonly runtimePolicyScope?: never;
      readonly ed25519YaoCapability?: never;
    }
  | {
      readonly kind: 'wallet_unlock_capabilities';
      readonly ecdsa: {
        readonly sessionHandleBinding: Extract<
          EmailOtpEcdsaSessionBootstrapHandleBinding,
          { operation: 'wallet_unlock' }
        >;
        readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
        readonly sessionPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
      };
      readonly ed25519Yao: {
        readonly recovery: EmailOtpEd25519YaoRecoveryAugmentationV1;
        readonly providerSubject: string;
        readonly nearAccountId: string;
        readonly expectedOperationalPublicKey: string;
        readonly expectedThresholdSessionId: string;
        readonly walletCustodyEd25519Material: EmailOtpWalletCustodyEd25519MaterialRequest;
      };
      readonly walletSessionAuth?: never;
    };

export type EmailOtpWalletUnlockMaterialResult =
  | ({
      readonly kind: 'ecdsa';
      readonly emailOtpSessionHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      readonly walletSessionAuthorization?: never;
      readonly pendingFactorHandle?: never;
      readonly ed25519YaoRecovery?: never;
    } & (
      | {
          readonly operation: 'wallet_unlock';
          readonly ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
          readonly ecdsaCustody: EmailOtpEcdsaCustodyRestoreV1;
        }
      | {
          readonly operation: Exclude<EmailOtpWorkerSessionHandleOperation, 'wallet_unlock'>;
          readonly ecdsaSession?: never;
        }
    ))
  | {
      readonly kind: 'wallet_custody_cache_absent';
      readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
      readonly emailOtpSessionHandle?: never;
      readonly walletSessionAuthorization?: never;
    }
  | {
      readonly kind: 'ed25519_yao_capability';
      readonly activeClientHandle: string;
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      readonly ed25519YaoCapability: EmailOtpEd25519YaoRecoveryBootstrapV1;
      readonly walletCustodyEd25519Material?: LoadedWalletCustodyEd25519MaterialV1;
      /** The export-root custody an unlock derives, for the unlocked capability. */
      readonly ed25519ExportRootCustody: {
        readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
        readonly factorSecret32: Uint8Array;
      };
      readonly walletSessionAuthorization: ExactWalletSessionAuthorization;
      readonly emailOtpSessionHandle?: never;
      readonly pendingFactorHandle?: never;
      readonly ed25519YaoRecovery?: never;
    }
  | {
      readonly kind: 'wallet_unlock_capabilities';
      readonly operation: 'wallet_unlock';
      readonly walletSessionAuthorization: ExactWalletSessionAuthorization;
      readonly ed25519ExportRootCustody: {
        readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
        readonly factorSecret32: Uint8Array;
      };
      readonly ecdsa: {
        readonly emailOtpSessionHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
        readonly session: RouterAbEcdsaCredentialFreeSessionActivationResponseV1;
        readonly custody: EmailOtpEcdsaCustodyRestoreV1;
      };
      readonly ed25519Yao:
        | {
            readonly kind: 'wallet_custody_cache_absent';
            readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
          }
        | {
            readonly kind: 'capability';
            readonly activeClientHandle: string;
            readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
            readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
          };
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

type EmailOtpEcdsaSessionBootstrapHandlePayloadBase = {
  kind: 'email_otp_worker_session_handle_v1';
  sessionId: string;
  walletId: string;
  authSubjectId: string;
  action: 'threshold_ecdsa_bootstrap';
  chainTarget: ThresholdEcdsaChainTarget;
};

type EmailOtpEcdsaRuntimeHandleOperation = Exclude<
  EmailOtpWorkerSessionHandleOperation,
  'registration'
>;

type EmailOtpEcdsaRuntimeSessionBootstrapHandlePayload = {
  [Operation in EmailOtpEcdsaRuntimeHandleOperation]: EmailOtpEcdsaSessionBootstrapHandlePayloadBase & {
    operation: Operation;
    keyHandle: string;
    evmFamilySigningKeySlotId?: never;
  };
}[EmailOtpEcdsaRuntimeHandleOperation];

export type EmailOtpEcdsaSessionBootstrapHandlePayload =
  EmailOtpEcdsaRuntimeSessionBootstrapHandlePayload;

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

type EmailOtpEcdsaSessionBootstrapHandleBindingBase = {
  authSubjectId: string;
  action?: 'threshold_ecdsa_bootstrap';
  chainTarget: ThresholdEcdsaChainTarget;
};

type EmailOtpEcdsaRuntimeSessionBootstrapHandleBinding = {
  [Operation in EmailOtpEcdsaRuntimeHandleOperation]: EmailOtpEcdsaSessionBootstrapHandleBindingBase & {
    operation: Operation;
    keyHandle: string;
    evmFamilySigningKeySlotId?: never;
  };
}[EmailOtpEcdsaRuntimeHandleOperation];

export type EmailOtpEcdsaSessionBootstrapHandleBinding =
  EmailOtpEcdsaRuntimeSessionBootstrapHandleBinding;

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

export type EmailOtpEcdsaSessionHandleBinding =
  | EmailOtpEcdsaSessionBootstrapHandleBinding
  | EmailOtpWalletRegistrationEcdsaPrepareHandleBinding;

export type EmailOtpYaoPrewarmFailureStage = 'worker_ready' | 'yao_wasm_init';

export type EmailOtpYaoPrewarmRequest = { kind: 'not_requested' } | { kind: 'requested' };

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

export type EmailOtpWarmMaterialTarget =
  | {
      readonly kind: 'ecdsa';
      readonly thresholdSessionId: string;
      readonly materialActivation?: never;
    }
  | {
      readonly kind: 'ed25519_yao';
      readonly thresholdSessionId: string;
      readonly materialActivation: MpcMaterialActivationRef;
    };

export type EmailOtpEd25519YaoOperationMaterialRequest = {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly providerSubjectId: string;
  readonly nearAccountId: string;
  readonly signerSlot: number;
  readonly expectedOperationalPublicKey: string;
  readonly expectedThresholdSessionId: ThresholdEd25519SessionId;
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryAugmentationV1;
  readonly walletCustodyEd25519Material: EmailOtpWalletCustodyEd25519MaterialRequest;
  readonly normalSigningRequest: RouterAbNormalSigningPrepareRequestV2Wire;
  readonly displayDigest: string;
  readonly proof: Extract<Ed25519OperationStepUpProof, { kind: 'email_otp' }>;
  readonly operationCredential: WalletSessionOperationCredentialV1;
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
      walletAuthMethodId?: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      operationFingerprintDigest?: DigestB64u;
    };
    result: {
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      delivery: EmailOtpChallengeDelivery;
      emailHint?: string;
      expiresAtMs?: number;
      ownerProofBindingDigest: string;
      walletAuthMethodId: string;
      signerSelection: EmailOtpUnlockSignerSelection;
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
    };
  };
  enrollEmailOtpWallet: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId: string;
      challengeId?: string;
      otpCode: string;
      groupId: string;
      routePlan: EmailOtpRoutePlan;
      googleEmailOtpRegistrationAttemptId?: string;
      otpChannel?: WalletEmailOtpChannel;
      clientSecret32?: ArrayBuffer;
    };
    result: {
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      serverSealedFactorCiphertextB64u: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
    };
  };
  prepareEmailOtpRegistrationEnrollmentMaterial: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId: string;
      groupId: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      clientSecret32?: ArrayBuffer;
      ecdsaSessionHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleRequest;
    };
    result: {
      otpChannel: WalletEmailOtpChannel;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      serverSealedFactorCiphertextB64u: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      emailOtpSessionHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleResult;
      emailOtpEnrollment: {
        enrollmentSealKeyVersion: string;
        serverSealedFactorCiphertextB64u: string;
        clientUnlockPublicKeyB64u: string;
        unlockKeyVersion: string;
      };
    };
  };
  releaseWalletRecoveryEmailOtpFactor: {
    payload: {
      relayUrl: string;
      walletId: string;
      recoveryOperationId: string;
      reservationId: string;
    };
    result:
      | {
          kind: 'existing';
          recoveryOperationId: string;
          reservationId: string;
          providerSubject: string;
          verifiedEmail: string;
          enrollmentId: string;
          enrollmentSealKeyVersion: string;
          factorSecret32: ArrayBuffer;
        }
      | {
          kind: 'create';
          recoveryOperationId: string;
          reservationId: string;
          providerSubject: string;
          verifiedEmail: string;
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
  prepareEmailOtpPasskeyCustodyLink: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId: string;
      groupId: string;
      routePlan: EmailOtpRoutePlan;
      verification: {
        kind: 'otp';
        challengeId: string;
        otpCode: string;
      };
    };
    result: {
      pendingHandleId: string;
      walletId: string;
      envelopeId: string;
      envelopeRevision: number;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      expiresAtMs: number;
    };
  };
  completeEmailOtpPasskeyCustodyLink: {
    payload: {
      pendingHandleId: string;
      existingEnvelope: PasskeyCustodyEnvelopeRecord;
      /** The server-allocated target method the resealed envelope belongs to. */
      walletAuthMethodId: WalletAuthMethodId;
      registration: {
        readonly kind: 'webauthn_add_auth_method_registration_v1';
        readonly rpId: WebAuthnRpId;
      };
      registrationCredential: WebAuthnRegistrationCredential;
    };
    result: {
      registrationCredential: WebAuthnRegistrationCredential;
      custodyEnvelope: PasskeyCustodyEnvelopeRecord;
    };
  };
  discardEmailOtpPasskeyCustodyLink: {
    payload: { pendingHandleId: string };
    result: { discarded: boolean };
  };
  rotateEmailOtpWalletRecoverySet: {
    payload: {
      relayUrl: string;
      walletId: string;
      userId: string;
      groupId: string;
      routePlan: EmailOtpRoutePlan;
      verification: {
        kind: 'otp';
        challengeId: string;
        otpCode: string;
      };
      recoveryCodesJson: string;
    };
    result: WalletRecoverySetRotationWorkerResultV1;
  };
  loginWithEmailOtpWallet: {
    payload: {
      relayUrl: string;
      walletId: string;
      authoritySelector: EmailOtpAuthoritySelector;
      userId: string;
      groupId: string;
      routePlan: EmailOtpRoutePlan;
      otpChannel?: WalletEmailOtpChannel;
      verification:
        | {
            kind: 'otp';
            challengeId?: string;
            otpCode: string;
          }
        | {
            kind: 'email_otp_unseal_grant';
            grant: string;
            challengeId: string;
          };
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
        verifiedAuthorityProjection: EmailOtpVerifiedAuthorityProjection;
      };
    } & EmailOtpWalletUnlockMaterialResult;
  };
  unlockEmailOtpAuthorityWallet: {
    payload: {
      relayUrl: string;
      walletId: string;
      walletAuthMethodId: string;
      challengeId: string;
      otpCode: string;
      /**
       * Which branch is unlocking, and what that branch requires.
       *
       * A linked device opens sealed material of its own after this call and
       * sends none of it here. An owner authority has no such material and
       * instead needs the runtime built inside this unlock, from the custody
       * projection the verify response already returns. Neither can hold the
       * other's fields, so a caller cannot ask for an owner runtime on the
       * linked branch or omit it on the owner one.
       */
      ed25519:
        | { readonly kind: 'no_ed25519'; readonly recovery?: never }
        | {
            readonly kind: 'owner_authority';
            readonly signerSlot: number;
            readonly remainingUses: number;
            readonly recovery: {
              readonly ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryAugmentationV1;
              readonly providerSubject: string;
              readonly nearAccountId: string;
              readonly expectedOperationalPublicKey: string;
              readonly expectedThresholdSessionId: string;
              readonly walletCustodyEd25519Material: EmailOtpWalletCustodyEd25519MaterialRequest;
            };
          }
        | {
            readonly kind: 'linked_device';
            readonly signerSlot: number;
            readonly remainingUses: number;
            readonly recovery?: never;
          };
    };
    result: {
      readonly kind: 'email_otp_authority_wallet_unlock_v1';
      readonly factorSecret32: Uint8Array;
      readonly walletSession: ActiveWalletSessionV1;
      readonly operationCredential: WalletSessionOperationCredentialV1;
      readonly verifiedAuthorityProjection: EmailOtpVerifiedAuthorityProjection;
      /**
       * Owner authorities unlock the wallet custody seed envelope. A linked
       * authority opens its separately provisioned signer material instead.
       */
      readonly walletCustodySeed:
        | {
            readonly kind: 'owner_authority_seed_envelope';
            readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
          }
        | {
            readonly kind: 'linked_device_seed_unavailable';
            readonly existingEnvelope?: never;
          };
      /**
       * Either the runtime is ready and every part of it is present, or there
       * is none. Three optional fields would let a caller hold a handle with no
       * metadata to check it against.
       */
      readonly ed25519Activation:
        | {
            readonly kind: 'ed25519_activation_ready';
            readonly activeClientHandle: string;
            readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
            readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
          }
        /* A linked device gets its bootstrap here and opens its own sealed
           material afterwards; no runtime is built in this call, so it carries
           no handle to hold or dispose. */
        | {
            readonly kind: 'ed25519_bootstrap_only';
            readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
            readonly activeClientHandle?: never;
            readonly metadata?: never;
          }
        | {
            readonly kind: 'ed25519_activation_absent';
            readonly bootstrap?: never;
            readonly activeClientHandle?: never;
            readonly metadata?: never;
          };
    };
  };
  getEmailOtpWarmSessionStatus: {
    payload: {
      target: EmailOtpWarmMaterialTarget;
    };
    result:
      | { ok: true; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
  };
  consumeEmailOtpWarmSessionUses: {
    payload: {
      target: EmailOtpWarmMaterialTarget;
      uses?: number;
    };
    result:
      | { ok: true; remainingUses: number; expiresAtMs: number }
      | { ok: false; code: string; message: string };
  };
  sealEmailOtpWarmSessionMaterial: {
    payload: {
      target: EmailOtpWarmMaterialTarget;
      transport: {
        relayerUrl: string;
        authorizationThresholdSessionId: string;
        operationCredential?: WalletSessionOperationCredentialV1;
        signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
        groupId?: string;
      };
    };
    result:
      | ({
          ok: true;
          sealedSecretB64u: string;
          keyVersion?: string;
          remainingUses: number;
          expiresAtMs: number;
        } & (
          | {
              materialKind: 'ecdsa';
              materialActivation?: never;
            }
          | {
              materialKind: 'ed25519_yao';
              materialActivation: MpcMaterialActivationRef;
            }
        ))
      | { ok: false; code: string; message: string };
  };
  rehydrateEmailOtpEcdsaWarmSessionMaterial: {
    payload: {
      target: Extract<EmailOtpWarmMaterialTarget, { kind: 'ecdsa' }>;
      sealedSecretB64u: string;
      remainingUses: number;
      expiresAtMs: number;
      transport: {
        relayerUrl: string;
        authorizationThresholdSessionId: string;
        operationCredential?: WalletSessionOperationCredentialV1;
        signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
        groupId?: string;
      };
      restore: {
        thresholdSessionId: string;
        walletId: string;
        keyHandle: string;
        chainTarget: ThresholdEcdsaChainTarget;
        authSubjectId: string;
      };
    };
    result:
      | {
          ok: true;
          remainingUses: number;
          expiresAtMs: number;
          emailOtpSessionHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
        }
      | { ok: false; code: string; message: string };
  };
  rehydrateEmailOtpEd25519YaoOperationMaterial: {
    payload: EmailOtpEd25519YaoOperationMaterialRequest;
    result: {
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
      walletCustodyEd25519Material?: LoadedWalletCustodyEd25519MaterialV1;
      issuedAuthorization: IssuedEd25519OperationStepUpAuthorization;
    };
  };
  rehydrateActiveEmailOtpEd25519YaoSessionMaterial: {
    payload: {
      readonly relayUrl: string;
      readonly walletId: string;
      readonly walletAuthMethodId: string;
      readonly orgId: string;
      readonly providerSubjectId: string;
      readonly nearAccountId: string;
      readonly signerSlot: number;
      readonly remainingUses: number;
      readonly expectedOperationalPublicKey: string;
      readonly expectedThresholdSessionId: ThresholdEd25519SessionId;
      readonly operationCredential: WalletSessionOperationCredentialV1;
      readonly ecdsa: {
        readonly sessionHandleBinding: Extract<
          EmailOtpEcdsaSessionBootstrapHandleBinding,
          { readonly operation: 'wallet_unlock' }
        >;
        readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
        readonly sessionPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
      };
      readonly walletCustodyEd25519Material: Extract<
        EmailOtpWalletCustodyEd25519MaterialRequest,
        { readonly kind: 'found' }
      >;
    };
    result: EmailOtpEd25519YaoWorkerActivationResult & {
      readonly ecdsaSession: RouterAbEcdsaCredentialFreeSessionActivationResponseV1;
      readonly walletSessionAuthorization: ExactWalletSessionAuthorization;
    };
  };
  activateEmailOtpEd25519YaoRegistrationMaterial: {
    payload: {
      readonly material: LoadedWalletCustodyEd25519MaterialV1;
      readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
      readonly envelope: WalletCustodyCacheEnvelopeV1;
      readonly factorSecret32: ArrayBuffer;
    };
    result: {
      readonly activeClientHandle: string;
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    };
  };
  clearEmailOtpWarmSessionMaterial: {
    payload: {
      target: EmailOtpWarmMaterialTarget;
    };
    result: {
      ok: true;
      cleared: true;
    };
  };
  exportEmailOtpEd25519YaoSeed: {
    payload: {
      relayUrl: string;
      challengeId: string;
      otpCode: string;
      lane: {
        walletId: string;
        providerSubjectId: string;
        /** The exact method this export acts as; linked wallets have several. */
        walletAuthMethodId: string;
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        signerSlot: number;
      };
      material: EmailOtpEd25519YaoExportMaterialV1;
    };
    result:
      | {
          kind: 'exported';
          artifactKind: 'near-ed25519-seed-v1';
          publicKey: string;
          privateKey: string;
        }
      | {
          kind: 'exported_and_rehydrated';
          artifactKind: 'near-ed25519-seed-v1';
          publicKey: string;
          privateKey: string;
          activeClientHandle: string;
          metadata: RouterAbEd25519YaoActiveClientMetadataV1;
          bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
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
  | 'requestEmailOtpEnrollmentChallenge';
export type EmailOtpEnrollmentOperationType =
  | 'enrollEmailOtpWallet'
  | 'prepareEmailOtpRegistrationEnrollmentMaterial'
  | 'createEmailOtpEd25519YaoSigningShare'
  | 'disposeEmailOtpEd25519YaoActiveClient'
  | 'prepareEmailOtpPasskeyCustodyLink'
  | 'completeEmailOtpPasskeyCustodyLink'
  | 'discardEmailOtpPasskeyCustodyLink'
  | 'rotateEmailOtpWalletRecoverySet';
export type EmailOtpWarmSessionOperationType =
  | 'loginWithEmailOtpWallet'
  | 'getEmailOtpWarmSessionStatus'
  | 'consumeEmailOtpWarmSessionUses'
  | 'sealEmailOtpWarmSessionMaterial'
  | 'rehydrateEmailOtpEcdsaWarmSessionMaterial'
  | 'rehydrateEmailOtpEd25519YaoOperationMaterial'
  | 'rehydrateActiveEmailOtpEd25519YaoSessionMaterial'
  | 'activateEmailOtpEd25519YaoRegistrationMaterial'
  | 'clearEmailOtpWarmSessionMaterial';
export type EmailOtpExportOperationType = 'exportEmailOtpEd25519YaoSeed';
export type EmailOtpDomainOperationType =
  | EmailOtpChallengeOperationType
  | EmailOtpEnrollmentOperationType
  | EmailOtpWarmSessionOperationType
  | EmailOtpExportOperationType;

export type EmailOtpChallengeOperationRequest<T extends EmailOtpChallengeOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;
export type EmailOtpEnrollmentOperationRequest<T extends EmailOtpEnrollmentOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;
export type EmailOtpWarmSessionOperationRequest<T extends EmailOtpWarmSessionOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;
export type EmailOtpExportOperationRequest<T extends EmailOtpExportOperationType> =
  EmailOtpWorkerOperationRequestEnvelopeFor<T>;

type NearSignerWorkerPublicWasmOperationType = keyof WorkerRequestTypeMap;

export type NearSignerWorkerWasmOperationMap = {
  [T in NearSignerWorkerPublicWasmOperationType]: {
    payload: WorkerRequestTypeMap[T]['request'];
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
  CreateRouterAbEcdsaRegistrationCeremony: 70_005,
  VerifyRouterAbEcdsaRegistrationClientProofs: 70_006,
  CloseRouterAbEcdsaRegistrationCeremony: 70_007,
  FinalizeRouterAbEcdsaRegistrationActivation: 70_008,
  CreateRouterAbEcdsaPostRegistrationCeremony: 70_009,
  FinalizeRouterAbEcdsaExplicitExport: 70_010,
  CloseRouterAbEcdsaPostRegistrationCeremony: 70_011,
  StoreThresholdEcdsaRoleLocalSigningMaterial: 70_004,
  RehydrateEcdsaRoleLocalSigningMaterial: 70_015,
  PersistInitialCanonicalEcdsaActivation: 70_016,
  ReconcileCanonicalEcdsaActivation: 70_017,
  PrewarmEcdsaRegistrationCrypto: 70_018,
  VerifyRouterAbEcdsaPostRegistrationProofs: 70_019,
  SignWalletRecoveryEcdsaMaterialPossessionProof: 70_020,
  PrepareEcdsaAdditiveLaneHolder: 70_021,
  PrepareLinkedDeviceEcdsaSourceContribution: 70_022,
  StoreLinkedDeviceEcdsaHolderMaterial: 70_023,
  DisposeLinkedDeviceEcdsaHolderMaterials: 70_024,
  CreateEcdsaHolderOrdinaryExportRequest: 70_027,
  FinalizeEcdsaHolderOrdinaryExport: 70_028,
} as const;

export type EcdsaDerivationClientCustomRequestType =
  (typeof EcdsaDerivationClientCustomRequestType)[keyof typeof EcdsaDerivationClientCustomRequestType];

export const EcdsaDerivationClientCustomResponseType = {
  PrepareThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess: 70_100,
  FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess: 70_101,
  CreateRouterAbEcdsaRegistrationCeremonySuccess: 70_105,
  VerifyRouterAbEcdsaRegistrationClientProofsSuccess: 70_106,
  CloseRouterAbEcdsaRegistrationCeremonySuccess: 70_107,
  FinalizeRouterAbEcdsaRegistrationActivationSuccess: 70_108,
  CreateRouterAbEcdsaPostRegistrationCeremonySuccess: 70_109,
  FinalizeRouterAbEcdsaExplicitExportSuccess: 70_110,
  CloseRouterAbEcdsaPostRegistrationCeremonySuccess: 70_111,
  StoreThresholdEcdsaRoleLocalSigningMaterialSuccess: 70_104,
  RehydrateEcdsaRoleLocalSigningMaterialSuccess: 70_115,
  PersistInitialCanonicalEcdsaActivationSuccess: 70_116,
  ReconcileCanonicalEcdsaActivationSuccess: 70_117,
  PrewarmEcdsaRegistrationCryptoSuccess: 70_118,
  VerifyRouterAbEcdsaPostRegistrationProofsSuccess: 70_119,
  SignWalletRecoveryEcdsaMaterialPossessionProofSuccess: 70_120,
  PrepareEcdsaAdditiveLaneHolderSuccess: 70_121,
  PrepareLinkedDeviceEcdsaSourceContributionSuccess: 70_122,
  StoreLinkedDeviceEcdsaHolderMaterialSuccess: 70_123,
  DisposeLinkedDeviceEcdsaHolderMaterialsSuccess: 70_124,
  CreateEcdsaHolderOrdinaryExportRequestSuccess: 70_127,
  FinalizeEcdsaHolderOrdinaryExportSuccess: 70_128,
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

export type StoreLinkedDeviceEcdsaHolderMaterialRequestV1 = {
  readonly holderHandleId: string;
  readonly ownedSigningShare32: ArrayBuffer;
  readonly activationReceiptJson: string;
};

export type StoreLinkedDeviceEcdsaHolderMaterialResponseV1 = {
  readonly type: typeof EcdsaDerivationClientCustomResponseType.StoreLinkedDeviceEcdsaHolderMaterialSuccess;
  readonly payload: { readonly holderHandleId: string };
  readonly diagnostics?: WorkerResponseDiagnostics;
};

export type DisposeLinkedDeviceEcdsaHolderMaterialsRequestV1 =
  | {
      readonly kind: 'all';
      readonly holderHandleId?: never;
    }
  | {
      readonly kind: 'one';
      readonly holderHandleId: string;
    };

export type DisposeLinkedDeviceEcdsaHolderMaterialsResponseV1 = {
  readonly type: typeof EcdsaDerivationClientCustomResponseType.DisposeLinkedDeviceEcdsaHolderMaterialsSuccess;
  readonly payload:
    | { readonly kind: 'all'; readonly holderHandleId?: never }
    | { readonly kind: 'one'; readonly holderHandleId: string };
  readonly diagnostics?: WorkerResponseDiagnostics;
};

export type CreateEcdsaHolderOrdinaryExportRequestWorkerV1 =
  CreateEcdsaHolderOrdinaryExportRequestV1;

export type CreateEcdsaHolderOrdinaryExportResponseWorkerV1 = {
  readonly type: typeof EcdsaDerivationClientCustomResponseType.CreateEcdsaHolderOrdinaryExportRequestSuccess;
  readonly payload: CreateEcdsaHolderOrdinaryExportResultV1;
  readonly diagnostics?: WorkerResponseDiagnostics;
};

export type FinalizeEcdsaHolderOrdinaryExportRequestWorkerV1 =
  FinalizeEcdsaHolderOrdinaryExportRequestV1;

export type FinalizeEcdsaHolderOrdinaryExportResponseWorkerV1 = {
  readonly type: typeof EcdsaDerivationClientCustomResponseType.FinalizeEcdsaHolderOrdinaryExportSuccess;
  readonly payload: FinalizeEcdsaHolderOrdinaryExportResultV1;
  readonly diagnostics?: WorkerResponseDiagnostics;
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
          material:
            | {
                kind: 'persisted';
                materialRef: EcdsaRoleLocalPersistedMaterialRef;
                expectedBindingDigest?: never;
              }
            | {
                kind: 'runtime_loaded';
                expectedBindingDigest: string;
                materialRef?: never;
              };
        };
      }
    | {
        authority: {
          kind: 'linked_holder_signing_material';
          holderHandleId: string;
          materialHandle?: never;
          material?: never;
        };
      }
  );

export type EcdsaPresignClientSessionInitResult =
  | {
      authority: { kind: 'role_local_derivation_handle' };
      progress: ThresholdEcdsaPresignProgressResult;
    }
  | {
      authority: { kind: 'linked_holder_signing_material' };
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
  [EcdsaDerivationClientCustomRequestType.PersistInitialCanonicalEcdsaActivation]: {
    payload: PersistInitialCanonicalEcdsaActivationRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.PersistInitialCanonicalEcdsaActivationSuccess;
      payload: PersistInitialCanonicalEcdsaActivationResultV1;
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
  [EcdsaDerivationClientCustomRequestType.ReconcileCanonicalEcdsaActivation]: {
    payload: ReconcileCanonicalEcdsaActivationRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.ReconcileCanonicalEcdsaActivationSuccess;
      payload: ReconcileCanonicalEcdsaActivationWorkerResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.PrewarmEcdsaRegistrationCrypto]: {
    payload: Record<string, never>;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.PrewarmEcdsaRegistrationCryptoSuccess;
      payload: {
        kind: 'ecdsa_registration_crypto_prewarm_result_v1';
        wasmInitMs: number;
      };
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
  [EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaPostRegistrationProofs]: {
    payload: VerifyRouterAbEcdsaPostRegistrationProofsRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaPostRegistrationProofsSuccess;
      payload: VerifyRouterAbEcdsaPostRegistrationProofsResultV1;
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
  [EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial]: {
    payload: StoreThresholdEcdsaRoleLocalSigningMaterialRequest;
    result: StoreThresholdEcdsaRoleLocalSigningMaterialResponse;
  };
  [EcdsaDerivationClientCustomRequestType.StoreLinkedDeviceEcdsaHolderMaterial]: {
    payload: StoreLinkedDeviceEcdsaHolderMaterialRequestV1;
    result: StoreLinkedDeviceEcdsaHolderMaterialResponseV1;
  };
  [EcdsaDerivationClientCustomRequestType.DisposeLinkedDeviceEcdsaHolderMaterials]: {
    payload: DisposeLinkedDeviceEcdsaHolderMaterialsRequestV1;
    result: DisposeLinkedDeviceEcdsaHolderMaterialsResponseV1;
  };
  [EcdsaDerivationClientCustomRequestType.CreateEcdsaHolderOrdinaryExportRequest]: {
    payload: CreateEcdsaHolderOrdinaryExportRequestWorkerV1;
    result: CreateEcdsaHolderOrdinaryExportResponseWorkerV1;
  };
  [EcdsaDerivationClientCustomRequestType.FinalizeEcdsaHolderOrdinaryExport]: {
    payload: FinalizeEcdsaHolderOrdinaryExportRequestWorkerV1;
    result: FinalizeEcdsaHolderOrdinaryExportResponseWorkerV1;
  };
  [EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial]: {
    payload: RehydrateEcdsaRoleLocalSigningMaterialRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess;
      payload: RehydrateEcdsaRoleLocalSigningMaterialResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.SignWalletRecoveryEcdsaMaterialPossessionProof]: {
    payload: SignWalletRecoveryEcdsaMaterialPossessionProofRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.SignWalletRecoveryEcdsaMaterialPossessionProofSuccess;
      payload: SignWalletRecoveryEcdsaMaterialPossessionProofResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.PrepareEcdsaAdditiveLaneHolder]: {
    payload: PrepareEcdsaAdditiveLaneHolderRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.PrepareEcdsaAdditiveLaneHolderSuccess;
      payload: PrepareEcdsaAdditiveLaneHolderResultV1;
      diagnostics?: WorkerResponseDiagnostics;
    };
  };
  [EcdsaDerivationClientCustomRequestType.PrepareLinkedDeviceEcdsaSourceContribution]: {
    payload: PrepareLinkedDeviceEcdsaSourceContributionRequestV1;
    result: {
      type: typeof EcdsaDerivationClientCustomResponseType.PrepareLinkedDeviceEcdsaSourceContributionSuccess;
      payload: PrepareLinkedDeviceEcdsaSourceContributionResultV1;
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
  type: T;
  payload: EcdsaDerivationWorkerOperationEntry<T>['payload'];
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
  | typeof EcdsaDerivationClientCustomRequestType.PersistInitialCanonicalEcdsaActivation
  | typeof EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation
  | typeof EcdsaDerivationClientCustomRequestType.ReconcileCanonicalEcdsaActivation
  | typeof EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony
  | typeof EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony
  | typeof EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport
  | typeof EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony
  | typeof EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaPostRegistrationProofs
  | typeof EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap
  | typeof EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap
  | typeof EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial
  | typeof EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial
  | typeof EcdsaDerivationClientCustomRequestType.SignWalletRecoveryEcdsaMaterialPossessionProof
  | typeof EcdsaDerivationClientCustomRequestType.PrepareEcdsaAdditiveLaneHolder
  | typeof EcdsaDerivationClientCustomRequestType.PrepareLinkedDeviceEcdsaSourceContribution
  | typeof EcdsaDerivationClientCustomRequestType.StoreLinkedDeviceEcdsaHolderMaterial
  | typeof EcdsaDerivationClientCustomRequestType.DisposeLinkedDeviceEcdsaHolderMaterials;

export type EcdsaDerivationRoleLocalMaterialOperationRequest<
  T extends EcdsaDerivationRoleLocalMaterialOperationType,
> = EcdsaDerivationWorkerOperationRequest<T>;

export type EcdsaHolderOrdinaryExportOperationType =
  | typeof EcdsaDerivationClientCustomRequestType.CreateEcdsaHolderOrdinaryExportRequest
  | typeof EcdsaDerivationClientCustomRequestType.FinalizeEcdsaHolderOrdinaryExport;

export type EcdsaDerivationHolderOrdinaryExportOperationRequest<
  T extends EcdsaHolderOrdinaryExportOperationType,
> = EcdsaDerivationWorkerOperationRequest<T>;
/**
 * Refactor 103 zero-prompt handoff — the public reference to an unlocked
 * wallet Ed25519 export-root capability.
 *
 * The worker owns the opened custody-seed handle; this reference carries only
 * the opaque handle id and the binding facts the worker will re-verify before
 * sealing: exact wallet, issuing auth method, owner Wallet Session, and
 * expiry. It is volatile by construction — nothing here can be used to reopen
 * an envelope after the worker destroys the handle, so persisting it grants
 * nothing.
 */
export type UnlockedWalletEd25519ExportRootCapabilityV1 = {
  readonly kind: 'unlocked_wallet_ed25519_export_root_capability_v1';
  readonly capabilityHandleId: string;
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly walletSessionId: string;
  readonly expiresAtMs: number;
  /**
   * Present only when this unlock opened a pre-109C envelope and resealed it
   * under the method that authenticated. The caller persists it; until it does,
   * the old row stands and the next unlock produces the upgrade again, so a
   * failed write costs a retry rather than access.
   */
  readonly upgradedEnvelope?: PasskeyCustodyEnvelopeRecord;
};

/**
 * What a destroy call invalidates. Lock and logout destroy by wallet, session
 * retirement or replacement by Wallet Session, failed activation by capability
 * handle, and worker reset or page teardown destroys all.
 */
export type UnlockedWalletEd25519ExportRootCapabilityDestroyScopeV1 =
  | { readonly kind: 'capability'; readonly capabilityHandleId: string }
  | { readonly kind: 'wallet'; readonly walletId: string }
  | { readonly kind: 'wallet_session'; readonly walletSessionId: string }
  | { readonly kind: 'all' };

/**
 * One wallet custody ceremony run, one operation per step.
 *
 * A run provisions exactly one key set. It either *establishes* custody — the
 * wallet's first key set, where the seed is generated, its envelope sealed and
 * the recovery set issued — or *joins* custody that already exists, reaching the
 * same seed by opening that envelope and writing nothing but its own manifest.
 *
 * The run's state lives in the worker between these calls, keyed by
 * `ceremonyId`, because it holds the seed and the in-flight protocol state.
 * Nothing here carries custody material in either direction: `protocolInputs`
 * and `protocolResult` are public protocol messages, and the finish returns
 * ciphertext and public records.
 *
 * `factorSecret` is the one secret that crosses inbound — a passkey PRF result
 * or the Email OTP factor key. An establishing run sends it at the finish, to
 * seal; a joining run sends it at the begin, to open. The worker clears its own
 * copy either way.
 */
export interface WalletCustodyCeremonyWorkerOperationMap {
  openEd25519YaoLaneSource: {
    payload:
      | {
          kind: 'factor';
          factorSecret: ArrayBuffer;
          envelope: PasskeyCustodyEnvelopeRecord;
          applicationBindingDigestB64u: string;
        }
      | {
          kind: 'unlocked_ed25519_export_root_capability';
          capability: UnlockedWalletEd25519ExportRootCapabilityV1;
          applicationBindingDigestB64u: string;
          walletKeyId: string;
          enrollmentId: string;
          revocationEpoch: number;
          registeredPublicKeyB64u: string;
        };
    result: { sourceHandle: string };
  };
  prepareEd25519YaoLane: {
    payload: {
      sourceHandle: string;
      job: Ed25519YaoLaneJobV1;
      ceremonyBinding: RouterAbEd25519YaoCeremonyBindingV1;
      applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
      participantIds: readonly [number, number];
      deriverAInputPublicKeyB64u: string;
      deriverBInputPublicKeyB64u: string;
    };
    result: { sessionHandle: string; requestJson: string };
  };
  prepareEd25519YaoSourcePreservingRegistration: {
    payload: {
      sourceHandle: string;
      targetAdmission: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
      applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
      participantIds: readonly [number, number];
      expectedRegisteredPublicKeyB64u: string;
      targetClientRecipientPublicKeyB64u: string;
    };
    result: { requestJson: string };
  };
  completeEd25519YaoLane: {
    payload: { sessionHandle: string; responseJson: string };
    result: Ed25519YaoLaneClientCompletionV1;
  };
  discardEd25519YaoLaneSource: {
    payload: { sourceHandle: string };
    result: { discarded: boolean };
  };
  beginWalletCustodyKeySetRun: {
    payload:
      | {
          ceremonyId: string;
          keySet: 'near_ed25519_v1';
          custody:
            | { origin: 'establish'; walletId: string }
            | { origin: 'join'; custodyJson: string; factorSecret: ArrayBuffer }
            | { origin: 'recover'; custodyJson: string; recoveryCode: ArrayBuffer }
            | {
                origin: 'recover_and_reseal';
                custodyJson: string;
                recoveryCode: ArrayBuffer;
                replacementFactorJson: string;
                replacementFactorSecret: ArrayBuffer;
              };
          protocolInputsJson: string;
        }
      | {
          ceremonyId: string;
          keySet: 'evm_family_ecdsa_v1';
          custody:
            | {
                origin: 'establish';
                walletId: string;
                factorJson: string;
                factorSecret: ArrayBuffer;
                recoveryCodesJson: string;
              }
            | { origin: 'join'; custodyJson: string; factorSecret: ArrayBuffer }
            | { origin: 'recover'; custodyJson: string; recoveryCode: ArrayBuffer }
            | {
                origin: 'recover_and_reseal';
                custodyJson: string;
                recoveryCode: ArrayBuffer;
                replacementFactorJson: string;
                replacementFactorSecret: ArrayBuffer;
              };
          protocolInputsJson: string;
          evmFamilySigningKeySlotId: string;
          recordedKeyManifestDigestB64u?: string;
        };
    result:
      | {
          ceremonyId: string;
          keySet: 'near_ed25519_v1';
          yaoExecuteRequestJson: string;
        }
      | {
          ceremonyId: string;
          keySet: 'evm_family_ecdsa_v1';
          ecdsaContextBinding32B64u: string;
          ecdsaClientSharePublicKey33B64u: string;
          ecdsaClientShareRetryCounter: number;
          preActivationCommitPayload: WalletCustodyCeremonyCommitPayload;
        };
  };
  completeWalletCustodyKeySetRun: {
    payload:
      | {
          ceremonyId: string;
          keySet: 'near_ed25519_v1';
          protocolResultJson: string;
          nearEd25519SigningKeyId: string;
          recordedKeyManifestDigestB64u?: string;
        }
      | {
          ceremonyId: string;
          keySet: 'evm_family_ecdsa_v1';
          protocolResultJson: string;
        };
    result:
      | { ceremonyId: string; keySet: 'near_ed25519_v1' }
      | {
          ceremonyId: string;
          keySet: 'evm_family_ecdsa_v1';
          activation: WalletCustodyEvmFamilyActivationCompletion;
        };
  };
  finishWalletCustodyKeySetRun: {
    payload: {
      ceremonyId: string;
      finish:
        | { kind: 'existing' }
        | {
            kind: 'establish';
            factorJson: string;
            factorSecret: ArrayBuffer;
            recoveryCodesJson: string;
          }
        | {
            kind: 'recover_reseal';
            replacementFactorJson: string;
            replacementFactorSecret: ArrayBuffer;
          };
    };
    result: WalletCustodyCeremonyCommitPayload;
  };
  linkWalletCustodyPasskey: {
    payload: {
      existingEnvelope: PasskeyCustodyEnvelopeRecord;
      existingFactorSecret: ArrayBuffer;
      replacementEnvelopeBindingJson: string;
      replacementFactorSecret: ArrayBuffer;
    };
    result: {
      nonceB64u: string;
      sealedCustodySecretB64u: string;
      aadHashB64u: string;
      ciphertextDigestB64u: string;
    };
  };
  /**
   * Device 2: generates the X25519 recipient key Device 1 will seal the wallet
   * custody seed to. The private half stays inside this worker under the
   * returned handle; only the public key crosses back.
   */
  createLinkedDeviceEd25519ExportRootRecipient: {
    payload: Record<string, never>;
    result: { recipientHandleId: string; recipientPublicKeyB64u: string };
  };
  /**
   * Refactor 103 zero-prompt handoff: opens the wallet custody seed envelope
   * with the factor secret already present in registration or ordinary unlock,
   * and parks the opened handle inside this worker for the lifetime of the
   * owner Wallet Session that authorized it. The result is the public
   * reference only — no seed bytes, and no serializable secret.
   *
   * At most one capability exists per wallet and owner Wallet Session;
   * establishing a new one destroys the previous handle first.
   */
  establishUnlockedWalletEd25519ExportRootCapability: {
    payload: {
      existingEnvelope: PasskeyCustodyEnvelopeRecord;
      existingFactorSecret: ArrayBuffer;
      walletId: string;
      walletAuthMethodId: string;
      walletSessionId: string;
      expiresAtMs: number;
    };
    result: UnlockedWalletEd25519ExportRootCapabilityV1;
  };
  /**
   * Destroys unlocked Ed25519 export-root capabilities. Wired into lock, logout,
   * wallet switch, Wallet Session retirement or replacement, expiry, failed
   * activation, and page teardown; `all` is the worker-reset scope.
   */
  destroyUnlockedWalletEd25519ExportRootCapabilities: {
    payload: { scope: UnlockedWalletEd25519ExportRootCapabilityDestroyScopeV1 };
    result: { destroyedCount: number };
  };
  /**
   * Device 1: seals the wallet custody seed for one approved linked device
   * from the worker-held unlocked capability. The seed and the derived
   * transfer key never leave the worker; a wallet, auth-method, Wallet
   * Session, or expiry mismatch fails before any ciphertext exists. Each call
   * draws a fresh X25519 ephemeral key and nonce.
   */
  /**
   * Refactor 109C: reseals this wallet's seed under a new factor, from the
   * capability an unlock already opened.
   *
   * For an addition whose source is Email OTP. The source factor secret is
   * already in the worker, so the addition costs no factor release and no
   * second one-time code — the fresh code the user typed authorized the
   * ceremony, and the seed comes from the handle unlock opened.
   */
  resealWalletCustodyFromUnlockedCapability: {
    payload: {
      capability: UnlockedWalletEd25519ExportRootCapabilityV1;
      replacementEnvelopeBindingJson: string;
      replacementFactorSecret: ArrayBuffer;
    };
    result: {
      nonceB64u: string;
      sealedCustodySecretB64u: string;
      aadHashB64u: string;
      ciphertextDigestB64u: string;
    };
  };
  sealEd25519ExportRootForLinkedDevice: {
    payload: {
      capability: UnlockedWalletEd25519ExportRootCapabilityV1;
      transferBindingJson: string;
    };
    result: {
      ephemeralPublicKeyB64u: string;
      nonceB64u: string;
      sealedExportRootB64u: string;
      bindingDigestB64u: string;
      ciphertextDigestB64u: string;
    };
  };
  /**
   * Device 2: opens the transfer with its recipient handle and immediately
   * reseals the seed under the passkey it just created. One operation rather
   * than two so the opened seed never sits in a handle JavaScript could hold
   * across a turn.
   */
  acceptLinkedDeviceEd25519ExportRoot: {
    payload: {
      recipientHandleId: string;
      transferBindingJson: string;
      ephemeralPublicKeyB64u: string;
      nonceB64u: string;
      sealedExportRootB64u: string;
      bindingDigestB64u: string;
      ciphertextDigestB64u: string;
      replacementEnvelopeBindingJson: string;
      replacementFactorSecret: ArrayBuffer;
    };
    result: {
      nonceB64u: string;
      sealedExportRootB64u: string;
      aadHashB64u: string;
      ciphertextDigestB64u: string;
    };
  };
  /** Zeroizes a recipient handle on cancel, failure, or page teardown. */
  discardLinkedDeviceEd25519ExportRootRecipient: {
    payload: { recipientHandleId: string };
    result: { recipientHandleId: string; discarded: boolean };
  };
  rotateWalletRecoverySet: {
    payload: {
      custodyJson: string;
      factorSecret: ArrayBuffer;
      recoveryCodesJson: string;
    };
    result: WalletRecoverySetRotationWorkerResultV1;
  };
  discardWalletCustodyCeremony: {
    payload: { ceremonyId: string };
    result: { ceremonyId: string; discarded: boolean };
  };
}

export interface SignerWorkerOperationMapByKind {
  nearSigner: NearSignerWorkerOperationMap;
  ecdsaDerivationClient: DerivationSignerWorkerOperationMap;
  ecdsaPresignClient: EcdsaPresignClientOperationMap;
  ecdsaOnlineClient: EcdsaOnlineClientOperationMap;
  evmCrypto: EvmCryptoWorkerOperationMap;
  tempoSigner: TempoSignerWorkerOperationMap;
  emailOtp: EmailOtpWorkerOperationMap;
  walletCustodyCeremony: WalletCustodyCeremonyWorkerOperationMap;
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
