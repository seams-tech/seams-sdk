import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import type {
  NearProvisioningState,
  NearProvisioningWriteV1,
  WalletAuthenticationState,
} from '@/core/types/seams';
import type { WalletId } from '@shared/utils/registrationIntent';
import type {
  ThresholdEcdsaChainTarget,
  WalletId as EcdsaWalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ProvisionWarmEd25519CapabilityResult } from '@/core/signingEngine/session/warmCapabilities/types';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type {
  AvailableSigningLanes,
  ReadAvailableSigningLanesInput,
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
} from '@/core/signingEngine/session/public';
import type { ExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import type { ReusableWalletSessionState } from '@/core/types/seams';
import type {
  NearSignIntentRequest,
  NearSignIntentResult,
} from '@/core/signingEngine/flows/signNear/signNear';
import type {
  ReconcileTempoNonceLaneArgs as RuntimeReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs as RuntimeReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs as RuntimeReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs as RuntimeReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs as RuntimeReportTempoFinalizedArgs,
  TempoNonceLaneStatus as RuntimeTempoNonceLaneStatus,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { ProductEd25519YaoCapabilityActivationPortV1 } from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import type { Ed25519YaoActiveClientIdentityV1 } from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import type {
  Ed25519YaoPublicCapabilityLaneReferenceV1,
  Ed25519YaoPublicCapabilityReferenceV1,
} from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import type { AccountId } from '@/core/types/accountIds';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { ImportWalletCustodyEcdsaContinuityInput } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import type { EcdsaRoleLocalPersistedMaterialRef } from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/nearAccountData.types';
import type { SeamsConfigsReadonly, SigningSessionStatus, ThemeMode } from '@/core/types/seams';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type {
  RegistrationWebAuthnPromptOwner,
  ReservedRegistrationWebAuthnPrompt,
  WebAuthnPromptCancellation,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import type {
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
  SigningEngineExportKeypairWithUIInput,
} from '@/core/signingEngine/flows/recovery/public';
import type {
  StoreAuthenticatorInput,
  StoredRegistrationData,
  StoredWalletEd25519SignerRegistration,
  StoreWalletEcdsaRegistrationInput,
  StoreWalletEcdsaWalletKey,
  StoreWalletEcdsaSignerRecordsInput,
  StoreWalletEcdsaSignerRecordsResult,
  StoreWalletEd25519RegistrationInput,
  StoreWalletEd25519SignerRecordInput,
  StoreWalletMixedRegistrationInput,
  StoreWalletMixedRegistrationResult,
  StoreWalletEmailOtpEd25519RegistrationInput,
  StoreWalletEmailOtpMixedRegistrationInput,
  StoreWalletEmailOtpMixedRegistrationResult,
  StoreWalletEmailOtpEcdsaRegistrationInput,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { FinalizeWalletRegistrationEcdsaSessionsInput } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type {
  CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  PersistInitialCanonicalEcdsaActivationRequestV1,
  PersistInitialCanonicalEcdsaActivationResultV1,
  VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  VerifyRouterAbEcdsaRegistrationClientProofsResultV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { ConnectEd25519SessionArgs } from '@/core/signingEngine/session/passkey/public';
import type { HydrateWarmSigningSessionInput } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type { LoginWithEmailOtpWalletCustodyEd25519Args } from '@/core/signingEngine/walletCustody/ed25519Login';
import type { EmailOtpEd25519YaoRecoveryBootstrapV1 } from '@/core/signingEngine/workerManager/workerTypes';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type { RouterAbEd25519YaoRegistrationAdmissionRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import type { RouterAbTraceContextV1 } from '@shared/utils/routerAbTraceContext';
import type {
  WalletCustodyCeremonyCommitPayload,
  WalletCustodyEvmFamilyPublicFacts,
} from '@shared/passkey-custody';
import type {
  LoadWalletCustodyEd25519MaterialResultV1,
  WalletCustodyEd25519MaterialBindingV1,
  WalletCustodySealedEd25519MaterialV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import type { EmailOtpAppSessionBinding } from '@/core/signingEngine/session/emailOtp/appSessionJwtCache';
import type { WalletCustodyEd25519Projection } from '@/core/signingEngine/walletCustody/ed25519Projection';
import type {
  EnrollEmailOtpInternalArgs,
  EnrollEmailOtpInternalResult,
  LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  LoginWithEmailOtpEcdsaCapabilityInternalResult,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
  RotateEmailOtpRecoveryCodesInternalArgs,
  RotateEmailOtpRecoveryCodesInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  WarmSessionSealAndPersistResult,
  WarmSessionSealTransportInput,
} from '@/core/types/secure-confirm-worker';
import type { SdkLifecycleEventListener, SigningFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  WorkerResourceWarmupAccountContext,
  WorkerResourceWarmupDiagnostics,
} from '@/core/signingEngine/assembly/warmup';
import type { EmailOtpYaoPrewarmOutcome } from '@/core/signingEngine/workerManager/workerTypes';

export interface RpIdSurface {
  getRpId(): string;
}

export interface SignerWorkerContextSurface {
  getSignerWorkerContext(): WorkerOperationContext;
}

export interface NonceCoordinatorSurface {
  getNonceCoordinator(): NonceCoordinator;
}

export interface NearSigningSurface extends NonceCoordinatorSurface {
  signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>>;
}

export interface EvmFamilySigningSurface {
  signEvmFamily(args: {
    walletSession: WalletSessionRef;
    request: TempoSigningRequest | EvmSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult>;
}

export interface TempoNonceLifecycleSurface {
  reportTempoBroadcastAccepted(args: RuntimeReportTempoBroadcastAcceptedArgs): Promise<void>;
  reportTempoBroadcastRejected(args: RuntimeReportTempoBroadcastRejectedArgs): Promise<void>;
  reportTempoFinalized(args: RuntimeReportTempoFinalizedArgs): Promise<void>;
  reportTempoDroppedOrReplaced(args: RuntimeReportTempoDroppedOrReplacedArgs): Promise<void>;
  reconcileTempoNonceLane(
    args: RuntimeReconcileTempoNonceLaneArgs,
  ): Promise<RuntimeTempoNonceLaneStatus>;
}

export interface EcdsaSessionBootstrapSurface {
  bootstrapEcdsaSession(args: EcdsaBootstrapRequest): Promise<ThresholdEcdsaSessionBootstrapResult>;
}

export type TempoSigningSurface = EvmFamilySigningSurface &
  TempoNonceLifecycleSurface &
  EcdsaSessionBootstrapSurface;

export interface WalletIframeWarmupSurface {
  warmCriticalResources(
    accountContext?: WorkerResourceWarmupAccountContext,
  ): Promise<WorkerResourceWarmupDiagnostics>;
}

export interface RegistrationResourceWarmupSurface {
  prewarmEmailOtpYao(): Promise<EmailOtpYaoPrewarmOutcome>;
  /* Refactor 94C: ECDSA WASM init during the auth prompt; fire-and-forget. */
  prewarmEcdsaRegistrationCrypto(): Promise<{ kind: 'succeeded' | 'failed'; wasmInitMs: number }>;
}

export interface RuntimeStartupSurface {
  assertSealedRefreshStartupParity(): Promise<void>;
}

export type WalletAuthenticationRestoreAuth =
  | { readonly kind: 'cookie' }
  | { readonly kind: 'caller_app_session_jwt'; readonly appSessionJwt: string };

export interface SigningEngineLifecycleEventSurface {
  onSdkLifecycleEvent(listener: SdkLifecycleEventListener): () => void;
}

export interface UserProfileStoreSurface {
  storeUserData(userData: StoreUserDataInput): Promise<void>;
  getAllUsers(): Promise<ClientUserData[]>;
  getUserBySignerSlot(nearAccountId: AccountId, signerSlot: number): Promise<ClientUserData | null>;
  getLastUser(): Promise<ClientUserData | null>;
  nearAuthenticatorsByAccount(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]>;
  setLastUser(walletId: WalletId, signerSlot: number): Promise<void>;
}

export type UserAccountLookupSurface = Pick<
  UserProfileStoreSurface,
  'getUserBySignerSlot' | 'getLastUser' | 'nearAuthenticatorsByAccount'
>;

export interface EcdsaLoginSessionSurface {
  scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(args: {
    walletId: EcdsaWalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    manifest: ActiveEcdsaCapabilityManifest;
    runtime: ExactEcdsaSealedRuntime;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult>;
}

export interface Ed25519SessionConnectionSurface {
  connectEd25519Session(
    args: ConnectEd25519SessionArgs,
  ): Promise<ProvisionWarmEd25519CapabilityResult>;
}

export type LoginWarmSigningSurface = RuntimeStartupSurface &
  EcdsaSessionBootstrapSurface &
  Ed25519SessionConnectionSurface &
  WorkerOperationContext &
  Pick<SigningSessionSurface, 'hydrateSigningSession'> &
  NonceCoordinatorSurface &
  RpIdSurface;

export interface RegistrationAccountSurface {
  /* Refactor 94 Phase 6. Durable NEAR provisioning state on the wallet root
     profile. This is authoritative; the page registry mirrors it. */
  setWalletNearProvisioningState(write: NearProvisioningWriteV1): Promise<void>;
  getWalletNearProvisioningState(walletId: EcdsaWalletId): Promise<NearProvisioningState | null>;
  activateAuthenticatedWalletState(args: {
    walletId: EcdsaWalletId;
    nearAccountId: AccountId;
    signerSlot: number;
    nearClient?: NearClient;
  }): Promise<void>;
  upsertEd25519YaoPublicCapabilityReference(
    identity: Ed25519YaoPublicCapabilityReferenceV1,
  ): Promise<void>;
  upsertEd25519YaoPublicCapabilityLaneReference(
    reference: Ed25519YaoPublicCapabilityLaneReferenceV1,
  ): Promise<void>;
  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void>;
  rollbackUserRegistration(nearAccountId: AccountId): Promise<void>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  storeWalletEd25519RegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletMixedRegistrationData(
    input: StoreWalletMixedRegistrationInput,
  ): Promise<StoreWalletMixedRegistrationResult>;
  storeWalletEd25519RecoveryRegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpEd25519RegistrationData(
    input: StoreWalletEmailOtpEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpMixedRegistrationData(
    input: StoreWalletEmailOtpMixedRegistrationInput,
  ): Promise<StoreWalletEmailOtpMixedRegistrationResult>;
  finalizeWalletEd25519SignerRegistration(
    input: StoreWalletEd25519SignerRecordInput,
  ): Promise<StoredWalletEd25519SignerRegistration>;
  rollbackWalletEd25519SignerRegistration(
    receipt: StoreWalletSignerFinalizeRollbackReceipt,
  ): Promise<void>;
}

export interface EcdsaRegistrationSurface {
  createRouterAbEcdsaRegistrationCeremony(
    input: CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  ): Promise<CreateRouterAbEcdsaRegistrationCeremonyResultV1>;
  verifyRouterAbEcdsaRegistrationClientProofs(
    input: VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  ): Promise<VerifyRouterAbEcdsaRegistrationClientProofsResultV1>;
  persistInitialCanonicalEcdsaActivation(
    input: PersistInitialCanonicalEcdsaActivationRequestV1,
  ): Promise<PersistInitialCanonicalEcdsaActivationResultV1>;
  finalizeRouterAbEcdsaRegistrationActivation(
    input: FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  ): Promise<FinalizeRouterAbEcdsaRegistrationActivationResultV1>;
  closeRouterAbEcdsaRegistrationCeremony(
    input: CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  ): Promise<CloseRouterAbEcdsaRegistrationCeremonyResultV1>;
  finalizeWalletRegistrationEcdsaSessions(
    input: FinalizeWalletRegistrationEcdsaSessionsInput,
  ): Promise<readonly [StoreWalletEcdsaWalletKey, ...StoreWalletEcdsaWalletKey[]]>;
  storeWalletEcdsaSignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEcdsaRecoverySignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEmailOtpEcdsaSignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  finalizeWalletEcdsaRegistration(
    input: StoreWalletEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEmailOtpEcdsaRegistrationData(
    input: StoreWalletEmailOtpEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
}

export type Ed25519YaoRegistrationActivationSurface = ProductEd25519YaoCapabilityActivationPortV1;

/**
 * Running one wallet custody key set from the registration flow.
 *
 * A port rather than direct worker access, for the same reason every other
 * signing operation is one: the operations layer never holds a worker handle.
 * It matters more here — a run's seed lives in the ceremony worker's wasm state
 * across three steps, so the flow that starts a run must not be able to route
 * one of its steps somewhere else.
 *
 * The result deliberately splits what leaves the device from what stays on it.
 * `commitPayload` is the wire projection; `localMaterial` is the continuity
 * cache and never crosses.
 */
export interface WalletCustodyCeremonySurface {
  establishWalletCustodyNearEd25519KeySet(args: {
    walletId: string;
    factorJson: string;
    factorSecret: ArrayBuffer;
    nearEd25519SigningKeyId: string;
    registrationCeremonyId: string;
    admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    admissionReceipt: unknown;
    participantIds: readonly [number, number];
    routerOrigin: string;
    /** The signed setup: the Router authorizes the execute round against it. */
    authorization: string;
    traceContext?: RouterAbTraceContextV1;
  }): Promise<EstablishedWalletCustodyNearEd25519KeySetV1>;

  joinWalletCustodyNearEd25519KeySet(args: {
    custodyJson: string;
    factorSecret: ArrayBuffer;
    nearEd25519SigningKeyId: string;
    registrationCeremonyId: string;
    admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    admissionReceipt: unknown;
    participantIds: readonly [number, number];
    routerOrigin: string;
    authorization: string;
    traceContext?: RouterAbTraceContextV1;
  }): Promise<JoinedWalletCustodyNearEd25519KeySetV1>;

  rejoinWalletCustodyNearEd25519KeySet(args: {
    walletId: string;
    custodyJson: string;
    factorSecret: ArrayBuffer;
    nearEd25519SigningKeyId: string;
    registrationCeremonyId: string;
    admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    admissionReceipt: unknown;
    participantIds: readonly [number, number];
    registeredPublicKeyB64u: string;
    routerOrigin: string;
    walletSessionJwt: string;
  }): Promise<JoinedWalletCustodyNearEd25519KeySetV1>;

  establishWalletCustodyEvmFamilyKeySet(args: {
    walletId: string;
    factorJson: string;
    factorSecret: ArrayBuffer;
    evmFamilySigningKeySlotId: string;
    applicationBindingDigestB64u: string;
    confirmRecoveryCodesBackedUp: (recoveryCodes: readonly string[]) => Promise<void>;
    runRelayerRound: (bootstrap: {
      contextBinding32B64u: string;
      clientSharePublicKey33B64u: string;
      clientShareRetryCounter: number;
      preActivationCommitPayload: WalletCustodyCeremonyCommitPayload;
    }) => Promise<string>;
  }): Promise<EstablishedWalletCustodyEvmFamilyKeySetV1>;

  joinWalletCustodyEvmFamilyKeySet(args: {
    walletId: string;
    custodyJson: string;
    factorSecret: ArrayBuffer;
    evmFamilySigningKeySlotId: string;
    applicationBindingDigestB64u: string;
    runRelayerRound: (bootstrap: {
      contextBinding32B64u: string;
      clientSharePublicKey33B64u: string;
      clientShareRetryCounter: number;
      preActivationCommitPayload: WalletCustodyCeremonyCommitPayload;
    }) => Promise<string>;
  }): Promise<JoinedWalletCustodyEvmFamilyKeySetV1>;

  rejoinWalletCustodyEvmFamilyKeySet(args: {
    walletId: string;
    custodyJson: string;
    factorSecret: ArrayBuffer;
    evmFamilySigningKeySlotId: string;
    applicationBindingDigestB64u: string;
    registeredClientRootPublicKey33B64u: string;
    relayerPublicIdentityJson: string;
  }): Promise<RejoinedWalletCustodyEvmFamilyKeySetV1>;

  restoreWalletCustodyEcdsaContinuity(
    args: Omit<ImportWalletCustodyEcdsaContinuityInput, 'store'>,
  ): Promise<{
    readonly materialActivation: MpcMaterialActivationRef;
    readonly materialRef: EcdsaRoleLocalPersistedMaterialRef;
  }>;

  /**
   * Persists the wallet-scoped continuity cache the ceremony sealed.
   *
   * Separate from establishing it because the record can only be written once
   * the wallet profile exists, which registration creates between the two.
   */
  persistWalletCustodyEd25519Material(args: {
    binding: WalletCustodyEd25519MaterialBindingV1;
    sealed: WalletCustodySealedEd25519MaterialV1;
  }): Promise<void>;

  loadWalletCustodyEd25519Material(args: {
    nearAccountId: string;
    signerSlot: number;
    expectedRegisteredPublicKeyB64u: string;
  }): Promise<LoadWalletCustodyEd25519MaterialResultV1>;

  deleteWalletCustodyEd25519Material(args: {
    nearAccountId: string;
    signerSlot: number;
  }): Promise<void>;
}

/**
 * What one established NEAR key set hands back to the registration flow.
 *
 * `recoveryCodes` are the only copy: the wraps are one-way, so a caller that
 * discards them has issued ten codes nobody can ever produce.
 */
export type EstablishedWalletCustodyNearEd25519KeySetV1 = {
  readonly recoveryCodes: readonly string[];
  readonly commitPayload: WalletCustodyCeremonyCommitPayload;
  readonly activationReference: {
    readonly kind: 'router_ab_ed25519_yao_activation_reference_v1';
    readonly lifecycle_id: string;
    readonly session_id: readonly number[];
  };
  /** Rebuilt from the Router's receipt; every identity on it is the Router's. */
  readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  /** The same-device cache. Stays on the device by construction. */
  readonly localMaterial: {
    readonly b64u: string;
    readonly nonceB64u: string;
    readonly applicationBindingDigestB64u: string;
  };
};

export type JoinedWalletCustodyNearEd25519KeySetV1 = Omit<
  EstablishedWalletCustodyNearEd25519KeySetV1,
  'recoveryCodes'
>;

export type EstablishedWalletCustodyEvmFamilyKeySetV1 = {
  readonly recoveryCodes: readonly string[];
  readonly commitPayload: WalletCustodyCeremonyCommitPayload;
  readonly clientBootstrap: {
    readonly contextBinding32B64u: string;
    readonly derivationClientSharePublicKey33B64u: string;
    readonly clientShareRetryCounter: number;
    readonly participantId: 1;
  };
  readonly localMaterial: {
    readonly readyStateBlobB64u: string;
    readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
  };
};

export type RejoinedWalletCustodyEvmFamilyKeySetV1 = {
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

export type JoinedWalletCustodyEvmFamilyKeySetV1 = Omit<
  EstablishedWalletCustodyEvmFamilyKeySetV1,
  'recoveryCodes'
>;

export interface Ed25519MaterialOwnerQueueSurface {
  withExactEd25519MaterialOwner<T>(args: {
    materialActivation: MpcMaterialActivationRef;
    nearAccountId: AccountId;
    task: () => Promise<T>;
  }): Promise<T>;
}

export interface SigningSessionSurface {
  hydrateSigningSession(input: HydrateWarmSigningSessionInput): Promise<void>;
  persistSigningSessionSealForThresholdSession(input: {
    thresholdSessionId: string;
    transport: Exclude<WarmSessionSealTransportInput, { authMethod: 'email_otp' }>;
  }): Promise<WarmSessionSealAndPersistResult>;
  readReusableWalletSessionState(walletId: WalletId | string): Promise<ReusableWalletSessionState>;
  discoverPersistedSessionsForWallet(
    args: DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult>;
  readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes>;
}

export interface WalletAuthenticationSurface {
  readWalletAuthenticationState(): WalletAuthenticationState;
  restoreWalletAuthenticationState(
    walletId: WalletId | string | undefined,
    auth: WalletAuthenticationRestoreAuth,
  ): Promise<WalletAuthenticationState>;
  restoreWalletAuthenticationStateFromHostSession(
    walletId: WalletId | string | undefined,
  ): Promise<WalletAuthenticationState>;
  setWalletAuthenticated(
    state: Extract<WalletAuthenticationState, { kind: 'authenticated' }>,
  ): void;
  clearWalletAuthentication(): void;
}

export interface WarmSessionStatusSurface {
  getWarmThresholdEd25519SessionStatus(args: {
    walletId: WalletId | string;
    nearAccountId: AccountId | string;
    nearEd25519SigningKeyId: string;
  }): Promise<SigningSessionStatus | null>;
}

export type WalletSessionReadSurface = RuntimeStartupSurface &
  SignerWorkerContextSurface &
  NonceCoordinatorSurface &
  UserAccountLookupSurface &
  WarmSessionStatusSurface &
  Pick<
    WalletAuthenticationSurface,
    'readWalletAuthenticationState' | 'restoreWalletAuthenticationState'
  > &
  Pick<
    SigningSessionSurface,
    'readReusableWalletSessionState' | 'readPersistedAvailableSigningLanes'
  >;

export type LoginUnlockSigningSurface = WalletSessionReadSurface &
  UserAccountLookupSurface &
  LoginWarmSigningSurface &
  Ed25519YaoRegistrationActivationSurface &
  Ed25519MaterialOwnerQueueSurface &
  Pick<WalletCustodyCeremonySurface, 'loadWalletCustodyEd25519Material'> &
  EcdsaLoginSessionSurface &
  PasskeyLoginAssertionSurface &
  Pick<EcdsaSessionControlSurface, 'clearVolatileWarmSigningMaterial'> &
  Pick<UserProfileStoreSurface, 'setLastUser'> &
  // Unlock must activate the NEAR account projection, not just write the
  // wallet-profile last-user pointer — see persistSuccessfulLoginState. The
  // restore path (LocalLoginStateSurface) already pairs these two for the same
  // reason.
  Pick<RegistrationAccountSurface, 'activateAuthenticatedWalletState'> &
  Pick<WalletAuthenticationSurface, 'setWalletAuthenticated'> &
  Pick<WarmSessionStatusSurface, 'getWarmThresholdEd25519SessionStatus'>;

export type RecentUnlocksSigningSurface = Pick<
  UserProfileStoreSurface,
  'getAllUsers' | 'getLastUser'
>;

export interface EcdsaSessionControlSurface {
  clearVolatileWarmSigningMaterial(walletId?: EcdsaWalletId): Promise<void>;
  clearThresholdEcdsaSigningQueue(): void;
}

export type LockSigningSurface = NonceCoordinatorSurface &
  EcdsaSessionControlSurface &
  Pick<WalletAuthenticationSurface, 'clearWalletAuthentication'>;

export type LocalLoginStateSurface = WalletSessionReadSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'setLastUser' | 'activateAuthenticatedWalletState'
  >;

export type AccountSyncSigningSurface = LocalLoginStateSurface &
  Ed25519YaoRegistrationActivationSurface &
  WalletCustodyCeremonySurface &
  Ed25519MaterialOwnerQueueSurface &
  Pick<EcdsaSessionControlSurface, 'clearVolatileWarmSigningMaterial'> &
  RpIdSurface &
  PasskeyLoginAssertionSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'storeUserData' | 'storeAuthenticator' | 'upsertEd25519YaoPublicCapabilityLaneReference'
  >;

export interface WebAuthnRegistrationConfirmationSurface {
  openRegistrationPreparationModal(params: {
    walletLabel: string;
    signerSlot: number;
  }): Promise<void>;
  closeRegistrationPreparationModal(): void;
  requestRegistrationCredentialConfirmation(params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
  }): Promise<RegistrationCredentialConfirmationPayload>;
  startPreparedPasskeyRegistrationCredential(args: {
    walletId: string;
    signerSlot: number;
    challengeB64u: string;
    expectedRpId: string;
    reservation: ReservedRegistrationWebAuthnPrompt;
    owner: RegistrationWebAuthnPromptOwner;
    cancellation: { kind: 'abort_signal'; signal: AbortSignal };
  }): Promise<WebAuthnRegistrationCredential>;
}

export interface PasskeyLoginAssertionSurface {
  getAuthenticationCredentialsSerialized(args: {
    subjectId: string;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
    cancellation?: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>;
  }): Promise<WebAuthnAuthenticationCredential>;
}

export interface EmailOtpSigningSessionSurface {
  rememberEmailOtpAppSessionBinding(binding: EmailOtpAppSessionBinding): void;
  rememberEmailOtpAppSessionJwt(walletId: WalletId, appSessionJwt: string): void;
  resolveEmailOtpEd25519CustodyProjectionInternal(args: {
    walletSession: WalletSessionRef;
  }): Promise<WalletCustodyEd25519Projection | null>;
  activateEmailOtpEd25519CustodyCapabilityInternal(args: {
    walletSession: WalletSessionRef;
    providerSubject: string;
    emailHashHex: string;
    signerSlot: number;
    expectedOperationalPublicKey: string;
    expectedThresholdSessionId: string;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    activeClientHandle: string;
    metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  }): Promise<NearEd25519SignerBinding>;
  loginWithEmailOtpWalletCustodyEd25519Internal(
    args: LoginWithEmailOtpWalletCustodyEd25519Args,
  ): Promise<NearEd25519SignerBinding>;
  loginWithEmailOtpEcdsaCapabilityInternal(
    args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult>;
  requestEmailOtpSigningSessionChallenge(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<{ challengeId: string; emailHint?: string }>;
  refreshEmailOtpSigningSession(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
  }): Promise<{
    recovery: EmailOtpBootstrapRecovery;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    authorization: ActiveWalletSessionAuthorizationProjection;
    authorizations: readonly [
      ActiveWalletSessionAuthorizationProjection,
      ...ActiveWalletSessionAuthorizationProjection[],
    ];
  }>;
  resolveEmailOtpAppSessionJwt(args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }): Promise<string>;
  enrollEmailOtpInternal(args: EnrollEmailOtpInternalArgs): Promise<EnrollEmailOtpInternalResult>;
  rotateEmailOtpRecoveryCodesInternal(
    args: RotateEmailOtpRecoveryCodesInternalArgs,
  ): Promise<RotateEmailOtpRecoveryCodesInternalResult>;
}

export interface KeyExportSigningSurface {
  resolveExactKeyExportLane(
    input: SigningEngineResolveExactKeyExportLaneInput,
  ): Promise<SigningEngineResolveExactKeyExportLaneResult>;
  exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }>;
}

export interface EmailOtpRegistrationEnrollmentSurface {
  prepareEmailOtpRegistrationEnrollmentMaterialInternal(
    args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  ): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult>;
}

export type RegistrationSigningSurface = RpIdSurface &
  Ed25519YaoRegistrationActivationSurface &
  WalletCustodyCeremonySurface &
  Pick<WalletIframeWarmupSurface, 'warmCriticalResources'> &
  RegistrationResourceWarmupSurface &
  Pick<
    SigningSessionSurface,
    'hydrateSigningSession' | 'persistSigningSessionSealForThresholdSession'
  > &
  Pick<
    EmailOtpRegistrationEnrollmentSurface,
    'prepareEmailOtpRegistrationEnrollmentMaterialInternal'
  > &
  Pick<
    EmailOtpSigningSessionSurface,
    'rememberEmailOtpAppSessionBinding'
  > &
  SignerWorkerContextSurface &
  PasskeyLoginAssertionSurface &
  Pick<WalletAuthenticationSurface, 'setWalletAuthenticated'> &
  Pick<UserProfileStoreSurface, 'getUserBySignerSlot'> &
  Pick<
    RegistrationAccountSurface,
    'storeWalletEd25519RegistrationData' | 'storeWalletEmailOtpEd25519RegistrationData'
  > &
  Pick<
    EcdsaRegistrationSurface,
    | 'storeWalletEcdsaSignerRecords'
    | 'storeWalletEmailOtpEcdsaSignerRecords'
    | 'storeWalletEmailOtpEcdsaRegistrationData'
  > &
  WebAuthnRegistrationConfirmationSurface &
  RegistrationAccountSurface &
  EcdsaRegistrationSurface;

export type SeamsWebBaseContext<TSigningEngine> = {
  signingEngine: TSigningEngine;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  theme: ThemeMode;
};

export type RegistrationWebContext = SeamsWebBaseContext<RegistrationSigningSurface>;

export type NearSigningWebContext = SeamsWebBaseContext<
  NearSigningSurface & UserAccountLookupSurface & RpIdSurface
>;

export type WalletSessionWebContext = SeamsWebBaseContext<WalletSessionReadSurface>;

export type LoginWebContext = SeamsWebBaseContext<LoginUnlockSigningSurface>;

export type LockWebContext = SeamsWebBaseContext<LockSigningSurface>;

export type RecentUnlocksWebContext = SeamsWebBaseContext<RecentUnlocksSigningSurface>;

export type WalletAuthWebContext = SeamsWebBaseContext<
  LoginUnlockSigningSurface &
    LockSigningSurface &
    RecentUnlocksSigningSurface &
    RegistrationAccountSurface &
    EcdsaLoginSessionSurface
>;

export type LocalLoginStateWebContext = SeamsWebBaseContext<LocalLoginStateSurface>;

export type AccountSyncWebContext = SeamsWebBaseContext<AccountSyncSigningSurface>;

export type EmailRecoverySigningSurface = AccountSyncSigningSurface &
  Ed25519YaoRegistrationActivationSurface &
  WebAuthnRegistrationConfirmationSurface &
  Pick<RegistrationAccountSurface, 'storeWalletEd25519RecoveryRegistrationData'> &
  Pick<EcdsaRegistrationSurface, 'storeWalletEcdsaRecoverySignerRecords'>;

export type EmailRecoveryWebContext = SeamsWebBaseContext<EmailRecoverySigningSurface>;

export type DeviceLinkingSigningSurface = LocalLoginStateSurface &
  NearSigningSurface &
  Pick<SigningSessionSurface, 'hydrateSigningSession'> &
  RpIdSurface &
  WebAuthnRegistrationConfirmationSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'storeUserData' | 'storeAuthenticator'
  > &
  Pick<EcdsaRegistrationSurface, 'storeWalletEcdsaSignerRecords'>;

export type DeviceLinkingWebContext = SeamsWebBaseContext<DeviceLinkingSigningSurface>;
