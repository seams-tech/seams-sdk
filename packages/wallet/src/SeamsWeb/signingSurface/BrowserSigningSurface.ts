import type { DurableRecordStore, RuntimePorts } from '@/core/platform';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  SdkLifecycleEvent,
  SdkLifecycleEventListener,
  SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import { createNearProvisioningStateChangedEvent } from '@/core/types/sdkSentEvents';
import {
  subscribeToNearProvisioning,
  type NearProvisioningListener,
} from '@/core/signingEngine/flows/registration/nearProvisioningRegistry';
import type {
  AppearanceConfig,
  SigningSessionStatus,
  SeamsConfigsReadonly,
  WalletAuthenticationState,
} from '@/core/types/seams';
import { WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import { type WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import {
  exactEd25519ExportMaterialIdentity,
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEd25519ExportMaterialIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { ThresholdEcdsaCanonicalExportArtifact } from '@/core/signingEngine/interfaces/signing';
import type {
  NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
  NearEd25519FundingSession,
  NearEd25519YaoOperationMaterialFacts,
  NearEd25519YaoPreparedMaterialBoundary,
  NearEd25519YaoOperationMaterial,
  NearResolvedEd25519SigningSessionState,
  NearPasskeyEd25519OperationStepUpCapabilityPreparation,
} from '@/core/signingEngine/interfaces/near';
import type {
  NearEd25519MaterialBoundaryInput,
  NearEd25519MaterialIdentity,
  NearSigningApiDeps,
} from '@/core/signingEngine/interfaces/operationDeps';
import type { Ed25519YaoActiveClientIdentityV1 } from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import {
  type Ed25519YaoPublicCapabilityLaneReferenceV1,
  type Ed25519YaoPublicCapabilityReferenceStorePort,
  type Ed25519YaoPublicCapabilityReferenceV1,
  publishEd25519YaoPublicCapabilityReferenceAndLane,
} from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { Ed25519YaoPageLifecycleOwner } from '@/core/signingEngine/threshold/ed25519/yaoPageLifecycleOwner';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  RouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import {
  establishEvmFamilyCustodyV1,
  joinEvmFamilyCustodyV1,
  establishNearEd25519CustodyV1,
  joinNearEd25519CustodyV1,
  rejoinEvmFamilyCustodyV1,
  rejoinNearEd25519CustodyV1,
} from '@/core/signingEngine/walletCustody/registrationCeremony';
import { walletCustodyCeremonyStepRunner } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import {
  walletCustodyEd25519ActiveClientMetadataV1,
  walletRecoveryEd25519ActiveClientMetadataV1,
} from '@/core/signingEngine/walletCustody/ceremonyActiveClientMetadata';
import {
  activateWalletRecoveryEd25519V1,
  admitWalletRecoveryEd25519V1,
  buildWalletSessionEd25519RecoveryAdmissionRequestV1,
  executeWalletRecoveryEd25519RoundV1,
  type WalletSessionEd25519RecoveryBasisV1,
} from '@/core/signingEngine/walletCustody/walletRecoveryEd25519';
import { recoverWalletCustodyManifestV1 } from '@/core/signingEngine/walletCustody/walletRecoveryManifest';
import {
  deleteWalletCustodyEd25519MaterialV1,
  loadWalletCustodyEd25519MaterialV1,
  persistWalletCustodyEd25519MaterialV1,
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type LoadedWalletCustodyEd25519MaterialV1,
  type WalletCustodyEd25519MaterialBindingV1,
  type WalletCustodySealedEd25519MaterialV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import type {
  EstablishedWalletCustodyEvmFamilyKeySetV1,
  EstablishedWalletCustodyNearEd25519KeySetV1,
  JoinedWalletCustodyNearEd25519KeySetV1,
  JoinedWalletCustodyEvmFamilyKeySetV1,
  RejoinedWalletCustodyEvmFamilyKeySetV1,
} from './ports';
import { RouterAbEd25519YaoHttpActivationTransportV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  deriveRouterAbEd25519YaoApplicationBindingDigestV1,
  ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { RouterAbTraceContextV1 } from '@shared/utils/routerAbTraceContext';
import type { SigningRuntime } from '@/core/runtime/runtime.types';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
  EmailOtpYaoPrewarmRequest,
  EmailOtpYaoPrewarmOutcome,
  EmailOtpEd25519YaoActiveCapabilityDescriptorV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  importWalletCustodyEcdsaContinuity,
  IndexedDbEcdsaCapabilityManifestStore,
  type ImportWalletCustodyEcdsaContinuityInput,
} from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  clearLinkedDeviceEcdsaHolderMaterialsWasm,
  destroyLinkedDeviceEcdsaHolderMaterialsWasm,
  openEcdsaRoleLocalSigningMaterialWasm,
} from '@/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm';
import {
  clearLinkedEcdsaHolderRuntimesV1,
  listLinkedEcdsaHolderRuntimesV1,
  removeLinkedEcdsaHolderRuntimeV1,
  resolveLinkedEcdsaHolderRuntimeV1,
} from '@/core/signingEngine/session/material/linkedEcdsaHolderRuntime';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { EcdsaRoleLocalPersistedMaterialRef } from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  PasskeyMpcSessionPort,
  UiConfirmSurfaceMeasurementBinding,
  UiConfirmRuntimeBridgePort,
  WarmSessionClaimResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { type ThresholdEcdsaBootstrapStorePort } from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import type { ExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { type RouterAbEcdsaDerivationLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import {
  signNear as signNearOperation,
  type NearSignIntentRequest,
  type NearSignIntentResult,
} from '@/core/signingEngine/flows/signNear/signNear';
import {
  isConcreteAvailableSigningLane,
  type AvailableEcdsaSigningLane,
  type AvailableEd25519SigningLane,
  type ConcreteAvailableEd25519SigningLane,
  type ConcreteAvailableEcdsaSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { resolvePasskeyEd25519YaoExportContextV1 } from '@/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import type {
  PasskeyEd25519YaoExportContextResolutionV1,
  PasskeyEd25519YaoExportMaterialV1,
  PasskeyEd25519WarmRecoverySubject,
} from '@/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import {
  nearEd25519YaoOperationMaterialFacts,
  buildEmailOtpRouterAbEd25519WalletSessionState,
  buildPasskeyRouterAbEd25519WalletSessionState,
  rebindRouterAbEd25519WalletSessionStateFromExactRuntime,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import {
  hydratePasskeyEd25519YaoLocalMaterialV1,
  preparePasskeyEd25519YaoLocalMaterialRehydrationV1,
  readPasskeyEd25519YaoLocalMaterialLocatorV1,
  type PasskeyEd25519YaoPublicLocatorObservationV1,
  type PasskeyEd25519YaoUnlockSourceV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import { readEmailOtpProviderSubjectForWalletV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import {
  buildActiveNearEd25519WalletSessionAuthorization,
  buildAuthorizationRequiredNearEd25519YaoSigningPreparation,
  buildAuthorizedNearEd25519YaoSigningPreparation,
  nearEd25519SessionMatchesMaterialActivation,
  type ExactNearEd25519WalletSessionAuthorization,
  type NearEd25519YaoSigningPreparation,
} from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import {
  buildBlockedMpcCapabilityHydrationPlan,
  buildRehydrateMaterialActivationHydrationPlan,
  buildUseLiveRuntimeHydrationPlan,
  type MpcCapabilityHydrationPlan,
} from '@/core/signingEngine/session/material/mpcCapabilityHydration';
import { buildRestorableMpcMaterialRefForHydration } from '@/core/signingEngine/session/material/ecdsaCapabilityHydration';
import {
  nearEd25519YaoMaterialActivationFromMetadata,
  nearEd25519YaoRuntimeRef,
  resolveNearEd25519YaoCapabilityHydrationV1,
  type NearEd25519YaoCapabilityHydrationInputV1,
  type NearEd25519YaoRuntimeObservationV1,
} from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import {
  readOwnerWalletExecutionLaneProjectionV1,
  type OwnerWalletExecutionLaneProjectionV1,
} from '@/core/rpcClients/relayer/ownerWalletExecutionLanePreflight';
import {
  hydrateWalletExecutionLane,
  type ActiveWalletExecutionLaneHydration,
} from '@/core/signingEngine/session/lanes/walletExecutionLaneHydration';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import type {
  LocalWalletAuthMethodRecord,
  WalletAuthoritySignerMaterialRecordV1,
} from '@/core/indexedDB/passkeyClientDB.types';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type {
  ClientUserData,
  ThresholdEd25519KeyMaterial,
} from '@/core/accountData/near/nearAccountData.types';
import {
  storeNearThresholdKeyMaterial,
  type StoreNearThresholdKeyMaterialInput,
} from '@/core/accountData/near/keyMaterial';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import type { WalletAuthMethodId, WalletAuthorityId } from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildEmailOtpWalletAuthAuthority,
  isEmailOtpWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  activeWalletSessionV1RecordsEqual,
  type WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import {
  persistVerifiedEmailOtpAuthorityAfterUnlock,
  walletAuthAuthorityRefForVerifiedEmailOtpUnlock,
} from '@/SeamsWeb/operations/authMethods/emailOtp/walletActivation';
import { resolveManagedRuntimeScopeBootstrap } from '@/core/config/managedRuntimeScope';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import {
  NEAR_ED25519_YAO_KEY_VERSION_V1,
  walletAuthMethodRecordId,
} from '@shared/utils/registrationIntent';
import {
  mpcMaterialActivationRefsEqual,
  parseProviderSubject,
  parseThresholdEd25519SessionId,
  parseWalletId,
  type MpcMaterialActivationRef,
  type ProviderSubject,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import { sha256HexUtf8 } from '@shared/utils/digests';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { materialActivationKey } from '@/core/signingEngine/session/sealedRecovery/materialActivationKey';
import { isPlainObject } from '@shared/utils/validation';
import {
  requireOpaqueWalletSessionToken,
  type OpaqueWalletSessionToken,
} from '@shared/utils/sessionTokens';
import { WalletSessionAuthorizationUpgradeRequiredError } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { createRelayerExactWalletSessionStatusPort } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import {
  buildThresholdEd25519WebAuthnPrfSecretSource,
  type Ed25519OperationStepUpProof,
} from '@/core/signingEngine/threshold/ed25519/walletSession';
import {
  reconcileTempoNonceLane as reconcileTempoNonceLaneOperation,
  reportTempoBroadcastAccepted as reportTempoBroadcastAcceptedOperation,
  reportTempoBroadcastRejected as reportTempoBroadcastRejectedOperation,
  reportTempoDroppedOrReplaced as reportTempoDroppedOrReplacedOperation,
  reportTempoFinalized as reportTempoFinalizedOperation,
  signEvmFamily as signEvmFamilyOperation,
  type ReconcileTempoNonceLaneArgs,
  type ReportTempoBroadcastAcceptedArgs,
  type ReportTempoBroadcastRejectedArgs,
  type ReportTempoDroppedOrReplacedArgs,
  type ReportTempoFinalizedArgs,
  type TempoNonceLaneStatus,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import {
  clearThresholdEcdsaSigningQueue,
  withThresholdEcdsaSigningQueue,
  type ThresholdEcdsaSigningQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/signingQueue';
import {
  resolveThresholdEd25519CommitQueueKey,
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from '@/core/signingEngine/threshold/ed25519/commitQueue';
import * as recoveryPublic from '@/core/signingEngine/flows/recovery/public';
import type {
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
  RecoveryPublicDeps,
  SigningEngineExportKeypairWithUIInput,
} from '@/core/signingEngine/flows/recovery/public';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import * as registrationPublic from '@/core/signingEngine/flows/registration/public';
import {
  type EmailOtpPublicDeps,
  type LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type LoginWithEmailOtpEcdsaCapabilityInternalResult,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type { WalletSessionAuthorizationExactOperationCredentialReadResult } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ExactWalletSessionAuthorization } from '@/core/signingEngine/session/persistence/walletSessionAuthorizationProjection';
import * as emailOtpPublic from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import { createManagerAssembly } from '@/core/signingEngine/assembly/createManagers';
import { verifySealedRefreshStartupParity } from '@/core/rpcClients/relayer/sealedRefreshCapabilities';
import { isRetryableSealedRefreshCapabilityFetchError } from '@/core/signingEngine/session/warmCapabilities/sealedRefreshParity';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { ProvisionWarmEd25519CapabilityResult } from '@/core/signingEngine/session/warmCapabilities/types';
import type { LoginWithEmailOtpWalletCustodyEd25519Args } from '@/core/signingEngine/walletCustody/ed25519Login';
import {
  unlockEmailOtpEd25519YaoCapability,
  type EmailOtpAuthorityUnlockEd25519Request,
} from '@/core/signingEngine/session/emailOtp/walletUnlock';
import { buildFreshEmailOtpRoutePlan } from '@/core/signingEngine/session/emailOtp/routePlan';
import { resolveEmailOtpAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import { activateWalletCustodyEd25519CapabilityV1 } from '@/core/signingEngine/walletCustody/activateEd25519Capability';
import { disposeWalletCustodyEd25519ActiveClientV1 } from '@/core/signingEngine/walletCustody/ed25519ActiveClient';
import type { WalletCustodyCacheEnvelopeV1 } from '@/core/signingEngine/walletCustody/openCustodyCache';
import {
  resolveWalletCustodyEd25519ProjectionV1,
  type WalletCustodyEd25519Projection,
} from '@/core/signingEngine/walletCustody/ed25519Projection';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import {
  ed25519SealedRuntimeAuthorityRef,
  parseExactEd25519SealedSessionRuntime,
  resolveExactEd25519SealedSessionRuntimeForLane,
  resolveExactEd25519SealedSessionRuntimeForWalletSubject,
  type ExactEd25519SealedSessionRuntime,
} from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import type {
  OwnerLaneScope,
  SigningLaneAuthBinding,
} from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  buildExactLinkedEmailOtpOwnerLaneScope,
  buildExactEcdsaPasskeyOwnerLaneScope,
  buildExactPasskeyOwnerLaneScope,
  resolveExactOwnerLaneScope,
  type ActiveWalletAuthMethodV2,
} from '@/core/signingEngine/session/identity/ownerLaneScope';
import { parseSignerSlot, type SignerSlot } from '@shared/utils/signerSlot';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import type { EmailOtpEd25519YaoRecoveryBootstrapV1 } from '@/core/signingEngine/workerManager/workerTypes';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type { RouterAbOwnerNormalSigningCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  listExactSealedSessionsForWallet,
  readExactEd25519SealedSession,
  readExactSealedSession,
  type CurrentSealedSessionRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { ed25519DurableMaterialLocator } from '@/core/signingEngine/session/sealedRecovery/materialActivationKey';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import { normalizeThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  DEFAULT_THRESHOLD_SESSION_POLICY,
  DEFAULT_UNLOCK_REMAINING_USES,
} from '@/core/signingEngine/threshold/sessionPolicy';
import { generateSessionId } from '@/core/signingEngine/session/passkey/prfCache';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  resolveWalletCustodyEd25519ExportContextV1,
  type EmailOtpEd25519ExportAuthorizationReadResultV1,
  type EmailOtpEd25519YaoRecoveredCapabilityActivationRequestV1,
  type EmailOtpEd25519YaoExportRootResolutionV1,
  type ResolvedWalletCustodyEd25519ExportV1,
} from '@/core/signingEngine/session/emailOtp/ed25519ExportContext';
import {
  requestClearEmailOtpWarmSessionMaterial,
  requestRehydrateEmailOtpEd25519YaoOperationMaterial,
} from '@/core/signingEngine/session/emailOtp/workerRequests';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
  SessionPublicDeps,
} from '@/core/signingEngine/session/public';
import * as sessionPublic from '@/core/signingEngine/session/public';
import {
  createWarmSigningPorts,
  type WarmSigningPorts,
} from '@/core/signingEngine/assembly/ports/warmSigning';
import { createSessionPublicDeps } from '@/core/signingEngine/assembly/ports/session';
import * as warmCapabilitiesPublic from '@/core/signingEngine/session/warmCapabilities/public';
import type { WarmCapabilitiesPublicDeps } from '@/core/signingEngine/session/warmCapabilities/public';
import * as passkeyPublic from '@/core/signingEngine/session/passkey/public';
import type {
  ConnectEd25519SessionArgs,
  PasskeyPublicDeps,
} from '@/core/signingEngine/session/passkey/public';
import { createBrowserRecoveryPublicDeps } from '../assembly/createBrowserRecoveryPublicDeps';
import { createBrowserStepUpRuntime } from '../assembly/createBrowserStepUpRuntime';
import { createBrowserWarmSessionPublicDeps } from '../assembly/createBrowserWarmSessionPublicDeps';
import type { LaneSealedHolderMaterialRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  EcdsaLaneProtocolWasmV1,
  Ed25519YaoLaneJobV1,
  WasmEd25519YaoLaneClientV1,
} from '@shared/signing-lanes/rotation';
import {
  assertEd25519YaoLaneCeremonyBindingParityV1,
  createEd25519YaoLaneDerivationWorkerWasmV1,
  openEd25519YaoLaneWorkerSourceV1,
  openEd25519YaoLaneWorkerSourceFromUnlockedCapabilityV1,
  type Ed25519YaoLaneWorkerSourceV1,
} from '@/core/signingEngine/threshold/crypto/ed25519YaoLaneWasm';
import { createEcdsaLaneDerivationWorkerWasmV1 } from '@/core/signingEngine/threshold/crypto/ecdsaLaneWasm';
import { reconcileCanonicalEcdsaActivationWasm } from '@/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm';
import type {
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoCeremonyBindingV1,
  RouterAbEd25519YaoActivationKeysetV1,
} from '@shared/utils/routerAbEd25519Yao';
import { readPasskeyCustodySessionEnvelope } from '@/core/signingEngine/session/passkey/passkeyCustodySessionCache';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { joinCustodyWireFromEnvelopeRecord } from '@/core/signingEngine/walletCustody/joinCustodyWire';
import {
  deriveEvmFamilySigningKeySlotId,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  isWalletCustodySeedBinding,
  type PasskeyCustodyEnvelopeRecord,
  type WalletCustodyEvmFamilyPublicFacts,
} from '@shared/passkey-custody';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import type { UnlockedWalletEd25519ExportRootCapabilityDestroyScopeV1 } from '@/core/signingEngine/workerManager/workerTypes';
import {
  destroyUnlockedWalletEd25519ExportRootCapabilitiesV1 as destroyUnlockedExportRootCapabilitiesWithWorkerV1,
  establishUnlockedWalletEd25519ExportRootCapabilityV1 as establishUnlockedExportRootCapabilityWithWorkerV1,
  readUnlockedWalletEd25519ExportRootCapabilityV1,
  setUnlockedCustodyEnvelopeUpgradeSinkV1,
} from '@/core/signingEngine/walletCustody/unlockedEd25519ExportRootCapability';
import { upgradeWalletCustodyEnvelopeOwnership } from '@/core/rpcClients/relayer/passkeyCustodyEnvelope';
import { base58Encode } from '@shared/utils/base58';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { UserConfirmationType } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import { resolveWalletAuthorityOperation } from '@/core/signingEngine/session/authority';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import {
  createBrowserActiveEcdsaWalletSessionAuthorizationResolver,
  createBrowserCanonicalWalletSessionStatusReader,
  createBrowserSigningSurfaceEnginePorts,
  listBrowserActiveEcdsaCapabilityManifestsForWallet,
  listBrowserEcdsaSigningCapabilitiesForWallet,
  readBrowserExactNearEd25519WalletSessionAuthorization,
  resolveBrowserActiveNearEd25519WalletSessionAuthorization,
  resolveExactWalletAuthAuthority,
  type BrowserSigningSurfaceEnginePorts,
} from '../assembly/browserSigningSurfaceAssembly';
import type { BrowserSigningSurfaceConstructorDeps } from '../assembly/browserSigningSurfacePorts';
import type { SigningSessionLifecycleSubscription } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { finalizeWalletRegistrationEcdsaSessions as finalizeWalletRegistrationEcdsaSessionsOperation } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type {
  WorkerResourceWarmupAccountContext,
  WorkerResourceWarmupDiagnostics,
} from '@/core/signingEngine/assembly/warmup';
import {
  redactedPasskeyRegistrationCredential,
  serializeRegistrationCredentialWithPRF,
} from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import { walletIframeRequestIdFromBoundary } from '@/core/types/walletIframeIdentity';
import type { WalletRecoveryRegistrationOptions } from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import type { WalletAddAuthMethodRegistrationOptions } from '@/core/rpcClients/relayer/walletRegistration';
import {
  walletRecoveryReplacementCredentialFromRegistrationV1,
  type WalletRecoveryReplacementCredential,
} from '@/core/signingEngine/walletCustody/walletRecoveryCredential';
import type {
  RegistrationWebAuthnPromptOwner,
  ReservedRegistrationWebAuthnPrompt,
  WebAuthnPromptCancellation,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
async function resolveActiveEd25519WalletSessionAuthorization(
  walletId: WalletId,
  relayerUrl: string,
): Promise<ExactNearEd25519WalletSessionAuthorization | null> {
  return await resolveBrowserActiveNearEd25519WalletSessionAuthorization(walletId, relayerUrl);
}

function requireEmailOtpEcdsaRehydrationManifest(
  manifests: readonly ActiveEcdsaCapabilityManifest[],
  authorityDigest: string,
): ActiveEcdsaCapabilityManifest {
  let selected: ActiveEcdsaCapabilityManifest | null = null;
  for (const manifest of manifests) {
    if (manifest.signer.authority.authorityDigest !== authorityDigest) continue;
    if (
      selected &&
      selected.durableMaterial.roleLocalBinding.keyHandle !==
        manifest.durableMaterial.roleLocalBinding.keyHandle
    ) {
      throw new Error('[SigningEngine][near] Email OTP ECDSA session identity is ambiguous');
    }
    selected = manifest;
  }
  if (!selected) {
    throw new Error('[SigningEngine][near] Email OTP ECDSA capability is unavailable');
  }
  return selected;
}

function buildEmailOtpEcdsaRehydrationPolicy(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly remainingUses: number;
}): RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 {
  const walletSessionMintId = parseWalletSessionMintId(generateSessionId('wallet-session-mint'));
  if (!walletSessionMintId.ok) {
    throw new Error('[SigningEngine][near] failed to generate an ECDSA Wallet Session mint id');
  }
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
    key_handle: String(args.manifest.durableMaterial.roleLocalBinding.keyHandle),
    session_policy: {
      threshold_session_id: SigningSessionIds.thresholdEcdsaSession(
        generateSessionId('threshold-ecdsa-login'),
      ),
      wallet_session_mint_id: walletSessionMintId.value,
      ttl_ms: DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
      remaining_uses: args.remainingUses,
      runtime_policy_scope: args.manifest.durableMaterial.runtimePolicyScope,
    },
  };
}

async function persistRehydratedEmailOtpEcdsaWalletSession(args: {
  readonly walletId: WalletId;
  readonly ed25519Authorization: ExactNearEd25519WalletSessionAuthorization;
  readonly response: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
}): Promise<void> {
  const session = args.response.session;
  if (
    session.wallet_session.walletId !== args.walletId ||
    session.wallet_session.authorizationId !== session.authorization_id ||
    session.operation_credential.walletSessionId !== session.wallet_session_id
  ) {
    throw new Error('[SigningEngine][near] refreshed ECDSA exact Wallet Session is inconsistent');
  }
  await walletSessionAuthorizations.writeExactWithOperationCredential({
    record: session.wallet_session,
    operationCredential: session.operation_credential,
  });
}

async function readBrowserEmailOtpProviderSubject(walletId: WalletId): Promise<string | null> {
  return await readEmailOtpProviderSubjectForWalletV1(IndexedDBManager, walletId);
}

const browserSigningSurfaceExactWalletAuthMethodStore = {
  getWalletAuthMethodV2: IndexedDBManager.getWalletAuthMethodV2.bind(IndexedDBManager),
  listWalletAuthMethodsForWallet:
    IndexedDBManager.listWalletAuthMethodsForWallet.bind(IndexedDBManager),
  readEmailOtpProviderSubjectForWallet: readBrowserEmailOtpProviderSubject,
};

function exactEmailOtpAuthorityRef(args: {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
}): WalletAuthAuthorityRef {
  const authorityRef = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: args.walletId,
    walletAuthMethodId: args.walletAuthMethodId,
    authorityDigest: args.authorityDigestB64u,
  });
  if (!authorityRef) {
    throw new Error('[SigningEngine][near] exact Email OTP authority digest is invalid');
  }
  return authorityRef;
}

async function resolveExactEmailOtpFactorAuthority(args: {
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly emailHashHex: string;
  readonly providerSubject: string;
}): Promise<EmailOtpWalletAuthAuthority> {
  const factorAuthority = await resolveExactWalletAuthAuthority(
    args.authorityRef,
    browserSigningSurfaceExactWalletAuthMethodStore,
  );
  if (
    !isEmailOtpWalletAuthAuthority(factorAuthority) ||
    factorAuthority.verifier.emailHashHex !== args.emailHashHex ||
    factorAuthority.factor.providerUserId !== args.providerSubject
  ) {
    throw new Error('[SigningEngine][near] exact Email OTP factor authority changed');
  }
  return factorAuthority;
}

type ExactEmailOtpEd25519ActivationAuthorization = {
  readonly authority: WalletAuthAuthorityRef;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

type EmailOtpEd25519CustodyCapabilityActivationArgs = {
  readonly commitQueue: 'acquire' | 'already_acquired';
  readonly walletSession: WalletSessionRef;
  readonly providerSubject: string;
  readonly emailHashHex: string;
  readonly signerSlot: number;
  readonly expectedOperationalPublicKey: string;
  readonly expectedThresholdSessionId: string;
  readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  readonly activeClientHandle: string;
  readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  readonly authority?: WalletAuthAuthorityRef;
};

type EmailOtpEd25519CredentialExpectation =
  | { readonly kind: 'resolve_exact_operation_credential' }
  | {
      readonly kind: 'expect_exact_operation_credential';
      readonly operationCredential: WalletSessionOperationCredentialV1;
    };

async function resolveExactEmailOtpEd25519ActivationAuthorization(args: {
  readonly walletId: WalletId;
  readonly emailHashHex: string;
  readonly providerSubject: string;
  readonly bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  readonly verifiedAuthority?: WalletAuthAuthorityRef;
}): Promise<ExactEmailOtpEd25519ActivationAuthorization> {
  const bootstrapSession = args.bootstrap.session;
  const stored = await walletSessionAuthorizations.readExact(bootstrapSession.walletSessionId);
  if (
    !stored ||
    stored.kind !== 'active_wallet_session_v1' ||
    stored.walletId !== args.walletId ||
    stored.authorizationId !== bootstrapSession.authorizationId ||
    stored.quotaId !== bootstrapSession.quotaId ||
    stored.expiresAtMs <= Date.now()
  ) {
    throw new Error('[SigningEngine][near] exact Email OTP activation session is unavailable');
  }
  const [method, authority] = await Promise.all([
    IndexedDBManager.getWalletAuthMethodV2(String(stored.authMethodId)),
    IndexedDBManager.getWalletAuthority(String(stored.authorityId)),
  ]);
  if (
    !method ||
    method.kind !== 'email_otp' ||
    method.status !== 'active' ||
    method.walletId !== args.walletId ||
    method.walletAuthorityId !== stored.authorityId ||
    method.emailHashHex !== args.emailHashHex ||
    !authority ||
    authority.state !== 'active' ||
    authority.walletId !== args.walletId ||
    authority.authorityId !== stored.authorityId ||
    authority.authorityDigestB64u !== stored.authorityDigestB64u ||
    authority.revocationEpoch !== stored.authorityRevocationEpoch
  ) {
    throw new Error('[SigningEngine][near] exact Email OTP activation authority is unavailable');
  }
  const authorityRef = exactEmailOtpAuthorityRef({
    walletId: args.walletId,
    walletAuthMethodId: method.walletAuthMethodId,
    authorityDigestB64u: authority.authorityDigestB64u,
  });
  if (
    args.verifiedAuthority &&
    (args.verifiedAuthority.walletId !== authorityRef.walletId ||
      args.verifiedAuthority.walletAuthMethodId !== authorityRef.walletAuthMethodId ||
      args.verifiedAuthority.authorityDigest !== authorityRef.authorityDigest)
  ) {
    throw new Error('[SigningEngine][near] verified Email OTP activation authority changed');
  }
  await resolveExactEmailOtpFactorAuthority({
    authorityRef,
    emailHashHex: args.emailHashHex,
    providerSubject: args.providerSubject,
  });
  const exact = await walletSessionAuthorizations.readExactActiveForWallet({
    walletId: args.walletId,
    authorityId: stored.authorityId,
    authMethodId: stored.authMethodId,
  });
  if (
    exact.kind !== 'found' ||
    !activeWalletSessionV1RecordsEqual(exact.record, stored) ||
    exact.operationCredential.walletSessionId !== bootstrapSession.walletSessionId
  ) {
    throw new Error('[SigningEngine][near] exact Email OTP activation credential is unavailable');
  }
  return { authority: authorityRef, operationCredential: exact.operationCredential };
}

function unavailableEmailOtpExportAuthorizationFromStatus(
  status: Exclude<
    Awaited<ReturnType<ReturnType<typeof createRelayerExactWalletSessionStatusPort>['read']>>,
    { readonly status: 'active' }
  >,
): EmailOtpEd25519ExportAuthorizationReadResultV1 {
  switch (status.status) {
    case 'missing':
      return { kind: 'missing' };
    case 'exhausted':
      return { kind: 'exhausted' };
    case 'expired':
      return { kind: 'expired' };
    case 'superseded':
      return { kind: 'superseded' };
    case 'authority_unavailable':
      return { kind: 'authority_unavailable' };
    case 'method_unavailable':
      return { kind: 'method_unavailable' };
    case 'capability_unavailable':
      return { kind: 'capability_unavailable' };
    case 'invalid':
      return { kind: 'corrupt' };
    default:
      status satisfies never;
      throw new Error('[SigningEngine][ed25519-export] unsupported exact session status');
  }
}

async function readExactEmailOtpEd25519ExportAuthorization(args: {
  readonly subject: ResolvedWalletCustodyEd25519ExportV1['lane'];
  readonly relayerUrl: string;
}): Promise<EmailOtpEd25519ExportAuthorizationReadResultV1> {
  const walletId = args.subject.signer.account.wallet.walletId;
  let selected: Awaited<ReturnType<typeof IndexedDBManager.resolveSelectedWalletAuthority>>;
  try {
    selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  } catch {
    return { kind: 'persistence_unavailable' };
  }
  if (selected.kind !== 'resolved') {
    return selected.kind === 'integrity_error' ? { kind: 'corrupt' } : { kind: 'missing' };
  }
  const { selection, authority, authMethod } = selected;
  if (
    selection.lockState !== 'unlocked' ||
    selection.walletId !== walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authority.state !== 'active' ||
    authority.walletId !== walletId ||
    authMethod.kind !== 'email_otp' ||
    authMethod.status !== 'active' ||
    authMethod.walletId !== walletId ||
    authMethod.walletAuthorityId !== authority.authorityId
  ) {
    return { kind: 'corrupt' };
  }
  const authorityRef = exactEmailOtpAuthorityRef({
    walletId,
    walletAuthMethodId: authMethod.walletAuthMethodId,
    authorityDigestB64u: authority.authorityDigestB64u,
  });
  let factorAuthority: EmailOtpWalletAuthAuthority;
  try {
    factorAuthority = await resolveExactEmailOtpFactorAuthority({
      authorityRef,
      emailHashHex: authMethod.emailHashHex,
      providerSubject: args.subject.auth.providerSubjectId,
    });
  } catch {
    return { kind: 'corrupt' };
  }
  const exact = await walletSessionAuthorizations.readExactActiveForWallet({
    walletId,
    authorityId: authority.authorityId,
    authMethodId: authMethod.walletAuthMethodId,
  });
  switch (exact.kind) {
    case 'missing':
    case 'upgrade_required':
    case 'corrupt':
    case 'persistence_unavailable':
      return exact;
    case 'found':
      break;
    default:
      exact satisfies never;
      throw new Error('[SigningEngine][ed25519-export] unsupported exact local session result');
  }
  if (exact.record.expiresAtMs <= Date.now()) return { kind: 'expired' };
  let status: Awaited<
    ReturnType<ReturnType<typeof createRelayerExactWalletSessionStatusPort>['read']>
  >;
  try {
    status = await createRelayerExactWalletSessionStatusPort({
      relayerUrl: args.relayerUrl,
      operationCredential: exact.operationCredential,
    }).read({
      walletSessionId: exact.operationCredential.walletSessionId,
      quotaId: exact.record.quotaId,
    });
  } catch {
    return { kind: 'persistence_unavailable' };
  }
  if (status.status !== 'active') {
    return unavailableEmailOtpExportAuthorizationFromStatus(status);
  }
  return {
    kind: 'found',
    authorization: {
      selectedAuthority: authority,
      selectedAuthMethod: authMethod,
      factorAuthority,
      record: exact.record,
      operationCredential: exact.operationCredential,
      status,
    },
  };
}

type NearEd25519CapabilityRehydrationSubject =
  | {
      readonly kind: 'account_signer';
      readonly walletId: WalletId;
      readonly nearAccountId: AccountId;
      readonly signerSlot: number | null;
    }
  | {
      readonly kind: 'exact_lane';
      readonly walletId: WalletId;
      readonly nearAccountId: AccountId;
      readonly signerSlot: number;
      readonly thresholdSessionId: ThresholdEd25519SessionId;
      readonly laneIdentity: ExactEd25519SigningLaneIdentity;
    }
  | {
      readonly kind: 'export_exact_lane';
      readonly walletId: WalletId;
      readonly nearAccountId: AccountId;
      readonly signerSlot: number;
      readonly thresholdSessionId: ThresholdEd25519SessionId;
      readonly laneIdentity: ExactEd25519ExportMaterialIdentity;
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'material_identity';
      readonly walletId: WalletId;
      readonly nearAccountId: AccountId;
      readonly signerSlot: number;
      readonly thresholdSessionId: ThresholdEd25519SessionId;
      readonly materialIdentity: NearEd25519MaterialIdentity;
    };

function fetchWithGlobalThis(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return globalThis.fetch(input, init);
}

function nearEd25519LaneMatchesCapabilityRehydrationSubject(
  lane: AvailableEd25519SigningLane,
  subject: NearEd25519CapabilityRehydrationSubject,
): boolean {
  if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') return false;
  if (
    String(lane.walletId) !== String(subject.walletId) ||
    String(lane.nearAccountId) !== String(subject.nearAccountId)
  ) {
    return false;
  }
  if (subject.signerSlot !== null && lane.signerSlot !== subject.signerSlot) return false;
  if (subject.kind === 'account_signer') return true;
  if (String(lane.thresholdSessionId) !== subject.thresholdSessionId) return false;
  return subject.kind === 'export_exact_lane'
    ? mpcMaterialActivationRefsEqual(lane.materialActivation, subject.materialActivation)
    : true;
}

function currentNearEd25519CapabilityRehydrationSubject(args: {
  subject: NearEd25519CapabilityRehydrationSubject;
  walletSessionState: NearResolvedEd25519SigningSessionState;
}): NearEd25519CapabilityRehydrationSubject {
  const thresholdSessionId = args.walletSessionState.thresholdSessionId;
  switch (args.subject.kind) {
    case 'account_signer':
      return args.subject;
    case 'exact_lane':
      return {
        ...args.subject,
        thresholdSessionId,
        laneIdentity: args.walletSessionState.signingLane.identity,
      };
    case 'export_exact_lane':
      return {
        ...args.subject,
        thresholdSessionId,
        laneIdentity: exactEd25519ExportMaterialIdentity({
          signer: args.walletSessionState.signingLane.identity.signer,
          auth: args.walletSessionState.signingLane.identity.auth,
          thresholdSessionId,
        }),
      };
    case 'material_identity':
      return {
        ...args.subject,
        thresholdSessionId,
        materialIdentity: {
          kind: 'near_ed25519_material_identity',
          signer: args.walletSessionState.signingLane.identity.signer,
          auth: args.walletSessionState.signingLane.identity.auth,
          thresholdSessionId,
        },
      };
    default:
      return assertNeverNearEd25519CapabilityRehydrationSubject(args.subject);
  }
}

function assertNeverNearEd25519CapabilityRehydrationSubject(value: never): never {
  throw new Error(`Unknown Ed25519 capability rehydration subject: ${String(value)}`);
}

function createDiscardingEd25519LaneClientV1(
  client: WasmEd25519YaoLaneClientV1,
  source: { readonly discard: () => Promise<void> },
): WasmEd25519YaoLaneClientV1 {
  let discarded = false;
  const discard = async (): Promise<void> => {
    if (discarded) return;
    discarded = true;
    await source.discard();
  };
  return {
    prepare: async (job) => {
      try {
        return await client.prepare(job);
      } catch (error: unknown) {
        await discard();
        throw error;
      }
    },
    complete: async (input) => {
      try {
        return await client.complete(input);
      } finally {
        await discard();
      }
    },
  };
}

async function reconcileWalletHostEcdsaActivationJournalV1(args: {
  readonly store: IndexedDbEcdsaCapabilityManifestStore;
  readonly workerCtx: WorkerOperationContext;
  readonly walletId: WalletId;
}): Promise<void> {
  const listed = await args.store.listWalletActivationJournalSelectors(args.walletId);
  if (listed.kind !== 'resolved') {
    throw new Error(`Wallet-host ECDSA activation journal is ${listed.kind}`);
  }
  for (const selector of listed.selectors) {
    const result = await reconcileCanonicalEcdsaActivationWasm({
      workerCtx: args.workerCtx,
      command: {
        kind: 'reconcile_canonical_ecdsa_activation_v1',
        capability: selector.capability,
        authority: selector.authority,
      },
    });
    if (
      result.kind !== 'canonical_ecdsa_activation_reconciliation_absent_v1' &&
      result.kind !== 'canonical_ecdsa_activation_reconciliation_finalized_v1'
    ) {
      throw new Error(`Wallet-host ECDSA activation reconciliation is ${result.kind}`);
    }
  }
}

export async function ensurePasskeyEd25519WarmSessionForSigning(args: {
  claimWarmSessionMaterial: PasskeyMpcSessionPort['claimWarmSessionMaterial'];
  rehydrateWarmSessionMaterial: PasskeyMpcSessionPort['rehydrateWarmSessionMaterial'];
  runtime: ExactEd25519SealedSessionRuntime;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  materialActivation: MpcMaterialActivationRef;
}): Promise<WarmSessionClaimResult> {
  const thresholdSessionId = args.walletSessionState.thresholdSessionId;
  let claim = await args.claimWarmSessionMaterial({
    thresholdSessionId,
    purpose: { curve: 'ed25519', materialActivation: args.materialActivation },
    consume: false,
  });
  if (claim.ok || claim.code !== 'not_found') return claim;

  if (args.runtime.factor.kind !== 'passkey') {
    throw new Error('[SigningEngine][near] persisted Ed25519 credential is unavailable');
  }
  const walletSessionToken = String(
    args.walletSessionState.walletSessionAuth.walletSessionToken || '',
  ).trim();
  const groupId = String(args.runtime.sealedRecord.groupId || '').trim();
  if (!walletSessionToken || !groupId) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Passkey Ed25519 sealed restore metadata is incomplete',
    };
  }
  if (
    !mpcMaterialActivationRefsEqual(
      args.runtime.sealedRecord.ed25519Restore.materialActivation,
      args.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][near] persisted Ed25519 material activation mismatch');
  }
  const keyVersion = parseSigningSessionSealKeyVersion(args.runtime.sealedRecord.keyVersion);
  const rehydrated = await args.rehydrateWarmSessionMaterial({
    thresholdSessionId,
    sealedSecretB64u: args.runtime.sealedRecord.sealedSecretB64u,
    signingSessionSealKeyVersion: keyVersion,
    expiresAtMs: args.runtime.sealedRecord.expiresAtMs,
    remainingUses: args.runtime.sealedRecord.remainingUses,
    transport: {
      curve: 'ed25519',
      authMethod: 'passkey',
      walletId: String(args.runtime.walletId),
      relayerUrl: args.runtime.relayerUrl,
      signingSessionSealKeyVersion: keyVersion,
      groupId,
      walletSessionToken,
      ed25519Restore: buildPasskeyEd25519RestoreMetadata({
        rpId: args.runtime.factor.rpId,
        nearAccountId: args.runtime.nearAccountId,
        nearEd25519SigningKeyId: args.runtime.nearEd25519SigningKeyId,
        relayerKeyId: args.runtime.relayerKeyId,
        participantIds: args.runtime.participantIds,
        runtimePolicyScope: args.runtime.runtimePolicyScope,
        signerSlot: args.runtime.signerSlot,
        routerAbNormalSigning: args.runtime.routerAbNormalSigning,
        credentialIdB64u: args.runtime.factor.credentialIdB64u,
        materialActivation: args.materialActivation,
      }),
    },
  });
  if (!rehydrated.ok) return rehydrated;
  claim = await args.claimWarmSessionMaterial({
    thresholdSessionId,
    purpose: { curve: 'ed25519', materialActivation: args.materialActivation },
    consume: false,
  });
  return claim;
}

function nearEd25519CapabilityRehydrationKey(
  subject: NearEd25519CapabilityRehydrationSubject,
): string {
  return JSON.stringify([
    String(subject.walletId),
    String(subject.nearAccountId),
    subject.signerSlot,
    subject.kind === 'account_signer' ? null : subject.thresholdSessionId,
    subject.kind === 'export_exact_lane' ? materialActivationKey(subject.materialActivation) : null,
  ]);
}

export function nearEd25519PublicLocatorObservation(args: {
  references: readonly Ed25519YaoPublicCapabilityLaneReferenceV1[];
  walletId: WalletId;
  nearAccountId: AccountId;
  signerSlot: number;
  thresholdSessionId: ThresholdEd25519SessionId;
}): PasskeyEd25519YaoPublicLocatorObservationV1 {
  const matches = args.references.filter(
    (reference) =>
      String(reference.walletId) === String(args.walletId) &&
      String(reference.nearAccountId) === String(args.nearAccountId) &&
      reference.signerSlot === args.signerSlot &&
      String(reference.thresholdSessionId) === String(args.thresholdSessionId),
  );
  if (matches.length === 0) return { kind: 'missing' };
  if (matches.length !== 1) return { kind: 'conflict' };
  return {
    kind: 'available',
    walletId: String(args.walletId),
    nearAccountId: String(args.nearAccountId),
    signerSlot: args.signerSlot,
    materialActivation: matches[0].materialActivation,
  };
}

async function resolveNearEd25519PublicCapabilityMaterialActivation(args: {
  store: Pick<
    BrowserSigningSurfaceConstructorDeps['ed25519YaoPublicCapabilityReferences'],
    'listLanes'
  >;
  identity: NearEd25519MaterialIdentity;
}): Promise<MpcMaterialActivationRef | null> {
  const signer = args.identity.signer;
  const matches = (await args.store.listLanes()).filter(
    (reference) =>
      String(reference.walletId) === String(signer.account.wallet.walletId) &&
      String(reference.nearAccountId) === String(signer.account.nearAccountId) &&
      String(reference.nearEd25519SigningKeyId) === String(signer.nearEd25519SigningKeyId) &&
      reference.signerSlot === signer.signerSlot &&
      String(reference.thresholdSessionId) === String(args.identity.thresholdSessionId) &&
      nearEd25519AuthBindingsEqual(reference.auth, args.identity.auth),
  );
  if (matches.length > 1) {
    throw new Error('[SigningEngine][near] public Ed25519 capability lane is conflicting');
  }
  return matches[0]?.materialActivation ?? null;
}

function emailOtpEd25519YaoLaneReferenceFromRecovery(args: {
  walletSessionState: NearResolvedEd25519SigningSessionState;
  materialActivation: MpcMaterialActivationRef;
}): Ed25519YaoPublicCapabilityLaneReferenceV1 {
  const lane = args.walletSessionState.signingLane;
  const signer = lane.identity.signer;
  if (lane.auth.kind !== 'email_otp') {
    throw new Error('[SigningEngine][near] Email OTP recovery returned another auth lane');
  }
  return {
    walletId: signer.account.wallet.walletId,
    nearAccountId: signer.account.nearAccountId,
    thresholdSessionId: args.walletSessionState.thresholdSessionId,
    runtimePolicyScope: args.walletSessionState.runtimePolicyScope,
    materialActivation: args.materialActivation,
    auth: {
      kind: 'email_otp',
      providerSubjectId: lane.auth.providerSubjectId,
    },
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    signerSlot: signer.signerSlot,
    remainingUses: args.walletSessionState.signingWalletSession.remainingUses,
    expiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
  };
}

function exactEd25519LaneIdentityFromAvailableLane(
  lane: ConcreteAvailableEd25519SigningLane,
): ExactEd25519SigningLaneIdentity {
  if (!lane.authorization) {
    throw new Error('Available Ed25519 lane requires Wallet Session authorization');
  }
  return exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
      signerSlot: lane.signerSlot,
    }),
    auth: lane.auth,
    walletSessionId: lane.authorization.operationCredential.walletSessionId,
    quotaId: lane.authorization.session.quotaId,
    thresholdSessionId: lane.thresholdSessionId,
  });
}

function isLinkedEd25519SignerMaterial(
  material: WalletAuthoritySignerMaterialRecordV1,
): material is Extract<
  WalletAuthoritySignerMaterialRecordV1,
  { kind: 'wallet_authority_linked_signer_material_v1'; keyFamily: 'ed25519' }
> {
  return (
    material.kind === 'wallet_authority_linked_signer_material_v1' &&
    material.keyFamily === 'ed25519'
  );
}

function resolveSelectedEmailOtpEd25519ExportRootV1(args: {
  readonly selected: ResolveSelectedWalletAuthorityResultV1;
  readonly subject: ResolvedWalletCustodyEd25519ExportV1['lane'];
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly activeCapability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1 | null;
}): PasskeyCustodyEnvelopeRecord | EmailOtpEd25519YaoExportRootResolutionV1 | null {
  const selected = args.selected;
  if (selected.kind !== 'resolved') {
    const detail = selected.kind === 'integrity_error' ? `: ${selected.reason}` : '';
    throw new Error(
      `[SigningEngine][ed25519-export] selected Wallet Authority is ${selected.kind}${detail}`,
    );
  }
  if (
    selected.authority.provenance.kind === 'wallet_registration' ||
    selected.authority.provenance.kind === 'wallet_recovery'
  ) {
    return null;
  }

  const { selection, authMethod, authority, signerMaterials, exportRoot } = selected;
  const signer = args.subject.signer;
  const ed25519Activation = authority.signerActivations.ed25519;
  if (
    selection.lockState !== 'unlocked' ||
    authMethod.kind !== WALLET_AUTH_METHODS.emailOtp ||
    authMethod.status !== 'active' ||
    authority.state !== 'active' ||
    String(selection.walletId) !== String(signer.account.wallet.walletId) ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    String(authMethod.walletId) !== String(signer.account.wallet.walletId) ||
    !authority.permissions.includes('export_keys') ||
    !ed25519Activation ||
    !mpcMaterialActivationRefsEqual(
      ed25519Activation.materialActivation,
      args.expectedMaterialActivation,
    ) ||
    !exportRoot
  ) {
    throw new Error(
      '[SigningEngine][ed25519-export] selected linked Email OTP authority has no exact export root',
    );
  }

  let linkedMaterial: Extract<
    WalletAuthoritySignerMaterialRecordV1,
    { kind: 'wallet_authority_linked_signer_material_v1'; keyFamily: 'ed25519' }
  > | null = null;
  for (const candidate of signerMaterials) {
    if (
      !isLinkedEd25519SignerMaterial(candidate) ||
      candidate.authorityId !== authority.authorityId ||
      candidate.walletAuthMethodId !== authMethod.walletAuthMethodId ||
      !mpcMaterialActivationRefsEqual(candidate.materialActivation, args.expectedMaterialActivation)
    ) {
      continue;
    }
    if (linkedMaterial) {
      throw new Error('[SigningEngine][ed25519-export] linked Ed25519 material is ambiguous');
    }
    linkedMaterial = candidate;
  }
  if (!linkedMaterial) {
    throw new Error('[SigningEngine][ed25519-export] linked Ed25519 material is unavailable');
  }

  const targetFactor = linkedMaterial.targetFactor;
  const application = linkedMaterial.publicFacts.applicationBinding;
  const lifecycle = linkedMaterial.publicFacts.targetBinding.lifecycle;
  const registeredPublicKeyB64u = ed25519Activation.signer.registeredPublicKeyB64u;
  if (
    targetFactor.kind !== WALLET_AUTH_METHODS.emailOtp ||
    targetFactor.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    targetFactor.emailHashHex !== authMethod.emailHashHex ||
    targetFactor.registrationAuthorityId !== authMethod.registrationAuthorityId ||
    exportRoot.authorityId !== authority.authorityId ||
    exportRoot.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    exportRoot.walletKeyId !== ed25519Activation.signer.walletKeyId ||
    exportRoot.envelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
    exportRoot.envelope.binding.registeredPublicKeyB64u !== registeredPublicKeyB64u ||
    exportRoot.envelope.factor.kind !== WALLET_AUTH_METHODS.emailOtp ||
    application.wallet_id !== String(signer.account.wallet.walletId) ||
    application.near_ed25519_signing_key_id !== String(signer.nearEd25519SigningKeyId) ||
    application.key_creation_signer_slot !== signer.signerSlot ||
    lifecycle.account_id !== String(signer.account.wallet.walletId) ||
    lifecycle.session_id !== String(args.subject.thresholdSessionId) ||
    lifecycle.selected_server_id !== args.expectedMaterialActivation.signingWorker ||
    base64UrlEncode(
      Uint8Array.from(linkedMaterial.publicFacts.activationReceipt.registered_public_key),
    ) !== registeredPublicKeyB64u
  ) {
    throw new Error('[SigningEngine][ed25519-export] linked Email OTP export identity changed');
  }

  if (args.activeCapability) {
    if (
      !mpcMaterialActivationRefsEqual(
        args.activeCapability.materialActivation,
        args.expectedMaterialActivation,
      ) ||
      base64UrlEncode(Uint8Array.from(args.activeCapability.registeredPublicKey)) !==
        registeredPublicKeyB64u
    ) {
      throw new Error('[SigningEngine][ed25519-export] active Email OTP capability changed');
    }
    return exportRoot.envelope;
  }
  return {
    envelope: exportRoot.envelope,
    source: {
      materialActivation: args.expectedMaterialActivation,
      signingWorkerId: lifecycle.selected_server_id,
      participantIds: linkedMaterial.publicFacts.participantIds,
      registeredPublicKeyB64u,
    },
  };
}

async function resolveLinkedPasskeyOwnerSignerSlot(args: {
  walletId: WalletId;
  authMethod: Extract<ActiveWalletAuthMethodV2, { kind: 'passkey' }>;
  signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
  publicLaneStore: Ed25519YaoPublicCapabilityReferenceStorePort;
}): Promise<SignerSlot> {
  let material: Extract<
    WalletAuthoritySignerMaterialRecordV1,
    { kind: 'wallet_authority_linked_signer_material_v1'; keyFamily: 'ed25519' }
  > | null = null;
  for (const candidate of args.signerMaterials) {
    if (
      !isLinkedEd25519SignerMaterial(candidate) ||
      candidate.authorityId !== args.authMethod.walletAuthorityId ||
      candidate.walletAuthMethodId !== args.authMethod.walletAuthMethodId
    ) {
      continue;
    }
    if (material) {
      throw new Error('[SigningEngine] linked Passkey Ed25519 signer material is conflicting');
    }
    material = candidate;
  }
  if (!material) {
    throw new Error('[SigningEngine] linked Passkey Ed25519 signer material is unavailable');
  }
  const application = material.publicFacts.applicationBinding;
  const signerSlot = parseSignerSlot(application.key_creation_signer_slot, { min: 1 });
  const target = material.targetFactor;
  if (
    !signerSlot ||
    application.wallet_id !== String(args.walletId) ||
    String(material.materialActivation.materialOwner) !== String(args.walletId) ||
    target.kind !== WALLET_AUTH_METHODS.passkey ||
    target.walletAuthMethodId !== args.authMethod.walletAuthMethodId ||
    String(target.rpId) !== String(args.authMethod.rpId) ||
    String(target.credentialIdB64u) !== String(args.authMethod.credentialIdB64u)
  ) {
    throw new Error('[SigningEngine] linked Passkey Ed25519 signer material identity is invalid');
  }
  let laneMatches = 0;
  for (const reference of await args.publicLaneStore.listLanes()) {
    if (reference.auth.kind !== 'passkey') continue;
    if (
      String(reference.walletId) !== String(args.walletId) ||
      String(reference.auth.rpId) !== String(args.authMethod.rpId) ||
      reference.auth.credentialIdB64u !== args.authMethod.credentialIdB64u ||
      String(reference.nearEd25519SigningKeyId) !==
        String(application.near_ed25519_signing_key_id) ||
      reference.signerSlot !== signerSlot ||
      !mpcMaterialActivationRefsEqual(reference.materialActivation, material.materialActivation)
    ) {
      continue;
    }
    laneMatches += 1;
  }
  if (laneMatches === 0) {
    throw new Error('[SigningEngine] linked Passkey Ed25519 public lane is unavailable');
  }
  if (laneMatches !== 1) {
    throw new Error('[SigningEngine] linked Passkey Ed25519 public lane is ambiguous');
  }
  return signerSlot;
}

async function resolveExactEmailOtpPublicLaneReference(args: {
  store: Ed25519YaoPublicCapabilityReferenceStorePort;
  laneIdentity: ExactEd25519SigningLaneIdentity;
  materialActivation: MpcMaterialActivationRef;
}): Promise<Ed25519YaoPublicCapabilityLaneReferenceV1> {
  const signer = args.laneIdentity.signer;
  const matches = (await args.store.listLanes()).filter(
    (reference) =>
      reference.auth.kind === WALLET_AUTH_METHODS.emailOtp &&
      args.laneIdentity.auth.kind === WALLET_AUTH_METHODS.emailOtp &&
      reference.auth.providerSubjectId === args.laneIdentity.auth.providerSubjectId &&
      String(reference.walletId) === String(signer.account.wallet.walletId) &&
      String(reference.nearAccountId) === String(signer.account.nearAccountId) &&
      String(reference.nearEd25519SigningKeyId) === String(signer.nearEd25519SigningKeyId) &&
      reference.signerSlot === signer.signerSlot &&
      String(reference.thresholdSessionId) === String(args.laneIdentity.thresholdSessionId) &&
      mpcMaterialActivationRefsEqual(reference.materialActivation, args.materialActivation),
  );
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0
        ? '[SigningEngine][near] Email OTP public lane is unavailable'
        : '[SigningEngine][near] Email OTP public lane is ambiguous',
    );
  }
  return matches[0];
}

async function resolveExactPasskeyPublicLaneReference(args: {
  store: Ed25519YaoPublicCapabilityReferenceStorePort;
  laneIdentity: ExactEd25519SigningLaneIdentity | ExactEd25519ExportMaterialIdentity;
}): Promise<Ed25519YaoPublicCapabilityLaneReferenceV1> {
  if (args.laneIdentity.auth.kind !== WALLET_AUTH_METHODS.passkey) {
    throw new Error('[SigningEngine][near] Passkey public lane authority is required');
  }
  const auth = args.laneIdentity.auth;
  const signer = args.laneIdentity.signer;
  const matches = (await args.store.listLanes()).filter(
    (reference) =>
      reference.auth.kind === WALLET_AUTH_METHODS.passkey &&
      reference.auth.rpId === auth.rpId &&
      reference.auth.credentialIdB64u === auth.credentialIdB64u &&
      String(reference.walletId) === String(signer.account.wallet.walletId) &&
      String(reference.nearAccountId) === String(signer.account.nearAccountId) &&
      String(reference.nearEd25519SigningKeyId) === String(signer.nearEd25519SigningKeyId) &&
      reference.signerSlot === signer.signerSlot &&
      String(reference.thresholdSessionId) === String(args.laneIdentity.thresholdSessionId),
  );
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0
        ? '[SigningEngine][near] Passkey public lane is unavailable'
        : '[SigningEngine][near] Passkey public lane is ambiguous',
    );
  }
  return matches[0];
}

async function resolveExactNearEd25519PublicLaneReference(args: {
  store: Ed25519YaoPublicCapabilityReferenceStorePort;
  identity: NearEd25519MaterialIdentity;
  materialActivation: MpcMaterialActivationRef;
}): Promise<Ed25519YaoPublicCapabilityLaneReferenceV1> {
  const signer = args.identity.signer;
  const matches = (await args.store.listLanes()).filter(
    (reference) =>
      String(reference.walletId) === String(signer.account.wallet.walletId) &&
      String(reference.nearAccountId) === String(signer.account.nearAccountId) &&
      String(reference.nearEd25519SigningKeyId) === String(signer.nearEd25519SigningKeyId) &&
      reference.signerSlot === signer.signerSlot &&
      String(reference.thresholdSessionId) === String(args.identity.thresholdSessionId) &&
      nearEd25519AuthBindingsEqual(reference.auth, args.identity.auth) &&
      mpcMaterialActivationRefsEqual(reference.materialActivation, args.materialActivation),
  );
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0
        ? '[SigningEngine][near] exact Ed25519 public lane is unavailable'
        : '[SigningEngine][near] exact Ed25519 public lane is ambiguous',
    );
  }
  return matches[0];
}

async function requireExactPasskeyWalletSessionAuthority(args: {
  reference: Ed25519YaoPublicCapabilityLaneReferenceV1;
  authorization: ExactNearEd25519WalletSessionAuthorization;
}): Promise<WalletAuthAuthorityRef> {
  if (args.reference.auth.kind !== WALLET_AUTH_METHODS.passkey) {
    throw new Error('[SigningEngine][near] Passkey public lane authority is required');
  }
  if (
    args.authorization.selectedAuthMethod.kind !== WALLET_AUTH_METHODS.passkey ||
    String(args.authorization.session.walletId) !== String(args.reference.walletId)
  ) {
    throw new Error('[SigningEngine][near] Passkey Wallet Session authority does not match lane');
  }
  const method = await IndexedDBManager.getWalletAuthMethodV2(
    args.authorization.selectedAuthMethod.walletAuthMethodId,
  );
  if (
    !method ||
    method.kind !== WALLET_AUTH_METHODS.passkey ||
    method.status !== 'active' ||
    String(method.walletId) !== String(args.reference.walletId) ||
    String(method.rpId) !== String(args.reference.auth.rpId) ||
    String(method.credentialIdB64u) !== String(args.reference.auth.credentialIdB64u)
  ) {
    throw new Error('[SigningEngine][near] Passkey Wallet Session method does not match lane');
  }
  const authority = await walletAuthAuthorityRef({
    authority: {
      walletId: method.walletId,
      factor: {
        kind: WALLET_AUTH_METHODS.passkey,
        credentialIdB64u: method.credentialIdB64u,
      },
      verifier: {
        kind: 'webauthn',
        rpId: method.rpId,
      },
      bindingId: method.walletAuthMethodId,
    },
  });
  const selectedFactorRef = await walletAuthAuthorityRef({
    authority: args.authorization.selectedFactorAuthority,
  });
  if (
    authority.authorityDigest !== selectedFactorRef.authorityDigest ||
    authority.walletAuthMethodId !== selectedFactorRef.walletAuthMethodId
  ) {
    throw new Error('[SigningEngine][near] Passkey Wallet Session authority changed');
  }
  return authority;
}

async function passkeyWalletSessionStateFromPublicLane(args: {
  reference: Ed25519YaoPublicCapabilityLaneReferenceV1;
  material: NearEd25519YaoOperationMaterial;
  authorization: ExactNearEd25519WalletSessionAuthorization;
  materialActivation: MpcMaterialActivationRef;
  relayerUrl: string;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  if (args.reference.auth.kind !== WALLET_AUTH_METHODS.passkey) {
    throw new Error('[SigningEngine][near] Passkey public lane authority is required');
  }
  if (
    !nearEd25519SessionMatchesMaterialActivation({
      session: args.authorization.session,
      materialActivation: args.materialActivation,
    })
  ) {
    throw new Error('[SigningEngine][near] Passkey Wallet Session material changed');
  }
  const authority = await requireExactPasskeyWalletSessionAuthority({
    reference: args.reference,
    authorization: args.authorization,
  });
  const authorizationId = parseWalletSessionAuthorizationId(
    args.authorization.session.authorizationId,
  );
  if (!authorizationId.ok || args.authorization.operationCredential.token.trim().length === 0) {
    throw new Error(
      '[SigningEngine][near] Passkey Ed25519 Wallet Session credential is unavailable',
    );
  }
  const facts = args.material.facts;
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(args.reference.walletId),
    nearAccountId: String(args.reference.nearAccountId),
    nearEd25519SigningKeyId: String(args.reference.nearEd25519SigningKeyId),
    walletSessionId: args.authorization.operationCredential.walletSessionId,
    authorizationId: authorizationId.value,
    quotaId: args.authorization.session.quotaId,
    thresholdSessionId: args.reference.thresholdSessionId,
    remainingUses: args.authorization.status.remainingUses,
    expiresAtMs: args.authorization.status.expiresAtMs,
    runtimePolicyScope: facts.runtimePolicyScope,
    signingRootId: facts.signingRootId,
    signingRootVersion: facts.signingRootVersion,
    routerAbNormalSigning: facts.routerAbNormalSigning,
    walletSessionToken: requireOpaqueWalletSessionToken(
      args.authorization.operationCredential.token,
      '[SigningEngine][near] Passkey Ed25519 Wallet Session token',
    ),
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `[SigningEngine][near] Passkey Wallet Session is unusable (${signingWalletSession.reason})`,
    );
  }
  return buildPasskeyRouterAbEd25519WalletSessionState({
    walletId: args.reference.walletId,
    nearAccountId: args.reference.nearAccountId,
    nearEd25519SigningKeyId: args.reference.nearEd25519SigningKeyId,
    signerSlot: args.reference.signerSlot,
    rpId: args.reference.auth.rpId,
    credentialIdB64u: args.reference.auth.credentialIdB64u,
    relayerUrl: args.relayerUrl,
    authority,
    signingWalletSession: signingWalletSession.value,
  });
}

async function requireExactEd25519SealedRuntimeForLane(args: {
  walletId: WalletId;
  laneIdentity: ExactEd25519SigningLaneIdentity;
}): Promise<ExactEd25519SealedSessionRuntime> {
  const resolution = await resolveExactEd25519SealedSessionRuntimeForLane(args);
  if (resolution.kind !== 'resolved') {
    throw new Error(`[SigningEngine][near] exact persisted Ed25519 runtime is ${resolution.kind}`);
  }
  return resolution.runtime;
}

async function requireExactEd25519SealedRuntimeForMaterialActivation(args: {
  walletId: WalletId;
  laneIdentity: ExactEd25519SigningLaneIdentity | ExactEd25519ExportMaterialIdentity;
  materialActivation: MpcMaterialActivationRef;
}): Promise<ExactEd25519SealedSessionRuntime> {
  const record = await readExactEd25519SealedSession(
    ed25519DurableMaterialLocator({
      authMethod: args.laneIdentity.auth.kind,
      materialActivation: args.materialActivation,
    }),
  );
  if (!record || record.curve !== 'ed25519') {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 runtime is missing');
  }
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (
    !runtime ||
    String(runtime.walletId) !== String(args.walletId) ||
    String(runtime.nearAccountId) !== String(args.laneIdentity.signer.account.nearAccountId) ||
    String(runtime.nearEd25519SigningKeyId) !==
      String(args.laneIdentity.signer.nearEd25519SigningKeyId) ||
    runtime.signerSlot !== args.laneIdentity.signer.signerSlot ||
    String(runtime.thresholdSessionId) !== String(args.laneIdentity.thresholdSessionId) ||
    !nearEd25519AuthBindingsEqual(runtime.auth, args.laneIdentity.auth) ||
    !mpcMaterialActivationRefsEqual(
      runtime.sealedRecord.ed25519Restore.materialActivation,
      args.materialActivation,
    )
  ) {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 runtime identity mismatch');
  }
  return runtime;
}

async function requireExactEd25519SealedRuntimeForMaterialIdentity(args: {
  walletId: WalletId;
  identity: NearEd25519MaterialIdentity;
}): Promise<ExactEd25519SealedSessionRuntime> {
  const records = await listExactSealedSessionsForWallet({
    walletId: args.walletId,
    filter: {
      authMethod: args.identity.auth.kind,
      curve: 'ed25519',
    },
  });
  const runtimes = records
    .filter(
      (record): record is Extract<CurrentSealedSessionRecord, { curve: 'ed25519' }> =>
        record.curve === 'ed25519',
    )
    .map(parseExactEd25519SealedSessionRuntime)
    .filter(
      (runtime): runtime is ExactEd25519SealedSessionRuntime =>
        runtime !== null &&
        nearEd25519RuntimeMatchesMaterialIdentity({ runtime, identity: args.identity }),
    );
  if (runtimes.length === 0) {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 runtime is missing');
  }
  if (runtimes.length !== 1) {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 runtime is conflicting');
  }
  return runtimes[0];
}

function exactWalletSessionWithOperationCredentialOrThrow(
  result: WalletSessionAuthorizationExactOperationCredentialReadResult,
  message: string,
): Extract<WalletSessionAuthorizationExactOperationCredentialReadResult, { kind: 'found' }> | null {
  switch (result.kind) {
    case 'found':
      return result;
    case 'missing':
      return null;
    case 'upgrade_required':
      throw new WalletSessionAuthorizationUpgradeRequiredError(message);
  }
}

async function readExactOwnerLaneWalletSession(args: {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
}): Promise<void> {
  const read = await walletSessionAuthorizations.readExactActiveForWallet({
    walletId: args.walletId,
    authorityId: args.authorityId,
    authMethodId: args.authMethodId,
  });
  switch (read.kind) {
    case 'found':
      if (
        read.record.walletId !== args.walletId ||
        read.record.authorityId !== args.authorityId ||
        read.record.authMethodId !== args.authMethodId ||
        read.record.authorityDigestB64u !== args.authorityDigestB64u ||
        read.record.authorityRevocationEpoch !== args.authorityRevocationEpoch ||
        read.operationCredential.kind !== 'opaque_wallet_session_operation_credential_v1' ||
        read.operationCredential.token.trim().length === 0
      ) {
        throw new Error('[SigningEngine] selected Wallet Authority session identity mismatch');
      }
      if (read.record.expiresAtMs <= Date.now()) {
        throw new Error(
          '[SigningEngine] selected Wallet Authority session is unavailable: expired',
        );
      }
      return;
    case 'missing':
      throw new Error('[SigningEngine] selected Wallet Authority session is unavailable: missing');
    case 'upgrade_required':
      throw new WalletSessionAuthorizationUpgradeRequiredError(
        '[SigningEngine] selected Wallet Authority Wallet Session requires a newer client',
      );
    case 'corrupt':
      throw new Error('[SigningEngine] selected Wallet Authority session is unavailable: corrupt');
    case 'persistence_unavailable':
      throw new Error(
        '[SigningEngine] selected Wallet Authority session is unavailable: persistence_unavailable',
      );
    default:
      return assertNeverWalletSessionAuthorizationExactActiveRead(read);
  }
}

function assertNeverWalletSessionAuthorizationExactActiveRead(value: never): never {
  throw new Error(`Unknown exact Wallet Session authorization read: ${String(value)}`);
}

function operationStepUpProofMatchesSelectedWalletAuthMethod(args: {
  readonly walletId: WalletId;
  readonly proof: Ed25519OperationStepUpProof;
  readonly selected: Extract<ResolveSelectedWalletAuthorityResultV1, { readonly kind: 'resolved' }>;
}): boolean {
  const { selection, authMethod, authority } = args.selected;
  if (
    selection.lockState !== 'unlocked' ||
    selection.walletId !== args.walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.walletId !== args.walletId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authority.walletId !== args.walletId
  ) {
    return false;
  }
  switch (args.proof.kind) {
    case 'passkey':
      return (
        authMethod.kind === WALLET_AUTH_METHODS.passkey &&
        args.proof.authority.walletId === args.walletId &&
        args.proof.authority.bindingId === authMethod.walletAuthMethodId &&
        args.proof.authority.factor.credentialIdB64u === authMethod.credentialIdB64u &&
        args.proof.authority.verifier.rpId === authMethod.rpId
      );
    case 'email_otp':
      return (
        authMethod.kind === WALLET_AUTH_METHODS.emailOtp &&
        args.proof.authorityRef.walletId === args.walletId &&
        args.proof.authorityRef.walletAuthMethodId === authMethod.walletAuthMethodId
      );
    default:
      args.proof satisfies never;
      throw new Error('[SigningEngine][near] unsupported operation step-up proof');
  }
}

export async function resolveExactNearEd25519WalletSessionTokenForStepUp(args: {
  readonly walletId: WalletId;
  readonly proof: Ed25519OperationStepUpProof;
}): Promise<OpaqueWalletSessionToken> {
  const selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(args.walletId));
  if (selected.kind !== 'resolved') {
    const detail = selected.kind === 'integrity_error' ? `: ${selected.reason}` : '';
    throw new Error(`[SigningEngine][near] selected Wallet Authority is ${selected.kind}${detail}`);
  }
  if (
    !operationStepUpProofMatchesSelectedWalletAuthMethod({
      walletId: args.walletId,
      proof: args.proof,
      selected,
    })
  ) {
    throw new Error('[SigningEngine][near] operation step-up authority does not match selection');
  }
  const operation = await resolveWalletAuthorityOperation({
    selected: { authMethod: selected.authMethod, authority: selected.authority },
    operation: { kind: 'near_sign', operation: 'sign', keyFamily: 'ed25519' },
  });
  if (operation.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][near] selected Wallet Authority rejected signing (${operation.reason.kind})`,
    );
  }
  const exactSession = exactWalletSessionWithOperationCredentialOrThrow(
    await walletSessionAuthorizations.readExactWithOperationCredential({
      walletId: args.walletId,
      authorityId: selected.authority.authorityId,
      authMethodId: selected.authMethod.walletAuthMethodId,
    }),
    '[SigningEngine][near] exact Wallet Session requires a newer client',
  );
  const hasSigningSubject =
    exactSession?.record.capabilitySubjects.filter(
      (subject) =>
        subject.kind === 'sign' &&
        subject.keyFamily === 'ed25519' &&
        mpcMaterialActivationRefsEqual(
          subject.materialActivation,
          operation.value.materialActivation,
        ),
    ).length === 1;
  if (
    !exactSession ||
    exactSession.record.walletId !== args.walletId ||
    exactSession.record.authorityId !== selected.authority.authorityId ||
    exactSession.record.authMethodId !== selected.authMethod.walletAuthMethodId ||
    exactSession.record.authorityDigestB64u !== selected.authority.authorityDigestB64u ||
    exactSession.record.authorityRevocationEpoch !== selected.authority.revocationEpoch ||
    exactSession.record.expiresAtMs <= Date.now() ||
    !hasSigningSubject
  ) {
    throw new Error(
      '[SigningEngine][near] exact Wallet Session is unavailable for operation step-up',
    );
  }
  return requireOpaqueWalletSessionToken(
    exactSession.operationCredential.token,
    '[SigningEngine][near] exact Wallet Session token',
  );
}

async function walletSessionStateFromExactEd25519Runtime(args: {
  readonly runtime: ExactEd25519SealedSessionRuntime;
  readonly relayerUrl: string;
}): Promise<Awaited<ReturnType<typeof rebindRouterAbEd25519WalletSessionStateFromExactRuntime>>> {
  const authorization = await resolveBrowserActiveNearEd25519WalletSessionAuthorization(
    args.runtime.walletId,
    args.relayerUrl,
  );
  if (!authorization) {
    throw new Error('[SigningEngine][near] active Wallet Session authorization is unavailable');
  }
  return await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime: args.runtime,
    authorization,
    nowMs: Date.now(),
  });
}

function nearEd25519YaoRuntimeObservation(
  material: NearEd25519YaoOperationMaterial | null,
): NearEd25519YaoRuntimeObservationV1 {
  if (!material || material.activeClient.status().kind !== 'active') {
    return { kind: 'absent' };
  }
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(
    material.activeClient.metadata(),
  );
  return {
    kind: 'live',
    runtime: nearEd25519YaoRuntimeRef(materialActivation),
    materialActivation,
  };
}

type PrepareNearEd25519YaoMaterialBoundaryInput = Parameters<
  NearSigningApiDeps['prepareNearEd25519YaoMaterialBoundary']
>[0];

type AuthorizedNearEd25519YaoMaterialBoundaryInput = Extract<
  PrepareNearEd25519YaoMaterialBoundaryInput,
  { readonly laneIdentity: ExactEd25519SigningLaneIdentity }
>;

function nearEd25519MaterialIdentityFromBoundaryInput(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): NearEd25519MaterialIdentity {
  if (input.laneIdentity !== undefined) {
    return {
      kind: 'near_ed25519_material_identity',
      signer: input.laneIdentity.signer,
      auth: input.laneIdentity.auth,
      thresholdSessionId: input.laneIdentity.thresholdSessionId,
    };
  }
  return input.materialIdentity;
}

function nearEd25519AuthFromBoundaryInput(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): SigningLaneAuthBinding {
  return nearEd25519MaterialIdentityFromBoundaryInput(input).auth;
}

function nearEd25519PresentedAuthFromBoundaryInput(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): SigningLaneAuthBinding {
  if (input.auth !== undefined) return input.auth;
  return input.materialIdentity.auth;
}

function nearEd25519SignerFromBoundaryInput(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): NearEd25519SignerBinding {
  return nearEd25519MaterialIdentityFromBoundaryInput(input).signer;
}

function nearEd25519ThresholdSessionIdFromBoundaryInput(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): string {
  return String(nearEd25519MaterialIdentityFromBoundaryInput(input).thresholdSessionId);
}

function requireAuthorizedNearEd25519BoundaryInput(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): AuthorizedNearEd25519YaoMaterialBoundaryInput {
  if (input.laneIdentity === undefined || input.auth === undefined) {
    throw new Error('[SigningEngine][near] authorized lane identity is required');
  }
  return {
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    laneIdentity: input.laneIdentity,
    auth: input.auth,
  };
}

function authNeutralNearEd25519BoundaryInput(
  input: AuthorizedNearEd25519YaoMaterialBoundaryInput,
): Extract<
  PrepareNearEd25519YaoMaterialBoundaryInput,
  { readonly materialIdentity: NearEd25519MaterialIdentity }
> {
  return {
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    materialIdentity: nearEd25519MaterialIdentityFromBoundaryInput(input),
  };
}

async function emailOtpWalletSessionStateFromPublicLane(args: {
  reference: Ed25519YaoPublicCapabilityLaneReferenceV1;
  material: NearEd25519YaoOperationMaterial;
  authorization: ExactNearEd25519WalletSessionAuthorization;
  materialActivation: MpcMaterialActivationRef;
  relayerUrl: string;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  if (args.reference.auth.kind !== WALLET_AUTH_METHODS.emailOtp) {
    throw new Error('[SigningEngine][near] Email OTP public lane authority is required');
  }
  if (
    !nearEd25519SessionMatchesMaterialActivation({
      session: args.authorization.session,
      materialActivation: args.materialActivation,
    })
  ) {
    throw new Error('[SigningEngine][near] Email OTP Wallet Session material changed');
  }
  const authorizationId = parseWalletSessionAuthorizationId(
    args.authorization.session.authorizationId,
  );
  if (!authorizationId.ok || args.authorization.operationCredential.token.trim().length === 0) {
    throw new Error(
      '[SigningEngine][near] Email OTP Ed25519 Wallet Session credential is unavailable',
    );
  }
  const authority = await walletAuthAuthorityRef({
    authority: args.authorization.selectedFactorAuthority,
  });
  const facts = args.material.facts;
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(args.reference.walletId),
    nearAccountId: String(args.reference.nearAccountId),
    nearEd25519SigningKeyId: String(args.reference.nearEd25519SigningKeyId),
    walletSessionId: args.authorization.operationCredential.walletSessionId,
    authorizationId: authorizationId.value,
    quotaId: args.authorization.session.quotaId,
    thresholdSessionId: args.reference.thresholdSessionId,
    remainingUses: args.authorization.status.remainingUses,
    expiresAtMs: args.authorization.status.expiresAtMs,
    runtimePolicyScope: facts.runtimePolicyScope,
    signingRootId: facts.signingRootId,
    signingRootVersion: facts.signingRootVersion,
    routerAbNormalSigning: facts.routerAbNormalSigning,
    walletSessionToken: requireOpaqueWalletSessionToken(
      args.authorization.operationCredential.token,
      '[SigningEngine][near] Email OTP Ed25519 Wallet Session token',
    ),
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `[SigningEngine][near] Email OTP Wallet Session is unusable (${signingWalletSession.reason})`,
    );
  }
  return buildEmailOtpRouterAbEd25519WalletSessionState({
    walletId: args.reference.walletId,
    nearAccountId: args.reference.nearAccountId,
    nearEd25519SigningKeyId: args.reference.nearEd25519SigningKeyId,
    providerSubjectId: args.reference.auth.providerSubjectId,
    signerSlot: args.reference.signerSlot,
    relayerUrl: args.relayerUrl,
    authority,
    signingWalletSession: signingWalletSession.value,
  });
}

function nearEd25519AuthBindingsEqual(
  left: SigningLaneAuthBinding,
  right: SigningLaneAuthBinding,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case WALLET_AUTH_METHODS.passkey:
      return (
        right.kind === WALLET_AUTH_METHODS.passkey &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u
      );
    case WALLET_AUTH_METHODS.emailOtp:
      return (
        right.kind === WALLET_AUTH_METHODS.emailOtp &&
        left.providerSubjectId === right.providerSubjectId
      );
    default:
      left satisfies never;
      throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
  }
}

function nearEd25519RuntimeMatchesMaterialIdentity(args: {
  runtime: ExactEd25519SealedSessionRuntime;
  identity: NearEd25519MaterialIdentity;
}): boolean {
  const signer = args.identity.signer;
  return (
    String(args.runtime.walletId) === String(signer.account.wallet.walletId) &&
    String(args.runtime.nearAccountId) === String(signer.account.nearAccountId) &&
    String(args.runtime.nearEd25519SigningKeyId) === String(signer.nearEd25519SigningKeyId) &&
    args.runtime.signerSlot === signer.signerSlot &&
    String(args.runtime.thresholdSessionId) === String(args.identity.thresholdSessionId) &&
    nearEd25519AuthBindingsEqual(args.runtime.auth, args.identity.auth)
  );
}

type PreparedNearEd25519YaoMaterialContext = {
  input: PrepareNearEd25519YaoMaterialBoundaryInput;
  materialActivation: MpcMaterialActivationRef | null;
};

type EmailOtpEd25519OperationRecoveryContext = {
  input: PrepareNearEd25519YaoMaterialBoundaryInput;
  materialActivation: MpcMaterialActivationRef;
  facts: NearEd25519YaoOperationMaterialFacts;
  publicLane: Ed25519YaoPublicCapabilityLaneReferenceV1;
  sealedMaterial: LoadedWalletCustodyEd25519MaterialV1;
  operationalPublicKey: string;
  emailHashHex: string;
};

type EmailOtpEd25519OperationRecoveryRequest = Parameters<
  Extract<
    NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
    { kind: 'sealed' }
  >['authorizeAndRehydrate']
>[0];

function emailOtpEd25519OperationMaterialFacts(args: {
  input: PrepareNearEd25519YaoMaterialBoundaryInput;
  publicLane: Ed25519YaoPublicCapabilityLaneReferenceV1;
  relayerUrl: string;
}): NearEd25519YaoOperationMaterialFacts {
  const signingRoot = signingRootScopeFromRuntimePolicyScope(args.publicLane.runtimePolicyScope);
  if (!signingRoot.signingRootVersion) {
    throw new Error('[SigningEngine][near] Email OTP lane requires a signing-root version');
  }
  return {
    thresholdSessionId: args.publicLane.thresholdSessionId,
    signer: nearEd25519SignerFromBoundaryInput(args.input),
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: String(args.publicLane.materialActivation.signingWorker),
    },
    runtimePolicyScope: args.publicLane.runtimePolicyScope,
    relayerUrl: args.relayerUrl,
  };
}

function assertNearEd25519YaoMaterialBoundaryAuth(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): void {
  const expected = nearEd25519AuthFromBoundaryInput(input);
  const actual = nearEd25519PresentedAuthFromBoundaryInput(input);
  if (expected.kind !== actual.kind) {
    throw new Error('[SigningEngine][near] prepared material factor changed');
  }
  switch (actual.kind) {
    case WALLET_AUTH_METHODS.passkey:
      if (
        expected.kind !== WALLET_AUTH_METHODS.passkey ||
        expected.rpId !== actual.rpId ||
        expected.credentialIdB64u !== actual.credentialIdB64u
      ) {
        throw new Error('[SigningEngine][near] prepared Passkey material binding changed');
      }
      return;
    case WALLET_AUTH_METHODS.emailOtp:
      if (
        expected.kind !== WALLET_AUTH_METHODS.emailOtp ||
        expected.providerSubjectId !== actual.providerSubjectId
      ) {
        throw new Error('[SigningEngine][near] prepared Email OTP material binding changed');
      }
      return;
    default:
      actual satisfies never;
      throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
  }
}

function validateExactNearEd25519YaoOperationMaterial(args: {
  material: NearEd25519YaoOperationMaterial;
  input: PrepareNearEd25519YaoMaterialBoundaryInput;
  expectedActivation: MpcMaterialActivationRef;
}): NearEd25519YaoOperationMaterial {
  const facts = args.material.facts;
  const metadata = args.material.activeClient.metadata();
  const thresholdSessionId = nearEd25519ThresholdSessionIdFromBoundaryInput(args.input);
  const expectedSigner = nearEd25519SignerFromBoundaryInput(args.input);
  const actualSigner = facts.signer;
  if (String(facts.thresholdSessionId) !== thresholdSessionId) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability session mismatch');
  }
  if (metadata.scope.threshold_session_id !== String(facts.thresholdSessionId)) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao metadata session mismatch');
  }
  if (
    metadata.scope.account_id !== String(args.input.walletId) ||
    metadata.applicationBinding.wallet_id !== String(args.input.walletId)
  ) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability subject mismatch');
  }
  if (
    String(actualSigner.account.wallet.walletId) !==
      String(expectedSigner.account.wallet.walletId) ||
    String(actualSigner.account.nearAccountId) !== String(expectedSigner.account.nearAccountId) ||
    actualSigner.signerSlot !== expectedSigner.signerSlot ||
    String(actualSigner.nearEd25519SigningKeyId) !== String(expectedSigner.nearEd25519SigningKeyId)
  ) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability signer mismatch');
  }
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  if (!mpcMaterialActivationRefsEqual(args.expectedActivation, materialActivation)) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability activation mismatch');
  }
  return args.material;
}

async function hydrateOwnerNearEd25519ExecutionLane(args: {
  input: PrepareNearEd25519YaoMaterialBoundaryInput;
  authorization: ExactNearEd25519WalletSessionAuthorization;
  sealedRuntime: ExactEd25519SealedSessionRuntime;
  material: NearEd25519YaoOperationMaterial;
}): Promise<ActiveWalletExecutionLaneHydration> {
  const metadata = args.material.activeClient.metadata();
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  if (
    !nearEd25519SessionMatchesMaterialActivation({
      session: args.authorization.session,
      materialActivation,
    })
  ) {
    throw new Error('Owner Ed25519 execution-lane material changed');
  }
  const walletSessionToken = requireOpaqueWalletSessionToken(
    args.authorization.operationCredential.token,
    'Owner Ed25519 execution-lane Wallet Session token',
  );
  const exactMaterial = validateExactNearEd25519YaoOperationMaterial({
    material: args.material,
    input: args.input,
    expectedActivation: materialActivation,
  });
  const authority = await ed25519SealedRuntimeAuthorityRef({
    runtime: args.sealedRuntime,
    walletAuthMethodId: args.authorization.selectedAuthMethod.walletAuthMethodId,
  });
  if (
    String(authority.authorityDigest) !==
    String(args.authorization.selectedAuthority.authorityDigestB64u)
  ) {
    throw new Error('Owner Ed25519 execution-lane authority does not match sealed material');
  }
  const runtime = nearEd25519YaoRuntimeObservation(exactMaterial);
  if (runtime.kind !== 'live') {
    throw new Error('Owner Ed25519 execution-lane preflight requires active Yao material');
  }
  const hydration: NearEd25519YaoCapabilityHydrationInputV1 = {
    publicLocator: {
      kind: 'available',
      walletId: String(exactMaterial.facts.signer.account.wallet.walletId),
      nearAccountId: String(exactMaterial.facts.signer.account.nearAccountId),
      signerSlot: exactMaterial.facts.signer.signerSlot,
      materialActivation,
      authority,
    },
    sealed: { kind: 'missing' },
    runtime,
    unlockSource: { kind: 'unavailable' },
  };
  const projection = await readOwnerWalletExecutionLaneProjectionV1({
    relayerUrl: exactMaterial.facts.relayerUrl,
    walletSessionToken,
    curve: 'ed25519',
    expectedMaterialActivation: materialActivation,
  });
  return assertOwnerNearEd25519ExecutionLaneProjection({
    projection,
    material: exactMaterial,
    hydration,
  });
}

function assertOwnerNearEd25519ExecutionLaneProjection(args: {
  projection: OwnerWalletExecutionLaneProjectionV1;
  material: NearEd25519YaoOperationMaterial;
  hydration: NearEd25519YaoCapabilityHydrationInputV1;
}): ActiveWalletExecutionLaneHydration {
  const hydrated = hydrateWalletExecutionLane({
    walletKey: args.projection.walletKey,
    lane: args.projection.lane,
    material: {
      keyFamily: 'ed25519',
      laneShareEpoch: args.projection.lane.laneShareEpoch,
      metadata: args.material.activeClient.metadata(),
      hydration: args.hydration,
    },
  });
  if (hydrated.kind !== 'active_wallet_execution_lane_v1') {
    throw new Error(`Owner Ed25519 execution lane is ${hydrated.reason}`);
  }
  if (
    !mpcMaterialActivationRefsEqual(
      hydrated.materialActivation,
      args.projection.materialActivation,
    ) ||
    hydrated.activationReceiptDigestB64u !==
      String(args.projection.verifiedActivationReceiptDigestB64u)
  ) {
    throw new Error('Owner Ed25519 execution-lane projection activation changed');
  }
  return hydrated;
}

function requireNearEd25519YaoPreparationActivation(
  preparation: NearEd25519YaoSigningPreparation,
): MpcMaterialActivationRef {
  const materialActivation = preparation.hydration.materialActivation;
  if (!materialActivation) {
    throw new Error('[SigningEngine][near] prepared material has no activation');
  }
  return materialActivation;
}

function requireBoundNearEd25519YaoPreparationActivation(args: {
  context: PreparedNearEd25519YaoMaterialContext;
  preparation: NearEd25519YaoSigningPreparation;
}): MpcMaterialActivationRef {
  const materialActivation = requireNearEd25519YaoPreparationActivation(args.preparation);
  if (
    !args.context.materialActivation ||
    !mpcMaterialActivationRefsEqual(args.context.materialActivation, materialActivation)
  ) {
    throw new Error('[SigningEngine][near] prepared material boundary changed activation');
  }
  return materialActivation;
}

type RuntimePortsRef = {
  current: RuntimePorts | null;
};

function serializePreparedRegistrationCredential(
  credential: PublicKeyCredential,
): WebAuthnRegistrationCredential {
  return serializeRegistrationCredentialWithPRF({
    credential,
    firstPrfOutput: true,
    secondPrfOutput: true,
  });
}

async function loadEcdsaRoleLocalReadyRecordFromRuntimePorts(
  runtimePortsRef: RuntimePortsRef,
  input: Parameters<DurableRecordStore['loadEcdsaRoleLocalReadyRecord']>[0],
): ReturnType<DurableRecordStore['loadEcdsaRoleLocalReadyRecord']> {
  if (!runtimePortsRef.current) {
    return {
      ok: false,
      code: 'unavailable',
      message: 'Signing runtime storage is not initialized',
    };
  }
  return await runtimePortsRef.current.storage.loadEcdsaRoleLocalReadyRecord(input);
}

function sdkLifecycleEventDeliveryKey(event: SdkLifecycleEvent): string {
  const eventName = event.event;
  switch (eventName) {
    case 'signing_session.expired':
      return `${String(event.walletId)}:${String(event.walletSessionId)}`;
    case 'registration.near_provisioning_changed':
      return `${String(event.walletId)}:${event.state.status}:${event.state.updatedAtMs}`;
    default:
      return assertNeverSdkLifecycleEventName(eventName);
  }
}

function assertNeverSdkLifecycleEventName(value: never): never {
  throw new Error(`Unsupported SDK lifecycle event: ${String(value)}`);
}

export class BrowserSigningSurface {
  // Kept as fields for low-level tests that intentionally access internals.
  private readonly touchConfirm: UiConfirmRuntimeBridgePort;
  private readonly passkeyMpcSession: PasskeyMpcSessionPort;
  private readonly signerWorkerManager: SignerWorkerManager;
  private readonly touchIdPrompt: TouchIdPrompt;
  private readonly userPreferencesManager: UserPreferencesManager;
  private readonly nearClient: NearClient;
  private readonly nonceCoordinator: NonceCoordinator;
  private workerBaseOrigin: string = '';
  private appearance: AppearanceConfig;
  private readonly thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>> = new Map();
  private readonly thresholdEcdsaSigningQueueByKey: ThresholdEcdsaSigningQueueByKey = new Map();
  private readonly thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey = new Map();
  private readonly nearEd25519CapabilityRehydrationBySubject: Map<
    string,
    Promise<NearEd25519CapabilityRehydrationSubject>
  > = new Map();
  private readonly emailOtpSessions: EmailOtpWalletSessionCoordinator;
  private readonly thresholdEcdsaExportArtifactByLane: Map<
    string,
    ThresholdEcdsaCanonicalExportArtifact
  >;
  private readonly warmSigning: WarmSigningPorts;
  private readonly passkeyPublicDeps: PasskeyPublicDeps;
  private readonly warmCapabilitiesPublicDeps: WarmCapabilitiesPublicDeps;
  private readonly sessionPublicDeps: SessionPublicDeps;
  private readonly emailOtpPublicDeps: EmailOtpPublicDeps;
  private readonly recoveryPublicDeps: RecoveryPublicDeps;
  private readonly registrationPublicDeps: registrationPublic.RegistrationPublicDeps;
  private readonly sealedRefreshStartupParityPromise: Promise<void>;
  private hostWarmCriticalResourcesTask: Promise<WorkerResourceWarmupDiagnostics> | null = null;
  private sealedRefreshStartupParityError: Error | null = null;
  private readonly signingRuntime: SigningRuntime;
  private readonly runtimePorts: RuntimePorts;
  private readonly enginePorts: BrowserSigningSurfaceEnginePorts;
  private readonly ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;
  private readonly ed25519YaoPageLifecycleOwner: Ed25519YaoPageLifecycleOwner;
  private readonly ed25519YaoPublicCapabilityReferences: BrowserSigningSurfaceConstructorDeps['ed25519YaoPublicCapabilityReferences'];
  private readonly sdkLifecycleEventListeners = new Set<SdkLifecycleEventListener>();
  private readonly deliveredSdkLifecycleEventKeys = new Set<string>();
  private readonly signingSessionLifecycleSubscription: SigningSessionLifecycleSubscription;
  private readonly nearProvisioningUnsubscribe: () => void;
  private walletAuthenticationState: WalletAuthenticationState = { kind: 'signed_out' };
  private walletAuthenticationRestoreGeneration = 0;
  private volatileWarmSigningMaterialCleanupInFlight: Promise<void> | null = null;

  readonly seamsWebConfigs: SeamsConfigsReadonly;

  private readExactNearEd25519WalletSessionAuthorization(
    walletId: WalletId,
  ): ReturnType<typeof readBrowserExactNearEd25519WalletSessionAuthorization> {
    return readBrowserExactNearEd25519WalletSessionAuthorization(
      walletId,
      String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
    );
  }

  private resolveActiveNearEd25519WalletSessionAuthorization(
    walletId: WalletId,
  ): ReturnType<typeof resolveBrowserActiveNearEd25519WalletSessionAuthorization> {
    return resolveBrowserActiveNearEd25519WalletSessionAuthorization(
      walletId,
      String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
    );
  }

  constructor(
    seamsWebConfigs: SeamsConfigsReadonly,
    nearClient: NearClient,
    deps: BrowserSigningSurfaceConstructorDeps,
  ) {
    this.seamsWebConfigs = seamsWebConfigs;
    this.ed25519YaoPublicCapabilityReferences = deps.ed25519YaoPublicCapabilityReferences;
    this.appearance = seamsWebConfigs.ui.appearance;
    this.nearClient = nearClient;
    this.ecdsaBootstrapStore =
      deps.signingEngineStores.walletProfileAndSignerRecords.ecdsaBootstrapStore;
    this.sealedRefreshStartupParityPromise = verifySealedRefreshStartupParity({
      configs: this.seamsWebConfigs,
    }).catch((error: unknown) => {
      this.sealedRefreshStartupParityError =
        error instanceof Error
          ? error
          : new Error(String(error || 'sealed refresh parity check failed'));
    });
    const runtimePortsForUiConfirm: RuntimePortsRef = { current: null };
    const loadEcdsaRoleLocalReadyRecord: DurableRecordStore['loadEcdsaRoleLocalReadyRecord'] =
      loadEcdsaRoleLocalReadyRecordFromRuntimePorts.bind(null, runtimePortsForUiConfirm);

    const assembly = createManagerAssembly({
      resolveOperationStepUpCredential: this.resolveOperationStepUpCredential.bind(this),
      stores: deps.managerStores,
      seamsWebConfigs: this.seamsWebConfigs,
      nearClient: this.nearClient,
      loadEcdsaRoleLocalReadyRecord,
      getTheme: () => this.appearance.theme.mode,
      getAppearance: () => this.appearance,
      thresholdEcdsaSigningQueueByKey: this.thresholdEcdsaSigningQueueByKey,
    });

    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceCoordinator = assembly.nonceCoordinator;
    this.signerWorkerManager = assembly.signerWorkerManager;
    const signingRuntime = deps.createRuntime({
      config: this.seamsWebConfigs,
      workerCtx: this.signerWorkerManager.getContext(),
      accountLifecycle: {
        accountStore: deps.signingEngineStores.walletProfileAndSignerRecords.accountStore,
        userPreferencesManager: this.userPreferencesManager,
        nonceCoordinator: this.nonceCoordinator,
      },
      ecdsaBootstrapStore: this.ecdsaBootstrapStore,
      getWarmSessionMaterialWriter: () => this.passkeyMpcSession,
      getNearSigningDeps: () => this.enginePorts.nearSigningDeps,
      getEvmFamilySigningDeps: () => this.enginePorts.tempoSigningDeps,
    });
    this.signingRuntime = signingRuntime;
    runtimePortsForUiConfirm.current = signingRuntime.runtimePorts;
    const ecdsaExportArtifactStore = signingRuntime.state.ecdsaSessions;
    this.runtimePorts = signingRuntime.runtimePorts;
    this.thresholdEcdsaExportArtifactByLane =
      signingRuntime.state.ecdsaSessions.exportArtifactsByLane;
    const stepUpRuntime = createBrowserStepUpRuntime({
      seamsWebConfigs: this.seamsWebConfigs,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      stores: deps.signingEngineStores,
      runtimePorts: this.runtimePorts,
      sealedSigningSessionStore: deps.sealedSigningSessionStore,
      baseTouchConfirm: assembly.touchConfirm,
      passkeyMpcSession: assembly.passkeyMpcSession,
      getEnginePorts: () => this.enginePorts,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      thresholdEcdsaSigningQueueByKey: this.thresholdEcdsaSigningQueueByKey,
      loadWalletCustodyEd25519Material: this.loadEmailOtpWalletCustodyEd25519Material.bind(this),
      restoreWalletCustodyEcdsaContinuity: this.restoreWalletCustodyEcdsaContinuity.bind(this),
      getWarmSigning: () => this.warmSigning,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      listActiveEcdsaCapabilityManifestsForWallet:
        listBrowserActiveEcdsaCapabilityManifestsForWallet,
    });
    this.emailOtpSessions = stepUpRuntime.emailOtpSessions;
    this.touchConfirm = stepUpRuntime.touchConfirm;
    this.passkeyMpcSession = stepUpRuntime.passkeyMpcSession;
    this.warmSigning = createWarmSigningPorts({
      touchConfirm: this.touchConfirm,
      passkeyMpcSession: this.passkeyMpcSession,
      getEmailOtpWarmSessionStatus: (target) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(target),
      signingSessionSeal: this.seamsWebConfigs.signing.sessionSeal,
      ecdsaExportArtifacts: ecdsaExportArtifactStore,
      resolveActiveEcdsaWalletSessionAuthorization:
        createBrowserActiveEcdsaWalletSessionAuthorizationResolver({
          seamsWebConfigs: this.seamsWebConfigs,
          touchIdPrompt: this.touchIdPrompt,
          stores: deps.signingEngineStores,
          emailOtpSessions: this.emailOtpSessions,
          sealedSigningSessionStore: deps.sealedSigningSessionStore,
        }),
      resolveActiveEd25519WalletSessionAuthorization:
        this.resolveActiveNearEd25519WalletSessionAuthorization.bind(this),
    });
    this.sessionPublicDeps = createSessionPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      touchConfirm: this.touchConfirm,
      passkeyMpcSession: this.passkeyMpcSession,
      emailOtpSessions: this.emailOtpSessions,
      ed25519YaoPublicCapabilityLanes: deps.ed25519YaoPublicCapabilityReferences,
      isEd25519YaoPublicCapabilityActive: this.isEd25519YaoPublicCapabilityActive.bind(this),
      readActiveWalletSessionAuthorization:
        this.readExactNearEd25519WalletSessionAuthorization.bind(this),
      listEcdsaSigningCapabilitiesForWallet: (input) =>
        listBrowserEcdsaSigningCapabilitiesForWallet(
          {
            seamsWebConfigs: this.seamsWebConfigs,
            touchIdPrompt: this.touchIdPrompt,
            stores: deps.signingEngineStores,
            emailOtpSessions: this.emailOtpSessions,
            sealedSigningSessionStore: deps.sealedSigningSessionStore,
          },
          input,
        ),
      getWalletSessionStatus: createBrowserCanonicalWalletSessionStatusReader({
        seamsWebConfigs: this.seamsWebConfigs,
        touchIdPrompt: this.touchIdPrompt,
        stores: deps.signingEngineStores,
        emailOtpSessions: this.emailOtpSessions,
        sealedSigningSessionStore: deps.sealedSigningSessionStore,
      }),
    });
    this.emailOtpPublicDeps = {
      relayerUrl: this.seamsWebConfigs.network.relayer?.url || '',
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      getSignerWorkerContext: () =>
        this.enginePorts.walletSessionActivationDeps.getSignerWorkerContext(),
      withThresholdEcdsaSigningQueue: (queueArgs) =>
        withThresholdEcdsaSigningQueue({
          queueByKey: this.thresholdEcdsaSigningQueueByKey,
          ...queueArgs,
        }),
      emailOtpSessions: this.emailOtpSessions,
    };
    this.recoveryPublicDeps = createBrowserRecoveryPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      runtimePorts: this.runtimePorts,
      signerWorkerManager: this.signerWorkerManager,
      warmSigning: this.warmSigning,
      touchConfirm: this.touchConfirm,
      passkeyMpcSession: this.passkeyMpcSession,
      passkeyMpcExport: assembly.passkeyMpcExport,
      emailOtpSessions: this.emailOtpSessions,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      thresholdEcdsaSigningQueueByKey: this.thresholdEcdsaSigningQueueByKey,
      thresholdEd25519CommitQueueByKey: this.thresholdEd25519CommitQueueByKey,
      getWalletSessionActivationDeps: () => this.enginePorts.walletSessionActivationDeps,
      resolvePasskeyEd25519YaoExportContext:
        this.resolveExactPasskeyEd25519YaoExportContext.bind(this),
      resolveEmailOtpEd25519YaoExportContext:
        this.resolveEmailOtpEd25519YaoExportContext.bind(this),
      getSigningSessionCoordinator: () => this.enginePorts.signingSessionCoordinator,
      getTheme: () => this.appearance.theme.mode,
      ed25519YaoPublicCapabilityLanes: deps.ed25519YaoPublicCapabilityReferences,
      isEd25519YaoPublicCapabilityActive: this.isEd25519YaoPublicCapabilityActive.bind(this),
      readActiveWalletSessionAuthorization:
        this.readExactNearEd25519WalletSessionAuthorization.bind(this),
      listEcdsaSigningCapabilitiesForWallet: (input) =>
        listBrowserEcdsaSigningCapabilitiesForWallet(
          {
            seamsWebConfigs: this.seamsWebConfigs,
            touchIdPrompt: this.touchIdPrompt,
            stores: deps.signingEngineStores,
            emailOtpSessions: this.emailOtpSessions,
            sealedSigningSessionStore: deps.sealedSigningSessionStore,
          },
          input,
        ),
      resolveOwnerLaneScope: (walletId) => this.resolveActiveOwnerLaneScope(walletId),
    });

    this.enginePorts = createBrowserSigningSurfaceEnginePorts({
      runtimePorts: this.runtimePorts,
      stores: deps.signingEngineStores,
      ed25519YaoPublicCapabilityReferences: deps.ed25519YaoPublicCapabilityReferences,
      seamsWebConfigs: this.seamsWebConfigs,
      nearClient: this.nearClient,
      touchIdPrompt: this.touchIdPrompt,
      userPreferencesManager: this.userPreferencesManager,
      nonceCoordinator: this.nonceCoordinator,
      touchConfirm: this.touchConfirm,
      passkeyMpcSession: this.passkeyMpcSession,
      passkeyMpcExport: assembly.passkeyMpcExport,
      signerWorkerManager: this.signerWorkerManager,
      emailOtpSessions: this.emailOtpSessions,
      warmSigning: this.warmSigning,
      sealedSigningSessionStore: deps.sealedSigningSessionStore,
      ecdsaBootstrapStore: this.ecdsaBootstrapStore,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      thresholdEcdsaSigningQueueByKey: this.thresholdEcdsaSigningQueueByKey,
      thresholdEd25519CommitQueueByKey: this.thresholdEd25519CommitQueueByKey,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      workerWarmupPolicy: deps.workerWarmupPolicy,
      getTheme: () => this.appearance.theme.mode,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      resolveOwnerLaneScope: (walletId) => this.resolveActiveOwnerLaneScope(walletId),
      getEnginePorts: () => this.enginePorts,
      getRegistrationPublicDeps: () => this.registrationPublicDeps,
      prepareNearEd25519YaoMaterialBoundary:
        this.prepareExactNearEd25519YaoMaterialBoundary.bind(this),
    });
    this.signingSessionLifecycleSubscription =
      this.enginePorts.signingSessionCoordinator.subscribeLifecycle(
        this.publishSdkLifecycleEvent.bind(this),
      );
    const nearProvisioningListener: NearProvisioningListener =
      this.publishNearProvisioningLifecycleEvent.bind(this);
    this.nearProvisioningUnsubscribe = subscribeToNearProvisioning(nearProvisioningListener);
    this.ed25519YaoPageLifecycleOwner = new Ed25519YaoPageLifecycleOwner(
      typeof window === 'undefined' ? null : window,
      this.enginePorts.ed25519YaoActiveClients,
    );
    const warmSessionPublicDeps = createBrowserWarmSessionPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      stores: deps.signingEngineStores,
      touchIdPrompt: this.touchIdPrompt,
      touchConfirm: this.touchConfirm,
      passkeyMpcSession: this.passkeyMpcSession,
      warmSigning: this.warmSigning,
      runtimePorts: this.runtimePorts,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      enginePorts: this.enginePorts,
    });
    this.passkeyPublicDeps = warmSessionPublicDeps.passkeyPublicDeps;
    this.warmCapabilitiesPublicDeps = warmSessionPublicDeps.warmCapabilitiesPublicDeps;
    this.registrationPublicDeps = {
      accountLifecycle: this.enginePorts.registrationAccountLifecycleDeps,
      session: this.enginePorts.registrationSessionDeps,
    };

    /* R109C: every path that unlocks a pre-109C envelope reseals it, and the
       reseal has nowhere to go without the relayer and the Wallet Session that
       only the host holds. Registered once, from the one object that has both. */
    setUnlockedCustodyEnvelopeUpgradeSinkV1((upgrade) => {
      void this.persistUpgradedWalletCustodyEnvelopeV1(upgrade);
    });

    deps.initializeRuntime({
      config: this.seamsWebConfigs,
      userPreferencesManager: this.userPreferencesManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      setWorkerBaseOrigin: (origin: string) => {
        this.workerBaseOrigin = origin;
        this.signerWorkerManager.setWorkerBaseOrigin(origin);
        this.touchConfirm.setWorkerBaseOrigin?.(origin);
        assembly.passkeyMpcExport.setWorkerBaseOrigin(origin);
        this.passkeyMpcSession.setWorkerBaseOrigin(origin);
      },
    });
  }

  private async resolveOperationStepUpCredential(args: {
    walletId: WalletId;
    relayerUrl: string;
    proof: Ed25519OperationStepUpProof;
  }): Promise<RouterAbOwnerNormalSigningCredential> {
    const walletSessionToken = await resolveExactNearEd25519WalletSessionTokenForStepUp({
      walletId: args.walletId,
      proof: args.proof,
    });
    return { kind: 'wallet_session_opaque', walletSessionToken };
  }

  private async ensureSealedRefreshStartupParity(): Promise<void> {
    await this.sealedRefreshStartupParityPromise;
    if (this.sealedRefreshStartupParityError) {
      throw this.sealedRefreshStartupParityError;
    }
  }

  /**
   * Runs one wallet custody key set for NEAR, from the registration flow.
   *
   * The flow never touches the ceremony worker itself: a run's seed lives in
   * that worker's wasm state across three steps, so this is the one place the
   * channel is reached and the one place the Router round is wired to it.
   *
   * The Router round is performed through the same HTTP transport the
   * PRF-derived path used, so the execute request goes to the same endpoint
   * with the same trace context — only the root behind it changed.
   */
  async establishWalletCustodyNearEd25519KeySet(args: {
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
  }): Promise<EstablishedWalletCustodyNearEd25519KeySetV1> {
    const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
      routerOrigin: args.routerOrigin,
      authorization: { kind: 'bearer', value: args.authorization },
      fetch: globalThis.fetch,
      ...(args.traceContext ? { traceContext: args.traceContext } : {}),
    });

    let activationResultJson: string | null = null;
    const established = await establishNearEd25519CustodyV1({
      runStep: walletCustodyCeremonyStepRunner({
        requestOperation: (operation) =>
          this.signerWorkerManager.requestWorkerOperation(
            operation as Parameters<SignerWorkerManager['requestWorkerOperation']>[0],
          ),
      }),
      walletId: args.walletId,
      factorJson: args.factorJson,
      factorSecret: args.factorSecret,
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      registrationCeremonyId: args.registrationCeremonyId,
      yaoAdmission: args.admissionReceipt,
      yaoApplication: args.admissionRequest.application_binding,
      participantIds: args.participantIds,
      runRouterRound: async (yaoExecuteRequestJson: string) => {
        const response = await transport.send({
          kind: 'execute',
          path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
          body: JSON.parse(yaoExecuteRequestJson),
        });
        if (!response.ok) {
          throw new Error(`Router Ed25519 Yao execute failed: ${response.message}`);
        }
        /* Kept so the metadata below is rebuilt from the same bytes the
           ceremony completed against — re-fetching could return a different
           activation and describe a key this run did not register. */
        activationResultJson = JSON.stringify(response.value);
        return activationResultJson;
      },
    });

    if (!activationResultJson) {
      throw new Error('the wallet custody NEAR run completed without a Router activation result');
    }
    if (!established.localMaterial) {
      throw new Error('the wallet custody NEAR run sealed no local material');
    }
    return {
      recoveryCodes: established.recoveryCodes,
      commitPayload: established.commitPayload,
      activationReference: established.activationReference,
      localMaterial: established.localMaterial,
      metadata: walletCustodyEd25519ActiveClientMetadataV1({
        admissionRequest: args.admissionRequest,
        activationResultJson,
      }),
    };
  }

  async recoverWalletCustodyManifest(
    args: Omit<Parameters<typeof recoverWalletCustodyManifestV1>[0], 'runStep' | 'workerCtx'>,
  ): Promise<Awaited<ReturnType<typeof recoverWalletCustodyManifestV1>>> {
    return await recoverWalletCustodyManifestV1({
      ...args,
      runStep: walletCustodyCeremonyStepRunner({
        requestOperation: (operation) =>
          this.signerWorkerManager.requestWorkerOperation(
            operation as Parameters<SignerWorkerManager['requestWorkerOperation']>[0],
          ),
      }),
      workerCtx: this.signerWorkerManager.getContext(),
    });
  }

  async createWalletRecoveryReplacementCredential(args: {
    readonly walletId: WalletId;
    readonly registration: WalletRecoveryRegistrationOptions;
    readonly cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>;
  }): Promise<WalletRecoveryReplacementCredential> {
    const requestId = walletIframeRequestIdFromBoundary(
      `wallet-recovery:${args.registration.challengeId}`,
    );
    const credentialPromise = this.touchIdPrompt.generateRegistrationCredentialsInternal({
      kind: 'wallet_recovery',
      walletId: args.walletId,
      intendedUserName: args.walletId,
      recoveryRegistration: args.registration,
      prompt: {
        kind: 'immediate',
        requestId,
        cancellation: args.cancellation,
      },
    });
    const credential = await credentialPromise;
    const replacement = walletRecoveryReplacementCredentialFromRegistrationV1(
      serializePreparedRegistrationCredential(credential),
    );
    return {
      registration: redactedPasskeyRegistrationCredential(replacement.registration),
      credentialIdB64u: replacement.credentialIdB64u,
      factorSecret: replacement.factorSecret,
    };
  }

  async joinWalletCustodyNearEd25519KeySet(args: {
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
  }): Promise<JoinedWalletCustodyNearEd25519KeySetV1> {
    const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
      routerOrigin: args.routerOrigin,
      authorization: { kind: 'bearer', value: args.authorization },
      fetch: globalThis.fetch,
      ...(args.traceContext ? { traceContext: args.traceContext } : {}),
    });

    let activationResultJson: string | null = null;
    const joined = await joinNearEd25519CustodyV1({
      runStep: walletCustodyCeremonyStepRunner({
        requestOperation: (operation) =>
          this.signerWorkerManager.requestWorkerOperation(
            operation as Parameters<SignerWorkerManager['requestWorkerOperation']>[0],
          ),
      }),
      custodyJson: args.custodyJson,
      factorSecret: args.factorSecret,
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      registrationCeremonyId: args.registrationCeremonyId,
      yaoAdmission: args.admissionReceipt,
      yaoApplication: args.admissionRequest.application_binding,
      participantIds: args.participantIds,
      runRouterRound: async (yaoExecuteRequestJson: string) => {
        const response = await transport.send({
          kind: 'execute',
          path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
          body: JSON.parse(yaoExecuteRequestJson),
        });
        if (!response.ok) {
          throw new Error(`Router Ed25519 Yao execute failed: ${response.message}`);
        }
        activationResultJson = JSON.stringify(response.value);
        return activationResultJson;
      },
    });
    if (!activationResultJson || !joined.localMaterial) {
      throw new Error('the wallet custody NEAR join produced no local signing material');
    }
    return {
      commitPayload: joined.commitPayload,
      activationReference: joined.activationReference,
      localMaterial: joined.localMaterial,
      metadata: walletCustodyEd25519ActiveClientMetadataV1({
        admissionRequest: args.admissionRequest,
        activationResultJson,
      }),
    };
  }

  async rejoinWalletCustodyNearEd25519KeySet(args: {
    walletId: string;
    custodyJson: string;
    factorSecret: ArrayBuffer;
    nearEd25519SigningKeyId: string;
    recoveryBasis: WalletSessionEd25519RecoveryBasisV1;
    routerOrigin: string;
    walletSessionToken: string;
  }): Promise<JoinedWalletCustodyNearEd25519KeySetV1> {
    const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
      routerOrigin: args.routerOrigin,
      authorization: { kind: 'bearer', value: `Bearer ${args.walletSessionToken}` },
      fetch: globalThis.fetch,
    });
    const recoveryRequest = await buildWalletSessionEd25519RecoveryAdmissionRequestV1({
      basis: args.recoveryBasis,
    });
    const admitted = await admitWalletRecoveryEd25519V1({
      request: recoveryRequest,
      transport,
    });
    const rejoined = await rejoinNearEd25519CustodyV1({
      runStep: walletCustodyCeremonyStepRunner({
        requestOperation: (operation) =>
          this.signerWorkerManager.requestWorkerOperation(
            operation as Parameters<SignerWorkerManager['requestWorkerOperation']>[0],
          ),
      }),
      walletId: args.walletId,
      custodyJson: args.custodyJson,
      factorSecret: args.factorSecret,
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      recoveryLifecycleId: recoveryRequest.scope.lifecycle_id,
      yaoAdmission: admitted.receipt,
      yaoApplication: admitted.request.application_binding,
      participantIds: args.recoveryBasis.participantIds,
      registeredPublicKeyB64u: base64UrlEncode(
        Uint8Array.from(args.recoveryBasis.registeredPublicKey),
      ),
      runRouterRound: (executeRequestJson) =>
        executeWalletRecoveryEd25519RoundV1({ executeRequestJson, transport }),
      activateRouterRecovery: (protocolResultJson) =>
        activateWalletRecoveryEd25519V1({
          request: recoveryRequest,
          protocolResultJson,
          transport,
        }),
    });
    if (!rejoined.localMaterial) {
      throw new Error('the wallet custody NEAR cold rejoin produced no local signing material');
    }
    return {
      commitPayload: rejoined.commitPayload,
      activationReference: rejoined.activationReference,
      localMaterial: rejoined.localMaterial,
      metadata: walletRecoveryEd25519ActiveClientMetadataV1({
        admissionRequest: recoveryRequest,
        activationResultJson: rejoined.activationResultJson,
        activationReceipt: rejoined.activationReceipt,
      }),
    };
  }

  async establishWalletCustodyEvmFamilyKeySet(args: {
    walletId: string;
    factorJson: string;
    factorSecret: ArrayBuffer;
    evmFamilySigningKeySlotId: string;
    applicationBindingDigestB64u: string;
    confirmRecoveryCodesBackedUp: Parameters<
      typeof establishEvmFamilyCustodyV1
    >[0]['confirmRecoveryCodesBackedUp'];
    runRelayerRound: Parameters<typeof establishEvmFamilyCustodyV1>[0]['runRelayerRound'];
  }): Promise<EstablishedWalletCustodyEvmFamilyKeySetV1> {
    return await establishEvmFamilyCustodyV1({
      ...args,
      runStep: walletCustodyCeremonyStepRunner({
        requestOperation: (operation) =>
          this.signerWorkerManager.requestWorkerOperation(
            operation as Parameters<SignerWorkerManager['requestWorkerOperation']>[0],
          ),
      }),
    });
  }

  async joinWalletCustodyEvmFamilyKeySet(args: {
    walletId: string;
    custodyJson: string;
    factorSecret: ArrayBuffer;
    evmFamilySigningKeySlotId: string;
    applicationBindingDigestB64u: string;
    runRelayerRound: Parameters<typeof joinEvmFamilyCustodyV1>[0]['runRelayerRound'];
  }): Promise<JoinedWalletCustodyEvmFamilyKeySetV1> {
    return await joinEvmFamilyCustodyV1({
      ...args,
      runStep: walletCustodyCeremonyStepRunner({
        requestOperation: (operation) =>
          this.signerWorkerManager.requestWorkerOperation(
            operation as Parameters<SignerWorkerManager['requestWorkerOperation']>[0],
          ),
      }),
    });
  }

  async rejoinWalletCustodyEvmFamilyKeySet(args: {
    walletId: string;
    custodyJson: string;
    factorSecret: ArrayBuffer;
    evmFamilySigningKeySlotId: string;
    applicationBindingDigestB64u: string;
    registeredClientRootPublicKey33B64u: string;
    relayerPublicIdentityJson: string;
  }): Promise<RejoinedWalletCustodyEvmFamilyKeySetV1> {
    return await rejoinEvmFamilyCustodyV1({
      ...args,
      runStep: walletCustodyCeremonyStepRunner({
        requestOperation: (operation) =>
          this.signerWorkerManager.requestWorkerOperation(
            operation as Parameters<SignerWorkerManager['requestWorkerOperation']>[0],
          ),
      }),
    });
  }

  async restoreWalletCustodyEcdsaContinuity(
    args: Omit<ImportWalletCustodyEcdsaContinuityInput, 'store'>,
  ): Promise<{
    readonly materialActivation: MpcMaterialActivationRef;
    readonly materialRef: EcdsaRoleLocalPersistedMaterialRef;
  }> {
    const imported = await importWalletCustodyEcdsaContinuity({
      ...args,
      store: new IndexedDbEcdsaCapabilityManifestStore(),
    });
    if (imported.kind !== 'committed') {
      throw new Error(`wallet custody ECDSA import returned ${imported.kind}`);
    }
    const materialActivation = routerAbMpcMaterialActivationRefFromWire(
      args.publicCapability.material_activation,
    );
    const opened = await openEcdsaRoleLocalSigningMaterialWasm({
      workerCtx: this.signerWorkerManager.getContext(),
      authority: args.authority,
      materialActivation,
    });
    if (!opened.ok) {
      throw new Error(`wallet custody ECDSA material open returned ${opened.reason}`);
    }
    return { materialActivation, materialRef: opened.materialRef };
  }

  async persistWalletCustodyEd25519Material(args: {
    binding: WalletCustodyEd25519MaterialBindingV1;
    sealed: WalletCustodySealedEd25519MaterialV1;
  }): Promise<void> {
    const context = this.signerWorkerManager.getContext();
    await persistWalletCustodyEd25519MaterialV1({
      store: context.nearKeyMaterialStore as Parameters<
        typeof persistWalletCustodyEd25519MaterialV1
      >[0]['store'],
      binding: args.binding,
      sealed: args.sealed,
    });
  }

  async loadWalletCustodyEd25519Material(args: {
    nearAccountId: string;
    signerSlot: number;
    expectedRegisteredPublicKeyB64u: string;
  }) {
    const context = this.signerWorkerManager.getContext();
    return await loadWalletCustodyEd25519MaterialV1({
      store: context.nearKeyMaterialStore as Parameters<
        typeof loadWalletCustodyEd25519MaterialV1
      >[0]['store'],
      nearAccountId: args.nearAccountId,
      signerSlot: args.signerSlot,
      expectedRegisteredPublicKeyB64u: args.expectedRegisteredPublicKeyB64u,
    });
  }

  private async loadEmailOtpWalletCustodyEd25519Material(args: {
    nearAccountId: string;
    signerSlot: number;
  }) {
    const loaded = await this.loadWalletCustodyEd25519Material({
      nearAccountId: args.nearAccountId,
      signerSlot: args.signerSlot,
      expectedRegisteredPublicKeyB64u: '',
    });
    return loaded.kind === 'found' ? loaded : { kind: 'absent' as const };
  }

  async deleteWalletCustodyEd25519Material(args: {
    nearAccountId: string;
    signerSlot: number;
  }): Promise<void> {
    const context = this.signerWorkerManager.getContext();
    await deleteWalletCustodyEd25519MaterialV1({
      store: context.nearKeyMaterialStore,
      nearAccountId: args.nearAccountId,
      signerSlot: args.signerSlot,
    });
  }

  async assertSealedRefreshStartupParity(): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
  }

  async discoverPersistedSessionsForWallet(
    args: DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult> {
    return await sessionPublic.discoverPersistedSessionsForWallet(this.sessionPublicDeps, args);
  }

  private isEd25519YaoPublicCapabilityActive(
    reference: Ed25519YaoPublicCapabilityLaneReferenceV1,
  ): boolean {
    switch (reference.auth.kind) {
      case WALLET_AUTH_METHODS.emailOtp:
        return true;
      case WALLET_AUTH_METHODS.passkey:
        return (
          this.enginePorts.ed25519YaoActiveClients.resolve({
            walletId: reference.walletId,
            nearAccountId: reference.nearAccountId,
            materialActivation: reference.materialActivation,
          }) !== null
        );
      default:
        reference.auth satisfies never;
        throw new Error('Unsupported Ed25519 public capability auth method');
    }
  }

  hasActiveNearEd25519YaoMaterial(args: {
    readonly walletId: WalletId;
    readonly nearAccountId: AccountId;
    readonly materialActivation: MpcMaterialActivationRef;
  }): boolean {
    return this.enginePorts.ed25519YaoActiveClients.resolve(args) !== null;
  }

  async readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    return await sessionPublic.readPersistedAvailableSigningLanes(this.sessionPublicDeps, args);
  }

  async readOwnerScopedSigningLanes(args: {
    readonly walletId: WalletId | string;
    readonly ownerScope: OwnerLaneScope;
  }): Promise<AvailableSigningLanes> {
    return await sessionPublic.readOwnerScopedSigningLanes(this.sessionPublicDeps, args);
  }

  /**
   * R103C derivation chain for post-login operations: the unique active Wallet
   * Session authority resolves through the active wallet auth method to one
   * exact owner scope. Callers never supply credential or slot hints.
   */
  async resolveActiveOwnerLaneScope(walletId: WalletId | string): Promise<OwnerLaneScope> {
    const parsedWalletId = parseWalletId(walletId);
    if (!parsedWalletId.ok) throw new Error(parsedWalletId.error.message);
    const stores = {
      getWalletAuthMethodV2: (id: string) => IndexedDBManager.getWalletAuthMethodV2(id),
      listWalletAuthMethodsForWallet: (id: string) =>
        IndexedDBManager.listWalletAuthMethodsForWallet(id),
      getWalletPasskeyAuthenticator: (input: {
        readonly walletId: string;
        readonly credentialId: string;
      }) => IndexedDBManager.getWalletPasskeyAuthenticator(input),
      readEmailOtpProviderSubjectForWallet: (id: string) =>
        readEmailOtpProviderSubjectForWalletV1(IndexedDBManager, id),
    };
    const selected = await IndexedDBManager.resolveSelectedWalletAuthority(
      String(parsedWalletId.value),
    );
    if (selected.kind === 'resolved') {
      const { selection, authMethod, authority } = selected;
      if (
        selection.walletId !== parsedWalletId.value ||
        selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
        authMethod.walletId !== parsedWalletId.value ||
        authMethod.walletAuthorityId !== authority.authorityId ||
        authority.walletId !== parsedWalletId.value
      ) {
        throw new Error('[SigningEngine] selected Wallet Authority identity mismatch');
      }
      if (
        selection.lockState !== 'unlocked' ||
        authMethod.status !== 'active' ||
        authority.state !== 'active'
      ) {
        throw new Error('[SigningEngine] selected Wallet Authority is inactive or locked');
      }
      await readExactOwnerLaneWalletSession({
        walletId: parsedWalletId.value,
        authorityId: authority.authorityId,
        authMethodId: authMethod.walletAuthMethodId,
        authorityDigestB64u: authority.authorityDigestB64u,
        authorityRevocationEpoch: authority.revocationEpoch,
      });
      if (
        authority.provenance.kind === 'device_link' &&
        authMethod.kind === 'passkey' &&
        authority.signerActivations.ed25519
      ) {
        const signerSlot = await resolveLinkedPasskeyOwnerSignerSlot({
          walletId: parsedWalletId.value,
          authMethod,
          signerMaterials: selected.signerMaterials,
          publicLaneStore: this.ed25519YaoPublicCapabilityReferences,
        });
        return buildExactPasskeyOwnerLaneScope({ authMethod, signerSlot });
      }
      if (
        authority.provenance.kind === 'device_link' &&
        authMethod.kind === 'passkey' &&
        authority.signerActivations.ecdsa
      ) {
        return buildExactEcdsaPasskeyOwnerLaneScope({ authMethod });
      }
      if (
        authority.provenance.kind === 'device_link' &&
        authMethod.kind === 'email_otp' &&
        authority.signerActivations.ecdsa
      ) {
        const holderRuntime = resolveLinkedEcdsaHolderRuntimeV1({
          walletId: parsedWalletId.value,
          materialActivation: authority.signerActivations.ecdsa.materialActivation,
        });
        if (
          !holderRuntime ||
          holderRuntime.authorityId !== authority.authorityId ||
          !isEmailOtpWalletAuthAuthority(holderRuntime.factorAuthority)
        ) {
          throw new Error(
            '[SigningEngine] selected linked Email OTP authority has no exact ECDSA holder runtime',
          );
        }
        const authorityRef = await walletAuthAuthorityRef({
          authority: holderRuntime.factorAuthority,
        });
        if (
          authorityRef.walletId !== parsedWalletId.value ||
          authorityRef.walletAuthMethodId !== authMethod.walletAuthMethodId
        ) {
          throw new Error(
            '[SigningEngine] selected linked Email OTP authority has no exact ECDSA holder runtime',
          );
        }
        return buildExactLinkedEmailOtpOwnerLaneScope({
          authMethod,
          factorAuthority: holderRuntime.factorAuthority,
          authorityRef,
        });
      }
      return await resolveExactOwnerLaneScope({ authMethod, stores });
    }
    const reason = selected.kind === 'integrity_error' ? `: ${selected.reason}` : '';
    throw new Error(`[SigningEngine] selected Wallet Authority is ${selected.kind}${reason}`);
  }

  readWalletAuthenticationState(): WalletAuthenticationState {
    return this.walletAuthenticationState;
  }

  async retireActiveWalletSessionAuthorizationForLock(walletId: WalletId): Promise<void> {
    const retiredAtMs = Date.now();
    const retiredExact = await walletSessionAuthorizations.retireExactActiveForWallet({
      walletId,
      reason: 'wallet_locked',
      retiredAtMs,
    });
    if (retiredExact.length > 0) {
      void this.destroyUnlockedWalletEd25519ExportRootCapabilitiesV1({
        kind: 'wallet',
        walletId: String(walletId),
      });
    }
  }

  async advanceWalletLockGeneration(walletId: WalletId): Promise<number> {
    return IndexedDBManager.advanceWalletLockGeneration({
      walletId,
      lockedAtMs: Date.now(),
    });
  }

  async markWalletSelectionUnlocked(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<void> {
    await IndexedDBManager.markWalletSelectionUnlocked({
      walletId: input.walletId,
      walletAuthMethodId: input.walletAuthMethodId,
      unlockedAtMs: Date.now(),
    });
  }

  async markSelectedEmailOtpWalletAuthorityUnlocked(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<void> {
    await this.markWalletSelectionUnlocked(input);
  }

  /**
   * Every route that lands a wallet in the authenticated state goes through
   * here — passkey unlock, email OTP login, the hosted auth menu, and session
   * restore. Binding the preferences manager at this choke point is what makes
   * per-wallet preferences real: without it the manager stays on "no last
   * user", so reads answer the built-in defaults while the wallet's persisted
   * choices sit unread, and writes stay memory-only and evaporate on reload —
   * the Confirmer UI toggle looked applied but silently reverted every page
   * load. setCurrentWallet also notifies, which pushes PREFERENCES_CHANGED to
   * the app origin so its mirrored uiMode follows the wallet too.
   */
  private applyAuthenticatedWalletState(
    state: Extract<WalletAuthenticationState, { kind: 'authenticated' }>,
  ): void {
    this.walletAuthenticationState = state;
    this.userPreferencesManager.setCurrentWallet(state.walletId);
  }

  setWalletAuthenticated(
    state: Extract<WalletAuthenticationState, { kind: 'authenticated' }>,
  ): void {
    // R103 zero-prompt handoff: switching wallets ends the previous wallet's
    // authority here without passing through clearWalletAuthentication, so its
    // The unlocked export-root capability is destroyed at the switch itself.
    const previous = this.walletAuthenticationState;
    if (previous.kind === 'authenticated' && String(previous.walletId) !== String(state.walletId)) {
      void this.destroyUnlockedWalletEd25519ExportRootCapabilitiesV1({
        kind: 'wallet',
        walletId: String(previous.walletId),
      });
    }
    this.walletAuthenticationRestoreGeneration += 1;
    this.applyAuthenticatedWalletState(state);
  }

  clearWalletAuthentication(): void {
    this.walletAuthenticationRestoreGeneration += 1;
    this.walletAuthenticationState = { kind: 'signed_out' };
    // R103 zero-prompt handoff: logout and wallet switch both land here, and
    // both end the authority the unlocked export-root capability was scoped to.
    void this.destroyUnlockedWalletEd25519ExportRootCapabilitiesV1({ kind: 'all' });
  }

  /**
   * The wallet custody ceremony worker as the small structural port the
   * custody modules take, so they can be exercised without a worker.
   */
  private walletCustodyCeremonyTransportV1(): WalletCustodyCeremonyTransportPort {
    return {
      requestOperation: async (operation: {
        readonly kind: 'walletCustodyCeremony';
        readonly request: unknown;
      }) =>
        await this.getSignerWorkerContext().requestWorkerOperation({
          kind: operation.kind,
          request: operation.request as never,
        }),
    };
  }

  /**
   * Refactor 103 zero-prompt handoff: parks the wallet custody seed inside the
   * ceremony worker for the lifetime of the just-activated owner Wallet
   * Session, reusing the factor secret this registration or unlock already
   * collected. Failure is absorbed: the wallet stays usable, and device
   * linking fails closed with `wallet_unlock_required` until the next unlock.
   */
  async establishUnlockedWalletEd25519ExportRootCapabilityV1(input: {
    readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly passkeyPrfFirstB64u: string;
    readonly walletId: string;
    readonly walletAuthMethodId: string;
    readonly walletSessionId: string;
    readonly expiresAtMs: number;
  }): Promise<void> {
    try {
      if (!isWalletCustodySeedBinding(input.existingEnvelope.binding)) return;
      const factor = input.existingEnvelope.factor;
      if (factor.kind !== 'passkey') {
        throw new Error('unlocked export-root capability requires a passkey envelope factor');
      }
      const existingFactorSecret = base64UrlDecode(input.passkeyPrfFirstB64u);
      try {
        await establishUnlockedExportRootCapabilityWithWorkerV1(
          this.walletCustodyCeremonyTransportV1(),
          {
            existingEnvelope: input.existingEnvelope,
            existingFactorSecret,
            walletId: input.walletId,
            walletAuthMethodId: input.walletAuthMethodId,
            walletSessionId: input.walletSessionId,
            expiresAtMs: input.expiresAtMs,
          },
        );
      } finally {
        existingFactorSecret.fill(0);
      }
    } catch (error: unknown) {
      console.warn(
        '[BrowserSigningSurface] unlocked Ed25519 export-root capability was not established:',
        error instanceof Error ? error.message : String(error || 'unknown error'),
      );
    }
  }

  /**
   * Stores a resealed pre-109C envelope under the method that opened it.
   *
   * Absorbed the same way establishment is, and for the same reason: the V2 row
   * still opens the wallet, so a failure here costs a retry at the next unlock
   * and nothing else. Surfacing it would interrupt a user who has no action to
   * take.
   */
  private async persistUpgradedWalletCustodyEnvelopeV1(upgrade: {
    readonly walletId: string;
    readonly envelope: PasskeyCustodyEnvelopeRecord;
  }): Promise<void> {
    try {
      const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
      if (!relayerUrl) return;
      const parsedWalletId = parseWalletId(upgrade.walletId);
      if (!parsedWalletId.ok) return;
      const authorization = await resolveActiveEd25519WalletSessionAuthorization(
        parsedWalletId.value,
        relayerUrl,
      );
      const walletSessionToken = authorization?.operationCredential.token;
      if (!walletSessionToken) return;
      const outcome = await upgradeWalletCustodyEnvelopeOwnership({
        relayUrl: relayerUrl,
        walletId: upgrade.walletId,
        walletSessionToken: String(walletSessionToken),
        envelope: upgrade.envelope,
      });
      if (outcome.kind === 'upgraded' || outcome.kind === 'already_owned') return;
      console.warn(
        '[BrowserSigningSurface] the upgraded custody envelope was not stored:',
        outcome.message,
      );
    } catch (error: unknown) {
      console.warn(
        '[BrowserSigningSurface] the upgraded custody envelope was not stored:',
        error instanceof Error ? error.message : String(error || 'unknown error'),
      );
    }
  }

  async destroyUnlockedWalletEd25519ExportRootCapabilitiesV1(
    scope: UnlockedWalletEd25519ExportRootCapabilityDestroyScopeV1,
  ): Promise<void> {
    await destroyUnlockedExportRootCapabilitiesWithWorkerV1(
      this.walletCustodyCeremonyTransportV1(),
      scope,
    );
  }

  private async runWarmCriticalResources(
    accountContext?: WorkerResourceWarmupAccountContext,
  ): Promise<WorkerResourceWarmupDiagnostics> {
    try {
      await this.ensureSealedRefreshStartupParity();
    } catch (error: unknown) {
      if (!isRetryableSealedRefreshCapabilityFetchError(error)) throw error;
      console.warn(
        '[BrowserSigningSurface] warmCriticalResources skipped retryable sealed-refresh capability fetch failure',
        error instanceof Error ? error.message : String(error || 'unknown error'),
      );
    }
    return await this.enginePorts
      .getManagerConveniencePorts()
      .warmCriticalResources(accountContext);
  }

  async warmCriticalResources(
    accountContext?: WorkerResourceWarmupAccountContext,
  ): Promise<WorkerResourceWarmupDiagnostics> {
    if (__isWalletIframeHostMode() && accountContext === undefined) {
      const existing = this.hostWarmCriticalResourcesTask;
      if (existing) return await existing;

      const task = this.runWarmCriticalResources();
      this.hostWarmCriticalResourcesTask = task;
      void task.catch(() => {
        if (this.hostWarmCriticalResourcesTask === task) {
          this.hostWarmCriticalResourcesTask = null;
        }
      });
      return await task;
    }
    return await this.runWarmCriticalResources(accountContext);
  }

  async prewarmEmailOtpYao(
    request?: EmailOtpYaoPrewarmRequest,
  ): Promise<EmailOtpYaoPrewarmOutcome> {
    return await this.signerWorkerManager.prewarmEmailOtpYao(request);
  }

  async prewarmEcdsaRegistrationCrypto(): Promise<{
    kind: 'succeeded' | 'failed';
    wasmInitMs: number;
  }> {
    return await this.signerWorkerManager.prewarmEcdsaRegistrationCrypto();
  }

  getRpId(): string {
    return this.touchIdPrompt.getRpId();
  }

  getSignerWorkerContext(): WorkerOperationContext {
    return this.enginePorts.walletSessionActivationDeps.getSignerWorkerContext();
  }

  getNonceCoordinator(): NonceCoordinator {
    return this.nonceCoordinator;
  }

  setAppearance(appearance: AppearanceConfig): void {
    this.appearance = appearance;
  }

  setWalletIframeSurfaceMeasurementBinding(binding: UiConfirmSurfaceMeasurementBinding): void {
    this.touchConfirm.getContext().surfaceMeasurementBinding = binding;
  }

  getWalletIframeSurfaceMeasurementBinding(): UiConfirmSurfaceMeasurementBinding {
    return this.touchConfirm.getContext().surfaceMeasurementBinding;
  }

  getUserPreferences(): UserPreferencesManager {
    return this.userPreferencesManager;
  }

  async signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>> {
    return await signNearOperation(this.enginePorts.nearSigningDeps, request);
  }

  private async ensureNearEd25519YaoCapabilityForSigning(
    subject: NearEd25519CapabilityRehydrationSubject,
  ): Promise<NearEd25519YaoOperationMaterial> {
    const rehydrationKey = nearEd25519CapabilityRehydrationKey(subject);
    const existingRehydration = this.nearEd25519CapabilityRehydrationBySubject.get(rehydrationKey);
    if (existingRehydration) {
      const reboundSubject = await existingRehydration;
      const rehydrated = await this.resolveActiveNearEd25519YaoSigningLane(reboundSubject);
      if (rehydrated) return rehydrated;
      throw new Error('[SigningEngine][near] joined rehydration did not publish an active lane');
    }

    const rehydration = this.rehydrateNearEd25519YaoCapabilityForSigning(subject);
    this.nearEd25519CapabilityRehydrationBySubject.set(rehydrationKey, rehydration);
    try {
      const reboundSubject = await rehydration;
      const rehydrated = await this.resolveActiveNearEd25519YaoSigningLane(reboundSubject);
      if (rehydrated) return rehydrated;
      throw new Error('[SigningEngine][near] local material rehydration did not publish a lane');
    } finally {
      if (this.nearEd25519CapabilityRehydrationBySubject.get(rehydrationKey) === rehydration) {
        this.nearEd25519CapabilityRehydrationBySubject.delete(rehydrationKey);
      }
    }
  }

  private async rehydrateExactPasskeyEd25519YaoCapabilityForSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearEd25519YaoOperationMaterial> {
    const identity = nearEd25519MaterialIdentityFromBoundaryInput(args);
    return await this.ensureNearEd25519YaoCapabilityForSigning(
      args.laneIdentity !== undefined
        ? {
            kind: 'exact_lane',
            walletId: args.walletId,
            nearAccountId: args.nearAccountId,
            signerSlot: identity.signer.signerSlot,
            thresholdSessionId: identity.thresholdSessionId,
            laneIdentity: args.laneIdentity,
          }
        : {
            kind: 'material_identity',
            walletId: args.walletId,
            nearAccountId: args.nearAccountId,
            signerSlot: identity.signer.signerSlot,
            thresholdSessionId: identity.thresholdSessionId,
            materialIdentity: identity,
          },
    );
  }

  private async prepareMaterialIdentityNearEd25519YaoSigning(
    args: Extract<
      PrepareNearEd25519YaoMaterialBoundaryInput,
      { readonly materialIdentity: NearEd25519MaterialIdentity }
    >,
  ): Promise<NearEd25519YaoSigningPreparation> {
    const identity = args.materialIdentity;
    const activeForAccount = this.enginePorts.ed25519YaoActiveClients.resolveForWalletAccount({
      walletId: identity.signer.account.wallet.walletId,
      nearAccountId: identity.signer.account.nearAccountId,
    });
    const publicCapabilityMaterialActivation =
      await resolveNearEd25519PublicCapabilityMaterialActivation({
        store: this.ed25519YaoPublicCapabilityReferences,
        identity,
      });
    if (identity.auth.kind === WALLET_AUTH_METHODS.passkey && publicCapabilityMaterialActivation) {
      const activeMaterial = this.enginePorts.ed25519YaoActiveClients.resolve({
        walletId: identity.signer.account.wallet.walletId,
        nearAccountId: identity.signer.account.nearAccountId,
        materialActivation: publicCapabilityMaterialActivation,
      });
      const liveRuntime = nearEd25519YaoRuntimeObservation(activeMaterial);
      if (activeMaterial && liveRuntime.kind === 'live') {
        const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
          args.walletId,
        );
        if (authorizationRead.kind === 'found') {
          const authorization = authorizationRead.authorization;
          if (authorization.selectedAuthMethod.kind !== WALLET_AUTH_METHODS.passkey) {
            throw new Error('[SigningEngine][near] active Wallet Session method is unavailable');
          }
          const authority = await walletAuthAuthorityRef({
            authority: authorization.selectedFactorAuthority,
          });
          return buildAuthorizedNearEd25519YaoSigningPreparation({
            hydration: buildUseLiveRuntimeHydrationPlan({
              authority,
              runtime: liveRuntime.runtime,
              materialActivation: publicCapabilityMaterialActivation,
            }),
            requirement: identity.auth,
            authorization,
          });
        }
        if (authorizationRead.kind !== 'exhausted') {
          throw new Error('[SigningEngine][near] active Wallet Session is unavailable');
        }
      }
    }
    const sealedRuntime =
      identity.auth.kind === WALLET_AUTH_METHODS.passkey
        ? await requireExactEd25519SealedRuntimeForMaterialIdentity({
            walletId: args.walletId,
            identity,
          })
        : null;
    const materialActivation =
      sealedRuntime?.sealedRecord.ed25519Restore.materialActivation ??
      (activeForAccount
        ? nearEd25519YaoMaterialActivationFromMetadata(activeForAccount.activeClient.metadata())
        : publicCapabilityMaterialActivation);
    if (!materialActivation) {
      throw new Error('[SigningEngine][near] Ed25519 material activation is unavailable');
    }
    const activeCapability = this.enginePorts.ed25519YaoActiveClients.resolve({
      walletId: identity.signer.account.wallet.walletId,
      nearAccountId: identity.signer.account.nearAccountId,
      materialActivation,
    });
    const runtimeObservation = nearEd25519YaoRuntimeObservation(activeCapability);
    let hydration: MpcCapabilityHydrationPlan;
    switch (identity.auth.kind) {
      case WALLET_AUTH_METHODS.passkey: {
        if (!sealedRuntime) {
          throw new Error('[SigningEngine][near] passkey sealed runtime is unavailable');
        }
        const activeAuthorization = await this.resolveActiveNearEd25519WalletSessionAuthorization(
          sealedRuntime.walletId,
        );
        const walletSessionState = activeAuthorization
          ? await walletSessionStateFromExactEd25519Runtime({
              runtime: sealedRuntime,
              relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
            })
          : null;
        const warmSessionClaim = walletSessionState
          ? await this.ensurePasskeyEd25519WarmSessionForSigning({
              runtime: sealedRuntime,
              walletSessionState,
              materialActivation,
            })
          : await this.passkeyMpcSession.claimWarmSessionMaterial({
              thresholdSessionId: sealedRuntime.thresholdSessionId,
              purpose: { curve: 'ed25519', materialActivation },
              consume: false,
            });
        if (!activeAuthorization) {
          throw new Error('[SigningEngine][near] exact Passkey authority is unavailable');
        }
        const authority = await ed25519SealedRuntimeAuthorityRef({
          runtime: sealedRuntime,
          walletAuthMethodId: activeAuthorization.selectedAuthMethod.walletAuthMethodId,
        });
        if (
          String(authority.authorityDigest) !==
          String(activeAuthorization.selectedAuthority.authorityDigestB64u)
        ) {
          throw new Error('[SigningEngine][near] exact Passkey authority changed');
        }
        const localMaterial = await readPasskeyEd25519YaoLocalMaterialLocatorV1({
          store: IndexedDBManager,
          walletId: String(identity.signer.account.wallet.walletId),
          nearAccountId: String(identity.signer.account.nearAccountId),
          nearEd25519SigningKeyId: String(identity.signer.nearEd25519SigningKeyId),
          signerSlot: identity.signer.signerSlot,
          rpId: identity.auth.rpId,
          credentialIdB64u: identity.auth.credentialIdB64u,
          authority,
        });
        const publicLocator = {
          kind: 'available' as const,
          walletId: String(identity.signer.account.wallet.walletId),
          nearAccountId: String(identity.signer.account.nearAccountId),
          signerSlot: identity.signer.signerSlot,
          materialActivation,
          authority,
        };
        hydration = resolveNearEd25519YaoCapabilityHydrationV1({
          publicLocator,
          sealed:
            localMaterial.kind === 'available'
              ? {
                  kind: 'available',
                  authority: localMaterial.locator.authority,
                  materialActivation: localMaterial.locator.materialActivation,
                  sealedMaterial: localMaterial.locator.sealedMaterial,
                }
              : { kind: 'missing' },
          runtime: runtimeObservation,
          unlockSource: warmSessionClaim.ok
            ? { kind: 'available', authority }
            : { kind: 'unavailable' },
        });
        break;
      }
      case WALLET_AUTH_METHODS.emailOtp:
        hydration = await this.resolveWalletCustodyEmailOtpHydration({
          walletId: args.walletId,
          nearAccountId: args.nearAccountId,
          signerSlot: identity.signer.signerSlot,
          materialActivation,
        });
        break;
      default:
        identity.auth satisfies never;
        throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
    }
    return buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
      hydration,
      requirement: identity.auth,
    });
  }

  private async resolveWalletCustodyEmailOtpHydration(args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    signerSlot: number;
    materialActivation: MpcMaterialActivationRef;
  }): Promise<MpcCapabilityHydrationPlan> {
    const activeMaterial = this.enginePorts.ed25519YaoActiveClients.resolve({
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      materialActivation: args.materialActivation,
    });
    const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
      args.walletId,
    );
    if (
      authorizationRead.kind === 'found' &&
      authorizationRead.authorization.selectedAuthMethod.kind === WALLET_AUTH_METHODS.emailOtp
    ) {
      const authority = await walletAuthAuthorityRef({
        authority: authorizationRead.authorization.selectedFactorAuthority,
      });
      if (activeMaterial) {
        return buildUseLiveRuntimeHydrationPlan({
          authority,
          runtime: nearEd25519YaoRuntimeRef(args.materialActivation),
          materialActivation: args.materialActivation,
        });
      }
      const loaded = await this.loadEmailOtpWalletCustodyEd25519Material({
        nearAccountId: String(args.nearAccountId),
        signerSlot: args.signerSlot,
      });
      if (
        loaded.kind === 'found' &&
        loaded.material.binding.walletId === String(args.walletId) &&
        loaded.material.binding.nearAccountId === String(args.nearAccountId) &&
        loaded.material.binding.signerSlot === args.signerSlot &&
        String(args.materialActivation.materialOwner) === String(args.walletId)
      ) {
        return buildRehydrateMaterialActivationHydrationPlan({
          authority,
          materialActivation: args.materialActivation,
          sealedMaterial: buildRestorableMpcMaterialRefForHydration(
            JSON.stringify([
              loaded.material.binding.walletId,
              loaded.material.binding.nearAccountId,
              loaded.material.binding.signerSlot,
              args.materialActivation.activationId,
            ]),
          ),
        });
      }
    }
    return buildBlockedMpcCapabilityHydrationPlan({
      capability: args.materialActivation.capability,
      reason: 'missing_material',
    });
  }

  private async rehydrateActiveEmailOtpEd25519YaoSessionMaterial(args: {
    input: PrepareNearEd25519YaoMaterialBoundaryInput;
    materialActivation: MpcMaterialActivationRef;
    authorization: ExactNearEd25519WalletSessionAuthorization;
    remainingUses: number;
  }): Promise<MpcCapabilityHydrationPlan> {
    const input = requireAuthorizedNearEd25519BoundaryInput(args.input);
    if (input.auth.kind !== WALLET_AUTH_METHODS.emailOtp) {
      throw new Error(
        '[SigningEngine][near] Email OTP session restore requires Email OTP material',
      );
    }
    const publicLane = await resolveExactEmailOtpPublicLaneReference({
      store: this.ed25519YaoPublicCapabilityReferences,
      laneIdentity: input.laneIdentity,
      materialActivation: args.materialActivation,
    });
    const user = await this.getUserBySignerSlot(
      input.nearAccountId,
      input.laneIdentity.signer.signerSlot,
    );
    if (
      !user ||
      String(user.walletId) !== String(input.walletId) ||
      String(user.nearAccountId) !== String(input.nearAccountId) ||
      user.signerSlot !== input.laneIdentity.signer.signerSlot ||
      user.authMethod !== WALLET_AUTH_METHODS.emailOtp
    ) {
      throw new Error('[SigningEngine][near] Email OTP signer record is unavailable');
    }
    const sealed = await this.loadEmailOtpWalletCustodyEd25519Material({
      nearAccountId: String(input.nearAccountId),
      signerSlot: user.signerSlot,
    });
    const walletSessionToken = requireOpaqueWalletSessionToken(
      args.authorization.operationCredential.token,
      '[SigningEngine][near] Email OTP Wallet Session token',
    );
    if (sealed.kind !== 'found') {
      throw new Error('[SigningEngine][near] Email OTP session material is unavailable');
    }
    const ecdsaManifest = requireEmailOtpEcdsaRehydrationManifest(
      await listBrowserActiveEcdsaCapabilityManifestsForWallet(String(input.walletId)),
      String(
        (
          await walletAuthAuthorityRef({
            authority: args.authorization.selectedFactorAuthority,
          })
        ).authorityDigest,
      ),
    );
    const ecdsaSessionPolicy = buildEmailOtpEcdsaRehydrationPolicy({
      manifest: ecdsaManifest,
      remainingUses: args.remainingUses,
    });
    const activated = await this.signerWorkerManager.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'rehydrateActiveEmailOtpEd25519YaoSessionMaterial',
        payload: {
          relayUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
          walletId: String(input.walletId),
          walletAuthMethodId: String(args.authorization.selectedAuthMethod.walletAuthMethodId),
          orgId: publicLane.runtimePolicyScope.orgId,
          providerSubjectId: input.auth.providerSubjectId,
          nearAccountId: String(input.nearAccountId),
          signerSlot: user.signerSlot,
          remainingUses: args.remainingUses,
          expectedOperationalPublicKey: user.operationalPublicKey,
          expectedThresholdSessionId: publicLane.thresholdSessionId,
          walletSessionToken,
          ecdsa: {
            sessionHandleBinding: {
              operation: 'wallet_unlock',
              keyHandle: String(ecdsaManifest.durableMaterial.roleLocalBinding.keyHandle),
              authSubjectId: input.auth.providerSubjectId,
              chainTarget: ecdsaManifest.signer.scope.targetMemberships[0],
            },
            runtimePolicyScope: ecdsaManifest.durableMaterial.runtimePolicyScope,
            sessionPolicy: ecdsaSessionPolicy,
          },
          walletCustodyEd25519Material: sealed,
        },
      },
    });
    await this.activateEmailOtpEd25519CustodyCapabilityInternal({
      commitQueue: 'acquire',
      walletSession: {
        walletId: input.walletId,
        walletSessionUserId: String(input.walletId),
      },
      providerSubject: input.auth.providerSubjectId,
      emailHashHex: await sha256HexUtf8(user.loginDisplayName.trim().toLowerCase()),
      signerSlot: user.signerSlot,
      expectedOperationalPublicKey: user.operationalPublicKey,
      expectedThresholdSessionId: String(publicLane.thresholdSessionId),
      bootstrap: activated.bootstrap,
      activeClientHandle: activated.activeClientHandle,
      metadata: activated.metadata,
    });
    const refreshedAuthorization = await this.readExactNearEd25519WalletSessionAuthorization(
      input.walletId,
    );
    if (refreshedAuthorization.kind !== 'found') {
      throw new Error('[SigningEngine][near] refreshed Ed25519 Wallet Session is unavailable');
    }
    await persistRehydratedEmailOtpEcdsaWalletSession({
      walletId: input.walletId,
      ed25519Authorization: refreshedAuthorization.authorization,
      response: activated.ecdsaSession,
    });
    const refreshedAuthority = await walletAuthAuthorityRef({
      authority: refreshedAuthorization.authorization.selectedFactorAuthority,
    });
    return buildUseLiveRuntimeHydrationPlan({
      authority: refreshedAuthority,
      runtime: nearEd25519YaoRuntimeRef(args.materialActivation),
      materialActivation: args.materialActivation,
    });
  }

  private async prepareExactNearEd25519YaoSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearEd25519YaoSigningPreparation> {
    if (args.laneIdentity !== undefined && args.auth?.kind === WALLET_AUTH_METHODS.emailOtp) {
      let preparation = await this.prepareMaterialIdentityNearEd25519YaoSigning(
        authNeutralNearEd25519BoundaryInput(args),
      );
      const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
        args.walletId,
      );
      if (
        authorizationRead.kind !== 'found' ||
        authorizationRead.authorization.selectedAuthMethod.kind !== WALLET_AUTH_METHODS.emailOtp
      ) {
        return preparation;
      }
      const authorization = authorizationRead.authorization;
      switch (preparation.hydration.kind) {
        case 'use_live_runtime':
          break;
        case 'rehydrate_material_activation':
          preparation = buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
            hydration: await this.rehydrateActiveEmailOtpEd25519YaoSessionMaterial({
              input: args,
              materialActivation: preparation.hydration.materialActivation,
              authorization,
              remainingUses: authorization.status.remainingUses,
            }),
            requirement: args.auth,
          });
          break;
        case 'reauthorize_public_anchor':
        case 'blocked':
          return preparation;
        default:
          preparation.hydration satisfies never;
          throw new Error('[SigningEngine][near] unsupported Email OTP hydration state');
      }
      const currentAuthorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
        args.walletId,
      );
      if (
        currentAuthorizationRead.kind !== 'found' ||
        currentAuthorizationRead.authorization.selectedAuthMethod.kind !==
          WALLET_AUTH_METHODS.emailOtp
      ) {
        return preparation;
      }
      return buildAuthorizedNearEd25519YaoSigningPreparation({
        hydration: preparation.hydration,
        requirement: args.auth,
        authorization: currentAuthorizationRead.authorization,
      });
    }
    if (args.laneIdentity === undefined) {
      return await this.prepareMaterialIdentityNearEd25519YaoSigning(args);
    }
    const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
      args.walletId,
    );
    switch (authorizationRead.kind) {
      case 'found': {
        const authorization = authorizationRead.authorization;
        if (authorization.selectedAuthMethod.kind !== args.auth.kind) {
          return await this.prepareMaterialIdentityNearEd25519YaoSigning(
            authNeutralNearEd25519BoundaryInput(args),
          );
        }
        const sealedRuntimeResolution = await resolveExactEd25519SealedSessionRuntimeForLane({
          walletId: args.walletId,
          laneIdentity: args.laneIdentity,
        });
        if (
          sealedRuntimeResolution.kind === 'missing' &&
          args.auth.kind === WALLET_AUTH_METHODS.passkey
        ) {
          const publicLane = await resolveExactPasskeyPublicLaneReference({
            store: this.ed25519YaoPublicCapabilityReferences,
            laneIdentity: args.laneIdentity,
          });
          const materialActivation = publicLane.materialActivation;
          const activeMaterial = this.enginePorts.ed25519YaoActiveClients.resolve({
            walletId: args.walletId,
            nearAccountId: args.nearAccountId,
            materialActivation,
          });
          if (!activeMaterial) {
            throw new Error('[SigningEngine][near] active Passkey Ed25519 material is unavailable');
          }
          const material = validateExactNearEd25519YaoOperationMaterial({
            material: activeMaterial,
            input: args,
            expectedActivation: materialActivation,
          });
          const walletSessionState = await passkeyWalletSessionStateFromPublicLane({
            reference: publicLane,
            material,
            authorization,
            materialActivation,
            relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
          });
          const runtime = nearEd25519YaoRuntimeObservation(material);
          if (runtime.kind !== 'live') {
            throw new Error('[SigningEngine][near] active Passkey Ed25519 material is unavailable');
          }
          return buildAuthorizedNearEd25519YaoSigningPreparation({
            hydration: buildUseLiveRuntimeHydrationPlan({
              authority: walletSessionState.authority,
              runtime: runtime.runtime,
              materialActivation,
            }),
            requirement: args.auth,
            authorization,
          });
        }
        if (sealedRuntimeResolution.kind !== 'resolved') {
          throw new Error(
            `[SigningEngine][near] exact persisted Ed25519 runtime is ${sealedRuntimeResolution.kind}`,
          );
        }
        const sealedRuntime = sealedRuntimeResolution.runtime;
        const materialActivation = sealedRuntime.sealedRecord.ed25519Restore.materialActivation;
        const walletSessionState = await walletSessionStateFromExactEd25519Runtime({
          runtime: sealedRuntime,
          relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
        });
        const signer = walletSessionState.signingLane.identity.signer;
        const publicLocator = {
          kind: 'available' as const,
          walletId: String(signer.account.wallet.walletId),
          nearAccountId: String(signer.account.nearAccountId),
          signerSlot: signer.signerSlot,
          materialActivation,
        } satisfies PasskeyEd25519YaoPublicLocatorObservationV1;
        const activeMaterial = this.enginePorts.ed25519YaoActiveClients.resolve({
          walletId: signer.account.wallet.walletId,
          nearAccountId: signer.account.nearAccountId,
          materialActivation,
        });
        const warmSessionClaim =
          args.auth.kind === WALLET_AUTH_METHODS.passkey
            ? await this.passkeyMpcSession.claimWarmSessionMaterial({
                thresholdSessionId: sealedRuntime.thresholdSessionId,
                purpose: { curve: 'ed25519', materialActivation },
                consume: false,
              })
            : null;
        let unlockSource: PasskeyEd25519YaoUnlockSourceV1 = { kind: 'unavailable' };
        if (warmSessionClaim?.ok === true) {
          unlockSource = {
            kind: 'available',
            passkeyPrfFirstB64u: warmSessionClaim.prfFirstB64u,
          };
        }
        const hydration = await this.resolveExactNearEd25519YaoSigningHydration({
          args,
          walletSessionState,
          publicLocator,
          runtime: nearEd25519YaoRuntimeObservation(activeMaterial),
          unlockSource,
        });
        if (hydration.kind === 'use_live_runtime') {
          if (!activeMaterial) {
            throw new Error('[SigningEngine][near] live Ed25519 material is unavailable');
          }
          await hydrateOwnerNearEd25519ExecutionLane({
            input: args,
            authorization,
            sealedRuntime,
            material: activeMaterial,
          });
        }
        return buildAuthorizedNearEd25519YaoSigningPreparation({
          hydration,
          requirement: args.auth,
          authorization,
        });
      }
      case 'missing':
      case 'expired':
      case 'exhausted':
      case 'superseded':
      case 'authority_unavailable':
      case 'method_unavailable':
      case 'capability_unavailable':
      case 'unavailable':
        return await this.prepareMaterialIdentityNearEd25519YaoSigning(
          authNeutralNearEd25519BoundaryInput(args),
        );
      case 'upgrade_required':
        throw new WalletSessionAuthorizationUpgradeRequiredError(
          '[SigningEngine][near] Wallet Session authorization requires a newer client',
        );
      case 'corrupt':
      case 'persistence_unavailable':
        throw new Error(
          `[SigningEngine][near] Wallet Session authorization is ${authorizationRead.kind}`,
        );
      default:
        authorizationRead satisfies never;
        throw new Error('[SigningEngine][near] unsupported Wallet Session authorization state');
    }
  }

  private async prepareExactNearEd25519YaoMaterialBoundary(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearEd25519YaoPreparedMaterialBoundary> {
    assertNearEd25519YaoMaterialBoundaryAuth(args);
    const preparation = await this.prepareExactNearEd25519YaoSigning(args);
    const context: PreparedNearEd25519YaoMaterialContext = {
      input: args,
      materialActivation: preparation.hydration.materialActivation || null,
    };
    return {
      preparation,
      executor: {
        resolveSigningKeyMaterial: this.resolveExactNearEd25519SigningKeyMaterial.bind(
          this,
          context,
        ),
        resolve: this.resolveExactNearEd25519YaoPreparedMaterial.bind(this, context),
        resolveWalletSessionState: this.resolveExactNearEd25519YaoWalletSessionState.bind(
          this,
          context,
        ),
        resolveFundingSession: this.resolveExactNearEd25519FundingSession.bind(this, context),
        preparePasskeyOperationStepUp:
          this.prepareExactNearEd25519YaoOperationStepUpAtBoundary.bind(this, context),
        prepareEmailOtpOperationStepUp:
          this.prepareExactNearEmailOtpEd25519YaoOperationStepUpAtBoundary.bind(this, context),
      },
    };
  }

  private async resolveExactNearEd25519SigningKeyMaterial(
    context: PreparedNearEd25519YaoMaterialContext,
  ): Promise<ThresholdEd25519KeyMaterial> {
    const identity = nearEd25519MaterialIdentityFromBoundaryInput(context.input);
    const signer = identity.signer;
    const auth = identity.auth;
    const materialActivation = context.materialActivation;
    if (!materialActivation) {
      throw new Error('[SigningEngine][near] prepared material has no activation');
    }
    if (
      String(signer.account.wallet.walletId) !== String(context.input.walletId) ||
      String(signer.account.nearAccountId) !== String(context.input.nearAccountId)
    ) {
      throw new Error('[SigningEngine][near] selected Ed25519 lane identity changed');
    }

    const selected = await IndexedDBManager.resolveSelectedWalletAuthority(
      String(context.input.walletId),
    );
    if (selected.kind !== 'resolved') {
      const detail = selected.kind === 'integrity_error' ? `: ${selected.reason}` : '';
      throw new Error(
        `[SigningEngine][near] selected Wallet Authority is ${selected.kind}${detail}`,
      );
    }

    const { selection, authMethod, authority, signerMaterials } = selected;
    const authMethodMatches =
      auth.kind === WALLET_AUTH_METHODS.passkey
        ? authMethod.kind === WALLET_AUTH_METHODS.passkey &&
          String(authMethod.rpId) === String(auth.rpId) &&
          authMethod.credentialIdB64u === auth.credentialIdB64u
        : authMethod.kind === WALLET_AUTH_METHODS.emailOtp;
    if (
      selection.lockState !== 'unlocked' ||
      authority.state !== 'active' ||
      authMethod.status !== 'active' ||
      String(selection.walletId) !== String(context.input.walletId) ||
      selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
      authMethod.walletAuthorityId !== authority.authorityId ||
      String(authMethod.walletId) !== String(context.input.walletId) ||
      !authMethodMatches
    ) {
      throw new Error('[SigningEngine][near] selected Wallet Authority does not match the lane');
    }

    const operation = await resolveWalletAuthorityOperation({
      selected: { authMethod, authority },
      operation: { kind: 'near_sign', operation: 'sign', keyFamily: 'ed25519' },
    });
    if (operation.kind !== 'resolved') {
      throw new Error(
        `[SigningEngine][near] selected Wallet Authority rejected signing (${operation.reason.kind})`,
      );
    }
    const resolved = operation.value;
    if (
      resolved.keyFamily !== 'ed25519' ||
      String(resolved.walletId) !== String(context.input.walletId) ||
      resolved.authMethodId !== authMethod.walletAuthMethodId ||
      !mpcMaterialActivationRefsEqual(resolved.materialActivation, materialActivation)
    ) {
      throw new Error('[SigningEngine][near] selected Wallet Authority activation changed');
    }
    if (
      authority.signerActivations.keyFamilies[0] !== 'ed25519' ||
      authority.signerActivations.ed25519 === undefined ||
      !mpcMaterialActivationRefsEqual(
        authority.signerActivations.ed25519.materialActivation,
        materialActivation,
      ) ||
      authority.signerActivations.ed25519.signer.registeredPublicKeyB64u !==
        resolved.registeredPublicKeyB64u
    ) {
      throw new Error('[SigningEngine][near] selected Ed25519 authority activation changed');
    }

    const registeredPublicKey = base64UrlDecode(resolved.registeredPublicKeyB64u);
    if (registeredPublicKey.byteLength !== 32) {
      throw new Error('[SigningEngine][near] selected Ed25519 public key is invalid');
    }
    const signingWorkerId = materialActivation.signingWorker;
    let participantIds: readonly [number, number] = [1, 2];
    let linkedMaterial: Extract<
      WalletAuthoritySignerMaterialRecordV1,
      { kind: 'wallet_authority_linked_signer_material_v1'; keyFamily: 'ed25519' }
    > | null = null;
    if (authority.provenance.kind === 'device_link') {
      await resolveExactNearEd25519PublicLaneReference({
        store: this.ed25519YaoPublicCapabilityReferences,
        identity,
        materialActivation,
      });
      for (const candidate of signerMaterials) {
        if (
          !isLinkedEd25519SignerMaterial(candidate) ||
          candidate.authorityId !== authority.authorityId ||
          candidate.walletAuthMethodId !== authMethod.walletAuthMethodId ||
          !mpcMaterialActivationRefsEqual(candidate.materialActivation, materialActivation)
        ) {
          continue;
        }
        if (linkedMaterial) {
          throw new Error('[SigningEngine][near] linked Ed25519 signer material is ambiguous');
        }
        linkedMaterial = candidate;
      }
      if (!linkedMaterial) {
        throw new Error('[SigningEngine][near] linked Ed25519 signer material is unavailable');
      }
      const application = linkedMaterial.publicFacts.applicationBinding;
      const targetBinding = linkedMaterial.publicFacts.targetBinding;
      const targetLifecycle = targetBinding.lifecycle;
      const targetFactor = linkedMaterial.targetFactor;
      const targetFactorMatches =
        auth.kind === WALLET_AUTH_METHODS.passkey
          ? targetFactor.kind === WALLET_AUTH_METHODS.passkey &&
            targetFactor.walletAuthMethodId === authMethod.walletAuthMethodId &&
            String(targetFactor.rpId) === String(auth.rpId) &&
            targetFactor.credentialIdB64u === auth.credentialIdB64u
          : targetFactor.kind === WALLET_AUTH_METHODS.emailOtp &&
            authMethod.kind === WALLET_AUTH_METHODS.emailOtp &&
            targetFactor.walletAuthMethodId === authMethod.walletAuthMethodId &&
            targetFactor.emailHashHex === authMethod.emailHashHex;
      if (
        application.wallet_id !== String(context.input.walletId) ||
        application.near_ed25519_signing_key_id !== String(signer.nearEd25519SigningKeyId) ||
        application.key_creation_signer_slot !== signer.signerSlot ||
        targetLifecycle.account_id !== String(context.input.walletId) ||
        targetLifecycle.session_id !== String(identity.thresholdSessionId) ||
        targetLifecycle.selected_server_id !== String(signingWorkerId) ||
        !mpcMaterialActivationRefsEqual(
          routerAbMpcMaterialActivationRefFromWire(targetBinding.material_activation),
          materialActivation,
        ) ||
        !mpcMaterialActivationRefsEqual(
          routerAbMpcMaterialActivationRefFromWire(
            linkedMaterial.publicFacts.activationReceipt.material_activation,
          ),
          materialActivation,
        ) ||
        base64UrlEncode(
          Uint8Array.from(linkedMaterial.publicFacts.activationReceipt.registered_public_key),
        ) !== resolved.registeredPublicKeyB64u ||
        !targetFactorMatches
      ) {
        throw new Error('[SigningEngine][near] linked Ed25519 signer identity changed');
      }
      participantIds = linkedMaterial.publicFacts.participantIds;
    }

    const activeMaterial = this.enginePorts.ed25519YaoActiveClients.resolve({
      walletId: context.input.walletId,
      nearAccountId: context.input.nearAccountId,
      materialActivation,
    });
    if (activeMaterial) {
      const exactMaterial = validateExactNearEd25519YaoOperationMaterial({
        material: activeMaterial,
        input: context.input,
        expectedActivation: materialActivation,
      });
      const metadata = exactMaterial.activeClient.metadata();
      const facts = exactMaterial.facts;
      if (
        base64UrlEncode(metadata.registeredPublicKey) !== resolved.registeredPublicKeyB64u ||
        metadata.participantIds[0] !== participantIds[0] ||
        metadata.participantIds[1] !== participantIds[1] ||
        metadata.applicationBinding.wallet_id !== String(context.input.walletId) ||
        metadata.applicationBinding.near_ed25519_signing_key_id !==
          String(signer.nearEd25519SigningKeyId) ||
        metadata.applicationBinding.key_creation_signer_slot !== signer.signerSlot ||
        metadata.scope.account_id !== String(context.input.walletId) ||
        metadata.scope.threshold_session_id !== String(identity.thresholdSessionId) ||
        metadata.scope.signing_worker_id !== String(signingWorkerId) ||
        facts.routerAbNormalSigning.signingWorkerId !== String(signingWorkerId) ||
        facts.signingRootId !== metadata.applicationBinding.signing_root_id ||
        facts.signingRootVersion !== metadata.scope.root_share_epoch
      ) {
        throw new Error('[SigningEngine][near] active Ed25519 public material changed');
      }
      if (linkedMaterial) {
        const application = linkedMaterial.publicFacts.applicationBinding;
        const targetLifecycle = linkedMaterial.publicFacts.targetBinding.lifecycle;
        if (
          metadata.applicationBinding.wallet_id !== application.wallet_id ||
          metadata.applicationBinding.near_ed25519_signing_key_id !==
            application.near_ed25519_signing_key_id ||
          metadata.applicationBinding.signing_root_id !== application.signing_root_id ||
          metadata.applicationBinding.key_creation_signer_slot !==
            application.key_creation_signer_slot ||
          metadata.scope.lifecycle_id !== targetLifecycle.lifecycle_id ||
          metadata.scope.root_share_epoch !== targetLifecycle.root_share_epoch ||
          metadata.scope.account_id !== targetLifecycle.account_id ||
          metadata.scope.threshold_session_id !== targetLifecycle.session_id ||
          metadata.scope.signing_worker_id !== targetLifecycle.selected_server_id
        ) {
          throw new Error('[SigningEngine][near] linked Ed25519 runtime identity changed');
        }
      }
    }

    const publicKey = `ed25519:${base58Encode(registeredPublicKey)}`;
    return {
      nearAccountId: context.input.nearAccountId,
      signerSlot: signer.signerSlot,
      kind: 'threshold_ed25519_v1',
      publicKey,
      relayerKeyId: signingWorkerId,
      keyVersion: NEAR_ED25519_YAO_KEY_VERSION_V1,
      participants: buildThresholdEd25519Participants2pV1({
        clientParticipantId: participantIds[0],
        relayerParticipantId: participantIds[1],
        relayerKeyId: signingWorkerId,
        clientShareDerivation: 'prf_first_v1',
      }),
      timestamp: authority.activatedAtMs,
    };
  }

  private async resolveExactNearEd25519YaoPreparedMaterial(
    context: PreparedNearEd25519YaoMaterialContext,
    preparation: NearEd25519YaoSigningPreparation,
  ): Promise<NearEd25519YaoOperationMaterial> {
    const expectedActivation = requireBoundNearEd25519YaoPreparationActivation({
      context,
      preparation,
    });
    switch (preparation.hydration.kind) {
      case 'use_live_runtime': {
        const capability = this.enginePorts.ed25519YaoActiveClients.resolve({
          walletId: context.input.walletId,
          nearAccountId: context.input.nearAccountId,
          materialActivation: expectedActivation,
        });
        if (!capability) {
          throw new Error('[SigningEngine][near] active Ed25519 Yao capability is unavailable');
        }
        return validateExactNearEd25519YaoOperationMaterial({
          material: capability,
          input: context.input,
          expectedActivation,
        });
      }
      case 'rehydrate_material_activation': {
        const args = requireAuthorizedNearEd25519BoundaryInput(context.input);
        switch (args.auth.kind) {
          case WALLET_AUTH_METHODS.passkey: {
            const material = await this.rehydrateExactPasskeyEd25519YaoCapabilityForSigning(args);
            try {
              const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
                args.walletId,
              );
              if (
                authorizationRead.kind !== 'found' ||
                authorizationRead.authorization.selectedAuthMethod.kind !==
                  WALLET_AUTH_METHODS.passkey
              ) {
                throw new Error(
                  `[SigningEngine][near] Wallet Session authorization is ${authorizationRead.kind}`,
                );
              }
              const sealedRuntime = await requireExactEd25519SealedRuntimeForLane({
                walletId: args.walletId,
                laneIdentity: args.laneIdentity,
              });
              await hydrateOwnerNearEd25519ExecutionLane({
                input: args,
                authorization: authorizationRead.authorization,
                sealedRuntime,
                material,
              });
              return validateExactNearEd25519YaoOperationMaterial({
                material,
                input: args,
                expectedActivation,
              });
            } catch (error) {
              material.activeClient.dispose();
              throw error;
            }
          }
          case WALLET_AUTH_METHODS.emailOtp: {
            throw new Error(
              '[SigningEngine][near] Email OTP custody cache is unavailable; link the device before signing',
            );
          }
          default:
            args.auth satisfies never;
            throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
        }
      }
      case 'reauthorize_public_anchor':
        throw new Error('[SigningEngine][near] retired material requires reauthorization');
      case 'blocked':
        throw new Error(
          `[SigningEngine][near] prepared material is blocked: ${preparation.hydration.reason}`,
        );
      default:
        preparation.hydration satisfies never;
        throw new Error('[SigningEngine][near] unsupported prepared material hydration');
    }
  }

  private async resolveExactNearEd25519YaoWalletSessionState(
    context: PreparedNearEd25519YaoMaterialContext,
  ): Promise<ResolvedRouterAbEd25519WalletSessionState> {
    const args = requireAuthorizedNearEd25519BoundaryInput(context.input);
    if (args.auth.kind === WALLET_AUTH_METHODS.emailOtp) {
      if (!context.materialActivation) {
        throw new Error('[SigningEngine][near] prepared material has no activation');
      }
      const publicLane = await resolveExactEmailOtpPublicLaneReference({
        store: this.ed25519YaoPublicCapabilityReferences,
        laneIdentity: args.laneIdentity,
        materialActivation: context.materialActivation,
      });
      const material = this.enginePorts.ed25519YaoActiveClients.resolve({
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        materialActivation: context.materialActivation,
      });
      if (!material) {
        throw new Error('[SigningEngine][near] active Email OTP Ed25519 material is unavailable');
      }
      const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
        args.walletId,
      );
      if (
        authorizationRead.kind !== 'found' ||
        authorizationRead.authorization.selectedAuthMethod.kind !== WALLET_AUTH_METHODS.emailOtp
      ) {
        throw new Error(
          `[SigningEngine][near] Wallet Session authorization is ${authorizationRead.kind}`,
        );
      }
      return await emailOtpWalletSessionStateFromPublicLane({
        reference: publicLane,
        material: validateExactNearEd25519YaoOperationMaterial({
          material,
          input: args,
          expectedActivation: context.materialActivation,
        }),
        authorization: authorizationRead.authorization,
        materialActivation: context.materialActivation,
        relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
      });
    }
    const runtimeResolution = await resolveExactEd25519SealedSessionRuntimeForLane({
      walletId: args.walletId,
      laneIdentity: args.laneIdentity,
    });
    if (runtimeResolution.kind === 'missing' && args.auth.kind === WALLET_AUTH_METHODS.passkey) {
      if (!context.materialActivation) {
        throw new Error('[SigningEngine][near] prepared material has no activation');
      }
      const publicLane = await resolveExactPasskeyPublicLaneReference({
        store: this.ed25519YaoPublicCapabilityReferences,
        laneIdentity: args.laneIdentity,
      });
      if (
        !mpcMaterialActivationRefsEqual(publicLane.materialActivation, context.materialActivation)
      ) {
        throw new Error('[SigningEngine][near] Passkey public lane activation changed');
      }
      const material = this.enginePorts.ed25519YaoActiveClients.resolve({
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        materialActivation: context.materialActivation,
      });
      if (!material) {
        throw new Error('[SigningEngine][near] active Passkey Ed25519 material is unavailable');
      }
      const exactMaterial = validateExactNearEd25519YaoOperationMaterial({
        material,
        input: args,
        expectedActivation: context.materialActivation,
      });
      const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
        args.walletId,
      );
      if (
        authorizationRead.kind !== 'found' ||
        authorizationRead.authorization.selectedAuthMethod.kind !== WALLET_AUTH_METHODS.passkey
      ) {
        throw new Error(
          `[SigningEngine][near] Wallet Session authorization is ${authorizationRead.kind}`,
        );
      }
      return await passkeyWalletSessionStateFromPublicLane({
        reference: publicLane,
        material: exactMaterial,
        authorization: authorizationRead.authorization,
        materialActivation: context.materialActivation,
        relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
      });
    }
    if (runtimeResolution.kind !== 'resolved') {
      throw new Error(
        `[SigningEngine][near] exact persisted Ed25519 runtime is ${runtimeResolution.kind}`,
      );
    }
    const runtime = runtimeResolution.runtime;
    return await walletSessionStateFromExactEd25519Runtime({
      runtime,
      relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
    });
  }

  private async resolveExactNearEd25519FundingSession(
    context: PreparedNearEd25519YaoMaterialContext,
  ): Promise<NearEd25519FundingSession> {
    const identity = nearEd25519MaterialIdentityFromBoundaryInput(context.input);
    const authorizationRead = await this.readExactNearEd25519WalletSessionAuthorization(
      identity.signer.account.wallet.walletId,
    );
    if (
      authorizationRead.kind !== 'found' ||
      authorizationRead.authorization.selectedAuthMethod.kind !== identity.auth.kind
    ) {
      throw new Error('[SigningEngine][near] authenticated funding session is unavailable');
    }
    if (!context.materialActivation) {
      throw new Error('[SigningEngine][near] funding session material activation is unavailable');
    }
    if (
      !nearEd25519SessionMatchesMaterialActivation({
        session: authorizationRead.authorization.session,
        materialActivation: context.materialActivation,
      })
    ) {
      throw new Error('[SigningEngine][near] authenticated funding session material changed');
    }
    const walletSessionToken = requireOpaqueWalletSessionToken(
      authorizationRead.authorization.operationCredential.token,
      '[SigningEngine][near] authenticated funding Wallet Session token',
    );
    if (
      authorizationRead.authorization.session.walletId !==
        identity.signer.account.wallet.walletId ||
      authorizationRead.authorization.selectedAuthMethod.kind !== identity.auth.kind ||
      !authorizationRead.authorization.operationCredential.walletSessionId ||
      !authorizationRead.authorization.session.quotaId
    ) {
      throw new Error('[SigningEngine][near] funding session identity does not match');
    }
    return {
      kind: 'near_ed25519_funding_session',
      signer: identity.signer,
      thresholdSessionId: identity.thresholdSessionId,
      walletSessionToken,
    };
  }

  private async prepareExactNearEd25519YaoOperationStepUpAtBoundary(
    context: PreparedNearEd25519YaoMaterialContext,
    preparation: NearEd25519YaoSigningPreparation,
  ): Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation> {
    if (
      nearEd25519PresentedAuthFromBoundaryInput(context.input).kind !== WALLET_AUTH_METHODS.passkey
    ) {
      throw new Error('[SigningEngine][near] Email OTP material cannot use Passkey rehydration');
    }
    const expectedActivation = requireBoundNearEd25519YaoPreparationActivation({
      context,
      preparation,
    });
    const prepared = await this.prepareExactPasskeyEd25519YaoOperationStepUpForSigning(
      context.input,
    );
    if (!mpcMaterialActivationRefsEqual(expectedActivation, prepared.materialActivation)) {
      throw new Error('[SigningEngine][near] operation step-up changed material activation');
    }
    return prepared;
  }

  private async prepareExactNearEmailOtpEd25519YaoOperationStepUpAtBoundary(
    context: PreparedNearEd25519YaoMaterialContext,
    preparation: NearEd25519YaoSigningPreparation,
  ): Promise<NearEmailOtpEd25519OperationStepUpCapabilityPreparation> {
    const args = requireAuthorizedNearEd25519BoundaryInput(context.input);
    if (args.auth.kind !== WALLET_AUTH_METHODS.emailOtp) {
      throw new Error('[SigningEngine][near] Passkey material cannot use Email OTP rehydration');
    }
    const expectedActivation = requireBoundNearEd25519YaoPreparationActivation({
      context,
      preparation,
    });
    switch (preparation.hydration.kind) {
      case 'use_live_runtime': {
        const material = await this.resolveExactNearEd25519YaoPreparedMaterial(
          context,
          preparation,
        );
        return {
          kind: 'live',
          materialActivation: expectedActivation,
          material,
        };
      }
      case 'rehydrate_material_activation': {
        const publicLane = await resolveExactEmailOtpPublicLaneReference({
          store: this.ed25519YaoPublicCapabilityReferences,
          laneIdentity: args.laneIdentity,
          materialActivation: expectedActivation,
        });
        const user = await this.getUserBySignerSlot(
          args.nearAccountId,
          args.laneIdentity.signer.signerSlot,
        );
        if (
          !user ||
          String(user.walletId) !== String(args.walletId) ||
          String(user.nearAccountId) !== String(args.nearAccountId) ||
          user.signerSlot !== args.laneIdentity.signer.signerSlot ||
          user.authMethod !== WALLET_AUTH_METHODS.emailOtp
        ) {
          throw new Error('[SigningEngine][near] Email OTP signer record is unavailable');
        }
        const sealed = await this.loadEmailOtpWalletCustodyEd25519Material({
          nearAccountId: String(args.nearAccountId),
          signerSlot: user.signerSlot,
        });
        if (sealed.kind !== 'found') {
          throw new Error('[SigningEngine][near] Email OTP custody material is unavailable');
        }
        const registeredPublicKey = `ed25519:${base58Encode(
          base64UrlDecode(sealed.material.binding.registeredPublicKeyB64u),
        )}`;
        if (
          registeredPublicKey !== user.operationalPublicKey ||
          sealed.material.binding.walletId !== String(args.walletId) ||
          sealed.material.binding.nearAccountId !== String(args.nearAccountId) ||
          sealed.material.binding.signerSlot !== user.signerSlot ||
          sealed.material.binding.signingWorkerId !== String(expectedActivation.signingWorker)
        ) {
          throw new Error('[SigningEngine][near] Email OTP custody material binding changed');
        }
        const relayerUrl = this.seamsWebConfigs.network.relayer?.url || '';
        if (!relayerUrl) {
          throw new Error('[SigningEngine][near] Email OTP recovery requires a relay URL');
        }
        const recoveryContext: EmailOtpEd25519OperationRecoveryContext = {
          input: args,
          materialActivation: expectedActivation,
          facts: emailOtpEd25519OperationMaterialFacts({
            input: args,
            publicLane,
            relayerUrl,
          }),
          publicLane,
          sealedMaterial: sealed.material,
          operationalPublicKey: user.operationalPublicKey,
          emailHashHex: await sha256HexUtf8(user.loginDisplayName.trim().toLowerCase()),
        };
        return {
          kind: 'sealed',
          materialActivation: expectedActivation,
          facts: recoveryContext.facts,
          authorizeAndRehydrate: this.authorizeAndRehydrateEmailOtpEd25519OperationMaterial.bind(
            this,
            recoveryContext,
          ),
        };
      }
      case 'reauthorize_public_anchor':
        throw new Error('[SigningEngine][near] retired Email OTP material cannot sign');
      case 'blocked':
        throw new Error(
          `[SigningEngine][near] Email OTP operation material is blocked: ${preparation.hydration.reason}`,
        );
      default:
        preparation.hydration satisfies never;
        throw new Error('[SigningEngine][near] unsupported Email OTP operation material');
    }
  }

  private async authorizeAndRehydrateEmailOtpEd25519OperationMaterial(
    context: EmailOtpEd25519OperationRecoveryContext,
    request: EmailOtpEd25519OperationRecoveryRequest,
  ): Promise<{
    material: NearEd25519YaoOperationMaterial;
    issuedAuthorization: {
      kind: 'verified_step_up';
      authorization: { kind: 'operation_step_up'; evidence_set_digest: string };
      expiresAtMs: number;
    };
  }> {
    const args = requireAuthorizedNearEd25519BoundaryInput(context.input);
    if (
      args.auth.kind !== WALLET_AUTH_METHODS.emailOtp ||
      request.proof.providerSubjectId !== args.auth.providerSubjectId
    ) {
      throw new Error('[SigningEngine][near] Email OTP operation authority changed');
    }
    const credential = await this.resolveOperationStepUpCredential({
      walletId: args.walletId,
      relayerUrl: context.facts.relayerUrl,
      proof: request.proof,
    });
    if (credential.kind !== 'wallet_session_opaque') {
      throw new Error('[SigningEngine][near] Email OTP recovery requires an opaque Wallet Session');
    }
    const recovered = await requestRehydrateEmailOtpEd25519YaoOperationMaterial({
      workerCtx: this.signerWorkerManager.getContext(),
      payload: {
        relayUrl: context.facts.relayerUrl,
        walletId: String(args.walletId),
        orgId: context.publicLane.runtimePolicyScope.orgId,
        providerSubjectId: args.auth.providerSubjectId,
        nearAccountId: String(args.nearAccountId),
        signerSlot: context.publicLane.signerSlot,
        expectedOperationalPublicKey: context.operationalPublicKey,
        expectedThresholdSessionId: context.publicLane.thresholdSessionId,
        expectedMaterialActivation: context.materialActivation,
        ed25519YaoRecovery: {
          kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
          signerSlot: context.publicLane.signerSlot,
          remainingUses: DEFAULT_UNLOCK_REMAINING_USES,
          orgId: context.publicLane.runtimePolicyScope.orgId,
        },
        walletCustodyEd25519Material: {
          kind: 'found',
          material: context.sealedMaterial,
        },
        normalSigningRequest: request.normalSigningRequest,
        displayDigest: request.displayDigest,
        proof: request.proof,
        credential,
      },
    });
    if (recovered.walletCustodyEd25519Material) {
      try {
        await this.persistWalletCustodyEd25519Material(recovered.walletCustodyEd25519Material);
      } catch (error) {
        await disposeWalletCustodyEd25519ActiveClientV1({
          workerContext: this.signerWorkerManager.getContext(),
          activeClientHandle: recovered.activeClientHandle,
        }).catch(() => undefined);
        throw error;
      }
    }
    await this.activateEmailOtpEd25519CustodyCapabilityInternal({
      commitQueue: 'already_acquired',
      walletSession: {
        walletId: args.walletId,
        walletSessionUserId: String(args.walletId),
      },
      providerSubject: args.auth.providerSubjectId,
      emailHashHex: context.emailHashHex,
      signerSlot: context.publicLane.signerSlot,
      expectedOperationalPublicKey: context.operationalPublicKey,
      expectedThresholdSessionId: String(context.publicLane.thresholdSessionId),
      bootstrap: recovered.bootstrap,
      activeClientHandle: recovered.activeClientHandle,
      metadata: recovered.metadata,
    });
    const active = this.enginePorts.ed25519YaoActiveClients.resolve({
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      materialActivation: context.materialActivation,
    });
    if (!active) {
      throw new Error('[SigningEngine][near] recovered Email OTP material is unavailable');
    }
    const material = validateExactNearEd25519YaoOperationMaterial({
      material: active,
      input: args,
      expectedActivation: context.materialActivation,
    });
    return {
      material,
      issuedAuthorization: {
        kind: recovered.issuedAuthorization.kind,
        authorization: recovered.issuedAuthorization.authorization,
        expiresAtMs: recovered.issuedAuthorization.expiresAtMs,
      },
    };
  }

  private async resolveExactNearEd25519YaoSigningHydration(input: {
    args: PrepareNearEd25519YaoMaterialBoundaryInput;
    walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
    publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1;
    runtime: NearEd25519YaoRuntimeObservationV1;
    unlockSource: PasskeyEd25519YaoUnlockSourceV1;
  }): Promise<MpcCapabilityHydrationPlan> {
    const args = requireAuthorizedNearEd25519BoundaryInput(input.args);
    switch (args.auth.kind) {
      case WALLET_AUTH_METHODS.passkey: {
        const resolved = await this.resolvePasskeyEd25519YaoHydration({
          walletSessionState: input.walletSessionState,
          credentialIdB64u: args.auth.credentialIdB64u,
          publicLocator: input.publicLocator,
          unlockSource: input.unlockSource,
        });
        let hydration: MpcCapabilityHydrationPlan;
        switch (resolved.kind) {
          case 'live':
          case 'blocked':
            hydration = resolved.plan;
            break;
          case 'rehydrated':
            resolved.activeClient.dispose();
            hydration = resolved.plan;
            break;
          default:
            resolved satisfies never;
            throw new Error('[SigningEngine][near] unsupported Passkey hydration result');
        }
        if (hydration.kind === 'blocked' && hydration.reason === 'missing_material') {
          const prepared = await preparePasskeyEd25519YaoLocalMaterialRehydrationV1({
            store: IndexedDBManager,
            walletSessionState: input.walletSessionState,
            rpId: args.auth.rpId,
            credentialIdB64u: args.auth.credentialIdB64u,
            authority: input.walletSessionState.authority,
            publicLocator: input.publicLocator,
          });
          return prepared.plan;
        }
        return hydration;
      }
      case WALLET_AUTH_METHODS.emailOtp:
        if (input.publicLocator.kind !== 'available') {
          throw new Error('[SigningEngine][near] Email OTP custody locator is unavailable');
        }
        return await this.resolveWalletCustodyEmailOtpHydration({
          walletId: args.walletId,
          nearAccountId: args.nearAccountId,
          signerSlot: args.laneIdentity.signer.signerSlot,
          materialActivation: input.publicLocator.materialActivation,
        });
      default:
        args.auth satisfies never;
        throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
    }
  }

  private async prepareExactPasskeyEd25519YaoOperationStepUpForSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation> {
    const identity = nearEd25519MaterialIdentityFromBoundaryInput(args);
    if (identity.auth.kind !== WALLET_AUTH_METHODS.passkey) {
      throw new Error('[SigningEngine][near] Passkey operation step-up requires Passkey material');
    }
    const lane = await this.resolveNearEd25519YaoSigningLane({
      ...(args.laneIdentity !== undefined
        ? {
            kind: 'exact_lane' as const,
            walletId: args.walletId,
            nearAccountId: args.nearAccountId,
            signerSlot: args.laneIdentity.signer.signerSlot,
            thresholdSessionId: args.laneIdentity.thresholdSessionId,
            laneIdentity: args.laneIdentity,
          }
        : {
            kind: 'material_identity' as const,
            walletId: args.walletId,
            nearAccountId: args.nearAccountId,
            signerSlot: identity.signer.signerSlot,
            thresholdSessionId: identity.thresholdSessionId,
            materialIdentity: identity,
          }),
    });
    if (!lane) {
      throw new Error('[SigningEngine][near] sealed Ed25519 operation lane is unavailable');
    }
    const runtime =
      args.laneIdentity !== undefined
        ? await requireExactEd25519SealedRuntimeForLane({
            walletId: args.walletId,
            laneIdentity: args.laneIdentity,
          })
        : await requireExactEd25519SealedRuntimeForMaterialIdentity({
            walletId: args.walletId,
            identity,
          });
    const walletSessionState = await walletSessionStateFromExactEd25519Runtime({
      runtime,
      relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
    });
    const credentialIdB64u =
      runtime.factor.kind === 'passkey' ? runtime.factor.credentialIdB64u : '';
    const rpId = runtime.factor.kind === 'passkey' ? runtime.factor.rpId : '';
    if (!credentialIdB64u || !rpId) {
      throw new Error('[SigningEngine][near] sealed Ed25519 passkey authority is unavailable');
    }
    const signer = walletSessionState.signingLane.identity.signer;
    const publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1 = {
      kind: 'available',
      walletId: String(signer.account.wallet.walletId),
      nearAccountId: String(signer.account.nearAccountId),
      signerSlot: signer.signerSlot,
      materialActivation: runtime.sealedRecord.ed25519Restore.materialActivation,
    };
    const prepared = await preparePasskeyEd25519YaoLocalMaterialRehydrationV1({
      store: IndexedDBManager,
      walletSessionState,
      rpId,
      credentialIdB64u,
      authority: walletSessionState.authority,
      publicLocator,
    });
    if (prepared.kind === 'blocked') {
      throw new Error(
        `[SigningEngine][near] sealed Ed25519 operation hydration blocked: ${prepared.plan.reason}`,
      );
    }
    return {
      materialActivation: prepared.plan.materialActivation,
      facts: nearEd25519YaoOperationMaterialFacts(walletSessionState),
      participantIds: [...runtime.participantIds],
      rehydrate: this.rehydratePreparedPasskeyEd25519YaoOperationStepUp.bind(this, {
        input: args,
        walletSessionState,
        authority: walletSessionState.authority,
        rpId,
        credentialIdB64u,
        publicLocator,
        materialActivation: prepared.plan.materialActivation,
      }),
    };
  }

  private async rehydratePreparedPasskeyEd25519YaoOperationStepUp(
    prepared: {
      input: PrepareNearEd25519YaoMaterialBoundaryInput;
      walletSessionState: NearResolvedEd25519SigningSessionState;
      authority: WalletAuthAuthorityRef;
      rpId: string;
      credentialIdB64u: string;
      publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1;
      materialActivation: MpcMaterialActivationRef;
    },
    credential: WebAuthnAuthenticationCredential,
  ): Promise<NearEd25519YaoOperationMaterial> {
    const credentialIdB64u = String(credential.rawId || credential.id || '').trim();
    if (credentialIdB64u !== prepared.credentialIdB64u) {
      throw new Error('[SigningEngine][near] operation assertion changed passkey credential');
    }
    const secretSource = buildThresholdEd25519WebAuthnPrfSecretSource({
      credential,
      rpId: prepared.rpId,
    });
    const hydrated = await hydratePasskeyEd25519YaoLocalMaterialV1({
      store: IndexedDBManager,
      walletSessionState: prepared.walletSessionState,
      rpId: prepared.rpId,
      credentialIdB64u: prepared.credentialIdB64u,
      authority: prepared.authority,
      publicLocator: prepared.publicLocator,
      unlockSource: {
        kind: 'available',
        passkeyPrfFirstB64u: secretSource.secretSource.prfFirstB64u,
      },
      liveMaterial: null,
    });
    if (hydrated.kind === 'blocked') {
      throw new Error(
        `[SigningEngine][near] operation assertion hydration blocked: ${hydrated.plan.reason}`,
      );
    }
    if (hydrated.kind !== 'rehydrated') {
      throw new Error(
        '[SigningEngine][near] operation assertion did not rehydrate sealed material',
      );
    }
    if (
      !mpcMaterialActivationRefsEqual(prepared.materialActivation, hydrated.plan.materialActivation)
    ) {
      hydrated.activeClient.dispose();
      throw new Error('[SigningEngine][near] operation assertion changed material activation');
    }
    const material = {
      activeClient: hydrated.activeClient,
      facts: nearEd25519YaoOperationMaterialFacts(prepared.walletSessionState),
    };
    try {
      return validateExactNearEd25519YaoOperationMaterial({
        material,
        input: prepared.input,
        expectedActivation: prepared.materialActivation,
      });
    } catch (error) {
      material.activeClient.dispose();
      throw error;
    }
  }

  private async resolveExactPasskeyEd25519YaoExportContext(
    args: Parameters<RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext']>[0],
  ): ReturnType<RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext']> {
    const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
    if (!relayerUrl) {
      throw new Error('[SigningEngine][ed25519-export] passkey export requires relayerUrl');
    }
    const walletId = toWalletId(String(args.laneIdentity.signer.account.wallet.walletId));
    const sealedRecord = await readExactEd25519SealedSession(
      ed25519DurableMaterialLocator({
        authMethod: args.laneIdentity.auth.kind,
        materialActivation: args.materialActivation,
      }),
    );
    if (!sealedRecord) {
      return await this.resolveLinkedPasskeyEd25519YaoExportContext({
        ...args,
        walletId,
        relayerUrl,
      });
    }
    const runtime = await requireExactEd25519SealedRuntimeForMaterialActivation({
      walletId,
      laneIdentity: args.laneIdentity,
      materialActivation: args.materialActivation,
    });
    let thresholdSessionId = args.laneIdentity.thresholdSessionId;
    const activeAuthorization = await resolveActiveEd25519WalletSessionAuthorization(
      runtime.walletId,
      relayerUrl,
    );
    if (activeAuthorization) {
      const walletSessionState = await walletSessionStateFromExactEd25519Runtime({
        runtime,
        relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
      });
      const warmSessionClaim = await this.ensurePasskeyEd25519WarmSessionForSigning({
        runtime,
        walletSessionState,
        materialActivation: args.materialActivation,
      });
      if (warmSessionClaim.ok) {
        thresholdSessionId = walletSessionState.thresholdSessionId;
      }
    }
    const input = {
      subject: {
        kind: 'owner_sealed_runtime',
        walletId: toWalletId(String(args.laneIdentity.signer.account.wallet.walletId)),
        nearAccountId: String(args.laneIdentity.signer.account.nearAccountId),
        nearEd25519SigningKeyId: String(args.laneIdentity.signer.nearEd25519SigningKeyId),
        signerSlot: args.laneIdentity.signer.signerSlot,
        thresholdSessionId,
        materialActivation: args.materialActivation,
      },
      relayerUrl,
      fetch: fetchWithGlobalThis,
    } as const;
    return await resolvePasskeyEd25519YaoExportContextV1(input);
  }

  private async resolveLinkedPasskeyEd25519YaoExportContext(
    args: Parameters<RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext']>[0] & {
      readonly walletId: WalletId;
      readonly relayerUrl: string;
    },
  ): Promise<PasskeyEd25519YaoExportContextResolutionV1> {
    if (args.laneIdentity.auth.kind !== WALLET_AUTH_METHODS.passkey) {
      throw new Error('[SigningEngine][ed25519-export] linked export requires a Passkey lane');
    }
    const selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(args.walletId));
    if (selected.kind !== 'resolved') {
      const detail = selected.kind === 'integrity_error' ? `: ${selected.reason}` : '';
      throw new Error(
        `[SigningEngine][ed25519-export] selected Wallet Authority is ${selected.kind}${detail}`,
      );
    }
    const { selection, authMethod, authority, signerMaterials, exportRoot } = selected;
    if (
      selection.lockState !== 'unlocked' ||
      authMethod.kind !== WALLET_AUTH_METHODS.passkey ||
      authMethod.status !== 'active' ||
      authority.state !== 'active' ||
      authority.provenance.kind !== 'device_link' ||
      String(authMethod.walletId) !== String(args.walletId) ||
      authMethod.walletAuthorityId !== authority.authorityId ||
      authMethod.walletAuthMethodId !== selection.walletAuthMethodId ||
      String(authMethod.rpId) !== String(args.laneIdentity.auth.rpId) ||
      authMethod.credentialIdB64u !== args.laneIdentity.auth.credentialIdB64u
    ) {
      throw new Error(
        '[SigningEngine][ed25519-export] selected linked Passkey authority is unavailable',
      );
    }
    const authorityActivation = authority.signerActivations.ed25519;
    if (
      !authority.permissions.includes('export_keys') ||
      !authorityActivation ||
      !mpcMaterialActivationRefsEqual(
        authorityActivation.materialActivation,
        args.materialActivation,
      ) ||
      !exportRoot
    ) {
      throw new Error(
        '[SigningEngine][ed25519-export] selected authority has no exact Ed25519 export capability',
      );
    }

    let linkedMaterial: Extract<
      WalletAuthoritySignerMaterialRecordV1,
      { kind: 'wallet_authority_linked_signer_material_v1'; keyFamily: 'ed25519' }
    > | null = null;
    for (const candidate of signerMaterials) {
      if (
        !isLinkedEd25519SignerMaterial(candidate) ||
        candidate.authorityId !== authority.authorityId ||
        candidate.walletAuthMethodId !== authMethod.walletAuthMethodId ||
        !mpcMaterialActivationRefsEqual(candidate.materialActivation, args.materialActivation)
      ) {
        continue;
      }
      if (linkedMaterial) {
        throw new Error('[SigningEngine][ed25519-export] linked Ed25519 material is ambiguous');
      }
      linkedMaterial = candidate;
    }
    if (!linkedMaterial) {
      throw new Error('[SigningEngine][ed25519-export] linked Ed25519 material is unavailable');
    }
    const targetFactor = linkedMaterial.targetFactor;
    if (
      targetFactor.kind !== WALLET_AUTH_METHODS.passkey ||
      targetFactor.walletAuthMethodId !== authMethod.walletAuthMethodId ||
      targetFactor.rpId !== authMethod.rpId ||
      targetFactor.credentialIdB64u !== authMethod.credentialIdB64u
    ) {
      throw new Error('[SigningEngine][ed25519-export] linked Ed25519 factor binding changed');
    }

    const exactSession = exactWalletSessionWithOperationCredentialOrThrow(
      await walletSessionAuthorizations.readExactWithOperationCredential({
        walletId: args.walletId,
        authorityId: authority.authorityId,
        authMethodId: authMethod.walletAuthMethodId,
      }),
      '[SigningEngine][ed25519-export] exact linked Wallet Session requires a newer client',
    );
    let exactExportSubject = false;
    if (exactSession) {
      for (const subject of exactSession.record.capabilitySubjects) {
        if (
          subject.kind === 'export_keys' &&
          subject.keyFamily === 'ed25519' &&
          mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation)
        ) {
          exactExportSubject = true;
          break;
        }
      }
    }
    if (
      !exactSession ||
      !exactExportSubject ||
      exactSession.record.authorityDigestB64u !== authority.authorityDigestB64u ||
      exactSession.record.authorityRevocationEpoch !== authority.revocationEpoch ||
      exactSession.record.expiresAtMs <= Date.now()
    ) {
      throw new Error('[SigningEngine][ed25519-export] exact linked Wallet Session is unavailable');
    }

    const publicLane = await resolveExactPasskeyPublicLaneReference({
      store: this.ed25519YaoPublicCapabilityReferences,
      laneIdentity: args.laneIdentity,
    });
    if (!mpcMaterialActivationRefsEqual(publicLane.materialActivation, args.materialActivation)) {
      throw new Error('[SigningEngine][ed25519-export] linked public lane activation changed');
    }
    const factorAuthority = await walletAuthAuthorityRef({
      authority: {
        walletId: authMethod.walletId,
        factor: {
          kind: WALLET_AUTH_METHODS.passkey,
          credentialIdB64u: authMethod.credentialIdB64u,
        },
        verifier: {
          kind: 'webauthn',
          rpId: authMethod.rpId,
        },
        bindingId: authMethod.walletAuthMethodId,
      },
    });
    if (
      String(factorAuthority.authorityDigest) !== String(authority.authorityDigestB64u) ||
      factorAuthority.walletAuthMethodId !== authMethod.walletAuthMethodId
    ) {
      throw new Error('[SigningEngine][ed25519-export] Passkey Wallet Session authority changed');
    }

    const activeMaterial = this.enginePorts.ed25519YaoActiveClients.resolve({
      walletId: args.walletId,
      nearAccountId: args.laneIdentity.signer.account.nearAccountId,
      materialActivation: args.materialActivation,
    });
    if (!activeMaterial || activeMaterial.activeClient.status().kind !== 'active') {
      throw new Error('[SigningEngine][ed25519-export] linked Ed25519 runtime is unavailable');
    }
    const metadata = activeMaterial.activeClient.metadata();
    const metadataActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
    const facts = activeMaterial.facts;
    const signer = args.laneIdentity.signer;
    const application = linkedMaterial.publicFacts.applicationBinding;
    const registeredPublicKeyB64u = base64UrlEncode(metadata.registeredPublicKey);
    const stateEpoch = Number(metadata.stateEpoch);
    const parsedThresholdSessionId = parseThresholdEd25519SessionId(
      metadata.scope.threshold_session_id,
    );
    const runtimeScope = facts.runtimePolicyScope;
    const laneScope = publicLane.runtimePolicyScope;
    if (
      !parsedThresholdSessionId.ok ||
      !Number.isSafeInteger(stateEpoch) ||
      stateEpoch < 1 ||
      !mpcMaterialActivationRefsEqual(metadataActivation, args.materialActivation) ||
      String(facts.thresholdSessionId) !== String(args.laneIdentity.thresholdSessionId) ||
      String(facts.signer.account.wallet.walletId) !== String(args.walletId) ||
      String(facts.signer.account.nearAccountId) !== String(signer.account.nearAccountId) ||
      String(facts.signer.nearEd25519SigningKeyId) !== String(signer.nearEd25519SigningKeyId) ||
      facts.signer.signerSlot !== signer.signerSlot ||
      application.wallet_id !== String(args.walletId) ||
      application.near_ed25519_signing_key_id !== String(signer.nearEd25519SigningKeyId) ||
      application.key_creation_signer_slot !== signer.signerSlot ||
      metadata.applicationBinding.wallet_id !== application.wallet_id ||
      metadata.applicationBinding.near_ed25519_signing_key_id !==
        application.near_ed25519_signing_key_id ||
      metadata.applicationBinding.signing_root_id !== application.signing_root_id ||
      metadata.applicationBinding.key_creation_signer_slot !==
        application.key_creation_signer_slot ||
      metadata.scope.lifecycle_id !==
        linkedMaterial.publicFacts.targetBinding.lifecycle.lifecycle_id ||
      metadata.scope.root_share_epoch !==
        linkedMaterial.publicFacts.targetBinding.lifecycle.root_share_epoch ||
      metadata.scope.account_id !== String(args.walletId) ||
      metadata.scope.threshold_session_id !== String(args.laneIdentity.thresholdSessionId) ||
      metadata.scope.signing_worker_id !== facts.routerAbNormalSigning.signingWorkerId ||
      facts.signingRootId !== application.signing_root_id ||
      facts.signingRootVersion !== metadata.scope.root_share_epoch ||
      runtimeScope.orgId !== laneScope.orgId ||
      runtimeScope.projectId !== laneScope.projectId ||
      runtimeScope.envId !== laneScope.envId ||
      runtimeScope.signingRootVersion !== laneScope.signingRootVersion ||
      linkedMaterial.publicFacts.participantIds[0] !== metadata.participantIds[0] ||
      linkedMaterial.publicFacts.participantIds[1] !== metadata.participantIds[1] ||
      base64UrlEncode(
        Uint8Array.from(linkedMaterial.publicFacts.activationReceipt.registered_public_key),
      ) !== registeredPublicKeyB64u ||
      authorityActivation.signer.registeredPublicKeyB64u !== registeredPublicKeyB64u
    ) {
      throw new Error('[SigningEngine][ed25519-export] linked Ed25519 runtime identity changed');
    }

    const material: PasskeyEd25519YaoExportMaterialV1 = {
      authority: factorAuthority,
      walletId: signer.account.wallet.walletId,
      nearAccountId: signer.account.nearAccountId,
      nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
      signerSlot: signer.signerSlot,
      operationalPublicKey: `ed25519:${base58Encode(metadata.registeredPublicKey)}`,
      relayerKeyId: metadata.scope.signing_worker_id,
      credentialIdB64u: authMethod.credentialIdB64u,
      capability: {
        materialActivation: metadataActivation,
        activeCapabilityBinding: [...metadata.activeCapabilityBinding],
        registeredPublicKey: [...metadata.registeredPublicKey],
        nearAccountId: signer.account.nearAccountId,
        applicationBinding: metadata.applicationBinding,
        participantIds: metadata.participantIds,
        runtimePolicyScope: facts.runtimePolicyScope,
        lifecycle: {
          lifecycleId: metadata.scope.lifecycle_id,
          rootShareEpoch: metadata.scope.root_share_epoch,
          accountId: metadata.scope.account_id,
          thresholdSessionId: parsedThresholdSessionId.value,
          signerSetId: metadata.scope.signer_set_id,
          signingWorkerId: metadata.scope.signing_worker_id,
        },
        stateEpoch,
      },
    };
    return {
      kind: 'ready',
      context: {
        kind: 'passkey_ed25519_yao_export_context_v1',
        selectedLaneMaterialActivation: args.materialActivation,
        material,
        authorization: exactSession,
        relayerUrl: args.relayerUrl,
        rpId: authMethod.rpId,
        walletCustodyEnvelope: exportRoot.envelope,
      },
    };
  }

  private readExactEmailOtpEd25519ExportAuthorization(args: {
    readonly subject: ResolvedWalletCustodyEd25519ExportV1['lane'];
    readonly expectedMaterialActivation: MpcMaterialActivationRef;
  }): Promise<EmailOtpEd25519ExportAuthorizationReadResultV1> {
    return readExactEmailOtpEd25519ExportAuthorization({
      subject: args.subject,
      relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
    });
  }

  private async activateRecoveredEmailOtpEd25519ExportCapability(
    lane: ResolvedWalletCustodyEd25519ExportV1['lane'],
    request: EmailOtpEd25519YaoRecoveredCapabilityActivationRequestV1,
  ): Promise<void> {
    const activation = request.activation;
    await this.activateEmailOtpEd25519CustodyCapabilityWithExactCredential({
      commitQueue: 'acquire',
      walletSession: {
        walletId: lane.signer.account.wallet.walletId,
        walletSessionUserId: String(lane.signer.account.wallet.walletId),
      },
      providerSubject: lane.auth.providerSubjectId,
      emailHashHex: activation.emailHashHex,
      signerSlot: lane.signer.signerSlot,
      expectedOperationalPublicKey: `ed25519:${base58Encode(activation.metadata.registeredPublicKey)}`,
      expectedThresholdSessionId: String(lane.thresholdSessionId),
      bootstrap: activation.bootstrap,
      activeClientHandle: activation.activeClientHandle,
      metadata: activation.metadata,
      credentialExpectation: {
        kind: 'expect_exact_operation_credential',
        operationCredential: request.operationCredential,
      },
    });
  }

  private async resolveEmailOtpEd25519YaoExportContext(args: {
    laneIdentity: ResolvedWalletCustodyEd25519ExportV1['lane'];
    materialActivation: MpcMaterialActivationRef;
  }): Promise<ResolvedWalletCustodyEd25519ExportV1> {
    return await resolveWalletCustodyEd25519ExportContextV1({
      subject: args.laneIdentity,
      expectedMaterialActivation: args.materialActivation,
      readExactWalletSessionAuthorization:
        this.readExactEmailOtpEd25519ExportAuthorization.bind(this),
      resolveActiveCapability: (walletId, nearAccountId, materialActivation) =>
        this.enginePorts.ed25519YaoActiveClients.resolve({
          walletId,
          nearAccountId: toAccountId(nearAccountId),
          materialActivation,
        }),
      resolveEd25519YaoClientRootEnvelope: async ({
        subject,
        capability,
        selectedMaterialActivation,
      }) =>
        resolveSelectedEmailOtpEd25519ExportRootV1({
          selected: await IndexedDBManager.resolveSelectedWalletAuthority(
            String(subject.signer.account.wallet.walletId),
          ),
          subject,
          expectedMaterialActivation: selectedMaterialActivation,
          activeCapability: capability,
        }),
      loadWalletCustodyMaterial: () =>
        this.loadEmailOtpWalletCustodyEd25519Material({
          nearAccountId: String(args.laneIdentity.signer.account.nearAccountId),
          signerSlot: args.laneIdentity.signer.signerSlot,
        }),
      relayerUrl: this.seamsWebConfigs.network.relayer?.url || '',
      fetch: fetchWithGlobalThis,
      activateRecoveredCapability: this.activateRecoveredEmailOtpEd25519ExportCapability.bind(
        this,
        args.laneIdentity,
      ),
    });
  }

  private async resolveActiveNearEd25519YaoSigningLane(
    subject: NearEd25519CapabilityRehydrationSubject,
  ): Promise<NearEd25519YaoOperationMaterial | null> {
    const lane = await this.resolveNearEd25519YaoSigningLane(subject);
    if (!lane) return null;
    const capability =
      subject.kind === 'export_exact_lane'
        ? this.enginePorts.ed25519YaoActiveClients.resolve({
            walletId: subject.walletId,
            nearAccountId: subject.nearAccountId,
            materialActivation: subject.materialActivation,
          })
        : this.enginePorts.ed25519YaoActiveClients.resolveForWalletAccount({
            walletId: subject.walletId,
            nearAccountId: subject.nearAccountId,
          });
    return capability?.activeClient.status().kind === 'active' ? capability : null;
  }

  private async resolveNearEd25519YaoSigningLane(
    subject: NearEd25519CapabilityRehydrationSubject,
  ): Promise<ConcreteAvailableEd25519SigningLane | null> {
    const availableLanes = await this.readPersistedAvailableSigningLanes({
      walletId: subject.walletId,
    });
    const matches: ConcreteAvailableEd25519SigningLane[] = [];
    for (const lane of availableLanes.candidates.ed25519.near) {
      if (!nearEd25519LaneMatchesCapabilityRehydrationSubject(lane, subject)) continue;
      if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') continue;
      matches.push(lane);
    }
    if (matches.length > 1) {
      throw new Error('[SigningEngine][near] local Ed25519 material lane is ambiguous');
    }
    return matches[0] || null;
  }

  private async ensurePasskeyEd25519WarmSessionForSigning(args: {
    runtime: ExactEd25519SealedSessionRuntime;
    walletSessionState: NearResolvedEd25519SigningSessionState;
    materialActivation: MpcMaterialActivationRef;
  }): Promise<WarmSessionClaimResult> {
    const claim = await ensurePasskeyEd25519WarmSessionForSigning({
      ...args,
      claimWarmSessionMaterial: this.passkeyMpcSession.claimWarmSessionMaterial.bind(
        this.passkeyMpcSession,
      ),
      rehydrateWarmSessionMaterial: this.passkeyMpcSession.rehydrateWarmSessionMaterial.bind(
        this.passkeyMpcSession,
      ),
    });
    if (
      claim.ok &&
      args.runtime.factor.kind === 'passkey' &&
      String(args.runtime.thresholdSessionId) !== String(args.walletSessionState.thresholdSessionId)
    ) {
      await persistPasskeyEd25519YaoSessionForRefresh({
        persistence: this,
        session: args.walletSessionState,
        prfFirstB64u: claim.prfFirstB64u,
        ed25519Restore: buildPasskeyEd25519RestoreMetadata({
          rpId: args.runtime.factor.rpId,
          nearAccountId: args.runtime.nearAccountId,
          nearEd25519SigningKeyId: args.runtime.nearEd25519SigningKeyId,
          relayerKeyId: args.runtime.relayerKeyId,
          participantIds: args.runtime.participantIds,
          runtimePolicyScope: args.runtime.runtimePolicyScope,
          signerSlot: args.runtime.signerSlot,
          routerAbNormalSigning: args.runtime.routerAbNormalSigning,
          credentialIdB64u: args.runtime.factor.credentialIdB64u,
          materialActivation: args.materialActivation,
        }),
        materialActivation: args.materialActivation,
      });
    }
    return claim;
  }

  private async rehydrateNearEd25519YaoCapabilityForSigning(
    subject: NearEd25519CapabilityRehydrationSubject,
  ): Promise<NearEd25519CapabilityRehydrationSubject> {
    const lane = await this.resolveNearEd25519YaoSigningLane(subject);
    if (!lane) {
      throw new Error('[SigningEngine][near] local Ed25519 material lane is unavailable');
    }
    let runtime: ExactEd25519SealedSessionRuntime;
    if (subject.kind === 'export_exact_lane') {
      runtime = await requireExactEd25519SealedRuntimeForMaterialActivation({
        walletId: subject.walletId,
        laneIdentity: subject.laneIdentity,
        materialActivation: subject.materialActivation,
      });
    } else {
      const laneIdentity =
        subject.kind === 'exact_lane'
          ? subject.laneIdentity
          : exactEd25519LaneIdentityFromAvailableLane(lane);
      runtime = await requireExactEd25519SealedRuntimeForLane({
        walletId: subject.walletId,
        laneIdentity,
      });
    }
    const walletSessionState = await walletSessionStateFromExactEd25519Runtime({
      runtime,
      relayerUrl: String(this.seamsWebConfigs.network.relayer?.url || '').trim(),
    });
    if (runtime.factor.kind !== 'passkey') {
      throw new Error('[SigningEngine][near] persisted Ed25519 credential is unavailable');
    }
    const credentialIdB64u = runtime.factor.credentialIdB64u;
    const materialActivation = runtime.sealedRecord.ed25519Restore.materialActivation;
    if (!mpcMaterialActivationRefsEqual(materialActivation, lane.materialActivation)) {
      throw new Error('[SigningEngine][near] persisted Ed25519 material activation mismatch');
    }
    const warmSessionClaim = await this.ensurePasskeyEd25519WarmSessionForSigning({
      runtime,
      walletSessionState,
      materialActivation,
    });
    const publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1 = {
      kind: 'available',
      walletId: String(walletSessionState.signingLane.identity.signer.account.wallet.walletId),
      nearAccountId: String(walletSessionState.signingLane.identity.signer.account.nearAccountId),
      signerSlot: walletSessionState.signingLane.identity.signer.signerSlot,
      materialActivation,
    };
    const liveHydration = await this.resolvePasskeyEd25519YaoHydration({
      walletSessionState,
      credentialIdB64u,
      publicLocator,
      unlockSource: warmSessionClaim.ok
        ? { kind: 'available', passkeyPrfFirstB64u: warmSessionClaim.prfFirstB64u }
        : { kind: 'unavailable' },
    });
    if (liveHydration.kind === 'live') return subject;
    if (liveHydration.kind === 'rehydrated') {
      if (!warmSessionClaim.ok) {
        liveHydration.activeClient.dispose();
        throw new Error('[SigningEngine][near] local material rehydration lost the PRF secret');
      }
      try {
        await persistPasskeyEd25519YaoSessionForRefresh({
          persistence: this,
          session: walletSessionState,
          prfFirstB64u: warmSessionClaim.prfFirstB64u,
          ed25519Restore: buildPasskeyEd25519RestoreMetadata({
            rpId: runtime.factor.rpId,
            nearAccountId: runtime.nearAccountId,
            nearEd25519SigningKeyId: runtime.nearEd25519SigningKeyId,
            relayerKeyId: runtime.relayerKeyId,
            participantIds: runtime.participantIds,
            runtimePolicyScope: runtime.runtimePolicyScope,
            signerSlot: runtime.signerSlot,
            routerAbNormalSigning: runtime.routerAbNormalSigning,
            credentialIdB64u,
            materialActivation,
          }),
          materialActivation,
        });
        await this.enginePorts.ed25519YaoActiveClients.activate({
          activeClient: liveHydration.activeClient,
          facts: nearEd25519YaoOperationMaterialFacts(walletSessionState),
        });
        const reboundSubject = currentNearEd25519CapabilityRehydrationSubject({
          subject,
          walletSessionState,
        });
        const published = await this.resolveActiveNearEd25519YaoSigningLane(reboundSubject);
        if (!published) {
          throw new Error(
            '[SigningEngine][near] local material rehydration did not publish an active lane',
          );
        }
        return reboundSubject;
      } catch (error) {
        liveHydration.activeClient.dispose();
        throw error;
      }
    }
    if (liveHydration.plan.reason !== 'missing_material') {
      throw new Error(
        `[SigningEngine][near] local threshold Ed25519 hydration blocked: ${liveHydration.plan.reason}`,
      );
    }
    throw new Error(
      '[SigningEngine][near] local threshold Ed25519 material requires Passkey reauthorization',
    );
  }

  private async resolvePasskeyEd25519YaoHydration(args: {
    walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
    credentialIdB64u: string;
    publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1;
    unlockSource: PasskeyEd25519YaoUnlockSourceV1;
  }): ReturnType<typeof hydratePasskeyEd25519YaoLocalMaterialV1> {
    const signer = args.walletSessionState.signingLane.identity.signer;
    return hydratePasskeyEd25519YaoLocalMaterialV1({
      store: IndexedDBManager,
      walletSessionState: args.walletSessionState,
      rpId: this.getRpId(),
      credentialIdB64u: args.credentialIdB64u,
      authority: args.walletSessionState.authority,
      publicLocator: args.publicLocator,
      unlockSource: args.unlockSource,
      liveMaterial:
        args.publicLocator.kind === 'available'
          ? this.enginePorts.ed25519YaoActiveClients.resolve({
              walletId: signer.account.wallet.walletId,
              nearAccountId: signer.account.nearAccountId,
              materialActivation: args.publicLocator.materialActivation,
            })
          : null,
    });
  }

  async signEvmFamily(args: {
    walletSession: WalletSessionRef;
    request: TempoSigningRequest | EvmSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult> {
    return await signEvmFamilyOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void> {
    await reportTempoBroadcastAcceptedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void> {
    await reportTempoBroadcastRejectedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoFinalized(args: ReportTempoFinalizedArgs): Promise<void> {
    await reportTempoFinalizedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void> {
    await reportTempoDroppedOrReplacedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reconcileTempoNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus> {
    return await reconcileTempoNonceLaneOperation(this.enginePorts.tempoSigningDeps, args);
  }

  storeUserData(
    userData: Parameters<typeof registrationPublic.storeUserData>[1],
  ): ReturnType<typeof registrationPublic.storeUserData> {
    return registrationPublic.storeUserData(this.registrationPublicDeps, userData);
  }

  async storeNearThresholdKeyMaterial(input: StoreNearThresholdKeyMaterialInput): Promise<void> {
    await storeNearThresholdKeyMaterial(
      {
        clientDB: IndexedDBManager,
        keyMaterialStore: IndexedDBManager,
      },
      input,
    );
  }

  getAllUsers(): ReturnType<typeof registrationPublic.getAllUsers> {
    return registrationPublic.getAllUsers(this.registrationPublicDeps);
  }

  getUserBySignerSlot(
    nearAccountId: Parameters<typeof registrationPublic.getUserBySignerSlot>[1],
    signerSlot: Parameters<typeof registrationPublic.getUserBySignerSlot>[2],
  ): ReturnType<typeof registrationPublic.getUserBySignerSlot> {
    return registrationPublic.getUserBySignerSlot(
      this.registrationPublicDeps,
      nearAccountId,
      signerSlot,
    );
  }

  getLastUser(): ReturnType<typeof registrationPublic.getLastUser> {
    return registrationPublic.getLastUser(this.registrationPublicDeps);
  }

  nearAuthenticatorsByAccount(
    nearAccountId: Parameters<typeof registrationPublic.nearAuthenticatorsByAccount>[1],
  ): ReturnType<typeof registrationPublic.nearAuthenticatorsByAccount> {
    return registrationPublic.nearAuthenticatorsByAccount(
      this.registrationPublicDeps,
      nearAccountId,
    );
  }

  setLastUser(
    walletId: Parameters<typeof registrationPublic.setLastUser>[1],
    signerSlot: Parameters<typeof registrationPublic.setLastUser>[2],
  ): ReturnType<typeof registrationPublic.setLastUser> {
    return registrationPublic.setLastUser(this.registrationPublicDeps, walletId, signerSlot);
  }

  activateAuthenticatedWalletState(
    args: Parameters<typeof registrationPublic.activateAuthenticatedWalletState>[1],
  ): ReturnType<typeof registrationPublic.activateAuthenticatedWalletState> {
    return registrationPublic.activateAuthenticatedWalletState(this.registrationPublicDeps, args);
  }

  async upsertEd25519YaoPublicCapabilityReference(
    identity: Ed25519YaoPublicCapabilityReferenceV1,
  ): Promise<void> {
    await this.ed25519YaoPublicCapabilityReferences.upsert(identity);
  }

  async upsertEd25519YaoPublicCapabilityLaneReference(
    reference: Ed25519YaoPublicCapabilityLaneReferenceV1,
  ): Promise<void> {
    await publishEd25519YaoPublicCapabilityReferenceAndLane(
      this.ed25519YaoPublicCapabilityReferences,
      reference,
    );
  }

  setWalletNearProvisioningState(
    write: Parameters<typeof registrationPublic.setWalletNearProvisioningState>[1],
  ): ReturnType<typeof registrationPublic.setWalletNearProvisioningState> {
    return registrationPublic.setWalletNearProvisioningState(this.registrationPublicDeps, write);
  }

  getWalletNearProvisioningState(
    walletId: Parameters<typeof registrationPublic.getWalletNearProvisioningState>[1],
  ): ReturnType<typeof registrationPublic.getWalletNearProvisioningState> {
    return registrationPublic.getWalletNearProvisioningState(this.registrationPublicDeps, walletId);
  }

  storeAuthenticator(
    authenticatorData: Parameters<typeof registrationPublic.storeAuthenticator>[1],
  ): ReturnType<typeof registrationPublic.storeAuthenticator> {
    return registrationPublic.storeAuthenticator(this.registrationPublicDeps, authenticatorData);
  }

  rollbackUserRegistration(
    nearAccountId: Parameters<typeof registrationPublic.rollbackUserRegistration>[1],
  ): ReturnType<typeof registrationPublic.rollbackUserRegistration> {
    return registrationPublic.rollbackUserRegistration(this.registrationPublicDeps, nearAccountId);
  }

  hasPasskeyCredential(
    nearAccountId: Parameters<typeof registrationPublic.hasPasskeyCredential>[1],
  ): ReturnType<typeof registrationPublic.hasPasskeyCredential> {
    return registrationPublic.hasPasskeyCredential(this.registrationPublicDeps, nearAccountId);
  }

  storeWalletEd25519RegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEd25519RegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEd25519RegistrationData> {
    return registrationPublic.storeWalletEd25519RegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  storeWalletMixedRegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletMixedRegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletMixedRegistrationData> {
    return registrationPublic.storeWalletMixedRegistrationData(this.registrationPublicDeps, input);
  }

  storeWalletEd25519RecoveryRegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEd25519RecoveryRegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEd25519RecoveryRegistrationData> {
    return registrationPublic.storeWalletEd25519RecoveryRegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  storeWalletEmailOtpEd25519RegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEmailOtpEd25519RegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEmailOtpEd25519RegistrationData> {
    return registrationPublic.storeWalletEmailOtpEd25519RegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  storeWalletEmailOtpMixedRegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEmailOtpMixedRegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEmailOtpMixedRegistrationData> {
    return registrationPublic.storeWalletEmailOtpMixedRegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  finalizeWalletEd25519SignerRegistration(
    input: Parameters<typeof registrationPublic.finalizeWalletEd25519SignerRegistration>[1],
  ): ReturnType<typeof registrationPublic.finalizeWalletEd25519SignerRegistration> {
    return registrationPublic.finalizeWalletEd25519SignerRegistration(
      this.registrationPublicDeps,
      input,
    );
  }

  rollbackWalletEd25519SignerRegistration(
    receipt: Parameters<typeof registrationPublic.rollbackWalletEd25519SignerRegistration>[1],
  ): ReturnType<typeof registrationPublic.rollbackWalletEd25519SignerRegistration> {
    return registrationPublic.rollbackWalletEd25519SignerRegistration(
      this.registrationPublicDeps,
      receipt,
    );
  }

  createRouterAbEcdsaRegistrationCeremony(
    input: Parameters<
      typeof this.runtimePorts.signerCrypto.createRouterAbEcdsaRegistrationCeremony
    >[0],
  ): ReturnType<typeof this.runtimePorts.signerCrypto.createRouterAbEcdsaRegistrationCeremony> {
    return this.runtimePorts.signerCrypto.createRouterAbEcdsaRegistrationCeremony(input);
  }

  verifyRouterAbEcdsaRegistrationClientProofs(
    input: Parameters<
      typeof this.runtimePorts.signerCrypto.verifyRouterAbEcdsaRegistrationClientProofs
    >[0],
  ): ReturnType<typeof this.runtimePorts.signerCrypto.verifyRouterAbEcdsaRegistrationClientProofs> {
    return this.runtimePorts.signerCrypto.verifyRouterAbEcdsaRegistrationClientProofs(input);
  }

  persistInitialCanonicalEcdsaActivation(
    input: Parameters<
      typeof this.runtimePorts.signerCrypto.persistInitialCanonicalEcdsaActivation
    >[0],
  ): ReturnType<typeof this.runtimePorts.signerCrypto.persistInitialCanonicalEcdsaActivation> {
    return this.runtimePorts.signerCrypto.persistInitialCanonicalEcdsaActivation(input);
  }

  finalizeRouterAbEcdsaRegistrationActivation(
    input: Parameters<
      typeof this.runtimePorts.signerCrypto.finalizeRouterAbEcdsaRegistrationActivation
    >[0],
  ): ReturnType<typeof this.runtimePorts.signerCrypto.finalizeRouterAbEcdsaRegistrationActivation> {
    return this.runtimePorts.signerCrypto.finalizeRouterAbEcdsaRegistrationActivation(input);
  }

  closeRouterAbEcdsaRegistrationCeremony(
    input: Parameters<
      typeof this.runtimePorts.signerCrypto.closeRouterAbEcdsaRegistrationCeremony
    >[0],
  ): ReturnType<typeof this.runtimePorts.signerCrypto.closeRouterAbEcdsaRegistrationCeremony> {
    return this.runtimePorts.signerCrypto.closeRouterAbEcdsaRegistrationCeremony(input);
  }

  finalizeWalletRegistrationEcdsaSessions(
    input: Parameters<typeof finalizeWalletRegistrationEcdsaSessionsOperation>[0],
  ): ReturnType<typeof finalizeWalletRegistrationEcdsaSessionsOperation> {
    return finalizeWalletRegistrationEcdsaSessionsOperation(input);
  }

  storeWalletEcdsaSignerRecords(
    input: Parameters<typeof registrationPublic.storeWalletEcdsaSignerRecords>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEcdsaSignerRecords> {
    return registrationPublic.storeWalletEcdsaSignerRecords(this.registrationPublicDeps, input);
  }

  storeWalletEcdsaRecoverySignerRecords(
    input: Parameters<typeof registrationPublic.storeWalletEcdsaRecoverySignerRecords>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEcdsaRecoverySignerRecords> {
    return registrationPublic.storeWalletEcdsaRecoverySignerRecords(
      this.registrationPublicDeps,
      input,
    );
  }

  storeWalletEmailOtpEcdsaSignerRecords(
    input: Parameters<typeof registrationPublic.storeWalletEmailOtpEcdsaSignerRecords>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEmailOtpEcdsaSignerRecords> {
    return registrationPublic.storeWalletEmailOtpEcdsaSignerRecords(
      this.registrationPublicDeps,
      input,
    );
  }

  finalizeWalletEcdsaRegistration(
    input: Parameters<typeof registrationPublic.finalizeWalletEcdsaRegistration>[1],
  ): ReturnType<typeof registrationPublic.finalizeWalletEcdsaRegistration> {
    return registrationPublic.finalizeWalletEcdsaRegistration(this.registrationPublicDeps, input);
  }

  async activateVerifiedNearEd25519YaoMaterial(
    material: NearEd25519YaoOperationMaterial,
  ): Promise<Ed25519YaoActiveClientIdentityV1> {
    return await this.enginePorts.ed25519YaoActiveClients.activate(material);
  }

  async withExactEd25519MaterialOwner<T>(args: {
    materialActivation: MpcMaterialActivationRef;
    nearAccountId: AccountId;
    task: () => Promise<T>;
  }): Promise<T> {
    return await withThresholdEd25519CommitQueue({
      queueByKey: this.thresholdEd25519CommitQueueByKey,
      queueKey: resolveThresholdEd25519CommitQueueKey({
        materialActivation: args.materialActivation,
      }),
      nearAccountId: args.nearAccountId,
      enabled: true,
      task: args.task,
    });
  }

  storeWalletEmailOtpEcdsaRegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEmailOtpEcdsaRegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEmailOtpEcdsaRegistrationData> {
    return registrationPublic.storeWalletEmailOtpEcdsaRegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  requestWorkerOperation = <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>> =>
    this.signerWorkerManager.getContext().requestWorkerOperation(args);

  hydrateSigningSession(
    input: Parameters<typeof warmCapabilitiesPublic.hydrateSigningSession>[1],
  ): ReturnType<typeof warmCapabilitiesPublic.hydrateSigningSession> {
    return warmCapabilitiesPublic.hydrateSigningSession(this.warmCapabilitiesPublicDeps, input);
  }

  persistSigningSessionSealForThresholdSession(
    input: Parameters<PasskeyMpcSessionPort['persistSigningSessionSealForThresholdSession']>[0],
  ): ReturnType<PasskeyMpcSessionPort['persistSigningSessionSealForThresholdSession']> {
    return this.passkeyMpcSession.persistSigningSessionSealForThresholdSession(input);
  }

  /**
   * Collects the one-time email code inside the wallet.
   *
   * Built on the same confirmation channel key export uses, so the code is
   * typed into the wallet's own surface and never passes through the host
   * application — the reason `addEmailOtp` takes an address and not a code.
   */
  async requestEmailOtpEnrollmentConfirmation(params: {
    walletId: string;
    emailAddress: string;
    challengeId: string;
    emailHint?: string;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    onResend: () => Promise<{ challengeId: string; emailHint?: string }>;
  }): Promise<{ challengeId: string; otpCode: string }> {
    let currentChallengeId = params.challengeId;
    const emailOtpPrompt = {
      challengeId: params.challengeId,
      ...(params.emailHint ? { emailHint: params.emailHint } : {}),
      title: params.confirmerText?.title || 'Enter email code to add sign-in',
      body:
        params.confirmerText?.body ||
        `This one-time code confirms ${params.emailAddress} can unlock this wallet.`,
      helperText: 'Enter the 6-digit code sent to your email',
      onResend: async () => {
        const resent = await params.onResend();
        currentChallengeId = resent.challengeId;
        return {
          challengeId: resent.challengeId,
          ...(resent.emailHint ? { emailHint: resent.emailHint } : {}),
          delivery: { mode: 'email_provider' as const },
        };
      },
    };
    const decision = await this.touchConfirm.requestUserConfirmation({
      requestId: secureRandomId('add-auth-method-email-otp', 32, 'Email OTP enrollment UI ids'),
      type: UserConfirmationType.SIGN_INTENT_DIGEST,
      summary: {
        type: 'add_auth_method',
        operation: 'Add email code sign-in',
        title: emailOtpPrompt.title,
        body: emailOtpPrompt.body,
        warning:
          'Security note: Adding email code lowers this wallet\u2019s security because your inbox becomes another way to unlock it.',
      },
      payload: {
        signingSubject: { kind: 'evm_wallet', walletId: params.walletId },
        challengeB64u: params.challengeId,
        signingAuthPlan: {
          kind: SigningAuthPlanKind.EmailOtpReauth,
          method: 'email_otp',
          emailOtpPrompt,
        },
        emailOtpPrompt,
      },
      intentDigest: `add-auth-method:${params.walletId}:email-otp`,
      ...(params.confirmationConfigOverride
        ? { confirmationConfigOverride: params.confirmationConfigOverride }
        : {}),
    });
    if (!decision.confirmed) {
      throw new Error(decision.error || 'Adding an email code was cancelled');
    }
    const otpCode = String(decision.otpCode || '')
      .replace(/\D/g, '')
      .slice(0, 6);
    if (otpCode.length !== 6) {
      throw new Error('Adding an email code requires a 6-digit code');
    }
    return {
      challengeId: String(decision.emailOtpChallengeId || currentChallengeId).trim(),
      otpCode,
    };
  }

  requestRegistrationCredentialConfirmation(params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
    registrationOptions?: WalletAddAuthMethodRegistrationOptions;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return registrationPublic.requestRegistrationCredentialConfirmation(
      this.registrationPublicDeps,
      params,
    );
  }

  openRegistrationPreparationModal(params: {
    walletLabel: string;
    signerSlot: number;
  }): Promise<void> {
    return this.touchConfirm.openRegistrationPreparationModal(params);
  }

  closeRegistrationPreparationModal(): void {
    this.touchConfirm.closeRegistrationPreparationModal();
  }

  startPreparedPasskeyRegistrationCredential(args: {
    walletId: string;
    signerSlot: number;
    challengeB64u: string;
    expectedRpId: string;
    reservation: ReservedRegistrationWebAuthnPrompt;
    owner: RegistrationWebAuthnPromptOwner;
    cancellation: { kind: 'abort_signal'; signal: AbortSignal };
  }): Promise<WebAuthnRegistrationCredential> {
    const runtimeRpId = this.touchIdPrompt.getRpId();
    if (runtimeRpId !== args.expectedRpId) {
      throw new Error('Prepared registration rpId does not match the wallet runtime');
    }
    const credential = this.touchIdPrompt.generateRegistrationCredentialsInternal({
      kind: 'wallet_registration',
      walletId: args.walletId,
      challengeB64u: args.challengeB64u,
      signerSlot: args.signerSlot,
      intendedUserName: args.walletId,
      prompt: {
        kind: 'reserved',
        reservation: args.reservation,
        owner: args.owner,
        cancellation: args.cancellation,
      },
    });
    return credential.then(serializePreparedRegistrationCredential);
  }

  getAuthenticationCredentialsSerialized(args: {
    subjectId: string;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
    cancellation?: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>;
  }): Promise<WebAuthnAuthenticationCredential> {
    if (args.cancellation) {
      return this.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u(args);
    }
    return registrationPublic.getAuthenticationCredentialsSerialized(
      this.registrationPublicDeps,
      args,
    );
  }

  async exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await recoveryPublic.exportKeypairWithUI(this.recoveryPublicDeps, input);
  }

  async resolveExactKeyExportLane(
    input: SigningEngineResolveExactKeyExportLaneInput,
  ): Promise<SigningEngineResolveExactKeyExportLaneResult> {
    return await recoveryPublic.resolveExactKeyExportLane(this.recoveryPublicDeps, input);
  }

  async connectEd25519Session(
    args: ConnectEd25519SessionArgs,
  ): Promise<ProvisionWarmEd25519CapabilityResult> {
    return await passkeyPublic.connectEd25519Session(this.passkeyPublicDeps, args);
  }

  async bootstrapEcdsaSession(
    args: EcdsaBootstrapRequest,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    return await passkeyPublic.bootstrapEcdsaSession(this.passkeyPublicDeps, args);
  }

  async loginWithEmailOtpEcdsaCapabilityInternal(
    args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult> {
    return await emailOtpPublic.loginWithEmailOtpEcdsaCapabilityInternal(
      this.emailOtpPublicDeps,
      args,
    );
  }

  async resolveEmailOtpEd25519CustodyProjectionInternal(args: {
    walletSession: WalletSessionRef;
    providerSubjectId: string;
    selector:
      | { kind: 'selected_wallet_authority' }
      | { kind: 'wallet_auth_method'; walletAuthMethodId: string }
      | { kind: 'material_activation'; materialActivation: MpcMaterialActivationRef };
  }): Promise<WalletCustodyEd25519Projection | null> {
    const walletId = String(args.walletSession.walletId);
    let activation: MpcMaterialActivationRef | undefined;
    switch (args.selector.kind) {
      case 'material_activation':
        activation = args.selector.materialActivation;
        break;
      case 'wallet_auth_method': {
        const selected = await IndexedDBManager.resolveWalletAuthorityForMethod(
          walletId,
          args.selector.walletAuthMethodId,
        );
        activation =
          selected.kind === 'resolved' && selected.authority.state === 'active'
            ? selected.authority.signerActivations.ed25519?.materialActivation
            : undefined;
        break;
      }
      case 'selected_wallet_authority': {
        const selected = await IndexedDBManager.resolveSelectedWalletAuthority(walletId);
        activation =
          selected.kind === 'resolved' && selected.authority.state === 'active'
            ? selected.authority.signerActivations.ed25519?.materialActivation
            : undefined;
        break;
      }
      default:
        args.selector satisfies never;
    }
    /* No Ed25519 activation on this authority is an answer, not a failure: an
       ECDSA-only wallet has no Ed25519 signer to project. */
    if (!activation) return null;
    return await resolveWalletCustodyEd25519ProjectionV1(
      {
        listPublicCapabilityReferences: this.ed25519YaoPublicCapabilityReferences.list.bind(
          this.ed25519YaoPublicCapabilityReferences,
        ),
        listUsers: this.getAllUsers.bind(this),
      },
      args.walletSession,
      args.providerSubjectId,
      activation,
    );
  }

  /**
   * R109C: what an owner authority needs to have its Ed25519 runtime built
   * inside the unlock that verifies its factor.
   *
   * Assembled here rather than by the caller because every field is read off
   * the exact authority projection - the identity, its runtime policy scope,
   * and the custody material cached against that signer. A caller assembling
   * them independently could pair one authority's identity with another's
   * material.
   */
  async resolveOwnerAuthorityEd25519UnlockRequestInternal(args: {
    walletSession: WalletSessionRef;
    providerSubjectId: string;
    walletAuthMethodId: string;
    remainingUses: number;
  }): Promise<EmailOtpAuthorityUnlockEd25519Request | null> {
    const projection = await this.resolveEmailOtpEd25519CustodyProjectionInternal({
      walletSession: args.walletSession,
      providerSubjectId: args.providerSubjectId,
      selector: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: args.walletAuthMethodId,
      },
    });
    if (!projection) return null;
    const signerSlot = projection.user.signerSlot;
    return {
      kind: 'owner_authority',
      signerSlot,
      remainingUses: args.remainingUses,
      recovery: {
        ed25519YaoRecovery: {
          kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
          signerSlot,
          remainingUses: args.remainingUses,
          orgId: projection.identity.runtimePolicyScope.orgId,
        },
        providerSubject: projection.providerSubject,
        nearAccountId: String(projection.identity.nearAccountId),
        expectedOperationalPublicKey: projection.user.operationalPublicKey,
        expectedThresholdSessionId: String(projection.identity.thresholdSessionId),
        walletCustodyEd25519Material: await this.loadEmailOtpWalletCustodyEd25519Material({
          nearAccountId: String(projection.identity.nearAccountId),
          signerSlot,
        }),
      },
    };
  }

  /**
   * R109C: activate the runtime an owner authority's unlock built.
   *
   * The identity it is checked against comes from the same authority projection
   * that produced the unlock request, not from the bootstrap being checked -
   * comparing a value against itself proves nothing, and the projection is what
   * says which signer this authority owns.
   */
  async activateOwnerAuthorityEd25519RuntimeInternal(args: {
    walletSession: WalletSessionRef;
    providerSubjectId: string;
    walletAuthMethodId: string;
    emailHashHex: string;
    activeClientHandle: string;
    metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    /** Built by the caller from the authority it verified this unlock against. */
    authority: WalletAuthAuthorityRef;
  }): Promise<void> {
    const projection = await this.resolveEmailOtpEd25519CustodyProjectionInternal({
      walletSession: args.walletSession,
      providerSubjectId: args.providerSubjectId,
      selector: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: args.walletAuthMethodId,
      },
    });
    if (!projection) {
      throw new Error('Owner Email OTP Ed25519 activation has no signer projection');
    }
    await this.activateEmailOtpEd25519CustodyCapabilityInternal({
      walletSession: args.walletSession,
      providerSubject: projection.providerSubject,
      emailHashHex: args.emailHashHex,
      signerSlot: projection.user.signerSlot,
      expectedOperationalPublicKey: projection.user.operationalPublicKey,
      expectedThresholdSessionId: String(projection.identity.thresholdSessionId),
      bootstrap: args.bootstrap,
      activeClientHandle: args.activeClientHandle,
      metadata: args.metadata,
      authority: args.authority,
      /* This unlock owns the commit queue for its own activation. */
      commitQueue: 'acquire',
    });
  }

  async activateEmailOtpEd25519RegistrationMaterialInternal(args: {
    walletSession: WalletSessionRef;
    providerSubject: string;
    emailHashHex: string;
    signerSlot: number;
    expectedOperationalPublicKey: string;
    expectedThresholdSessionId: string;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    material: LoadedWalletCustodyEd25519MaterialV1;
    envelope: WalletCustodyCacheEnvelopeV1;
    factorSecret32: ArrayBuffer;
  }): Promise<NearEd25519SignerBinding> {
    const activated = await this.signerWorkerManager.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'activateEmailOtpEd25519YaoRegistrationMaterial',
        payload: {
          material: args.material,
          bootstrap: args.bootstrap,
          envelope: args.envelope,
          factorSecret32: args.factorSecret32,
        },
        transfer: [args.factorSecret32],
      },
    });
    try {
      return await this.activateEmailOtpEd25519CustodyCapabilityInternal({
        commitQueue: 'acquire',
        walletSession: args.walletSession,
        providerSubject: args.providerSubject,
        emailHashHex: args.emailHashHex,
        signerSlot: args.signerSlot,
        expectedOperationalPublicKey: args.expectedOperationalPublicKey,
        expectedThresholdSessionId: args.expectedThresholdSessionId,
        bootstrap: args.bootstrap,
        activeClientHandle: activated.activeClientHandle,
        metadata: activated.metadata,
      });
    } catch (error) {
      try {
        await this.enginePorts.ed25519YaoActiveClients.rollbackActivation({
          walletId: args.walletSession.walletId,
          nearAccountId: toAccountId(args.bootstrap.session.nearAccountId),
          materialActivation: activated.metadata.materialActivation,
        });
      } catch {}
      try {
        await requestClearEmailOtpWarmSessionMaterial({
          worker: this.signerWorkerManager.getContext(),
          target: {
            kind: 'ed25519_yao',
            thresholdSessionId: args.bootstrap.session.thresholdSessionId,
            materialActivation: activated.metadata.materialActivation,
          },
        });
      } catch {}
      try {
        await disposeWalletCustodyEd25519ActiveClientV1({
          workerContext: this.signerWorkerManager.getContext(),
          activeClientHandle: activated.activeClientHandle,
        });
      } catch {}
      throw error;
    }
  }

  async activateEmailOtpEd25519CustodyCapabilityInternal(
    args: EmailOtpEd25519CustodyCapabilityActivationArgs,
  ): Promise<NearEd25519SignerBinding> {
    return await this.activateEmailOtpEd25519CustodyCapabilityWithExactCredential({
      ...args,
      credentialExpectation: { kind: 'resolve_exact_operation_credential' },
    });
  }

  private async activateEmailOtpEd25519CustodyCapabilityWithExactCredential(
    args: EmailOtpEd25519CustodyCapabilityActivationArgs & {
      readonly credentialExpectation: EmailOtpEd25519CredentialExpectation;
    },
  ): Promise<NearEd25519SignerBinding> {
    const exactAuthorization = await resolveExactEmailOtpEd25519ActivationAuthorization({
      walletId: args.walletSession.walletId,
      emailHashHex: args.emailHashHex,
      providerSubject: args.providerSubject,
      bootstrap: args.bootstrap,
      ...(args.authority ? { verifiedAuthority: args.authority } : {}),
    });
    if (
      args.credentialExpectation.kind === 'expect_exact_operation_credential' &&
      (args.credentialExpectation.operationCredential.walletSessionId !==
        exactAuthorization.operationCredential.walletSessionId ||
        args.credentialExpectation.operationCredential.token !==
          exactAuthorization.operationCredential.token)
    ) {
      throw new Error('[SigningEngine][near] expected Email OTP operation credential changed');
    }
    return await withThresholdEd25519CommitQueue({
      queueByKey: this.thresholdEd25519CommitQueueByKey,
      queueKey: resolveThresholdEd25519CommitQueueKey({
        materialActivation: args.metadata.materialActivation,
      }),
      nearAccountId: toAccountId(args.bootstrap.session.nearAccountId),
      enabled: args.commitQueue === 'acquire',
      task: async () => {
        const activated = await activateWalletCustodyEd25519CapabilityV1({
          walletSession: args.walletSession,
          nearAccountId: args.bootstrap.session.nearAccountId,
          providerSubject: args.providerSubject,
          relayerUrl: this.seamsWebConfigs.network.relayer?.url || '',
          authority: exactAuthorization.authority,
          signerSlot: args.signerSlot,
          expectedOperationalPublicKey: args.expectedOperationalPublicKey,
          expectedThresholdSessionId: args.expectedThresholdSessionId,
          bootstrap: args.bootstrap,
          operationCredential: exactAuthorization.operationCredential,
          activeClientHandle: args.activeClientHandle,
          metadata: args.metadata,
          workerContext: this.signerWorkerManager.getContext(),
          activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
            this.enginePorts.ed25519YaoActiveClients,
          ),
        });
        const state = activated.walletSessionState;
        await this.upsertEd25519YaoPublicCapabilityLaneReference(
          emailOtpEd25519YaoLaneReferenceFromRecovery({
            walletSessionState: state,
            materialActivation: activated.material.activeClient.metadata().materialActivation,
          }),
        );
        const current = this.enginePorts.ed25519YaoActiveClients.resolve({
          walletId: state.signingLane.identity.signer.account.wallet.walletId,
          nearAccountId: state.signingLane.identity.signer.account.nearAccountId,
          materialActivation: activated.material.activeClient.metadata().materialActivation,
        });
        if (!current) {
          throw new Error('[SigningEngine][near] wallet custody activation was superseded');
        }
        return state.signingLane.identity.signer;
      },
    });
  }

  async loginWithEmailOtpWalletCustodyEd25519Internal(
    args: LoginWithEmailOtpWalletCustodyEd25519Args,
  ): Promise<NearEd25519SignerBinding> {
    if (args.authoritySelector.kind !== 'wallet_auth_method') {
      throw new Error('Email OTP Ed25519 unlock requires an exact wallet auth method');
    }
    const walletAuthMethodId = args.authoritySelector.walletAuthMethodId;
    const selection = args.ed25519Selection;
    /* This is a cold unlock: the OTP verification below is the factor proof
       and the route plan authenticates with it, so no prior Wallet Session
       may be required here. */
    const unlock = await unlockEmailOtpEd25519YaoCapability({
      walletSession: args.walletSession,
      authoritySelector: args.authoritySelector,
      relayUrl: this.seamsWebConfigs.network.relayer?.url || '',
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      verification: { kind: 'otp', challengeId: args.challengeId, otpCode: args.otpCode },
      routePlan: buildFreshEmailOtpRoutePlan({
        freshRouteFamily: 'login',
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      }),
      workerCtx: this.signerWorkerManager.getContext(),
      providerSubject: args.providerSubjectId,
      signerSlot: selection.signerSlot,
      remainingUses: args.remainingUses,
      orgId: selection.runtimePolicyScope.orgId,
      nearAccountId: selection.nearAccountId,
      expectedOperationalPublicKey: selection.operationalPublicKey,
      expectedThresholdSessionId: selection.thresholdSessionId,
      walletCustodyEd25519Material: await this.loadEmailOtpWalletCustodyEd25519Material({
        nearAccountId: selection.nearAccountId,
        signerSlot: selection.signerSlot,
      }),
    });
    if (unlock.kind === 'wallet_custody_cache_absent') {
      throw new Error(
        'Email OTP wallet custody material is unavailable; recover with a recovery code',
      );
    }
    try {
      await persistVerifiedEmailOtpAuthorityAfterUnlock({
        walletId: String(args.walletSession.walletId),
        walletAuthMethodId,
        projection: unlock.recovery.verifiedAuthorityProjection,
      });
      const authority = await walletAuthAuthorityRefForVerifiedEmailOtpUnlock({
        walletId: String(args.walletSession.walletId),
        walletAuthMethodId,
        providerSubject: args.providerSubjectId,
        emailHashHex: args.emailHashHex,
        projection: unlock.recovery.verifiedAuthorityProjection,
      });
      if (unlock.walletCustodyEd25519Material) {
        await this.persistWalletCustodyEd25519Material(unlock.walletCustodyEd25519Material);
      }
      const signer = await this.activateEmailOtpEd25519CustodyCapabilityInternal({
        commitQueue: 'acquire',
        walletSession: args.walletSession,
        providerSubject: args.providerSubjectId,
        emailHashHex: args.emailHashHex,
        signerSlot: selection.signerSlot,
        expectedOperationalPublicKey: selection.operationalPublicKey,
        expectedThresholdSessionId: selection.thresholdSessionId,
        bootstrap: unlock.ed25519YaoCapability,
        activeClientHandle: unlock.activeClientHandle,
        metadata: unlock.metadata,
        authority,
      });
      const exactSession = exactWalletSessionWithOperationCredentialOrThrow(
        await walletSessionAuthorizations.readExactWithOperationCredential({
          walletId: args.walletSession.walletId,
          authorityId: unlock.recovery.verifiedAuthorityProjection.authority.authorityId,
          authMethodId: unlock.recovery.verifiedAuthorityProjection.authMethod.walletAuthMethodId,
        }),
        '[SigningEngine][ed25519] exact Wallet Session requires a newer client',
      );
      if (exactSession) {
        await establishUnlockedExportRootCapabilityWithWorkerV1(
          this.walletCustodyCeremonyTransportV1(),
          {
            existingEnvelope: unlock.ed25519ExportRootCustody.existingEnvelope,
            existingFactorSecret: unlock.ed25519ExportRootCustody.factorSecret32,
            walletId: String(args.walletSession.walletId),
            walletAuthMethodId: String(exactSession.record.authMethodId),
            walletSessionId: String(exactSession.operationCredential.walletSessionId),
            expiresAtMs: exactSession.record.expiresAtMs,
          },
        );
      }
      return signer;
    } catch (error) {
      await disposeWalletCustodyEd25519ActiveClientV1({
        workerContext: this.signerWorkerManager.getContext(),
        activeClientHandle: unlock.activeClientHandle,
      }).catch(() => undefined);
      throw error;
    } finally {
      unlock.ed25519ExportRootCustody.factorSecret32.fill(0);
    }
  }

  async requestEmailOtpSigningSessionChallenge(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    return await emailOtpPublic.requestEmailOtpSigningSessionChallenge(
      this.emailOtpPublicDeps,
      args,
    );
  }

  async refreshEmailOtpSigningSession(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
  }): Promise<{
    recovery: EmailOtpBootstrapRecovery;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    authorization: ExactWalletSessionAuthorization;
    authorizations: readonly [
      ExactWalletSessionAuthorization,
      ...ExactWalletSessionAuthorization[],
    ];
  }> {
    return await emailOtpPublic.refreshEmailOtpSigningSession(this.emailOtpPublicDeps, args);
  }

  async enrollEmailOtpInternal(args: {
    walletId: WalletId;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    groupId?: string;
    clientSecret32?: Uint8Array;
    otpChannel?: WalletEmailOtpChannel;
  }): Promise<Awaited<ReturnType<typeof emailOtpPublic.enrollEmailOtpInternal>>> {
    return await emailOtpPublic.enrollEmailOtpInternal(this.emailOtpPublicDeps, args);
  }

  async prepareEmailOtpRegistrationEnrollmentMaterialInternal(
    args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  ): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult> {
    return await emailOtpPublic.prepareEmailOtpRegistrationEnrollmentMaterialInternal(
      this.emailOtpPublicDeps,
      args,
    );
  }

  async getWarmThresholdEd25519SessionStatus(args: {
    walletId: WalletId | string;
    nearAccountId: AccountId | string;
    nearEd25519SigningKeyId: string;
  }): Promise<SigningSessionStatus | null> {
    const walletId = toWalletId(args.walletId);
    const nearAccountId = toAccountId(args.nearAccountId);
    const resolution = await resolveExactEd25519SealedSessionRuntimeForWalletSubject({
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(args.nearEd25519SigningKeyId),
    });
    if (resolution.kind === 'missing') return null;
    if (resolution.kind !== 'resolved') {
      throw new Error(`[WarmSessionStore] Ed25519 sealed runtime is ${resolution.kind}`);
    }
    const authorization = await this.resolveActiveNearEd25519WalletSessionAuthorization(walletId);
    return await warmCapabilitiesPublic.getWarmThresholdEd25519SessionStatus(
      this.warmCapabilitiesPublicDeps,
      {
        runtime: resolution.runtime,
        authorization,
        nowMs: Date.now(),
      },
    );
  }

  async scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    manifest: ActiveEcdsaCapabilityManifest;
    runtime: ExactEcdsaSealedRuntime;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult> {
    return await warmCapabilitiesPublic.scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(
      this.warmCapabilitiesPublicDeps,
      args,
    );
  }

  async clearVolatileWarmSigningMaterial(walletId?: WalletId): Promise<void> {
    const cleanup = this.clearVolatileWarmSigningMaterialInternal(walletId);
    this.volatileWarmSigningMaterialCleanupInFlight = cleanup;
    try {
      await cleanup;
    } finally {
      if (this.volatileWarmSigningMaterialCleanupInFlight === cleanup) {
        this.volatileWarmSigningMaterialCleanupInFlight = null;
      }
    }
  }

  private async clearVolatileWarmSigningMaterialInternal(walletId?: WalletId): Promise<void> {
    try {
      if (walletId) {
        this.enginePorts.ed25519YaoActiveClients.disposeWallet(walletId);
      } else {
        this.enginePorts.ed25519YaoActiveClients.dispose();
      }
    } finally {
      try {
        await warmCapabilitiesPublic.clearVolatileWarmSigningMaterial(
          this.warmCapabilitiesPublicDeps,
          walletId,
        );
      } finally {
        if (walletId === undefined) {
          await this.clearLinkedEcdsaHolderMaterials();
        } else {
          await this.clearLinkedEcdsaHolderMaterialsForWallet(walletId);
        }
      }
    }
  }

  onSdkLifecycleEvent(listener: SdkLifecycleEventListener): () => void {
    this.sdkLifecycleEventListeners.add(listener);
    return this.removeSdkLifecycleEventListener.bind(this, listener);
  }

  publishSdkLifecycleEvent(event: SdkLifecycleEvent): void {
    const deliveryKey = sdkLifecycleEventDeliveryKey(event);
    if (this.deliveredSdkLifecycleEventKeys.has(deliveryKey)) return;
    this.deliveredSdkLifecycleEventKeys.add(deliveryKey);
    for (const listener of Array.from(this.sdkLifecycleEventListeners)) {
      listener(event);
    }
  }

  private publishNearProvisioningLifecycleEvent(
    walletId: Parameters<NearProvisioningListener>[0],
    state: Parameters<NearProvisioningListener>[1],
  ): void {
    this.publishSdkLifecycleEvent(createNearProvisioningStateChangedEvent({ walletId, state }));
  }

  private removeSdkLifecycleEventListener(listener: SdkLifecycleEventListener): void {
    this.sdkLifecycleEventListeners.delete(listener);
  }

  dispose(): void {
    this.signingSessionLifecycleSubscription.unsubscribe();
    this.nearProvisioningUnsubscribe();
    this.sdkLifecycleEventListeners.clear();
    this.deliveredSdkLifecycleEventKeys.clear();
    this.ed25519YaoPageLifecycleOwner.dispose();
  }

  clearThresholdEcdsaSigningQueue(): void {
    clearThresholdEcdsaSigningQueue(this.thresholdEcdsaSigningQueueByKey);
  }

  async clearLinkedEcdsaHolderMaterials(): Promise<void> {
    await clearLinkedDeviceEcdsaHolderMaterialsWasm({
      workerCtx: this.signerWorkerManager.getContext(),
    });
    clearLinkedEcdsaHolderRuntimesV1();
  }

  private async clearLinkedEcdsaHolderMaterialsForWallet(walletId: WalletId): Promise<void> {
    const runtimes = listLinkedEcdsaHolderRuntimesV1(walletId);
    let firstError: unknown;
    for (const runtime of runtimes) {
      try {
        await destroyLinkedDeviceEcdsaHolderMaterialsWasm({
          holderHandleIds: [runtime.holderHandleId],
          workerCtx: this.signerWorkerManager.getContext(),
        });
        removeLinkedEcdsaHolderRuntimeV1(runtime);
      } catch (error: unknown) {
        firstError ??= error;
      }
    }
    if (firstError !== undefined) throw firstError;
  }
}
