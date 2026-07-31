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
  ReusableWalletSessionState,
  SigningSessionStatus,
  SeamsConfigsReadonly,
} from '@/core/types/seams';
import { WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import { type WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { ThresholdEcdsaCanonicalExportArtifact } from '@/core/signingEngine/interfaces/signing';
import type {
  NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
  NearEd25519YaoPreparedMaterialBoundary,
  NearEd25519YaoOperationMaterial,
  NearEd25519YaoSigningCapability,
  NearPasskeyEd25519OperationStepUpCapabilityPreparation,
} from '@/core/signingEngine/interfaces/near';
import type { NearSigningApiDeps } from '@/core/signingEngine/interfaces/operationDeps';
import type { Ed25519YaoActiveClientIdentityV1 } from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import { Ed25519YaoPageLifecycleOwner } from '@/core/signingEngine/threshold/ed25519/yaoPageLifecycleOwner';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { SigningRuntime } from '@/core/runtime/runtime.types';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
  EmailOtpYaoPrewarmRequest,
  EmailOtpYaoPrewarmOutcome,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
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
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import {
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
  type AvailableEd25519SigningLane,
  type ConcreteAvailableEd25519SigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  resolvePasskeyEd25519YaoExportContextV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import { readPersistedEd25519SessionRecordForSigning } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import {
  nearEd25519YaoOperationMaterialFacts,
  resolveRouterAbEd25519WalletSessionStateFromCurrentRecord,
  resolveRouterAbEd25519WalletSessionStateFromRecord,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  hydratePasskeyEd25519YaoLocalMaterialV1,
  preparePasskeyEd25519YaoLocalMaterialRehydrationV1,
  type PasskeyEd25519YaoPublicLocatorObservationV1,
  type PasskeyEd25519YaoUnlockSourceV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import {
  buildActiveNearEd25519WalletSessionAuthorization,
  buildAuthorizationRequiredNearEd25519YaoSigningPreparation,
  buildAuthorizedNearEd25519YaoSigningPreparation,
  type NearEd25519YaoSigningPreparation,
} from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import type { MpcCapabilityHydrationPlan } from '@/core/signingEngine/session/material/mpcCapabilityHydration';
import {
  nearEd25519YaoMaterialActivationFromMetadata,
  nearEd25519YaoRuntimeRef,
  type NearEd25519YaoRuntimeObservationV1,
} from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import {
  mpcMaterialActivationRefsEqual,
  parseAppSessionJwt,
  parseWalletId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { retireWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  createRelayerReusableWalletSessionStatusPort,
  type ReusableWalletSessionStatusAuth,
} from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '@/core/signingEngine/threshold/ed25519/walletSession';
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
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import * as emailOtpPublic from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import { createManagerAssembly } from '@/core/signingEngine/assembly/createManagers';
import { verifySealedRefreshStartupParity } from '@/core/rpcClients/relayer/sealedRefreshCapabilities';
import { isRetryableSealedRefreshCapabilityFetchError } from '@/core/signingEngine/session/warmCapabilities/sealedRefreshParity';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { ProvisionWarmEd25519CapabilityResult } from '@/core/signingEngine/session/warmCapabilities/types';
import {
  resolveEmailOtpEd25519YaoColdRecoveryV1,
  type LoginWithEmailOtpEd25519YaoCapabilityInternalArgs,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoLogin';
import {
  activateColdEmailOtpEd25519YaoUnlockedRecoveryV1,
  activateColdEmailOtpEd25519YaoLocalSessionV1,
  prepareColdEmailOtpEd25519YaoRecoveryV1,
  recoverColdEmailOtpEd25519CapabilityForLoginV1,
  type PreparedColdEmailOtpEd25519YaoRecoveryV1,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoBudgetRecovery';
import type {
  EmailOtpEd25519YaoExactLocalSessionBootstrapV1,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type { EmailOtpEd25519YaoPendingFactorHandle } from '@/core/signingEngine/session/emailOtp/ed25519YaoRootVault';
import { readExactSealedSession } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  recoverEmailOtpEd25519YaoFromSealedSessionV1,
  resolveEmailOtpEd25519YaoHydrationPlanForSigningV1,
  resolveEmailOtpEd25519YaoExportContextV1,
  type EmailOtpEd25519YaoExportContextV1,
  type EmailOtpEd25519YaoExportSubjectV1,
  type EmailOtpEd25519YaoSilentRecoveryResultV1,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoSealedRecovery';
import { rehydrateEmailOtpEd25519YaoOperationMaterialV1 } from '@/core/signingEngine/session/emailOtp/ed25519YaoWorkerClient';
import type { EmailOtpAppSessionBinding } from '@/core/signingEngine/session/emailOtp/appSessionJwtCache';
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
import {
  createBrowserActiveEcdsaWalletSessionAuthorizationResolver,
  createBrowserSigningSurfaceEnginePorts,
  listBrowserActiveEcdsaCapabilityManifestsForWallet,
  listBrowserEcdsaSigningCapabilitiesForWallet,
  type BrowserSigningSurfaceEnginePorts,
} from '../assembly/browserSigningSurfaceAssembly';
import type { BrowserSigningSurfaceConstructorDeps } from '../assembly/browserSigningSurfacePorts';
import type { SigningSessionLifecycleSubscription } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { finalizeWalletRegistrationEcdsaSessions as finalizeWalletRegistrationEcdsaSessionsOperation } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type {
  WorkerResourceWarmupAccountContext,
  WorkerResourceWarmupDiagnostics,
} from '@/core/signingEngine/assembly/warmup';
import { serializeRegistrationCredentialWithPRF } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type {
  RegistrationWebAuthnPromptOwner,
  ReservedRegistrationWebAuthnPrompt,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';

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
      readonly thresholdSessionId: string;
      readonly laneIdentity: ExactEd25519SigningLaneIdentity;
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
  return subject.kind === 'account_signer'
    ? true
    : String(lane.thresholdSessionId) === subject.thresholdSessionId;
}

function nearEd25519CapabilityRehydrationKey(
  subject: NearEd25519CapabilityRehydrationSubject,
): string {
  return JSON.stringify([
    String(subject.walletId),
    String(subject.nearAccountId),
    subject.signerSlot,
    subject.kind === 'exact_lane' ? subject.thresholdSessionId : null,
  ]);
}

function nearEd25519PublicLocatorObservation(args: {
  references: readonly Ed25519YaoActiveClientIdentityV1[];
  walletId: WalletId;
  nearAccountId: AccountId;
  signerSlot: number;
}): PasskeyEd25519YaoPublicLocatorObservationV1 {
  const matches = args.references.filter(
    (reference) =>
      String(reference.walletId) === String(args.walletId) &&
      String(reference.nearAccountId) === String(args.nearAccountId),
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

function exactEd25519LaneIdentityFromAvailableLane(
  lane: ConcreteAvailableEd25519SigningLane,
): ExactEd25519SigningLaneIdentity {
  return exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
      signerSlot: lane.signerSlot,
    }),
    auth: lane.auth,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
  });
}

function nearEd25519YaoRuntimeObservation(
  capability: NearEd25519YaoSigningCapability | null,
): NearEd25519YaoRuntimeObservationV1 {
  if (!capability || capability.activeClient.status().kind !== 'active') {
    return { kind: 'absent' };
  }
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(
    capability.activeClient.metadata(),
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

type EmailOtpEd25519YaoSilentRecoveryInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  signerSlot: number;
  thresholdSessionId: string;
  materialActivation: MpcMaterialActivationRef;
};

type PreparedNearEd25519YaoMaterialContext = {
  input: PrepareNearEd25519YaoMaterialBoundaryInput;
  materialActivation: MpcMaterialActivationRef | null;
};

type NearEmailOtpEd25519OperationStepUpAuthorizationInput = Parameters<
  Extract<
    NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
    { kind: 'sealed' }
  >['authorizeAndRehydrate']
>[0];

function assertNearEd25519YaoMaterialBoundaryAuth(
  input: PrepareNearEd25519YaoMaterialBoundaryInput,
): void {
  const expected = input.laneIdentity.auth;
  const actual = input.auth;
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

function validateExactNearEd25519YaoSigningCapability(args: {
  capability: NearEd25519YaoSigningCapability;
  input: PrepareNearEd25519YaoMaterialBoundaryInput;
  expectedActivation: MpcMaterialActivationRef;
}): NearEd25519YaoSigningCapability {
  const sessionState = args.capability.walletSessionState;
  const metadata = args.capability.activeClient.metadata();
  const thresholdSessionId = String(args.input.laneIdentity.thresholdSessionId);
  const expectedSigner = args.input.laneIdentity.signer;
  const actualSigner = sessionState.signingLane.identity.signer;
  if (
    String(sessionState.thresholdSessionId) !== thresholdSessionId ||
    String(sessionState.signingLane.thresholdSessionId) !== thresholdSessionId
  ) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability session mismatch');
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
    String(actualSigner.account.nearAccountId) !==
      String(expectedSigner.account.nearAccountId) ||
    actualSigner.signerSlot !== expectedSigner.signerSlot ||
    String(actualSigner.nearEd25519SigningKeyId) !==
      String(expectedSigner.nearEd25519SigningKeyId)
  ) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability signer mismatch');
  }
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  if (!mpcMaterialActivationRefsEqual(args.expectedActivation, materialActivation)) {
    throw new Error('[SigningEngine][near] active Ed25519 Yao capability activation mismatch');
  }
  return args.capability;
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

/**
 * BrowserSigningSurface owns browser signing assembly state and exposes the SeamsWeb signing surface.
 */
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
  private readonly nearEd25519CapabilityRehydrationBySubject: Map<string, Promise<void>> =
    new Map();
  private readonly emailOtpEd25519SilentRecoveryBySubject: Map<
    string,
    Promise<EmailOtpEd25519YaoSilentRecoveryResultV1>
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

  readonly seamsWebConfigs: SeamsConfigsReadonly;

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
      stores: deps.managerStores,
      seamsWebConfigs: this.seamsWebConfigs,
      nearClient: this.nearClient,
      loadEcdsaRoleLocalReadyRecord,
      getTheme: () => this.appearance.theme.mode,
      getAppearance: () => this.appearance,
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
      getEmailOtpWarmSessionStatus: (sessionId) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      signingSessionSeal: this.seamsWebConfigs.signing.sessionSeal,
      ecdsaExportArtifacts: ecdsaExportArtifactStore,
      resolveActiveEcdsaWalletSessionAuthorization:
        createBrowserActiveEcdsaWalletSessionAuthorizationResolver({
          seamsWebConfigs: this.seamsWebConfigs,
          emailOtpSessions: this.emailOtpSessions,
          sealedSigningSessionStore: deps.sealedSigningSessionStore,
        }),
    });
    this.sessionPublicDeps = createSessionPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      touchConfirm: this.touchConfirm,
      passkeyMpcSession: this.passkeyMpcSession,
      emailOtpSessions: this.emailOtpSessions,
      listEcdsaSigningCapabilitiesForWallet: (input) =>
        listBrowserEcdsaSigningCapabilitiesForWallet(
          {
            seamsWebConfigs: this.seamsWebConfigs,
            emailOtpSessions: this.emailOtpSessions,
            sealedSigningSessionStore: deps.sealedSigningSessionStore,
          },
          input,
        ),
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
      resolveActiveEd25519YaoCapability: (scope) =>
        this.enginePorts.ed25519YaoActiveClients.resolveForWalletAccount(scope),
      recoverPasskeyEd25519YaoCapability:
        this.recoverExactPasskeyEd25519YaoCapabilityForExport.bind(this),
      resolvePasskeyEd25519YaoExportContext:
        this.resolveExactPasskeyEd25519YaoExportContext.bind(this),
      resolveEmailOtpEd25519YaoExportContext:
        this.resolveEmailOtpEd25519YaoExportContext.bind(this),
      getSigningSessionCoordinator: () => this.enginePorts.signingSessionCoordinator,
      getTheme: () => this.appearance.theme.mode,
      listEcdsaSigningCapabilitiesForWallet: (input) =>
        listBrowserEcdsaSigningCapabilitiesForWallet(
          {
            seamsWebConfigs: this.seamsWebConfigs,
            emailOtpSessions: this.emailOtpSessions,
            sealedSigningSessionStore: deps.sealedSigningSessionStore,
          },
          input,
        ),
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

  private async ensureSealedRefreshStartupParity(): Promise<void> {
    await this.sealedRefreshStartupParityPromise;
    if (this.sealedRefreshStartupParityError) {
      throw this.sealedRefreshStartupParityError;
    }
  }

  async assertSealedRefreshStartupParity(): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
  }

  async discoverPersistedSessionsForWallet(
    args: DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult> {
    return await sessionPublic.discoverPersistedSessionsForWallet(this.sessionPublicDeps, args);
  }

  async readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    return await sessionPublic.readPersistedAvailableSigningLanes(this.sessionPublicDeps, args);
  }

  async readReusableWalletSessionState(
    walletId: WalletId | string,
  ): Promise<ReusableWalletSessionState> {
    const parsedWalletId = parseWalletId(walletId);
    if (!parsedWalletId.ok) {
      throw new Error(parsedWalletId.error.message);
    }
    const exactWalletId = parsedWalletId.value;
    const read = await walletSessionAuthorizations.readActiveForWallet(exactWalletId);
    if (read.kind !== 'found') {
      switch (read.kind) {
        case 'missing':
          return { kind: 'missing', walletId: exactWalletId };
        case 'persistence_unavailable':
          return {
            kind: 'unavailable',
            walletId: exactWalletId,
            reason: 'persistence_unavailable',
          };
        case 'corrupt':
          return { kind: 'invalid', walletId: exactWalletId, reason: 'malformed' };
      }
    }
    const authorization = read.projection;
    const nowMs = Date.now();
    if (authorization.expiresAtMs <= nowMs) {
      await walletSessionAuthorizations.write(
        retireWalletSessionAuthorizationProjection({
          active: authorization,
          reason: 'expired',
          retiredAtMs: nowMs,
        }),
      );
      return {
        kind: 'expired',
        walletId: exactWalletId,
        walletSessionId: authorization.walletSessionId,
        authMethod: authorization.authMethod,
        expiresAtMs: authorization.expiresAtMs,
        detectedAtMs: nowMs,
      };
    }
    const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
    if (!relayerUrl) {
      return {
        kind: 'unavailable',
        walletId: exactWalletId,
        reason: 'persistence_unavailable',
      };
    }
    let auth: ReusableWalletSessionStatusAuth;
    if (authorization.authMethod === WALLET_AUTH_METHODS.emailOtp) {
      const appSessionJwt = await this.emailOtpSessions
        .resolveAppSessionJwt({
          walletSession: {
            walletId: exactWalletId,
            walletSessionUserId: String(authorization.authority.authorityDigest),
          },
          relayUrl: relayerUrl,
        })
        .catch(() => '');
      const parsedAppSessionJwt = parseAppSessionJwt(appSessionJwt);
      if (!parsedAppSessionJwt.ok) {
        return {
          kind: 'unavailable',
          walletId: exactWalletId,
          reason: 'persistence_unavailable',
        };
      }
      auth = {
        kind: 'app_session_jwt',
        appSessionJwt: parsedAppSessionJwt.value,
      };
    } else {
      auth = { kind: 'app_session_cookie' };
    }
    const status = await createRelayerReusableWalletSessionStatusPort({
      relayerUrl,
      auth,
    })
      .read({
        walletSessionId: authorization.walletSessionId,
        quotaId: authorization.quotaId,
      })
      .catch(() => null);
    if (!status) {
      return {
        kind: 'unavailable',
        walletId: exactWalletId,
        reason: 'persistence_unavailable',
      };
    }
    switch (status.status) {
      case 'active':
        return {
          kind: 'active',
          walletId: exactWalletId,
          walletSessionId: authorization.walletSessionId,
          authMethod: authorization.authMethod,
          remainingUses: status.remainingUses,
          expiresAtMs: status.expiresAtMs,
        };
      case 'exhausted':
        return {
          kind: 'exhausted',
          walletId: exactWalletId,
          walletSessionId: authorization.walletSessionId,
          authMethod: authorization.authMethod,
          remainingUses: 0,
          expiresAtMs: status.expiresAtMs,
        };
      case 'expired':
        await walletSessionAuthorizations.write(
          retireWalletSessionAuthorizationProjection({
            active: authorization,
            reason: 'expired',
            retiredAtMs: Math.max(nowMs, status.expiresAtMs),
          }),
        );
        return {
          kind: 'expired',
          walletId: exactWalletId,
          walletSessionId: authorization.walletSessionId,
          authMethod: authorization.authMethod,
          expiresAtMs: status.expiresAtMs,
          detectedAtMs: nowMs,
        };
      case 'missing':
        await walletSessionAuthorizations.write(
          retireWalletSessionAuthorizationProjection({
            active: authorization,
            reason: 'invalidated',
            retiredAtMs: nowMs,
          }),
        );
        return { kind: 'missing', walletId: exactWalletId };
      case 'superseded':
        await walletSessionAuthorizations.write(
          retireWalletSessionAuthorizationProjection({
            active: authorization,
            reason: 'replaced',
            retiredAtMs: nowMs,
          }),
        );
        // Replaced, not broken. The caller discards this session and resolves
        // current state again; reporting `invalid` sent it to an error path.
        return {
          kind: 'superseded',
          walletId: exactWalletId,
          walletSessionId: authorization.walletSessionId,
          authMethod: authorization.authMethod,
          detectedAtMs: nowMs,
        };
      case 'invalid':
        await walletSessionAuthorizations.write(
          retireWalletSessionAuthorizationProjection({
            active: authorization,
            reason: 'invalidated',
            retiredAtMs: nowMs,
          }),
        );
        return { kind: 'invalid', walletId: exactWalletId, reason: 'identity_mismatch' };
    }
  }

  async warmCriticalResources(
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
  ): Promise<NearEd25519YaoSigningCapability> {
    const rehydrationKey = nearEd25519CapabilityRehydrationKey(subject);
    const existingRehydration = this.nearEd25519CapabilityRehydrationBySubject.get(rehydrationKey);
    if (existingRehydration) {
      await existingRehydration;
      const rehydrated = await this.resolveActiveNearEd25519YaoSigningLane(subject);
      if (rehydrated) return rehydrated;
      throw new Error('[SigningEngine][near] joined rehydration did not publish an active lane');
    }

    const rehydration = this.rehydrateNearEd25519YaoCapabilityForSigning(subject);
    this.nearEd25519CapabilityRehydrationBySubject.set(rehydrationKey, rehydration);
    try {
      await rehydration;
    } finally {
      if (this.nearEd25519CapabilityRehydrationBySubject.get(rehydrationKey) === rehydration) {
        this.nearEd25519CapabilityRehydrationBySubject.delete(rehydrationKey);
      }
    }
    const rehydrated = await this.resolveActiveNearEd25519YaoSigningLane(subject);
    if (rehydrated) return rehydrated;
    throw new Error('[SigningEngine][near] local material rehydration did not publish a lane');
  }

  private async rehydrateExactPasskeyEd25519YaoCapabilityForSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearEd25519YaoSigningCapability> {
    return await this.ensureNearEd25519YaoCapabilityForSigning({
      kind: 'exact_lane',
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      signerSlot: args.laneIdentity.signer.signerSlot,
      thresholdSessionId: String(args.laneIdentity.thresholdSessionId),
      laneIdentity: args.laneIdentity,
    });
  }

  private async prepareExactNearEd25519YaoSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearEd25519YaoSigningPreparation> {
    const record = await readPersistedEd25519SessionRecordForSigning({
      walletId: String(args.walletId),
      laneIdentity: args.laneIdentity,
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(
      record || undefined,
    );
    if (!record || !walletSessionState) {
      throw new Error('[SigningEngine][near] exact persisted Ed25519 material is unavailable');
    }
    const signer = walletSessionState.signingLane.identity.signer;
    const publicLocator = nearEd25519PublicLocatorObservation({
      references: await this.ed25519YaoPublicCapabilityReferences.list(),
      walletId: signer.account.wallet.walletId,
      nearAccountId: signer.account.nearAccountId,
      signerSlot: signer.signerSlot,
    });
    const activeCapability =
      publicLocator.kind === 'available'
        ? this.enginePorts.ed25519YaoActiveClients.resolve({
            walletId: signer.account.wallet.walletId,
            nearAccountId: signer.account.nearAccountId,
            materialActivation: publicLocator.materialActivation,
          })
        : null;
    const runtime = nearEd25519YaoRuntimeObservation(activeCapability);
    const hydration = await this.resolveExactNearEd25519YaoSigningHydration({
      args,
      walletSessionState,
      publicLocator,
      runtime,
    });
    const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(args.walletId);
    switch (authorizationRead.kind) {
      case 'found': {
        const reusableSession = await this.readReusableWalletSessionState(args.walletId);
        if (
          reusableSession.kind === 'active' &&
          reusableSession.walletSessionId === authorizationRead.projection.walletSessionId &&
          reusableSession.authMethod === authorizationRead.projection.authMethod
        ) {
          return buildAuthorizedNearEd25519YaoSigningPreparation({
            hydration,
            requirement: args.auth,
            authorization: buildActiveNearEd25519WalletSessionAuthorization({
              projection: authorizationRead.projection,
              status: {
                status: 'active',
                walletSessionId: authorizationRead.projection.walletSessionId,
                quotaId: authorizationRead.projection.quotaId,
                remainingUses: reusableSession.remainingUses,
                expiresAtMs: reusableSession.expiresAtMs,
              },
            }),
          });
        }
        return buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
          hydration,
          requirement: args.auth,
        });
      }
      case 'missing':
        return buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
          hydration,
          requirement: args.auth,
        });
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
    let preparation = await this.prepareExactNearEd25519YaoSigning(args);
    if (
      args.auth.kind === WALLET_AUTH_METHODS.emailOtp &&
      preparation.hydration.kind === 'rehydrate_material_activation'
    ) {
      const expectedActivation = requireNearEd25519YaoPreparationActivation(preparation);
      const recovery = await this.recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning({
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        signerSlot: args.laneIdentity.signer.signerSlot,
        thresholdSessionId: String(args.laneIdentity.thresholdSessionId),
        materialActivation: expectedActivation,
      });
      switch (recovery.kind) {
        case 'recovered':
          validateExactNearEd25519YaoSigningCapability({
            capability: recovery.recovery,
            input: args,
            expectedActivation,
          });
          preparation = await this.prepareExactNearEd25519YaoSigning(args);
          if (
            !mpcMaterialActivationRefsEqual(
              expectedActivation,
              requireNearEd25519YaoPreparationActivation(preparation),
            )
          ) {
            throw new Error(
              '[SigningEngine][near] Email OTP recovery changed prepared material activation',
            );
          }
          break;
        case 'reauth_required':
          preparation = buildAuthorizationRequiredNearEd25519YaoSigningPreparation({
            hydration: preparation.hydration,
            requirement: args.auth,
          });
          break;
        default:
          recovery satisfies never;
          throw new Error('[SigningEngine][near] unsupported Email OTP recovery result');
      }
    }
    const context: PreparedNearEd25519YaoMaterialContext = {
      input: args,
      materialActivation: preparation.hydration.materialActivation || null,
    };
    return {
      preparation,
      executor: {
        resolve: this.resolveExactNearEd25519YaoPreparedMaterial.bind(this, context),
        preparePasskeyOperationStepUp:
          this.prepareExactNearEd25519YaoOperationStepUpAtBoundary.bind(this, context),
        prepareEmailOtpOperationStepUp:
          this.prepareExactNearEmailOtpEd25519YaoOperationStepUpAtBoundary.bind(this, context),
      },
    };
  }

  private async resolveExactNearEd25519YaoPreparedMaterial(
    context: PreparedNearEd25519YaoMaterialContext,
    preparation: NearEd25519YaoSigningPreparation,
  ): Promise<NearEd25519YaoSigningCapability> {
    const args = context.input;
    const expectedActivation = requireBoundNearEd25519YaoPreparationActivation({
      context,
      preparation,
    });
    switch (preparation.hydration.kind) {
      case 'use_live_runtime': {
        const capability = this.enginePorts.ed25519YaoActiveClients.resolve({
          walletId: args.walletId,
          nearAccountId: args.nearAccountId,
          materialActivation: expectedActivation,
        });
        if (!capability) {
          throw new Error('[SigningEngine][near] active Ed25519 Yao capability is unavailable');
        }
        return validateExactNearEd25519YaoSigningCapability({
          capability,
          input: args,
          expectedActivation,
        });
      }
      case 'rehydrate_material_activation':
        switch (args.auth.kind) {
          case WALLET_AUTH_METHODS.passkey:
            return validateExactNearEd25519YaoSigningCapability({
              capability:
                await this.rehydrateExactPasskeyEd25519YaoCapabilityForSigning(args),
              input: args,
              expectedActivation,
            });
          case WALLET_AUTH_METHODS.emailOtp: {
            const recovery =
              await this.recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning({
                walletId: args.walletId,
                nearAccountId: args.nearAccountId,
                signerSlot: args.laneIdentity.signer.signerSlot,
                thresholdSessionId: String(args.laneIdentity.thresholdSessionId),
                materialActivation: expectedActivation,
              });
            switch (recovery.kind) {
              case 'recovered':
                return validateExactNearEd25519YaoSigningCapability({
                  capability: recovery.recovery,
                  input: args,
                  expectedActivation,
                });
              case 'reauth_required':
                throw new Error(
                  `[SigningEngine][near] Email OTP material requires reauthorization: ${recovery.reason}`,
                );
              default:
                recovery satisfies never;
                throw new Error('[SigningEngine][near] unsupported Email OTP recovery result');
            }
          }
          default:
            args.auth satisfies never;
            throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
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

  private async prepareExactNearEd25519YaoOperationStepUpAtBoundary(
    context: PreparedNearEd25519YaoMaterialContext,
    preparation: NearEd25519YaoSigningPreparation,
  ): Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation> {
    const args = context.input;
    if (args.auth.kind !== WALLET_AUTH_METHODS.passkey) {
      throw new Error('[SigningEngine][near] Email OTP material cannot use Passkey rehydration');
    }
    const expectedActivation = requireBoundNearEd25519YaoPreparationActivation({
      context,
      preparation,
    });
    const prepared = await this.prepareExactPasskeyEd25519YaoOperationStepUpForSigning(args);
    if (!mpcMaterialActivationRefsEqual(expectedActivation, prepared.materialActivation)) {
      throw new Error('[SigningEngine][near] operation step-up changed material activation');
    }
    return prepared;
  }

  private async prepareExactNearEmailOtpEd25519YaoOperationStepUpAtBoundary(
    context: PreparedNearEd25519YaoMaterialContext,
    preparation: NearEd25519YaoSigningPreparation,
  ): Promise<NearEmailOtpEd25519OperationStepUpCapabilityPreparation> {
    const args = context.input;
    if (args.auth.kind !== WALLET_AUTH_METHODS.emailOtp) {
      throw new Error('[SigningEngine][near] Passkey material cannot use Email OTP rehydration');
    }
    const expectedActivation = requireBoundNearEd25519YaoPreparationActivation({
      context,
      preparation,
    });
    switch (preparation.hydration.kind) {
      case 'use_live_runtime': {
        const capability = await this.resolveExactNearEd25519YaoPreparedMaterial(
          context,
          preparation,
        );
        return {
          kind: 'live',
          materialActivation: expectedActivation,
          material: {
            activeClient: capability.activeClient,
            facts: nearEd25519YaoOperationMaterialFacts(capability.walletSessionState),
          },
        };
      }
      case 'rehydrate_material_activation': {
        const record = await readPersistedEd25519SessionRecordForSigning({
          walletId: String(args.walletId),
          laneIdentity: args.laneIdentity,
        });
        const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(
          record || undefined,
        );
        if (!record || !walletSessionState) {
          throw new Error('[SigningEngine][near] sealed Email OTP material facts are unavailable');
        }
        const user = await this.getUserBySignerSlot(
          args.nearAccountId,
          args.laneIdentity.signer.signerSlot,
        );
        if (!user || String(user.walletId) !== String(args.walletId)) {
          throw new Error('[SigningEngine][near] Email OTP operation signer is unavailable');
        }
        const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
        if (!relayerUrl) {
          throw new Error('[SigningEngine][near] Email OTP operation requires relayerUrl');
        }
        const facts = nearEd25519YaoOperationMaterialFacts(walletSessionState);
        return {
          kind: 'sealed',
          materialActivation: expectedActivation,
          facts,
          authorizeAndRehydrate:
            this.authorizeAndRehydrateExactNearEmailOtpEd25519YaoOperationStepUp.bind(this, {
              workerContext: this.signerWorkerManager.getContext(),
              relayerUrl,
              walletId: String(args.walletId),
              nearAccountId: String(args.nearAccountId),
              signerSlot: args.laneIdentity.signer.signerSlot,
              providerSubjectId: args.auth.providerSubjectId,
              expectedOperationalPublicKey: user.operationalPublicKey,
              expectedThresholdSessionId: args.laneIdentity.thresholdSessionId,
              expectedMaterialActivation: expectedActivation,
              facts,
            }),
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

  private async authorizeAndRehydrateExactNearEmailOtpEd25519YaoOperationStepUp(
    prepared: {
      workerContext: WorkerOperationContext;
      relayerUrl: string;
      walletId: string;
      nearAccountId: string;
      signerSlot: number;
      providerSubjectId: string;
      expectedOperationalPublicKey: string;
      expectedThresholdSessionId: ExactEd25519SigningLaneIdentity['thresholdSessionId'];
      expectedMaterialActivation: MpcMaterialActivationRef;
      facts: NearEd25519YaoOperationMaterial['facts'];
    },
    authorization: NearEmailOtpEd25519OperationStepUpAuthorizationInput,
  ): ReturnType<
    Extract<
      NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
      { kind: 'sealed' }
    >['authorizeAndRehydrate']
  > {
    const recovered = await rehydrateEmailOtpEd25519YaoOperationMaterialV1({
      workerContext: prepared.workerContext,
      relayUrl: prepared.relayerUrl,
      walletId: prepared.walletId,
      nearAccountId: prepared.nearAccountId,
      signerSlot: prepared.signerSlot,
      providerSubjectId: prepared.providerSubjectId,
      expectedOperationalPublicKey: prepared.expectedOperationalPublicKey,
      expectedThresholdSessionId: prepared.expectedThresholdSessionId,
      expectedMaterialActivation: prepared.expectedMaterialActivation,
      normalSigningRequest: authorization.normalSigningRequest,
      displayDigest: authorization.displayDigest,
      proof: authorization.proof,
    });
    return {
      material: {
        activeClient: recovered.activeClient,
        facts: prepared.facts,
      },
      issuedGrant: recovered.issuedGrant,
    };
  }

  private async resolveExactNearEd25519YaoSigningHydration(input: {
    args: PrepareNearEd25519YaoMaterialBoundaryInput;
    walletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
    publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1;
    runtime: NearEd25519YaoRuntimeObservationV1;
  }): Promise<MpcCapabilityHydrationPlan> {
    const { args } = input;
    switch (args.auth.kind) {
      case WALLET_AUTH_METHODS.passkey: {
        const resolved = await this.resolvePasskeyEd25519YaoHydration({
          walletSessionState: input.walletSessionState,
          credentialIdB64u: args.auth.credentialIdB64u,
          unlockSource: { kind: 'unavailable' },
        });
        let hydration: MpcCapabilityHydrationPlan;
        switch (resolved.kind) {
          case 'live':
          case 'blocked':
            hydration = resolved.plan;
            break;
          case 'rehydrated':
            resolved.activeClient.dispose();
            throw new Error(
              '[SigningEngine][near] unavailable unlock source rehydrated Passkey material',
            );
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
            publicLocator: input.publicLocator,
          });
          return prepared.plan;
        }
        return hydration;
      }
      case WALLET_AUTH_METHODS.emailOtp:
        return await resolveEmailOtpEd25519YaoHydrationPlanForSigningV1({
          subject: {
            walletId: args.walletId,
            nearAccountId: args.nearAccountId,
            signerSlot: args.laneIdentity.signer.signerSlot,
            thresholdSessionId: String(args.laneIdentity.thresholdSessionId),
          },
          publicLocator: input.publicLocator,
          runtime: input.runtime,
          readExactSealedSession,
        });
      default:
        args.auth satisfies never;
        throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
    }
  }

  private async prepareExactPasskeyEd25519YaoOperationStepUpForSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation> {
    const lane = await this.resolveNearEd25519YaoSigningLane({
      kind: 'exact_lane',
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      signerSlot: args.laneIdentity.signer.signerSlot,
      thresholdSessionId: String(args.laneIdentity.thresholdSessionId),
      laneIdentity: args.laneIdentity,
    });
    if (!lane) {
      throw new Error('[SigningEngine][near] sealed Ed25519 operation lane is unavailable');
    }
    const record = await readPersistedEd25519SessionRecordForSigning({
      walletId: String(args.walletId),
      laneIdentity: args.laneIdentity,
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromCurrentRecord(
      record || undefined,
    );
    if (!record || !walletSessionState) {
      throw new Error('[SigningEngine][near] sealed Ed25519 operation state is unavailable');
    }
    const credentialIdB64u = String(record.passkeyCredentialIdB64u || '').trim();
    const rpId = String(record.rpId || '').trim();
    if (!credentialIdB64u || !rpId) {
      throw new Error('[SigningEngine][near] sealed Ed25519 passkey authority is unavailable');
    }
    const signer = walletSessionState.signingLane.identity.signer;
    const publicLocator = nearEd25519PublicLocatorObservation({
      references: await this.ed25519YaoPublicCapabilityReferences.list(),
      walletId: signer.account.wallet.walletId,
      nearAccountId: signer.account.nearAccountId,
      signerSlot: signer.signerSlot,
    });
    const prepared = await preparePasskeyEd25519YaoLocalMaterialRehydrationV1({
      store: IndexedDBManager,
      walletSessionState,
      rpId,
      credentialIdB64u,
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
      participantIds: [...record.participantIds],
      rehydrate: this.rehydratePreparedPasskeyEd25519YaoOperationStepUp.bind(this, {
        walletSessionState,
        rpId,
        credentialIdB64u,
        publicLocator,
        materialActivation: prepared.plan.materialActivation,
      }),
    };
  }

  private async rehydratePreparedPasskeyEd25519YaoOperationStepUp(
    prepared: {
      walletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
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
      publicLocator: prepared.publicLocator,
      unlockSource: {
        kind: 'available',
        passkeyPrfFirstB64u: secretSource.secretSource.prfFirstB64u,
      },
      liveCapability: null,
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
    return {
      activeClient: hydrated.activeClient,
      facts: nearEd25519YaoOperationMaterialFacts(prepared.walletSessionState),
    };
  }

  private async recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning(
    args: EmailOtpEd25519YaoSilentRecoveryInput,
  ): Promise<EmailOtpEd25519YaoSilentRecoveryResultV1> {
    const recoveryKey = JSON.stringify([
      String(args.walletId),
      String(args.nearAccountId),
      args.signerSlot,
      args.thresholdSessionId,
      String(args.materialActivation.activationId),
      String(args.materialActivation.lifecycleBinding),
    ]);
    const existing = this.emailOtpEd25519SilentRecoveryBySubject.get(recoveryKey);
    if (existing) return await existing;
    const recovery = this.runExactEmailOtpEd25519YaoSilentRecovery(args);
    this.emailOtpEd25519SilentRecoveryBySubject.set(recoveryKey, recovery);
    try {
      return await recovery;
    } finally {
      if (this.emailOtpEd25519SilentRecoveryBySubject.get(recoveryKey) === recovery) {
        this.emailOtpEd25519SilentRecoveryBySubject.delete(recoveryKey);
      }
    }
  }

  private async runExactEmailOtpEd25519YaoSilentRecovery(
    args: EmailOtpEd25519YaoSilentRecoveryInput,
  ): Promise<EmailOtpEd25519YaoSilentRecoveryResultV1> {
    const user = await this.getUserBySignerSlot(args.nearAccountId, args.signerSlot);
    if (!user || String(user.walletId) !== String(args.walletId)) {
      throw new Error(
        '[SigningEngine][near] Email OTP Ed25519 sealed recovery signer identity is unavailable',
      );
    }
    const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
    if (!relayerUrl) {
      throw new Error(
        '[SigningEngine][near] Email OTP Ed25519 sealed recovery requires relayerUrl',
      );
    }
    const result = await recoverEmailOtpEd25519YaoFromSealedSessionV1({
      subject: {
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        signerSlot: args.signerSlot,
        thresholdSessionId: args.thresholdSessionId,
      },
      expectedMaterialActivation: args.materialActivation,
      expectedOperationalPublicKey: user.operationalPublicKey,
      rpId: this.getRpId(),
      relayerUrl,
      authPolicy: this.seamsWebConfigs.signing.emailOtp.authPolicy,
      ports: {
        readExactSealedSession,
        readActiveWalletSessionAuthorization: walletSessionAuthorizations.readActiveForWallet.bind(
          walletSessionAuthorizations,
        ),
        workerContext: this.signerWorkerManager.getContext(),
        resolveActiveCapability:
          this.enginePorts.ed25519YaoActiveClients.resolveForWalletAccount.bind(
            this.enginePorts.ed25519YaoActiveClients,
          ),
        activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
          this.enginePorts.ed25519YaoActiveClients,
        ),
        withThresholdEd25519CommitQueue: (queueArgs) =>
          withThresholdEd25519CommitQueue({
            queueByKey: this.thresholdEd25519CommitQueueByKey,
            ...queueArgs,
          }),
        persistRecoveredSession:
          this.persistEmailOtpEd25519YaoSessionForRefreshInternal.bind(this),
        nowMs: Date.now,
      },
    });
    return result;
  }

  private async recoverExactPasskeyEd25519YaoCapabilityForExport(
    laneIdentity: Parameters<RecoveryPublicDeps['ed25519Yao']['recoverPasskeyCapability']>[0],
  ): Promise<NearEd25519YaoSigningCapability> {
    return await this.ensureNearEd25519YaoCapabilityForSigning({
      kind: 'exact_lane',
      walletId: laneIdentity.signer.account.wallet.walletId,
      nearAccountId: laneIdentity.signer.account.nearAccountId,
      signerSlot: laneIdentity.signer.signerSlot,
      thresholdSessionId: String(laneIdentity.thresholdSessionId),
      laneIdentity,
    });
  }

  private async resolveExactPasskeyEd25519YaoExportContext(
    laneIdentity: Parameters<RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext']>[0],
  ): ReturnType<RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext']> {
    const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
    if (!relayerUrl) {
      throw new Error('[SigningEngine][ed25519-export] passkey export requires relayerUrl');
    }
    return await resolvePasskeyEd25519YaoExportContextV1({
      subject: {
        walletId: String(laneIdentity.signer.account.wallet.walletId),
        nearAccountId: String(laneIdentity.signer.account.nearAccountId),
        signerSlot: laneIdentity.signer.signerSlot,
        thresholdSessionId: String(laneIdentity.thresholdSessionId),
      },
      relayerUrl,
      fetch: fetchWithGlobalThis,
    });
  }

  private async resolveEmailOtpEd25519YaoExportContext(
    subject: EmailOtpEd25519YaoExportSubjectV1,
  ): Promise<EmailOtpEd25519YaoExportContextV1> {
    const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
    if (!relayerUrl) {
      throw new Error('[SigningEngine][ed25519-export] Email OTP export requires relayerUrl');
    }
    return await resolveEmailOtpEd25519YaoExportContextV1({
      subject,
      relayerUrl,
      ports: {
        readExactSealedSession,
        readActiveWalletSessionAuthorization: walletSessionAuthorizations.readActiveForWallet.bind(
          walletSessionAuthorizations,
        ),
        fetch: fetchWithGlobalThis,
      },
    });
  }

  private async resolveActiveNearEd25519YaoSigningLane(
    subject: NearEd25519CapabilityRehydrationSubject,
  ): Promise<NearEd25519YaoSigningCapability | null> {
    const lane = await this.resolveNearEd25519YaoSigningLane(subject);
    if (!lane) return null;
    const capability = this.enginePorts.ed25519YaoActiveClients.resolveForWalletAccount({
      walletId: subject.walletId,
      nearAccountId: subject.nearAccountId,
    });
    return capability?.activeClient.status().kind === 'active' ? capability : null;
  }

  private async resolveNearEd25519YaoSigningLane(
    subject: NearEd25519CapabilityRehydrationSubject,
  ): Promise<ConcreteAvailableEd25519SigningLane | null> {
    const availableLanes =
      await this.enginePorts.nearSigningDeps.readAvailableSigningLanesForSigning({
        walletId: subject.walletId,
        curve: 'ed25519',
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

  private async rehydrateNearEd25519YaoCapabilityForSigning(
    subject: NearEd25519CapabilityRehydrationSubject,
  ): Promise<void> {
    const lane = await this.resolveNearEd25519YaoSigningLane(subject);
    if (!lane) {
      throw new Error('[SigningEngine][near] local Ed25519 material lane is unavailable');
    }
    const laneIdentity =
      subject.kind === 'exact_lane'
        ? subject.laneIdentity
        : exactEd25519LaneIdentityFromAvailableLane(lane);
    const record = await readPersistedEd25519SessionRecordForSigning({
      walletId: String(subject.walletId),
      laneIdentity,
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(
      record || undefined,
    );
    if (!record || !walletSessionState) {
      throw new Error('[SigningEngine][near] persisted Ed25519 Wallet Session is unavailable');
    }
    const credentialIdB64u = String(record.passkeyCredentialIdB64u || '').trim();
    if (!credentialIdB64u) {
      throw new Error('[SigningEngine][near] persisted Ed25519 credential is unavailable');
    }
    const liveHydration = await this.resolvePasskeyEd25519YaoHydration({
      walletSessionState,
      credentialIdB64u,
      unlockSource: { kind: 'unavailable' },
    });
    if (liveHydration.kind === 'live') return;
    if (liveHydration.kind === 'rehydrated') {
      liveHydration.activeClient.dispose();
      throw new Error('[SigningEngine][near] unavailable unlock source rehydrated local material');
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
    walletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
    credentialIdB64u: string;
    unlockSource: PasskeyEd25519YaoUnlockSourceV1;
  }): ReturnType<typeof hydratePasskeyEd25519YaoLocalMaterialV1> {
    const signer = args.walletSessionState.signingLane.identity.signer;
    const publicLocator = nearEd25519PublicLocatorObservation({
      references: await this.ed25519YaoPublicCapabilityReferences.list(),
      walletId: signer.account.wallet.walletId,
      nearAccountId: signer.account.nearAccountId,
      signerSlot: signer.signerSlot,
    });
    return hydratePasskeyEd25519YaoLocalMaterialV1({
      store: IndexedDBManager,
      walletSessionState: args.walletSessionState,
      rpId: this.getRpId(),
      credentialIdB64u: args.credentialIdB64u,
      publicLocator,
      unlockSource: args.unlockSource,
      liveCapability:
        publicLocator.kind === 'available'
          ? this.enginePorts.ed25519YaoActiveClients.resolve({
              walletId: signer.account.wallet.walletId,
              nearAccountId: signer.account.nearAccountId,
              materialActivation: publicLocator.materialActivation,
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

  async activateVerifiedNearEd25519YaoSigningCapability(
    capability: NearEd25519YaoSigningCapability,
  ): Promise<Ed25519YaoActiveClientIdentityV1> {
    return await this.enginePorts.ed25519YaoActiveClients.activate(capability);
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
    input: Parameters<
      PasskeyMpcSessionPort['persistSigningSessionSealForThresholdSession']
    >[0],
  ): ReturnType<PasskeyMpcSessionPort['persistSigningSessionSealForThresholdSession']> {
    return this.passkeyMpcSession.persistSigningSessionSealForThresholdSession(input);
  }

  requestRegistrationCredentialConfirmation(params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
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
  }): Promise<WebAuthnAuthenticationCredential> {
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

  async prepareEmailOtpEd25519YaoLoginRecoveryInternal(args: {
    walletSession: WalletSessionRef;
    remainingUses: number;
    emailHashHex: string;
  }): Promise<PreparedColdEmailOtpEd25519YaoRecoveryV1 | null> {
    const resolved = await resolveEmailOtpEd25519YaoColdRecoveryV1(
      {
        listPublicCapabilityReferences: this.ed25519YaoPublicCapabilityReferences.list.bind(
          this.ed25519YaoPublicCapabilityReferences,
        ),
        listUsers: this.getAllUsers.bind(this),
      },
      args.walletSession,
    );
    if (!resolved) return null;
    const authorizationRecord = getStoredThresholdEd25519SessionRecordForAccount(
      resolved.user.nearAccountId,
    );
    if (
      !authorizationRecord ||
      String(authorizationRecord.walletId) !== String(resolved.identity.walletId)
    ) {
      throw new Error(
        'Email OTP Ed25519 Yao login requires an exact persisted authorization session',
      );
    }
    const runtimePolicyScope = authorizationRecord.runtimePolicyScope;
    if (!runtimePolicyScope) {
      throw new Error(
        'Email OTP Ed25519 Yao login requires an exact persisted runtime policy scope',
      );
    }
    return prepareColdEmailOtpEd25519YaoRecoveryV1({
      identity: resolved.identity,
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
        authorizationRecord.thresholdSessionId,
      ),
      signerSlot: resolved.user.signerSlot,
      expectedOperationalPublicKey: resolved.user.operationalPublicKey,
      providerSubject: resolved.providerSubject,
      emailHashHex: args.emailHashHex,
      rpId: this.getRpId(),
      relayerUrl: this.seamsWebConfigs.network.relayer?.url || '',
      runtimePolicyScope,
      authPolicy: this.seamsWebConfigs.signing.emailOtp.authPolicy,
      remainingUses: args.remainingUses,
      resolveActiveCapability:
        this.enginePorts.ed25519YaoActiveClients.resolveForWalletAccount.bind(
          this.enginePorts.ed25519YaoActiveClients,
        ),
    });
  }

  async persistEmailOtpEd25519YaoSessionForRefreshInternal(
    record: ThresholdEd25519SessionRecord,
  ): Promise<void> {
    await this.emailOtpSessions.persistEd25519YaoSessionForRefresh({
      record,
      rpId: this.getRpId(),
    });
  }

  async activateEmailOtpEd25519YaoUnlockedRecoveryInternal(args: {
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  }): Promise<ThresholdEd25519SessionRecord> {
    const recovered = await activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
      prepared: args.prepared,
      bootstrap: args.bootstrap,
      pendingFactorHandle: args.pendingFactorHandle,
      workerContext: this.signerWorkerManager.getContext(),
      activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
        this.enginePorts.ed25519YaoActiveClients,
      ),
    });
    await this.persistEmailOtpEd25519YaoSessionForRefreshInternal(recovered.record);
    return recovered.record;
  }

  async activateEmailOtpEd25519YaoLocalSessionInternal(args: {
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
    bootstrap: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
    activeClientHandle: string;
    metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  }): Promise<ThresholdEd25519SessionRecord> {
    const activated = await activateColdEmailOtpEd25519YaoLocalSessionV1({
      prepared: args.prepared,
      bootstrap: args.bootstrap,
      activeClientHandle: args.activeClientHandle,
      metadata: args.metadata,
      workerContext: this.signerWorkerManager.getContext(),
      activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
        this.enginePorts.ed25519YaoActiveClients,
      ),
    });
    await this.persistEmailOtpEd25519YaoSessionForRefreshInternal(activated.record);
    return activated.record;
  }

  async loginWithEmailOtpEd25519YaoCapabilityInternal(
    args: LoginWithEmailOtpEd25519YaoCapabilityInternalArgs,
  ): Promise<ThresholdEd25519SessionRecord> {
    const prepared = await this.prepareEmailOtpEd25519YaoLoginRecoveryInternal({
      walletSession: args.walletSession,
      remainingUses: args.remainingUses,
      emailHashHex: args.emailHashHex,
    });
    if (!prepared) {
      throw new Error('Email OTP Ed25519 Yao login requires a persisted signer capability');
    }
    const recovered = await recoverColdEmailOtpEd25519CapabilityForLoginV1({
      prepared,
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      appSessionJwt: args.appSessionJwt,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      workerContext: this.signerWorkerManager.getContext(),
      activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
        this.enginePorts.ed25519YaoActiveClients,
      ),
    });
    await this.persistEmailOtpEd25519YaoSessionForRefreshInternal(recovered.record);
    return recovered.record;
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
    authorization: ActiveWalletSessionAuthorizationProjection;
    authorizations: readonly [
      ActiveWalletSessionAuthorizationProjection,
      ...ActiveWalletSessionAuthorizationProjection[],
    ];
  }> {
    return await emailOtpPublic.refreshEmailOtpSigningSession(this.emailOtpPublicDeps, args);
  }

  async resolveEmailOtpAppSessionJwt(args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }): Promise<string> {
    return await this.emailOtpSessions.resolveAppSessionJwt(args);
  }

  rememberEmailOtpAppSessionBinding(binding: EmailOtpAppSessionBinding): void {
    this.emailOtpSessions.rememberAppSessionBinding(binding);
  }

  async enrollEmailOtpInternal(args: {
    walletId: WalletId;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    groupId?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    otpChannel?: WalletEmailOtpChannel;
  }): Promise<Awaited<ReturnType<typeof emailOtpPublic.enrollEmailOtpInternal>>> {
    return await emailOtpPublic.enrollEmailOtpInternal(this.emailOtpPublicDeps, args);
  }

  async rotateEmailOtpRecoveryCodesInternal(args: {
    walletId: WalletId;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<Awaited<ReturnType<typeof emailOtpPublic.rotateEmailOtpRecoveryCodesInternal>>> {
    return await emailOtpPublic.rotateEmailOtpRecoveryCodesInternal(this.emailOtpPublicDeps, args);
  }

  async prepareEmailOtpRegistrationEnrollmentMaterialInternal(
    args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  ): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult> {
    return await emailOtpPublic.prepareEmailOtpRegistrationEnrollmentMaterialInternal(
      this.emailOtpPublicDeps,
      args,
    );
  }

  getWarmThresholdEd25519SessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    return warmCapabilitiesPublic.getWarmThresholdEd25519SessionStatus(
      this.warmCapabilitiesPublicDeps,
      toAccountId(nearAccountId),
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
    try {
      if (walletId) {
        this.enginePorts.ed25519YaoActiveClients.disposeWallet(walletId);
      } else {
        this.enginePorts.ed25519YaoActiveClients.dispose();
      }
    } finally {
      await warmCapabilitiesPublic.clearVolatileWarmSigningMaterial(
        this.warmCapabilitiesPublicDeps,
        walletId,
      );
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
}
