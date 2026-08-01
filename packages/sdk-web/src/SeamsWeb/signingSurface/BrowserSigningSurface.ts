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
  NearResolvedEd25519SigningSessionState,
  NearPasskeyEd25519OperationStepUpCapabilityPreparation,
} from '@/core/signingEngine/interfaces/near';
import type {
  NearEd25519MaterialBoundaryInput,
  NearEd25519MaterialIdentity,
  NearSigningApiDeps,
} from '@/core/signingEngine/interfaces/operationDeps';
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
  type AvailableEd25519SigningLane,
  type ConcreteAvailableEd25519SigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  resolvePasskeyEd25519YaoExportContextV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import {
  buildRouterAbEd25519WalletSessionStateFromExactRuntime,
  nearEd25519YaoOperationMaterialFacts,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  hydratePasskeyEd25519YaoLocalMaterialV1,
  preparePasskeyEd25519YaoLocalMaterialRehydrationV1,
  readPasskeyEd25519YaoLocalMaterialLocatorV1,
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
  resolveNearEd25519YaoCapabilityHydrationV1,
  type NearEd25519YaoRuntimeObservationV1,
} from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import {
  mpcMaterialActivationRefsEqual,
  parseAppSessionJwt,
  parseWalletId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import { materialActivationKey } from '@/core/signingEngine/session/sealedRecovery/materialActivationKey';
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
  activateEmailOtpEd25519YaoLocalCapabilityV1,
  prepareColdEmailOtpEd25519YaoRecoveryV1,
  recoverColdEmailOtpEd25519CapabilityForLoginV1,
  type PreparedColdEmailOtpEd25519YaoRecoveryV1,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoCapabilityRecovery';
import type { EmailOtpEd25519YaoPublicationInput } from '@/core/signingEngine/session/emailOtp/ed25519YaoPublication';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import {
  ed25519SealedRuntimeAuthorityRef,
  parseExactEd25519SealedSessionRuntime,
  resolveExactEd25519SealedSessionRuntimeForLane,
  resolveExactEd25519SealedSessionRuntimeForWalletSubject,
  type ExactEd25519SealedSessionRuntime,
} from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { signingLaneAuthMethod } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type { EmailOtpEd25519YaoPendingFactorHandle } from '@/core/signingEngine/session/emailOtp/ed25519YaoRootVault';
import {
  listExactSealedSessionsForWallet,
  readExactEd25519SealedSession,
  readExactSealedSession,
  type CurrentSealedSessionRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { ed25519DurableMaterialLocator } from '@/core/signingEngine/session/sealedRecovery/materialActivationKey';
import { normalizeThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  recoverEmailOtpEd25519YaoFromSealedSessionV1,
  resolveEmailOtpEd25519YaoHydrationPlanForSigningV1,
  resolveEmailOtpEd25519YaoExportContextV1,
  type ResolvedEmailOtpEd25519YaoExportV1,
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
  createBrowserCanonicalWalletSessionStatusReader,
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

async function resolveActiveEd25519WalletSessionAuthorization(
  walletId: WalletId,
): Promise<ActiveWalletSessionAuthorizationProjection | null> {
  const read = await walletSessionAuthorizations.readActiveForWallet(walletId);
  return read.kind === 'found' ? read.projection : null;
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
      readonly laneIdentity: ExactEd25519SigningLaneIdentity;
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

async function requireExactEd25519SealedRuntimeForLane(args: {
  walletId: WalletId;
  laneIdentity: ExactEd25519SigningLaneIdentity;
}): Promise<ExactEd25519SealedSessionRuntime> {
  const resolution = await resolveExactEd25519SealedSessionRuntimeForLane(args);
  if (resolution.kind !== 'resolved') {
    throw new Error(
      `[SigningEngine][near] exact persisted Ed25519 runtime is ${resolution.kind}`,
    );
  }
  return resolution.runtime;
}

async function requireExactEd25519SealedRuntimeForExport(args: {
  walletId: WalletId;
  laneIdentity: ExactEd25519SigningLaneIdentity;
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
    .filter((record): record is Extract<CurrentSealedSessionRecord, { curve: 'ed25519' }> =>
      record.curve === 'ed25519',
    )
    .map(parseExactEd25519SealedSessionRuntime)
    .filter(
      (runtime): runtime is ExactEd25519SealedSessionRuntime =>
        runtime !== null && nearEd25519RuntimeMatchesMaterialIdentity({ runtime, identity: args.identity }),
    );
  if (runtimes.length === 0) {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 runtime is missing');
  }
  if (runtimes.length !== 1) {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 runtime is conflicting');
  }
  return runtimes[0];
}

async function walletSessionStateFromExactEd25519Runtime(
  runtime: ExactEd25519SealedSessionRuntime,
): Promise<ReturnType<typeof buildRouterAbEd25519WalletSessionStateFromExactRuntime>> {
  const authorization = await resolveActiveEd25519WalletSessionAuthorization(runtime.walletId);
  const expectedAuthority = await ed25519SealedRuntimeAuthorityRef(runtime);
  if (
    !authorization ||
    authorization.authMethod !== signingLaneAuthMethod(runtime.auth) ||
    authorization.authority.authorityDigest !== expectedAuthority.authorityDigest ||
    authorization.expiresAtMs <= Date.now()
  ) {
    throw new Error('[SigningEngine][near] active Wallet Session authorization is unavailable');
  }
  return buildRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    walletSessionJwt: authorization.walletSessionJwt,
    nowMs: Math.min(Date.now(), runtime.expiresAtMs - 1),
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

type EmailOtpEd25519YaoSilentRecoveryInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  signerSlot: number;
  thresholdSessionId: ThresholdEd25519SessionId;
  materialActivation: MpcMaterialActivationRef;
};

function isExactEmailOtpEd25519RecoveryRecord(args: {
  record: CurrentSealedSessionRecord;
  providerSubjectId: string;
  nearAccountId: string;
  signerSlot: number;
  materialActivation: MpcMaterialActivationRef;
}): boolean {
  const record = args.record;
  if (record.curve !== 'ed25519') return false;
  const restore = record.ed25519Restore;
  return (
    restore.providerSubjectId === args.providerSubjectId &&
    restore.nearAccountId === args.nearAccountId &&
    restore.signerSlot === args.signerSlot &&
    restore.materialActivation !== undefined &&
    mpcMaterialActivationRefsEqual(restore.materialActivation, args.materialActivation)
  );
}

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
  if (
    String(facts.thresholdSessionId) !== thresholdSessionId
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
  return args.material;
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
          emailOtpSessions: this.emailOtpSessions,
          sealedSigningSessionStore: deps.sealedSigningSessionStore,
        }),
      resolveActiveEd25519WalletSessionAuthorization,
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
      getWalletSessionStatus: createBrowserCanonicalWalletSessionStatusReader({
        seamsWebConfigs: this.seamsWebConfigs,
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
  ): Promise<NearEd25519YaoOperationMaterial> {
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
    const sealedRuntime = await requireExactEd25519SealedRuntimeForMaterialIdentity({
      walletId: args.walletId,
      identity,
    });
    const publicLocatorBase = nearEd25519PublicLocatorObservation({
      references: await this.ed25519YaoPublicCapabilityReferences.list(),
      walletId: identity.signer.account.wallet.walletId,
      nearAccountId: identity.signer.account.nearAccountId,
      signerSlot: identity.signer.signerSlot,
    });
    const activeCapability =
      publicLocatorBase.kind === 'available'
        ? this.enginePorts.ed25519YaoActiveClients.resolve({
            walletId: identity.signer.account.wallet.walletId,
            nearAccountId: identity.signer.account.nearAccountId,
            materialActivation: publicLocatorBase.materialActivation,
          })
        : null;
    const runtimeObservation = nearEd25519YaoRuntimeObservation(activeCapability);
    let hydration: MpcCapabilityHydrationPlan;
    switch (identity.auth.kind) {
      case WALLET_AUTH_METHODS.passkey: {
        const authority = await ed25519SealedRuntimeAuthorityRef(sealedRuntime);
        const publicLocator =
          publicLocatorBase.kind === 'available'
            ? { ...publicLocatorBase, authority }
            : publicLocatorBase;
        const localMaterial = await readPasskeyEd25519YaoLocalMaterialLocatorV1({
          store: IndexedDBManager,
          walletId: String(identity.signer.account.wallet.walletId),
          nearAccountId: String(identity.signer.account.nearAccountId),
          nearEd25519SigningKeyId: String(identity.signer.nearEd25519SigningKeyId),
          signerSlot: identity.signer.signerSlot,
          rpId: identity.auth.rpId,
          credentialIdB64u: identity.auth.credentialIdB64u,
        });
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
          unlockSource: { kind: 'unavailable' },
        });
        break;
      }
      case WALLET_AUTH_METHODS.emailOtp:
        hydration = await resolveEmailOtpEd25519YaoHydrationPlanForSigningV1({
          subject: {
            walletId: args.walletId,
            nearAccountId: args.nearAccountId,
            signerSlot: identity.signer.signerSlot,
            thresholdSessionId: identity.thresholdSessionId,
          },
          publicLocator: publicLocatorBase,
          runtime: runtimeObservation,
          readExactEd25519SealedSession,
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

  private async prepareExactNearEd25519YaoSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearEd25519YaoSigningPreparation> {
    if (args.laneIdentity === undefined) {
      return await this.prepareMaterialIdentityNearEd25519YaoSigning(args);
    }
    const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(args.walletId);
    switch (authorizationRead.kind) {
      case 'found': {
        const reusableSession = await this.readReusableWalletSessionState(args.walletId);
        if (
          reusableSession.kind !== 'active' ||
          reusableSession.walletSessionId !== authorizationRead.projection.walletSessionId ||
          reusableSession.authMethod !== authorizationRead.projection.authMethod
        ) {
          return await this.prepareMaterialIdentityNearEd25519YaoSigning(
            authNeutralNearEd25519BoundaryInput(args),
          );
        }
        const sealedRuntime = await requireExactEd25519SealedRuntimeForLane({
          walletId: args.walletId,
          laneIdentity: args.laneIdentity,
        });
        const walletSessionState = await walletSessionStateFromExactEd25519Runtime(sealedRuntime);
        const signer = walletSessionState.signingLane.identity.signer;
        const publicLocator = nearEd25519PublicLocatorObservation({
          references: await this.ed25519YaoPublicCapabilityReferences.list(),
          walletId: signer.account.wallet.walletId,
          nearAccountId: signer.account.nearAccountId,
          signerSlot: signer.signerSlot,
        });
        const activeMaterial =
          publicLocator.kind === 'available'
            ? this.enginePorts.ed25519YaoActiveClients.resolve({
                walletId: signer.account.wallet.walletId,
                nearAccountId: signer.account.nearAccountId,
                materialActivation: publicLocator.materialActivation,
              })
            : null;
        const hydration = await this.resolveExactNearEd25519YaoSigningHydration({
          args,
          walletSessionState,
          publicLocator,
          runtime: nearEd25519YaoRuntimeObservation(activeMaterial),
        });
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
      case 'missing':
        return await this.prepareMaterialIdentityNearEd25519YaoSigning(
          authNeutralNearEd25519BoundaryInput(args),
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
    let preparation = await this.prepareExactNearEd25519YaoSigning(args);
    if (
      args.laneIdentity !== undefined &&
      args.auth.kind === WALLET_AUTH_METHODS.emailOtp &&
      preparation.hydration.kind === 'rehydrate_material_activation'
    ) {
      const expectedActivation = requireNearEd25519YaoPreparationActivation(preparation);
      const recovery = await this.recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning({
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        signerSlot: args.laneIdentity.signer.signerSlot,
        thresholdSessionId: args.laneIdentity.thresholdSessionId,
        materialActivation: expectedActivation,
      });
      switch (recovery.kind) {
        case 'recovered':
          validateExactNearEd25519YaoOperationMaterial({
            material: recovery.recovery.material,
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
        resolveWalletSessionState: this.resolveExactNearEd25519YaoWalletSessionState.bind(
          this,
          context,
        ),
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
  ): Promise<NearEd25519YaoOperationMaterial> {
    const args = requireAuthorizedNearEd25519BoundaryInput(context.input);
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
        return validateExactNearEd25519YaoOperationMaterial({
          material: capability,
          input: args,
          expectedActivation,
        });
      }
      case 'rehydrate_material_activation':
        switch (args.auth.kind) {
          case WALLET_AUTH_METHODS.passkey:
            return validateExactNearEd25519YaoOperationMaterial({
              material:
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
                thresholdSessionId: args.laneIdentity.thresholdSessionId,
                materialActivation: expectedActivation,
              });
            switch (recovery.kind) {
              case 'recovered':
                return validateExactNearEd25519YaoOperationMaterial({
                  material: recovery.recovery.material,
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

  private async resolveExactNearEd25519YaoWalletSessionState(
    context: PreparedNearEd25519YaoMaterialContext,
  ): Promise<NearResolvedEd25519SigningSessionState> {
    const args = requireAuthorizedNearEd25519BoundaryInput(context.input);
    const runtime = await requireExactEd25519SealedRuntimeForLane({
      walletId: args.walletId,
      laneIdentity: args.laneIdentity,
    });
    return await walletSessionStateFromExactEd25519Runtime(runtime);
  }

  private async prepareExactNearEd25519YaoOperationStepUpAtBoundary(
    context: PreparedNearEd25519YaoMaterialContext,
    preparation: NearEd25519YaoSigningPreparation,
  ): Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation> {
    const args = requireAuthorizedNearEd25519BoundaryInput(context.input);
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
        const runtime = await requireExactEd25519SealedRuntimeForLane({
          walletId: args.walletId,
          laneIdentity: args.laneIdentity,
        });
        const walletSessionState = await walletSessionStateFromExactEd25519Runtime(runtime);
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
    walletSessionState: NearResolvedEd25519SigningSessionState;
    publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1;
    runtime: NearEd25519YaoRuntimeObservationV1;
  }): Promise<MpcCapabilityHydrationPlan> {
    const args = requireAuthorizedNearEd25519BoundaryInput(input.args);
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
                thresholdSessionId: args.laneIdentity.thresholdSessionId,
          },
          publicLocator: input.publicLocator,
          runtime: input.runtime,
          readExactEd25519SealedSession,
        });
      default:
        args.auth satisfies never;
        throw new Error('[SigningEngine][near] unsupported Ed25519 material authority');
    }
  }

  private async prepareExactPasskeyEd25519YaoOperationStepUpForSigning(
    args: PrepareNearEd25519YaoMaterialBoundaryInput,
  ): Promise<NearPasskeyEd25519OperationStepUpCapabilityPreparation> {
    const authorizedArgs = requireAuthorizedNearEd25519BoundaryInput(args);
    const lane = await this.resolveNearEd25519YaoSigningLane({
      kind: 'exact_lane',
      walletId: authorizedArgs.walletId,
      nearAccountId: authorizedArgs.nearAccountId,
      signerSlot: authorizedArgs.laneIdentity.signer.signerSlot,
      thresholdSessionId: authorizedArgs.laneIdentity.thresholdSessionId,
      laneIdentity: authorizedArgs.laneIdentity,
    });
    if (!lane) {
      throw new Error('[SigningEngine][near] sealed Ed25519 operation lane is unavailable');
    }
    const runtime = await requireExactEd25519SealedRuntimeForLane({
      walletId: authorizedArgs.walletId,
      laneIdentity: authorizedArgs.laneIdentity,
    });
    const walletSessionState = await walletSessionStateFromExactEd25519Runtime(runtime);
    const credentialIdB64u =
      runtime.factor.kind === 'passkey' ? runtime.factor.credentialIdB64u : '';
    const rpId = runtime.factor.kind === 'passkey' ? runtime.factor.rpId : '';
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
      participantIds: [...runtime.participantIds],
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
      walletSessionState: NearResolvedEd25519SigningSessionState;
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
        readExactEd25519SealedSession,
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
          this.persistEmailOtpEd25519YaoCapabilityForRefreshInternal.bind(this),
        fetch: fetchWithGlobalThis,
        nowMs: Date.now,
      },
    });
    return result;
  }

  private async resolveExactPasskeyEd25519YaoExportContext(
    args: Parameters<RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext']>[0],
  ): ReturnType<RecoveryPublicDeps['ed25519Yao']['resolvePasskeyExportContext']> {
    const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
    if (!relayerUrl) {
      throw new Error('[SigningEngine][ed25519-export] passkey export requires relayerUrl');
    }
    return await resolvePasskeyEd25519YaoExportContextV1({
      subject: {
        walletId: String(args.laneIdentity.signer.account.wallet.walletId),
        nearAccountId: String(args.laneIdentity.signer.account.nearAccountId),
        signerSlot: args.laneIdentity.signer.signerSlot,
        thresholdSessionId: args.laneIdentity.thresholdSessionId,
        materialActivation: args.materialActivation,
      },
      relayerUrl,
      fetch: fetchWithGlobalThis,
    });
  }

  private async resolveEmailOtpEd25519YaoExportContext(
    args: {
      laneIdentity: Parameters<typeof resolveEmailOtpEd25519YaoExportContextV1>[0]['subject'];
      materialActivation: MpcMaterialActivationRef;
    },
  ): Promise<ResolvedEmailOtpEd25519YaoExportV1> {
    const relayerUrl = String(this.seamsWebConfigs.network.relayer?.url || '').trim();
    if (!relayerUrl) {
      throw new Error('[SigningEngine][ed25519-export] Email OTP export requires relayerUrl');
    }
    return await resolveEmailOtpEd25519YaoExportContextV1({
      subject: args.laneIdentity,
      expectedMaterialActivation: args.materialActivation,
      relayerUrl,
      ports: {
        readExactEd25519SealedSession,
        readActiveWalletSessionAuthorization: walletSessionAuthorizations.readActiveForWallet.bind(
          walletSessionAuthorizations,
        ),
        fetch: fetchWithGlobalThis,
      },
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
      subject.kind === 'exact_lane' || subject.kind === 'export_exact_lane'
        ? subject.laneIdentity
        : exactEd25519LaneIdentityFromAvailableLane(lane);
    const runtime =
      subject.kind === 'export_exact_lane'
        ? await requireExactEd25519SealedRuntimeForExport({
            walletId: subject.walletId,
            laneIdentity,
            materialActivation: subject.materialActivation,
          })
        : await requireExactEd25519SealedRuntimeForLane({
            walletId: subject.walletId,
            laneIdentity,
          });
    const walletSessionState = await walletSessionStateFromExactEd25519Runtime(runtime);
    const credentialIdB64u =
      runtime.factor.kind === 'passkey' ? runtime.factor.credentialIdB64u : '';
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
    walletSessionState: NearResolvedEd25519SigningSessionState;
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
      liveMaterial:
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
    const sealedRecords = await listExactSealedSessionsForWallet({
      walletId: String(resolved.identity.walletId),
      filter: { authMethod: 'email_otp', curve: 'ed25519' },
    });
    const exactRecords: CurrentSealedSessionRecord[] = [];
    for (const record of sealedRecords) {
      if (
        isExactEmailOtpEd25519RecoveryRecord({
          record,
          providerSubjectId: resolved.providerSubject,
          nearAccountId: String(resolved.user.nearAccountId),
          signerSlot: resolved.user.signerSlot,
          materialActivation: resolved.identity.materialActivation,
        })
      ) {
        exactRecords.push(record);
      }
    }
    if (exactRecords.length !== 1) {
      throw new Error(
        'Email OTP Ed25519 Yao login requires an exact persisted authorization session',
      );
    }
    const authorizationRecord = exactRecords[0];
    const authorizationRestore = authorizationRecord.ed25519Restore;
    if (authorizationRecord.curve !== 'ed25519' || !authorizationRestore) {
      throw new Error(
        'Email OTP Ed25519 Yao login requires exact Ed25519 restore metadata',
      );
    }
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
      authorizationRestore.runtimePolicyScope,
    );
    if (!runtimePolicyScope) {
      throw new Error(
        'Email OTP Ed25519 Yao login requires an exact persisted runtime policy scope',
      );
    }
    return prepareColdEmailOtpEd25519YaoRecoveryV1({
      identity: resolved.identity,
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
        authorizationRecord.thresholdSessionIds.ed25519,
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

  async persistEmailOtpEd25519YaoCapabilityForRefreshInternal(
    input: EmailOtpEd25519YaoPublicationInput,
  ): Promise<void> {
    await this.emailOtpSessions.persistEd25519YaoCapabilityForRefresh(input);
  }

  async activateEmailOtpEd25519YaoUnlockedRecoveryInternal(args: {
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  }): Promise<NearEd25519SignerBinding> {
    return await withThresholdEd25519CommitQueue({
      queueByKey: this.thresholdEd25519CommitQueueByKey,
      queueKey: resolveThresholdEd25519CommitQueueKey({
        materialActivation: args.prepared.identity.materialActivation,
      }),
      nearAccountId: args.prepared.identity.nearAccountId,
      enabled: true,
      task: this.runEmailOtpEd25519YaoUnlockedRecoveryActivation.bind(this, args),
    });
  }

  private async runEmailOtpEd25519YaoUnlockedRecoveryActivation(args: {
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  }): Promise<NearEd25519SignerBinding> {
    const recovered = await activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
      prepared: args.prepared,
      bootstrap: args.bootstrap,
      pendingFactorHandle: args.pendingFactorHandle,
      workerContext: this.signerWorkerManager.getContext(),
      activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
        this.enginePorts.ed25519YaoActiveClients,
      ),
    });
    await this.persistEmailOtpEd25519YaoCapabilityForRefreshInternal({
      material: recovered.material,
      walletSessionState: recovered.walletSessionState,
      publicationContext: recovered.publicationContext,
    });
    this.requireCurrentEmailOtpEd25519Activation(args.prepared);
    return recovered.walletSessionState.signingLane.identity.signer;
  }

  async activateEmailOtpEd25519YaoLocalCapabilityInternal(args: {
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    activeClientHandle: string;
    metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  }): Promise<NearEd25519SignerBinding> {
    return await withThresholdEd25519CommitQueue({
      queueByKey: this.thresholdEd25519CommitQueueByKey,
      queueKey: resolveThresholdEd25519CommitQueueKey({
        materialActivation: args.prepared.identity.materialActivation,
      }),
      nearAccountId: args.prepared.identity.nearAccountId,
      enabled: true,
      task: this.runEmailOtpEd25519YaoLocalCapabilityActivation.bind(this, args),
    });
  }

  private async runEmailOtpEd25519YaoLocalCapabilityActivation(args: {
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    activeClientHandle: string;
    metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  }): Promise<NearEd25519SignerBinding> {
    const activated = await activateEmailOtpEd25519YaoLocalCapabilityV1({
      prepared: args.prepared,
      bootstrap: args.bootstrap,
      activeClientHandle: args.activeClientHandle,
      metadata: args.metadata,
      workerContext: this.signerWorkerManager.getContext(),
      activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
        this.enginePorts.ed25519YaoActiveClients,
      ),
    });
    await this.persistEmailOtpEd25519YaoCapabilityForRefreshInternal({
      material: activated.material,
      walletSessionState: activated.walletSessionState,
      publicationContext: activated.publicationContext,
    });
    this.requireCurrentEmailOtpEd25519Activation(args.prepared);
    return activated.walletSessionState.signingLane.identity.signer;
  }

  async loginWithEmailOtpEd25519YaoCapabilityInternal(
    args: LoginWithEmailOtpEd25519YaoCapabilityInternalArgs,
  ): Promise<NearEd25519SignerBinding> {
    const prepared = await this.prepareEmailOtpEd25519YaoLoginRecoveryInternal({
      walletSession: args.walletSession,
      remainingUses: args.remainingUses,
      emailHashHex: args.emailHashHex,
    });
    if (!prepared) {
      throw new Error('Email OTP Ed25519 Yao login requires a persisted signer capability');
    }
    return await withThresholdEd25519CommitQueue({
      queueByKey: this.thresholdEd25519CommitQueueByKey,
      queueKey: resolveThresholdEd25519CommitQueueKey({
        materialActivation: prepared.identity.materialActivation,
      }),
      nearAccountId: prepared.identity.nearAccountId,
      enabled: true,
      task: this.runEmailOtpEd25519YaoCapabilityLogin.bind(this, {
        args,
        prepared,
      }),
    });
  }

  private async runEmailOtpEd25519YaoCapabilityLogin(input: {
    args: LoginWithEmailOtpEd25519YaoCapabilityInternalArgs;
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
  }): Promise<NearEd25519SignerBinding> {
    const recovered = await recoverColdEmailOtpEd25519CapabilityForLoginV1({
      prepared: input.prepared,
      challengeId: input.args.challengeId,
      otpCode: input.args.otpCode,
      appSessionJwt: input.args.appSessionJwt,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      workerContext: this.signerWorkerManager.getContext(),
      activateCapability: this.enginePorts.ed25519YaoActiveClients.activate.bind(
        this.enginePorts.ed25519YaoActiveClients,
      ),
    });
    await this.persistEmailOtpEd25519YaoCapabilityForRefreshInternal({
      material: recovered.material,
      walletSessionState: recovered.walletSessionState,
      publicationContext: recovered.publicationContext,
    });
    this.requireCurrentEmailOtpEd25519Activation(input.prepared);
    return recovered.walletSessionState.signingLane.identity.signer;
  }

  private requireCurrentEmailOtpEd25519Activation(
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1,
  ): void {
    const current = this.enginePorts.ed25519YaoActiveClients.resolve({
      walletId: prepared.identity.walletId,
      nearAccountId: prepared.identity.nearAccountId,
      materialActivation: prepared.identity.materialActivation,
    });
    if (!current) {
      throw new Error(
        '[SigningEngine][near] Email OTP Ed25519 activation was superseded during commit',
      );
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

  async getWarmThresholdEd25519SessionStatus(args: {
    walletId: WalletId | string;
    nearAccountId: AccountId | string;
    nearEd25519SigningKeyId: string;
  }): Promise<SigningSessionStatus | null> {
    const walletId = toWalletId(args.walletId);
    const nearAccountId = toAccountId(args.nearAccountId);
    const resolution =
      await resolveExactEd25519SealedSessionRuntimeForWalletSubject({
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
          args.nearEd25519SigningKeyId,
        ),
      });
    if (resolution.kind === 'missing') return null;
    if (resolution.kind !== 'resolved') {
      throw new Error(
        `[WarmSessionStore] Ed25519 sealed runtime is ${resolution.kind}`,
      );
    }
    const authorization =
      await resolveActiveEd25519WalletSessionAuthorization(walletId);
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
