import { BrowserSigningSurface } from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import {
  walletSessionAuthorizations,
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  addWalletSigner as addWalletSignerWithUnifiedCeremony,
  isRegistrationBenchmarkDiagnosticsEnabled,
  registerWallet as registerWalletWithUnifiedCeremony,
  WALLET_IFRAME_TRANSPORT_TIMING_LABEL,
} from '@/SeamsWeb/operations/registration/registration';
import { addPasskeyWalletAuthMethod } from '@/SeamsWeb/operations/authMethods/passkey/addPasskey';
import { MinimalNearClient, type NearClient } from '@/core/rpcClients/near/NearClient';
import type {
  ActionResult,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  RegistrationResult,
  ThemeMode,
  AppearanceConfig,
  AppearanceConfigInput,
  EmailOtpAuthPolicy,
  SeamsConfigsReadonly,
  SeamsConfigsInput,
} from '@/core/types/seams';
import type {
  ActionHooksOptions,
  CreateRegistrationFlowEventInput,
  CreateUnlockFlowEventInput,
  KeyExportHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  RegistrationFlowEvent,
  NearProvisioningStateChangedEvent,
  SdkLifecycleEvent,
  SdkLifecycleEventListener,
  UnlockFlowEvent,
  SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  createRegistrationFlowEvent,
  createUnlockFlowEvent,
  RegistrationEventPhase,
  UnlockEventPhase,
} from '@/core/types/sdkSentEvents';
import { readNearProvisioningState } from '@/core/signingEngine/flows/registration/nearProvisioningRegistry';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { toAccountId } from '@/core/types/accountIds';
import { IndexedDBManager } from '@/core/indexedDB';
import type {
  HostedAuthMenuExternalAuthRequest,
  HostedAuthMenuDemoEmailOtpDelivery,
  HostedAuthMenuExternalAuthResolutionInput,
  HostedAuthMenuOpenRequest,
  HostedAuthMenuOutcome,
  HostedAuthMenuSessionId,
  PreferencesChangedPayload,
} from '@/SeamsWeb/walletIframe/shared/messages';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import { isUserCancellationError, toError } from '@shared/utils/errors';
import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { sha256HexUtf8 } from '@shared/utils/digests';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import {
  walletAuthAuthoritiesMatch,
  type ActiveWalletSession,
} from '@shared/utils/walletAuthAuthority';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { resolveAppearanceTheme, resolveThemePalette } from '@/core/config/configHelpers';
import { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import {
  parseWalletIframeExactSessionIdentity,
  type WalletIframeExactSessionIdentity,
  type WalletIframeExactSessionIdentityInput,
  type WalletIframeExactSessionLockResult,
  type WalletIframeExactSessionState,
} from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import { resolveBrowserWorkerWarmupPolicy } from './assembly/browserWorkerWarmupPolicy';
import { configureBrowserIndexedDB } from './assembly/configureBrowserIndexedDB';
import {
  createBrowserHostPlatformRuntime,
  createBrowserSigningRuntime,
} from './assembly/createBrowserSigningRuntime';
import { createBrowserSigningStores } from './assembly/createBrowserSigningStores';
import { initializeBrowserSigningRuntime } from './assembly/initializeBrowserSigningRuntime';
import {
  getWalletSessionDomain,
  type WalletAuthDomainDeps,
} from '@/SeamsWeb/operations/auth/walletAuth';
import {
  createPublicApi,
  createWalletIframeLinkedDeviceManagementPortV1,
  type DevicesCapabilityDomainMethods,
  type LinkedDeviceManagementPortV1,
  type WalletIframeControlCapability,
} from './publicApi';
import { createWalletHostCompositionV1 } from './operations/devices/walletHostComposition';
import { createWalletHostOwnerAuthoritiesV1 } from './operations/devices/walletHostOwnerAuthority';
import type {
  LinkSessionOwnerApprovalUpdatesPortV1,
  LinkSessionOwnerAuthenticatedRequestPortV1,
} from './operations/devices/deviceLinkingOwnerTransport';
import { LINKED_DEVICE_SESSION_HTTP_BASE_PATH_V1 } from './operations/devices/deviceLinkingHttpTransport';
import { readOwnerWalletExecutionLaneProjectionV1 } from '@/core/rpcClients/relayer/ownerWalletExecutionLanePreflight';
import {
  isConcreteAvailableSigningLane,
  type AvailableSigningLanes,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  walletCustodyCeremonyTransportFromWorkerContextV1,
  readUnlockedWalletEd25519ExportRootCapabilityV1,
} from '@/core/signingEngine/walletCustody/unlockedEd25519ExportRootCapability';
import {
  parseLinkedDeviceApprovalResultV1,
  type LinkedDeviceOwnerSourceLaneV1,
} from '@shared/device-linking';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '@shared/utils/ecdsaCapabilityActivation';
import type {
  AuthCapability,
  DevicesCapability,
  EmailOtpChallengeResult,
  EmailOtpOperationChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  SeamsWebContext,
  SeamsWebSigningSurface,
  PreferencesCapability,
  RegistrationCapability,
  RecoveryCapability,
  TempoSignerCapability,
} from '@/SeamsWeb/signingSurface/types';
import type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { UiConfirmSurfaceMeasurementBinding } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  EnrollEmailOtpInternalResult,
  LoginWithEmailOtpEcdsaCapabilityInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import {
  thresholdEcdsaChainTargetsEqual,
  configuredThresholdEcdsaChainTargets,
  nearAccountRefFromAccountId,
  toWalletId,
  thresholdEcdsaChainTargetFromRequest,
  walletSessionRefFromSession,
  type NearAccountRef,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  resolveConfiguredChainTarget,
  type EcdsaChainSelector,
} from '@/SeamsWeb/publicApi/chainTargets';
import type { SigningEngineExportKeypairWithUIInput } from '@/core/signingEngine/flows/recovery/public';
import type { TempoChainTarget } from '@/core/platform/types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import {
  requireTempoFeeTokenPreferenceSigningRequest,
  type TempoFeeTokenPreferenceSigningRequest,
} from '@/core/signingEngine/chains/tempo/feeToken';
import {
  parseExactEcdsaSigningLaneIdentity,
  parseExactEd25519ExportMaterialIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  assertWalletRuntimePostconditions,
  type WalletRuntimeInventory,
} from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import { configuredEmailOtpEcdsaSnapshotChainTargets } from '@/core/signingEngine/session/emailOtp/persistedSnapshot';
import type { LoginWithEmailOtpWalletCustodyEd25519Args } from '@/core/signingEngine/walletCustody/ed25519Login';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import {
  requestEmailOtpChallenge,
  requestEmailOtpEnrollmentChallenge,
  resolveGoogleEmailOtpProvider,
} from '@/SeamsWeb/operations/authMethods/emailOtp/challenge';
import {
  beginGoogleEmailOtpWalletAuth,
  type GoogleEmailOtpWalletAuthDeps,
} from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import {
  buildWalletCustodyPasskeyFactorProof,
  rotateWalletRecoveryCodes,
} from '@/SeamsWeb/operations/recovery/walletRecoveryRotation';
import { showWalletRecoveryCodeBackupUi } from '@/SeamsWeb/operations/recovery/walletRecoveryCodeBackup';
import { pendingWalletRecoveryCodeBackupRepository } from '@/core/indexedDB/seamsWalletDB/pendingWalletRecoveryCodeBackup';
import {
  acknowledgeWalletRecoveryBackup,
  requestWalletCustodyEmailOtpChallenge,
  readWalletRecoveryCodeStatus,
} from '@/core/rpcClients/relayer/walletRecoveryRotate';
import {
  activateEmailOtpWalletAfterUnlock,
  type EmailOtpWalletPostUnlockActivation,
} from '@/SeamsWeb/operations/authMethods/emailOtp/walletActivation';
import type { RegistrationSignerSetSelection } from '@shared/utils/registrationIntent';
import {
  nearAccountBindingFromRaw,
  type NearAccountBinding,
  type NearEd25519SignerBinding,
} from '@shared/utils/walletCapabilityBindings';
import {
  buildNearWalletRegistrationSignerSetSelection,
  resolvePasskeyRegistrationAccountProvisioning,
} from '@/SeamsWeb/operations/registration/registrationSignerSet';
import { createServerAllocatedWalletId } from '@shared/utils/registrationIntent';
import { isObject } from '@shared/utils/validation';

type EmailOtpWalletCustodyEd25519LoginDomainArgs = Omit<
  LoginWithEmailOtpWalletCustodyEd25519Args,
  'emailHashHex'
>;

///////////////////////////////////////
// PASSKEY MANAGER
///////////////////////////////////////

type InternalEmailOtpEcdsaCapabilityArgs = EmailOtpEcdsaCapabilityArgs & {
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
};

type EmailOtpUnlockActiveRuntimeState = {
  kind: 'email_otp_unlock_active_runtime_state_v1';
  inventory: WalletRuntimeInventory;
};

type EmailOtpUnlockActivationPlan = {
  kind: 'email_otp_unlock_activation_plan_v1';
  mode: 'evm_family_ecdsa';
  activeAuthorization: ActiveWalletSessionAuthorizationProjection;
  authorizations: readonly [
    ActiveWalletSessionAuthorizationProjection,
    ...ActiveWalletSessionAuthorizationProjection[],
  ];
  runtimeState: EmailOtpUnlockActiveRuntimeState;
};

type EmailOtpUnlockTimingBucket =
  | 'emailOtpProofVerificationMs'
  | 'walletUnlockExchangeMs'
  | 'ecdsaMaterialRestoreMs'
  | 'signingSessionSealApplyMs'
  | 'warmCapabilityPersistenceMs'
  | 'activeRuntimeConstructionMs'
  | 'emailHashLookupMs'
  | 'workerUnlockAndSessionBootstrapMs'
  | 'walletStateActivationMs'
  | 'runtimePostconditionMs'
  | 'walletIframeRoundTripMs';

type EmailOtpUnlockTimingSummary = {
  kind: 'email_otp_unlock_timing_summary_v1';
  status: 'succeeded' | 'failed';
  mode: 'evm_family_ecdsa';
  walletId: string;
  prewarm: EmailOtpUnlockPrewarmSnapshot;
  chainTarget?: ThresholdEcdsaChainTarget;
  totalElapsedMs: number;
  timings: Record<EmailOtpUnlockTimingBucket, number>;
  topBuckets: { bucket: EmailOtpUnlockTimingBucket; durationMs: number }[];
  errorMessage?: string;
};

type EmailOtpUnlockPrewarmScope =
  | {
      kind: 'global';
      walletId?: never;
      nearAccountId?: never;
    }
  | {
      kind: 'near_account_bound';
      walletId: string;
      nearAccountId: string;
    };

type EmailOtpUnlockPrewarmRequest =
  | {
      kind: 'iframe_and_local_resources';
    }
  | {
      kind: 'local_worker_resources';
    };

type EmailOtpUnlockPrewarmRecord =
  | {
      kind: 'none';
      status?: never;
      completedAtMs?: never;
      request?: never;
      scope?: never;
    }
  | {
      kind: 'attempted';
      status: 'succeeded' | 'failed';
      completedAtMs: number;
      request: EmailOtpUnlockPrewarmRequest;
      scope: EmailOtpUnlockPrewarmScope;
    };

type EmailOtpUnlockPrewarmSnapshot =
  | {
      kind: 'not_prewarmed';
      status?: never;
      ageMs?: never;
      completedAtMs?: never;
      request?: never;
      scope?: never;
      walletMatches?: never;
    }
  | {
      kind: 'prewarm_attempted';
      status: 'succeeded' | 'failed';
      ageMs: number;
      completedAtMs: number;
      request: EmailOtpUnlockPrewarmRequest;
      scope: EmailOtpUnlockPrewarmScope;
      walletMatches: boolean;
    };

function nowMs(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function createEmailOtpUnlockTimings(): Record<EmailOtpUnlockTimingBucket, number> {
  return {
    emailOtpProofVerificationMs: 0,
    walletUnlockExchangeMs: 0,
    ecdsaMaterialRestoreMs: 0,
    signingSessionSealApplyMs: 0,
    warmCapabilityPersistenceMs: 0,
    activeRuntimeConstructionMs: 0,
    emailHashLookupMs: 0,
    workerUnlockAndSessionBootstrapMs: 0,
    walletStateActivationMs: 0,
    runtimePostconditionMs: 0,
    walletIframeRoundTripMs: 0,
  };
}

function recordEmailOtpUnlockTiming(
  timings: Record<EmailOtpUnlockTimingBucket, number>,
  bucket: EmailOtpUnlockTimingBucket,
  startedAtMs: number,
): void {
  addEmailOtpUnlockTiming(timings, bucket, nowMs() - startedAtMs);
}

function recordEmailOtpUnlockElapsedTiming(
  timings: Record<EmailOtpUnlockTimingBucket, number>,
  bucket: EmailOtpUnlockTimingBucket,
  durationMs: number,
): void {
  addEmailOtpUnlockTiming(timings, bucket, durationMs);
}

function addEmailOtpUnlockTiming(
  timings: Record<EmailOtpUnlockTimingBucket, number>,
  bucket: EmailOtpUnlockTimingBucket,
  durationMs: number,
): void {
  const deltaMs = Math.max(0, Math.round(durationMs));
  timings[bucket] += deltaMs;
  if (!isEmailOtpUnlockDiagnosticsEnabled()) return;
  console.info('[EmailOtpUnlock] timing', {
    bucket,
    deltaMs,
    accumulatedMs: timings[bucket],
  });
}

function isEmailOtpUnlockDiagnosticsEnabled(): boolean {
  return Reflect.get(globalThis, '__SEAMS_EMAIL_OTP_UNLOCK_DIAGNOSTICS') === true;
}

function logEmailOtpUnlockTimingSummary(input: {
  status: EmailOtpUnlockTimingSummary['status'];
  mode: EmailOtpUnlockTimingSummary['mode'];
  walletId: string;
  prewarm: EmailOtpUnlockPrewarmSnapshot;
  startedAtMs: number;
  timings: Record<EmailOtpUnlockTimingBucket, number>;
  chainTarget?: ThresholdEcdsaChainTarget;
  error?: unknown;
}): void {
  if (!isEmailOtpUnlockDiagnosticsEnabled()) return;
  const entries = Object.entries(input.timings) as [EmailOtpUnlockTimingBucket, number][];
  const topBuckets = entries
    .filter(([, durationMs]) => durationMs > 0)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([bucket, durationMs]) => ({ bucket, durationMs }));
  const errorMessage =
    input.error instanceof Error ? input.error.message : input.error ? String(input.error) : '';
  const summary: EmailOtpUnlockTimingSummary = {
    kind: 'email_otp_unlock_timing_summary_v1',
    status: input.status,
    mode: input.mode,
    walletId: input.walletId,
    prewarm: input.prewarm,
    ...(input.chainTarget ? { chainTarget: input.chainTarget } : {}),
    totalElapsedMs: Math.max(0, Math.round(nowMs() - input.startedAtMs)),
    timings: input.timings,
    topBuckets,
    ...(errorMessage ? { errorMessage } : {}),
  };
  console.info('[EmailOtpUnlock] timing summary', summary);
}

function emailOtpUnlockPrewarmScopeFromBinding(
  nearAccountBinding: NearAccountBinding | undefined,
): EmailOtpUnlockPrewarmScope {
  if (!nearAccountBinding) return { kind: 'global' };
  return {
    kind: 'near_account_bound',
    walletId: String(nearAccountBinding.wallet.walletId),
    nearAccountId: String(nearAccountBinding.nearAccountId),
  };
}

function emailOtpUnlockPrewarmRequestFromOptions(
  opts: SeamsWebPrewarmOptions | undefined,
): EmailOtpUnlockPrewarmRequest | null {
  if (opts?.iframe) return { kind: 'iframe_and_local_resources' };
  if (opts?.workers) return { kind: 'local_worker_resources' };
  return null;
}

function emailOtpUnlockPrewarmSnapshot(args: {
  record: EmailOtpUnlockPrewarmRecord;
  walletId: string;
  nowMs: number;
}): EmailOtpUnlockPrewarmSnapshot {
  if (args.record.kind === 'none') {
    return { kind: 'not_prewarmed' };
  }
  const scope = args.record.scope;
  return {
    kind: 'prewarm_attempted',
    status: args.record.status,
    completedAtMs: args.record.completedAtMs,
    ageMs: Math.max(0, Math.round(args.nowMs - args.record.completedAtMs)),
    request: args.record.request,
    scope,
    walletMatches: scope.kind === 'global' || scope.walletId === args.walletId,
  };
}

function emailOtpUnlockActiveRuntimeState(
  inventory: WalletRuntimeInventory,
): EmailOtpUnlockActiveRuntimeState {
  return {
    kind: 'email_otp_unlock_active_runtime_state_v1',
    inventory,
  };
}

function buildEmailOtpEcdsaUnlockActivationPlan(args: {
  walletSession: WalletSessionRef;
  result: LoginWithEmailOtpEcdsaCapabilityInternalResult;
  runtimeInventory: WalletRuntimeInventory;
}): EmailOtpUnlockActivationPlan {
  if (args.result.authorization.walletId !== args.walletSession.walletId) {
    throw new Error('Email OTP unlock authorization does not match the wallet session');
  }
  return {
    kind: 'email_otp_unlock_activation_plan_v1',
    mode: 'evm_family_ecdsa',
    activeAuthorization: args.result.authorization,
    authorizations: args.result.authorizations,
    runtimeState: emailOtpUnlockActiveRuntimeState(args.runtimeInventory),
  };
}

function logEmailOtpUnlockActivationPlan(plan: EmailOtpUnlockActivationPlan): void {
  if (!isEmailOtpUnlockDiagnosticsEnabled()) return;
  console.info('[EmailOtpUnlock] activation plan constructed', {
    kind: plan.kind,
    mode: plan.mode,
    walletId: plan.activeAuthorization.walletId,
    authorityDigest: plan.activeAuthorization.authority.authorityDigest,
    walletSessionIds: plan.authorizations.map((authorization) => authorization.walletSessionId),
    runtimeTargetCount: plan.runtimeState.inventory.ecdsaByTarget.size,
  });
}

type SeamsWebPrewarmOptions =
  | {
      iframe?: boolean;
      workers?: boolean;
      walletId?: never;
      nearAccountId?: never;
    }
  | {
      iframe?: boolean;
      workers?: boolean;
      walletId: string;
      nearAccountId: string;
    };

function nearAccountBindingKindFromId(nearAccountId: string): NearAccountBinding['kind'] {
  return nearAccountId.length === 64 && /^[0-9a-f]+$/i.test(nearAccountId)
    ? 'implicit_near_account'
    : 'named_near_account';
}

function requireNearAccountBindingForOperation(args: {
  walletId: string;
  nearAccountId: string;
  operation: string;
}): NearAccountBinding {
  const walletId = String(args.walletId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  if (!walletId || !nearAccountId) {
    throw new Error(`[SeamsWeb] ${args.operation} requires walletId and nearAccountId`);
  }
  const parsed = nearAccountBindingFromRaw({
    kind: nearAccountBindingKindFromId(nearAccountId),
    wallet: { walletId },
    nearAccountId,
  });
  if (!parsed.ok) {
    throw new Error(`[SeamsWeb] ${args.operation} requires a valid NEAR account binding`);
  }
  return parsed.value;
}

function resolvePrewarmNearAccountBinding(
  opts: SeamsWebPrewarmOptions | undefined,
): NearAccountBinding | undefined {
  const walletId = String(opts?.walletId || '').trim();
  const nearAccountId = String(opts?.nearAccountId || '').trim();
  if (!walletId && !nearAccountId) return undefined;
  return requireNearAccountBindingForOperation({
    walletId,
    nearAccountId,
    operation: 'prewarm',
  });
}

function requireConcreteEcdsaChainTarget(
  value: unknown,
  operation: string,
): ThresholdEcdsaChainTarget {
  if (!isObject(value)) {
    throw new Error(`[SeamsWeb] ${operation} requires a concrete ECDSA chainTarget`);
  }
  return thresholdEcdsaChainTargetFromRequest(value);
}

// The public `options` bag is optional; it is normalized before it reaches the
// boundary, so everything below always sees a resolved one.
type ExportKeypairWithUIBoundaryInput = SigningEngineExportKeypairWithUIInput;
type ResolveExactKeyExportLaneBoundaryInput = Parameters<
  KeyExportCapability['resolveExactKeyExportLane']
>[0];
type ResolveExactKeyExportLaneBoundaryResult = Awaited<
  ReturnType<KeyExportCapability['resolveExactKeyExportLane']>
>;

function normalizeResolveExactKeyExportLaneInput(
  input: ResolveExactKeyExportLaneBoundaryInput,
): ResolveExactKeyExportLaneBoundaryInput {
  switch (input.kind) {
    case 'ecdsa':
      return {
        kind: 'ecdsa',
        walletSession: walletSessionRefFromSession(input.walletSession),
        chainTarget: thresholdEcdsaChainTargetFromRequest(input.chainTarget),
      };
    case 'ed25519':
      return {
        kind: 'ed25519',
        walletSession: walletSessionRefFromSession(input.walletSession),
        nearAccount: nearAccountRefFromAccountId(input.nearAccount.accountId),
      };
  }
}

function normalizeResolveExactKeyExportLaneResult(
  result: ResolveExactKeyExportLaneBoundaryResult,
): ResolveExactKeyExportLaneBoundaryResult {
  switch (result.kind) {
    case 'relink_required':
      return {
        kind: 'relink_required',
        reason: result.reason,
      };
    case 'ecdsa':
      return {
        kind: 'ecdsa',
        laneIdentity: parseExactEcdsaSigningLaneIdentity(result.laneIdentity),
      };
    case 'ed25519': {
      const materialActivation = parseMpcMaterialActivationRef(result.materialActivation);
      if (!materialActivation.ok) throw new Error(materialActivation.error.message);
      return {
        kind: 'ed25519',
        laneIdentity: parseExactEd25519ExportMaterialIdentity(result.laneIdentity),
        materialActivation: materialActivation.value,
      };
    }
  }
}

function normalizeExportKeypairWithUIInput(
  input: ExportKeypairWithUIBoundaryInput,
  theme: ThemeMode,
): ExportKeypairWithUIBoundaryInput {
  const resolvedOptions = {
    ...input.options,
    theme: input.options.theme ?? theme,
  };
  switch (input.kind) {
    case 'ecdsa': {
      const laneIdentity = parseExactEcdsaSigningLaneIdentity(input.laneIdentity);
      if (String(laneIdentity.signer.walletId) !== String(input.walletSession.walletId)) {
        throw new Error('[SeamsWeb] key export lane wallet does not match wallet session');
      }
      if (!thresholdEcdsaChainTargetsEqual(laneIdentity.signer.chainTarget, input.chainTarget)) {
        throw new Error('[SeamsWeb] key export lane chain target does not match request target');
      }
      return {
        kind: 'ecdsa',
        chainTarget: input.chainTarget,
        walletSession: input.walletSession,
        laneIdentity,
        options: resolvedOptions,
      };
    }
    case 'ed25519': {
      const laneIdentity = parseExactEd25519ExportMaterialIdentity(input.laneIdentity);
      const materialActivation = parseMpcMaterialActivationRef(input.materialActivation);
      if (!materialActivation.ok) throw new Error(materialActivation.error.message);
      if (
        String(laneIdentity.signer.account.wallet.walletId) !== String(input.walletSession.walletId)
      ) {
        throw new Error('[SeamsWeb] Ed25519 export lane wallet does not match wallet session');
      }
      if (
        String(laneIdentity.signer.account.nearAccountId) !== String(input.nearAccount.accountId)
      ) {
        throw new Error('[SeamsWeb] Ed25519 export lane does not match the NEAR account');
      }
      return {
        kind: 'ed25519',
        nearAccount: nearAccountRefFromAccountId(input.nearAccount.accountId),
        walletSession: input.walletSession,
        laneIdentity,
        materialActivation: materialActivation.value,
        options: resolvedOptions,
      };
    }
  }
}

function resolveRuntimeAppearance(
  current: AppearanceConfig,
  input: AppearanceConfigInput,
): AppearanceConfig {
  const rawInput = input as Record<string, unknown>;
  return {
    theme: resolveAppearanceTheme({
      value: rawInput.theme,
      fallback: current.theme,
      legacyTokens: rawInput.tokens,
    }),
    palette: resolveThemePalette({
      value: rawInput.palette,
      fallback: current.palette,
    }),
  };
}

type SeamsWebRuntimeMode = 'application' | 'wallet_host';
export type SeamsWebInternalOptions =
  | {
      readonly kind: 'application';
    }
  | {
      readonly kind: 'wallet_host';
    };

type SeamsWebLifecycleEventSource =
  | {
      readonly kind: 'signing_engine';
      readonly source: Pick<SeamsWebSigningSurface, 'onSdkLifecycleEvent'>;
    }
  | {
      readonly kind: 'wallet_iframe';
      readonly source: WalletIframeCoordinator;
    };

function resolveSeamsWebRuntimeMode(
  internalOptions: SeamsWebInternalOptions | undefined,
): SeamsWebRuntimeMode {
  if (internalOptions?.kind === 'wallet_host') return 'wallet_host';
  return 'application';
}

function resolveSeamsWebLifecycleEventSource(args: {
  readonly mode: SeamsWebRuntimeMode;
  readonly signingEngine: SeamsWebSigningSurface;
  readonly walletIframe: WalletIframeCoordinator;
}): SeamsWebLifecycleEventSource {
  switch (args.mode) {
    case 'wallet_host':
      return { kind: 'signing_engine', source: args.signingEngine };
    case 'application':
      return { kind: 'wallet_iframe', source: args.walletIframe };
  }
}

function subscribeToSeamsWebLifecycleEvents(
  eventSource: SeamsWebLifecycleEventSource,
  listener: SdkLifecycleEventListener,
): () => void {
  switch (eventSource.kind) {
    case 'signing_engine':
    case 'wallet_iframe':
      return eventSource.source.onSdkLifecycleEvent(listener);
  }
}

function deliverNearProvisioningStateChanged(
  listener: (event: NearProvisioningStateChangedEvent) => void,
  event: SdkLifecycleEvent,
): void {
  if (event.event === 'registration.near_provisioning_changed') listener(event);
}

type SeamsWebDeviceDomain = {
  readonly domain: DevicesCapabilityDomainMethods;
  readonly dispose: () => void;
};

type WalletHostOwnerSourceLaneCandidateV1 =
  | {
      readonly curve: 'ed25519';
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly curve: 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
      readonly ecdsaSourceManifest: {
        readonly manifestId: EcdsaCapabilityManifestId;
        readonly manifestRevision: EcdsaCapabilityManifestRevision;
      };
    };

export function resolveSeamsWebDeviceDomainModeV1(mode: SeamsWebRuntimeMode): 'direct' | 'iframe' {
  return mode === 'wallet_host' ? 'direct' : 'iframe';
}

function createSeamsWebDeviceDomainV1(args: {
  readonly mode: SeamsWebRuntimeMode;
  readonly configs: SeamsConfigsReadonly;
  readonly signingEngine: BrowserSigningSurface;
  readonly walletIframe: WalletIframeCoordinator;
}): SeamsWebDeviceDomain {
  switch (resolveSeamsWebDeviceDomainModeV1(args.mode)) {
    case 'iframe':
      return {
        domain: {
          kind: 'iframe',
          linkedDeviceManagement: createWalletIframeLinkedDeviceManagementPortV1({
            walletIframe: args.walletIframe,
          }),
        },
        dispose: noopDeviceLinkingDisposeV1,
      };
    case 'direct': {
      const platform = createBrowserHostPlatformRuntime(
        args.signingEngine.getSignerWorkerContext(),
      );
      const ownerAuthorities = createWalletHostOwnerAuthoritiesV1({
        http: platform.http,
        relayerUrl: String(args.configs.network.relayer?.url || '').trim(),
        walletSessions: walletSessionAuthorizations,
        readWalletAuthenticationState: args.signingEngine.readWalletAuthenticationState.bind(
          args.signingEngine,
        ),
        readOwnerSourceLaneHintsV1: (input) =>
          readWalletHostOwnerSourceLaneHintsV1({
            signingEngine: args.signingEngine,
            relayerUrl: String(args.configs.network.relayer?.url || '').trim(),
            projection: input.projection,
          }),
        readUnlockedEd25519ExportRootCapabilityV1: readUnlockedWalletEd25519ExportRootCapabilityV1,
      });
      const composition = createWalletHostCompositionV1({
        authenticator: platform.authenticator,
        http: platform.http,
        relayerUrl: String(args.configs.network.relayer?.url || '').trim(),
        ownerRequest: ownerAuthorities.ownerRequest,
        ownerApprovalUpdates: createWalletHostOwnerApprovalUpdatesV1({
          request: ownerAuthorities.ownerRequest,
          pollIntervalMs: 1_000,
        }),
        ownerAuthorization: ownerAuthorities.ownerAuthorization,
        custodyCeremonyTransport: walletCustodyCeremonyTransportFromWorkerContextV1(
          args.signingEngine.getSignerWorkerContext(),
        ),
        managementRequest: ownerAuthorities.managementRequest,
        nowMs: Date.now,
        pollIntervalMs: 1_000,
      });
      return {
        domain: {
          kind: 'direct',
          linkedDeviceManagement: composition.linkedDeviceManagement,
          deviceLinkingPorts: composition.deviceLinkingPorts,
        },
        dispose: composition.dispose,
      };
    }
  }
}

function noopDeviceLinkingDisposeV1(): void {}

function ownerSourceLaneCandidateKeyV1(candidate: WalletHostOwnerSourceLaneCandidateV1): string {
  const activation = candidate.materialActivation;
  return [
    candidate.curve,
    activation.activationId,
    activation.capability,
    activation.materialOwner,
    activation.keyBinding,
    activation.lifecycleBinding,
    activation.signingWorker,
  ].join('|');
}

function collectWalletHostOwnerSourceLaneCandidatesV1(
  available: AvailableSigningLanes,
): readonly WalletHostOwnerSourceLaneCandidateV1[] {
  const candidates = new Map<string, WalletHostOwnerSourceLaneCandidateV1>();
  for (const lane of available.candidates.ed25519.near) {
    if (
      !isConcreteAvailableSigningLane(lane) ||
      lane.curve !== 'ed25519' ||
      lane.state !== 'ready'
    ) {
      continue;
    }
    const candidate: WalletHostOwnerSourceLaneCandidateV1 = {
      curve: 'ed25519',
      materialActivation: lane.materialActivation,
    };
    candidates.set(ownerSourceLaneCandidateKeyV1(candidate), candidate);
  }
  for (const lane of Object.values(available.ecdsa.candidatesByTarget).flat()) {
    if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ecdsa' || lane.state !== 'ready') {
      continue;
    }
    const candidate: WalletHostOwnerSourceLaneCandidateV1 = {
      curve: 'ecdsa_secp256k1',
      materialActivation: lane.materialActivation,
      ecdsaSourceManifest: {
        manifestId: lane.capability.manifest.identity.manifestId,
        manifestRevision: lane.capability.manifest.identity.manifestRevision,
      },
    };
    const key = ownerSourceLaneCandidateKeyV1(candidate);
    const previous = candidates.get(key);
    if (
      previous?.curve === 'ecdsa_secp256k1' &&
      (previous.ecdsaSourceManifest.manifestId !== candidate.ecdsaSourceManifest.manifestId ||
        previous.ecdsaSourceManifest.manifestRevision !==
          candidate.ecdsaSourceManifest.manifestRevision)
    ) {
      throw new Error('Wallet-host owner ECDSA source lane identity is ambiguous');
    }
    candidates.set(key, candidate);
  }
  return [...candidates.values()];
}

function buildWalletHostOwnerSourceLaneHintV1(
  candidate: WalletHostOwnerSourceLaneCandidateV1,
  projection: Awaited<ReturnType<typeof readOwnerWalletExecutionLaneProjectionV1>>,
): LinkedDeviceOwnerSourceLaneV1 {
  switch (candidate.curve) {
    case 'ed25519':
      if (projection.walletKey.keyFamily !== 'ed25519') {
        throw new Error('Wallet-host owner Ed25519 source lane family changed');
      }
      return {
        kind: 'linked_device_owner_source_lane_v1',
        keyFamily: 'ed25519',
        walletKey: projection.walletKey,
        lane: projection.lane,
        materialActivation: projection.materialActivation,
        verifiedActivationReceiptDigestB64u: projection.verifiedActivationReceiptDigestB64u,
      };
    case 'ecdsa_secp256k1':
      if (projection.walletKey.keyFamily !== 'ecdsa_secp256k1') {
        throw new Error('Wallet-host owner ECDSA source lane family changed');
      }
      return {
        kind: 'linked_device_owner_source_lane_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletKey: projection.walletKey,
        lane: projection.lane,
        materialActivation: projection.materialActivation,
        verifiedActivationReceiptDigestB64u: projection.verifiedActivationReceiptDigestB64u,
        ecdsaSourceManifest: candidate.ecdsaSourceManifest,
      };
  }
}

async function readWalletHostOwnerSourceLaneHintsV1(args: {
  readonly signingEngine: BrowserSigningSurface;
  readonly relayerUrl: string;
  readonly projection: ActiveWalletSessionAuthorizationProjection;
}): Promise<readonly [LinkedDeviceOwnerSourceLaneV1, ...LinkedDeviceOwnerSourceLaneV1[]]> {
  const ownerScope = await args.signingEngine.resolveActiveOwnerLaneScope(args.projection.walletId);
  const available = await args.signingEngine.readOwnerScopedSigningLanes({
    walletId: args.projection.walletId,
    ownerScope,
  });
  const candidates = collectWalletHostOwnerSourceLaneCandidatesV1(available);
  if (candidates.length === 0) {
    throw new Error('Wallet-host owner source lanes are unavailable');
  }
  const tokenByCurve = {
    ed25519: walletSessionTokenForCurve(args.projection, 'ed25519'),
    ecdsa_secp256k1: walletSessionTokenForCurve(args.projection, 'ecdsa'),
  } as const;
  const hints = await Promise.all(
    candidates.map(async (candidate) => {
      const token = tokenByCurve[candidate.curve];
      if (!token) {
        throw new Error(`Wallet-host owner ${candidate.curve} Wallet Session token is unavailable`);
      }
      const projection = await readOwnerWalletExecutionLaneProjectionV1({
        relayerUrl: args.relayerUrl,
        walletSessionToken: token,
        curve: candidate.curve,
        expectedMaterialActivation: candidate.materialActivation,
      });
      return buildWalletHostOwnerSourceLaneHintV1(candidate, projection);
    }),
  );
  const first = hints[0];
  if (!first) throw new Error('Wallet-host owner source lanes are unavailable');
  return [first, ...hints.slice(1)];
}

function createWalletHostOwnerApprovalUpdatesV1(args: {
  readonly request: LinkSessionOwnerAuthenticatedRequestPortV1;
  readonly pollIntervalMs: number;
}): LinkSessionOwnerApprovalUpdatesPortV1 {
  return {
    getApprovalV1: async (input) => await requestWalletHostApprovalV1(args.request, input),
    subscribeApprovalV1: async (input) =>
      createWalletHostApprovalSubscriptionV1({ ...args, input }),
  };
}

async function requestWalletHostApprovalV1(
  request: LinkSessionOwnerAuthenticatedRequestPortV1,
  input: Parameters<LinkSessionOwnerApprovalUpdatesPortV1['getApprovalV1']>[0],
): Promise<Awaited<ReturnType<LinkSessionOwnerApprovalUpdatesPortV1['getApprovalV1']>>> {
  const response = await request.requestOwnerV1({
    method: 'GET',
    canonicalPath: `${LINKED_DEVICE_SESSION_HTTP_BASE_PATH_V1}/${String(
      input.linkSessionId,
    )}/approval`,
    authentication: input.authentication,
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`Wallet-host approval request failed with HTTP ${response.status}`);
  }
  return parseLinkedDeviceApprovalResultV1(response.body);
}

function createWalletHostApprovalSubscriptionV1(args: {
  readonly request: LinkSessionOwnerAuthenticatedRequestPortV1;
  readonly pollIntervalMs: number;
  readonly input: Parameters<LinkSessionOwnerApprovalUpdatesPortV1['subscribeApprovalV1']>[0];
}): { readonly close: () => void } {
  let closed = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const poll = async (): Promise<void> => {
    if (closed) return;
    try {
      const result = await requestWalletHostApprovalV1(args.request, args.input);
      if (!closed) args.input.onResult(result);
    } catch {
      // The next poll retries transient owner-session transport failures.
    }
    if (!closed) timer = setTimeout(() => void poll(), args.pollIntervalMs);
  };
  void poll();
  return {
    close: () => {
      closed = true;
      if (timer) clearTimeout(timer);
      timer = null;
    },
  };
}

/**
 * Main SeamsWeb class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class SeamsWeb {
  private readonly signingEngine: SeamsWebSigningSurface;
  private readonly nearClient: NearClient;
  readonly configs: SeamsConfigsReadonly;
  private appearance: AppearanceConfig;
  theme: ThemeMode;
  private readonly walletIframe: WalletIframeCoordinator;
  private readonly lifecycleEventSource: SeamsWebLifecycleEventSource;
  readonly recovery: RecoveryCapability;
  readonly devices: DevicesCapability;
  readonly keys: KeyExportCapability;
  readonly preferences: PreferencesCapability;
  readonly auth: AuthCapability;
  readonly registration: RegistrationCapability;
  readonly near: NearSignerCapability;
  readonly tempo: TempoSignerCapability;
  readonly evm: EvmSignerCapability;
  private readonly walletIframeControls: WalletIframeControlCapability;
  private readonly deviceLinkingDispose: () => void;
  private emailOtpUnlockPrewarmRecord: EmailOtpUnlockPrewarmRecord = { kind: 'none' };

  constructor(
    configs: SeamsConfigsInput,
    nearClient?: NearClient,
    internalOptions?: SeamsWebInternalOptions,
  ) {
    this.configs = buildConfigsFromEnv(configs, {
      ...(internalOptions?.kind === 'wallet_host' ? { allowDirectWalletMode: 'wallet_host' } : {}),
    });
    configureBrowserIndexedDB(this.configs);
    // Use provided client or create default one
    this.nearClient =
      nearClient || new MinimalNearClient(resolvePrimaryNearRpcUrl(this.configs.network.chains));
    const browserSigningStores = createBrowserSigningStores(IndexedDBManager);
    const browserSigningSurface = new BrowserSigningSurface(this.configs, this.nearClient, {
      managerStores: browserSigningStores.managerStores,
      signingEngineStores: browserSigningStores.signingEngineStores,
      sealedSigningSessionStore: browserSigningStores.sealedSigningSessionStore,
      ed25519YaoPublicCapabilityReferences:
        browserSigningStores.ed25519YaoPublicCapabilityReferences,
      createRuntime: createBrowserSigningRuntime,
      initializeRuntime: initializeBrowserSigningRuntime,
      workerWarmupPolicy: resolveBrowserWorkerWarmupPolicy(this.configs),
    });
    this.signingEngine = browserSigningSurface;
    this.appearance = this.configs.ui.appearance;
    this.theme = this.appearance.theme.mode;
    try {
      this.signingEngine.setAppearance(this.appearance);
    } catch {}
    const userPreferences = this.signingEngine.getUserPreferences();
    this.walletIframe = new WalletIframeCoordinator({
      configs: this.configs,
      signingEngine: this.signingEngine,
      userPreferences: userPreferences,
      getAppearance: () => this.appearance,
    });
    const deviceDomain = createSeamsWebDeviceDomainV1({
      mode: resolveSeamsWebRuntimeMode(internalOptions),
      configs: this.configs,
      signingEngine: browserSigningSurface,
      walletIframe: this.walletIframe,
    });
    this.deviceLinkingDispose = deviceDomain.dispose;
    this.lifecycleEventSource = resolveSeamsWebLifecycleEventSource({
      mode: resolveSeamsWebRuntimeMode(internalOptions),
      signingEngine: this.signingEngine,
      walletIframe: this.walletIframe,
    });
    const publicApi = createPublicApi({
      signingEngine: this.signingEngine,
      nearClient: this.nearClient,
      configs: this.configs,
      getTheme: () => this.theme,
      userPreferences,
      getWalletIframe: () => this.walletIframe,
      getWalletAuthDeps: () => this.getWalletAuthDeps(),
      auth: {
        requestEmailOtpChallenge: async (args) => await this.requestEmailOtpChallengeDomain(args),
        requestEmailOtpSigningSessionChallenge: async (args) =>
          await this.requestEmailOtpSigningSessionChallengeDomain(args),
        refreshEmailOtpSigningSession: async (args) =>
          await this.refreshEmailOtpSigningSessionDomain(args),
        loginWithEmailOtpEcdsaCapability: async (args) =>
          await this.loginWithEmailOtpEcdsaCapabilityDomain(args),
        beginGoogleEmailOtpWalletAuth: async (args) =>
          await this.beginGoogleEmailOtpWalletAuthDomain(args),
      },
      registration: {
        getNearProvisioningState: async (args) => await this.getNearProvisioningStateDomain(args),
        onNearProvisioningStateChanged: (listener) =>
          subscribeToSeamsWebLifecycleEvents(
            this.lifecycleEventSource,
            deliverNearProvisioningStateChanged.bind(null, listener),
          ),
        addWalletSigner: async (args) => await this.registerWalletSignerDomain(args),
        addPasskey: async (args) => await this.addPasskeyDomain(args),
        registerWallet: async (args) => await this.registerWalletDomain(args),
        registerPasskey: async (options) => await this.registerPasskeyDomain(options),
        requestEmailOtpEnrollmentChallenge: async (args) =>
          await this.requestEmailOtpEnrollmentChallengeDomain(args),
        enrollEmailOtp: async (args) => await this.enrollEmailOtpDomain(args),
      },
      recovery: {
        getWalletRecoveryCodeStatus: async (args) =>
          await this.getWalletRecoveryCodeStatusDomain(args),
        acknowledgeWalletRecoveryCodeBackup: async (args) =>
          await this.acknowledgeWalletRecoveryCodeBackupDomain(args),
        requestWalletCustodyEmailOtpChallenge: async (args) =>
          await this.requestWalletCustodyEmailOtpChallengeDomain(args),
        rotateWalletRecoveryCodes: async (args) => await this.rotateWalletRecoveryCodesDomain(args),
      },
      devices: {
        ...deviceDomain.domain,
      },
      keys: {
        resolveExactKeyExportLane: async (input) =>
          await this.resolveExactKeyExportLaneDomain(input),
        exportKeypairWithUI: async (input) => await this.exportKeypairWithUIDomain(input),
      },
    });
    this.walletIframeControls = publicApi.walletIframeControls;
    this.preferences = publicApi.preferences;
    this.auth = publicApi.auth;
    this.registration = publicApi.registration;
    this.recovery = publicApi.recovery;
    this.devices = publicApi.devices;
    this.keys = publicApi.keys;
    this.near = publicApi.near;
    this.tempo = publicApi.tempo;
    this.evm = publicApi.evm;

    // UserConfirm worker initializes automatically in the constructor
  }

  /**
   * Initialize the hidden wallet service iframe client (optional) and warm critical resources.
   * Always warms local resources; initializes iframe when wallet mode is `iframe`.
   * Idempotent and safe to call multiple times.
   */
  async initWalletIframe(walletId?: string): Promise<WalletIframeExactSessionState> {
    return await this.walletIframe.init(walletId);
  }

  async getWalletIframeExactSessionState(): Promise<WalletIframeExactSessionState> {
    return await this.walletIframe.getExactSessionState();
  }

  async openHostedAuthMenu(
    request: HostedAuthMenuOpenRequest,
    anchorElement?: HTMLElement,
  ): Promise<HostedAuthMenuOutcome> {
    return await this.walletIframe.openHostedAuthMenu(request, anchorElement);
  }

  async cancelHostedAuthMenu(args: { authMenuSessionId: HostedAuthMenuSessionId }): Promise<void> {
    await this.walletIframe.cancelHostedAuthMenu(args);
  }

  onHostedAuthMenuExternalAuthRequest(
    listener: (request: HostedAuthMenuExternalAuthRequest) => void,
  ): () => void {
    return this.walletIframe.onHostedAuthMenuExternalAuthRequest(listener);
  }

  onHostedAuthMenuDemoEmailOtpDelivery(
    listener: (delivery: HostedAuthMenuDemoEmailOtpDelivery) => void,
  ): () => void {
    return this.walletIframe.onHostedAuthMenuDemoEmailOtpDelivery(listener);
  }

  async resolveHostedAuthMenuExternalAuth(
    resolution: HostedAuthMenuExternalAuthResolutionInput,
  ): Promise<void> {
    await this.walletIframe.resolveHostedAuthMenuExternalAuth(resolution);
  }

  async lockWalletIframeExactSession(
    identity: WalletIframeExactSessionIdentityInput,
  ): Promise<WalletIframeExactSessionLockResult> {
    const parsedIdentity: WalletIframeExactSessionIdentity =
      parseWalletIframeExactSessionIdentity(identity);
    return await this.walletIframe.lockExactSession(parsedIdentity);
  }

  /** True when the wallet iframe client is connected and ready. */
  isWalletIframeReady(): boolean {
    return this.walletIframeControls.isWalletIframeReady();
  }

  /** Subscribe to wallet iframe ready state transitions. */
  onWalletIframeReady(listener: () => void): () => void {
    return this.walletIframeControls.onWalletIframeReady(listener);
  }

  /** Subscribe to wallet-host login status updates. */
  onWalletIframeLoginStatusChanged(
    listener: (status: { isLoggedIn: boolean; walletId: string | null }) => void,
  ): () => void {
    return this.walletIframeControls.onWalletIframeLoginStatusChanged(listener);
  }

  /** Subscribe to typed lifecycle events emitted by the wallet boundary. */
  onSdkLifecycleEvent(listener: SdkLifecycleEventListener): () => void {
    return subscribeToSeamsWebLifecycleEvents(this.lifecycleEventSource, listener);
  }

  /** Subscribe to wallet-host preference updates. */
  onWalletIframePreferencesChanged(
    listener: (payload: PreferencesChangedPayload) => void,
  ): () => void {
    return this.walletIframeControls.onWalletIframePreferencesChanged(listener);
  }

  getContext(): SeamsWebContext {
    return {
      signingEngine: this.signingEngine,
      nearClient: this.nearClient,
      configs: this.configs,
      theme: this.theme,
    };
  }

  dispose(): void {
    this.deviceLinkingDispose();
    this.walletIframe.dispose();
    this.signingEngine.dispose();
  }

  private getWalletAuthDeps(): WalletAuthDomainDeps {
    return {
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
      signingEngine: this.signingEngine,
      nearClient: this.nearClient,
      initWalletIframe: async (walletId?: string) => {
        return await this.initWalletIframe(walletId);
      },
    };
  }

  setTheme(next: ThemeMode): void {
    if (next !== 'light' && next !== 'dark') return;
    this.setAppearance({
      theme: {
        ...this.appearance.theme,
        mode: next,
      },
    });
  }

  /**
   * Resolve one configured ECDSA chain target by network slug, chain id, or
   * family — the value every EVM-family signing and export call takes.
   *
   * Throws when the selector matches no configured chain, or more than one.
   * Every configured chain is named in the error, so an ambiguous selector is
   * a clear failure rather than a silent first-match pick.
   *
   * @example seams.chainTarget('tempo-testnet')
   */
  chainTarget(selector: EcdsaChainSelector): ThresholdEcdsaChainTarget {
    return resolveConfiguredChainTarget(this.configs.network.chains, selector);
  }

  /** Every ECDSA chain target this client is configured for. */
  configuredChainTargets(): readonly ThresholdEcdsaChainTarget[] {
    return configuredThresholdEcdsaChainTargets(this.configs.network.chains);
  }

  /**
   * Update resolved appearance at runtime.
   * This is the canonical internal propagation path for local signing UI,
   * wallet-host documents, and app-origin wallet iframe mode. Appearance is
   * excluded from the runtime-reset fingerprint, so warm signing-session state
   * is preserved. Fire-and-forget; never throws.
   */
  setAppearance(appearance: AppearanceConfigInput): void {
    const normalizedAppearance = resolveRuntimeAppearance(this.appearance, appearance);
    this.appearance = normalizedAppearance;
    this.theme = normalizedAppearance.theme.mode;
    try {
      this.signingEngine.setAppearance(normalizedAppearance);
    } catch {}
    if (__isWalletIframeHostMode()) {
      try {
        document.documentElement.setAttribute('data-w3a-theme', this.theme);
      } catch {}
    }

    if (this.walletIframe.shouldUseWalletIframe()) {
      void (async () => {
        try {
          const router = await this.walletIframe.requireRouter();
          await router.setAppearance(normalizedAppearance);
        } catch {}
      })();
    }
  }

  setWalletIframeSurfaceMeasurementBinding(binding: UiConfirmSurfaceMeasurementBinding): void {
    this.signingEngine.setWalletIframeSurfaceMeasurementBinding(binding);
  }

  /**
   * Pre-warm resources on a best-effort basis without changing visible state.
   * - When iframe=true, initializes the wallet iframe client.
   * - When workers=true, warms local critical resources only outside app-origin iframe mode.
   * - When both are false/omitted, does nothing.
   */
  async prewarm(opts?: SeamsWebPrewarmOptions): Promise<void> {
    const iframe = !!opts?.iframe;
    const workers = !!opts?.workers;
    const nearAccountBinding = resolvePrewarmNearAccountBinding(opts);
    const prewarmRequest = emailOtpUnlockPrewarmRequestFromOptions(opts);
    const prewarmScope = emailOtpUnlockPrewarmScopeFromBinding(nearAccountBinding);

    const tasks: Promise<unknown>[] = [];

    if (iframe) {
      // initWalletIframe also calls the browser signing surface warmup internally.
      tasks.push(this.initWalletIframe(nearAccountBinding?.wallet.walletId));
    } else if (workers && !this.walletIframe.shouldUseWalletIframe()) {
      // Warm local-only resources without touching the iframe.
      const accountContext = nearAccountBinding
        ? { kind: 'near_account_bound' as const, account: nearAccountBinding }
        : { kind: 'none' as const };
      tasks.push(this.signingEngine.warmCriticalResources(accountContext));
    }

    if (tasks.length === 0) return;
    let status: Extract<EmailOtpUnlockPrewarmRecord, { kind: 'attempted' }>['status'] = 'succeeded';
    try {
      await Promise.all(tasks);
    } catch {
      status = 'failed';
      // Best-effort: swallow errors so prewarm never breaks app flows
    }
    if (prewarmRequest) {
      this.emailOtpUnlockPrewarmRecord = {
        kind: 'attempted',
        status,
        completedAtMs: Date.now(),
        request: prewarmRequest,
        scope: prewarmScope,
      };
    }
  }

  private emitWalletIframeTransportTimingSummary(input: {
    operation: 'registerWallet' | 'registerPasskey';
    walletId: string | null;
  }): void {
    if (!isRegistrationBenchmarkDiagnosticsEnabled()) return;
    const diagnostics = this.walletIframe.getTransportDiagnosticsSnapshot();
    if (!diagnostics) return;
    const { kind: transportKind, ...timings } = diagnostics;
    console.info(WALLET_IFRAME_TRANSPORT_TIMING_LABEL, {
      kind: 'wallet_iframe_registration_transport_timing_v1',
      operation: input.operation,
      walletId: input.walletId,
      transportKind,
      ...timings,
    });
  }

  ///////////////////////////////////////
  // === Registration and Login ===
  ///////////////////////////////////////

  private async registerWalletDomain(
    args: Parameters<RegistrationCapability['registerWallet']>[0],
  ): Promise<RegistrationResult> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const walletRouterId =
          args.wallet.kind === 'provided' ? String(args.wallet.walletId) : undefined;
        const router = await this.walletIframe.requireRouter(walletRouterId);
        this.emitWalletIframeTransportTimingSummary({
          operation: 'registerWallet',
          walletId: walletRouterId ?? null,
        });
        const res = await router.registerWallet(args);
        const registeredWalletId = res.success ? String(res.walletId || '').trim() : '';
        if (registeredWalletId) {
          void (async () => {
            try {
              await this.initWalletIframe(registeredWalletId);
            } catch {}
          })();
        }
        await args.options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false);
        throw e;
      }
    }
    return await registerWalletWithUnifiedCeremony({
      context: this.getContext(),
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      options: args.options || {},
      authenticatorOptions: cloneAuthenticatorOptions(this.configs.webauthn.authenticatorOptions),
    });
  }

  private async getNearProvisioningStateDomain(
    args: Parameters<RegistrationCapability['getNearProvisioningState']>[0],
  ): ReturnType<RegistrationCapability['getNearProvisioningState']> {
    const walletId = toWalletId(args.walletId);
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(walletId));
      return await router.getNearProvisioningState({ walletId });
    }
    const live = readNearProvisioningState(walletId);
    if (live) return live;
    return await this.getContext().signingEngine.getWalletNearProvisioningState(walletId);
  }

  private async registerWalletSignerDomain(
    args: Parameters<RegistrationCapability['addWalletSigner']>[0],
  ): Promise<RegistrationResult> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(String(args.walletId || ''));
        const res = await router.addWalletSigner(args);
        await args.options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false);
        throw e;
      }
    }
    return await addWalletSignerWithUnifiedCeremony({
      context: this.getContext(),
      walletId: args.walletId,
      rpId: args.rpId,
      signerSelection: args.signerSelection,
      options: args.options || {},
    });
  }

  private async addPasskeyDomain(
    args: Parameters<RegistrationCapability['addPasskey']>[0],
  ): Promise<Awaited<ReturnType<RegistrationCapability['addPasskey']>>> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(String(args.walletId || ''));
        const result = await router.addPasskey(args);
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const normalized = toError(error);
        await args.options?.onError?.(normalized);
        await args.options?.afterCall?.(false);
        throw normalized;
      }
    }
    return await addPasskeyWalletAuthMethod({
      context: this.getContext(),
      walletId: args.walletId,
      rpId: args.rpId,
      authorization: args.authorization,
      options: args.options,
    });
  }

  private async registerPasskeyDomain(
    options: Parameters<RegistrationCapability['registerPasskey']>[0] = {},
  ): Promise<RegistrationResult> {
    if (typeof options === 'string') {
      throw new Error(
        '[SeamsWeb] registration.registerPasskey no longer accepts a NEAR account id; call registration.registerPasskey(options) for implicit NEAR registration or registerWallet(...) with explicit sponsored accountProvisioning.',
      );
    }
    const { wallet, nearAccountProvisioning, ...registrationOptions } = options || {};
    const rpId = this.walletIframe.resolveRegistrationRpId(this.signingEngine.getRpId());
    const provisioningPreference =
      nearAccountProvisioning ?? this.configs.registration.nearAccountProvisioning;
    const resolvedWallet =
      wallet ||
      (provisioningPreference.kind === 'relayer_named_subaccount'
        ? { kind: 'provided' as const, walletId: createServerAllocatedWalletId() }
        : { kind: 'server_allocated' as const });
    const accountProvisioning = resolvePasskeyRegistrationAccountProvisioning({
      configs: this.configs,
      wallet: resolvedWallet,
      preference: provisioningPreference,
    });
    return await this.registerWalletDomain({
      wallet: resolvedWallet,
      authMethod: { kind: 'passkey', rpId },
      signerSelection: buildNearWalletRegistrationSignerSetSelection({
        configs: this.configs,
        accountProvisioning,
        options: registrationOptions,
      }),
      options: registrationOptions,
    });
  }

  private emailOtpRegistrationFlowId(walletId: string, challengeId?: string): string {
    const accountPart = String(walletId || 'unknown-wallet').trim() || 'unknown-wallet';
    const challengePart = String(challengeId || 'active').trim() || 'active';
    return `email-otp-registration:${accountPart}:${challengePart}`;
  }

  private emailOtpUnlockFlowId(walletId: string, challengeId?: string): string {
    const accountPart = String(walletId || 'unknown-wallet').trim() || 'unknown-wallet';
    const challengePart = String(challengeId || 'active').trim() || 'active';
    return `email-otp-unlock:${accountPart}:${challengePart}`;
  }

  private emitEmailOtpRegistrationEvent(
    onEvent: ((event: RegistrationFlowEvent) => void) | undefined,
    input: CreateRegistrationFlowEventInput,
  ): void {
    try {
      onEvent?.(createRegistrationFlowEvent(input));
    } catch {}
  }

  private emitEmailOtpUnlockEvent(
    onEvent: ((event: UnlockFlowEvent) => void) | undefined,
    input: CreateUnlockFlowEventInput,
  ): void {
    try {
      onEvent?.(createUnlockFlowEvent(input));
    } catch {}
  }

  private emitEmailOtpRegistrationFailure(
    onEvent: ((event: RegistrationFlowEvent) => void) | undefined,
    input: Omit<CreateRegistrationFlowEventInput, 'phase' | 'status' | 'error'> & {
      error: Error;
    },
  ): void {
    this.emitEmailOtpRegistrationEvent(onEvent, {
      ...input,
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      error: { message: input.error.message },
    });
  }

  private emitEmailOtpRegistrationWorkerProgress(
    onEvent: ((event: RegistrationFlowEvent) => void) | undefined,
    args: {
      flowId: string;
      walletId: string;
      challengeId?: string;
      chainTarget: ThresholdEcdsaChainTarget;
      progress: EmailOtpWorkerProgressEvent;
    },
  ): RegistrationEventPhase | null {
    const base = {
      flowId: args.flowId,
      walletId: args.walletId,
      authMethod: 'email_otp' as const,
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    };
    switch (args.progress.code) {
      case 'otp.verify.succeeded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
        });
        return RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED;
      case 'signer.email_otp.enroll.started':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
          status: 'running',
        });
        return RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED;
      case 'signer.email_otp.enroll.succeeded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
          status: 'succeeded',
        });
        return RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED;
      case 'signer.ecdsa.bootstrap.started':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED;
      case 'signer.ecdsa.bootstrap.prepared':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          message: 'Coordinating EVM signing session',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED;
      case 'signer.ecdsa.bootstrap.responded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          message: 'Finalizing EVM signing session',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED;
      case 'signer.ecdsa.bootstrap.succeeded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
          status: 'succeeded',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED;
      default:
        return null;
    }
  }

  private emitEmailOtpUnlockWorkerProgress(
    onEvent: ((event: UnlockFlowEvent) => void) | undefined,
    args: {
      flowId: string;
      walletId: string;
      challengeId?: string;
      chainTarget: ThresholdEcdsaChainTarget;
      progress: EmailOtpWorkerProgressEvent;
    },
  ): UnlockEventPhase | null {
    const chainLabel = args.chainTarget.kind === 'tempo' ? 'Tempo' : 'EVM';
    const base = {
      flowId: args.flowId,
      walletId: args.walletId,
      authMethod: 'email_otp' as const,
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    };
    switch (args.progress.code) {
      case 'otp.verify.succeeded':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
        });
        return UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED;
      case 'signer.ecdsa.bootstrap.started':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Preparing ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      case 'signer.ecdsa.bootstrap.prepared':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Coordinating ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      case 'signer.ecdsa.bootstrap.responded':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Finalizing ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      case 'signer.ecdsa.bootstrap.succeeded':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Saving ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      default:
        return null;
    }
  }

  private emitEmailOtpUnlockFailure(
    onEvent: ((event: UnlockFlowEvent) => void) | undefined,
    input: Omit<CreateUnlockFlowEventInput, 'phase' | 'status' | 'error'> & {
      error: Error;
    },
  ): void {
    const cancelled = isUserCancellationError(input.error);
    this.emitEmailOtpUnlockEvent(onEvent, {
      ...input,
      phase: cancelled ? UnlockEventPhase.CANCELLED : UnlockEventPhase.FAILED,
      status: cancelled ? 'cancelled' : 'failed',
      interaction: input.interaction ?? {
        kind: cancelled ? 'otp_input' : 'none',
        overlay: 'hide',
      },
      error: { message: input.error.message },
    });
  }

  private async requestEmailOtpChallengeDomain(args: {
    walletId: string;
    relayUrl?: string;
    operation?: WalletEmailOtpLoginOperation;
    operationFingerprintDigest?: DigestB64u;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpOperationChallengeResult> {
    const flowId = this.emailOtpUnlockFlowId(args.walletId);
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      walletId: args.walletId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(args.walletId);
        const result = await router.requestEmailOtpChallenge(args);
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId: this.emailOtpUnlockFlowId(args.walletId, result.challengeId),
          walletId: args.walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
          status: 'succeeded',
          data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
        });
        return result;
      }
      const result = await requestEmailOtpChallenge({
        relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
        walletId: String(args.walletId || '').trim(),
        ...(args.operation ? { operation: args.operation } : {}),
        ...(args.operationFingerprintDigest
          ? { operationFingerprintDigest: args.operationFingerprintDigest }
          : {}),
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId: this.emailOtpUnlockFlowId(args.walletId, result.challengeId),
        walletId: args.walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
        status: 'succeeded',
        data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        walletId: args.walletId,
        authMethod: 'email_otp',
        error: e,
      });
      throw e;
    }
  }

  private async requestEmailOtpEnrollmentChallengeDomain(args: {
    walletId: string;
    relayUrl?: string;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult> {
    const flowId = this.emailOtpRegistrationFlowId(args.walletId);
    this.emitEmailOtpRegistrationEvent(args.onEvent, {
      flowId,
      walletId: args.walletId,
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_STARTED,
      status: 'running',
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(args.walletId);
        const result = await router.requestEmailOtpEnrollmentChallenge(args);
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId: this.emailOtpRegistrationFlowId(args.walletId, result.challengeId),
          walletId: args.walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_SENT,
          status: 'succeeded',
          data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
        });
        return result;
      }
      const result = await requestEmailOtpEnrollmentChallenge({
        relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
        walletId: String(args.walletId || '').trim(),
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId: this.emailOtpRegistrationFlowId(args.walletId, result.challengeId),
        walletId: args.walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_SENT,
        status: 'succeeded',
        data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpRegistrationFailure(args.onEvent, {
        flowId,
        walletId: args.walletId,
        authMethod: 'email_otp',
        error: e,
      });
      throw e;
    }
  }

  private async requestEmailOtpSigningSessionChallengeDomain(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpUnlockFlowId(walletId);
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      walletId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(walletId);
        const result = await router.requestEmailOtpSigningSessionChallenge({
          walletSession: args.walletSession,
          chainTarget: args.chainTarget,
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId: this.emailOtpUnlockFlowId(walletId, result.challengeId),
          walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
          status: 'succeeded',
          data: { challengeId: result.challengeId, otpChannel: 'email_otp' },
        });
        return result;
      }
      const result = await this.signingEngine.requestEmailOtpSigningSessionChallenge({
        walletSession: args.walletSession,
        chainTarget: args.chainTarget,
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId: this.emailOtpUnlockFlowId(walletId, result.challengeId),
        walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
        status: 'succeeded',
        data: { challengeId: result.challengeId, otpChannel: 'email_otp' },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        error: e,
      });
      throw e;
    }
  }

  private async enrollEmailOtpDomain(args: {
    walletId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    groupId?: string;
    clientSecret32?: Uint8Array;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EnrollEmailOtpInternalResult> {
    const flowId = this.emailOtpRegistrationFlowId(args.walletId, args.challengeId);
    this.emitEmailOtpRegistrationEvent(args.onEvent, {
      flowId,
      walletId: args.walletId,
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        if (args.clientSecret32) {
          throw new Error(
            '[SeamsWeb] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
          );
        }
        const router = await this.walletIframe.requireRouter(args.walletId);
        const iframeArgs = { ...args };
        delete iframeArgs.clientSecret32;
        delete iframeArgs.onEvent;
        const result = await router.enrollEmailOtp(iframeArgs);
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId: args.walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: {
            otpChannel: result.otpChannel,
            enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
          },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId: args.walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId: args.walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { unlockKeyVersion: result.unlockKeyVersion },
        });
        return result;
      }
      const result = await this.signingEngine.enrollEmailOtpInternal({
        walletId: toWalletId(args.walletId),
        otpCode: args.otpCode,
        ...(args.relayUrl ? { relayUrl: args.relayUrl } : {}),
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        ...(args.groupId ? { groupId: args.groupId } : {}),
        ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        walletId: args.walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: {
          otpChannel: result.otpChannel,
          enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
        },
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        walletId: args.walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        walletId: args.walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { unlockKeyVersion: result.unlockKeyVersion },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpRegistrationFailure(args.onEvent, {
        flowId,
        walletId: args.walletId,
        authMethod: 'email_otp',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        error: e,
      });
      throw e;
    }
  }

  private async getWalletRecoveryCodeStatusDomain(args: { walletId: string }) {
    const relayUrl = String(this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.getWalletRecoveryCodeStatus({
        walletId: args.walletId,
      });
    }
    const status = await readWalletRecoveryCodeStatus({
      relayUrl,
      walletId: args.walletId,
    });
    return status.kind === 'ready'
      ? {
          ...status,
          pendingLocalBackup: await pendingWalletRecoveryCodeBackupRepository.has(args.walletId),
        }
      : status;
  }

  private async beginGoogleEmailOtpWalletAuthDomain(
    args: Parameters<AuthCapability['beginGoogleEmailOtpWalletAuth']>[0],
  ): ReturnType<AuthCapability['beginGoogleEmailOtpWalletAuth']> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter();
      return await router.beginGoogleEmailOtpWalletAuth(args);
    }
    return await beginGoogleEmailOtpWalletAuth(
      {
        configs: this.configs,
        resolveGoogleEmailOtpProvider: this.resolveGoogleEmailOtpProviderDomain.bind(this),
        requestEmailOtpChallenge: this.requestEmailOtpChallengeDomain.bind(this),
        prewarmEmailOtpYao: this.prewarmEmailOtpYaoDomain.bind(this),
        registerWallet: this.registerWalletDomain.bind(this),
        loginWithEmailOtpEcdsaCapability: this.loginWithEmailOtpEcdsaCapabilityDomain.bind(this),
        loginWithEmailOtpEd25519YaoCapability:
          this.loginWithEmailOtpEd25519YaoCapabilityDomain.bind(this),
        getWalletSession: this.getGoogleEmailOtpWalletSessionDomain.bind(this),
      },
      args,
    );
  }

  private async resolveGoogleEmailOtpProviderDomain(
    args: Parameters<GoogleEmailOtpWalletAuthDeps['resolveGoogleEmailOtpProvider']>[0],
  ): ReturnType<GoogleEmailOtpWalletAuthDeps['resolveGoogleEmailOtpProvider']> {
    return await resolveGoogleEmailOtpProvider({
      relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
      idToken: args.idToken,
      accountMode: args.accountMode,
      projectEnvironmentId: this.configs.registration.projectEnvironmentId,
      publishableKey: this.configs.registration.publishableKey,
      ...(args.restartRegistrationOffer === true ? { restartRegistrationOffer: true } : {}),
    });
  }

  private async prewarmEmailOtpYaoDomain(): Promise<void> {
    await this.signingEngine.prewarmEmailOtpYao();
  }

  private async getGoogleEmailOtpWalletSessionDomain(
    walletId: string,
  ): ReturnType<GoogleEmailOtpWalletAuthDeps['getWalletSession']> {
    return await getWalletSessionDomain(this.getWalletAuthDeps(), walletId);
  }

  private async acknowledgeWalletRecoveryCodeBackupDomain(args: { walletId: string }) {
    const relayUrl = String(this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.acknowledgeWalletRecoveryCodeBackup({
        walletId: args.walletId,
      });
    }
    const pending = await pendingWalletRecoveryCodeBackupRepository.read(args.walletId);
    if (pending) {
      const acknowledgement = await showWalletRecoveryCodeBackupUi(
        {
          kind: 'wallet_recovery_code_backup_request_v1',
          walletId: pending.walletId,
          recoveryCodes: pending.recoveryCodes,
          continuation: 'pending_backup_must_finish',
        },
        this.signingEngine.getWalletIframeSurfaceMeasurementBinding(),
      );
      if (acknowledgement.kind !== 'wallet_recovery_codes_backed_up_v1') {
        throw new Error('Pending wallet recovery-code backup was not completed');
      }
    }
    const factorProof = await buildWalletCustodyPasskeyFactorProof({
      context: this.getContext(),
      walletId: args.walletId,
      operation: 'recovery_acknowledge',
      payload: { walletId: args.walletId },
    });
    const result = await acknowledgeWalletRecoveryBackup({
      relayUrl,
      walletId: args.walletId,
      factorProof,
    });
    if (pending && result.kind === 'acknowledged') {
      await pendingWalletRecoveryCodeBackupRepository.delete(args.walletId);
    }
    return result;
  }

  private async requestWalletCustodyEmailOtpChallengeDomain(
    args: Parameters<RecoveryCapability['requestWalletCustodyEmailOtpChallenge']>[0],
  ) {
    const relayUrl = String(this.configs.network.relayer.url || '').trim();
    return await requestWalletCustodyEmailOtpChallenge({ relayUrl, ...args });
  }

  private async rotateWalletRecoveryCodesDomain(
    args: Parameters<RecoveryCapability['rotateWalletRecoveryCodes']>[0],
  ) {
    const relayUrl = String(this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.rotateWalletRecoveryCodes(args);
    }
    return await rotateWalletRecoveryCodes({
      context: this.getContext(),
      relayUrl,
      walletId: args.walletId,
      authorization: args.authorization,
    });
  }

  private async loginWithEmailOtpEd25519YaoCapabilityDomain(
    args: EmailOtpWalletCustodyEd25519LoginDomainArgs,
  ): Promise<void> {
    const emailHashHex = await this.emailOtpEmailHashHex(args.emailOtpAuthorityEmail);
    const signer = await this.signingEngine.loginWithEmailOtpWalletCustodyEd25519Internal({
      ...args,
      emailHashHex,
    });
    await activateEmailOtpWalletAfterUnlock(
      { signingEngine: this.signingEngine, nearClient: this.nearClient },
      {
        kind: 'near_ed25519_wallet',
        signer,
      },
    );
  }

  private async emailOtpEmailHashHex(email: string): Promise<string> {
    const normalizedEmail = String(email || '')
      .trim()
      .toLowerCase();
    if (!normalizedEmail) {
      throw new Error('[SeamsWeb][email-otp] verified email is required for auth-method hash');
    }
    return sha256HexUtf8(normalizedEmail);
  }

  private async loginWithEmailOtpEcdsaCapabilityDomain(
    args: InternalEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpEcdsaCapabilityResult> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpUnlockFlowId(walletId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(args.chainTarget, 'Email OTP ECDSA unlock');
    const unlockTiming = {
      startedAtMs: nowMs(),
      timings: createEmailOtpUnlockTimings(),
    };
    const prewarm = emailOtpUnlockPrewarmSnapshot({
      record: this.emailOtpUnlockPrewarmRecord,
      walletId,
      nowMs: Date.now(),
    });
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      walletId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(walletId);
        const iframeArgs = { ...args, chainTarget };
        delete iframeArgs.onEvent;
        const iframeStartedAtMs = nowMs();
        const result = await router.loginWithEmailOtpEcdsaCapability(iframeArgs);
        const walletIframeRoundTripMs = nowMs() - iframeStartedAtMs;
        recordEmailOtpUnlockElapsedTiming(
          unlockTiming.timings,
          'walletIframeRoundTripMs',
          walletIframeRoundTripMs,
        );
        logEmailOtpUnlockTimingSummary({
          status: 'succeeded',
          mode: 'evm_family_ecdsa',
          walletId,
          prewarm,
          chainTarget,
          startedAtMs: unlockTiming.startedAtMs,
          timings: unlockTiming.timings,
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_07_COMPLETED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        return result;
      }
      const workerProgressPhases = new Set<UnlockEventPhase>();
      const markWorkerProgress = (progress: EmailOtpWorkerProgressEvent) => {
        const phase = this.emitEmailOtpUnlockWorkerProgress(args.onEvent, {
          flowId,
          walletId,
          challengeId: args.challengeId,
          chainTarget,
          progress,
        });
        if (phase) workerProgressPhases.add(phase);
      };
      const emitIfWorkerProgressMissing = (input: CreateUnlockFlowEventInput) => {
        if (workerProgressPhases.has(input.phase)) return;
        this.emitEmailOtpUnlockEvent(args.onEvent, input);
      };
      let timingStartedAtMs = nowMs();
      const relayUrl = String(args.relayUrl || this.configs.network.relayer.url).trim();
      const emailHashHex = await this.emailOtpEmailHashHex(args.emailOtpAuthorityEmail || '');
      recordEmailOtpUnlockTiming(unlockTiming.timings, 'emailHashLookupMs', timingStartedAtMs);
      timingStartedAtMs = nowMs();
      const ed25519CustodyProjection =
        await this.signingEngine.resolveEmailOtpEd25519CustodyProjectionInternal({
          walletSession: args.walletSession,
          providerSubjectId: args.providerIdentity.providerSubjectId,
        });
      const result = await this.signingEngine.loginWithEmailOtpEcdsaCapabilityInternal({
        ...args,
        chainTarget,
        emailHashHex,
        ...(ed25519CustodyProjection
          ? {
              runtimePolicyScope: ed25519CustodyProjection.identity.runtimePolicyScope,
              ed25519YaoRecovery: {
                kind: 'requested' as const,
                providerSubject: ed25519CustodyProjection.providerSubject,
                signerSlot: ed25519CustodyProjection.user.signerSlot,
                nearAccountId: String(ed25519CustodyProjection.identity.nearAccountId),
                expectedOperationalPublicKey: ed25519CustodyProjection.user.operationalPublicKey,
                expectedThresholdSessionId: String(
                  ed25519CustodyProjection.identity.thresholdSessionId,
                ),
              },
            }
          : { ed25519YaoRecovery: { kind: 'not_requested' as const } }),
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        providerIdentity: {
          kind: 'explicit_provider_user',
          provider: args.providerIdentity.provider,
          providerUserId: args.providerIdentity.providerSubjectId,
        },
        onProgress: markWorkerProgress,
      });
      let walletActivation: EmailOtpWalletPostUnlockActivation;
      if (ed25519CustodyProjection) {
        let recoveredEd25519Signer: NearEd25519SignerBinding;
        switch (result.ed25519YaoRecovery.kind) {
          case 'capability':
            recoveredEd25519Signer =
              await this.signingEngine.activateEmailOtpEd25519CustodyCapabilityInternal({
                walletSession: args.walletSession,
                providerSubject: ed25519CustodyProjection.providerSubject,
                emailHashHex,
                signerSlot: ed25519CustodyProjection.user.signerSlot,
                expectedOperationalPublicKey: ed25519CustodyProjection.user.operationalPublicKey,
                expectedThresholdSessionId: String(
                  ed25519CustodyProjection.identity.thresholdSessionId,
                ),
                bootstrap: result.ed25519YaoRecovery.bootstrap,
                activeClientHandle: result.ed25519YaoRecovery.activeClientHandle,
                metadata: result.ed25519YaoRecovery.metadata,
              });
            break;
          case 'cache_absent':
            throw new Error('Email OTP Ed25519 custody rejoin did not return active material');
          case 'not_requested':
            throw new Error('Email OTP capability unlock omitted Ed25519 Yao session material');
          default:
            throw new Error('Email OTP capability unlock returned an invalid Ed25519 Yao state');
        }
        walletActivation = {
          kind: 'near_ed25519_wallet',
          signer: recoveredEd25519Signer,
        };
      } else {
        if (result.ed25519YaoRecovery.kind !== 'not_requested') {
          throw new Error(
            'EVM-family ECDSA Email OTP unlock returned unexpected Ed25519 Yao material',
          );
        }
        walletActivation = {
          kind: 'evm_family_ecdsa_wallet',
          walletId,
        };
      }
      const workerUnlockMs = nowMs() - timingStartedAtMs;
      recordEmailOtpUnlockElapsedTiming(
        unlockTiming.timings,
        'workerUnlockAndSessionBootstrapMs',
        workerUnlockMs,
      );
      recordEmailOtpUnlockElapsedTiming(
        unlockTiming.timings,
        'emailOtpProofVerificationMs',
        result.timings.emailOtpProofVerificationMs,
      );
      recordEmailOtpUnlockElapsedTiming(
        unlockTiming.timings,
        'ecdsaMaterialRestoreMs',
        result.timings.ecdsaMaterialRestoreMs,
      );
      recordEmailOtpUnlockElapsedTiming(
        unlockTiming.timings,
        'signingSessionSealApplyMs',
        result.timings.signingSessionSealApplyMs,
      );
      recordEmailOtpUnlockElapsedTiming(
        unlockTiming.timings,
        'warmCapabilityPersistenceMs',
        result.timings.warmCapabilityPersistenceMs,
      );
      timingStartedAtMs = nowMs();
      await activateEmailOtpWalletAfterUnlock(
        { signingEngine: this.signingEngine, nearClient: this.nearClient },
        walletActivation,
      );
      recordEmailOtpUnlockTiming(
        unlockTiming.timings,
        'walletStateActivationMs',
        timingStartedAtMs,
      );
      timingStartedAtMs = nowMs();
      const runtimeInventory = await assertWalletRuntimePostconditions({
        source: 'wallet_unlock',
        walletId,
        ownerScope: {
          auth: {
            kind: 'email_otp',
            providerSubjectId: args.providerIdentity.providerSubjectId,
          },
        },
        requiredTargets: [
          ...(ed25519CustodyProjection ? [{ curve: 'ed25519' as const }] : []),
          ...configuredEmailOtpEcdsaSnapshotChainTargets(this.configs).map((target) => ({
            curve: 'ecdsa' as const,
            chainTarget: target,
          })),
        ],
        readOwnerScopedSigningLanes: async (input) =>
          await this.signingEngine.readOwnerScopedSigningLanes(input),
      });
      logEmailOtpUnlockActivationPlan(
        buildEmailOtpEcdsaUnlockActivationPlan({
          walletSession: args.walletSession,
          result,
          runtimeInventory,
        }),
      );
      const activeRuntimeConstructionMs = nowMs() - timingStartedAtMs;
      recordEmailOtpUnlockElapsedTiming(
        unlockTiming.timings,
        'runtimePostconditionMs',
        activeRuntimeConstructionMs,
      );
      recordEmailOtpUnlockElapsedTiming(
        unlockTiming.timings,
        'activeRuntimeConstructionMs',
        activeRuntimeConstructionMs,
      );
      logEmailOtpUnlockTimingSummary({
        status: 'succeeded',
        mode: 'evm_family_ecdsa',
        walletId,
        prewarm,
        chainTarget,
        startedAtMs: unlockTiming.startedAtMs,
        timings: unlockTiming.timings,
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_07_COMPLETED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      logEmailOtpUnlockTimingSummary({
        status: 'failed',
        mode: 'evm_family_ecdsa',
        walletId,
        prewarm,
        chainTarget,
        startedAtMs: unlockTiming.startedAtMs,
        timings: unlockTiming.timings,
        error: e,
      });
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        error: e,
      });
      throw e;
    }
  }

  private async refreshEmailOtpSigningSessionDomain(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpEcdsaCapabilityResult> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpUnlockFlowId(walletId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(
      args.chainTarget,
      'Email OTP signing-session refresh',
    );
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      walletId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      requestId: args.challengeId,
    });
    try {
      const result = this.walletIframe.shouldUseWalletIframe()
        ? await (
            await this.walletIframe.requireRouter(walletId)
          ).refreshEmailOtpSigningSession({
            walletSession: args.walletSession,
            chainTarget,
            challengeId: args.challengeId,
            otpCode: args.otpCode,
            ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
            ...(typeof args.remainingUses === 'number'
              ? { remainingUses: args.remainingUses }
              : {}),
          })
        : await this.signingEngine.refreshEmailOtpSigningSession({
            walletSession: args.walletSession,
            chainTarget,
            challengeId: args.challengeId,
            otpCode: args.otpCode,
            ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
            ...(typeof args.remainingUses === 'number'
              ? { remainingUses: args.remainingUses }
              : {}),
          });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        requestId: args.challengeId,
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
        status: 'succeeded',
        requestId: args.challengeId,
        data: { chainTarget },
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_07_COMPLETED,
        status: 'succeeded',
        requestId: args.challengeId,
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        requestId: args.challengeId,
        error: e,
      });
      throw e;
    }
  }

  ///////////////////////////////////////
  // === User Settings ===
  ///////////////////////////////////////

  /**
   * Prefetch latest block height/hash (and nonce if context missing) to reduce
   * perceived latency when the user initiates a signing flow.
   */
  async prefetchBlockheight(): Promise<void> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter();
      await router.prefetchBlockheight();
      return;
    }
    try {
      await this.signingEngine.getNonceCoordinator().prefetchNearContext({
        kind: 'initialized_state',
        nearClient: this.nearClient,
      });
    } catch {}
  }

  /** Wallet-host entrypoint for the exact FeeManager preference operation. */
  async signTempoFeeTokenPreferenceInternal(args: {
    walletSession: WalletSessionRef;
    request: TempoFeeTokenPreferenceSigningRequest;
    chainTarget: TempoChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<EvmSignedResult> {
    if (!__isWalletIframeHostMode()) {
      throw new Error('[SeamsWeb][tempo] fee-token preference signing requires wallet-host mode');
    }
    const request = requireTempoFeeTokenPreferenceSigningRequest(args);
    const result = await this.signingEngine.signEvmFamily({
      ...args,
      request,
    });
    if (result.chain !== 'evm' || result.kind !== 'eip1559') {
      throw new Error(`[SeamsWeb][tempo] expected EVM FeeManager result, received ${result.chain}`);
    }
    return result;
  }

  ///////////////////////////////////////
  // === KEY MANAGEMENT ===
  ///////////////////////////////////////

  /**
   * Canonical entrypoint to show secure key export UI (wallet-origin only) without
   * returning private keys to the caller.
   */
  private async resolveExactKeyExportLaneDomain(
    input: Parameters<KeyExportCapability['resolveExactKeyExportLane']>[0],
  ): Promise<Awaited<ReturnType<KeyExportCapability['resolveExactKeyExportLane']>>> {
    const resolvedInput = normalizeResolveExactKeyExportLaneInput(input);
    const routerAccountId = String(resolvedInput.walletSession.walletId || '').trim();
    if (!routerAccountId) {
      throw new Error('[SeamsWeb] key export lane resolution requires wallet session context');
    }

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(routerAccountId);
      const result = await router.resolveExactKeyExportLane(resolvedInput);
      return normalizeResolveExactKeyExportLaneResult(result);
    }

    const result = await this.signingEngine.resolveExactKeyExportLane(resolvedInput);
    return normalizeResolveExactKeyExportLaneResult(result);
  }

  private async exportKeypairWithUIDomain(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<void> {
    const resolvedInput = normalizeExportKeypairWithUIInput(input, this.theme);
    const routerAccountId = String(resolvedInput.walletSession.walletId || '').trim();
    if (!routerAccountId) {
      throw new Error('[SeamsWeb] key export requires wallet session user context');
    }

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(routerAccountId);
      await router.exportKeypairWithUI(resolvedInput);
      return;
    }

    await this.signingEngine.exportKeypairWithUI(resolvedInput);
  }
}
