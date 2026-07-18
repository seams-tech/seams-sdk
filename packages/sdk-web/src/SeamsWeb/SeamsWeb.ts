import { BrowserSigningSurface } from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import {
  addWalletSigner as addWalletSignerWithUnifiedCeremony,
  isRegistrationBenchmarkDiagnosticsEnabled,
  registerWallet as registerWalletWithUnifiedCeremony,
  WALLET_IFRAME_TRANSPORT_TIMING_LABEL,
} from '@/SeamsWeb/operations/registration/registration';
import {
  MinimalNearClient,
  type NearClient,
  type AccessKeyList,
} from '@/core/rpcClients/near/NearClient';
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
  UnlockFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  createRegistrationFlowEvent,
  createUnlockFlowEvent,
  RegistrationEventPhase,
  UnlockEventPhase,
} from '@/core/types/sdkSentEvents';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { toAccountId } from '@/core/types/accountIds';
import { IndexedDBManager } from '@/core/indexedDB';
import { ActionType } from '@/core/types/actions';
import type { PreferencesChangedPayload } from '@/SeamsWeb/walletIframe/shared/messages';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import { isUserCancellationError, toError } from '@shared/utils/errors';
import { sha256HexUtf8 } from '@shared/utils/digests';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import {
  walletAuthAuthoritiesMatch,
  type ActiveWalletSession,
} from '@shared/utils/walletAuthAuthority';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { resolveAppearanceTheme, resolveThemePalette } from '@/core/config/configHelpers';
import { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { resolveBrowserWorkerWarmupPolicy } from './assembly/browserWorkerWarmupPolicy';
import { configureBrowserIndexedDB } from './assembly/configureBrowserIndexedDB';
import { createBrowserSigningRuntime } from './assembly/createBrowserSigningRuntime';
import { createBrowserSigningStores } from './assembly/createBrowserSigningStores';
import { initializeBrowserSigningRuntime } from './assembly/initializeBrowserSigningRuntime';
import {
  getWalletSessionDomain,
  type WalletAuthDomainDeps,
} from '@/SeamsWeb/operations/auth/walletAuth';
import { createPublicApi, type WalletIframeControlCapability } from './publicApi';
import type {
  AuthCapability,
  DevicesCapability,
  EmailOtpBackedUpEnrollmentResult,
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  EmailOtpEcdsaEnrollmentCapabilityArgs,
  EmailOtpEcdsaEnrollmentCapabilityResult,
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
import type {
  EnrollEmailOtpInternalResult,
  LoginWithEmailOtpEcdsaCapabilityInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import {
  thresholdEcdsaChainTargetsEqual,
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
  parseExactEcdsaSigningLaneIdentity,
  parseExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  assertWalletRuntimePostconditions,
  type WalletRuntimeInventory,
} from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import {
  buildOperationUsableThresholdEcdsaSessionRecord,
  type EmailOtpEcdsaSessionRecord,
  type OperationUsableThresholdEcdsaSessionRecord,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { configuredEmailOtpEcdsaSnapshotChainTargets } from '@/core/signingEngine/session/emailOtp/persistedSnapshot';
import type { LoginWithEmailOtpEd25519YaoCapabilityInternalArgs } from '@/core/signingEngine/session/emailOtp/ed25519YaoLogin';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import {
  exchangeGoogleEmailOtpSession,
  requestEmailOtpChallenge,
  requestEmailOtpEnrollmentChallenge,
} from '@/SeamsWeb/operations/authMethods/emailOtp/challenge';
import { beginGoogleEmailOtpWalletAuth } from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import {
  getEmailOtpRecoveryCodeStatus,
  storeRotatedEmailOtpRecoveryCodes,
} from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import {
  activateEmailOtpWalletAfterUnlock,
  type EmailOtpWalletPostUnlockActivation,
} from '@/SeamsWeb/operations/authMethods/emailOtp/walletActivation';
import {
  walletIdFromString,
  type RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import {
  buildNearEd25519SignerBinding,
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
import { DEV_DEFAULT_UNLOCK_REMAINING_USES } from '@/core/signingEngine/session/budget/policy';

function requireSeamsWebRegistrationRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

type EmailOtpEd25519YaoLoginDomainArgs = Omit<
  LoginWithEmailOtpEd25519YaoCapabilityInternalArgs,
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
  activeSession: ActiveWalletSession;
  ecdsa: readonly [
    OperationUsableThresholdEcdsaSessionRecord,
    ...OperationUsableThresholdEcdsaSessionRecord[],
  ];
  runtimeState: EmailOtpUnlockActiveRuntimeState;
};

type EmailOtpUnlockTimingBucket =
  | 'emailOtpProofVerificationMs'
  | 'appSessionExchangeMs'
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
    appSessionExchangeMs: 0,
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
  timings[bucket] += Math.max(0, Math.round(nowMs() - startedAtMs));
}

function recordEmailOtpUnlockElapsedTiming(
  timings: Record<EmailOtpUnlockTimingBucket, number>,
  bucket: EmailOtpUnlockTimingBucket,
  durationMs: number,
): void {
  timings[bucket] += Math.max(0, Math.round(durationMs));
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
  console.info(`[EmailOtpUnlock] timing summary ${JSON.stringify(summary)}`);
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

function assertEmailOtpUnlockEcdsaRecord(
  record: OperationUsableThresholdEcdsaSessionRecord,
): asserts record is OperationUsableThresholdEcdsaSessionRecord & EmailOtpEcdsaSessionRecord {
  if (record.source !== 'email_otp') {
    throw new Error('Email OTP unlock ECDSA current record is missing Email OTP authority');
  }
  if (!record.emailOtpAuthContext) {
    throw new Error('Email OTP unlock ECDSA current record is missing Email OTP authority');
  }
  if (!String(record.walletSessionJwt || '').trim()) {
    throw new Error('Email OTP unlock ECDSA current record is missing bearer JWT');
  }
}

function requireEmailOtpUnlockBearerJwt(value: string, label: string): string {
  const jwt = String(value || '').trim();
  if (!jwt) {
    throw new Error(`Email OTP unlock ${label} current record is missing bearer JWT`);
  }
  return jwt;
}

function buildEmailOtpUnlockActiveSession(args: {
  walletSession: WalletSessionRef;
  ecdsa: readonly [
    OperationUsableThresholdEcdsaSessionRecord,
    ...OperationUsableThresholdEcdsaSessionRecord[],
  ];
}): ActiveWalletSession {
  const [firstRecord, ...remainingRecords] = args.ecdsa;
  assertEmailOtpUnlockEcdsaRecord(firstRecord);
  const authority = firstRecord.emailOtpAuthContext.authority;
  if (authority.walletId !== args.walletSession.walletId) {
    throw new Error('Email OTP unlock active session wallet id does not match wallet session');
  }
  const walletSessionJwt = requireEmailOtpUnlockBearerJwt(firstRecord.walletSessionJwt, 'ECDSA');
  for (const record of remainingRecords) {
    assertEmailOtpUnlockEcdsaRecord(record);
    const ecdsaAuthority = record.emailOtpAuthContext.authority;
    if (!walletAuthAuthoritiesMatch(authority, ecdsaAuthority)) {
      throw new Error('Email OTP unlock ECDSA current record authority mismatch');
    }
    requireEmailOtpUnlockBearerJwt(record.walletSessionJwt, 'ECDSA');
  }
  return {
    kind: 'active_wallet_session',
    authority,
    walletSessionJwt,
  };
}

function requireEmailOtpUnlockEcdsaCurrentRecord(
  capability: LoginWithEmailOtpEcdsaCapabilityInternalResult['warmCapabilities'][number],
): OperationUsableThresholdEcdsaSessionRecord {
  const record = capability.record;
  if (!record) {
    throw new Error('Email OTP ECDSA unlock did not produce a current session record');
  }
  const currentRecord = buildOperationUsableThresholdEcdsaSessionRecord(record);
  if (!currentRecord) {
    throw new Error(
      'Email OTP ECDSA unlock did not produce an operation-usable current session record',
    );
  }
  return currentRecord;
}

function requireEmailOtpUnlockEcdsaCurrentRecords(
  result: LoginWithEmailOtpEcdsaCapabilityInternalResult,
): readonly [
  OperationUsableThresholdEcdsaSessionRecord,
  ...OperationUsableThresholdEcdsaSessionRecord[],
] {
  const currentRecords = result.warmCapabilities.map((capability) =>
    requireEmailOtpUnlockEcdsaCurrentRecord(capability),
  );
  const [firstRecord, ...remainingRecords] = currentRecords;
  if (!firstRecord) {
    throw new Error('Email OTP ECDSA unlock did not produce any current session records');
  }
  return [firstRecord, ...remainingRecords];
}

function buildEmailOtpEcdsaUnlockActivationPlan(args: {
  walletSession: WalletSessionRef;
  result: LoginWithEmailOtpEcdsaCapabilityInternalResult;
  runtimeInventory: WalletRuntimeInventory;
}): EmailOtpUnlockActivationPlan {
  const ecdsa = requireEmailOtpUnlockEcdsaCurrentRecords(args.result);
  return {
    kind: 'email_otp_unlock_activation_plan_v1',
    mode: 'evm_family_ecdsa',
    activeSession: buildEmailOtpUnlockActiveSession({
      walletSession: args.walletSession,
      ecdsa,
    }),
    ecdsa,
    runtimeState: emailOtpUnlockActiveRuntimeState(args.runtimeInventory),
  };
}

function logEmailOtpUnlockActivationPlan(plan: EmailOtpUnlockActivationPlan): void {
  console.info('[EmailOtpUnlock] activation plan constructed', {
    kind: plan.kind,
    mode: plan.mode,
    walletId: plan.activeSession.authority.walletId,
    authorityBindingId: plan.activeSession.authority.bindingId,
    ecdsaThresholdSessionIds: plan.ecdsa.map((record) => record.thresholdSessionId),
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

function emailOtpEd25519SignerFromRecoveredRecord(
  record: ThresholdEd25519SessionRecord,
): NearEd25519SignerBinding {
  return buildNearEd25519SignerBinding({
    account: requireNearAccountBindingForOperation({
      walletId: record.walletId,
      nearAccountId: String(record.nearAccountId),
      operation: 'Email OTP wallet activation',
    }),
    nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
    signerSlot: record.signerSlot,
  });
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

type ExportKeypairWithUIBoundaryInput = Parameters<KeyExportCapability['exportKeypairWithUI']>[0];
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
    case 'ecdsa':
      return {
        kind: 'ecdsa',
        laneIdentity: parseExactEcdsaSigningLaneIdentity(result.laneIdentity),
      };
    case 'ed25519':
      return {
        kind: 'ed25519',
        laneIdentity: parseExactEd25519SigningLaneIdentity(result.laneIdentity),
      };
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
      const laneIdentity = parseExactEd25519SigningLaneIdentity(input.laneIdentity);
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
  private emailOtpUnlockPrewarmRecord: EmailOtpUnlockPrewarmRecord = { kind: 'none' };

  constructor(
    configs: SeamsConfigsInput,
    nearClient?: NearClient,
    internalOptions?: { allowDirectWalletMode?: 'wallet_host' },
  ) {
    this.configs = buildConfigsFromEnv(configs, {
      ...(internalOptions?.allowDirectWalletMode === 'wallet_host'
        ? { allowDirectWalletMode: 'wallet_host' }
        : {}),
    });
    configureBrowserIndexedDB(this.configs);
    // Use provided client or create default one
    this.nearClient =
      nearClient || new MinimalNearClient(resolvePrimaryNearRpcUrl(this.configs.network.chains));
    const browserSigningStores = createBrowserSigningStores(IndexedDBManager);
    this.signingEngine = new BrowserSigningSurface(this.configs, this.nearClient, {
      managerStores: browserSigningStores.managerStores,
      signingEngineStores: browserSigningStores.signingEngineStores,
      sealedSigningSessionStore: browserSigningStores.sealedSigningSessionStore,
      ed25519YaoPublicCapabilityReferences:
        browserSigningStores.ed25519YaoPublicCapabilityReferences,
      createRuntime: createBrowserSigningRuntime,
      initializeRuntime: initializeBrowserSigningRuntime,
      workerWarmupPolicy: resolveBrowserWorkerWarmupPolicy(this.configs),
    });

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
      refreshWalletSession: async (walletId?: string) => {
        await getWalletSessionDomain(this.getWalletAuthDeps(), walletId);
      },
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
        exchangeGoogleEmailOtpSession: async (args) =>
          await this.exchangeGoogleEmailOtpSessionDomain(args),
        loginWithEmailOtpEcdsaCapability: async (args) =>
          await this.loginWithEmailOtpEcdsaCapabilityDomain(args),
        beginGoogleEmailOtpWalletAuth: async (args) =>
          await this.beginGoogleEmailOtpWalletAuthDomain(args),
      },
      registration: {
        addWalletSigner: async (args) => await this.registerWalletSignerDomain(args),
        registerWallet: async (args) => await this.registerWalletDomain(args),
        registerPasskey: async (options) => await this.registerPasskeyDomain(options),
        requestEmailOtpEnrollmentChallenge: async (args) =>
          await this.requestEmailOtpEnrollmentChallengeDomain(args),
        enrollEmailOtp: async (args) => await this.enrollEmailOtpDomain(args),
        enrollAndLoginWithEmailOtpEcdsaCapability: async (args) =>
          await this.enrollAndLoginWithEmailOtpEcdsaCapabilityDomain(args),
      },
      recovery: {
        getEmailOtpRecoveryCodeStatus: async (args) =>
          await this.getEmailOtpRecoveryCodeStatusDomain(args),
        rotateEmailOtpRecoveryCodes: async (args) =>
          await this.rotateEmailOtpRecoveryCodesDomain(args),
      },
      devices: {
        viewAccessKeyList: async (args) => await this.viewAccessKeyListDomain(args),
        deleteDeviceKey: async (args) => await this.deleteDeviceKeyDomain(args),
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
  async initWalletIframe(walletId?: string): Promise<void> {
    await this.walletIframeControls.initWalletIframe(walletId);
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
    this.signingEngine.dispose();
  }

  private getWalletAuthDeps(): WalletAuthDomainDeps {
    return {
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
      signingEngine: this.signingEngine,
      nearClient: this.nearClient,
      initWalletIframe: async (walletId?: string) => {
        await this.initWalletIframe(walletId);
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

  /**
   */
  private async viewAccessKeyListDomain(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
  }): Promise<AccessKeyList> {
    const accountId = String(args.nearAccount.accountId);
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletSession.walletId);
      return await router.viewAccessKeyList({
        walletId: args.walletSession.walletId,
        nearAccountId: accountId,
      });
    }
    return this.nearClient.viewAccessKeyList(accountId);
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

  private async registerPasskeyDomain(
    options: Parameters<RegistrationCapability['registerPasskey']>[0] = {},
  ): Promise<RegistrationResult> {
    if (typeof options === 'string') {
      throw new Error(
        '[SeamsWeb] registration.registerPasskey no longer accepts a NEAR account id; call registration.registerPasskey(options) for implicit NEAR registration or registerWallet(...) with explicit sponsored accountProvisioning.',
      );
    }
    const { wallet, nearAccountProvisioning, ...registrationOptions } = options || {};
    const rpId = requireSeamsWebRegistrationRpId(this.signingEngine.getRpId());
    if (!rpId) {
      throw new Error('Missing rpId for Router API registration');
    }
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
    appSessionJwt?: string;
    operation?: WalletEmailOtpLoginOperation;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult> {
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
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
        ...(args.operation ? { operation: args.operation } : {}),
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
    appSessionJwt?: string;
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
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
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

  private async exchangeGoogleEmailOtpSessionDomain(args: {
    idToken: string;
    accountMode: 'register' | 'login';
    relayUrl?: string;
    sessionKind?: 'jwt' | 'cookie';
    onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
  }): Promise<Awaited<ReturnType<typeof exchangeGoogleEmailOtpSession>>> {
    const exchangeFlowId = `email-otp-${args.accountMode}:google-session`;
    const exchangeStartedAtMs = nowMs();
    if (args.accountMode === 'register') {
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId: exchangeFlowId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_STARTED,
        status: 'running',
      });
    } else {
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId: exchangeFlowId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
        status: 'running',
      });
    }
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter();
        const result = await router.exchangeGoogleEmailOtpSession(args);
        const walletId = String(result.session?.walletId || '').trim();
        if (args.accountMode === 'register') {
          this.emitEmailOtpRegistrationEvent(args.onEvent, {
            flowId: walletId ? this.emailOtpRegistrationFlowId(walletId) : exchangeFlowId,
            ...(walletId ? { walletId } : {}),
            authMethod: 'email_otp',
            phase: RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_SUCCEEDED,
            status: 'succeeded',
            data: {
              googleEmailOtpResolution: result.session?.googleEmailOtpResolution,
            },
          });
        } else {
          this.emitEmailOtpUnlockEvent(args.onEvent, {
            flowId: walletId ? this.emailOtpUnlockFlowId(walletId) : exchangeFlowId,
            ...(walletId ? { walletId } : {}),
            authMethod: 'email_otp',
            phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
            status: 'succeeded',
            data: {
              appSessionExchangeMs: Math.max(0, Math.round(nowMs() - exchangeStartedAtMs)),
            },
          });
        }
        return result;
      }
      const managedRegistration =
        this.configs.registration.mode === 'managed' ? this.configs.registration : null;
      const result = await exchangeGoogleEmailOtpSession({
        relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
        idToken: args.idToken,
        accountMode: args.accountMode,
        ...(args.sessionKind ? { sessionKind: args.sessionKind } : {}),
        ...(managedRegistration
          ? {
              projectEnvironmentId: managedRegistration.projectEnvironmentId,
              publishableKey: managedRegistration.publishableKey,
            }
          : {}),
      });
      const walletId = String(result.session?.walletId || '').trim();
      if (args.accountMode === 'register') {
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId: walletId ? this.emailOtpRegistrationFlowId(walletId) : exchangeFlowId,
          ...(walletId ? { walletId } : {}),
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
          data: {
            googleEmailOtpResolution: result.session?.googleEmailOtpResolution,
          },
        });
      } else {
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId: walletId ? this.emailOtpUnlockFlowId(walletId) : exchangeFlowId,
          ...(walletId ? { walletId } : {}),
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
          data: {
            appSessionExchangeMs: Math.max(0, Math.round(nowMs() - exchangeStartedAtMs)),
          },
        });
      }
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      if (args.accountMode === 'register') {
        this.emitEmailOtpRegistrationFailure(args.onEvent, {
          flowId: exchangeFlowId,
          authMethod: 'email_otp',
          error: e,
        });
      } else {
        this.emitEmailOtpUnlockFailure(args.onEvent, {
          flowId: exchangeFlowId,
          authMethod: 'email_otp',
          error: e,
        });
      }
      throw e;
    }
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
        exchangeGoogleEmailOtpSession: async (exchangeArgs) =>
          await this.exchangeGoogleEmailOtpSessionDomain(exchangeArgs),
        requestEmailOtpChallenge: async (challengeArgs) =>
          await this.requestEmailOtpChallengeDomain(challengeArgs),
        registerWallet: async (registerArgs) => await this.registerWalletDomain(registerArgs),
        loginWithEmailOtpEcdsaCapability: async (loginArgs) =>
          await this.loginWithEmailOtpEcdsaCapabilityDomain(loginArgs),
        loginWithEmailOtpEd25519YaoCapability:
          this.loginWithEmailOtpEd25519YaoCapabilityDomain.bind(this),
        getWalletSession: async (walletId) =>
          await getWalletSessionDomain(this.getWalletAuthDeps(), walletId),
      },
      args,
    );
  }

  private async enrollEmailOtpDomain(args: {
    walletId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EnrollEmailOtpInternalResult | EmailOtpBackedUpEnrollmentResult> {
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
        ...(args.shamirPrimeB64u ? { shamirPrimeB64u: args.shamirPrimeB64u } : {}),
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
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

  private async getEmailOtpRecoveryCodeStatusDomain(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) {
    const relayUrl = String(args.relayUrl || this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.getEmailOtpRecoveryCodeStatus({
        walletId: args.walletId,
        relayUrl,
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
    }
    const appSessionJwt = await this.resolveEmailOtpRecoveryCodeAppSessionJwt({
      walletId: args.walletId,
      relayUrl,
      appSessionJwt: args.appSessionJwt,
    });
    return await getEmailOtpRecoveryCodeStatus({
      relayUrl,
      walletId: args.walletId,
      ...(appSessionJwt ? { appSessionJwt } : {}),
    });
  }

  async showEmailOtpRecoveryCodesForAccountMenu(args: { walletId: string }) {
    return await this.showEmailOtpRecoveryCodesDomain({
      walletId: args.walletId,
    });
  }

  private async showEmailOtpRecoveryCodesDomain(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) {
    const relayUrl = String(args.relayUrl || this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.showEmailOtpRecoveryCodes({
        walletId: args.walletId,
        relayUrl,
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
    }
    const status = await this.getEmailOtpRecoveryCodeStatusDomain(args);
    return { status, displayedStoredCodes: false };
  }

  private async rotateEmailOtpRecoveryCodesDomain(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) {
    const relayUrl = String(args.relayUrl || this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.rotateEmailOtpRecoveryCodes({
        walletId: args.walletId,
        relayUrl,
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
    }
    const appSessionJwt = await this.resolveEmailOtpRecoveryCodeAppSessionJwt({
      walletId: args.walletId,
      relayUrl,
      appSessionJwt: args.appSessionJwt,
    });
    const rotation = await this.signingEngine.rotateEmailOtpRecoveryCodesInternal({
      walletId: toWalletId(args.walletId),
      relayUrl,
      ...(appSessionJwt ? { appSessionJwt } : {}),
    });
    const recoveryCodeBackup = await storeRotatedEmailOtpRecoveryCodes({
      walletId: args.walletId,
      rotation,
      storageScope: 'host_origin_indexeddb',
    });
    const status = await this.getEmailOtpRecoveryCodeStatusDomain({
      walletId: args.walletId,
      relayUrl,
      ...(appSessionJwt ? { appSessionJwt } : {}),
    });
    return { status, recoveryCodeBackup };
  }

  private async resolveEmailOtpRecoveryCodeAppSessionJwt(args: {
    walletId: string;
    relayUrl: string;
    appSessionJwt?: string;
  }): Promise<string> {
    const providedJwt = String(args.appSessionJwt || '').trim();
    if (providedJwt) return providedJwt;
    const walletId = toWalletId(args.walletId);
    const session = await getWalletSessionDomain(this.getWalletAuthDeps(), walletId);
    const walletSessionUserId = String(session.login.walletId || '').trim();
    if (walletSessionUserId !== String(walletId)) {
      throw new Error(
        '[SeamsWeb] recovery-code app-session resolution requires a wallet-bound session',
      );
    }
    return await this.signingEngine.resolveEmailOtpAppSessionJwt({
      walletSession: walletSessionRefFromSession({
        walletId,
        walletSessionUserId,
      }),
      relayUrl: args.relayUrl,
    });
  }

  private async requireEmailOtpWalletAuthMethodEmailHashHex(walletId: WalletId): Promise<string> {
    const normalizedWalletId = String(walletId || '').trim();
    if (!normalizedWalletId) {
      throw new Error('[SeamsWeb][email-otp] walletId is required for auth-method binding');
    }
    const authMethods = await IndexedDBManager.listWalletAuthMethodsForWallet(normalizedWalletId);
    const matches = authMethods.filter(
      (record) => record.kind === 'email_otp' && record.status === 'active',
    );
    if (matches.length !== 1) {
      throw new Error(
        '[SeamsWeb][email-otp] expected one active Email OTP wallet auth-method binding',
      );
    }
    const emailHashHex = String(matches[0].emailHashHex || '').trim();
    if (!emailHashHex) {
      throw new Error('[SeamsWeb][email-otp] Email OTP wallet auth-method binding is missing hash');
    }
    return emailHashHex;
  }

  private async loginWithEmailOtpEd25519YaoCapabilityDomain(
    args: EmailOtpEd25519YaoLoginDomainArgs,
  ): Promise<void> {
    const emailHashHex = await this.requireEmailOtpWalletAuthMethodEmailHashHex(
      args.walletSession.walletId,
    );
    const record = await this.signingEngine.loginWithEmailOtpEd25519YaoCapabilityInternal({
      ...args,
      emailHashHex,
    });
    await activateEmailOtpWalletAfterUnlock(
      { signingEngine: this.signingEngine, nearClient: this.nearClient },
      {
        kind: 'near_ed25519_wallet',
        signer: emailOtpEd25519SignerFromRecoveredRecord(record),
      },
    );
  }

  private async emailOtpEmailHashHex(email: string | undefined): Promise<string> {
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
      const emailHashHex = await this.requireEmailOtpWalletAuthMethodEmailHashHex(walletId);
      recordEmailOtpUnlockTiming(unlockTiming.timings, 'emailHashLookupMs', timingStartedAtMs);
      timingStartedAtMs = nowMs();
      const preparedEd25519YaoRecovery =
        await this.signingEngine.prepareEmailOtpEd25519YaoLoginRecoveryInternal({
          walletSession: args.walletSession,
          emailHashHex,
          remainingUses: Math.min(
            Math.max(
              1,
              Math.floor(
                Number(this.configs.signing.sessionDefaults?.remainingUses) ||
                  DEV_DEFAULT_UNLOCK_REMAINING_USES,
              ),
            ),
            DEV_DEFAULT_UNLOCK_REMAINING_USES,
          ),
        });
      const result = await this.signingEngine.loginWithEmailOtpEcdsaCapabilityInternal({
        ...args,
        chainTarget,
        emailHashHex,
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        providerIdentity: { kind: 'derive_from_route_auth' },
        ...(preparedEd25519YaoRecovery
          ? {
              ed25519YaoRecovery: {
                kind: 'requested' as const,
                providerSubject: preparedEd25519YaoRecovery.providerSubject,
                signerSlot: preparedEd25519YaoRecovery.signerSlot,
              },
            }
          : {}),
        onProgress: markWorkerProgress,
      });
      let walletActivation: EmailOtpWalletPostUnlockActivation;
      if (preparedEd25519YaoRecovery) {
        if (result.ed25519YaoRecovery.kind !== 'unlocked') {
          throw new Error('Mixed Email OTP unlock omitted Ed25519 Yao recovery material');
        }
        const recoveredEd25519Record =
          await this.signingEngine.activateEmailOtpEd25519YaoUnlockedRecoveryInternal({
            prepared: preparedEd25519YaoRecovery,
            bootstrap: result.ed25519YaoRecovery.bootstrap,
            pendingFactorHandle: result.ed25519YaoRecovery.pendingFactorHandle,
          });
        walletActivation = {
          kind: 'near_ed25519_wallet',
          signer: emailOtpEd25519SignerFromRecoveredRecord(recoveredEd25519Record),
        };
      } else if (result.ed25519YaoRecovery.kind !== 'not_requested') {
        throw new Error(
          'EVM-family ECDSA Email OTP unlock returned unexpected Ed25519 Yao material',
        );
      } else {
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
        authMethod: 'email_otp',
        requiredTargets: [
          ...(preparedEd25519YaoRecovery ? [{ curve: 'ed25519' as const }] : []),
          ...configuredEmailOtpEcdsaSnapshotChainTargets(this.configs).map((target) => ({
            curve: 'ecdsa' as const,
            chainTarget: target,
          })),
        ],
        readPersistedAvailableSigningLanes: async (input) =>
          await this.signingEngine.readPersistedAvailableSigningLanes(input),
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

  private async enrollAndLoginWithEmailOtpEcdsaCapabilityDomain(
    args: EmailOtpEcdsaEnrollmentCapabilityArgs,
  ): Promise<EmailOtpEcdsaEnrollmentCapabilityResult> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpRegistrationFlowId(walletId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(
      args.chainTarget,
      'Email OTP ECDSA enrollment',
    );
    this.emitEmailOtpRegistrationEvent(args.onEvent, {
      flowId,
      walletId,
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
        const router = await this.walletIframe.requireRouter(walletId);
        const iframeArgs = { ...args, chainTarget };
        delete iframeArgs.clientSecret32;
        delete iframeArgs.onEvent;
        const result = await router.enrollAndLoginWithEmailOtpEcdsaCapability(iframeArgs);
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { otpChannel: result.enrollment.otpChannel },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { otpChannel: result.enrollment.otpChannel },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_11_COMPLETED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        return result;
      }
      const workerProgressPhases = new Set<RegistrationEventPhase>();
      const markWorkerProgress = (progress: EmailOtpWorkerProgressEvent) => {
        const phase = this.emitEmailOtpRegistrationWorkerProgress(args.onEvent, {
          flowId,
          walletId,
          challengeId: args.challengeId,
          chainTarget,
          progress,
        });
        if (phase) workerProgressPhases.add(phase);
      };
      const emitIfWorkerProgressMissing = (input: CreateRegistrationFlowEventInput) => {
        if (workerProgressPhases.has(input.phase)) return;
        this.emitEmailOtpRegistrationEvent(args.onEvent, input);
      };
      const emailHashHex = await this.emailOtpEmailHashHex(args.emailOtpAuthorityEmail);
      const result = await this.signingEngine.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal({
        ...args,
        chainTarget,
        emailHashHex,
        onProgress: markWorkerProgress,
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { otpChannel: result.enrollment.otpChannel },
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { otpChannel: result.enrollment.otpChannel },
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      emitIfWorkerProgressMissing({
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_11_COMPLETED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpRegistrationFailure(args.onEvent, {
        flowId,
        walletId,
        authMethod: 'email_otp',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
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
    input: Parameters<KeyExportCapability['exportKeypairWithUI']>[0],
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

  /**
   * Delete a device key from an account
   */
  private async deleteDeviceKeyDomain(
    args: Parameters<DevicesCapability['deleteDeviceKey']>[0],
  ): Promise<ActionResult> {
    const accountId = String(args.nearAccount.accountId);
    // Validate that we're not deleting the last key
    const keysView = await this.viewAccessKeyListDomain({
      walletSession: args.walletSession,
      nearAccount: args.nearAccount,
    });
    if (keysView.keys.length <= 1) {
      throw new Error('Cannot delete the last access key from an account');
    }

    // Find the key to delete
    const keyToDelete = keysView.keys.find(
      (k: { public_key: string }) => k.public_key === args.publicKeyToDelete,
    );
    if (!keyToDelete) {
      throw new Error(`Access key ${args.publicKeyToDelete} not found on account ${accountId}`);
    }

    // Use NEAR signer executeAction with DeleteKey action
    return this.near.executeAction({
      walletSession: args.walletSession,
      nearAccount: args.nearAccount,
      receiverId: accountId,
      actionArgs: {
        type: ActionType.DeleteKey,
        publicKey: args.publicKeyToDelete,
      },
      options: args.options,
    });
  }
}
