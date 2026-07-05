import {
  computeRegistrationIntentDigestB64u,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  nearEd25519SigningKeyIdFromString,
  registrationIntentGrantFromString,
  registrationSignerPlanFromSelection,
  type RegistrationEvmFamilyEcdsaSignerPlan,
  type RegistrationIntentV1,
  type RegistrationNearAccountProvisioning,
  type RegistrationNearEd25519SignerPlan,
  type RegistrationSignerPlan,
  type ResolvedRegistrationNearAccount,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { deriveSigningRootId, type RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  AccountCreationResult,
  ThresholdEd25519BootstrapSession,
  type ThresholdEd25519HssRegistrationServerEvalSource,
} from '../../core/types';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../../core/thresholdEcdsaChainTarget';
import {
  registrationPreparationIdFromString,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationPrepareRequest,
  WalletRegistrationPrepareResponse,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationHssAdvanceStateRequest,
  WalletRegistrationHssAdvanceStateResponse,
  WalletRegistrationHssRespondRequest,
  WalletRegistrationHssRespondResponse,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
  type Ed25519HssAdvanceSource,
  type Ed25519HssFinalizeSource,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
} from '../../core/registrationContracts';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../core/ThresholdService';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import type { WalletStore } from '../../core/d1WalletStore';
import type { WebAuthnCredentialBindingStore } from '../../core/WebAuthnCredentialBindingStore';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import {
  buildStoredWalletRegistrationPreparedContext,
  buildStoredWalletRegistrationHssPreparationPrepared,
  buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch,
  buildStoredWalletRegistrationNearEd25519PreparedBranch,
  findStoredWalletRegistrationEvmFamilyEcdsaBranch,
  findStoredWalletRegistrationNearEd25519Branch,
  getPreparedWalletRegistrationHssPreparation,
  replaceStoredWalletRegistrationSignerBranch,
  storedEd25519RegistrationPrepareScopesMatch,
  type StoredWalletRegistrationPreparedContext,
} from '../../core/RegistrationCeremonyStore';
import {
  buildD1EcdsaWalletKeysFromBootstrap,
  buildD1DurableEd25519HssAdvanceClaimRecord,
  buildD1DurableEd25519HssAdvancedEvalRecord,
  buildD1DurableEd25519HssFinalizedReportRecord,
  buildD1WalletEcdsaSignerRecords,
  buildD1WalletRecord,
  isMatchingD1EcdsaClientBootstrap,
  normalizeThresholdEcdsaChainTargets,
  parseD1RegistrationIntent,
  parseD1RuntimePolicyScope,
  toD1EcdsaHssClientBootstrapRequest,
  type D1DurableEd25519HssAdvanceClaimRecord,
  type D1DurableEd25519HssAdvancedEvalRecord,
} from './d1RegistrationCeremonyRecords';
import { walletRegistrationFinalizeAuthMethodFromAuthority } from './d1WalletAuthMethodBoundary';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from './d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1WalletAuthMethodService } from './d1WalletAuthMethodService';
import { buildD1EvmFamilyEcdsaRegistrationPrepare } from './d1EvmFamilyEcdsaRegistrationBranch';
import {
  buildD1ThresholdEd25519RegistrationSessionPolicy,
  buildD1WalletEd25519SignerRecord,
  d1RegistrationAuthorityNearEd25519SigningKeyId,
  d1RegistrationAuthorityThresholdEd25519AuthorityScope,
  d1WalletAuthAuthorityFromRegistrationAuthority,
  d1RegistrationIntentSigningRootId,
  d1RegistrationIntentSigningRootVersion,
  d1ThresholdEd25519RegistrationAccountScope,
  prepareD1NearEd25519RegistrationHss,
  resolveD1NearEd25519RegistrationPrepareScope,
  respondD1NearEd25519RegistrationHss,
  toD1ThresholdEd25519BootstrapSession,
} from './d1NearEd25519RegistrationBranch';
import { sha256BytesPortable } from './d1RouterApiAuthBoundary';

type StartWalletRegistrationInput = WalletRegistrationStartRequest;
type PrepareWalletRegistrationInput = WalletRegistrationPrepareRequest;
type RespondWalletRegistrationHssInput = WalletRegistrationHssRespondRequest;
type AdvanceWalletRegistrationHssStateInput = WalletRegistrationHssAdvanceStateRequest;
type FinalizeWalletRegistrationInput = WalletRegistrationFinalizeRequest;

type EcdsaPreparedTarget = NonNullable<
  Extract<WalletRegistrationStartResponse, { ok: true }>['ecdsa']
>['targets'][number];
type EcdsaClientBootstrapTarget = NonNullable<
  WalletRegistrationHssRespondRequest['ecdsa']
>['clientBootstraps'][number];
type EcdsaServerBootstrapTarget = NonNullable<
  Extract<WalletRegistrationHssRespondResponse, { ok: true }>['ecdsa']
>['bootstraps'][number];

const ED25519_HSS_ADVANCE_CLAIM_LEASE_MS = 60_000;
const ED25519_HSS_ADVANCE_FINALIZE_WAIT_MS = 5_000;
const ED25519_HSS_ADVANCE_FINALIZE_POLL_MS = 100;

function ecdsaPreparedTargetForClientBootstrap(input: {
  readonly preparedTargets: readonly EcdsaPreparedTarget[];
  readonly actual: EcdsaClientBootstrapTarget;
}): EcdsaPreparedTarget | null {
  const actualKey = thresholdEcdsaChainTargetKey(input.actual.chainTarget);
  for (const prepared of input.preparedTargets) {
    if (thresholdEcdsaChainTargetKey(prepared.chainTarget) === actualKey) return prepared;
  }
  return null;
}

function ecdsaBootstrapForTarget(input: {
  readonly bootstraps: readonly EcdsaServerBootstrapTarget[];
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): EcdsaServerBootstrapTarget | null {
  const expectedKey = thresholdEcdsaChainTargetKey(input.chainTarget);
  for (const bootstrap of input.bootstraps) {
    if (thresholdEcdsaChainTargetKey(bootstrap.chainTarget) === expectedKey) return bootstrap;
  }
  return null;
}

function ecdsaTargetKeys(
  targets: readonly { chainTarget: ThresholdEcdsaChainTarget }[],
): Set<string> {
  const keys = new Set<string>();
  for (const target of targets) {
    keys.add(thresholdEcdsaChainTargetKey(target.chainTarget));
  }
  return keys;
}

function ecdsaTargetCoverageMatches(input: {
  readonly expected: readonly { chainTarget: ThresholdEcdsaChainTarget }[];
  readonly actual: readonly { chainTarget: ThresholdEcdsaChainTarget }[];
}): boolean {
  const expected = ecdsaTargetKeys(input.expected);
  const actual = ecdsaTargetKeys(input.actual);
  if (expected.size !== input.expected.length || actual.size !== input.actual.length) return false;
  if (expected.size !== actual.size) return false;
  for (const key of expected) {
    if (!actual.has(key)) return false;
  }
  return true;
}
type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type ThresholdSigningServiceProvider = () => ThresholdSigningService | null;
type WalletStoreProvider = () => WalletStore;
type WebAuthnCredentialBindingStoreProvider = () => WebAuthnCredentialBindingStore;
type SponsoredNamedNearAccountCreator = (input: {
  readonly accountId: string;
  readonly publicKey: string;
}) => Promise<AccountCreationResult>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

type D1RegistrationRouteTimingMark = {
  readonly name: WalletRegistrationRouteTimingName;
  readonly startedAtMs: number;
};

type D1RegistrationRouteTimingRecorder = {
  readonly route: WalletRegistrationRouteDiagnostics['route'];
  readonly entries: WalletRegistrationRouteDiagnostics['entries'];
  ed25519HssAdvance?: {
    source: Ed25519HssAdvanceSource;
  };
  ed25519HssFinalize?: {
    source: Ed25519HssFinalizeSource;
  };
};

function createD1RegistrationRouteTimingRecorder(
  route: WalletRegistrationRouteDiagnostics['route'],
): D1RegistrationRouteTimingRecorder {
  return {
    route,
    entries: [],
  };
}

function startD1RegistrationRouteTiming(
  name: WalletRegistrationRouteTimingName,
): D1RegistrationRouteTimingMark {
  return {
    name,
    startedAtMs: Date.now(),
  };
}

function finishD1RegistrationRouteTiming(
  recorder: D1RegistrationRouteTimingRecorder,
  mark: D1RegistrationRouteTimingMark,
): void {
  recorder.entries.push({
    name: mark.name,
    durationMs: Math.max(0, Date.now() - mark.startedAtMs),
  });
}

function appendD1RegistrationRouteTiming(
  recorder: D1RegistrationRouteTimingRecorder,
  name: WalletRegistrationRouteTimingName,
  durationMs: number,
): void {
  recorder.entries.push({
    name,
    durationMs: Math.max(0, Math.round(durationMs)),
  });
}

function recordD1RegistrationEd25519HssFinalizeSource(input: {
  readonly recorder: D1RegistrationRouteTimingRecorder;
  readonly source: Ed25519HssFinalizeSource;
}): void {
  input.recorder.ed25519HssFinalize = {
    source: input.source,
  };
}

function recordD1RegistrationEd25519HssAdvanceSource(input: {
  readonly recorder: D1RegistrationRouteTimingRecorder;
  readonly source: Ed25519HssAdvanceSource;
}): void {
  input.recorder.ed25519HssAdvance = {
    source: input.source,
  };
}

function d1RegistrationRouteDiagnostics(
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationRouteDiagnostics {
  const diagnostics: WalletRegistrationRouteDiagnostics = {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: recorder.route,
    entries: recorder.entries.map((entry) => ({
      name: entry.name,
      durationMs: entry.durationMs,
    })),
  };
  if (recorder.ed25519HssAdvance) {
    diagnostics.ed25519HssAdvance = recorder.ed25519HssAdvance;
  }
  if (recorder.ed25519HssFinalize) {
    diagnostics.ed25519HssFinalize = recorder.ed25519HssFinalize;
  }
  return diagnostics;
}

type ThresholdEd25519HssFinalizeForRegistrationTimings = NonNullable<
  Extract<
    Awaited<ReturnType<ThresholdSigningService['ed25519Hss']['finalizeForRegistration']>>,
    { ok: true }
  >['finalizeReportTimings']
>;

type ThresholdEd25519HssAdvanceForRegistrationTimings = NonNullable<
  Extract<
    Awaited<ReturnType<ThresholdSigningService['ed25519Hss']['advanceForRegistration']>>,
    { ok: true }
  >['advanceServerEvalTimings']
>;

function appendThresholdEd25519HssAdvanceRouteTimings(input: {
  readonly recorder: D1RegistrationRouteTimingRecorder;
  readonly timings: ThresholdEd25519HssAdvanceForRegistrationTimings;
}): void {
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssAdvanceStateDecodeStateMs',
    input.timings.decodeStateMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssAdvanceStateSerializedSessionMaterializeMs',
    input.timings.serializedSessionMaterializeMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssAdvanceStateAddStageResponseMs',
    input.timings.advanceAddStageResponseMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssAdvanceStateMessageScheduleRoundsMs',
    input.timings.advanceMessageScheduleRoundsMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssAdvanceStateRoundCoreRoundsMs',
    input.timings.advanceRoundCoreRoundsMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssAdvanceStateEncodeAdvancedStateMs',
    input.timings.encodeAdvancedStateMs,
  );
}

function appendThresholdEd25519HssFinalizeRouteTimings(input: {
  readonly recorder: D1RegistrationRouteTimingRecorder;
  readonly timings: ThresholdEd25519HssFinalizeForRegistrationTimings;
}): void {
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeDecodeArtifactMs',
    input.timings.decodeArtifactMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeSerializedSessionMaterializeMs',
    input.timings.serializedSessionMaterializeMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeAdvanceAddStageResponseMs',
    input.timings.advanceAddStageResponseMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeAdvanceMessageScheduleRoundsMs',
    input.timings.advanceMessageScheduleRoundsMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeAdvanceRoundCoreRoundsMs',
    input.timings.advanceRoundCoreRoundsMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeAdvanceOutputProjectionMs',
    input.timings.advanceOutputProjectionMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeReportMs',
    input.timings.finalizeReportMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizePacketAssemblyMs',
    input.timings.finalizePacketAssemblyMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeEncodeReportMs',
    input.timings.encodeReportMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeOpenServerOutputMs',
    input.timings.openServerOutputMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeOpenSeedOutputMs',
    input.timings.openSeedOutputMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeDeriveSeedKeypairMs',
    input.timings.deriveSeedKeypairMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeDeriveRelayerVerifyingShareMs',
    input.timings.deriveRelayerVerifyingShareMs,
  );
  appendD1RegistrationRouteTiming(
    input.recorder,
    'registrationHssFinalizeKeyStorePutMs',
    input.timings.keyStorePutMs,
  );
}

async function d1Ed25519HssAddStageRequestDigestB64u(input: {
  readonly addStageRequestMessageB64u: string;
}): Promise<string | null> {
  const addStageRequestMessageB64u = toOptionalTrimmedString(input.addStageRequestMessageB64u);
  if (!addStageRequestMessageB64u) return null;
  try {
    const bytes = base64UrlDecode(addStageRequestMessageB64u);
    const digest = await sha256BytesPortable(bytes);
    return base64UrlEncode(digest);
  } catch {
    return null;
  }
}

type D1Ed25519HssDurableAdvancedEvalForFinalize =
  | { readonly kind: 'ready'; readonly record: D1DurableEd25519HssAdvancedEvalRecord }
  | {
      readonly kind: 'in_flight';
      readonly claim: Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'in_flight' }>;
      readonly retryAfterMs: number;
    }
  | {
      readonly kind: 'failed';
      readonly claim: Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'failed' }>;
    }
  | { readonly kind: 'missing' }
  | { readonly kind: 'invalid_fulfilled_claim' };

function buildD1Ed25519HssAdvanceInFlightClaim(input: {
  readonly ceremonyHandle: string;
  readonly addStageRequestDigestB64u: string;
  readonly nowMs: number;
  readonly expiresAtMs: number;
}): Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'in_flight' }> {
  return buildD1DurableEd25519HssAdvanceClaimRecord({
    state: 'in_flight',
    ceremonyHandle: input.ceremonyHandle,
    addStageRequestDigestB64u: input.addStageRequestDigestB64u,
    claimId: `ehss-advclaim_${secureRandomBase64Url(24)}`,
    leaseExpiresAtMs: input.nowMs + ED25519_HSS_ADVANCE_CLAIM_LEASE_MS,
    attempt: {
      route: 'wallets_register_hss_advance_state',
      startedAtMs: input.nowMs,
    },
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
    expiresAtMs: input.expiresAtMs,
  });
}

function buildD1Ed25519HssAdvanceFulfilledClaim(input: {
  readonly claim: Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'in_flight' }>;
  readonly nowMs: number;
}): Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'fulfilled' }> {
  return buildD1DurableEd25519HssAdvanceClaimRecord({
    state: 'fulfilled',
    ceremonyHandle: input.claim.ceremonyHandle,
    addStageRequestDigestB64u: input.claim.addStageRequestDigestB64u,
    claimId: input.claim.claimId,
    advancedEval: {
      ceremonyHandle: input.claim.ceremonyHandle,
      addStageRequestDigestB64u: input.claim.addStageRequestDigestB64u,
    },
    createdAtMs: input.claim.createdAtMs,
    updatedAtMs: input.nowMs,
    expiresAtMs: input.claim.expiresAtMs,
  });
}

function buildD1Ed25519HssAdvanceFailedClaim(input: {
  readonly claim: Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'in_flight' }>;
  readonly nowMs: number;
  readonly code: string;
  readonly message: string;
}): Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'failed' }> {
  return buildD1DurableEd25519HssAdvanceClaimRecord({
    state: 'failed',
    ceremonyHandle: input.claim.ceremonyHandle,
    addStageRequestDigestB64u: input.claim.addStageRequestDigestB64u,
    claimId: input.claim.claimId,
    failure: {
      code: input.code,
      message: input.message,
    },
    createdAtMs: input.claim.createdAtMs,
    updatedAtMs: input.nowMs,
    expiresAtMs: input.claim.expiresAtMs,
  });
}

async function failD1Ed25519HssAdvanceClaim(input: {
  readonly store: CloudflareD1RegistrationCeremonyIntentStore;
  readonly claim: Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'in_flight' }>;
  readonly code: string;
  readonly message: string;
}): Promise<void> {
  await input.store.failEd25519HssAdvanceClaim(
    buildD1Ed25519HssAdvanceFailedClaim({
      claim: input.claim,
      nowMs: Date.now(),
      code: input.code,
      message: input.message,
    }),
  );
}

function d1Ed25519HssAdvanceRetryAfterMs(
  claim: Extract<D1DurableEd25519HssAdvanceClaimRecord, { state: 'in_flight' }>,
): number {
  return Math.max(100, Math.min(1_000, claim.leaseExpiresAtMs - Date.now()));
}

async function resolveD1Ed25519HssDurableAdvancedEvalForFinalize(input: {
  readonly store: CloudflareD1RegistrationCeremonyIntentStore;
  readonly ceremonyHandle: string;
  readonly addStageRequestDigestB64u: string;
}): Promise<D1Ed25519HssDurableAdvancedEvalForFinalize> {
  const deadlineMs = Date.now() + ED25519_HSS_ADVANCE_FINALIZE_WAIT_MS;
  while (Date.now() <= deadlineMs) {
    const ready = await input.store.getEd25519HssAdvancedEvalRecord({
      ceremonyHandle: input.ceremonyHandle,
      addStageRequestDigestB64u: input.addStageRequestDigestB64u,
    });
    if (ready) return { kind: 'ready', record: ready };
    const claim = await input.store.getEd25519HssAdvanceClaimRecord({
      ceremonyHandle: input.ceremonyHandle,
      addStageRequestDigestB64u: input.addStageRequestDigestB64u,
    });
    if (!claim) return { kind: 'missing' };
    switch (claim.state) {
      case 'fulfilled':
        await sleepMs(ED25519_HSS_ADVANCE_FINALIZE_POLL_MS);
        break;
      case 'failed':
        return { kind: 'failed', claim };
      case 'in_flight':
        if (claim.leaseExpiresAtMs <= Date.now()) {
          return {
            kind: 'in_flight',
            claim,
            retryAfterMs: d1Ed25519HssAdvanceRetryAfterMs(claim),
          };
        }
        await sleepMs(ED25519_HSS_ADVANCE_FINALIZE_POLL_MS);
        break;
    }
  }
  const claim = await input.store.getEd25519HssAdvanceClaimRecord({
    ceremonyHandle: input.ceremonyHandle,
    addStageRequestDigestB64u: input.addStageRequestDigestB64u,
  });
  if (claim?.state === 'in_flight') {
    return {
      kind: 'in_flight',
      claim,
      retryAfterMs: d1Ed25519HssAdvanceRetryAfterMs(claim),
    };
  }
  return claim?.state === 'fulfilled' ? { kind: 'invalid_fulfilled_claim' } : { kind: 'missing' };
}

async function sleepMs(durationMs: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, durationMs));
}

function withD1RegistrationRouteDiagnostics(
  response: WalletRegistrationFinalizeResponse,
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationFinalizeResponse {
  if (!response.ok) return response;
  return {
    ...response,
    registrationDiagnostics: d1RegistrationRouteDiagnostics(recorder),
  };
}

function withD1RegistrationStartDiagnostics(
  response: WalletRegistrationStartResponse,
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationStartResponse {
  if (!response.ok) return response;
  return {
    ...response,
    registrationDiagnostics: d1RegistrationRouteDiagnostics(recorder),
  };
}

function withD1RegistrationHssAdvanceStateDiagnostics(
  response: WalletRegistrationHssAdvanceStateResponse,
  recorder: D1RegistrationRouteTimingRecorder,
): WalletRegistrationHssAdvanceStateResponse {
  if (!response.ok) return response;
  return {
    ...response,
    registrationDiagnostics: d1RegistrationRouteDiagnostics(recorder),
  };
}

function hasUnexpectedKeyHandle(
  expectedKeyHandles: readonly string[],
  actualKeyHandles: readonly string[],
): boolean {
  if (expectedKeyHandles.length === 0) return false;
  const expected = new Set(expectedKeyHandles.map((keyHandle) => String(keyHandle || '').trim()));
  if (expected.size !== expectedKeyHandles.length || expected.size !== actualKeyHandles.length) {
    return true;
  }
  for (const keyHandle of actualKeyHandles) {
    if (!expected.has(String(keyHandle || '').trim())) return true;
  }
  return false;
}

type RegistrationIntentSignerBranches = {
  readonly plan: RegistrationSignerPlan;
  readonly nearEd25519: RegistrationNearEd25519SignerPlan | null;
  readonly evmFamilyEcdsa: RegistrationEvmFamilyEcdsaSignerPlan | null;
};

type RegistrationIntentSignerBranchesResult =
  | { ok: true; value: RegistrationIntentSignerBranches }
  | { ok: false; code: string; message: string };

function registrationIntentSignerBranches(
  intent: RegistrationIntentV1,
): RegistrationIntentSignerBranchesResult {
  const plan = registrationSignerPlanFromSelection(intent.signerSelection);
  if (!plan.ok) return plan;
  return { ok: true, value: registrationSignerBranchesFromPlan(plan.value) };
}

function registrationSignerBranchesFromPlan(
  plan: RegistrationSignerPlan,
): RegistrationIntentSignerBranches {
  return {
    plan,
    nearEd25519: findRegistrationSignerPlanNearEd25519Branch(plan),
    evmFamilyEcdsa: findRegistrationSignerPlanEvmFamilyEcdsaBranch(plan),
  };
}

type RegistrationPreparedContextResolution =
  | {
      ok: true;
      preparedContext: StoredWalletRegistrationPreparedContext;
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[] | null;
    }
  | {
      ok: false;
      code: 'invalid_body';
      message: string;
    };

function resolveRegistrationPreparedContextFromPlan(input: {
  readonly signerPlan: RegistrationSignerPlan;
  readonly runtimePolicyScope: RuntimePolicyScope | undefined;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): RegistrationPreparedContextResolution {
  const branches = registrationSignerBranchesFromPlan(input.signerPlan);
  const ecdsaChainTargets = branches.evmFamilyEcdsa
    ? normalizeThresholdEcdsaChainTargets(branches.evmFamilyEcdsa.chainTargets)
    : null;
  if (branches.evmFamilyEcdsa && !ecdsaChainTargets) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration contains an invalid chain target',
    };
  }
  try {
    return {
      ok: true,
      preparedContext: buildStoredWalletRegistrationPreparedContext({
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        runtimePolicyScope: input.runtimePolicyScope || null,
        ecdsaChainTargets,
      }),
      ecdsaChainTargets,
    };
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: errorMessage(error) || 'registration prepared context is invalid',
    };
  }
}

function registrationPreparedContextRuntimePolicyScope(
  preparedContext: StoredWalletRegistrationPreparedContext,
): RuntimePolicyScope | undefined {
  return preparedContext.runtimePolicy.kind === 'runtime_policy_scope'
    ? preparedContext.runtimePolicy.scope
    : undefined;
}

function registrationPreparedContextEcdsaChainTargets(
  preparedContext: StoredWalletRegistrationPreparedContext,
): readonly ThresholdEcdsaChainTarget[] | null {
  return preparedContext.ecdsa.kind === 'evm_family_ecdsa_requested'
    ? preparedContext.ecdsa.chainTargets
    : null;
}

function registrationIntentResponseRpId(intent: RegistrationIntentV1): string | undefined {
  return intent.authMethod.kind === 'passkey' ? intent.authMethod.rpId : undefined;
}

function registrationIntentWalletsMatch(input: {
  readonly requestIntent: RegistrationIntentV1;
  readonly storedIntent: RegistrationIntentV1;
}): boolean {
  return input.requestIntent.walletId === input.storedIntent.walletId;
}

function registrationPreparationWalletsMatch(input: {
  readonly expectedWalletId: string;
  readonly preparation: {
    readonly intent: RegistrationIntentV1;
    readonly authority: { readonly walletId: string };
    readonly ed25519Scope: { readonly walletId: string };
  };
}): boolean {
  return (
    input.preparation.intent.walletId === input.expectedWalletId &&
    input.preparation.authority.walletId === input.expectedWalletId &&
    input.preparation.ed25519Scope.walletId === input.expectedWalletId
  );
}

function registrationCeremonyWalletsMatch(input: {
  readonly ceremony: {
    readonly intent: RegistrationIntentV1;
    readonly authority: { readonly walletId: string };
  };
}): boolean {
  return input.ceremony.authority.walletId === input.ceremony.intent.walletId;
}

function resolvedRegistrationNearAccount(input: {
  readonly accountProvisioning: RegistrationNearAccountProvisioning;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly sponsoredTransactionHash?: string;
}):
  | { ok: true; value: ResolvedRegistrationNearAccount }
  | { ok: false; code: string; message: string } {
  const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(input.nearEd25519SigningKeyId);
  switch (input.accountProvisioning.kind) {
    case 'implicit_account': {
      const parsed = parseImplicitNearAccountId(input.nearAccountId);
      if (!parsed.ok) return { ok: false, code: 'internal', message: parsed.message };
      return {
        ok: true,
        value: {
          kind: 'implicit_account',
          nearAccountId: parsed.value,
          nearEd25519SigningKeyId,
        },
      };
    }
    case 'sponsored_named_account': {
      const parsed = parseNamedNearAccountId(input.nearAccountId);
      if (!parsed.ok) return { ok: false, code: 'internal', message: parsed.message };
      const transactionHash = toOptionalTrimmedString(input.sponsoredTransactionHash);
      if (!transactionHash) {
        return {
          ok: false,
          code: 'internal',
          message: 'Sponsored named registration missing account creation transaction hash',
        };
      }
      return {
        ok: true,
        value: {
          kind: 'sponsored_named_account',
          nearAccountId: parsed.value,
          nearEd25519SigningKeyId,
          transactionHash,
        },
      };
    }
  }
}

function sponsoredNamedRegistrationAccountId(
  provisioning: RegistrationNearAccountProvisioning,
): string | null {
  switch (provisioning.kind) {
    case 'implicit_account':
      return null;
    case 'sponsored_named_account':
      return String(provisioning.requestedAccountId);
  }
}

export class CloudflareD1WalletRegistrationService {
  private readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
  private readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getThresholdSigningService: ThresholdSigningServiceProvider;
  private readonly getWalletStore: WalletStoreProvider;
  private readonly getWebAuthnCredentialBindingStore: WebAuthnCredentialBindingStoreProvider;
  private readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;

  constructor(input: {
    readonly createSponsoredNamedNearAccount: SponsoredNamedNearAccountCreator;
    readonly emailOtpRegistrationEnrollmentFinalizer: CloudflareD1EmailOtpRegistrationEnrollmentFinalizer;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getThresholdSigningService: ThresholdSigningServiceProvider;
    readonly getWalletStore: WalletStoreProvider;
    readonly getWebAuthnCredentialBindingStore: WebAuthnCredentialBindingStoreProvider;
    readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  }) {
    this.createSponsoredNamedNearAccount = input.createSponsoredNamedNearAccount;
    this.emailOtpRegistrationEnrollmentFinalizer = input.emailOtpRegistrationEnrollmentFinalizer;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getThresholdSigningService = input.getThresholdSigningService;
    this.getWalletStore = input.getWalletStore;
    this.getWebAuthnCredentialBindingStore = input.getWebAuthnCredentialBindingStore;
    this.walletAuthMethods = input.walletAuthMethods;
  }

  async prepareWalletRegistration(
    request: PrepareWalletRegistrationInput,
  ): Promise<WalletRegistrationPrepareResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const grant = registrationIntentGrantFromString(
        toOptionalTrimmedString(request.registrationIntentGrant) || '',
      );
      if (!grant) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'registration intent grant is required',
        };
      }
      const storedIntent = await store.getIntent(grant);
      if (!storedIntent) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      const signerBranches = registrationIntentSignerBranches(storedIntent.intent);
      if (!signerBranches.ok) return signerBranches;
      const ed25519Selection = signerBranches.value.nearEd25519;
      if (!ed25519Selection) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 HSS preparation requires an Ed25519 registration branch',
        };
      }
      const requestIntent = parseD1RegistrationIntent(request.intent);
      if (!requestIntent) {
        return { ok: false, code: 'invalid_body', message: 'registration intent is invalid' };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      const requestDigest = await computeRegistrationIntentDigestB64u(requestIntent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== storedIntent.digestB64u) {
        return { ok: false, code: 'invalid_body', message: 'registration intent mismatch' };
      }
      if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: storedIntent.intent })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent walletId mismatch',
        };
      }
      const runtimePolicyScope = parseD1RuntimePolicyScope(storedIntent.intent.runtimePolicyScope);
      const signingRootId =
        storedIntent.signingRootId ||
        (runtimePolicyScope ? deriveSigningRootId(runtimePolicyScope) : '');
      const signingRootVersion =
        storedIntent.signingRootVersion || runtimePolicyScope?.signingRootVersion || 'default';
      const preparedContext = resolveRegistrationPreparedContextFromPlan({
        signerPlan: signerBranches.value.plan,
        runtimePolicyScope,
        signingRootId,
        signingRootVersion,
      });
      if (!preparedContext.ok) return preparedContext;
      const authority = request.authority;
      if (!authority || (authority.kind !== 'passkey' && authority.kind !== 'email_otp')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration authority is required',
        };
      }
      const storedExpectedOrigin = toOptionalTrimmedString(storedIntent.expectedOrigin) || '';
      if (authority.kind === 'passkey' && !storedExpectedOrigin) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const verifiedAuthority = await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
        orgId: storedIntent.orgId,
        authority,
        expectedDigestB64u: storedIntent.digestB64u,
        expectedOrigin: storedExpectedOrigin,
        intent: storedIntent.intent,
      });
      if (!verifiedAuthority.ok) return verifiedAuthority;
      const scope = await resolveD1NearEd25519RegistrationPrepareScope({
        intent: storedIntent.intent,
        authority: verifiedAuthority.authority,
        nearEd25519: ed25519Selection,
        registrationIntentDigestB64u: storedIntent.digestB64u,
        orgId: storedIntent.orgId,
        signingRootId,
        signingRootVersion,
        expectedOrigin: storedExpectedOrigin,
      });
      const prepared = await prepareD1NearEd25519RegistrationHss({
        threshold: this.getThresholdSigningService(),
        scope,
        accountProvisioning: ed25519Selection.accountProvisioning,
      });
      if (!prepared.ok) {
        return {
          ok: false,
          code: prepared.code || 'hss_prepare_failed',
          message: prepared.message || 'Ed25519 HSS prepare failed',
        };
      }
      const registrationPreparationId = registrationPreparationIdFromString(
        `wrp_${secureRandomBase64Url(24)}`,
      );
      const expiresAtMs = Math.min(storedIntent.expiresAtMs, Date.now() + 10 * 60_000);
      await store.putPreparation(
        buildStoredWalletRegistrationHssPreparationPrepared({
          registrationPreparationId,
          registrationIntentGrant: grant,
          registrationIntentDigestB64u: storedIntent.digestB64u,
          intent: storedIntent.intent,
          authority: verifiedAuthority.authority,
          signerPlan: signerBranches.value.plan,
          preparedContext: preparedContext.preparedContext,
          orgId: storedIntent.orgId,
          expectedOrigin: storedExpectedOrigin,
          signingRootId,
          signingRootVersion,
          ed25519Scope: scope,
          prepared: {
            kind: 'ed25519_prepared',
            ceremonyHandle: prepared.ceremonyHandle,
            preparedSession: prepared.preparedSession,
            clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
            serverState: prepared.serverState,
          },
          createdAtMs: Date.now(),
          expiresAtMs,
        }),
      );
      return {
        ok: true,
        state: 'prepared',
        registrationPreparationId,
        expiresAtMs,
        ed25519: {
          ceremonyHandle: prepared.ceremonyHandle,
          preparedSession: prepared.preparedSession,
          clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to prepare wallet registration',
      };
    }
  }

  async startWalletRegistration(
    request: StartWalletRegistrationInput,
  ): Promise<WalletRegistrationStartResponse> {
    const startTiming = createD1RegistrationRouteTimingRecorder('wallets_register_start');
    const totalTiming = startD1RegistrationRouteTiming('registerStartTotalMs');
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const grant = registrationIntentGrantFromString(
        toOptionalTrimmedString(request.registrationIntentGrant) || '',
      );
      if (!grant) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'registration intent grant is required',
        };
      }
      const intentPreview = await store.getIntent(grant);
      if (!intentPreview) {
        return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
      }
      const requestIntent = parseD1RegistrationIntent(request.intent);
      if (!requestIntent) {
        return { ok: false, code: 'invalid_body', message: 'registration intent is invalid' };
      }
      const digestB64u = toOptionalTrimmedString(request.registrationIntentDigestB64u);
      const requestDigest = await computeRegistrationIntentDigestB64u(requestIntent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent digest mismatch',
        };
      }
      if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: intentPreview.intent })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent walletId mismatch',
        };
      }
      const previewBranches = registrationIntentSignerBranches(intentPreview.intent);
      if (!previewBranches.ok) return previewBranches;
      const previewNearEd25519 = previewBranches.value.nearEd25519;
      const previewEvmFamilyEcdsa = previewBranches.value.evmFamilyEcdsa;
      if (!previewNearEd25519 && request.registrationPreparationId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationPreparationId is not used when no Ed25519 branch is requested',
        };
      }
      const runtimePolicyScope = parseD1RuntimePolicyScope(intentPreview.intent.runtimePolicyScope);
      const signingRootId =
        intentPreview.signingRootId ||
        (runtimePolicyScope ? deriveSigningRootId(runtimePolicyScope) : '');
      const signingRootVersion =
        toOptionalTrimmedString(intentPreview.signingRootVersion) ||
        runtimePolicyScope?.signingRootVersion ||
        'default';
      if (previewEvmFamilyEcdsa && !signingRootId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration requires a signing root',
        };
      }
      const previewPreparedContext = resolveRegistrationPreparedContextFromPlan({
        signerPlan: previewBranches.value.plan,
        runtimePolicyScope,
        signingRootId,
        signingRootVersion,
      });
      if (!previewPreparedContext.ok) return previewPreparedContext;
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing service is not configured on this server',
        };
      }

      const storedExpectedOrigin = toOptionalTrimmedString(intentPreview.expectedOrigin);
      const preparedRegistration = !previewNearEd25519
        ? null
        : request.registrationPreparationId
          ? await store.getPreparation(request.registrationPreparationId)
          : null;
      if (previewNearEd25519 && !preparedRegistration) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registrationPreparationId is required for Ed25519 registration',
        };
      }
      const preparedRegistrationState = preparedRegistration
        ? getPreparedWalletRegistrationHssPreparation(preparedRegistration)
        : null;
      if (preparedRegistrationState && !preparedRegistrationState.ok) {
        return {
          ok: false,
          code: preparedRegistrationState.code,
          message: preparedRegistrationState.message,
        };
      }
      if (
        preparedRegistrationState?.ok &&
        !registrationPreparationWalletsMatch({
          expectedWalletId: intentPreview.intent.walletId,
          preparation: preparedRegistrationState.preparation,
        })
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration preparation walletId mismatch',
        };
      }
      const verifiedAuthority = preparedRegistrationState?.ok
        ? { ok: true as const, authority: preparedRegistrationState.preparation.authority }
        : request.authority
          ? await this.walletAuthMethods.verifyRegistrationAuthorityForIntent({
              orgId: intentPreview.orgId,
              authority: request.authority,
              expectedDigestB64u: intentPreview.digestB64u,
              expectedOrigin: storedExpectedOrigin || '',
              intent: intentPreview.intent,
            })
          : {
              ok: false as const,
              code: 'invalid_body',
              message: 'registration authority is required',
            };
      if (!verifiedAuthority.ok) return verifiedAuthority;
      const preparedScope = !previewNearEd25519
        ? null
        : await resolveD1NearEd25519RegistrationPrepareScope({
            intent: intentPreview.intent,
            authority: verifiedAuthority.authority,
            nearEd25519: previewNearEd25519,
            registrationIntentDigestB64u: intentPreview.digestB64u,
            orgId: intentPreview.orgId,
            signingRootId,
            signingRootVersion,
            expectedOrigin: storedExpectedOrigin || '',
          });
      if (
        preparedRegistration &&
        preparedRegistrationState?.ok &&
        preparedScope &&
        !(
          preparedRegistration.registrationIntentGrant === grant &&
          preparedRegistration.registrationIntentDigestB64u === intentPreview.digestB64u &&
          storedEd25519RegistrationPrepareScopesMatch(
            preparedRegistrationState.preparation.ed25519Scope,
            preparedScope,
          )
        )
      ) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration preparation scope does not match verified intent',
        };
      }
      const storedIntentResult = !previewNearEd25519
        ? await store.takeIntent(grant).then((intent) =>
            intent
              ? { ok: true as const, intent }
              : {
                  ok: false as const,
                  code: 'invalid_grant' as const,
                  message: 'registration intent grant expired',
                },
          )
        : await store.consumeRegistrationIntentForPreparation({
            registrationIntentGrant: grant,
            registrationIntentDigestB64u: intentPreview.digestB64u,
            registrationPreparationId: request.registrationPreparationId!,
            authority: verifiedAuthority.authority,
            signerPlan: preparedRegistrationState!.preparation.signerPlan,
            preparedContext: preparedRegistrationState!.preparation.preparedContext,
            ed25519Scope: preparedScope!,
          });
      if (!storedIntentResult.ok) return storedIntentResult;
      const storedIntent = storedIntentResult.intent;
      if (!registrationIntentWalletsMatch({ requestIntent, storedIntent: storedIntent.intent })) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration intent walletId mismatch',
        };
      }
      const storedSignerPlan = preparedRegistrationState?.ok
        ? preparedRegistrationState.preparation.signerPlan
        : previewBranches.value.plan;
      const storedPreparedContext = preparedRegistrationState?.ok
        ? preparedRegistrationState.preparation.preparedContext
        : previewPreparedContext.preparedContext;
      const storedBranches = registrationSignerBranchesFromPlan(storedSignerPlan);
      const storedNearEd25519 = storedBranches.nearEd25519;
      const storedEvmFamilyEcdsa = storedBranches.evmFamilyEcdsa;
      const storedEcdsaChainTargets =
        registrationPreparedContextEcdsaChainTargets(storedPreparedContext);
      if (storedEvmFamilyEcdsa && !storedEcdsaChainTargets) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration prepared context is missing ECDSA chain targets',
        };
      }
      if (!storedEvmFamilyEcdsa && storedEcdsaChainTargets) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration prepared context has unexpected ECDSA chain targets',
        };
      }
      const storedRuntimePolicyScope =
        registrationPreparedContextRuntimePolicyScope(storedPreparedContext);
      const registrationCeremonyId = `wrc_${secureRandomBase64Url(24)}`;
      if (!storedNearEd25519) {
        if (!storedEvmFamilyEcdsa || !storedEcdsaChainTargets) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'registration signer set requires a signer branch',
          };
        }
        const ecdsaResult = await buildD1EvmFamilyEcdsaRegistrationPrepare({
          registrationCeremonyId,
          walletId: storedIntent.intent.walletId,
          signingRootId,
          signingRootVersion,
          chainTargets: storedEcdsaChainTargets,
          participantIds: [...storedEvmFamilyEcdsa.participantIds],
          ...(storedRuntimePolicyScope ? { runtimePolicyScope: storedRuntimePolicyScope } : {}),
        });
        if (!ecdsaResult.ok) return ecdsaResult;
        const ecdsa = ecdsaResult.ecdsa;
        await store.putCeremony({
          registrationCeremonyId,
          intent: storedIntent.intent,
          digestB64u: storedIntent.digestB64u,
          signerPlan: storedSignerPlan,
          preparedContext: storedPreparedContext,
          orgId: storedIntent.orgId,
          signingRootId,
          signingRootVersion,
          ...(storedExpectedOrigin ? { expectedOrigin: storedExpectedOrigin } : {}),
          expiresAtMs: Date.now() + 10 * 60_000,
          authority: verifiedAuthority.authority,
          signerState: {
            kind: 'signer_set_registration',
            branches: [
              buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch({
                branchKey: storedEvmFamilyEcdsa.branchKey,
                ecdsa,
              }),
            ],
          },
        });
        finishD1RegistrationRouteTiming(startTiming, totalTiming);
        return withD1RegistrationStartDiagnostics(
          {
            ok: true,
            registrationCeremonyId,
            intent: storedIntent.intent,
            ecdsa,
          },
          startTiming,
        );
      }

      if (!preparedRegistrationState?.ok) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 registration preparation is required',
        };
      }
      if (!storedNearEd25519) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 registration branch is required',
        };
      }
      const ed25519 = {
        ceremonyHandle: preparedRegistrationState.preparation.prepared.ceremonyHandle,
        preparedSession: preparedRegistrationState.preparation.prepared.preparedSession,
        clientOtOfferMessageB64u:
          preparedRegistrationState.preparation.prepared.clientOtOfferMessageB64u,
      };
      const storedEd25519 = {
        ...ed25519,
        serverState: preparedRegistrationState.preparation.prepared.serverState,
      };
      if (!storedEvmFamilyEcdsa) {
        await store.putCeremony({
          registrationCeremonyId,
          intent: storedIntent.intent,
          digestB64u: storedIntent.digestB64u,
          signerPlan: storedSignerPlan,
          preparedContext: storedPreparedContext,
          orgId: storedIntent.orgId,
          signingRootId,
          signingRootVersion,
          ...(storedExpectedOrigin ? { expectedOrigin: storedExpectedOrigin } : {}),
          expiresAtMs: Date.now() + 10 * 60_000,
          authority: verifiedAuthority.authority,
          signerState: {
            kind: 'signer_set_registration',
            branches: [
              buildStoredWalletRegistrationNearEd25519PreparedBranch({
                branchKey: storedNearEd25519.branchKey,
                prepared: storedEd25519,
              }),
            ],
          },
        });
        await store.takePreparation(request.registrationPreparationId!);
        finishD1RegistrationRouteTiming(startTiming, totalTiming);
        return withD1RegistrationStartDiagnostics(
          {
            ok: true,
            registrationCeremonyId,
            intent: storedIntent.intent,
            ed25519,
          },
          startTiming,
        );
      }
      if (!storedEcdsaChainTargets) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA registration contains an invalid chain target',
        };
      }

      const combinedEcdsaResult = await buildD1EvmFamilyEcdsaRegistrationPrepare({
        registrationCeremonyId,
        registrationPreparationId: request.registrationPreparationId,
        walletId: storedIntent.intent.walletId,
        signingRootId,
        signingRootVersion,
        chainTargets: storedEcdsaChainTargets,
        participantIds: [...storedEvmFamilyEcdsa.participantIds],
        ...(storedRuntimePolicyScope ? { runtimePolicyScope: storedRuntimePolicyScope } : {}),
      });
      if (!combinedEcdsaResult.ok) return combinedEcdsaResult;
      const ecdsa = combinedEcdsaResult.ecdsa;
      await store.putCeremony({
        registrationCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        signerPlan: storedSignerPlan,
        preparedContext: storedPreparedContext,
        orgId: storedIntent.orgId,
        signingRootId,
        signingRootVersion,
        ...(storedExpectedOrigin ? { expectedOrigin: storedExpectedOrigin } : {}),
        expiresAtMs: Date.now() + 10 * 60_000,
        authority: verifiedAuthority.authority,
        signerState: {
          kind: 'signer_set_registration',
          branches: [
            buildStoredWalletRegistrationNearEd25519PreparedBranch({
              branchKey: storedNearEd25519.branchKey,
              prepared: storedEd25519,
            }),
            buildStoredWalletRegistrationEvmFamilyEcdsaPreparedBranch({
              branchKey: storedEvmFamilyEcdsa.branchKey,
              ecdsa,
            }),
          ],
        },
      });
      await store.takePreparation(request.registrationPreparationId!);
      finishD1RegistrationRouteTiming(startTiming, totalTiming);
      return withD1RegistrationStartDiagnostics(
        {
          ok: true,
          registrationCeremonyId,
          intent: storedIntent.intent,
          ed25519,
          ecdsa,
        },
        startTiming,
      );
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet registration ceremony',
      };
    }
  }

  async respondWalletRegistrationHss(
    request: RespondWalletRegistrationHssInput,
  ): Promise<WalletRegistrationHssRespondResponse> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getCeremony(request.registrationCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (!registrationCeremonyWalletsMatch({ ceremony })) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration ceremony walletId mismatch',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const signerBranches = registrationSignerBranchesFromPlan(ceremony.signerPlan);
      const requestedNearEd25519 = signerBranches.nearEd25519;
      const requestedEvmFamilyEcdsa = signerBranches.evmFamilyEcdsa;
      let nextSignerState = ceremony.signerState;
      const response: Extract<WalletRegistrationHssRespondResponse, { ok: true }> = {
        ok: true,
        registrationCeremonyId: ceremony.registrationCeremonyId,
      };
      if (request.ed25519) {
        if (!requestedNearEd25519) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration signer set does not accept Ed25519 HSS input',
          };
        }
        const ed25519Branch = findStoredWalletRegistrationNearEd25519Branch(ceremony.signerState);
        if (!ed25519Branch) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'signer-set registration requires an Ed25519 branch',
          };
        }
        if (ed25519Branch.kind !== 'near_ed25519_prepared') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 HSS response already recorded',
          };
        }
        const ed25519Response = await respondD1NearEd25519RegistrationHss({
          threshold: this.getThresholdSigningService(),
          ceremony,
          nearEd25519: requestedNearEd25519,
          preparedEd25519: {
            kind: 'ed25519_prepared',
            ceremonyHandle: ed25519Branch.ceremonyHandle,
            preparedSession: ed25519Branch.preparedSession,
            clientOtOfferMessageB64u: ed25519Branch.clientOtOfferMessageB64u,
            serverState: ed25519Branch.serverState,
          },
          requestEd25519: request.ed25519,
        });
        if (!ed25519Response.ok) return ed25519Response;
        nextSignerState = replaceStoredWalletRegistrationSignerBranch({
          state: nextSignerState,
          replacement: {
            kind: 'near_ed25519_responded',
            branchKey: ed25519Branch.branchKey,
            ceremonyHandle: ed25519Branch.ceremonyHandle,
            preparedSession: ed25519Branch.preparedSession,
            clientOtOfferMessageB64u: ed25519Branch.clientOtOfferMessageB64u,
            serverState: ed25519Response.serverState,
            responded: ed25519Response.responded,
          },
        });
        response.ed25519 = ed25519Response.responded;
      } else if (requestedNearEd25519) {
        return { ok: false, code: 'invalid_body', message: 'missing Ed25519 HSS response' };
      }
      if (request.ecdsa) {
        if (!requestedEvmFamilyEcdsa) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration signer set does not accept ECDSA HSS input',
          };
        }
        const ecdsaBranch = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
        if (!ecdsaBranch) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'signer-set registration requires an ECDSA branch',
          };
        }
        if (ecdsaBranch.kind !== 'evm_family_ecdsa_prepared') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'ECDSA HSS response already recorded',
          };
        }
        const clientBootstraps = request.ecdsa.clientBootstraps;
        if (
          !ecdsaTargetCoverageMatches({
            expected: ecdsaBranch.targets,
            actual: clientBootstraps,
          })
        ) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ECDSA bootstrap target coverage mismatch',
          };
        }
        const threshold = this.getThresholdSigningService();
        if (!threshold) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'threshold signing is not configured on this server',
          };
        }
        const bootstraps: EcdsaServerBootstrapTarget[] = [];
        for (const actual of clientBootstraps) {
          const expected = ecdsaPreparedTargetForClientBootstrap({
            preparedTargets: ecdsaBranch.targets,
            actual,
          });
          if (
            !expected ||
            !isMatchingD1EcdsaClientBootstrap({
              expected: expected.prepare,
              actual: actual.clientBootstrap,
            })
          ) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'ECDSA bootstrap identity mismatch',
            };
          }
          const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(
            toD1EcdsaHssClientBootstrapRequest(actual.clientBootstrap),
          );
          if (!bootstrap.ok) {
            return {
              ok: false,
              code: bootstrap.code || 'hss_respond_failed',
              message: bootstrap.message || 'ECDSA HSS bootstrap failed',
            };
          }
          bootstraps.push({
            chainTarget: actual.chainTarget,
            bootstrap: bootstrap.value,
          });
        }
        nextSignerState = replaceStoredWalletRegistrationSignerBranch({
          state: nextSignerState,
          replacement: {
            kind: 'evm_family_ecdsa_responded',
            branchKey: ecdsaBranch.branchKey,
            hssKind: ecdsaBranch.hssKind,
            targets: ecdsaBranch.targets,
            responded: {
              bootstraps,
            },
          },
        });
        response.ecdsa = { bootstraps };
      } else if (requestedEvmFamilyEcdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA HSS response' };
      }
      if (!response.ed25519 && !response.ecdsa) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration HSS response is required',
        };
      }
      await store.updateCeremony({
        ...ceremony,
        signerState: nextSignerState,
      });
      return response;
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to respond to wallet registration ceremony',
      };
    }
  }

  async advanceWalletRegistrationHssState(
    request: AdvanceWalletRegistrationHssStateInput,
  ): Promise<WalletRegistrationHssAdvanceStateResponse> {
    const advanceTiming = createD1RegistrationRouteTimingRecorder(
      'wallets_register_hss_advance_state',
    );
    const totalTiming = startD1RegistrationRouteTiming('registerHssAdvanceStateTotalMs');
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremonyLoadTiming = startD1RegistrationRouteTiming(
        'registrationHssAdvanceStateCeremonyLoadMs',
      );
      let ceremony: Awaited<ReturnType<typeof store.getCeremony>>;
      try {
        ceremony = await store.getCeremony(request.registrationCeremonyId);
      } finally {
        finishD1RegistrationRouteTiming(advanceTiming, ceremonyLoadTiming);
      }
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (!registrationCeremonyWalletsMatch({ ceremony })) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration ceremony walletId mismatch',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const signerBranches = registrationSignerBranchesFromPlan(ceremony.signerPlan);
      const requestedNearEd25519 = signerBranches.nearEd25519;
      if (!requestedNearEd25519) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration signer set does not accept Ed25519 HSS input',
        };
      }
      const ed25519State = findStoredWalletRegistrationNearEd25519Branch(ceremony.signerState);
      if (!ed25519State || ed25519State.kind !== 'near_ed25519_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 HSS response is required before advance-state',
        };
      }
      const addStageRequestMessageB64u = toOptionalTrimmedString(
        request.ed25519.addStageRequestMessageB64u,
      );
      if (!addStageRequestMessageB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ed25519.addStageRequestMessageB64u is required',
        };
      }
      const digestTiming = startD1RegistrationRouteTiming('registrationHssAdvanceStateDigestMs');
      let addStageRequestDigestB64u: string | null;
      try {
        addStageRequestDigestB64u = await d1Ed25519HssAddStageRequestDigestB64u({
          addStageRequestMessageB64u,
        });
      } finally {
        finishD1RegistrationRouteTiming(advanceTiming, digestTiming);
      }
      if (!addStageRequestDigestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ed25519.addStageRequestMessageB64u is invalid',
        };
      }
      const existing = await store.getEd25519HssAdvancedEvalRecord({
        ceremonyHandle: ed25519State.ceremonyHandle,
        addStageRequestDigestB64u,
      });
      if (existing) {
        finishD1RegistrationRouteTiming(advanceTiming, totalTiming);
        return withD1RegistrationHssAdvanceStateDiagnostics(
          {
            ok: true,
            registrationCeremonyId: ceremony.registrationCeremonyId,
            ed25519: {
              contextBindingB64u: existing.contextBindingB64u,
              addStageRequestDigestB64u: existing.addStageRequestDigestB64u,
              projectionMode: existing.projectionMode,
            },
          },
          advanceTiming,
        );
      }
      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing service is not configured on this server',
        };
      }
      const nearEd25519SigningKeyId = await d1RegistrationAuthorityNearEd25519SigningKeyId({
        intent: ceremony.intent,
        authority: ceremony.authority,
        nearEd25519: requestedNearEd25519,
        signingRootId: ceremony.signingRootId,
        signingRootVersion: ceremony.signingRootVersion,
      });
      const claim = buildD1Ed25519HssAdvanceInFlightClaim({
        ceremonyHandle: ed25519State.ceremonyHandle,
        addStageRequestDigestB64u,
        nowMs: Date.now(),
        expiresAtMs: ceremony.expiresAtMs,
      });
      const claimResult = await store.beginEd25519HssAdvanceClaim(claim);
      switch (claimResult.status) {
        case 'started':
          break;
        case 'in_flight':
          finishD1RegistrationRouteTiming(advanceTiming, totalTiming);
          return withD1RegistrationHssAdvanceStateDiagnostics(
            {
              ok: false,
              code: 'hss_advance_in_flight',
              message: 'Ed25519 HSS advance is already in progress',
              retryAfterMs: d1Ed25519HssAdvanceRetryAfterMs(claimResult.record),
            },
            advanceTiming,
          );
        case 'fulfilled': {
          const fulfilled = await store.getEd25519HssAdvancedEvalRecord({
            ceremonyHandle: claimResult.record.advancedEval.ceremonyHandle,
            addStageRequestDigestB64u: claimResult.record.advancedEval.addStageRequestDigestB64u,
          });
          if (!fulfilled) {
            return {
              ok: false,
              code: 'invalid_state',
              message: 'Ed25519 HSS advance claim is fulfilled without durable advanced eval',
            };
          }
          finishD1RegistrationRouteTiming(advanceTiming, totalTiming);
          return withD1RegistrationHssAdvanceStateDiagnostics(
            {
              ok: true,
              registrationCeremonyId: ceremony.registrationCeremonyId,
              ed25519: {
                contextBindingB64u: fulfilled.contextBindingB64u,
                addStageRequestDigestB64u: fulfilled.addStageRequestDigestB64u,
                projectionMode: fulfilled.projectionMode,
              },
            },
            advanceTiming,
          );
        }
        case 'invalid_existing':
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 HSS advance claim state is invalid',
          };
      }
      const wasmTiming = startD1RegistrationRouteTiming('registrationHssAdvanceStateWasmMs');
      let advanced: Awaited<ReturnType<ThresholdSigningService['ed25519Hss']['advanceForRegistration']>>;
      try {
        advanced = await threshold.ed25519Hss.advanceForRegistration({
          orgId: ceremony.orgId,
          request: {
            registrationAccountScope: d1ThresholdEd25519RegistrationAccountScope({
              walletId: ceremony.intent.walletId,
              intentDigestB64u: ceremony.digestB64u,
              signingRootId: d1RegistrationIntentSigningRootId({
                signingRootId: ceremony.signingRootId,
                intent: ceremony.intent,
              }),
              signingRootVersion: d1RegistrationIntentSigningRootVersion({
                signingRootVersion: ceremony.signingRootVersion,
                intent: ceremony.intent,
              }),
              nearEd25519SigningKeyId,
              signerSlot: requestedNearEd25519.signerSlot,
              keyPurpose: requestedNearEd25519.keyPurpose,
              keyVersion: requestedNearEd25519.keyVersion,
              derivationVersion: requestedNearEd25519.derivationVersion,
              participantIds: [...requestedNearEd25519.participantIds],
              accountProvisioning: requestedNearEd25519.accountProvisioning,
            }),
            wallet_key_id: nearEd25519SigningKeyId,
            ceremonyHandle: ed25519State.ceremonyHandle,
            preparedSession: ed25519State.preparedSession,
            serverState: ed25519State.serverState,
            addStageRequestMessageB64u,
            projectionMode: 'registration_seed_and_output',
          },
        });
      } finally {
        finishD1RegistrationRouteTiming(advanceTiming, wasmTiming);
      }
      recordD1RegistrationEd25519HssAdvanceSource({
        recorder: advanceTiming,
        source: 'durable_workerd_wasm',
      });
      if (!advanced.ok) {
        await failD1Ed25519HssAdvanceClaim({
          store,
          claim: claimResult.record,
          code: advanced.code || 'hss_advance_failed',
          message: advanced.message || 'Ed25519 HSS advance-state failed',
        });
        return {
          ok: false,
          code: advanced.code || 'hss_advance_failed',
          message: advanced.message || 'Ed25519 HSS advance-state failed',
        };
      }
      if (advanced.addStageRequestDigestB64u !== addStageRequestDigestB64u) {
        await failD1Ed25519HssAdvanceClaim({
          store,
          claim: claimResult.record,
          code: 'digest_mismatch',
          message: 'Ed25519 HSS add-stage digest mismatch',
        });
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Ed25519 HSS add-stage digest mismatch',
        };
      }
      if (advanced.advanceServerEvalTimings) {
        appendThresholdEd25519HssAdvanceRouteTimings({
          recorder: advanceTiming,
          timings: advanced.advanceServerEvalTimings,
        });
      }
      const persistenceTiming = startD1RegistrationRouteTiming(
        'registrationHssAdvanceStatePersistenceMs',
      );
      try {
        await store.putEd25519HssAdvancedEvalRecord(
          buildD1DurableEd25519HssAdvancedEvalRecord({
            ceremonyHandle: ed25519State.ceremonyHandle,
            contextBindingB64u: advanced.contextBindingB64u,
            addStageRequestDigestB64u: advanced.addStageRequestDigestB64u,
            projectionMode: advanced.projectionMode,
            advancedServerEvalStateB64u: advanced.advancedServerEvalStateB64u,
            priorStageResponseMessageB64u: advanced.priorStageResponseMessageB64u,
            createdAtMs: Date.now(),
            expiresAtMs: ceremony.expiresAtMs,
          }),
        );
        await store.fulfillEd25519HssAdvanceClaim(
          buildD1Ed25519HssAdvanceFulfilledClaim({
            claim: claimResult.record,
            nowMs: Date.now(),
          }),
        );
      } finally {
        finishD1RegistrationRouteTiming(advanceTiming, persistenceTiming);
      }
      finishD1RegistrationRouteTiming(advanceTiming, totalTiming);
      return withD1RegistrationHssAdvanceStateDiagnostics(
        {
          ok: true,
          registrationCeremonyId: ceremony.registrationCeremonyId,
          ed25519: {
            contextBindingB64u: advanced.contextBindingB64u,
            addStageRequestDigestB64u: advanced.addStageRequestDigestB64u,
            projectionMode: advanced.projectionMode,
          },
        },
        advanceTiming,
      );
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to advance wallet registration HSS state',
      };
    }
  }

  async finalizeWalletRegistration(
    request: FinalizeWalletRegistrationInput,
  ): Promise<WalletRegistrationFinalizeResponse> {
    const finalizeTiming = createD1RegistrationRouteTimingRecorder('wallets_register_finalize');
    const totalTiming = startD1RegistrationRouteTiming('registerFinalizeTotalMs');
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const idempotencyKey = toOptionalTrimmedString(request.idempotencyKey);
      if (idempotencyKey) {
        const replayTiming = startD1RegistrationRouteTiming('registrationFinalizeReplayLoadMs');
        let replay: Awaited<ReturnType<typeof store.getFinalizeReplay>>;
        try {
          replay = await store.getFinalizeReplay({
            registrationCeremonyId: request.registrationCeremonyId,
            idempotencyKey,
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, replayTiming);
        }
        if (replay) {
          finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
          return withD1RegistrationRouteDiagnostics(replay.response, finalizeTiming);
        }
      }
      const ceremonyLoadTiming = startD1RegistrationRouteTiming('registrationCeremonyLoadMs');
      let ceremony: Awaited<ReturnType<typeof store.getCeremony>>;
      try {
        ceremony = await store.getCeremony(request.registrationCeremonyId);
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, ceremonyLoadTiming);
      }
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      if (!registrationCeremonyWalletsMatch({ ceremony })) {
        return {
          ok: false,
          code: 'scope_mismatch',
          message: 'registration ceremony walletId mismatch',
        };
      }
      const signerBranches = registrationSignerBranchesFromPlan(ceremony.signerPlan);
      const requestedNearEd25519 = signerBranches.nearEd25519;
      const requestedEvmFamilyEcdsa = signerBranches.evmFamilyEcdsa;
      if (requestedNearEd25519) {
        if (!request.ed25519) {
          return { ok: false, code: 'invalid_body', message: 'missing Ed25519 finalize input' };
        }
        if (request.ecdsa && !requestedEvmFamilyEcdsa) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'registration signer set does not accept ECDSA finalize input',
          };
        }
        if (ceremony.signerState.kind !== 'signer_set_registration') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'signer-set registration state is required',
          };
        }
        const ed25519State = findStoredWalletRegistrationNearEd25519Branch(ceremony.signerState);
        if (!ed25519State || ed25519State.kind !== 'near_ed25519_responded') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Ed25519 HSS response is required before finalize',
          };
        }
        const ecdsaState = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
        if (requestedEvmFamilyEcdsa) {
          if (!request.ecdsa) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'registration signer set requires ECDSA finalize input',
            };
          }
          if (!ecdsaState || ecdsaState.kind !== 'evm_family_ecdsa_responded') {
            return {
              ok: false,
              code: 'invalid_state',
              message: 'registration signer set requires ECDSA HSS response before finalize',
            };
          }
          const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
          const actualKeyHandles = ecdsaState.responded.bootstraps.map((entry) =>
            String(entry.bootstrap.keyHandle || '').trim(),
          );
          if (hasUnexpectedKeyHandle(expectedKeyHandles, actualKeyHandles)) {
            return {
              ok: false,
              code: 'key_handle_mismatch',
              message: 'ECDSA finalize expected key handle mismatch',
            };
          }
        }
        const threshold = this.getThresholdSigningService();
        if (!threshold) {
          return {
            ok: false,
            code: 'not_configured',
            message: 'threshold signing is not configured on this server',
          };
        }
        const ed25519 = requestedNearEd25519;
        const nearEd25519SigningKeyId = await d1RegistrationAuthorityNearEd25519SigningKeyId({
          intent: ceremony.intent,
          authority: ceremony.authority,
          nearEd25519: requestedNearEd25519,
          signingRootId: ceremony.signingRootId,
          signingRootVersion: ceremony.signingRootVersion,
        });
        const ed25519AuthorityScope = d1RegistrationAuthorityThresholdEd25519AuthorityScope(
          ceremony.authority,
        );
        const walletAuthAuthority = d1WalletAuthAuthorityFromRegistrationAuthority(
          ceremony.authority,
        );
        const addStageRequestDigestB64u = await d1Ed25519HssAddStageRequestDigestB64u({
          addStageRequestMessageB64u: request.ed25519.evaluationResult.addStageRequestMessageB64u,
        });
        if (!addStageRequestDigestB64u) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'ed25519.evaluationResult.addStageRequestMessageB64u is invalid',
          };
        }
        const durableFinalizedReport = await store.getEd25519HssFinalizedReportRecord({
          ceremonyHandle: ed25519State.ceremonyHandle,
          addStageRequestDigestB64u,
        });
        let hssFinalizeSource: Ed25519HssFinalizeSource = 'durable_finalized_report';
        let serverEvalSource: ThresholdEd25519HssRegistrationServerEvalSource;
        if (durableFinalizedReport) {
          if (durableFinalizedReport.projectionMode !== 'registration_seed_and_output') {
            return {
              ok: false,
              code: 'invalid_state',
              message: 'Ed25519 HSS durable finalized report projection mode is invalid',
            };
          }
          serverEvalSource = {
            kind: 'durable_finalized_report',
            finalizedReport: {
              contextBindingB64u: durableFinalizedReport.contextBindingB64u,
              addStageRequestDigestB64u: durableFinalizedReport.addStageRequestDigestB64u,
              clientOutputMessageB64u:
                durableFinalizedReport.finalizedReport.clientOutputMessageB64u,
              serverOutputMessageB64u:
                durableFinalizedReport.finalizedReport.serverOutputMessageB64u,
              seedOutputMessageB64u: durableFinalizedReport.finalizedReport.seedOutputMessageB64u,
            },
          };
        } else {
          const durableAdvancedEvalResult =
            await resolveD1Ed25519HssDurableAdvancedEvalForFinalize({
              store,
              ceremonyHandle: ed25519State.ceremonyHandle,
              addStageRequestDigestB64u,
            });
          if (durableAdvancedEvalResult.kind === 'in_flight') {
            return {
              ok: false,
              code: 'hss_advance_in_flight',
              message: 'Ed25519 HSS advance is still in progress',
              retryAfterMs: durableAdvancedEvalResult.retryAfterMs,
            };
          }
          if (durableAdvancedEvalResult.kind === 'failed') {
            return {
              ok: false,
              code: durableAdvancedEvalResult.claim.failure.code,
              message: durableAdvancedEvalResult.claim.failure.message,
            };
          }
          if (durableAdvancedEvalResult.kind === 'missing') {
            return {
              ok: false,
              code: 'hss_advance_state_missing',
              message: 'Ed25519 HSS durable advanced eval is unavailable',
            };
          }
          if (durableAdvancedEvalResult.kind === 'invalid_fulfilled_claim') {
            return {
              ok: false,
              code: 'invalid_state',
              message: 'Ed25519 HSS advance claim is fulfilled without durable advanced eval',
            };
          }
          const durableAdvancedEval = durableAdvancedEvalResult.record;
          if (durableAdvancedEval.projectionMode !== 'registration_seed_and_output') {
            return {
              ok: false,
              code: 'invalid_state',
              message: 'Ed25519 HSS durable advanced eval projection mode is invalid',
            };
          }
          hssFinalizeSource = 'durable_advanced_eval';
          serverEvalSource = {
            kind: 'durable_advanced_eval',
            advancedServerEval: {
              contextBindingB64u: durableAdvancedEval.contextBindingB64u,
              addStageRequestDigestB64u: durableAdvancedEval.addStageRequestDigestB64u,
              advancedServerEvalStateB64u: durableAdvancedEval.advancedServerEvalStateB64u,
              priorStageResponseMessageB64u: durableAdvancedEval.priorStageResponseMessageB64u,
            },
          };
        }
        const hssFinalizeTiming = startD1RegistrationRouteTiming('registrationHssFinalizeMs');
        let finalized: Awaited<ReturnType<typeof threshold.ed25519Hss.finalizeForRegistration>>;
        try {
          finalized = await threshold.ed25519Hss.finalizeForRegistration({
            orgId: ceremony.orgId,
            request: {
              registrationAccountScope: d1ThresholdEd25519RegistrationAccountScope({
                walletId: ceremony.intent.walletId,
                intentDigestB64u: ceremony.digestB64u,
                signingRootId: d1RegistrationIntentSigningRootId({
                  signingRootId: ceremony.signingRootId,
                  intent: ceremony.intent,
                }),
                signingRootVersion: d1RegistrationIntentSigningRootVersion({
                  signingRootVersion: ceremony.signingRootVersion,
                  intent: ceremony.intent,
                }),
                nearEd25519SigningKeyId,
                signerSlot: ed25519.signerSlot,
                keyPurpose: ed25519.keyPurpose,
                keyVersion: ed25519.keyVersion,
                derivationVersion: ed25519.derivationVersion,
                participantIds: [...ed25519.participantIds],
                accountProvisioning: ed25519.accountProvisioning,
              }),
              wallet_key_id: nearEd25519SigningKeyId,
              authority: walletAuthAuthority,
              ceremonyHandle: ed25519State.ceremonyHandle,
              preparedSession: ed25519State.preparedSession,
              serverState: ed25519State.serverState,
              serverEvalSource,
              evaluationResult: request.ed25519.evaluationResult,
              accountResolution: {
                kind: 'registration_provisioning',
                accountProvisioning: ed25519.accountProvisioning,
              },
            },
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, hssFinalizeTiming);
        }
        if (!finalized.ok) {
          return {
            ok: false,
            code: finalized.code || 'hss_finalize_failed',
            message: finalized.message || 'Ed25519 HSS finalize failed',
          };
        }
        recordD1RegistrationEd25519HssFinalizeSource({
          recorder: finalizeTiming,
          source: hssFinalizeSource,
        });
        if (finalized.finalizeReportTimings) {
          appendThresholdEd25519HssFinalizeRouteTimings({
            recorder: finalizeTiming,
            timings: finalized.finalizeReportTimings,
          });
        }
        const finalizedServerOutputMessageB64u = toOptionalTrimmedString(
          finalized.finalizedServerOutputMessageB64u,
        );
        const finalizedSeedOutputMessageB64u = toOptionalTrimmedString(
          finalized.finalizedReport.seedOutputMessageB64u,
        );
        if (!finalizedServerOutputMessageB64u || !finalizedSeedOutputMessageB64u) {
          return {
            ok: false,
            code: 'internal',
            message: 'Ed25519 HSS finalized report is incomplete',
          };
        }
        await store.putEd25519HssFinalizedReportRecord(
          buildD1DurableEd25519HssFinalizedReportRecord({
            ceremonyHandle: ed25519State.ceremonyHandle,
            contextBindingB64u: finalized.finalizedReport.contextBindingB64u,
            addStageRequestDigestB64u,
            projectionMode: 'registration_seed_and_output',
            finalizedReport: {
              contextBindingB64u: finalized.finalizedReport.contextBindingB64u,
              clientOutputMessageB64u: finalized.finalizedReport.clientOutputMessageB64u,
              serverOutputMessageB64u: finalizedServerOutputMessageB64u,
              seedOutputMessageB64u: finalizedSeedOutputMessageB64u,
            },
            createdAtMs: Date.now(),
            expiresAtMs: ceremony.expiresAtMs,
          }),
        );
        const sponsoredNamedAccountId = sponsoredNamedRegistrationAccountId(
          ed25519.accountProvisioning,
        );
        let sponsoredTransactionHash: string | undefined;
        if (sponsoredNamedAccountId) {
          const sponsoredAccountTiming = startD1RegistrationRouteTiming(
            'sponsoredNearAccountCreateMs',
          );
          let created: Awaited<ReturnType<typeof this.createSponsoredNamedNearAccount>>;
          try {
            created = await this.createSponsoredNamedNearAccount({
              accountId: sponsoredNamedAccountId,
              publicKey: finalized.publicKey,
            });
          } finally {
            finishD1RegistrationRouteTiming(finalizeTiming, sponsoredAccountTiming);
          }
          if (!created.success) {
            return {
              ok: false,
              code: 'account_creation_failed',
              message: created.error || created.message || 'Failed to create NEAR account',
            };
          }
          sponsoredTransactionHash = created.transactionHash;
        }
        const resolvedAccount = resolvedRegistrationNearAccount({
          accountProvisioning: ed25519.accountProvisioning,
          nearAccountId: finalized.nearAccountId,
          nearEd25519SigningKeyId,
          sponsoredTransactionHash,
        });
        if (!resolvedAccount.ok) return resolvedAccount;
        const scheme = threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
        if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
          return {
            ok: false,
            code: 'not_configured',
            message: `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled`,
          };
        }
        const keygenTiming = startD1RegistrationRouteTiming('registrationKeygenMs');
        let keygen: Awaited<ReturnType<typeof scheme.registration.keygenFromRegistrationMaterial>>;
        try {
          keygen = await scheme.registration.keygenFromRegistrationMaterial({
            walletId: ceremony.intent.walletId,
            nearAccountId: finalized.nearAccountId,
            nearEd25519SigningKeyId,
            authority: walletAuthAuthority,
            keyVersion: ed25519.keyVersion,
            recoveryExportCapable: true,
            publicKey: finalized.publicKey,
            relayerKeyId: finalized.relayerKeyId,
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, keygenTiming);
        }
        if (!keygen.ok) {
          return {
            ok: false,
            code: keygen.code || 'keygen_failed',
            message: keygen.message || 'Ed25519 registration keygen failed',
          };
        }
        const now = Date.now();
        const runtimePolicyScope = registrationPreparedContextRuntimePolicyScope(
          ceremony.preparedContext,
        );
        const emailOtpEnrollmentTiming = startD1RegistrationRouteTiming(
          'registrationEmailOtpEnrollmentPlanMs',
        );
        let emailOtpEnrollment: Awaited<
          ReturnType<
            typeof this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize
          >
        >;
        try {
          emailOtpEnrollment =
            await this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize({
              authority: ceremony.authority,
              request,
              walletId: ceremony.intent.walletId,
              orgId: ceremony.orgId,
              nowMs: now,
            });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, emailOtpEnrollmentTiming);
        }
        if (!emailOtpEnrollment.ok) return emailOtpEnrollment;
        let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
        if (request.ed25519.sessionPolicy) {
          const sessionKind = String(request.ed25519.sessionKind || 'jwt')
            .trim()
            .toLowerCase();
          if (sessionKind !== 'jwt') {
            return { ok: false, code: 'invalid_body', message: 'ed25519.sessionKind must be jwt' };
          }
          const requestedPolicy = request.ed25519.sessionPolicy as Record<string, unknown>;
          const sessionPolicy = buildD1ThresholdEd25519RegistrationSessionPolicy({
            requestedSessionPolicy: requestedPolicy,
            walletId: String(ceremony.intent.walletId),
            nearAccountId: finalized.nearAccountId,
            nearEd25519SigningKeyId,
            relayerKeyId: keygen.relayerKeyId,
            authority: walletAuthAuthority,
            ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          });
          if (!sessionPolicy.ok) return sessionPolicy;
          const sessionMintTiming = startD1RegistrationRouteTiming('relaySessionMintMs');
          let session: Awaited<ReturnType<typeof threshold.mintEd25519SessionFromRegistration>>;
          try {
            session = await threshold.mintEd25519SessionFromRegistration({
              walletId: String(ceremony.intent.walletId),
              nearAccountId: finalized.nearAccountId,
              nearEd25519SigningKeyId,
              authority: walletAuthAuthority,
              relayerKeyId: keygen.relayerKeyId,
              sessionPolicy: sessionPolicy.value,
            });
          } finally {
            finishD1RegistrationRouteTiming(finalizeTiming, sessionMintTiming);
          }
          if (
            !session.ok ||
            !session.thresholdSessionId ||
            !Number.isFinite(Number(session.expiresAtMs))
          ) {
            return {
              ok: false,
              code: session.code || 'internal',
              message: session.message || 'threshold-ed25519 session bootstrap failed',
            };
          }
          const normalizedSession = toD1ThresholdEd25519BootstrapSession({
            walletId: session.walletId,
            nearAccountId: session.nearAccountId,
            nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
            authorityScope: ed25519AuthorityScope,
            thresholdSessionId: session.thresholdSessionId,
            signingGrantId: session.signingGrantId,
            expiresAtMs: session.expiresAtMs,
            expiresAt: session.expiresAt,
            participantIds: session.participantIds,
            remainingUses: session.remainingUses,
            runtimePolicyScope: session.runtimePolicyScope,
            routerAbNormalSigning: session.routerAbNormalSigning,
            jwt: session.jwt,
          });
          if (!normalizedSession) {
            return {
              ok: false,
              code: 'internal',
              message: 'threshold-ed25519 session bootstrap failed',
            };
          }
          thresholdEd25519Session = normalizedSession;
        }
        const walletKeyResult =
          ecdsaState && ecdsaState.kind === 'evm_family_ecdsa_responded'
            ? buildD1EcdsaWalletKeysFromBootstrap({
                bootstraps: ecdsaState.responded.bootstraps,
                errorContext: 'combined ECDSA registration finalize',
              })
            : null;
        if (walletKeyResult && !walletKeyResult.ok) return walletKeyResult;
        const wallet = buildD1WalletRecord({
          walletId: ceremony.intent.walletId,
          now,
        });
        const walletSigners = [
          buildD1WalletEd25519SignerRecord({
            walletId: ceremony.intent.walletId,
            nearAccountId: finalized.nearAccountId,
            nearEd25519SigningKeyId,
            signerSlot: ed25519.signerSlot,
            keygen,
            now,
          }),
          ...(walletKeyResult?.ok
            ? buildD1WalletEcdsaSignerRecords({
                walletId: ceremony.intent.walletId,
                walletKeys: walletKeyResult.walletKeys,
                now,
              })
            : []),
        ];
        const persistenceTiming = startD1RegistrationRouteTiming('relayPersistenceMs');
        let deleted = false;
        try {
          if (emailOtpEnrollment.persistence) {
            const persisted = await this.emailOtpRegistrationEnrollmentFinalizer.persistPrepared(
              emailOtpEnrollment.persistence,
            );
            if (!persisted.ok) return persisted;
          }
          const walletStore = this.getWalletStore();
          await walletStore.putSubject(wallet);
          await walletStore.putSigners(walletSigners);
          await this.walletAuthMethods.persistAuthority({
            authority: ceremony.authority,
            now,
          });
          if (ceremony.authority.kind === 'passkey') {
            await this.getWebAuthnCredentialBindingStore().put({
              version: 'webauthn_credential_binding_v1',
              rpId: ceremony.authority.rpId,
              credentialIdB64u: ceremony.authority.credentialIdB64u,
              userId: ceremony.intent.walletId,
              nearAccountId: finalized.nearAccountId,
              nearEd25519SigningKeyId,
              signerSlot: ed25519.signerSlot,
              publicKey: keygen.publicKey,
              relayerKeyId: keygen.relayerKeyId,
              keyVersion: keygen.keyVersion,
              recoveryExportCapable: keygen.recoveryExportCapable,
              clientParticipantId: keygen.clientParticipantId,
              relayerParticipantId: keygen.relayerParticipantId,
              participantIds: keygen.participantIds,
              ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
              createdAtMs: now,
              updatedAtMs: now,
            });
          }
          deleted = await store.deleteCeremony(ceremony.registrationCeremonyId);
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, persistenceTiming);
        }
        if (!deleted) {
          return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
        }
        const rpId = registrationIntentResponseRpId(ceremony.intent);
        const ed25519Response: NonNullable<
          Extract<WalletRegistrationFinalizeResponse, { ed25519: object }>['ed25519']
        > = {
          nearAccountId: finalized.nearAccountId,
          nearEd25519SigningKeyId,
          publicKey: keygen.publicKey,
          relayerKeyId: keygen.relayerKeyId,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: keygen.recoveryExportCapable,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          registrationWorkerMaterialReport: {
            kind: 'threshold_ed25519_registration_worker_material_report_v1',
            contextBindingB64u: finalized.finalizedReport.contextBindingB64u,
            clientOutputMessageB64u: finalized.finalizedReport.clientOutputMessageB64u,
          },
        };
        if (thresholdEd25519Session) ed25519Response.session = thresholdEd25519Session;
        const response: Extract<WalletRegistrationFinalizeResponse, { ed25519: object }> = {
          ok: true,
          walletId: ceremony.intent.walletId,
          authority: walletAuthAuthority,
          authorityScope: ed25519AuthorityScope,
          authMethod: walletRegistrationFinalizeAuthMethodFromAuthority(ceremony.authority),
          accountProvisioning: ed25519.accountProvisioning,
          resolvedAccount: resolvedAccount.value,
          ed25519: ed25519Response,
        };
        if (rpId) response.rpId = rpId;
        if (walletKeyResult?.ok) response.ecdsa = { walletKeys: walletKeyResult.walletKeys };
        if (idempotencyKey) {
          const replayCacheTiming = startD1RegistrationRouteTiming(
            'registrationFinalizeReplayCacheMs',
          );
          try {
            await store.putFinalizeReplay({
              kind: 'wallet_registration_finalize_replay_v1',
              registrationCeremonyId: ceremony.registrationCeremonyId,
              idempotencyKey,
              response,
              createdAtMs: now,
              expiresAtMs: ceremony.expiresAtMs,
            });
          } finally {
            finishD1RegistrationRouteTiming(finalizeTiming, replayCacheTiming);
          }
        }
        finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
        return withD1RegistrationRouteDiagnostics(response, finalizeTiming);
      }
      if (!requestedEvmFamilyEcdsa) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'registration signer set requires a signer branch',
        };
      }
      if (!request.ecdsa) {
        return { ok: false, code: 'invalid_body', message: 'missing ECDSA finalize input' };
      }
      if (request.ed25519) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'registration signer set does not accept Ed25519 finalize input',
        };
      }
      if (ceremony.signerState.kind !== 'signer_set_registration') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'signer-set registration state is required',
        };
      }
      const ecdsaState = findStoredWalletRegistrationEvmFamilyEcdsaBranch(ceremony.signerState);
      if (!ecdsaState || ecdsaState.kind !== 'evm_family_ecdsa_responded') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'ECDSA HSS response is required before finalize',
        };
      }
      const expectedKeyHandles = request.ecdsa.expectedKeyHandles || [];
      const actualKeyHandles = ecdsaState.responded.bootstraps.map((entry) =>
        String(entry.bootstrap.keyHandle || '').trim(),
      );
      if (hasUnexpectedKeyHandle(expectedKeyHandles, actualKeyHandles)) {
        return {
          ok: false,
          code: 'key_handle_mismatch',
          message: 'ECDSA finalize expected key handle mismatch',
        };
      }
      const ecdsaVerifyTiming = startD1RegistrationRouteTiming(
        'registrationEcdsaBootstrapVerifyMs',
      );
      let walletKeyResult: ReturnType<typeof buildD1EcdsaWalletKeysFromBootstrap>;
      try {
        walletKeyResult = buildD1EcdsaWalletKeysFromBootstrap({
          bootstraps: ecdsaState.responded.bootstraps,
          errorContext: 'ECDSA registration finalize',
        });
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, ecdsaVerifyTiming);
      }
      if (!walletKeyResult.ok) return walletKeyResult;

      const now = Date.now();
      const emailOtpEnrollmentTiming = startD1RegistrationRouteTiming(
        'registrationEmailOtpEnrollmentPlanMs',
      );
      let emailOtpEnrollment: Awaited<
        ReturnType<typeof this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize>
      >;
      try {
        emailOtpEnrollment =
          await this.emailOtpRegistrationEnrollmentFinalizer.prepareRegistrationFinalize({
            authority: ceremony.authority,
            request,
            walletId: ceremony.intent.walletId,
            orgId: ceremony.orgId,
            nowMs: now,
          });
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, emailOtpEnrollmentTiming);
      }
      if (!emailOtpEnrollment.ok) return emailOtpEnrollment;

      const wallet = buildD1WalletRecord({
        walletId: ceremony.intent.walletId,
        now,
      });
      const walletSigners = buildD1WalletEcdsaSignerRecords({
        walletId: ceremony.intent.walletId,
        walletKeys: walletKeyResult.walletKeys,
        now,
      });
      const walletAuthAuthority = d1WalletAuthAuthorityFromRegistrationAuthority(
        ceremony.authority,
      );
      const persistenceTiming = startD1RegistrationRouteTiming('relayPersistenceMs');
      let deleted = false;
      try {
        if (emailOtpEnrollment.persistence) {
          const persisted = await this.emailOtpRegistrationEnrollmentFinalizer.persistPrepared(
            emailOtpEnrollment.persistence,
          );
          if (!persisted.ok) return persisted;
        }
        const walletStore = this.getWalletStore();
        await walletStore.putSubject(wallet);
        await walletStore.putSigners(walletSigners);
        await this.walletAuthMethods.persistAuthority({
          authority: ceremony.authority,
          now,
        });
        deleted = await store.deleteCeremony(ceremony.registrationCeremonyId);
      } finally {
        finishD1RegistrationRouteTiming(finalizeTiming, persistenceTiming);
      }
      if (!deleted) {
        return { ok: false, code: 'not_found', message: 'registration ceremony not found' };
      }
      const response: Extract<WalletRegistrationFinalizeResponse, { ecdsa: object }> = {
        ok: true,
        walletId: ceremony.intent.walletId,
        authority: walletAuthAuthority,
        authMethod: walletRegistrationFinalizeAuthMethodFromAuthority(ceremony.authority),
        ecdsa: {
          walletKeys: walletKeyResult.walletKeys,
        },
      };
      if (ceremony.authority.kind === 'passkey') response.rpId = ceremony.authority.rpId;
      if (idempotencyKey) {
        const replayCacheTiming = startD1RegistrationRouteTiming(
          'registrationFinalizeReplayCacheMs',
        );
        try {
          await store.putFinalizeReplay({
            kind: 'wallet_registration_finalize_replay_v1',
            registrationCeremonyId: ceremony.registrationCeremonyId,
            idempotencyKey,
            response,
            createdAtMs: now,
            expiresAtMs: ceremony.expiresAtMs,
          });
        } finally {
          finishD1RegistrationRouteTiming(finalizeTiming, replayCacheTiming);
        }
      }
      finishD1RegistrationRouteTiming(finalizeTiming, totalTiming);
      return withD1RegistrationRouteDiagnostics(response, finalizeTiming);
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet registration ceremony',
      };
    }
  }
}
