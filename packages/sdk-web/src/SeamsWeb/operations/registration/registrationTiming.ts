/**
 * Registration timing, diagnostics, and span accounting.
 *
 * Moved verbatim out of `registration.ts` so the registration flow itself is
 * readable. This module records and shapes measurements; it makes no protocol
 * decisions and holds no registration state.
 *
 * `assertNever` lives here despite its generic name because its message names
 * a timing branch — it is a timing helper, not a general utility.
 */

import { isObject } from '@shared/utils/validation';
import type {
  RegistrationHooksOptions,
  RegistrationTimingSpanV1,
} from '@/core/types/sdkSentEvents';
import type { WorkerResourceWarmupDiagnostics } from '@/core/signingEngine/assembly/warmup';
import type { EmailOtpYaoPrewarmOutcome } from '@/core/signingEngine/workerManager/workerTypes';
import type {
  RegistrationAuthMethodInput,
  RegistrationSignerPlan,
  RegistrationSignerPlanBranch,
} from '@shared/utils/registrationIntent';
import {
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
} from '@/core/rpcClients/relayer/walletRegistration';
import { type PasskeyRegistrationAuthorityDiagnostics } from '@/SeamsWeb/operations/authMethods/passkey/registrationAuthority';
import { type RouterAbTraceContextV1 } from '@shared/utils/routerAbTraceContext';
export const REGISTRATION_TIMING_LABEL = '[Registration] wallet timing summary';

/**
 * `Server-Timing` metric name → timing bucket, for both the Ed25519 Yao execute
 * response and the ECDSA respond/activate responses. Anything unrecognised is
 * ignored, so a server-side rename can never break registration.
 */
const YAO_SERVER_TIMING_BUCKET_BY_METRIC = new Map<string, RegistrationTimingBucketName>(
  Object.entries({
    yao_credential_digest: 'yaoServerCredentialDigestMs',
    yao_request_digest: 'yaoServerRequestDigestMs',
    yao_d1_claim: 'yaoServerD1ClaimMs',
    yao_router_execution: 'yaoServerRouterExecutionMs',
    yao_result_reconstruction: 'yaoServerResultReconstructionMs',
    yao_d1_terminal_commit: 'yaoServerD1TerminalCommitMs',
    yao_router_prepare_pair: 'yaoServerRouterPreparePairMs',
    yao_router_verify_readiness: 'yaoServerRouterVerifyReadinessMs',
    yao_router_role_execution: 'yaoServerRouterRoleExecutionMs',
    yao_router_signing_worker_delivery: 'yaoServerRouterSigningWorkerDeliveryMs',
    ecdsa_respond_d1_claim: 'ecdsaRespondD1ClaimMs',
    ecdsa_respond_reconcile: 'ecdsaRespondReconcileMs',
    ecdsa_respond_router: 'ecdsaRespondRouterMs',
    ecdsa_respond_d1_commit: 'ecdsaRespondD1CommitMs',
    ecdsa_respond_total: 'ecdsaRespondTotalMs',
    ecdsa_activate_d1_claim: 'ecdsaActivateD1ClaimMs',
    ecdsa_activate_reconcile: 'ecdsaActivateReconcileMs',
    ecdsa_activate_router: 'ecdsaActivateRouterMs',
    ecdsa_activate_bootstrap: 'ecdsaActivateBootstrapMs',
    ecdsa_activate_session_provision: 'ecdsaActivateSessionProvisionMs',
    ecdsa_activate_d1_commit: 'ecdsaActivateD1CommitMs',
    ecdsa_activate_policy_lookup: 'ecdsaActivatePolicyLookupMs',
    ecdsa_activate_jwt_mint: 'ecdsaActivateJwtMintMs',
    ecdsa_activate_total: 'ecdsaActivateTotalMs',
    ecdsa_rt_authorize: 'ecdsaRtAuthorizeMs',
    ecdsa_rt_admission: 'ecdsaRtAdmissionMs',
    ecdsa_rt_derivers: 'ecdsaRtDeriversMs',
    ecdsa_rt_deriver_a: 'ecdsaRtDeriverAMs',
    ecdsa_rt_deriver_b: 'ecdsaRtDeriverBMs',
    ecdsa_rt_completion: 'ecdsaRtCompletionMs',
    ecdsa_rt_total: 'ecdsaRtTotalMs',
    ecdsa_rt_act_session: 'ecdsaRtActSessionMs',
    ecdsa_rt_act_worker: 'ecdsaRtActWorkerMs',
    ecdsa_rt_act_total: 'ecdsaRtActTotalMs',
    /* Role-local spans. The Router prefixes each role's own bare metric names
       (`parse`, `preload`, `execute`, `total`) when it folds them in, so
       `parse` lands as `ecdsa_a_parse` and so on.
       These nest inside the Router spans above, and the gap is the finding:
       when `ecdsaRtDeriverAMs` far exceeds `ecdsaDeriverATotalMs`, the time
       went to Worker cold start and transport, not to the deriver's work. */
    ecdsa_a_parse: 'ecdsaDeriverAParseMs',
    ecdsa_a_preload: 'ecdsaDeriverAPreloadMs',
    ecdsa_a_execute: 'ecdsaDeriverAExecuteMs',
    ecdsa_a_total: 'ecdsaDeriverATotalMs',
    ecdsa_b_parse: 'ecdsaDeriverBParseMs',
    ecdsa_b_preload: 'ecdsaDeriverBPreloadMs',
    ecdsa_b_execute: 'ecdsaDeriverBExecuteMs',
    ecdsa_b_total: 'ecdsaDeriverBTotalMs',
    ecdsa_sw_parse: 'ecdsaSigningWorkerParseMs',
    ecdsa_sw_activate: 'ecdsaSigningWorkerActivateMs',
    ecdsa_sw_total: 'ecdsaSigningWorkerTotalMs',
  } as const satisfies Record<string, RegistrationTimingBucketName>),
);

/**
 * Parses a `Server-Timing` header into bucket durations. Diagnostics only: a
 * malformed or absent header yields an empty map and never throws.
 */
/**
 * Folds a raw `Server-Timing` header into the registration timing recorder.
 * Shared by the Yao and ECDSA paths; unrecognised metrics are dropped.
 */
function recordServerTimingBuckets(
  recorder: {
    record: (bucket: RegistrationTimingBucketName, durationMs: number) => void;
  } | null,
  header: string | null,
): void {
  if (!recorder) return;
  for (const [bucket, durationMs] of parseYaoServerTimingBuckets(header)) {
    recorder.record(bucket, durationMs);
  }
}

type StrictEcdsaServerTimingLeg = 'respond' | 'activate';

/** Records fixed timing buckets and reports only whether the raw header arrived. */
export function recordStrictEcdsaServerTimingBuckets(
  recorder: {
    record: (bucket: RegistrationTimingBucketName, durationMs: number) => void;
  } | null,
  leg: StrictEcdsaServerTimingLeg,
  header: string | null,
): void {
  if (isRegistrationBenchmarkDiagnosticsEnabled()) {
    console.info('[Registration] ECDSA Server-Timing header presence', {
      leg,
      present: Boolean(header?.trim()),
    });
  }
  recordServerTimingBuckets(recorder, header);
}

export function parseYaoServerTimingBuckets(
  header: string | null | undefined,
): ReadonlyArray<readonly [RegistrationTimingBucketName, number]> {
  if (!header) return [];
  const parsed: Array<readonly [RegistrationTimingBucketName, number]> = [];
  for (const entry of header.split(',')) {
    const parts = entry.split(';');
    const name = String(parts[0] || '').trim();
    /* Map lookup, not property access: a metric literally named `__proto__`
       or `constructor` would otherwise resolve against Object.prototype and be
       recorded as a bucket. */
    const bucket = YAO_SERVER_TIMING_BUCKET_BY_METRIC.get(name);
    if (!bucket) continue;
    for (const part of parts.slice(1)) {
      const [key, rawValue] = part.split('=');
      if (String(key || '').trim() !== 'dur') continue;
      const duration = Number(String(rawValue || '').trim());
      if (!Number.isFinite(duration) || duration < 0) break;
      parsed.push([bucket, duration]);
      break;
    }
  }
  return parsed;
}

export const WALLET_IFRAME_TRANSPORT_TIMING_LABEL =
  '[Registration] wallet iframe transport timing summary';

export function isRegistrationBenchmarkDiagnosticsEnabled(): boolean {
  const globalFlag = (
    globalThis as {
      __SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS?: unknown;
    }
  ).__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS;
  return globalFlag === true;
}

type RegistrationTimingAuthMethod = RegistrationAuthMethodInput['kind'];

type RegistrationTimingSignerBranch = 'near_ed25519' | 'evm_family_ecdsa';

type RegistrationTimingSignerSet = {
  kind: 'signer_set';
  branches: readonly RegistrationTimingSignerBranch[];
};

type RegistrationTimingBucketValues = {
  registrationWarmupMs: number;
  registrationWarmupWaitMs: number;
  registrationWarmupAuthenticatedWalletStateMs: number;
  registrationWarmupNoncePrefetchMs: number;
  registrationWarmupKeyMaterialReadMs: number;
  registrationWarmupUiConfirmPrewarmMs: number;
  registrationWarmupSignerWorkerPrewarmMs: number;
  registrationWarmupEmailOtpWorkerPrewarmMs: number;
  registrationWarmupEmailOtpYaoWasmInitMs: number;
  managedRegistrationGrantMs: number;
  registrationIntentMs: number;
  registrationIntentDigestMs: number;
  authProofMs: number;
  passkeyAuthConfirmationMs: number;
  passkeyAuthPrfExtractionMs: number;
  passkeyAuthCredentialRedactionMs: number;
  passkeyAuthWorkerReadyMs: number;
  passkeyAuthWorkerRequestRoundTripMs: number;
  passkeyAuthWorkerResponseValidationMs: number;
  passkeyAuthRequestSetupMs: number;
  passkeyAuthPromptUserMs: number;
  passkeyAuthPromptElementDefineMs: number;
  passkeyAuthPromptMountMs: number;
  passkeyAuthPromptHostFirstUpdateMs: number;
  passkeyAuthPromptHostInteractiveMs: number;
  passkeyAuthPromptConfirmEventMs: number;
  passkeyAuthPromptDecisionWaitMs: number;
  passkeyAuthCredentialCreateStartMs: number;
  passkeyAuthCredentialCreateMs: number;
  passkeyAuthCredentialSerializeMs: number;
  passkeyAuthDuplicateRetryCount: number;
  passkeyAuthMainThreadTotalMs: number;
  emailOtpEnrollmentMaterialMs: number;
  emailOtpYaoEnrollmentMaterialWaitMs: number;
  emailOtpYaoWorkerRegistrationMs: number;
  emailOtpYaoTotalMs: number;
  // Ed25519 Yao branch, client-observed. Applies to passkey and Email OTP
  // alike; the emailOtpYao* buckets above stay Email-OTP specific.
  yaoBranchTotalMs: number;
  yaoAdmissionMs: number;
  yaoClientSessionCreateMs: number;
  yaoClientCompletionMs: number;
  // Router-reported, parsed from the execute call's Server-Timing header.
  // Names mirror the server metric names exactly.
  yaoServerCredentialDigestMs: number;
  yaoServerRequestDigestMs: number;
  yaoServerD1ClaimMs: number;
  yaoServerRouterExecutionMs: number;
  yaoServerResultReconstructionMs: number;
  yaoServerD1TerminalCommitMs: number;
  yaoServerRouterPreparePairMs: number;
  yaoServerRouterVerifyReadinessMs: number;
  yaoServerRouterRoleExecutionMs: number;
  yaoServerRouterSigningWorkerDeliveryMs: number;
  // Gateway-reported ECDSA boundaries, parsed from the respond/activate
  // Server-Timing headers. Names mirror the server metric names.
  ecdsaRespondD1ClaimMs: number;
  ecdsaRespondReconcileMs: number;
  ecdsaRespondRouterMs: number;
  ecdsaRespondD1CommitMs: number;
  ecdsaRespondTotalMs: number;
  ecdsaActivateD1ClaimMs: number;
  ecdsaActivateReconcileMs: number;
  ecdsaActivateRouterMs: number;
  ecdsaActivateBootstrapMs: number;
  ecdsaActivateSessionProvisionMs: number;
  ecdsaActivateD1CommitMs: number;
  ecdsaActivatePolicyLookupMs: number;
  ecdsaActivateJwtMintMs: number;
  ecdsaActivateTotalMs: number;
  // Router-reported spans, folded into the Gateway header at the service
  // binding. `rtDeriverA`/`rtDeriverB` overlap: the two run concurrently, and
  // `rtDerivers` is their joined wall time.
  ecdsaRtAuthorizeMs: number;
  ecdsaRtAdmissionMs: number;
  ecdsaRtDeriversMs: number;
  ecdsaRtDeriverAMs: number;
  ecdsaRtDeriverBMs: number;
  ecdsaRtCompletionMs: number;
  ecdsaRtTotalMs: number;
  ecdsaRtActSessionMs: number;
  ecdsaRtActWorkerMs: number;
  ecdsaRtActTotalMs: number;
  // Role-local spans, folded in by the Router under a per-role prefix.
  ecdsaDeriverAParseMs: number;
  ecdsaDeriverAPreloadMs: number;
  ecdsaDeriverAExecuteMs: number;
  ecdsaDeriverATotalMs: number;
  ecdsaDeriverBParseMs: number;
  ecdsaDeriverBPreloadMs: number;
  ecdsaDeriverBExecuteMs: number;
  ecdsaDeriverBTotalMs: number;
  ecdsaSigningWorkerParseMs: number;
  ecdsaSigningWorkerActivateMs: number;
  ecdsaSigningWorkerTotalMs: number;
  walletRegisterStartMs: number;
  ecdsaClientBootstrapMs: number;
  ecdsaRegistrationTotalMs: number;
  ecdsaRegistrationClientCreateMs: number;
  ecdsaRegistrationGatewayRespondMs: number;
  ecdsaRegistrationClientProofVerifyMs: number;
  ecdsaRegistrationGatewayActivateMs: number;
  ecdsaRegistrationClientActivationFinalizeMs: number;
  emailOtpRecoveryCodeBackupMs: number;
  walletRegisterFinalizeMs: number;
  ecdsaRegistrationPersistenceMs: number;
  ecdsaRegistrationSessionFinalizeMs: number;
  ecdsaRegistrationLocalRecordPersistenceMs: number;
  ecdsaRegistrationTargetCount: number;
  ecdsaRegistrationClientFinalizeMs: number;
  ecdsaRegistrationClientMaterialStoreMs: number;
  ecdsaRegistrationServerBootstrapMs: number;
  ecdsaRegistrationPasskeyBootstrapStoreMs: number;
  ecdsaRegistrationRoleLocalRecordPersistenceMs: number;
  ecdsaRegistrationWarmSessionHydrationMs: number;
  ecdsaRegistrationWarmSessionWorkerReadyMs: number;
  ecdsaRegistrationWarmSessionWorkerPutMs: number;
  ecdsaRegistrationWarmSessionSealedRecordPersistMs: number;
  ecdsaRegistrationWarmSessionSealResolveTransportMs: number;
  ecdsaRegistrationWarmSessionSealExistingRecordReadMs: number;
  ecdsaRegistrationWarmSessionSealPolicyReadMs: number;
  ecdsaRegistrationWarmSessionSealApplyServerSealMs: number;
  ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs: number;
  ecdsaRegistrationWarmSessionSealApplyClientSealMs: number;
  ecdsaRegistrationWarmSessionSealApplyServerRouteMs: number;
  ecdsaRegistrationWarmSessionSealApplyClientUnsealMs: number;
  ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs: number;
  ecdsaRegistrationWarmSessionSealRegisterMs: number;
  ecdsaRegistrationWarmSessionSealVerifyReadMs: number;
  ecdsaRegistrationEmailOtpSessionCommitMs: number;
};

type RegistrationTimingBucketName = keyof RegistrationTimingBucketValues;

type RegistrationTimingSpanKind = 'warmup' | 'auth' | 'ed25519_yao' | 'ecdsa' | 'registration';

type RegistrationTimingSpan = {
  name: RegistrationTimingBucketName;
  kind: RegistrationTimingSpanKind;
  startOffsetMs: number;
  endOffsetMs: number;
};

type RegistrationCriticalPathBucket = {
  name: RegistrationTimingBucketName;
  durationMs: number;
};

type RegistrationCriticalPathSummary = {
  kind: 'registration_critical_path_summary_v2';
  totalElapsedMs: number;
  measuredWorkMs: number;
  spanUnionMs: number;
  spanCoverageRatio: number;
  unattributedElapsedMs: number;
  overlappedOrBackgroundMs: number;
  topBuckets: readonly RegistrationCriticalPathBucket[];
  spans: readonly RegistrationTimingSpan[];
};

type PasskeyRegistrationAuthTiming = {
  kind: 'passkey';
  authProofMs: number;
  passkeyAuthConfirmationMs: number;
  passkeyAuthPrfExtractionMs: number;
  passkeyAuthCredentialRedactionMs: number;
  passkeyAuthWorkerReadyMs: number;
  passkeyAuthWorkerRequestRoundTripMs: number;
  passkeyAuthWorkerResponseValidationMs: number;
  passkeyAuthRequestSetupMs: number;
  passkeyAuthPromptUserMs: number;
  passkeyAuthPromptElementDefineMs: number;
  passkeyAuthPromptMountMs: number;
  passkeyAuthPromptHostFirstUpdateMs: number;
  passkeyAuthPromptHostInteractiveMs: number;
  passkeyAuthPromptConfirmEventMs: number;
  passkeyAuthPromptDecisionWaitMs: number;
  passkeyAuthCredentialCreateStartMs: number;
  passkeyAuthCredentialCreateMs: number;
  passkeyAuthCredentialSerializeMs: number;
  passkeyAuthDuplicateRetryCount: number;
  passkeyAuthMainThreadTotalMs: number;
  emailOtpEnrollmentMaterialMs: 0;
  emailOtpRecoveryCodeBackupMs: 0;
};

type EmailOtpRegistrationAuthTiming = {
  kind: 'email_otp';
  authProofMs: number;
  passkeyAuthConfirmationMs: 0;
  passkeyAuthPrfExtractionMs: 0;
  passkeyAuthCredentialRedactionMs: 0;
  passkeyAuthWorkerReadyMs: 0;
  passkeyAuthWorkerRequestRoundTripMs: 0;
  passkeyAuthWorkerResponseValidationMs: 0;
  passkeyAuthRequestSetupMs: 0;
  passkeyAuthPromptUserMs: 0;
  passkeyAuthPromptElementDefineMs: 0;
  passkeyAuthPromptMountMs: 0;
  passkeyAuthPromptHostFirstUpdateMs: 0;
  passkeyAuthPromptHostInteractiveMs: 0;
  passkeyAuthPromptConfirmEventMs: 0;
  passkeyAuthPromptDecisionWaitMs: 0;
  passkeyAuthCredentialCreateStartMs: 0;
  passkeyAuthCredentialCreateMs: 0;
  passkeyAuthCredentialSerializeMs: 0;
  passkeyAuthDuplicateRetryCount: 0;
  passkeyAuthMainThreadTotalMs: 0;
  emailOtpEnrollmentMaterialMs: number;
  emailOtpRecoveryCodeBackupMs: number;
};

type RegistrationAuthTiming = PasskeyRegistrationAuthTiming | EmailOtpRegistrationAuthTiming;

type RegistrationEd25519Timing =
  | {
      kind: 'ed25519_yao_enabled';
      emailOtpYaoEnrollmentMaterialWaitMs: number;
      emailOtpYaoWorkerRegistrationMs: number;
      emailOtpYaoTotalMs: number;
    }
  | {
      kind: 'ed25519_disabled';
      emailOtpYaoEnrollmentMaterialWaitMs: 0;
      emailOtpYaoWorkerRegistrationMs: 0;
      emailOtpYaoTotalMs: 0;
    };

type EcdsaEnabledRegistrationTiming = {
  kind: 'ecdsa_enabled';
  ecdsaClientBootstrapMs: number;
  ecdsaRegistrationTotalMs: number;
  ecdsaRegistrationClientCreateMs: number;
  ecdsaRegistrationGatewayRespondMs: number;
  ecdsaRegistrationClientProofVerifyMs: number;
  ecdsaRegistrationGatewayActivateMs: number;
  ecdsaRegistrationClientActivationFinalizeMs: number;
  ecdsaRegistrationPersistenceMs: number;
  ecdsaRegistrationSessionFinalizeMs: number;
  ecdsaRegistrationLocalRecordPersistenceMs: number;
  ecdsaRegistrationTargetCount: number;
  ecdsaRegistrationClientFinalizeMs: number;
  ecdsaRegistrationClientMaterialStoreMs: number;
  ecdsaRegistrationServerBootstrapMs: number;
  ecdsaRegistrationPasskeyBootstrapStoreMs: number;
  ecdsaRegistrationRoleLocalRecordPersistenceMs: number;
  ecdsaRegistrationWarmSessionHydrationMs: number;
  ecdsaRegistrationWarmSessionWorkerReadyMs: number;
  ecdsaRegistrationWarmSessionWorkerPutMs: number;
  ecdsaRegistrationWarmSessionSealedRecordPersistMs: number;
  ecdsaRegistrationWarmSessionSealResolveTransportMs: number;
  ecdsaRegistrationWarmSessionSealExistingRecordReadMs: number;
  ecdsaRegistrationWarmSessionSealPolicyReadMs: number;
  ecdsaRegistrationWarmSessionSealApplyServerSealMs: number;
  ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs: number;
  ecdsaRegistrationWarmSessionSealApplyClientSealMs: number;
  ecdsaRegistrationWarmSessionSealApplyServerRouteMs: number;
  ecdsaRegistrationWarmSessionSealApplyClientUnsealMs: number;
  ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs: number;
  ecdsaRegistrationWarmSessionSealRegisterMs: number;
  ecdsaRegistrationWarmSessionSealVerifyReadMs: number;
  ecdsaRegistrationEmailOtpSessionCommitMs: number;
};

type EcdsaDisabledRegistrationTiming = {
  kind: 'ecdsa_disabled';
  ecdsaClientBootstrapMs: 0;
  ecdsaRegistrationTotalMs: 0;
  ecdsaRegistrationClientCreateMs: 0;
  ecdsaRegistrationGatewayRespondMs: 0;
  ecdsaRegistrationClientProofVerifyMs: 0;
  ecdsaRegistrationGatewayActivateMs: 0;
  ecdsaRegistrationClientActivationFinalizeMs: 0;
  ecdsaRegistrationPersistenceMs: 0;
  ecdsaRegistrationSessionFinalizeMs: 0;
  ecdsaRegistrationLocalRecordPersistenceMs: 0;
  ecdsaRegistrationTargetCount: 0;
  ecdsaRegistrationClientFinalizeMs: 0;
  ecdsaRegistrationClientMaterialStoreMs: 0;
  ecdsaRegistrationServerBootstrapMs: 0;
  ecdsaRegistrationPasskeyBootstrapStoreMs: 0;
  ecdsaRegistrationRoleLocalRecordPersistenceMs: 0;
  ecdsaRegistrationWarmSessionHydrationMs: 0;
  ecdsaRegistrationWarmSessionWorkerReadyMs: 0;
  ecdsaRegistrationWarmSessionWorkerPutMs: 0;
  ecdsaRegistrationWarmSessionSealedRecordPersistMs: 0;
  ecdsaRegistrationWarmSessionSealResolveTransportMs: 0;
  ecdsaRegistrationWarmSessionSealExistingRecordReadMs: 0;
  ecdsaRegistrationWarmSessionSealPolicyReadMs: 0;
  ecdsaRegistrationWarmSessionSealApplyServerSealMs: 0;
  ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs: 0;
  ecdsaRegistrationWarmSessionSealApplyClientSealMs: 0;
  ecdsaRegistrationWarmSessionSealApplyServerRouteMs: 0;
  ecdsaRegistrationWarmSessionSealApplyClientUnsealMs: 0;
  ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs: 0;
  ecdsaRegistrationWarmSessionSealRegisterMs: 0;
  ecdsaRegistrationWarmSessionSealVerifyReadMs: 0;
  ecdsaRegistrationEmailOtpSessionCommitMs: 0;
};

type RegistrationEcdsaTiming = EcdsaEnabledRegistrationTiming | EcdsaDisabledRegistrationTiming;

type RegistrationTimingBuckets = RegistrationTimingBucketValues & {
  auth: RegistrationAuthTiming;
  ed25519: RegistrationEd25519Timing;
  ecdsa: RegistrationEcdsaTiming;
  emailOtpYaoPrewarm: EmailOtpYaoPrewarmOutcome;
};

type SucceededRegistrationTimingSummary = {
  kind: 'registration_timing_summary_v2';
  status: 'succeeded';
  authMethod: RegistrationTimingAuthMethod;
  signerSet: RegistrationTimingSignerSet;
  totalMs: number;
  criticalPath: RegistrationCriticalPathSummary;
  relayDiagnostics: WalletRegistrationRouteDiagnostics[];
  errorCode?: never;
  timings: RegistrationTimingBuckets;
};

type FailedRegistrationTimingSummary = {
  kind: 'registration_timing_summary_v2';
  status: 'failed';
  authMethod: RegistrationTimingAuthMethod;
  signerSet: RegistrationTimingSignerSet;
  totalMs: number;
  criticalPath: RegistrationCriticalPathSummary;
  errorCode: string | null;
  relayDiagnostics: WalletRegistrationRouteDiagnostics[];
  timings: RegistrationTimingBuckets;
};

type RegistrationTimingSummary =
  | SucceededRegistrationTimingSummary
  | FailedRegistrationTimingSummary;

export function assertNever(value: never): never {
  throw new Error(`Unexpected registration timing branch: ${String(value)}`);
}

function registrationTimingBranchFromPlanBranch(
  branch: RegistrationSignerPlanBranch,
): RegistrationTimingSignerBranch {
  switch (branch.kind) {
    case 'near_ed25519':
      return 'near_ed25519';
    case 'evm_family_ecdsa':
      return 'evm_family_ecdsa';
    default:
      return assertNever(branch);
  }
}

export function registrationTimingSignerSetFromPlan(
  plan: RegistrationSignerPlan,
): RegistrationTimingSignerSet {
  return {
    kind: 'signer_set',
    branches: plan.branches.map(registrationTimingBranchFromPlanBranch),
  };
}

function registrationTimingSignerSetHasBranch(
  signerSet: RegistrationTimingSignerSet,
  branch: RegistrationTimingSignerBranch,
): boolean {
  return signerSet.branches.includes(branch);
}

export function roundDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function parseWalletRegistrationRouteTimingName(
  value: unknown,
): WalletRegistrationRouteTimingName | null {
  switch (value) {
    case 'registrationIntentLoadMs':
    case 'registrationIntentDigestMs':
    case 'registrationIntentConsumeMs':
    case 'registrationPreparationPersistMs':
    case 'registrationPreparationLoadMs':
    case 'registrationPreparationConsumeMs':
    case 'registrationPreparationScopeCheckMs':
    case 'registrationAuthorityVerifyMs':
    case 'registrationEcdsaPrepareMs':
    case 'registrationCeremonyPersistMs':
    case 'registerPrepareTotalMs':
    case 'registerStartTotalMs':
    case 'registrationEcdsaRespondMs':
    case 'registrationFinalizeReplayLoadMs':
    case 'registrationCeremonyLoadMs':
    case 'registrationEcdsaBootstrapVerifyMs':
    case 'sponsoredNearAccountCreateMs':
    case 'registrationKeygenMs':
    case 'registrationEmailOtpEnrollmentPlanMs':
    case 'relaySessionMintMs':
    case 'relayGoogleEmailOtpActivationPlanMs':
    case 'relayPersistenceMs':
    case 'registrationFinalizeReplayCacheMs':
    case 'registerFinalizeTotalMs':
      return value;
    default:
      return null;
  }
}

function sanitizeWalletRegistrationRouteDiagnostics(
  value: unknown,
): WalletRegistrationRouteDiagnostics | null {
  if (!isObject(value) || value.kind !== 'wallet_registration_route_diagnostics_v1') return null;
  if (
    value.route !== 'wallets_register_start' &&
    value.route !== 'wallets_register_ecdsa_derivation_respond' &&
    value.route !== 'wallets_register_finalize'
  ) {
    return null;
  }
  if (!Array.isArray(value.entries)) return null;
  const entries: WalletRegistrationRouteDiagnostics['entries'] = [];
  for (const entry of value.entries) {
    if (!isObject(entry)) continue;
    const name = parseWalletRegistrationRouteTimingName(entry.name);
    const durationMs = Number(entry.durationMs);
    if (!name || !Number.isFinite(durationMs) || durationMs < 0) continue;
    entries.push({ name, durationMs });
  }
  return {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: value.route,
    entries,
  };
}

function copyWalletRegistrationRouteDiagnostics(
  diagnostics: WalletRegistrationRouteDiagnostics,
): WalletRegistrationRouteDiagnostics {
  return {
    kind: diagnostics.kind,
    route: diagnostics.route,
    entries: diagnostics.entries.map(copyWalletRegistrationRouteTimingEntry),
  };
}

function copyWalletRegistrationRouteTimingEntry(
  entry: WalletRegistrationRouteDiagnostics['entries'][number],
): WalletRegistrationRouteDiagnostics['entries'][number] {
  return { name: entry.name, durationMs: entry.durationMs };
}

function createZeroRegistrationTimingBucketValues(): RegistrationTimingBucketValues {
  return {
    registrationWarmupMs: 0,
    registrationWarmupWaitMs: 0,
    registrationWarmupAuthenticatedWalletStateMs: 0,
    registrationWarmupNoncePrefetchMs: 0,
    registrationWarmupKeyMaterialReadMs: 0,
    registrationWarmupUiConfirmPrewarmMs: 0,
    registrationWarmupSignerWorkerPrewarmMs: 0,
    registrationWarmupEmailOtpWorkerPrewarmMs: 0,
    registrationWarmupEmailOtpYaoWasmInitMs: 0,
    managedRegistrationGrantMs: 0,
    registrationIntentMs: 0,
    registrationIntentDigestMs: 0,
    authProofMs: 0,
    passkeyAuthConfirmationMs: 0,
    passkeyAuthPrfExtractionMs: 0,
    passkeyAuthCredentialRedactionMs: 0,
    passkeyAuthWorkerReadyMs: 0,
    passkeyAuthWorkerRequestRoundTripMs: 0,
    passkeyAuthWorkerResponseValidationMs: 0,
    passkeyAuthRequestSetupMs: 0,
    passkeyAuthPromptUserMs: 0,
    passkeyAuthPromptElementDefineMs: 0,
    passkeyAuthPromptMountMs: 0,
    passkeyAuthPromptHostFirstUpdateMs: 0,
    passkeyAuthPromptHostInteractiveMs: 0,
    passkeyAuthPromptConfirmEventMs: 0,
    passkeyAuthPromptDecisionWaitMs: 0,
    passkeyAuthCredentialCreateStartMs: 0,
    passkeyAuthCredentialCreateMs: 0,
    passkeyAuthCredentialSerializeMs: 0,
    passkeyAuthDuplicateRetryCount: 0,
    passkeyAuthMainThreadTotalMs: 0,
    emailOtpEnrollmentMaterialMs: 0,
    emailOtpYaoEnrollmentMaterialWaitMs: 0,
    emailOtpYaoWorkerRegistrationMs: 0,
    emailOtpYaoTotalMs: 0,
    yaoBranchTotalMs: 0,
    yaoAdmissionMs: 0,
    yaoClientSessionCreateMs: 0,
    yaoClientCompletionMs: 0,
    yaoServerCredentialDigestMs: 0,
    yaoServerRequestDigestMs: 0,
    yaoServerD1ClaimMs: 0,
    yaoServerRouterExecutionMs: 0,
    yaoServerResultReconstructionMs: 0,
    yaoServerD1TerminalCommitMs: 0,
    yaoServerRouterPreparePairMs: 0,
    yaoServerRouterVerifyReadinessMs: 0,
    yaoServerRouterRoleExecutionMs: 0,
    yaoServerRouterSigningWorkerDeliveryMs: 0,
    ecdsaRespondD1ClaimMs: 0,
    ecdsaRespondReconcileMs: 0,
    ecdsaRespondRouterMs: 0,
    ecdsaRespondD1CommitMs: 0,
    ecdsaRespondTotalMs: 0,
    ecdsaActivateD1ClaimMs: 0,
    ecdsaActivateReconcileMs: 0,
    ecdsaActivateRouterMs: 0,
    ecdsaActivateBootstrapMs: 0,
    ecdsaActivateSessionProvisionMs: 0,
    ecdsaActivateD1CommitMs: 0,
    ecdsaActivatePolicyLookupMs: 0,
    ecdsaActivateJwtMintMs: 0,
    ecdsaActivateTotalMs: 0,
    ecdsaRtAuthorizeMs: 0,
    ecdsaRtAdmissionMs: 0,
    ecdsaRtDeriversMs: 0,
    ecdsaRtDeriverAMs: 0,
    ecdsaRtDeriverBMs: 0,
    ecdsaRtCompletionMs: 0,
    ecdsaRtTotalMs: 0,
    ecdsaRtActSessionMs: 0,
    ecdsaRtActWorkerMs: 0,
    ecdsaRtActTotalMs: 0,
    ecdsaDeriverAParseMs: 0,
    ecdsaDeriverAPreloadMs: 0,
    ecdsaDeriverAExecuteMs: 0,
    ecdsaDeriverATotalMs: 0,
    ecdsaDeriverBParseMs: 0,
    ecdsaDeriverBPreloadMs: 0,
    ecdsaDeriverBExecuteMs: 0,
    ecdsaDeriverBTotalMs: 0,
    ecdsaSigningWorkerParseMs: 0,
    ecdsaSigningWorkerActivateMs: 0,
    ecdsaSigningWorkerTotalMs: 0,
    walletRegisterStartMs: 0,
    ecdsaClientBootstrapMs: 0,
    ecdsaRegistrationTotalMs: 0,
    ecdsaRegistrationClientCreateMs: 0,
    ecdsaRegistrationGatewayRespondMs: 0,
    ecdsaRegistrationClientProofVerifyMs: 0,
    ecdsaRegistrationGatewayActivateMs: 0,
    ecdsaRegistrationClientActivationFinalizeMs: 0,
    emailOtpRecoveryCodeBackupMs: 0,
    walletRegisterFinalizeMs: 0,
    ecdsaRegistrationPersistenceMs: 0,
    ecdsaRegistrationSessionFinalizeMs: 0,
    ecdsaRegistrationLocalRecordPersistenceMs: 0,
    ecdsaRegistrationTargetCount: 0,
    ecdsaRegistrationClientFinalizeMs: 0,
    ecdsaRegistrationClientMaterialStoreMs: 0,
    ecdsaRegistrationServerBootstrapMs: 0,
    ecdsaRegistrationPasskeyBootstrapStoreMs: 0,
    ecdsaRegistrationRoleLocalRecordPersistenceMs: 0,
    ecdsaRegistrationWarmSessionHydrationMs: 0,
    ecdsaRegistrationWarmSessionWorkerReadyMs: 0,
    ecdsaRegistrationWarmSessionWorkerPutMs: 0,
    ecdsaRegistrationWarmSessionSealedRecordPersistMs: 0,
    ecdsaRegistrationWarmSessionSealResolveTransportMs: 0,
    ecdsaRegistrationWarmSessionSealExistingRecordReadMs: 0,
    ecdsaRegistrationWarmSessionSealPolicyReadMs: 0,
    ecdsaRegistrationWarmSessionSealApplyServerSealMs: 0,
    ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs: 0,
    ecdsaRegistrationWarmSessionSealApplyClientSealMs: 0,
    ecdsaRegistrationWarmSessionSealApplyServerRouteMs: 0,
    ecdsaRegistrationWarmSessionSealApplyClientUnsealMs: 0,
    ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs: 0,
    ecdsaRegistrationWarmSessionSealRegisterMs: 0,
    ecdsaRegistrationWarmSessionSealVerifyReadMs: 0,
    ecdsaRegistrationEmailOtpSessionCommitMs: 0,
  };
}

function copyRegistrationTimingBucketValues(
  buckets: RegistrationTimingBucketValues,
): RegistrationTimingBucketValues {
  return {
    registrationWarmupMs: buckets.registrationWarmupMs,
    registrationWarmupWaitMs: buckets.registrationWarmupWaitMs,
    registrationWarmupAuthenticatedWalletStateMs:
      buckets.registrationWarmupAuthenticatedWalletStateMs,
    registrationWarmupNoncePrefetchMs: buckets.registrationWarmupNoncePrefetchMs,
    registrationWarmupKeyMaterialReadMs: buckets.registrationWarmupKeyMaterialReadMs,
    registrationWarmupUiConfirmPrewarmMs: buckets.registrationWarmupUiConfirmPrewarmMs,
    registrationWarmupSignerWorkerPrewarmMs: buckets.registrationWarmupSignerWorkerPrewarmMs,
    registrationWarmupEmailOtpWorkerPrewarmMs: buckets.registrationWarmupEmailOtpWorkerPrewarmMs,
    registrationWarmupEmailOtpYaoWasmInitMs: buckets.registrationWarmupEmailOtpYaoWasmInitMs,
    managedRegistrationGrantMs: buckets.managedRegistrationGrantMs,
    registrationIntentMs: buckets.registrationIntentMs,
    registrationIntentDigestMs: buckets.registrationIntentDigestMs,
    authProofMs: buckets.authProofMs,
    passkeyAuthConfirmationMs: buckets.passkeyAuthConfirmationMs,
    passkeyAuthPrfExtractionMs: buckets.passkeyAuthPrfExtractionMs,
    passkeyAuthCredentialRedactionMs: buckets.passkeyAuthCredentialRedactionMs,
    passkeyAuthWorkerReadyMs: buckets.passkeyAuthWorkerReadyMs,
    passkeyAuthWorkerRequestRoundTripMs: buckets.passkeyAuthWorkerRequestRoundTripMs,
    passkeyAuthWorkerResponseValidationMs: buckets.passkeyAuthWorkerResponseValidationMs,
    passkeyAuthRequestSetupMs: buckets.passkeyAuthRequestSetupMs,
    passkeyAuthPromptUserMs: buckets.passkeyAuthPromptUserMs,
    passkeyAuthPromptElementDefineMs: buckets.passkeyAuthPromptElementDefineMs,
    passkeyAuthPromptMountMs: buckets.passkeyAuthPromptMountMs,
    passkeyAuthPromptHostFirstUpdateMs: buckets.passkeyAuthPromptHostFirstUpdateMs,
    passkeyAuthPromptHostInteractiveMs: buckets.passkeyAuthPromptHostInteractiveMs,
    passkeyAuthPromptConfirmEventMs: buckets.passkeyAuthPromptConfirmEventMs,
    passkeyAuthPromptDecisionWaitMs: buckets.passkeyAuthPromptDecisionWaitMs,
    passkeyAuthCredentialCreateStartMs: buckets.passkeyAuthCredentialCreateStartMs,
    passkeyAuthCredentialCreateMs: buckets.passkeyAuthCredentialCreateMs,
    passkeyAuthCredentialSerializeMs: buckets.passkeyAuthCredentialSerializeMs,
    passkeyAuthDuplicateRetryCount: buckets.passkeyAuthDuplicateRetryCount,
    passkeyAuthMainThreadTotalMs: buckets.passkeyAuthMainThreadTotalMs,
    emailOtpEnrollmentMaterialMs: buckets.emailOtpEnrollmentMaterialMs,
    emailOtpYaoEnrollmentMaterialWaitMs: buckets.emailOtpYaoEnrollmentMaterialWaitMs,
    emailOtpYaoWorkerRegistrationMs: buckets.emailOtpYaoWorkerRegistrationMs,
    emailOtpYaoTotalMs: buckets.emailOtpYaoTotalMs,
    yaoBranchTotalMs: buckets.yaoBranchTotalMs,
    yaoAdmissionMs: buckets.yaoAdmissionMs,
    yaoClientSessionCreateMs: buckets.yaoClientSessionCreateMs,
    yaoClientCompletionMs: buckets.yaoClientCompletionMs,
    yaoServerCredentialDigestMs: buckets.yaoServerCredentialDigestMs,
    yaoServerRequestDigestMs: buckets.yaoServerRequestDigestMs,
    yaoServerD1ClaimMs: buckets.yaoServerD1ClaimMs,
    yaoServerRouterExecutionMs: buckets.yaoServerRouterExecutionMs,
    yaoServerResultReconstructionMs: buckets.yaoServerResultReconstructionMs,
    yaoServerD1TerminalCommitMs: buckets.yaoServerD1TerminalCommitMs,
    yaoServerRouterPreparePairMs: buckets.yaoServerRouterPreparePairMs,
    yaoServerRouterVerifyReadinessMs: buckets.yaoServerRouterVerifyReadinessMs,
    yaoServerRouterRoleExecutionMs: buckets.yaoServerRouterRoleExecutionMs,
    yaoServerRouterSigningWorkerDeliveryMs: buckets.yaoServerRouterSigningWorkerDeliveryMs,
    ecdsaRespondD1ClaimMs: buckets.ecdsaRespondD1ClaimMs,
    ecdsaRespondReconcileMs: buckets.ecdsaRespondReconcileMs,
    ecdsaRespondRouterMs: buckets.ecdsaRespondRouterMs,
    ecdsaRespondD1CommitMs: buckets.ecdsaRespondD1CommitMs,
    ecdsaRespondTotalMs: buckets.ecdsaRespondTotalMs,
    ecdsaActivateD1ClaimMs: buckets.ecdsaActivateD1ClaimMs,
    ecdsaActivateReconcileMs: buckets.ecdsaActivateReconcileMs,
    ecdsaActivateRouterMs: buckets.ecdsaActivateRouterMs,
    ecdsaActivateBootstrapMs: buckets.ecdsaActivateBootstrapMs,
    ecdsaActivateSessionProvisionMs: buckets.ecdsaActivateSessionProvisionMs,
    ecdsaActivateD1CommitMs: buckets.ecdsaActivateD1CommitMs,
    ecdsaActivatePolicyLookupMs: buckets.ecdsaActivatePolicyLookupMs,
    ecdsaActivateJwtMintMs: buckets.ecdsaActivateJwtMintMs,
    ecdsaActivateTotalMs: buckets.ecdsaActivateTotalMs,
    ecdsaRtAuthorizeMs: buckets.ecdsaRtAuthorizeMs,
    ecdsaRtAdmissionMs: buckets.ecdsaRtAdmissionMs,
    ecdsaRtDeriversMs: buckets.ecdsaRtDeriversMs,
    ecdsaRtDeriverAMs: buckets.ecdsaRtDeriverAMs,
    ecdsaRtDeriverBMs: buckets.ecdsaRtDeriverBMs,
    ecdsaRtCompletionMs: buckets.ecdsaRtCompletionMs,
    ecdsaRtTotalMs: buckets.ecdsaRtTotalMs,
    ecdsaRtActSessionMs: buckets.ecdsaRtActSessionMs,
    ecdsaRtActWorkerMs: buckets.ecdsaRtActWorkerMs,
    ecdsaRtActTotalMs: buckets.ecdsaRtActTotalMs,
    ecdsaDeriverAParseMs: buckets.ecdsaDeriverAParseMs,
    ecdsaDeriverAPreloadMs: buckets.ecdsaDeriverAPreloadMs,
    ecdsaDeriverAExecuteMs: buckets.ecdsaDeriverAExecuteMs,
    ecdsaDeriverATotalMs: buckets.ecdsaDeriverATotalMs,
    ecdsaDeriverBParseMs: buckets.ecdsaDeriverBParseMs,
    ecdsaDeriverBPreloadMs: buckets.ecdsaDeriverBPreloadMs,
    ecdsaDeriverBExecuteMs: buckets.ecdsaDeriverBExecuteMs,
    ecdsaDeriverBTotalMs: buckets.ecdsaDeriverBTotalMs,
    ecdsaSigningWorkerParseMs: buckets.ecdsaSigningWorkerParseMs,
    ecdsaSigningWorkerActivateMs: buckets.ecdsaSigningWorkerActivateMs,
    ecdsaSigningWorkerTotalMs: buckets.ecdsaSigningWorkerTotalMs,
    walletRegisterStartMs: buckets.walletRegisterStartMs,
    ecdsaClientBootstrapMs: buckets.ecdsaClientBootstrapMs,
    ecdsaRegistrationTotalMs: buckets.ecdsaRegistrationTotalMs,
    ecdsaRegistrationClientCreateMs: buckets.ecdsaRegistrationClientCreateMs,
    ecdsaRegistrationGatewayRespondMs: buckets.ecdsaRegistrationGatewayRespondMs,
    ecdsaRegistrationClientProofVerifyMs: buckets.ecdsaRegistrationClientProofVerifyMs,
    ecdsaRegistrationGatewayActivateMs: buckets.ecdsaRegistrationGatewayActivateMs,
    ecdsaRegistrationClientActivationFinalizeMs:
      buckets.ecdsaRegistrationClientActivationFinalizeMs,
    emailOtpRecoveryCodeBackupMs: buckets.emailOtpRecoveryCodeBackupMs,
    walletRegisterFinalizeMs: buckets.walletRegisterFinalizeMs,
    ecdsaRegistrationPersistenceMs: buckets.ecdsaRegistrationPersistenceMs,
    ecdsaRegistrationSessionFinalizeMs: buckets.ecdsaRegistrationSessionFinalizeMs,
    ecdsaRegistrationLocalRecordPersistenceMs: buckets.ecdsaRegistrationLocalRecordPersistenceMs,
    ecdsaRegistrationTargetCount: buckets.ecdsaRegistrationTargetCount,
    ecdsaRegistrationClientFinalizeMs: buckets.ecdsaRegistrationClientFinalizeMs,
    ecdsaRegistrationClientMaterialStoreMs: buckets.ecdsaRegistrationClientMaterialStoreMs,
    ecdsaRegistrationServerBootstrapMs: buckets.ecdsaRegistrationServerBootstrapMs,
    ecdsaRegistrationPasskeyBootstrapStoreMs: buckets.ecdsaRegistrationPasskeyBootstrapStoreMs,
    ecdsaRegistrationRoleLocalRecordPersistenceMs:
      buckets.ecdsaRegistrationRoleLocalRecordPersistenceMs,
    ecdsaRegistrationWarmSessionHydrationMs: buckets.ecdsaRegistrationWarmSessionHydrationMs,
    ecdsaRegistrationWarmSessionWorkerReadyMs: buckets.ecdsaRegistrationWarmSessionWorkerReadyMs,
    ecdsaRegistrationWarmSessionWorkerPutMs: buckets.ecdsaRegistrationWarmSessionWorkerPutMs,
    ecdsaRegistrationWarmSessionSealedRecordPersistMs:
      buckets.ecdsaRegistrationWarmSessionSealedRecordPersistMs,
    ecdsaRegistrationWarmSessionSealResolveTransportMs:
      buckets.ecdsaRegistrationWarmSessionSealResolveTransportMs,
    ecdsaRegistrationWarmSessionSealExistingRecordReadMs:
      buckets.ecdsaRegistrationWarmSessionSealExistingRecordReadMs,
    ecdsaRegistrationWarmSessionSealPolicyReadMs:
      buckets.ecdsaRegistrationWarmSessionSealPolicyReadMs,
    ecdsaRegistrationWarmSessionSealApplyServerSealMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyServerSealMs,
    ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs,
    ecdsaRegistrationWarmSessionSealApplyClientSealMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyClientSealMs,
    ecdsaRegistrationWarmSessionSealApplyServerRouteMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyServerRouteMs,
    ecdsaRegistrationWarmSessionSealApplyClientUnsealMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyClientUnsealMs,
    ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs,
    ecdsaRegistrationWarmSessionSealRegisterMs: buckets.ecdsaRegistrationWarmSessionSealRegisterMs,
    ecdsaRegistrationWarmSessionSealVerifyReadMs:
      buckets.ecdsaRegistrationWarmSessionSealVerifyReadMs,
    ecdsaRegistrationEmailOtpSessionCommitMs: buckets.ecdsaRegistrationEmailOtpSessionCommitMs,
  };
}

function buildRegistrationAuthTiming(input: {
  authMethod: RegistrationTimingAuthMethod;
  buckets: RegistrationTimingBucketValues;
}): RegistrationAuthTiming {
  switch (input.authMethod) {
    case 'passkey':
      return {
        kind: 'passkey',
        authProofMs: input.buckets.authProofMs,
        passkeyAuthConfirmationMs: input.buckets.passkeyAuthConfirmationMs,
        passkeyAuthPrfExtractionMs: input.buckets.passkeyAuthPrfExtractionMs,
        passkeyAuthCredentialRedactionMs: input.buckets.passkeyAuthCredentialRedactionMs,
        passkeyAuthWorkerReadyMs: input.buckets.passkeyAuthWorkerReadyMs,
        passkeyAuthWorkerRequestRoundTripMs: input.buckets.passkeyAuthWorkerRequestRoundTripMs,
        passkeyAuthWorkerResponseValidationMs: input.buckets.passkeyAuthWorkerResponseValidationMs,
        passkeyAuthRequestSetupMs: input.buckets.passkeyAuthRequestSetupMs,
        passkeyAuthPromptUserMs: input.buckets.passkeyAuthPromptUserMs,
        passkeyAuthPromptElementDefineMs: input.buckets.passkeyAuthPromptElementDefineMs,
        passkeyAuthPromptMountMs: input.buckets.passkeyAuthPromptMountMs,
        passkeyAuthPromptHostFirstUpdateMs: input.buckets.passkeyAuthPromptHostFirstUpdateMs,
        passkeyAuthPromptHostInteractiveMs: input.buckets.passkeyAuthPromptHostInteractiveMs,
        passkeyAuthPromptConfirmEventMs: input.buckets.passkeyAuthPromptConfirmEventMs,
        passkeyAuthPromptDecisionWaitMs: input.buckets.passkeyAuthPromptDecisionWaitMs,
        passkeyAuthCredentialCreateStartMs: input.buckets.passkeyAuthCredentialCreateStartMs,
        passkeyAuthCredentialCreateMs: input.buckets.passkeyAuthCredentialCreateMs,
        passkeyAuthCredentialSerializeMs: input.buckets.passkeyAuthCredentialSerializeMs,
        passkeyAuthDuplicateRetryCount: input.buckets.passkeyAuthDuplicateRetryCount,
        passkeyAuthMainThreadTotalMs: input.buckets.passkeyAuthMainThreadTotalMs,
        emailOtpEnrollmentMaterialMs: 0,
        emailOtpRecoveryCodeBackupMs: 0,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        authProofMs: input.buckets.authProofMs,
        passkeyAuthConfirmationMs: 0,
        passkeyAuthPrfExtractionMs: 0,
        passkeyAuthCredentialRedactionMs: 0,
        passkeyAuthWorkerReadyMs: 0,
        passkeyAuthWorkerRequestRoundTripMs: 0,
        passkeyAuthWorkerResponseValidationMs: 0,
        passkeyAuthRequestSetupMs: 0,
        passkeyAuthPromptUserMs: 0,
        passkeyAuthPromptElementDefineMs: 0,
        passkeyAuthPromptMountMs: 0,
        passkeyAuthPromptHostFirstUpdateMs: 0,
        passkeyAuthPromptHostInteractiveMs: 0,
        passkeyAuthPromptConfirmEventMs: 0,
        passkeyAuthPromptDecisionWaitMs: 0,
        passkeyAuthCredentialCreateStartMs: 0,
        passkeyAuthCredentialCreateMs: 0,
        passkeyAuthCredentialSerializeMs: 0,
        passkeyAuthDuplicateRetryCount: 0,
        passkeyAuthMainThreadTotalMs: 0,
        emailOtpEnrollmentMaterialMs: input.buckets.emailOtpEnrollmentMaterialMs,
        emailOtpRecoveryCodeBackupMs: input.buckets.emailOtpRecoveryCodeBackupMs,
      };
    default:
      return assertNever(input.authMethod);
  }
}

function buildRegistrationEd25519Timing(input: {
  signerSet: RegistrationTimingSignerSet;
  buckets: RegistrationTimingBucketValues;
}): RegistrationEd25519Timing {
  return registrationTimingSignerSetHasBranch(input.signerSet, 'near_ed25519')
    ? {
        kind: 'ed25519_yao_enabled',
        emailOtpYaoEnrollmentMaterialWaitMs: input.buckets.emailOtpYaoEnrollmentMaterialWaitMs,
        emailOtpYaoWorkerRegistrationMs: input.buckets.emailOtpYaoWorkerRegistrationMs,
        emailOtpYaoTotalMs: input.buckets.emailOtpYaoTotalMs,
      }
    : {
        kind: 'ed25519_disabled',
        emailOtpYaoEnrollmentMaterialWaitMs: 0,
        emailOtpYaoWorkerRegistrationMs: 0,
        emailOtpYaoTotalMs: 0,
      };
}

function buildRegistrationEcdsaTiming(input: {
  signerSet: RegistrationTimingSignerSet;
  buckets: RegistrationTimingBucketValues;
}): RegistrationEcdsaTiming {
  if (registrationTimingSignerSetHasBranch(input.signerSet, 'evm_family_ecdsa')) {
    return {
      kind: 'ecdsa_enabled',
      ecdsaClientBootstrapMs: input.buckets.ecdsaClientBootstrapMs,
      ecdsaRegistrationTotalMs: input.buckets.ecdsaRegistrationTotalMs,
      ecdsaRegistrationClientCreateMs: input.buckets.ecdsaRegistrationClientCreateMs,
      ecdsaRegistrationGatewayRespondMs: input.buckets.ecdsaRegistrationGatewayRespondMs,
      ecdsaRegistrationClientProofVerifyMs: input.buckets.ecdsaRegistrationClientProofVerifyMs,
      ecdsaRegistrationGatewayActivateMs: input.buckets.ecdsaRegistrationGatewayActivateMs,
      ecdsaRegistrationClientActivationFinalizeMs:
        input.buckets.ecdsaRegistrationClientActivationFinalizeMs,
      ecdsaRegistrationPersistenceMs: input.buckets.ecdsaRegistrationPersistenceMs,
      ecdsaRegistrationSessionFinalizeMs: input.buckets.ecdsaRegistrationSessionFinalizeMs,
      ecdsaRegistrationLocalRecordPersistenceMs:
        input.buckets.ecdsaRegistrationLocalRecordPersistenceMs,
      ecdsaRegistrationTargetCount: input.buckets.ecdsaRegistrationTargetCount,
      ecdsaRegistrationClientFinalizeMs: input.buckets.ecdsaRegistrationClientFinalizeMs,
      ecdsaRegistrationClientMaterialStoreMs: input.buckets.ecdsaRegistrationClientMaterialStoreMs,
      ecdsaRegistrationServerBootstrapMs: input.buckets.ecdsaRegistrationServerBootstrapMs,
      ecdsaRegistrationPasskeyBootstrapStoreMs:
        input.buckets.ecdsaRegistrationPasskeyBootstrapStoreMs,
      ecdsaRegistrationRoleLocalRecordPersistenceMs:
        input.buckets.ecdsaRegistrationRoleLocalRecordPersistenceMs,
      ecdsaRegistrationWarmSessionHydrationMs:
        input.buckets.ecdsaRegistrationWarmSessionHydrationMs,
      ecdsaRegistrationWarmSessionWorkerReadyMs:
        input.buckets.ecdsaRegistrationWarmSessionWorkerReadyMs,
      ecdsaRegistrationWarmSessionWorkerPutMs:
        input.buckets.ecdsaRegistrationWarmSessionWorkerPutMs,
      ecdsaRegistrationWarmSessionSealedRecordPersistMs:
        input.buckets.ecdsaRegistrationWarmSessionSealedRecordPersistMs,
      ecdsaRegistrationWarmSessionSealResolveTransportMs:
        input.buckets.ecdsaRegistrationWarmSessionSealResolveTransportMs,
      ecdsaRegistrationWarmSessionSealExistingRecordReadMs:
        input.buckets.ecdsaRegistrationWarmSessionSealExistingRecordReadMs,
      ecdsaRegistrationWarmSessionSealPolicyReadMs:
        input.buckets.ecdsaRegistrationWarmSessionSealPolicyReadMs,
      ecdsaRegistrationWarmSessionSealApplyServerSealMs:
        input.buckets.ecdsaRegistrationWarmSessionSealApplyServerSealMs,
      ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs:
        input.buckets.ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs,
      ecdsaRegistrationWarmSessionSealApplyClientSealMs:
        input.buckets.ecdsaRegistrationWarmSessionSealApplyClientSealMs,
      ecdsaRegistrationWarmSessionSealApplyServerRouteMs:
        input.buckets.ecdsaRegistrationWarmSessionSealApplyServerRouteMs,
      ecdsaRegistrationWarmSessionSealApplyClientUnsealMs:
        input.buckets.ecdsaRegistrationWarmSessionSealApplyClientUnsealMs,
      ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs:
        input.buckets.ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs,
      ecdsaRegistrationWarmSessionSealRegisterMs:
        input.buckets.ecdsaRegistrationWarmSessionSealRegisterMs,
      ecdsaRegistrationWarmSessionSealVerifyReadMs:
        input.buckets.ecdsaRegistrationWarmSessionSealVerifyReadMs,
      ecdsaRegistrationEmailOtpSessionCommitMs:
        input.buckets.ecdsaRegistrationEmailOtpSessionCommitMs,
    };
  }
  return {
    kind: 'ecdsa_disabled',
    ecdsaClientBootstrapMs: 0,
    ecdsaRegistrationTotalMs: 0,
    ecdsaRegistrationClientCreateMs: 0,
    ecdsaRegistrationGatewayRespondMs: 0,
    ecdsaRegistrationClientProofVerifyMs: 0,
    ecdsaRegistrationGatewayActivateMs: 0,
    ecdsaRegistrationClientActivationFinalizeMs: 0,
    ecdsaRegistrationPersistenceMs: 0,
    ecdsaRegistrationSessionFinalizeMs: 0,
    ecdsaRegistrationLocalRecordPersistenceMs: 0,
    ecdsaRegistrationTargetCount: 0,
    ecdsaRegistrationClientFinalizeMs: 0,
    ecdsaRegistrationClientMaterialStoreMs: 0,
    ecdsaRegistrationServerBootstrapMs: 0,
    ecdsaRegistrationPasskeyBootstrapStoreMs: 0,
    ecdsaRegistrationRoleLocalRecordPersistenceMs: 0,
    ecdsaRegistrationWarmSessionHydrationMs: 0,
    ecdsaRegistrationWarmSessionWorkerReadyMs: 0,
    ecdsaRegistrationWarmSessionWorkerPutMs: 0,
    ecdsaRegistrationWarmSessionSealedRecordPersistMs: 0,
    ecdsaRegistrationWarmSessionSealResolveTransportMs: 0,
    ecdsaRegistrationWarmSessionSealExistingRecordReadMs: 0,
    ecdsaRegistrationWarmSessionSealPolicyReadMs: 0,
    ecdsaRegistrationWarmSessionSealApplyServerSealMs: 0,
    ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs: 0,
    ecdsaRegistrationWarmSessionSealApplyClientSealMs: 0,
    ecdsaRegistrationWarmSessionSealApplyServerRouteMs: 0,
    ecdsaRegistrationWarmSessionSealApplyClientUnsealMs: 0,
    ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs: 0,
    ecdsaRegistrationWarmSessionSealRegisterMs: 0,
    ecdsaRegistrationWarmSessionSealVerifyReadMs: 0,
    ecdsaRegistrationEmailOtpSessionCommitMs: 0,
  };
}

const REGISTRATION_CRITICAL_PATH_BUCKETS: readonly RegistrationTimingBucketName[] = [
  'registrationWarmupWaitMs',
  'managedRegistrationGrantMs',
  'registrationIntentMs',
  'registrationIntentDigestMs',
  'authProofMs',
  'emailOtpEnrollmentMaterialMs',
  'emailOtpYaoEnrollmentMaterialWaitMs',
  'emailOtpYaoWorkerRegistrationMs',
  'emailOtpYaoTotalMs',
  'walletRegisterStartMs',
  'ecdsaClientBootstrapMs',
  'ecdsaRegistrationTotalMs',
  'emailOtpRecoveryCodeBackupMs',
  'walletRegisterFinalizeMs',
  'ecdsaRegistrationPersistenceMs',
];

function registrationTimingSpanKindFromBucket(
  bucket: RegistrationTimingBucketName,
): RegistrationTimingSpanKind {
  if (bucket.startsWith('registrationWarmup')) return 'warmup';
  if (bucket.startsWith('passkeyAuth') || bucket === 'authProofMs') return 'auth';
  if (bucket.includes('Yao') || bucket.includes('yao')) return 'ed25519_yao';
  if (bucket.includes('ecdsa')) return 'ecdsa';
  return 'registration';
}

function copyRegistrationTimingSpan(span: RegistrationTimingSpan): RegistrationTimingSpan {
  return {
    name: span.name,
    kind: span.kind,
    startOffsetMs: span.startOffsetMs,
    endOffsetMs: span.endOffsetMs,
  };
}

function registrationTimingSpanUnionMs(
  totalElapsedMs: number,
  spans: readonly RegistrationTimingSpan[],
): number {
  const sortedSpans = spans
    .map((span) => ({
      start: Math.max(0, Math.min(totalElapsedMs, span.startOffsetMs)),
      end: Math.max(0, Math.min(totalElapsedMs, span.endOffsetMs)),
    }))
    .filter((span) => span.end > span.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  let unionMs = 0;
  let currentStart = 0;
  let currentEnd = 0;
  for (const span of sortedSpans) {
    if (currentEnd <= currentStart) {
      currentStart = span.start;
      currentEnd = span.end;
      continue;
    }
    if (span.start > currentEnd) {
      unionMs += currentEnd - currentStart;
      currentStart = span.start;
      currentEnd = span.end;
      continue;
    }
    currentEnd = Math.max(currentEnd, span.end);
  }
  return currentEnd > currentStart ? unionMs + currentEnd - currentStart : unionMs;
}

function buildRegistrationCriticalPathSummary(input: {
  totalElapsedMs: number;
  buckets: RegistrationTimingBucketValues;
  spans: readonly RegistrationTimingSpan[];
}): RegistrationCriticalPathSummary {
  const measuredBuckets = REGISTRATION_CRITICAL_PATH_BUCKETS.map((name) => ({
    name,
    durationMs: input.buckets[name],
  }));
  const measuredWorkMs = measuredBuckets.reduce(
    (total, bucket) => total + Math.max(0, bucket.durationMs),
    0,
  );
  const topBuckets = measuredBuckets
    .filter((bucket) => bucket.durationMs > 0)
    .sort((left, right) =>
      right.durationMs === left.durationMs
        ? left.name.localeCompare(right.name)
        : right.durationMs - left.durationMs,
    )
    .slice(0, 5);
  const spanUnionMs = registrationTimingSpanUnionMs(input.totalElapsedMs, input.spans);
  return {
    kind: 'registration_critical_path_summary_v2',
    totalElapsedMs: input.totalElapsedMs,
    measuredWorkMs,
    spanUnionMs,
    spanCoverageRatio:
      input.totalElapsedMs > 0 ? Math.min(1, spanUnionMs / input.totalElapsedMs) : 1,
    unattributedElapsedMs: Math.max(0, input.totalElapsedMs - spanUnionMs),
    overlappedOrBackgroundMs: Math.max(0, measuredWorkMs - input.totalElapsedMs),
    topBuckets,
    spans: input.spans.map(copyRegistrationTimingSpan),
  };
}

function buildRegistrationTimingBuckets(input: {
  authMethod: RegistrationTimingAuthMethod;
  signerSet: RegistrationTimingSignerSet;
  buckets: RegistrationTimingBucketValues;
  emailOtpYaoPrewarm: EmailOtpYaoPrewarmOutcome;
}): RegistrationTimingBuckets {
  const buckets = copyRegistrationTimingBucketValues(input.buckets);
  return {
    registrationWarmupMs: buckets.registrationWarmupMs,
    registrationWarmupWaitMs: buckets.registrationWarmupWaitMs,
    registrationWarmupAuthenticatedWalletStateMs:
      buckets.registrationWarmupAuthenticatedWalletStateMs,
    registrationWarmupNoncePrefetchMs: buckets.registrationWarmupNoncePrefetchMs,
    registrationWarmupKeyMaterialReadMs: buckets.registrationWarmupKeyMaterialReadMs,
    registrationWarmupUiConfirmPrewarmMs: buckets.registrationWarmupUiConfirmPrewarmMs,
    registrationWarmupSignerWorkerPrewarmMs: buckets.registrationWarmupSignerWorkerPrewarmMs,
    registrationWarmupEmailOtpWorkerPrewarmMs: buckets.registrationWarmupEmailOtpWorkerPrewarmMs,
    registrationWarmupEmailOtpYaoWasmInitMs: buckets.registrationWarmupEmailOtpYaoWasmInitMs,
    managedRegistrationGrantMs: buckets.managedRegistrationGrantMs,
    registrationIntentMs: buckets.registrationIntentMs,
    registrationIntentDigestMs: buckets.registrationIntentDigestMs,
    authProofMs: buckets.authProofMs,
    passkeyAuthConfirmationMs: buckets.passkeyAuthConfirmationMs,
    passkeyAuthPrfExtractionMs: buckets.passkeyAuthPrfExtractionMs,
    passkeyAuthCredentialRedactionMs: buckets.passkeyAuthCredentialRedactionMs,
    passkeyAuthWorkerReadyMs: buckets.passkeyAuthWorkerReadyMs,
    passkeyAuthWorkerRequestRoundTripMs: buckets.passkeyAuthWorkerRequestRoundTripMs,
    passkeyAuthWorkerResponseValidationMs: buckets.passkeyAuthWorkerResponseValidationMs,
    passkeyAuthRequestSetupMs: buckets.passkeyAuthRequestSetupMs,
    passkeyAuthPromptUserMs: buckets.passkeyAuthPromptUserMs,
    passkeyAuthPromptElementDefineMs: buckets.passkeyAuthPromptElementDefineMs,
    passkeyAuthPromptMountMs: buckets.passkeyAuthPromptMountMs,
    passkeyAuthPromptHostFirstUpdateMs: buckets.passkeyAuthPromptHostFirstUpdateMs,
    passkeyAuthPromptHostInteractiveMs: buckets.passkeyAuthPromptHostInteractiveMs,
    passkeyAuthPromptConfirmEventMs: buckets.passkeyAuthPromptConfirmEventMs,
    passkeyAuthPromptDecisionWaitMs: buckets.passkeyAuthPromptDecisionWaitMs,
    passkeyAuthCredentialCreateStartMs: buckets.passkeyAuthCredentialCreateStartMs,
    passkeyAuthCredentialCreateMs: buckets.passkeyAuthCredentialCreateMs,
    passkeyAuthCredentialSerializeMs: buckets.passkeyAuthCredentialSerializeMs,
    passkeyAuthDuplicateRetryCount: buckets.passkeyAuthDuplicateRetryCount,
    passkeyAuthMainThreadTotalMs: buckets.passkeyAuthMainThreadTotalMs,
    emailOtpEnrollmentMaterialMs: buckets.emailOtpEnrollmentMaterialMs,
    emailOtpYaoEnrollmentMaterialWaitMs: buckets.emailOtpYaoEnrollmentMaterialWaitMs,
    emailOtpYaoWorkerRegistrationMs: buckets.emailOtpYaoWorkerRegistrationMs,
    emailOtpYaoTotalMs: buckets.emailOtpYaoTotalMs,
    yaoBranchTotalMs: buckets.yaoBranchTotalMs,
    yaoAdmissionMs: buckets.yaoAdmissionMs,
    yaoClientSessionCreateMs: buckets.yaoClientSessionCreateMs,
    yaoClientCompletionMs: buckets.yaoClientCompletionMs,
    yaoServerCredentialDigestMs: buckets.yaoServerCredentialDigestMs,
    yaoServerRequestDigestMs: buckets.yaoServerRequestDigestMs,
    yaoServerD1ClaimMs: buckets.yaoServerD1ClaimMs,
    yaoServerRouterExecutionMs: buckets.yaoServerRouterExecutionMs,
    yaoServerResultReconstructionMs: buckets.yaoServerResultReconstructionMs,
    yaoServerD1TerminalCommitMs: buckets.yaoServerD1TerminalCommitMs,
    yaoServerRouterPreparePairMs: buckets.yaoServerRouterPreparePairMs,
    yaoServerRouterVerifyReadinessMs: buckets.yaoServerRouterVerifyReadinessMs,
    yaoServerRouterRoleExecutionMs: buckets.yaoServerRouterRoleExecutionMs,
    yaoServerRouterSigningWorkerDeliveryMs: buckets.yaoServerRouterSigningWorkerDeliveryMs,
    ecdsaRespondD1ClaimMs: buckets.ecdsaRespondD1ClaimMs,
    ecdsaRespondReconcileMs: buckets.ecdsaRespondReconcileMs,
    ecdsaRespondRouterMs: buckets.ecdsaRespondRouterMs,
    ecdsaRespondD1CommitMs: buckets.ecdsaRespondD1CommitMs,
    ecdsaRespondTotalMs: buckets.ecdsaRespondTotalMs,
    ecdsaActivateD1ClaimMs: buckets.ecdsaActivateD1ClaimMs,
    ecdsaActivateReconcileMs: buckets.ecdsaActivateReconcileMs,
    ecdsaActivateRouterMs: buckets.ecdsaActivateRouterMs,
    ecdsaActivateBootstrapMs: buckets.ecdsaActivateBootstrapMs,
    ecdsaActivateSessionProvisionMs: buckets.ecdsaActivateSessionProvisionMs,
    ecdsaActivateD1CommitMs: buckets.ecdsaActivateD1CommitMs,
    ecdsaActivatePolicyLookupMs: buckets.ecdsaActivatePolicyLookupMs,
    ecdsaActivateJwtMintMs: buckets.ecdsaActivateJwtMintMs,
    ecdsaActivateTotalMs: buckets.ecdsaActivateTotalMs,
    ecdsaRtAuthorizeMs: buckets.ecdsaRtAuthorizeMs,
    ecdsaRtAdmissionMs: buckets.ecdsaRtAdmissionMs,
    ecdsaRtDeriversMs: buckets.ecdsaRtDeriversMs,
    ecdsaRtDeriverAMs: buckets.ecdsaRtDeriverAMs,
    ecdsaRtDeriverBMs: buckets.ecdsaRtDeriverBMs,
    ecdsaRtCompletionMs: buckets.ecdsaRtCompletionMs,
    ecdsaRtTotalMs: buckets.ecdsaRtTotalMs,
    ecdsaRtActSessionMs: buckets.ecdsaRtActSessionMs,
    ecdsaRtActWorkerMs: buckets.ecdsaRtActWorkerMs,
    ecdsaRtActTotalMs: buckets.ecdsaRtActTotalMs,
    ecdsaDeriverAParseMs: buckets.ecdsaDeriverAParseMs,
    ecdsaDeriverAPreloadMs: buckets.ecdsaDeriverAPreloadMs,
    ecdsaDeriverAExecuteMs: buckets.ecdsaDeriverAExecuteMs,
    ecdsaDeriverATotalMs: buckets.ecdsaDeriverATotalMs,
    ecdsaDeriverBParseMs: buckets.ecdsaDeriverBParseMs,
    ecdsaDeriverBPreloadMs: buckets.ecdsaDeriverBPreloadMs,
    ecdsaDeriverBExecuteMs: buckets.ecdsaDeriverBExecuteMs,
    ecdsaDeriverBTotalMs: buckets.ecdsaDeriverBTotalMs,
    ecdsaSigningWorkerParseMs: buckets.ecdsaSigningWorkerParseMs,
    ecdsaSigningWorkerActivateMs: buckets.ecdsaSigningWorkerActivateMs,
    ecdsaSigningWorkerTotalMs: buckets.ecdsaSigningWorkerTotalMs,
    walletRegisterStartMs: buckets.walletRegisterStartMs,
    ecdsaClientBootstrapMs: buckets.ecdsaClientBootstrapMs,
    ecdsaRegistrationTotalMs: buckets.ecdsaRegistrationTotalMs,
    ecdsaRegistrationClientCreateMs: buckets.ecdsaRegistrationClientCreateMs,
    ecdsaRegistrationGatewayRespondMs: buckets.ecdsaRegistrationGatewayRespondMs,
    ecdsaRegistrationClientProofVerifyMs: buckets.ecdsaRegistrationClientProofVerifyMs,
    ecdsaRegistrationGatewayActivateMs: buckets.ecdsaRegistrationGatewayActivateMs,
    ecdsaRegistrationClientActivationFinalizeMs:
      buckets.ecdsaRegistrationClientActivationFinalizeMs,
    emailOtpRecoveryCodeBackupMs: buckets.emailOtpRecoveryCodeBackupMs,
    walletRegisterFinalizeMs: buckets.walletRegisterFinalizeMs,
    ecdsaRegistrationPersistenceMs: buckets.ecdsaRegistrationPersistenceMs,
    ecdsaRegistrationSessionFinalizeMs: buckets.ecdsaRegistrationSessionFinalizeMs,
    ecdsaRegistrationLocalRecordPersistenceMs: buckets.ecdsaRegistrationLocalRecordPersistenceMs,
    ecdsaRegistrationTargetCount: buckets.ecdsaRegistrationTargetCount,
    ecdsaRegistrationClientFinalizeMs: buckets.ecdsaRegistrationClientFinalizeMs,
    ecdsaRegistrationClientMaterialStoreMs: buckets.ecdsaRegistrationClientMaterialStoreMs,
    ecdsaRegistrationServerBootstrapMs: buckets.ecdsaRegistrationServerBootstrapMs,
    ecdsaRegistrationPasskeyBootstrapStoreMs: buckets.ecdsaRegistrationPasskeyBootstrapStoreMs,
    ecdsaRegistrationRoleLocalRecordPersistenceMs:
      buckets.ecdsaRegistrationRoleLocalRecordPersistenceMs,
    ecdsaRegistrationWarmSessionHydrationMs: buckets.ecdsaRegistrationWarmSessionHydrationMs,
    ecdsaRegistrationWarmSessionWorkerReadyMs: buckets.ecdsaRegistrationWarmSessionWorkerReadyMs,
    ecdsaRegistrationWarmSessionWorkerPutMs: buckets.ecdsaRegistrationWarmSessionWorkerPutMs,
    ecdsaRegistrationWarmSessionSealedRecordPersistMs:
      buckets.ecdsaRegistrationWarmSessionSealedRecordPersistMs,
    ecdsaRegistrationWarmSessionSealResolveTransportMs:
      buckets.ecdsaRegistrationWarmSessionSealResolveTransportMs,
    ecdsaRegistrationWarmSessionSealExistingRecordReadMs:
      buckets.ecdsaRegistrationWarmSessionSealExistingRecordReadMs,
    ecdsaRegistrationWarmSessionSealPolicyReadMs:
      buckets.ecdsaRegistrationWarmSessionSealPolicyReadMs,
    ecdsaRegistrationWarmSessionSealApplyServerSealMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyServerSealMs,
    ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs,
    ecdsaRegistrationWarmSessionSealApplyClientSealMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyClientSealMs,
    ecdsaRegistrationWarmSessionSealApplyServerRouteMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyServerRouteMs,
    ecdsaRegistrationWarmSessionSealApplyClientUnsealMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyClientUnsealMs,
    ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs:
      buckets.ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs,
    ecdsaRegistrationWarmSessionSealRegisterMs: buckets.ecdsaRegistrationWarmSessionSealRegisterMs,
    ecdsaRegistrationWarmSessionSealVerifyReadMs:
      buckets.ecdsaRegistrationWarmSessionSealVerifyReadMs,
    ecdsaRegistrationEmailOtpSessionCommitMs: buckets.ecdsaRegistrationEmailOtpSessionCommitMs,
    auth: buildRegistrationAuthTiming({
      authMethod: input.authMethod,
      buckets,
    }),
    ed25519: buildRegistrationEd25519Timing({
      signerSet: input.signerSet,
      buckets,
    }),
    ecdsa: buildRegistrationEcdsaTiming({
      signerSet: input.signerSet,
      buckets,
    }),
    emailOtpYaoPrewarm: { ...input.emailOtpYaoPrewarm },
  };
}

export class RegistrationTimingRecorder {
  private readonly startedAt: number;
  private readonly buckets: RegistrationTimingBucketValues;
  private readonly relayDiagnostics: WalletRegistrationRouteDiagnostics[];
  private readonly spans: RegistrationTimingSpan[];
  private emailOtpYaoPrewarm: EmailOtpYaoPrewarmOutcome;

  constructor(startedAt: number) {
    this.startedAt = startedAt;
    this.buckets = createZeroRegistrationTimingBucketValues();
    this.relayDiagnostics = [];
    this.spans = [];
    this.emailOtpYaoPrewarm = zeroEmailOtpYaoPrewarmDiagnostics();
  }

  async measure<K extends RegistrationTimingBucketName, T>(
    bucket: K,
    operation: () => Promise<T>,
  ): Promise<T> {
    const startedAt = performance.now();
    try {
      return await operation();
    } finally {
      this.buckets[bucket] = roundDurationMs(startedAt);
      this.recordSpan(bucket, startedAt, performance.now());
    }
  }

  measureSync<K extends RegistrationTimingBucketName, T>(bucket: K, operation: () => T): T {
    const startedAt = performance.now();
    try {
      return operation();
    } finally {
      this.buckets[bucket] = roundDurationMs(startedAt);
      this.recordSpan(bucket, startedAt, performance.now());
    }
  }

  record<K extends RegistrationTimingBucketName>(bucket: K, durationMs: number): void {
    const rounded = Math.max(0, Math.round(durationMs));
    this.buckets[bucket] += rounded;
  }

  snapshot(): RegistrationTimingBucketValues {
    return copyRegistrationTimingBucketValues(this.buckets);
  }

  spansSnapshot(): readonly RegistrationTimingSpan[] {
    return this.spans.map(copyRegistrationTimingSpan);
  }

  private recordSpan(
    bucket: RegistrationTimingBucketName,
    startedAt: number,
    endedAt: number,
  ): void {
    this.spans.push({
      name: bucket,
      kind: registrationTimingSpanKindFromBucket(bucket),
      startOffsetMs: Math.max(0, Math.round(startedAt - this.startedAt)),
      endOffsetMs: Math.max(0, Math.round(endedAt - this.startedAt)),
    });
  }

  mergeSnapshot(snapshot: RegistrationTimingBucketValues): void {
    for (const key of Object.keys(snapshot) as RegistrationTimingBucketName[]) {
      const value = snapshot[key];
      if (value > 0 && this.buckets[key] === 0) {
        this.buckets[key] = value;
      }
    }
  }

  captureRouteDiagnostics(value: unknown): void {
    const sanitized = sanitizeWalletRegistrationRouteDiagnostics(value);
    if (sanitized) this.relayDiagnostics.push(sanitized);
  }

  captureRouteDiagnosticsSnapshot(snapshot: readonly WalletRegistrationRouteDiagnostics[]): void {
    for (const diagnostics of snapshot) {
      this.relayDiagnostics.push(copyWalletRegistrationRouteDiagnostics(diagnostics));
    }
  }

  captureWarmupDiagnostics(diagnostics: RegistrationWarmupDiagnostics): void {
    this.buckets.registrationWarmupAuthenticatedWalletStateMs =
      diagnostics.authenticatedWalletStateMs;
    this.buckets.registrationWarmupNoncePrefetchMs = diagnostics.noncePrefetchMs;
    this.buckets.registrationWarmupKeyMaterialReadMs = diagnostics.keyMaterialReadMs;
    this.buckets.registrationWarmupUiConfirmPrewarmMs = diagnostics.uiConfirmPrewarmMs;
    this.buckets.registrationWarmupSignerWorkerPrewarmMs = diagnostics.signerWorkerPrewarmMs;
    this.buckets.registrationWarmupEmailOtpWorkerPrewarmMs = diagnostics.emailOtpWorkerPrewarmMs;
    this.buckets.registrationWarmupEmailOtpYaoWasmInitMs = diagnostics.emailOtpYaoWasmInitMs;
    this.emailOtpYaoPrewarm = { ...diagnostics.emailOtpYaoPrewarm };
  }

  emailOtpYaoPrewarmSnapshot(): EmailOtpYaoPrewarmOutcome {
    return { ...this.emailOtpYaoPrewarm };
  }

  capturePasskeyAuthDiagnostics(diagnostics: PasskeyRegistrationAuthorityDiagnostics): void {
    this.buckets.passkeyAuthConfirmationMs = diagnostics.requestConfirmationMs;
    this.buckets.passkeyAuthPrfExtractionMs = diagnostics.prfExtractionMs;
    this.buckets.passkeyAuthCredentialRedactionMs = diagnostics.credentialRedactionMs;
    this.buckets.passkeyAuthWorkerReadyMs = diagnostics.confirmationWorkerReadyMs;
    this.buckets.passkeyAuthWorkerRequestRoundTripMs =
      diagnostics.confirmationWorkerRequestRoundTripMs;
    this.buckets.passkeyAuthWorkerResponseValidationMs =
      diagnostics.confirmationWorkerResponseValidationMs;
    this.buckets.passkeyAuthRequestSetupMs = diagnostics.confirmationRequestSetupMs;
    this.buckets.passkeyAuthPromptUserMs = diagnostics.confirmationPromptUserMs;
    this.buckets.passkeyAuthPromptElementDefineMs = diagnostics.confirmationPromptElementDefineMs;
    this.buckets.passkeyAuthPromptMountMs = diagnostics.confirmationPromptMountMs;
    this.buckets.passkeyAuthPromptHostFirstUpdateMs =
      diagnostics.confirmationPromptHostFirstUpdateMs;
    this.buckets.passkeyAuthPromptHostInteractiveMs =
      diagnostics.confirmationPromptHostInteractiveMs;
    this.buckets.passkeyAuthPromptConfirmEventMs = diagnostics.confirmationPromptConfirmEventMs;
    this.buckets.passkeyAuthPromptDecisionWaitMs = diagnostics.confirmationPromptDecisionWaitMs;
    this.buckets.passkeyAuthCredentialCreateStartMs =
      diagnostics.confirmationCredentialCreateStartMs;
    this.buckets.passkeyAuthCredentialCreateMs = diagnostics.confirmationCredentialCreateMs;
    this.buckets.passkeyAuthCredentialSerializeMs = diagnostics.confirmationCredentialSerializeMs;
    this.buckets.passkeyAuthDuplicateRetryCount = diagnostics.confirmationDuplicateRetryCount;
    this.buckets.passkeyAuthMainThreadTotalMs = diagnostics.confirmationMainThreadTotalMs;
  }

  routeDiagnosticsSnapshot(): WalletRegistrationRouteDiagnostics[] {
    return this.relayDiagnostics.map(copyWalletRegistrationRouteDiagnostics);
  }

  totalMs(): number {
    return roundDurationMs(this.startedAt);
  }
}

export type RegistrationWarmupDiagnostics = WorkerResourceWarmupDiagnostics & {
  emailOtpWorkerPrewarmMs: number;
  emailOtpYaoWasmInitMs: number;
  emailOtpYaoPrewarm: EmailOtpYaoPrewarmOutcome;
};

export function zeroEmailOtpYaoPrewarmDiagnostics(): EmailOtpYaoPrewarmOutcome {
  return {
    kind: 'not_requested',
    elapsedMs: 0,
    workerPrewarmMs: 0,
    yaoWasmInitMs: 0,
  };
}

export function createSucceededRegistrationTimingSummary(input: {
  recorder: RegistrationTimingRecorder;
  authMethod: RegistrationTimingAuthMethod;
  signerSet: RegistrationTimingSignerSet;
}): SucceededRegistrationTimingSummary {
  const totalMs = input.recorder.totalMs();
  const buckets = input.recorder.snapshot();
  return {
    kind: 'registration_timing_summary_v2',
    status: 'succeeded',
    authMethod: input.authMethod,
    signerSet: input.signerSet,
    totalMs,
    criticalPath: buildRegistrationCriticalPathSummary({
      totalElapsedMs: totalMs,
      buckets,
      spans: input.recorder.spansSnapshot(),
    }),
    relayDiagnostics: input.recorder.routeDiagnosticsSnapshot(),
    timings: buildRegistrationTimingBuckets({
      authMethod: input.authMethod,
      signerSet: input.signerSet,
      buckets,
      emailOtpYaoPrewarm: input.recorder.emailOtpYaoPrewarmSnapshot(),
    }),
  };
}

export function createFailedRegistrationTimingSummary(input: {
  recorder: RegistrationTimingRecorder;
  authMethod: RegistrationTimingAuthMethod;
  signerSet: RegistrationTimingSignerSet;
  errorCode: string | null;
}): FailedRegistrationTimingSummary {
  const totalMs = input.recorder.totalMs();
  const buckets = input.recorder.snapshot();
  return {
    kind: 'registration_timing_summary_v2',
    status: 'failed',
    authMethod: input.authMethod,
    signerSet: input.signerSet,
    totalMs,
    criticalPath: buildRegistrationCriticalPathSummary({
      totalElapsedMs: totalMs,
      buckets,
      spans: input.recorder.spansSnapshot(),
    }),
    errorCode: input.errorCode,
    relayDiagnostics: input.recorder.routeDiagnosticsSnapshot(),
    timings: buildRegistrationTimingBuckets({
      authMethod: input.authMethod,
      signerSet: input.signerSet,
      buckets,
      emailOtpYaoPrewarm: input.recorder.emailOtpYaoPrewarmSnapshot(),
    }),
  };
}

export function emitRegistrationTimingSummary(summary: RegistrationTimingSummary): void {
  if (!isRegistrationBenchmarkDiagnosticsEnabled()) return;
  console.info(REGISTRATION_TIMING_LABEL, summary);
  console.info(`${REGISTRATION_TIMING_LABEL} ${JSON.stringify(summary)}`);
}

export function emitRegistrationTimingSpan(input: {
  callback: RegistrationHooksOptions['onTimingSpan'];
  span: RegistrationTimingSpanV1['span'];
  outcome: RegistrationTimingSpanV1['outcome'];
  durationMs: number;
  traceContext: RouterAbTraceContextV1;
}): void {
  const event: RegistrationTimingSpanV1 = {
    event: 'seams_registration_timing_span_v1',
    span: input.span,
    operation: 'registration',
    outcome: input.outcome,
    duration_ms: Math.max(0, Math.round(input.durationMs)),
    trace_id: input.traceContext.value,
  };
  try {
    input.callback?.(event);
  } catch {
    // Telemetry must never change registration behavior.
  }
}
