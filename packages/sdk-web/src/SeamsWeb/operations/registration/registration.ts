import { isObject } from '@shared/utils/validation';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
  type CorrelationId,
} from '@shared/utils/canonicalPrimitives';
import {
  parseThresholdEd25519SessionId,
  parseWebAuthnRpId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type { ThresholdEd25519SessionId } from '@/core/signingEngine/session/operationState/types';
import type {
  CreateRegistrationFlowEventInput,
  RegistrationFlowEvent,
  RegistrationHooksOptions,
  RegistrationTimingSpanV1,
  WalletFlowAuthMethod,
} from '@/core/types/sdkSentEvents';
import type {
  NearProvisioningErrorCode,
  NearProvisioningState,
  RegistrationNearProvisioningState,
  RegistrationResult,
  SeamsConfigsReadonly,
} from '@/core/types/seams';
import {
  publishNearProvisioningState,
  runSingleFlightNearProvisioning,
} from '@/core/signingEngine/flows/registration/nearProvisioningRegistry';
import { resolveManagedRuntimeScopeBootstrap } from '@/core/config/managedRuntimeScope';
import {
  cloneAuthenticatorOptions,
  type AuthenticatorOptions,
} from '@/core/types/authenticatorOptions';
import { createRegistrationFlowEvent, RegistrationEventPhase } from '@/core/types/sdkSentEvents';
import type {
  RegistrationSigningSurface,
  RegistrationWebContext,
} from '@/SeamsWeb/signingSurface/types';
import type { WorkerResourceWarmupDiagnostics } from '@/core/signingEngine/assembly/warmup';
import type { EmailOtpYaoPrewarmOutcome } from '@/core/signingEngine/workerManager/workerTypes';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { alphabetizeStringify, sha256BytesUtf8, sha256HexUtf8 } from '@shared/utils/digests';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { normalizeRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { IndexedDBManager, walletSessionAuthorizations } from '@/core/indexedDB';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import type {
  WalletIframeAuthMenuSessionId,
  WalletIframeRequestId,
} from '@/core/types/walletIframeIdentity';
import {
  webAuthnPromptCoordinator,
  type HostedAuthMenuRegistrationWebAuthnPromptOwner,
  type ReservedRegistrationWebAuthnPrompt,
  type WebAuthnPromptCancellation,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  AddSignerSelection,
  RegistrationAuthMethodInput,
  RegistrationEvmFamilyEcdsaSignerPlan,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationNearEd25519SignerPlan,
  RegistrationSignerPlan,
  RegistrationSignerPlanBranch,
  RegisterWalletInput,
  RegistrationSignerSetSelection,
  WalletId,
} from '@shared/utils/registrationIntent';
import {
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  registrationSignerPlanFromSelection,
  parseNearEd25519SigningKeyId,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toParticipantId,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  type ExactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { computeRegistrationIntentDigest } from '@/utils/intentDigest';
import { computeAddSignerIntentDigest } from '@/utils/intentDigest';
import type { EmailOtpRegistrationProof } from '@shared/utils/registrationIntent';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  setupWalletRegistration,
  activateWalletAddSignerEcdsa,
  activateWalletRegistrationEcdsa,
  canonicalWalletAddSignerEcdsaActivationCommitRequest,
  canonicalWalletRegistrationEcdsaActivationCommitRequest,
  createWalletAddSignerIntent,
  finalizeWalletAddSigner,
  isEmailOtpWalletRegistrationFinalizeResponse,
  parseWalletRegistrationEcdsaDerivationRespond,
  prepareWalletAddSignerEcdsaActivation,
  prepareWalletRegistrationEcdsaActivation,
  queryWalletAddSignerEcdsaActivation,
  queryWalletRegistrationEcdsaActivation,
  activateWalletRegistration,
  completeWalletRegistrationNearProvisioning,
  respondWalletAddSignerEcdsa,
  respondWalletRegistration,
  respondWalletRegistrationEcdsa,
  startWalletAddSigner,
  type RegistrationPreparationId,
  type WalletRegistrationActivateResponseV2,
  type WalletRegistrationSetupResponseV2,
  type WalletRegistrationRespondEd25519DeferredWork,
  type WalletRegistrationEcdsaDerivationRespondBootstrap,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEmailOtpEnrollmentMaterial,
  type WalletRegistrationEd25519YaoActivationReference,
  type WalletRegistrationEmailOtpBackupAck,
  type WalletRegistrationEd25519YaoPublicResult,
  type WalletRegistrationFinalizeResponse,
  type WalletRegistrationEcdsaRespondResponse,
  type WalletRegistrationEcdsaPreparePayload,
  type WalletRegistrationStartResponse,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
  type WalletAddSignerFinalizeResponse,
  type WalletAddSignerStartResponse,
} from '@/core/rpcClients/relayer/walletRegistration';
import type {
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import {
  collectPasskeyRegistrationAuthority,
  collectPasskeyRegistrationAuthorityFromCredential,
  type PasskeyRegistrationAuthorityDiagnostics,
} from '@/SeamsWeb/operations/authMethods/passkey/registrationAuthority';
import { backupEmailOtpRecoveryCodes } from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import type { GoogleEmailOtpRegistrationBackupEnrollmentInput } from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import type {
  GoogleEmailOtpRegistrationBackedUpEnrollmentResult,
  RegistrationFinalizeIdempotencyKey,
} from '@/SeamsWeb/publicApi/types';
import { registrationFinalizeIdempotencyKeyFromString } from '@/SeamsWeb/publicApi/types';
import { collectEmailOtpRegistrationAuthority } from '@/SeamsWeb/operations/authMethods/emailOtp/registrationAuthority';
import type { PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult as EmailOtpRegistrationEnrollmentMaterial } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import { requirePasskeyPrfFirstB64u } from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import { rememberWalletOriginAppSession } from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  startEmailOtpEd25519YaoWorkerRegistrationV1,
  EmailOtpEd25519YaoWorkerPendingRegistrationV1,
  type EmailOtpEd25519YaoWorkerActiveClientV1,
  type EmailOtpEd25519YaoRegistrationDiagnosticsV1,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoWorkerClient';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  isEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpProvider,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { parseCanonicalEcdsaServerActivationRequest } from '@shared/utils/ecdsaCapabilityActivation';
import { registerVerifiedPasskeyEd25519YaoV1 } from '@/core/signingEngine/flows/registration/services/passkeyEd25519YaoRegistration';
import { registerVerifiedPasskeyEd25519YaoAddSignerV1 } from '@/core/signingEngine/flows/registration/services/passkeyEd25519YaoAddSigner';
import type {
  ProductEd25519YaoBrowserMaterialPersistencePortV1,
  ProductEd25519YaoPendingRegistrationPortV1,
  ProductEd25519YaoRegistrationResultV1,
} from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoSealableActiveClientV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  deletePasskeyEd25519YaoSignerMaterialV1,
  persistPasskeyEd25519YaoSignerMaterialV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { nearEd25519YaoMaterialActivationFromMetadata } from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  buildPasskeyRouterAbEd25519WalletSessionState,
  buildEmailOtpRouterAbEd25519WalletSessionState,
  nearEd25519YaoOperationMaterialFacts,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';
import { toAccountId } from '@/core/types/accountIds';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type {
  RegistrationEstablishedEcdsaSession,
  RegistrationEstablishedEd25519Session,
  RegistrationEstablishedSession,
} from '@shared/utils/registrationEstablishedSession';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import { persistActiveWalletSessionAuthorizationFromRegistration } from '@/core/signingEngine/session/persistence/walletSessionAuthorizationProjection';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import {
  emailOtpAppSessionBindingFromJwt,
  type EmailOtpAppSessionBinding,
} from '@/core/signingEngine/session/emailOtp/appSessionJwtCache';
import {
  createRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';

// Registration forces a visible, clickable confirmation for cross-origin safety.

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

function requireWebAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

type PasskeyAuthorityCredential = {
  readonly id?: unknown;
  readonly rawId?: unknown;
};

function passkeyWalletAuthAuthorityFromCredential(args: {
  walletId: WalletId | string;
  rpId: WebAuthnRpId | string;
  credential: PasskeyAuthorityCredential;
}): WalletAuthAuthority {
  return buildPasskeyWalletAuthAuthority({
    walletId: args.walletId,
    rpId: args.rpId,
    credentialIdB64u: String(args.credential.rawId || args.credential.id || '').trim(),
  });
}

export function isRegistrationBenchmarkDiagnosticsEnabled(): boolean {
  const globalFlag = (
    globalThis as {
      __SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS?: unknown;
    }
  ).__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS;
  return globalFlag === true;
}

type EmitRegistrationEventInput = Omit<
  CreateRegistrationFlowEventInput,
  'accountId' | 'flowId' | 'authMethod'
> & {
  authMethod: WalletFlowAuthMethod;
};

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

type EmailOtpRegistrationAuthMethod = Extract<RegistrationAuthMethodInput, { kind: 'email_otp' }>;

type EmailOtpRecoveryCodeBackupOutcome =
  | {
      ok: true;
      backedUpEnrollment: Awaited<ReturnType<typeof backupEmailOtpRecoveryCodes>>;
      error?: never;
    }
  | {
      ok: false;
      error: unknown;
      backedUpEnrollment?: never;
    };

export type RegisterWalletOperationInput = {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  options: RegistrationHooksOptions;
  authenticatorOptions: AuthenticatorOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

const hostedPasskeyRegistrationPreparedBrand: unique symbol = Symbol(
  'hostedPasskeyRegistrationPrepared',
);

export type HostedPasskeyRegistrationPrepared = Readonly<{
  kind: 'hosted_passkey_registration_prepared_v1';
  walletId: WalletId;
  signerSlot: number;
  rpId: WebAuthnRpId;
  challengeB64u: string;
  registrationIntentDigestB64u: string;
  expiresAtMs: number;
  owner: HostedAuthMenuRegistrationWebAuthnPromptOwner;
  reservation: ReservedRegistrationWebAuthnPrompt<HostedAuthMenuRegistrationWebAuthnPromptOwner>;
  cancellation: {
    kind: 'abort_signal';
    signal: AbortSignal;
  };
  [hostedPasskeyRegistrationPreparedBrand]: true;
}>;

export type HostedPasskeyRegistrationPreparationInput = {
  context: RegistrationWebContext;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
  authMenuSessionId: WalletIframeAuthMenuSessionId;
  requestId: WalletIframeRequestId;
  cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>;
  options?: RegistrationHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  expiresInMs?: number;
};

type HostedPasskeyRegistrationPreparationState = {
  prepared: HostedPasskeyRegistrationPrepared;
  context: RegistrationWebContext;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
  options: RegistrationHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  setup: Awaited<ReturnType<typeof setupThreeRouteRegistration>>;
  controller: AbortController;
  removeExternalCancellationListener: (() => void) | null;
  binding: string;
  lifecycle: 'ready' | 'consuming' | 'consumed' | 'cancelled' | 'finished';
  authority: Promise<RegistrationPasskeyAuthority> | null;
  registrationStarted: boolean;
};

const hostedPasskeyRegistrationStates = new WeakMap<
  HostedPasskeyRegistrationPrepared,
  HostedPasskeyRegistrationPreparationState
>();

type RegisterWalletPasskeyExecution =
  | { kind: 'collect_during_registration' }
  | {
      kind: 'use_hosted_preparation';
      prepared: HostedPasskeyRegistrationPrepared;
      authority: Promise<RegistrationPasskeyAuthority>;
    };

/* Setup writes one ceremony row and nothing else, so a failed registration
   has no separate reservation or grant to release — only the page-owned Yao
   work needs disposing. */
async function cleanUpFailedWalletRegistration(yaoWork: RegistrationYaoWork): Promise<void> {
  await yaoWork.dispose();
}

type EvmFamilyEcdsaRegistrationBranch = RegistrationEvmFamilyEcdsaSignerPlan;

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

function assertNever(value: never): never {
  throw new Error(`Unexpected registration timing branch: ${String(value)}`);
}

function registrationSignerPlanFromSignerSet(
  selection: RegistrationSignerSetSelection,
): RegistrationSignerPlan {
  const plan = registrationSignerPlanFromSelection(selection);
  if (!plan.ok) {
    throw new Error(plan.message);
  }
  return plan.value;
}

function registrationSignerPlanFromIntentSelection(input: {
  selection: Parameters<typeof registrationSignerPlanFromSelection>[0];
}): RegistrationSignerPlan {
  const plan = registrationSignerPlanFromSelection(input.selection);
  if (!plan.ok) {
    throw new Error(plan.message);
  }
  return plan.value;
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

function registrationTimingSignerSetFromPlan(
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

function requiredRegistrationRpId(input: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  operation: string;
}): string {
  const rpId =
    input.authMethod.kind === 'passkey'
      ? String(input.authMethod.rpId || '').trim()
      : String(input.context.signingEngine.getRpId() || '').trim();
  if (!rpId) {
    throw new Error(`${input.operation} requires configured rpId`);
  }
  return rpId;
}

function roundDurationMs(startedAt: number): number {
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

class RegistrationTimingRecorder {
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

type RegistrationWarmupDiagnostics = WorkerResourceWarmupDiagnostics & {
  emailOtpWorkerPrewarmMs: number;
  emailOtpYaoWasmInitMs: number;
  emailOtpYaoPrewarm: EmailOtpYaoPrewarmOutcome;
};

type RegistrationWarmupOutcome =
  | {
      kind: 'completed';
      diagnostics: RegistrationWarmupDiagnostics;
      error?: never;
    }
  | {
      kind: 'failed';
      error: unknown;
    };

function registrationWarmupWork(
  context: RegistrationWebContext,
): () => Promise<WorkerResourceWarmupDiagnostics> {
  return context.signingEngine.warmCriticalResources.bind(context.signingEngine, { kind: 'none' });
}

function registrationPlanBranchIncludesNearEd25519(branch: RegistrationSignerPlanBranch): boolean {
  return branch.kind === 'near_ed25519';
}

function registrationSelectionRequiresEmailOtpYaoWarmup(
  signerSelection: RegistrationSignerSetSelection,
): boolean {
  return registrationSignerPlanFromSignerSet(signerSelection).branches.some(
    registrationPlanBranchIncludesNearEd25519,
  );
}

function zeroEmailOtpYaoPrewarmDiagnostics(): EmailOtpYaoPrewarmOutcome {
  return {
    kind: 'not_requested',
    elapsedMs: 0,
    workerPrewarmMs: 0,
    yaoWasmInitMs: 0,
  };
}

function noEmailOtpYaoPrewarm(): Promise<EmailOtpYaoPrewarmOutcome> {
  return Promise.resolve(zeroEmailOtpYaoPrewarmDiagnostics());
}

function registrationSelectionIncludesEcdsa(
  signerSelection: RegistrationSignerSetSelection,
): boolean {
  return signerSelection.signers.some((signer) => signer.kind === 'evm_family_ecdsa');
}

function registrationEmailOtpYaoPrewarmWork(input: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSetSelection;
}): () => Promise<EmailOtpYaoPrewarmOutcome> {
  if (
    input.authMethod.kind !== 'email_otp' ||
    !registrationSelectionRequiresEmailOtpYaoWarmup(input.signerSelection)
  ) {
    return noEmailOtpYaoPrewarm;
  }
  return executeRegistrationEmailOtpYaoPrewarm.bind(undefined, {
    prewarm: input.context.signingEngine.prewarmEmailOtpYao.bind(input.context.signingEngine),
  });
}

function recoverEmailOtpYaoPrewarmFailure(
  _error: unknown,
  startedAt: number,
): EmailOtpYaoPrewarmOutcome {
  const elapsedMs = roundDurationMs(startedAt);
  return {
    kind: 'failed',
    elapsedMs,
    workerPrewarmMs: elapsedMs,
    yaoWasmInitMs: 0,
    failureStage: 'worker_ready',
  };
}

function executeRegistrationEmailOtpYaoPrewarm(input: {
  prewarm: () => Promise<EmailOtpYaoPrewarmOutcome>;
}): Promise<EmailOtpYaoPrewarmOutcome> {
  const startedAt = performance.now();
  return input
    .prewarm()
    .catch((error: unknown) => recoverEmailOtpYaoPrewarmFailure(error, startedAt));
}

function completedRegistrationWarmup(
  results: [WorkerResourceWarmupDiagnostics, EmailOtpYaoPrewarmOutcome],
): RegistrationWarmupOutcome {
  const [diagnostics, emailOtpYao] = results;
  return {
    kind: 'completed',
    diagnostics: {
      ...diagnostics,
      emailOtpWorkerPrewarmMs: emailOtpYao.workerPrewarmMs,
      emailOtpYaoWasmInitMs: emailOtpYao.yaoWasmInitMs,
      emailOtpYaoPrewarm: emailOtpYao,
    },
  };
}

function failedRegistrationWarmup(error: unknown): RegistrationWarmupOutcome {
  return { kind: 'failed', error };
}

function startRegistrationWarmup(input: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSetSelection;
}): Promise<RegistrationWarmupOutcome> {
  const genericWarmup = input.recorder.measure(
    'registrationWarmupMs',
    registrationWarmupWork(input.context),
  );
  const emailOtpYaoWarmup = input.recorder.measure(
    'registrationWarmupEmailOtpYaoWasmInitMs',
    registrationEmailOtpYaoPrewarmWork({
      context: input.context,
      authMethod: input.authMethod,
      signerSelection: input.signerSelection,
    }),
  );
  /* Refactor 94C. ECDSA WASM init pays 654 ms cold on the first ceremony
     call; starting it here lets the authentication prompt absorb it. Not
     awaited by the warmup barrier: the create path still lazily initializes,
     so a failed or slow prewarm changes nothing. */
  if (registrationSelectionIncludesEcdsa(input.signerSelection)) {
    void input.context.signingEngine.prewarmEcdsaRegistrationCrypto?.().catch(() => {});
  }
  return Promise.all([genericWarmup, emailOtpYaoWarmup]).then(
    completedRegistrationWarmup,
    failedRegistrationWarmup,
  );
}

function observeRegistrationWarmup(input: {
  recorder: RegistrationTimingRecorder;
  warmup: Promise<RegistrationWarmupOutcome>;
}): void {
  void input.warmup.then((outcome) => {
    if (outcome.kind === 'completed') input.recorder.captureWarmupDiagnostics(outcome.diagnostics);
  });
}

function registrationPreparationWalletLabel(wallet: RegisterWalletInput): string {
  switch (wallet.kind) {
    case 'provided':
      return String(wallet.walletId);
    case 'server_allocated':
      return 'New wallet';
    default:
      return assertNever(wallet);
  }
}

function registrationPreparationSignerSlot(
  signerSelection: RegistrationSignerSetSelection,
): number {
  const signerPlan = registrationSignerPlanFromSignerSet(signerSelection);
  return findRegistrationSignerPlanNearEd25519Branch(signerPlan)?.signerSlot ?? 1;
}

async function resolvePasskeyRegistrationAuthority(args: {
  context: RegistrationWebContext;
  walletId: WalletId;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  options: RegistrationHooksOptions;
  confirmationConfigOverride: Partial<ConfirmationConfig>;
  passkeyExecution?: RegisterWalletPasskeyExecution;
}): Promise<Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>>> {
  if (args.passkeyExecution?.kind === 'use_hosted_preparation') {
    return await args.passkeyExecution.authority;
  }
  return await collectPasskeyRegistrationAuthority({
    context: args.context,
    walletId: args.walletId,
    signerSlot: args.signerSlot,
    registrationIntentDigestB64u: args.registrationIntentDigestB64u,
    options: args.options,
    confirmationConfigOverride: args.confirmationConfigOverride,
  });
}

function hostedPasskeyRegistrationState(
  prepared: HostedPasskeyRegistrationPrepared,
): HostedPasskeyRegistrationPreparationState {
  if (prepared[hostedPasskeyRegistrationPreparedBrand] !== true) {
    throw new Error('Invalid hosted passkey registration preparation');
  }
  const state = hostedPasskeyRegistrationStates.get(prepared);
  if (!state) throw new Error('Hosted passkey registration preparation is unknown');
  return state;
}

function assertHostedPasskeyRegistrationLive(
  state: HostedPasskeyRegistrationPreparationState,
): void {
  if (state.lifecycle !== 'ready') {
    throw new Error('Hosted passkey registration preparation is no longer usable');
  }
  if (Date.now() >= state.prepared.expiresAtMs) {
    cancelHostedPasskeyRegistration(state.prepared);
    throw new Error('Hosted passkey registration preparation expired');
  }
  if (state.controller.signal.aborted) {
    throw new Error('Hosted passkey registration preparation was cancelled');
  }
  if (
    !webAuthnPromptCoordinator.isLiveReservation({
      reservation: state.prepared.reservation,
      owner: state.prepared.owner,
    })
  ) {
    cancelHostedPasskeyRegistration(state.prepared);
    throw new Error('Hosted passkey registration prompt reservation is no longer active');
  }
}

function hostedPasskeyRegistrationBinding(args: {
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
  walletId: WalletId;
  signerSlot: number;
  rpId: WebAuthnRpId;
  challengeB64u: string;
}): string {
  return alphabetizeStringify({
    wallet: args.wallet,
    signerSelection: args.signerSelection,
    authMethod: args.authMethod,
    walletId: args.walletId,
    signerSlot: args.signerSlot,
    rpId: args.rpId,
    challengeB64u: args.challengeB64u,
  });
}

function hostedPasskeyRegistrationCancellationError(): Error {
  return new Error('Hosted passkey registration preparation was cancelled');
}

function throwIfHostedPasskeyRegistrationCancelled(signal: AbortSignal): void {
  if (signal.aborted) throw hostedPasskeyRegistrationCancellationError();
}

function awaitHostedPasskeyRegistrationStage<T>(args: {
  operation: Promise<T>;
  cancellation: Extract<WebAuthnPromptCancellation, { kind: 'abort_signal' }>;
}): Promise<T> {
  const signal = args.cancellation.signal;
  throwIfHostedPasskeyRegistrationCancelled(signal);
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const onAbort = (): void => {
      rejectOnce(hostedPasskeyRegistrationCancellationError());
    };
    const cleanup = (): void => {
      signal.removeEventListener('abort', onAbort);
    };
    const resolveOnce = (value: T): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const rejectOnce = (error: unknown): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    signal.addEventListener('abort', onAbort, { once: true });
    void args.operation.then(resolveOnce, rejectOnce);
  });
}

export async function prepareHostedPasskeyRegistration(
  args: HostedPasskeyRegistrationPreparationInput,
): Promise<HostedPasskeyRegistrationPrepared> {
  const authMethod = args.authMethod;
  const rpId = requireWebAuthnRpId(String(authMethod.rpId));
  const runtimeRpId = requireWebAuthnRpId(String(args.context.signingEngine.getRpId() || ''));
  if (runtimeRpId !== rpId) {
    throw new Error('Hosted passkey registration rpId does not match the wallet runtime');
  }
  const signerSlot = registrationPreparationSignerSlot(args.signerSelection);
  const expiresInMs = args.expiresInMs ?? 5 * 60 * 1000;
  if (!Number.isSafeInteger(expiresInMs) || expiresInMs <= 0) {
    throw new Error('Hosted passkey registration expiry must be a positive safe integer');
  }
  const expiresAtMs = Date.now() + expiresInMs;
  const owner: HostedAuthMenuRegistrationWebAuthnPromptOwner = {
    kind: 'hosted_auth_menu_registration',
    authMenuSessionId: args.authMenuSessionId,
    requestId: args.requestId,
  };
  const controller = new AbortController();
  let prepared: HostedPasskeyRegistrationPrepared | null = null;
  let reservation: ReservedRegistrationWebAuthnPrompt<HostedAuthMenuRegistrationWebAuthnPromptOwner> | null =
    null;
  const onHostCancellation = (): void => {
    controller.abort();
    if (prepared) cancelHostedPasskeyRegistration(prepared);
  };
  const removeExternalCancellationListener = (): void => {
    args.cancellation.signal.removeEventListener('abort', onHostCancellation);
  };
  throwIfHostedPasskeyRegistrationCancelled(args.cancellation.signal);
  args.cancellation.signal.addEventListener('abort', onHostCancellation, { once: true });
  const recorder = new RegistrationTimingRecorder(performance.now());
  try {
    const setup = await awaitHostedPasskeyRegistrationStage({
      operation: setupThreeRouteRegistration({
        context: args.context,
        authMethod,
        wallet: args.wallet,
        signerSelection: args.signerSelection,
        recorder,
      }),
      cancellation: args.cancellation,
    });
    const intent = requirePasskeyRegistrationIntent(setup.setup.intent);
    if (
      String(intent.authMethod.rpId) !== String(rpId) ||
      alphabetizeStringify(intent.signerSelection) !== alphabetizeStringify(args.signerSelection)
    ) {
      throw new Error('Hosted passkey registration setup changed its authority binding');
    }
    const walletId = walletIdFromString(String(intent.walletId));
    const challengeB64u = String(setup.setup.registrationIntentDigestB64u || '').trim();
    if (!challengeB64u) throw new Error('Hosted passkey registration setup returned no challenge');
    const expectedSignerSlot = registrationPreparationSignerSlot(args.signerSelection);
    if (signerSlot !== expectedSignerSlot) {
      throw new Error('Hosted passkey registration signer slot changed during preparation');
    }
    observeRegistrationWarmup({
      recorder,
      warmup: setup.registrationWarmup,
    });
    if (Date.now() >= expiresAtMs) {
      throw new Error('Hosted passkey registration preparation expired before reservation');
    }
    const acquiredReservation = await webAuthnPromptCoordinator.reserveRegistrationPrompt({
      owner,
      expiresAtMs,
      cancellation: args.cancellation,
    });
    reservation = acquiredReservation;
    const binding = hostedPasskeyRegistrationBinding({
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      authMethod,
      walletId,
      signerSlot,
      rpId,
      challengeB64u,
    });
    const preparedValue: HostedPasskeyRegistrationPrepared = Object.freeze({
      kind: 'hosted_passkey_registration_prepared_v1',
      walletId,
      signerSlot,
      rpId,
      challengeB64u,
      registrationIntentDigestB64u: challengeB64u,
      expiresAtMs,
      owner,
      reservation: acquiredReservation,
      cancellation: {
        kind: 'abort_signal' as const,
        signal: controller.signal,
      },
      [hostedPasskeyRegistrationPreparedBrand]: true as const,
    });
    hostedPasskeyRegistrationStates.set(preparedValue, {
      prepared: preparedValue,
      context: args.context,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      authMethod,
      options: args.options ?? {},
      ...(args.confirmationConfigOverride
        ? { confirmationConfigOverride: args.confirmationConfigOverride }
        : {}),
      setup,
      controller,
      removeExternalCancellationListener,
      binding,
      lifecycle: 'ready',
      authority: null,
      registrationStarted: false,
    });
    prepared = preparedValue;
    return preparedValue;
  } catch (error) {
    controller.abort();
    removeExternalCancellationListener();
    if (prepared) cancelHostedPasskeyRegistration(prepared);
    else if (reservation) webAuthnPromptCoordinator.releaseReservation(reservation);
    throw error;
  }
}

export function cancelHostedPasskeyRegistration(prepared: HostedPasskeyRegistrationPrepared): void {
  const state = hostedPasskeyRegistrationState(prepared);
  if (state.lifecycle === 'finished' || state.lifecycle === 'cancelled') return;
  state.lifecycle = 'cancelled';
  state.controller.abort();
  state.removeExternalCancellationListener?.();
  state.removeExternalCancellationListener = null;
  webAuthnPromptCoordinator.releaseReservation(prepared.reservation);
}

/**
 * Starts WebAuthn synchronously from the caller's wallet-origin activation.
 * The adapter call intentionally occurs before this function awaits anything.
 */
export function startHostedPasskeyRegistrationCredential(
  prepared: HostedPasskeyRegistrationPrepared,
): Promise<RegistrationPasskeyAuthority> {
  const state = hostedPasskeyRegistrationState(prepared);
  assertHostedPasskeyRegistrationLive(state);
  state.lifecycle = 'consuming';
  const credentialPromise = state.context.signingEngine.startPreparedPasskeyRegistrationCredential({
    walletId: String(prepared.walletId),
    signerSlot: prepared.signerSlot,
    challengeB64u: prepared.challengeB64u,
    expectedRpId: String(prepared.rpId),
    reservation: prepared.reservation,
    owner: prepared.owner,
    cancellation: prepared.cancellation,
  });
  const authority = collectPasskeyRegistrationAuthorityFromCredential(credentialPromise);
  state.authority = authority;
  void authority.then(
    () => {
      if (state.lifecycle === 'consuming') state.lifecycle = 'consumed';
    },
    () => {
      cancelHostedPasskeyRegistration(prepared);
    },
  );
  return authority;
}

export async function registerPreparedHostedPasskeyRegistration(args: {
  prepared: HostedPasskeyRegistrationPrepared;
}): Promise<RegistrationResult> {
  const state = hostedPasskeyRegistrationState(args.prepared);
  if ((state.lifecycle !== 'consuming' && state.lifecycle !== 'consumed') || !state.authority) {
    throw new Error('Hosted passkey registration credential must be started by its CTA');
  }
  if (state.registrationStarted) {
    throw new Error('Hosted passkey registration continuation was already consumed');
  }
  state.registrationStarted = true;
  try {
    return await registerWalletInternal({
      context: state.context,
      authMethod: state.authMethod,
      wallet: state.wallet,
      signerSelection: state.signerSelection,
      options: state.options,
      authenticatorOptions: cloneAuthenticatorOptions(
        state.context.configs.webauthn.authenticatorOptions,
      ),
      ...(state.confirmationConfigOverride
        ? { confirmationConfigOverride: state.confirmationConfigOverride }
        : {}),
      passkeyExecution: {
        kind: 'use_hosted_preparation',
        prepared: args.prepared,
        authority: state.authority,
      },
    });
  } finally {
    state.lifecycle = 'finished';
    state.controller.abort();
    state.removeExternalCancellationListener?.();
    state.removeExternalCancellationListener = null;
    webAuthnPromptCoordinator.releaseReservation(args.prepared.reservation);
  }
}

function createSucceededRegistrationTimingSummary(input: {
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

function createFailedRegistrationTimingSummary(input: {
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

function emitRegistrationTimingSummary(summary: RegistrationTimingSummary): void {
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

function registrationRouteHeaders(
  traceContext?: RouterAbTraceContextV1,
): Record<string, string> | undefined {
  const headers: Record<string, string> = {};
  if (isRegistrationBenchmarkDiagnosticsEnabled()) {
    headers['X-Seams-Benchmark-Diagnostics'] = 'registration-flow';
  }
  if (traceContext) headers[ROUTER_AB_TRACE_ID_HEADER_V1] = traceContext.value;
  return Object.keys(headers).length > 0 ? headers : undefined;
}

/**
 * Near-provisioning retries must present the SAME operation identity.
 *
 * The server's Yao consume writes a first-writer consumer binding derived from
 * the request fingerprint, which includes this key. A fresh key per attempt
 * would permanently poison the activation on any ambiguous first attempt —
 * the retry would arrive as a different consumer and hit `activation_consumed`
 * forever. Deriving the key from the ceremony and activation reference makes
 * every retry the same consumer, so takeover resume works instead.
 */
async function deriveNearProvisioningIdempotencyKey(input: {
  readonly registrationCeremonyId: string;
  readonly activationReference: {
    readonly lifecycle_id: string;
    readonly session_id: readonly number[];
  };
}): Promise<RegistrationFinalizeIdempotencyKey> {
  const digestHex = await sha256HexUtf8(
    [
      'wallet-registration-near-provisioning',
      input.registrationCeremonyId,
      input.activationReference.lifecycle_id,
      input.activationReference.session_id
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join(''),
    ].join(':'),
  );
  return registrationFinalizeIdempotencyKeyFromString(
    `wallet-registration-near-provisioning:${digestHex}`,
  );
}

function createRegistrationOperationIdempotencyKey(
  label: string,
): RegistrationFinalizeIdempotencyKey {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi && typeof cryptoApi.randomUUID === 'function') {
    return registrationFinalizeIdempotencyKeyFromString(`${label}:${cryptoApi.randomUUID()}`);
  }
  const bytes = new Uint8Array(16);
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('Secure randomness is required for registration finalization');
  }
  cryptoApi.getRandomValues(bytes);
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return registrationFinalizeIdempotencyKeyFromString(`${label}:${hex}`);
}

function emailOtpBackupAckFromStoredBackup(input: {
  authMethod: RegistrationAuthMethodInput;
  backedUpEnrollment: Awaited<ReturnType<typeof backupEmailOtpRecoveryCodes>>;
}): WalletRegistrationEmailOtpBackupAck {
  const backupAckIdempotencyKey = createRegistrationOperationIdempotencyKey(
    'email-otp-recovery-code-backup-ack',
  );
  const googleOffer =
    input.authMethod.kind === 'email_otp' &&
    input.authMethod.proofKind === 'google_sso_registration'
      ? {
          offerId: input.authMethod.googleEmailOtpRegistrationOfferId,
          candidateId: input.authMethod.googleEmailOtpRegistrationCandidateId,
        }
      : {};
  return {
    kind: 'email_otp_recovery_code_backup_ack_v1',
    ...googleOffer,
    recoveryCodesIssuedAtMs: input.backedUpEnrollment.recoveryCodesIssuedAtMs,
    backupActionKind: 'manual',
    acknowledgedAtMs: Date.now(),
    idempotencyKey: backupAckIdempotencyKey,
  };
}

function googleEmailOtpRegistrationMaterialToBackupEnrollment(input: {
  material: EmailOtpRegistrationEnrollmentMaterial;
  registrationAuthorityId: string;
}): GoogleEmailOtpRegistrationBackupEnrollmentInput {
  const recoveryEscrow =
    input.material.emailOtpEnrollment.recoveryWrappedEnrollmentEscrows[0] &&
    typeof input.material.emailOtpEnrollment.recoveryWrappedEnrollmentEscrows[0] === 'object'
      ? (input.material.emailOtpEnrollment.recoveryWrappedEnrollmentEscrows[0] as Record<
          string,
          unknown
        >)
      : {};
  return {
    thresholdEcdsaClientVerifyingShareB64u:
      input.material.emailOtpEnrollment.thresholdEcdsaClientVerifyingShareB64u,
    recoveryKeys: input.material.recoveryKeys,
    recoveryCodesIssuedAtMs: input.material.recoveryCodesIssuedAtMs,
    registrationAuthorityId: input.registrationAuthorityId,
    otpChannel: EMAIL_OTP_CHANNEL,
    enrollmentId: String(recoveryEscrow.enrollmentId || '').trim(),
    enrollmentSealKeyVersion: input.material.emailOtpEnrollment.enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u: input.material.emailOtpEnrollment.clientUnlockPublicKeyB64u,
    unlockKeyVersion: input.material.emailOtpEnrollment.unlockKeyVersion,
  };
}

function startEmailOtpRecoveryCodeBackup(input: {
  recorder: RegistrationTimingRecorder;
  authMethod: EmailOtpRegistrationAuthMethod;
  relayerUrl: string;
  walletId: string;
  enrollmentMaterial: EmailOtpRegistrationEnrollmentMaterial;
  registrationAuthorityId: string;
}): Promise<EmailOtpRecoveryCodeBackupOutcome> {
  return input.recorder
    .measure('emailOtpRecoveryCodeBackupMs', () =>
      backupEmailOtpRecoveryCodes({
        relayUrl: input.relayerUrl,
        walletId: input.walletId,
        appSessionJwt: input.authMethod.appSessionJwt,
        enrollment: googleEmailOtpRegistrationMaterialToBackupEnrollment({
          material: input.enrollmentMaterial,
          registrationAuthorityId: input.registrationAuthorityId,
        }),
      }),
    )
    .then(
      (backedUpEnrollment) => ({ ok: true as const, backedUpEnrollment }),
      (error: unknown) => ({ ok: false as const, error }),
    );
}

function startEmailOtpRegistrationEnrollmentMaterial(input: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  authMethod: EmailOtpRegistrationAuthMethod;
  relayerUrl: string;
  walletId: string;
  providerSubject: string;
  ed25519YaoFactor:
    | { kind: 'ed25519_yao_factor_requested'; providerSubject: string }
    | { kind: 'ed25519_yao_factor_not_requested'; providerSubject?: never };
  appSessionJwt: string;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  return input.recorder.measure('emailOtpEnrollmentMaterialMs', () =>
    resolveEmailOtpRegistrationEnrollmentMaterial({
      context: input.context,
      authMethod: input.authMethod,
      relayerUrl: input.relayerUrl,
      walletId: input.walletId,
      providerSubject: input.providerSubject,
      ed25519YaoFactor: input.ed25519YaoFactor,
      appSessionJwt: input.appSessionJwt,
    }),
  );
}

async function startEmailOtpRecoveryCodeBackupAfterEnrollmentMaterial(input: {
  recorder: RegistrationTimingRecorder;
  authMethod: EmailOtpRegistrationAuthMethod;
  relayerUrl: string;
  walletId: string;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial>;
  registrationAuthorityId: string;
}): Promise<EmailOtpRecoveryCodeBackupOutcome> {
  try {
    const enrollmentMaterial = await input.enrollmentMaterial;
    return await startEmailOtpRecoveryCodeBackup({
      recorder: input.recorder,
      authMethod: input.authMethod,
      relayerUrl: input.relayerUrl,
      walletId: input.walletId,
      enrollmentMaterial,
      registrationAuthorityId: input.registrationAuthorityId,
    });
  } catch (error: unknown) {
    return { ok: false, error };
  }
}

async function requireEmailOtpRegistrationEnrollmentMaterial(input: {
  material: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  operation: string;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  if (!input.material) {
    throw new Error(`Email OTP registration ${input.operation} is missing enrollment material`);
  }
  return await input.material;
}

function assertEmailOtpRegistrationHasNoLegacyEcdsaRoot(
  material: EmailOtpRegistrationEnrollmentMaterial,
): void {
  if (material.clientRootShareHandle.kind !== 'not_requested') {
    throw new Error('Strict ECDSA registration received obsolete Email OTP root-share material');
  }
}

async function resolveEmailOtpBackupAck(input: {
  authMethod: RegistrationAuthMethodInput;
  backup: Promise<EmailOtpRecoveryCodeBackupOutcome> | null;
}): Promise<WalletRegistrationEmailOtpBackupAck | undefined> {
  if (input.authMethod.kind !== 'email_otp' || !input.backup) return undefined;
  const outcome = await input.backup;
  if (!outcome.ok) throw outcome.error;
  return emailOtpBackupAckFromStoredBackup({
    authMethod: input.authMethod,
    backedUpEnrollment: outcome.backedUpEnrollment,
  });
}

async function resolveEmailOtpRegistrationEnrollmentMaterial(input: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  relayerUrl: string;
  walletId: string;
  providerSubject: string;
  ed25519YaoFactor:
    | { kind: 'ed25519_yao_factor_requested'; providerSubject: string }
    | { kind: 'ed25519_yao_factor_not_requested'; providerSubject?: never };
  appSessionJwt: string;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  if (input.authMethod.kind !== 'email_otp') {
    throw new Error('Email OTP enrollment material requires Email OTP auth');
  }
  const material =
    await input.context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
      relayUrl: input.relayerUrl,
      walletId: toWalletId(input.walletId),
      userId: input.providerSubject,
      appSessionJwt: input.appSessionJwt,
      ed25519YaoFactor: input.ed25519YaoFactor,
    });
  assertEmailOtpRegistrationHasNoLegacyEcdsaRoot(material);
  return material;
}

export function createRegistrationLifecycleEvent(input: {
  accountId: string;
  event: EmitRegistrationEventInput;
}): RegistrationFlowEvent {
  const authMethod = input.event.authMethod;
  const accountId = registrationEventAccountId(input.accountId);
  return createRegistrationFlowEvent({
    ...input.event,
    flowId: `registration:${authMethod}:${accountId}`,
    accountId,
    authMethod,
  });
}

function registrationEventAccountId(value: string): string {
  const accountId = String(value || '').trim();
  if (!accountId) {
    throw new Error('Registration event account id is required');
  }
  return accountId;
}

function registrationErrorCodeFromUnknown(error: unknown): string {
  return isObject(error) && 'code' in error ? String(error.code || '').trim() : '';
}

function registrationErrorWithCode(message: string, errorCode: string): Error & { code?: string } {
  return Object.assign(new Error(message), errorCode ? { code: errorCode } : {});
}

function alreadyFinalizedRestoreRequiredResult(_walletId: string): RegistrationResult {
  return {
    success: false,
    error: 'Wallet registration was already finalized. Restore or unlock the wallet to continue.',
    errorCode: 'already_finalized_restore_required',
  };
}

function webAuthnTransportsFromRaw(value: unknown): AuthenticatorTransport[] {
  if (!Array.isArray(value)) return [];
  return value.filter((transport): transport is AuthenticatorTransport => {
    switch (transport) {
      case 'ble':
      case 'hybrid':
      case 'internal':
      case 'nfc':
      case 'smart-card':
      case 'usb':
        return true;
      default:
        return false;
    }
  });
}

function requireFinalizedPasskeyCredentialPublicKeyB64u(args: {
  finalized: WalletRegistrationFinalizeResponse;
  credential: WebAuthnRegistrationCredential;
}): string {
  const authMethod = args.finalized.authMethod;
  if (!authMethod || authMethod.kind !== 'passkey') {
    throw new Error('Passkey registration finalize returned non-passkey auth material');
  }
  const localCredentialId = String(args.credential.rawId || args.credential.id || '').trim();
  const returnedCredentialId = String(authMethod.credentialIdB64u || '').trim();
  if (!localCredentialId || returnedCredentialId !== localCredentialId) {
    throw new Error('Passkey registration finalize returned credential id mismatch');
  }
  const credentialPublicKeyB64u = String(authMethod.credentialPublicKeyB64u || '').trim();
  if (!credentialPublicKeyB64u) {
    throw new Error('Passkey registration finalize returned missing credentialPublicKeyB64u');
  }
  return credentialPublicKeyB64u;
}

function emitRegistrationEvent(
  onEvent: RegistrationHooksOptions['onEvent'] | undefined,
  accountId: string,
  event: EmitRegistrationEventInput,
): void {
  onEvent?.(createRegistrationLifecycleEvent({ accountId, event }));
}

async function emailOtpEmailHashHex(email: string): Promise<string> {
  const normalizedEmail = String(email || '')
    .trim()
    .toLowerCase();
  if (!normalizedEmail) {
    throw new Error('Email OTP registration auth context requires email');
  }
  return sha256HexUtf8(normalizedEmail);
}

function emailOtpProviderFromRegistrationProof(proof: EmailOtpRegistrationProof): EmailOtpProvider {
  switch (proof.proofKind) {
    case 'otp_challenge':
      return 'email';
    case 'google_sso_registration':
      return 'google';
    default:
      return assertNever(proof);
  }
}

async function buildRegistrationEmailOtpAuthContext(args: {
  configs: SeamsConfigsReadonly;
  walletId: WalletId;
  email: string;
  provider: EmailOtpProvider;
  providerSubject: string;
}): Promise<ThresholdEcdsaEmailOtpAuthContext> {
  const policy = args.configs.signing.emailOtp.authPolicy;
  const providerUserId = String(args.providerSubject || '').trim();
  if (!providerUserId) {
    throw new Error('Email OTP registration auth context requires providerSubject');
  }
  return buildEmailOtpAuthContextForWalletAuthMethod({
    policy,
    walletId: args.walletId,
    emailHashHex: await emailOtpEmailHashHex(args.email),
    retention: 'session',
    reason: 'login',
    provider: args.provider,
    providerUserId,
  });
}

type RegistrationPersistenceAuth =
  | {
      kind: 'passkey';
      rpId: string;
      credential: WebAuthnRegistrationCredential;
      credentialPublicKeyB64u: string;
      passkeyPrfFirstB64u: string;
      email?: never;
      registrationAuthorityId?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      registrationAuthorityId: string;
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      rpId?: never;
      credential?: never;
      credentialPublicKeyB64u?: never;
    };

function registrationPersistenceAuthMethod(
  auth: RegistrationPersistenceAuth,
): RegistrationAuthMethodInput['kind'] {
  switch (auth.kind) {
    case 'passkey':
      return 'passkey';
    case 'email_otp':
      return 'email_otp';
    default:
      return assertNever(auth);
  }
}

type RegistrationEcdsaSession = {
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  authority: FinalizeRouterAbEcdsaRegistrationActivationResultV1['authority'];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  /** Canonical threshold identity returned by the activated server bootstrap. */
  activatedThresholdSessionId: string;
  roleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
  materialActivation: FinalizeRouterAbEcdsaRegistrationActivationResultV1['materialActivation'];
  clientPublicFacts: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicFacts'];
  publicCapability: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicCapability'];
  registrationEstablishedSession: RegistrationEstablishedSession;
};

type PendingRegistrationEcdsaLocalFinalization = {
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  activatedThresholdSessionId: string;
  journalId: CorrelationId;
  activationReceipt: FinalizeRouterAbEcdsaRegistrationActivationRequestV1['activationReceipt'];
};

type RegistrationPersistenceEcdsa = {
  kind: 'evm_family_ecdsa';
  session: RegistrationEcdsaSession;
  walletKeys: readonly [WalletRegistrationEcdsaWalletKey, ...WalletRegistrationEcdsaWalletKey[]];
  expectedChainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
};

type RegistrationPersistencePlan = {
  kind: 'registration_persistence_plan_v1';
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
  ecdsa: RegistrationPersistenceEcdsa;
};

type RegistrationLocalEcdsaWalletKeys = Awaited<
  ReturnType<RegistrationSigningSurface['finalizeWalletRegistrationEcdsaSessions']>
>;

type RegistrationPasskeyEcdsaWarmSession = {
  readonly transport: {
    readonly curve: 'ecdsa';
    readonly authMethod: 'passkey';
    readonly walletId: string;
    readonly chainTarget: ThresholdEcdsaChainTarget;
    readonly relayerUrl: string;
    readonly walletSessionJwt: string;
    readonly ecdsaRestore: Exclude<
      SealedSigningSessionEcdsaRestoreMetadata,
      { source: 'email_otp' }
    >;
  };
};

async function buildRegistrationPersistenceAuth(args: {
  authMethod: RegistrationAuthMethodInput;
  configs: SeamsConfigsReadonly;
  walletId: WalletId;
  finalized: WalletRegistrationFinalizeResponse;
  passkeyAuthority: RegistrationPasskeyAuthority | null;
  email: string;
  providerSubject: string;
  registrationAuthorityId: string;
}): Promise<RegistrationPersistenceAuth> {
  switch (args.authMethod.kind) {
    case 'passkey': {
      if (!args.passkeyAuthority) {
        throw new Error('Passkey registration authority was not collected');
      }
      return {
        kind: 'passkey',
        rpId: args.authMethod.rpId,
        credential: args.passkeyAuthority.credential,
        credentialPublicKeyB64u: requireFinalizedPasskeyCredentialPublicKeyB64u({
          finalized: args.finalized,
          credential: args.passkeyAuthority.credential,
        }),
        passkeyPrfFirstB64u: args.passkeyAuthority.prfFirstB64u,
      };
    }
    case 'email_otp': {
      const email = String(args.email || '').trim();
      const providerSubject = String(args.providerSubject || '').trim();
      const registrationAuthorityId = String(args.registrationAuthorityId || '').trim();
      if (!email || !providerSubject || !registrationAuthorityId) {
        throw new Error('Email OTP registration persistence requires provider identity');
      }
      if (!isEmailOtpWalletAuthAuthority(args.finalized.authority)) {
        throw new Error('Email OTP registration finalize returned a different authority');
      }
      return {
        kind: 'email_otp',
        email,
        registrationAuthorityId,
        emailOtpAuthContext: await buildRegistrationEmailOtpAuthContext({
          configs: args.configs,
          walletId: args.walletId,
          email,
          provider: args.finalized.authority.factor.provider,
          providerSubject,
        }),
      };
    }
    default:
      return assertNever(args.authMethod);
  }
}

function assertSharedRegistrationEvmFamilyWalletKeyMaterial(
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[],
): void {
  const first = walletKeys[0];
  if (!first) return;
  for (const walletKey of walletKeys.slice(1)) {
    const mismatch = firstRegistrationEvmFamilyWalletKeyMaterialMismatch(first, walletKey);
    if (mismatch) {
      throw new Error(
        `ECDSA registration returned partitioned EVM-family wallet key material: ${mismatch}`,
      );
    }
  }
}

function assertRegistrationWalletKeyCapabilities(args: {
  readonly session: RegistrationEcdsaSession;
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
}): void {
  const expected = alphabetizeStringify(args.session.publicCapability);
  for (const walletKey of args.walletKeys) {
    if (alphabetizeStringify(walletKey.publicCapability) !== expected) {
      throw new Error(
        'ECDSA registration wallet key public capability does not match client-verified activation',
      );
    }
  }
}

function registrationParticipantIdsMatch(
  left: readonly number[],
  right: readonly number[],
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function firstRegistrationEvmFamilyWalletKeyMaterialMismatch(
  left: WalletRegistrationEcdsaWalletKey,
  right: WalletRegistrationEcdsaWalletKey,
): string | null {
  if (left.keyScope !== 'evm-family' || right.keyScope !== 'evm-family') return 'keyScope';
  if (left.walletId !== right.walletId) return 'walletId';
  if (left.evmFamilySigningKeySlotId !== right.evmFamilySigningKeySlotId)
    return 'evmFamilySigningKeySlotId';
  if (left.keyHandle !== right.keyHandle) return 'keyHandle';
  if (left.ecdsaThresholdKeyId !== right.ecdsaThresholdKeyId) return 'ecdsaThresholdKeyId';
  if (left.signingRootId !== right.signingRootId) return 'signingRootId';
  if (left.signingRootVersion !== right.signingRootVersion) return 'signingRootVersion';
  if (left.thresholdEcdsaPublicKeyB64u !== right.thresholdEcdsaPublicKeyB64u)
    return 'thresholdEcdsaPublicKeyB64u';
  if (
    left.thresholdOwnerAddress.trim().toLowerCase() !==
    right.thresholdOwnerAddress.trim().toLowerCase()
  )
    return 'thresholdOwnerAddress';
  if (left.relayerKeyId !== right.relayerKeyId) return 'relayerKeyId';
  if (left.relayerVerifyingShareB64u !== right.relayerVerifyingShareB64u)
    return 'relayerVerifyingShareB64u';
  if (left.participantIds.join(',') !== right.participantIds.join(',')) return 'participantIds';
  return null;
}

function buildRegistrationPersistenceEcdsa(args: {
  session: RegistrationEcdsaSession;
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  expectedChainTargets: readonly ThresholdEcdsaChainTarget[];
}): RegistrationPersistenceEcdsa {
  const [firstWalletKey, ...remainingWalletKeys] = args.walletKeys;
  const [firstTarget, ...remainingTargets] = args.expectedChainTargets;
  if (!firstWalletKey || !firstTarget) {
    throw new Error('ECDSA registration persistence requires session, key, and target material');
  }
  if (args.walletKeys.length !== args.expectedChainTargets.length) {
    throw new Error(
      'ECDSA registration persistence requires one family session projected to every target',
    );
  }
  if (
    args.session.chainTargets.length !== args.expectedChainTargets.length ||
    !registrationChainTargetListsMatch(args.session.chainTargets, args.expectedChainTargets)
  ) {
    throw new Error('ECDSA registration family session target projection is incomplete');
  }
  assertSharedRegistrationEvmFamilyWalletKeyMaterial(args.walletKeys);
  assertRegistrationWalletKeyCapabilities({
    session: args.session,
    walletKeys: args.walletKeys,
  });
  assertRegistrationEcdsaSessionMatchesWalletKeys({
    session: args.session,
    walletKeys: args.walletKeys,
  });
  return {
    kind: 'evm_family_ecdsa',
    session: args.session,
    walletKeys: [firstWalletKey, ...remainingWalletKeys],
    expectedChainTargets: [firstTarget, ...remainingTargets],
  };
}

function registrationChainTargetListsMatch(
  left: readonly ThresholdEcdsaChainTarget[],
  right: readonly ThresholdEcdsaChainTarget[],
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    const leftTarget = left[index];
    const rightTarget = right[index];
    if (!leftTarget || !rightTarget) return false;
    if (thresholdEcdsaChainTargetKey(leftTarget) !== thresholdEcdsaChainTargetKey(rightTarget)) {
      return false;
    }
  }
  return true;
}

async function closeStrictEcdsaRegistrationCeremony(args: {
  context: RegistrationWebContext;
  ceremonyId: string;
}): Promise<void> {
  try {
    await args.context.signingEngine.closeRouterAbEcdsaRegistrationCeremony({
      kind: 'close_router_ab_ecdsa_registration_ceremony_v1',
      ceremonyId: args.ceremonyId,
    });
  } catch {
    return;
  }
}

function buildStrictRegistrationClientBootstrap(args: {
  prepare: WalletRegistrationEcdsaPreparePayload['prepare'];
  verified: Awaited<
    ReturnType<
      RegistrationWebContext['signingEngine']['verifyRouterAbEcdsaRegistrationClientProofs']
    >
  >['clientBootstrap'];
}): WalletRegistrationEcdsaClientBootstrap {
  const prepare = args.prepare;
  return {
    formatVersion: prepare.formatVersion,
    walletId: prepare.walletId,
    evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
    keyScope: prepare.keyScope,
    relayerKeyId: prepare.relayerKeyId,
    registrationPreparationId: prepare.registrationPreparationId,
    requestId: prepare.requestId,
    thresholdSessionId: prepare.thresholdSessionId,
    ttlMs: prepare.ttlMs,
    remainingUses: prepare.remainingUses,
    participantIds: [...prepare.participantIds],
    runtimePolicyScope: prepare.runtimePolicyScope,
    derivationClientSharePublicKey33B64u: args.verified.derivationClientSharePublicKey33B64u,
    clientShareRetryCounter: args.verified.clientShareRetryCounter,
    contextBinding32B64u: args.verified.contextBinding32B64u,
  };
}

type StrictEcdsaFamilyCeremonyRoute =
  | {
      kind: 'registration';
      registrationCeremonyId: string;
      walletId?: never;
      addSignerCeremonyId?: never;
    }
  | {
      kind: 'add_signer';
      walletId: WalletId;
      addSignerCeremonyId: string;
      registrationCeremonyId?: never;
    };

function strictEcdsaFamilyCeremonyId(route: StrictEcdsaFamilyCeremonyRoute): string {
  switch (route.kind) {
    case 'registration':
      return route.registrationCeremonyId;
    case 'add_signer':
      return route.addSignerCeremonyId;
    default:
      return assertNever(route);
  }
}

async function forwardStrictEcdsaFamilyRegistration(args: {
  relayerUrl: string;
  route: StrictEcdsaFamilyCeremonyRoute;
  traceContext?: RouterAbTraceContextV1;
  strictRegistration: Awaited<
    ReturnType<RegistrationWebContext['signingEngine']['createRouterAbEcdsaRegistrationCeremony']>
  >['registrationRequest'];
  onServerTiming?: (header: string | null) => void;
}) {
  switch (args.route.kind) {
    case 'registration':
      return await respondWalletRegistrationEcdsa({
        relayerUrl: args.relayerUrl,
        headers: registrationRouteHeaders(args.traceContext),
        registrationCeremonyId: args.route.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: args.strictRegistration,
        },
        ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
      });
    case 'add_signer':
      return await respondWalletAddSignerEcdsa({
        relayerUrl: args.relayerUrl,
        walletId: args.route.walletId,
        addSignerCeremonyId: args.route.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: args.strictRegistration,
        },
      });
    default:
      return assertNever(args.route);
  }
}

async function prepareStrictEcdsaFamilyActivation(args: {
  relayerUrl: string;
  route: StrictEcdsaFamilyCeremonyRoute;
  activationCorrelationId: CorrelationId;
  traceContext?: RouterAbTraceContextV1;
  publicFacts: Parameters<typeof activateWalletRegistrationEcdsa>[0]['publicFacts'];
  onServerTiming?: (header: string | null) => void;
}) {
  switch (args.route.kind) {
    case 'registration':
      return (
        await prepareWalletRegistrationEcdsaActivation({
          relayerUrl: args.relayerUrl,
          headers: registrationRouteHeaders(args.traceContext),
          registrationCeremonyId: args.route.registrationCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
          ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
        })
      ).ecdsa.preparation;
    case 'add_signer':
      return (
        await prepareWalletAddSignerEcdsaActivation({
          relayerUrl: args.relayerUrl,
          walletId: args.route.walletId,
          addSignerCeremonyId: args.route.addSignerCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
        })
      ).ecdsa.preparation;
    default:
      return assertNever(args.route);
  }
}

type StrictEcdsaActivationCommitInput = {
  route: StrictEcdsaFamilyCeremonyRoute;
  activationCorrelationId: CorrelationId;
  publicFacts: Parameters<typeof activateWalletRegistrationEcdsa>[0]['publicFacts'];
  expectedActivationRequestDigest: Parameters<
    typeof activateWalletRegistrationEcdsa
  >[0]['expectedActivationRequestDigest'];
};

function canonicalStrictEcdsaFamilyActivationRequest(input: StrictEcdsaActivationCommitInput) {
  switch (input.route.kind) {
    case 'registration':
      return canonicalWalletRegistrationEcdsaActivationCommitRequest({
        registrationCeremonyId: input.route.registrationCeremonyId,
        activationCorrelationId: input.activationCorrelationId,
        publicFacts: input.publicFacts,
        expectedActivationRequestDigest: input.expectedActivationRequestDigest,
      });
    case 'add_signer':
      return canonicalWalletAddSignerEcdsaActivationCommitRequest({
        addSignerCeremonyId: input.route.addSignerCeremonyId,
        activationCorrelationId: input.activationCorrelationId,
        publicFacts: input.publicFacts,
        expectedActivationRequestDigest: input.expectedActivationRequestDigest,
      });
    default:
      return assertNever(input.route);
  }
}

async function activateStrictEcdsaFamilyRegistration(
  args: StrictEcdsaActivationCommitInput & {
    materialActivation: RouterAbMpcMaterialActivationRefWire;
    relayerUrl: string;
    traceContext?: RouterAbTraceContextV1;
    onServerTiming?: (header: string | null) => void;
  },
) {
  switch (args.route.kind) {
    case 'registration':
      return await activateWalletRegistrationEcdsa({
        relayerUrl: args.relayerUrl,
        headers: registrationRouteHeaders(args.traceContext),
        registrationCeremonyId: args.route.registrationCeremonyId,
        activationCorrelationId: args.activationCorrelationId,
        publicFacts: args.publicFacts,
        expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        materialActivation: args.materialActivation,
        ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
      });
    case 'add_signer':
      return await activateWalletAddSignerEcdsa({
        relayerUrl: args.relayerUrl,
        walletId: args.route.walletId,
        addSignerCeremonyId: args.route.addSignerCeremonyId,
        activationCorrelationId: args.activationCorrelationId,
        publicFacts: args.publicFacts,
        expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        materialActivation: args.materialActivation,
      });
    default:
      return assertNever(args.route);
  }
}

async function queryStrictEcdsaFamilyActivation(
  args: StrictEcdsaActivationCommitInput & {
    relayerUrl: string;
    traceContext?: RouterAbTraceContextV1;
  },
) {
  switch (args.route.kind) {
    case 'registration':
      return (
        await queryWalletRegistrationEcdsaActivation({
          relayerUrl: args.relayerUrl,
          headers: registrationRouteHeaders(args.traceContext),
          registrationCeremonyId: args.route.registrationCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
          expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        })
      ).ecdsa.result;
    case 'add_signer':
      return (
        await queryWalletAddSignerEcdsaActivation({
          relayerUrl: args.relayerUrl,
          walletId: args.route.walletId,
          addSignerCeremonyId: args.route.addSignerCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
          expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        })
      ).ecdsa.result;
    default:
      return assertNever(args.route);
  }
}

function assertActivationQueryCoordinates(
  result: Extract<
    Awaited<ReturnType<typeof queryStrictEcdsaFamilyActivation>>,
    { readonly kind: 'not_committed' }
  >,
  input: StrictEcdsaActivationCommitInput,
): void {
  if (
    result.activation_correlation_id !== input.activationCorrelationId ||
    alphabetizeStringify(result.activation_request_digest) !==
      alphabetizeStringify(input.expectedActivationRequestDigest)
  ) {
    throw new Error('ECDSA activation query changed the prepared activation coordinates');
  }
}

async function activateStrictEcdsaFamilyRegistrationWithReconciliation(
  args: StrictEcdsaActivationCommitInput & {
    materialActivation: RouterAbMpcMaterialActivationRefWire;
    relayerUrl: string;
    traceContext?: RouterAbTraceContextV1;
    onServerTiming?: (header: string | null) => void;
  },
) {
  try {
    return await activateStrictEcdsaFamilyRegistration(args);
  } catch {
    const queried = await queryStrictEcdsaFamilyActivation(args);
    switch (queried.kind) {
      case 'committed': {
        const replayed = await activateStrictEcdsaFamilyRegistration(args);
        if (
          alphabetizeStringify(replayed.ecdsa.activation) !== alphabetizeStringify(queried.receipt)
        ) {
          throw new Error('ECDSA activation replay changed the committed receipt');
        }
        return replayed;
      }
      case 'not_committed':
        assertActivationQueryCoordinates(queried, args);
        return await activateStrictEcdsaFamilyRegistration(args);
      case 'correlation_conflict':
        throw new Error('ECDSA activation query reported a correlation conflict');
      default:
        return assertNever(queried);
    }
  }
}

type StrictEcdsaCeremonyTimingBucket =
  | 'ecdsaRegistrationClientCreateMs'
  | 'ecdsaRegistrationGatewayRespondMs'
  | 'ecdsaRegistrationClientProofVerifyMs'
  | 'ecdsaRegistrationGatewayActivateMs'
  | 'ecdsaRegistrationClientActivationFinalizeMs';

async function measureStrictEcdsaCeremonyStep<T>(args: {
  registrationTiming: RegistrationTimingRecorder | null;
  bucket: StrictEcdsaCeremonyTimingBucket;
  operation: () => Promise<T>;
}): Promise<T> {
  if (!args.registrationTiming) return await args.operation();
  return await args.registrationTiming.measure(args.bucket, args.operation);
}

async function runStrictEcdsaFamilyCeremony(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  route: StrictEcdsaFamilyCeremonyRoute;
  traceContext?: RouterAbTraceContextV1;
  started: WalletRegistrationEcdsaPreparePayload;
  authority: WalletAuthAuthorityRef;
  registrationTiming: RegistrationTimingRecorder | null;
}): Promise<PendingRegistrationEcdsaLocalFinalization> {
  const [firstChainTarget, ...remainingChainTargets] = args.started.chainTargets;
  if (!firstChainTarget) {
    throw new Error('Strict ECDSA ceremony requires at least one EVM-family target');
  }
  const ceremonyId = strictEcdsaFamilyCeremonyId(args.route);
  const activationCorrelationId = parseCorrelationId(ceremonyId);
  try {
    const created = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientCreateMs',
      operation: args.context.signingEngine.createRouterAbEcdsaRegistrationCeremony.bind(
        args.context.signingEngine,
        {
          kind: 'create_router_ab_ecdsa_registration_ceremony_v1',
          ceremonyId,
          registration: args.started.strictRegistration,
        },
      ),
    });
    const forwarded = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayRespondMs',
      operation: forwardStrictEcdsaFamilyRegistration.bind(undefined, {
        relayerUrl: args.relayerUrl,
        route: args.route,
        traceContext: args.traceContext,
        strictRegistration: created.registrationRequest,
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'respond', header),
      }),
    });
    const verified = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientProofVerifyMs',
      operation: args.context.signingEngine.verifyRouterAbEcdsaRegistrationClientProofs.bind(
        args.context.signingEngine,
        {
          kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1',
          ceremonyId,
          clientProofFinalization: {
            kind: 'finalize_encrypted_client_proof_bundles_v1',
            bundles: forwarded.ecdsa.strictResult.response.bundles,
          },
        },
      ),
    });
    const activationPreparation = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayActivateMs',
      operation: prepareStrictEcdsaFamilyActivation.bind(undefined, {
        relayerUrl: args.relayerUrl,
        route: args.route,
        activationCorrelationId,
        traceContext: args.traceContext,
        publicFacts: verified.publicFacts,
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'activate', header),
      }),
    });
    const expectedActivationRequestDigest = activationPreparation.activation_request_digest;
    const canonicalRequest = canonicalStrictEcdsaFamilyActivationRequest({
      route: args.route,
      activationCorrelationId,
      publicFacts: verified.publicFacts,
      expectedActivationRequestDigest,
    });
    const persisted = await args.context.signingEngine.persistInitialCanonicalEcdsaActivation({
      kind: 'persist_initial_canonical_ecdsa_activation_v1',
      ceremonyId,
      planInput: {
        authority: args.authority,
        targetMemberships: [firstChainTarget, ...remainingChainTargets],
        evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
          args.started.prepare.evmFamilySigningKeySlotId,
          'registration ECDSA signing key slot',
        ),
        ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(args.started.prepare.ecdsaThresholdKeyId),
        signingRootId: parseSdkEcdsaDerivationSigningRootId(args.started.prepare.signingRootId),
        signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
          args.started.prepare.signingRootVersion,
        ),
        runtimePolicyScope: args.started.prepare.runtimePolicyScope,
        clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
          verified.publicFacts.derivationClientSharePublicKey33B64u,
        ),
        participantIds: [
          toParticipantId(args.started.prepare.participantIds[0]),
          toParticipantId(args.started.prepare.participantIds[1]),
        ],
        relayerKeyId: parseEcdsaRelayerKeyId(args.started.prepare.relayerKeyId),
        bindingDigest: parseEcdsaRoleLocalBindingDigest(verified.publicFacts.contextBinding32B64u),
        journalId: activationCorrelationId,
        requestDigest: parseDigestB64u(
          base64UrlEncode(Uint8Array.from(expectedActivationRequestDigest.bytes)),
        ),
        canonicalRequest,
        createdAt: parseIsoTimestamp(new Date().toISOString()),
      },
    });
    if (!persisted.ok) {
      throw new Error(
        `Canonical ECDSA activation persistence failed (${persisted.code}): ${persisted.message}`,
      );
    }
    const activated = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayActivateMs',
      operation: activateStrictEcdsaFamilyRegistrationWithReconciliation.bind(undefined, {
        relayerUrl: args.relayerUrl,
        route: args.route,
        traceContext: args.traceContext,
        activationCorrelationId,
        materialActivation: persisted.materialActivation,
        publicFacts: verified.publicFacts,
        expectedActivationRequestDigest,
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'activate', header),
      }),
    });
    const clientBootstrap = buildStrictRegistrationClientBootstrap({
      prepare: args.started.prepare,
      verified: verified.clientBootstrap,
    });
    const bootstrap = parseWalletRegistrationEcdsaDerivationRespond({
      clientBootstrap,
      serverBootstrap: activated.ecdsa.bootstrap,
      activationEpoch: activated.ecdsa.activation.ecdsa_activation.activation_epoch,
    });
    return {
      chainTargets: [firstChainTarget, ...remainingChainTargets],
      clientBootstrap,
      bootstrap,
      activatedThresholdSessionId: activated.ecdsa.bootstrap.thresholdSessionId,
      journalId: persisted.journalId,
      activationReceipt: activated.ecdsa.activation,
    };
  } catch (error: unknown) {
    await closeStrictEcdsaRegistrationCeremony({
      context: args.context,
      ceremonyId,
    });
    throw error;
  }
}

async function finalizeStrictEcdsaFamilyLocalActivation(args: {
  context: RegistrationWebContext;
  pending: PendingRegistrationEcdsaLocalFinalization;
}): Promise<Omit<RegistrationEcdsaSession, 'registrationEstablishedSession'>> {
  const finalized = await args.context.signingEngine.finalizeRouterAbEcdsaRegistrationActivation({
    kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
    journalId: args.pending.journalId,
    activationReceipt: args.pending.activationReceipt,
    routerAbEcdsaDerivationNormalSigning:
      args.pending.bootstrap.routerAbEcdsaDerivationNormalSigning,
  });
  return {
    chainTargets: args.pending.chainTargets,
    authority: finalized.authority,
    clientBootstrap: args.pending.clientBootstrap,
    bootstrap: args.pending.bootstrap,
    activatedThresholdSessionId: args.pending.activatedThresholdSessionId,
    roleLocalMaterial: finalized.roleLocalMaterial,
    materialActivation: finalized.materialActivation,
    clientPublicFacts: finalized.publicFacts,
    publicCapability: finalized.publicCapability,
  };
}

/**
 * Refactor 94C. The registration ceremony over the three routes.
 *
 * Linear and registration-specific on purpose. Add-signer keeps the shared
 * `runStrictEcdsaFamilyCeremony`, which still has its own respond, activate,
 * and finalize legs; forcing both through one function is what made the shared
 * version hard to follow, and add-signer's semantics are not changing here.
 *
 * The ordering that matters: deferred NEAR work is handed to the caller as
 * soon as respond returns it, *before* activate runs, so Yao proceeds
 * alongside the rest of registration instead of behind it. Nothing here awaits
 * it — the wallet is usable on ECDSA alone, and the caller decides what to do
 * with the handle.
 */
type RegistrationThreeRouteAuthority =
  | { kind: 'passkey'; webauthnRegistration: unknown }
  | { kind: 'email_otp'; emailOtpRegistrationProof: EmailOtpRegistrationProof };

async function buildThreeRouteCanonicalActivationCommand(args: {
  registrationCeremonyId: string;
  activationCorrelationId: CorrelationId;
  idempotencyKey: string;
  publicFacts: Parameters<typeof activateWalletRegistrationEcdsa>[0]['publicFacts'];
}) {
  const canonicalRequest = parseCanonicalEcdsaServerActivationRequest(
    alphabetizeStringify({
      operation: 'wallet_registration_activate_v2',
      registrationCeremonyId: args.registrationCeremonyId,
      activationCorrelationId: args.activationCorrelationId,
      idempotencyKey: args.idempotencyKey,
      publicFacts: args.publicFacts,
    }),
  );
  return {
    canonicalRequest,
    requestDigest: parseDigestB64u(
      base64UrlEncode(await sha256BytesUtf8(String(canonicalRequest))),
    ),
  };
}

/**
 * Refactor 94C. Calls `/wallets/register/setup`, which replaces the bootstrap
 * grant, the registration intent, and registration start.
 *
 * Runs before the authenticator prompt, because its response carries the
 * challenge that prompt must sign — so the Router's ECDSA preparation overlaps
 * the user's interaction instead of being serialized after it.
 */
async function setupThreeRouteRegistration(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  recorder: RegistrationTimingRecorder;
}): Promise<{
  relayerUrl: string;
  setup: Extract<WalletRegistrationSetupResponseV2, { ok: true }>;
  registrationWarmup: Promise<RegistrationWarmupOutcome>;
}> {
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) throw new Error('registerWallet requires relayer.url');
  const registration = args.context.configs.registration;
  const publishableKey = String(registration?.publishableKey || '').trim();
  const environmentId = String(registration?.projectEnvironmentId || '').trim();
  if (!publishableKey || !environmentId) {
    throw new Error(
      'registerWallet requires registration.publishableKey and registration.projectEnvironmentId',
    );
  }
  const registrationWarmup = startRegistrationWarmup({
    recorder: args.recorder,
    context: args.context,
    authMethod: args.authMethod,
    signerSelection: args.signerSelection,
  });
  const setup = await args.recorder.measure('registrationIntentMs', () =>
    setupWalletRegistration({
      relayerUrl,
      request: {
        ...(args.wallet.kind === 'provided' ? { wallet: args.wallet } : {}),
        signerSelection: args.signerSelection,
        authMethod: args.authMethod,
      },
      auth: { publishableKey, environmentId },
    }),
  );
  if (!setup.ok) {
    throw registrationErrorWithCode(setup.message, setup.code);
  }
  return { relayerUrl, setup, registrationWarmup };
}

async function setupRegistrationForPasskeyExecution(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  recorder: RegistrationTimingRecorder;
  passkeyExecution: RegisterWalletPasskeyExecution;
}): Promise<Awaited<ReturnType<typeof setupThreeRouteRegistration>>> {
  if (args.passkeyExecution.kind === 'collect_during_registration') {
    return await setupThreeRouteRegistration({
      context: args.context,
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      recorder: args.recorder,
    });
  }
  if (args.authMethod.kind !== 'passkey') {
    throw new Error('Hosted passkey preparation requires passkey registration');
  }
  const state = hostedPasskeyRegistrationState(args.passkeyExecution.prepared);
  if (state.context !== args.context || state.lifecycle === 'cancelled') {
    throw new Error('Hosted passkey registration preparation belongs to a different operation');
  }
  const setup = state.setup;
  const intent = requirePasskeyRegistrationIntent(setup.setup.intent);
  const challengeB64u = String(setup.setup.registrationIntentDigestB64u || '').trim();
  const signerSlot = registrationPreparationSignerSlot(args.signerSelection);
  const binding = hostedPasskeyRegistrationBinding({
    wallet: args.wallet,
    signerSelection: args.signerSelection,
    authMethod: args.authMethod,
    walletId: walletIdFromString(String(intent.walletId)),
    signerSlot,
    rpId: requireWebAuthnRpId(String(args.authMethod.rpId)),
    challengeB64u,
  });
  if (
    binding !== state.binding ||
    String(intent.walletId) !== String(args.passkeyExecution.prepared.walletId) ||
    challengeB64u !== args.passkeyExecution.prepared.challengeB64u
  ) {
    throw new Error('Hosted passkey registration preparation binding changed');
  }
  return setup;
}

/* Exported for tests: the ordering guarantee below (deferred NEAR handed off
   before activate, never awaited) is the ceremony's contract, and it is only
   observable by driving the ceremony itself. */
export async function runEcdsaEnabledThreeRouteRegistrationCeremony(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationCeremonyId: string;
  signerPlanKind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa';
  signedSetup: string;
  ecdsaPrepare: WalletRegistrationEcdsaPreparePayload;
  authority: RegistrationThreeRouteAuthority;
  materialAuthority: WalletAuthAuthorityRef;
  idempotencyKey: string;
  /**
   * Resolved just before activate rather than before respond: this material is
   * only needed by activate, and awaiting it earlier would serialize it ahead
   * of the Router legs it can overlap.
   */
  resolveActivateEmailOtp: () => Promise<{
    enrollment: WalletRegistrationEmailOtpEnrollmentMaterial | null;
    backupAck: WalletRegistrationEmailOtpBackupAck | null;
  }>;
  traceContext?: RouterAbTraceContextV1;
  registrationTiming: RegistrationTimingRecorder | null;
  /** Invoked once, before activate, when the plan carries a NEAR branch. */
  onDeferredNearWork: (work: WalletRegistrationRespondEd25519DeferredWork) => void;
}): Promise<{
  session: RegistrationEcdsaSession;
  activated: WalletRegistrationActivateResponseV2;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork | null;
  /** Returned so the deferred NEAR commit reuses it instead of resolving twice. */
  activateEmailOtp: {
    enrollment: WalletRegistrationEmailOtpEnrollmentMaterial | null;
    backupAck: WalletRegistrationEmailOtpBackupAck | null;
  };
}> {
  const [firstChainTarget, ...remainingChainTargets] = args.ecdsaPrepare.chainTargets;
  if (!firstChainTarget) {
    throw new Error('Strict ECDSA ceremony requires at least one EVM-family target');
  }
  const ceremonyId = args.registrationCeremonyId;
  const activationCorrelationId = parseCorrelationId(ceremonyId);
  try {
    const created = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientCreateMs',
      operation: args.context.signingEngine.createRouterAbEcdsaRegistrationCeremony.bind(
        args.context.signingEngine,
        {
          kind: 'create_router_ab_ecdsa_registration_ceremony_v1',
          ceremonyId,
          registration: args.ecdsaPrepare.strictRegistration,
        },
      ),
    });

    const responded = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayRespondMs',
      operation: respondWalletRegistration.bind(undefined, {
        relayerUrl: args.relayerUrl,
        headers: registrationRouteHeaders(args.traceContext),
        registrationCeremonyId: ceremonyId,
        signerPlanKind: args.signerPlanKind,
        signedSetup: args.signedSetup,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: created.registrationRequest,
          requestDigestB64u: created.registrationRequestDigestB64u,
        },
        ...args.authority,
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'respond', header),
      }),
    });

    if (responded.kind === 'near_ed25519') {
      /* This ceremony exists to drive the ECDSA legs; an Ed25519-only plan has
         none and runs its own path. Reaching here means setup and respond
         disagreed about the plan, which must fail rather than proceed with a
         wallet whose signer was never prepared. */
      throw new Error('ECDSA registration ceremony received an Ed25519-only respond result');
    }
    /* Hand off before activate so Yao runs alongside it, not after. */
    const deferredNear =
      responded.kind === 'near_ed25519_and_evm_family_ecdsa' ? responded.ed25519 : null;
    if (deferredNear) args.onDeferredNearWork(deferredNear);

    const verified = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientProofVerifyMs',
      operation: args.context.signingEngine.verifyRouterAbEcdsaRegistrationClientProofs.bind(
        args.context.signingEngine,
        {
          kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1',
          ceremonyId,
          clientProofFinalization: {
            kind: 'finalize_encrypted_client_proof_bundles_v1',
            bundles: responded.ecdsa.strictResult.response.bundles,
          },
        },
      ),
    });

    const activationCommand = await buildThreeRouteCanonicalActivationCommand({
      registrationCeremonyId: ceremonyId,
      activationCorrelationId,
      idempotencyKey: args.idempotencyKey,
      publicFacts: verified.publicFacts,
    });
    const persisted = await args.context.signingEngine.persistInitialCanonicalEcdsaActivation({
      kind: 'persist_initial_canonical_ecdsa_activation_v1',
      ceremonyId,
      planInput: {
        authority: args.materialAuthority,
        targetMemberships: [firstChainTarget, ...remainingChainTargets],
        evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
          args.ecdsaPrepare.prepare.evmFamilySigningKeySlotId,
          'registration ECDSA signing key slot',
        ),
        ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(
          args.ecdsaPrepare.prepare.ecdsaThresholdKeyId,
        ),
        signingRootId: parseSdkEcdsaDerivationSigningRootId(
          args.ecdsaPrepare.prepare.signingRootId,
        ),
        signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
          args.ecdsaPrepare.prepare.signingRootVersion,
        ),
        runtimePolicyScope: args.ecdsaPrepare.prepare.runtimePolicyScope,
        clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
          verified.publicFacts.derivationClientSharePublicKey33B64u,
        ),
        participantIds: [
          toParticipantId(args.ecdsaPrepare.prepare.participantIds[0]),
          toParticipantId(args.ecdsaPrepare.prepare.participantIds[1]),
        ],
        relayerKeyId: parseEcdsaRelayerKeyId(args.ecdsaPrepare.prepare.relayerKeyId),
        bindingDigest: parseEcdsaRoleLocalBindingDigest(verified.publicFacts.contextBinding32B64u),
        journalId: activationCorrelationId,
        requestDigest: activationCommand.requestDigest,
        canonicalRequest: activationCommand.canonicalRequest,
        createdAt: parseIsoTimestamp(new Date().toISOString()),
      },
    });
    if (!persisted.ok) {
      throw new Error(
        `Canonical ECDSA activation persistence failed (${persisted.code}): ${persisted.message}`,
      );
    }

    const activateEmailOtp = await args.resolveActivateEmailOtp();
    const activated = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayActivateMs',
      operation: activateWalletRegistration.bind(undefined, {
        relayerUrl: args.relayerUrl,
        headers: registrationRouteHeaders(args.traceContext),
        registrationCeremonyId: ceremonyId,
        signerPlanKind: args.signerPlanKind,
        signedSetup: args.signedSetup,
        idempotencyKey: args.idempotencyKey,
        /* No `expectedKeyHandles`: the handle only exists once activate
           returns the server bootstrap, so the client cannot assert it
           beforehand. The guard it provided — finalize persisting a different
           key than the session — is structurally impossible now that activate
           both activates and persists within one ceremony-bound operation. */
        ecdsa: {
          clientActivation: verified.publicFacts,
          activationCorrelationId,
          activationRequestDigestB64u: activationCommand.requestDigest,
          materialActivation: persisted.materialActivation,
        },
        ...(activateEmailOtp.enrollment ? { emailOtpEnrollment: activateEmailOtp.enrollment } : {}),
        ...(activateEmailOtp.backupAck ? { emailOtpBackupAck: activateEmailOtp.backupAck } : {}),
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'activate', header),
      }),
    });

    if (activated.kind !== 'evm_family_ecdsa' || !activated.ecdsa) {
      /* Same disagreement as above, one leg later: this ceremony cannot build
         a local session without the activation payload. */
      throw new Error('ECDSA registration ceremony received a non-ECDSA activate result');
    }
    if (activated.authMethod.kind === 'passkey') {
      rememberPasskeyAppSessionForRegisteredWallet({
        appSessionJwt: activated.appSessionJwt,
        relayerUrl: args.relayerUrl,
        walletId: activated.walletId,
      });
    }
    const clientBootstrap = buildStrictRegistrationClientBootstrap({
      prepare: args.ecdsaPrepare.prepare,
      verified: verified.clientBootstrap,
    });
    const registrationBootstrap = parseWalletRegistrationEcdsaDerivationRespond({
      clientBootstrap,
      serverBootstrap: activated.ecdsa.bootstrap,
      activationEpoch: activated.ecdsa.activation.ecdsa_activation.activation_epoch,
    });
    const finalized = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientActivationFinalizeMs',
      operation: args.context.signingEngine.finalizeRouterAbEcdsaRegistrationActivation.bind(
        args.context.signingEngine,
        {
          kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
          journalId: persisted.journalId,
          activationReceipt: activated.ecdsa.activation,
          routerAbEcdsaDerivationNormalSigning:
            registrationBootstrap.routerAbEcdsaDerivationNormalSigning,
        },
      ),
    });

    return {
      session: {
        chainTargets: [firstChainTarget, ...remainingChainTargets],
        clientBootstrap,
        bootstrap: registrationBootstrap,
        activatedThresholdSessionId: activated.ecdsa.bootstrap.thresholdSessionId,
        roleLocalMaterial: finalized.roleLocalMaterial,
        authority: finalized.authority,
        materialActivation: finalized.materialActivation,
        clientPublicFacts: finalized.publicFacts,
        publicCapability: finalized.publicCapability,
        registrationEstablishedSession: activated.registrationEstablishedSession,
      },
      activated,
      deferredNear,
      activateEmailOtp,
    };
  } catch (error: unknown) {
    await closeStrictEcdsaRegistrationCeremony({ context: args.context, ceremonyId });
    throw error;
  }
}

function finalizeResponseViewFromActivatedEcdsa(
  activated: Extract<WalletRegistrationActivateResponseV2, { ok: true; kind: 'evm_family_ecdsa' }>,
): Extract<WalletRegistrationFinalizeResponse, { ok: true; kind: 'evm_family_ecdsa' }> {
  const {
    walletId,
    authority,
    registrationDiagnostics,
    rpId,
    authMethod,
    ecdsa: activatedEcdsa,
  } = activated;
  const { activation: _activation, bootstrap: _bootstrap, ...ecdsa } = activatedEcdsa;
  const base = {
    ok: true as const,
    walletId,
    authority,
    ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
    kind: 'evm_family_ecdsa' as const,
    ecdsa,
  };
  if (authMethod.kind === 'passkey') {
    if (!rpId) throw new Error('Passkey activation is missing its relying-party id');
    return { ...base, rpId, authMethod };
  }
  if (rpId !== undefined) {
    throw new Error('Email OTP activation returned a relying-party id');
  }
  if (!activated.appSessionJwt) {
    throw new Error('Email OTP activation is missing its app session');
  }
  return { ...base, authMethod, appSessionJwt: activated.appSessionJwt };
}

function buildRegistrationPersistencePlan(args: {
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
  ecdsa: RegistrationPersistenceEcdsa;
}): RegistrationPersistencePlan {
  return {
    kind: 'registration_persistence_plan_v1',
    walletId: args.walletId,
    auth: args.auth,
    ecdsa: args.ecdsa,
  };
}

async function finalizeRegistrationEcdsaSessions(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
}): Promise<RegistrationLocalEcdsaWalletKeys> {
  args.registrationTiming.record('ecdsaRegistrationTargetCount', args.plan.ecdsa.walletKeys.length);
  const startedAt = performance.now();
  try {
    return await args.context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
      walletId: toWalletId(args.plan.walletId),
      session: args.plan.ecdsa.session,
      walletKeys: [...args.plan.ecdsa.walletKeys],
    });
  } finally {
    args.registrationTiming.record(
      'ecdsaRegistrationSessionFinalizeMs',
      roundDurationMs(startedAt),
    );
  }
}

async function persistRegistrationEcdsaLocalRecords(args: {
  context: RegistrationWebContext;
  plan: RegistrationPersistencePlan;
  walletKeys: RegistrationLocalEcdsaWalletKeys;
}): Promise<void> {
  if (args.plan.auth.kind === 'passkey') {
    await args.context.signingEngine.finalizeWalletEcdsaRegistration({
      walletId: args.plan.walletId,
      rpId: requireWebAuthnRpId(args.plan.auth.rpId),
      credential: args.plan.auth.credential,
      credentialPublicKeyB64u: args.plan.auth.credentialPublicKeyB64u,
      walletKeys: args.walletKeys,
    });
    return;
  }
  await args.context.signingEngine.storeWalletEmailOtpEcdsaRegistrationData({
    walletId: args.plan.walletId,
    email: args.plan.auth.email,
    registrationAuthorityId: args.plan.auth.registrationAuthorityId,
    walletKeys: args.walletKeys,
  });
}

async function persistRegistrationEcdsaPlan(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
}): Promise<void> {
  const walletKeys = await finalizeRegistrationEcdsaSessions(args);
  const warmSessions =
    args.plan.auth.kind === 'passkey'
      ? buildRegistrationPasskeyEcdsaWarmSessions({
          relayerUrl: args.relayerUrl,
          session: args.plan.ecdsa.session,
          walletKeys,
          auth: args.plan.auth,
        })
      : [];
  const startedAt = performance.now();
  try {
    await persistRegistrationEcdsaLocalRecords({
      context: args.context,
      plan: args.plan,
      walletKeys,
    });
  } finally {
    args.registrationTiming.record(
      'ecdsaRegistrationLocalRecordPersistenceMs',
      roundDurationMs(startedAt),
    );
  }
  if (args.plan.auth.kind === 'passkey') {
    await persistRegistrationPasskeyEcdsaWarmSessions({
      context: args.context,
      session: args.plan.ecdsa.session,
      warmSessions,
      auth: args.plan.auth,
    });
  }
  await persistActiveWalletSessionAuthorizationFromRegistration(walletSessionAuthorizations, {
    authority: args.plan.ecdsa.session.authority,
    authMethod: registrationPersistenceAuthMethod(args.plan.auth),
    session: args.plan.ecdsa.session.registrationEstablishedSession,
  });
}

function registrationEcdsaPlanPersistenceWork(
  args: Parameters<typeof persistRegistrationEcdsaPlan>[0],
): () => Promise<void> {
  return persistRegistrationEcdsaPlan.bind(undefined, args);
}

async function commitRegistrationPersistencePlan(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
}): Promise<void> {
  await args.registrationTiming.measure(
    'ecdsaRegistrationPersistenceMs',
    registrationEcdsaPlanPersistenceWork(args),
  );
}

type RegisterEcdsaOrMixedWalletBaseArgs = {
  context: RegistrationWebContext;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  signerPlan: RegistrationSignerPlan;
  ecdsaSelection: EvmFamilyEcdsaRegistrationBranch;
  options: RegistrationHooksOptions;
  passkeyExecution: RegisterWalletPasskeyExecution;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

type RegisterEcdsaOrMixedWalletArgs = RegisterEcdsaOrMixedWalletBaseArgs &
  (
    | {
        kind: 'evm_family_ecdsa';
        authMethod: RegistrationAuthMethodInput;
        ed25519Selection?: never;
      }
    | {
        kind: 'near_ed25519_and_evm_family_ecdsa';
        authMethod: RegistrationAuthMethodInput;
        ed25519Selection: RegistrationNearEd25519SignerPlan;
      }
  );

type EcdsaEnabledRegistrationStart = Extract<
  WalletRegistrationStartResponse,
  { kind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa' }
>;

type RegistrationYaoWorkCompletion =
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
      /** Raw Router Server-Timing for the execute call. Diagnostics only. */
      routerServerTiming?: string;
      /** Client-observed Yao sub-steps in ms. Diagnostics only. */
      clientTimings?: { admissionMs: number; sessionCreateMs: number };
    }
  | {
      kind: 'failed';
      error: Error;
    };

function registrationYaoWorkError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

function completeRegistrationYaoWork(
  result: ProductEd25519YaoRegistrationResultV1,
): RegistrationYaoWorkCompletion {
  return result.ok
    ? {
        kind: 'pending',
        pending: result.registration,
        ...(result.routerServerTiming ? { routerServerTiming: result.routerServerTiming } : {}),
        ...(result.clientTimings ? { clientTimings: result.clientTimings } : {}),
      }
    : { kind: 'failed', error: new Error(result.message) };
}

function failRegistrationYaoWork(error: unknown): RegistrationYaoWorkCompletion {
  return { kind: 'failed', error: registrationYaoWorkError(error) };
}

function completeRegistrationYaoPending(
  pending: ProductEd25519YaoPendingRegistrationPortV1,
): RegistrationYaoWorkCompletion {
  return { kind: 'pending', pending };
}

function settleRegistrationYaoResult(
  result: Promise<ProductEd25519YaoRegistrationResultV1>,
): Promise<RegistrationYaoWorkCompletion> {
  return result.then(completeRegistrationYaoWork, failRegistrationYaoWork);
}

function settleRegistrationYaoPending(
  pending: Promise<ProductEd25519YaoPendingRegistrationPortV1>,
): Promise<RegistrationYaoWorkCompletion> {
  return pending.then(completeRegistrationYaoPending, failRegistrationYaoWork);
}

type RegistrationYaoWorkState =
  | { kind: 'disabled' }
  | {
      kind: 'running';
      completion: Promise<RegistrationYaoWorkCompletion>;
    }
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
    }
  | { kind: 'failed'; error: Error }
  | { kind: 'committed' }
  | { kind: 'disposed' };

type ClaimedRegistrationYao =
  | { kind: 'disabled' }
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
      clientPublicKey: string;
    };

type RegistrationEd25519MaterialFacts = {
  identity: {
    walletId: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    thresholdSessionId: ThresholdEd25519SessionId;
    signerSlot: number;
    signingRootId: string;
    signingRootVersion: string;
    signingWorkerId: string;
  };
  stableServerScope: {
    relayerKeyId: string;
    participantIds: readonly [number, number];
    runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
    routerAbNormalSigning: {
      kind: typeof ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND;
      signingWorkerId: string;
    };
  };
};

function requireDeferredNearWork(
  value: WalletRegistrationRespondEd25519DeferredWork | null,
): WalletRegistrationRespondEd25519DeferredWork {
  if (!value) throw new Error('Mixed registration is missing deferred NEAR material facts');
  return value;
}

function registrationEd25519MaterialFacts(args: {
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  finalized: WalletRegistrationEd25519YaoPublicResult;
  walletId: WalletId;
  expectedRuntimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
}): RegistrationEd25519MaterialFacts {
  const admission = args.deferredNear.admissionRequest;
  const thresholdSessionId = parseThresholdEd25519SessionId(admission.scope.threshold_session_id);
  if (!thresholdSessionId.ok) {
    throw new Error('Ed25519 registration threshold-session identity is invalid');
  }
  const participantIds = admission.participant_ids;
  const finalizedRuntimePolicyScope = normalizeRuntimePolicyScope(
    args.finalized.runtimePolicyScope,
  );
  if (
    admission.application_binding.wallet_id !== args.walletId ||
    admission.application_binding.near_ed25519_signing_key_id !==
      args.finalized.nearEd25519SigningKeyId ||
    admission.application_binding.key_creation_signer_slot !== args.finalized.signerSlot ||
    participantIds[0] !== args.finalized.participantIds[0] ||
    participantIds[1] !== args.finalized.participantIds[1] ||
    !sameRuntimePolicyScope(finalizedRuntimePolicyScope, args.expectedRuntimePolicyScope) ||
    admission.application_binding.signing_root_id !==
      `${finalizedRuntimePolicyScope.projectId}:${finalizedRuntimePolicyScope.envId}` ||
    admission.scope.root_share_epoch !== finalizedRuntimePolicyScope.signingRootVersion ||
    admission.scope.signing_worker_id !== args.finalized.routerAbNormalSigning.signingWorkerId ||
    args.finalized.relayerKeyId !== args.finalized.routerAbNormalSigning.signingWorkerId
  ) {
    throw new Error('Ed25519 registration material changed the admitted signer identity');
  }
  return {
    identity: {
      walletId: String(args.walletId),
      nearAccountId: args.finalized.nearAccountId,
      nearEd25519SigningKeyId: args.finalized.nearEd25519SigningKeyId,
      thresholdSessionId: thresholdSessionId.value,
      signerSlot: args.finalized.signerSlot,
      signingRootId: admission.application_binding.signing_root_id,
      signingRootVersion: admission.scope.root_share_epoch,
      signingWorkerId: admission.scope.signing_worker_id,
    },
    stableServerScope: {
      relayerKeyId: args.finalized.relayerKeyId,
      participantIds: args.finalized.participantIds,
      runtimePolicyScope: finalizedRuntimePolicyScope,
      routerAbNormalSigning: args.finalized.routerAbNormalSigning,
    },
  };
}

function registrationEstablishedEd25519Session(
  session: RegistrationEstablishedSession,
): RegistrationEstablishedEd25519Session {
  switch (session.tokens.kind) {
    case 'near_ed25519':
    case 'near_ed25519_and_evm_family_ecdsa':
      return session.tokens.ed25519;
    case 'evm_family_ecdsa':
      throw new Error('Registration-established session is missing Ed25519 authorization');
    default:
      return assertNever(session.tokens);
  }
}

function registrationEstablishedEcdsaSession(
  session: RegistrationEstablishedSession,
): RegistrationEstablishedEcdsaSession {
  switch (session.tokens.kind) {
    case 'evm_family_ecdsa':
    case 'near_ed25519_and_evm_family_ecdsa':
      return session.tokens.ecdsa;
    case 'near_ed25519':
      throw new Error('Registration-established session is missing ECDSA authorization');
    default:
      return assertNever(session.tokens);
  }
}

function assertRegistrationEcdsaSessionMatchesWalletKeys(args: {
  session: RegistrationEcdsaSession;
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
}): void {
  const [firstWalletKey] = args.walletKeys;
  if (!firstWalletKey) {
    throw new Error('ECDSA registration did not return wallet key material');
  }
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  if (
    String(args.session.registrationEstablishedSession.walletId) !== firstWalletKey.walletId ||
    token.thresholdSessionId !== args.session.activatedThresholdSessionId ||
    token.keyHandle !== firstWalletKey.keyHandle ||
    !sameRuntimePolicyScope(
      token.runtimePolicyScope,
      args.session.clientBootstrap.runtimePolicyScope,
    ) ||
    alphabetizeStringify(token.routerAbEcdsaDerivationNormalSigning) !==
      alphabetizeStringify(args.session.bootstrap.routerAbEcdsaDerivationNormalSigning)
  ) {
    throw new Error('Registration-established ECDSA session changed the signer identity');
  }
  for (const walletKey of args.walletKeys) {
    if (
      walletKey.walletId !== firstWalletKey.walletId ||
      walletKey.keyHandle !== token.keyHandle ||
      walletKey.ecdsaThresholdKeyId !== firstWalletKey.ecdsaThresholdKeyId
    ) {
      throw new Error('ECDSA registration material changed the established session identity');
    }
  }
}

function buildRegistrationPasskeyEcdsaRestoreMetadata(args: {
  session: RegistrationEcdsaSession;
  walletKey: Awaited<
    ReturnType<RegistrationSigningSurface['finalizeWalletRegistrationEcdsaSessions']>
  >[number];
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
}): Exclude<SealedSigningSessionEcdsaRestoreMetadata, { source: 'email_otp' }> {
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  if (args.walletKey.walletId !== String(args.session.authority.walletId)) {
    throw new Error('Registration ECDSA runtime wallet does not match its authority');
  }
  if (
    alphabetizeStringify(args.walletKey.roleLocalMaterialRef.materialActivation) !==
    alphabetizeStringify(args.session.materialActivation)
  ) {
    throw new Error('Registration ECDSA runtime material activation does not match the session');
  }
  if (
    !args.session.chainTargets.some(
      (chainTarget) =>
        thresholdEcdsaChainTargetKey(chainTarget) ===
        thresholdEcdsaChainTargetKey(args.walletKey.chainTarget),
    )
  ) {
    throw new Error('Registration ECDSA runtime target is outside the activated family');
  }
  const publicFacts = args.walletKey.ecdsaRoleLocalPublicFacts;
  if (
    publicFacts.walletId !== args.walletKey.walletId ||
    thresholdEcdsaChainTargetKey(publicFacts.chainTarget) !==
      thresholdEcdsaChainTargetKey(args.walletKey.chainTarget) ||
    publicFacts.keyHandle !== args.walletKey.keyHandle ||
    publicFacts.ecdsaThresholdKeyId !== args.walletKey.ecdsaThresholdKeyId ||
    alphabetizeStringify(publicFacts.publicCapability) !==
      alphabetizeStringify(args.session.publicCapability)
  ) {
    throw new Error('Registration ECDSA runtime public facts do not match the activated family');
  }
  const credentialIdB64u = String(
    args.auth.credential.rawId || args.auth.credential.id || '',
  ).trim();
  if (!credentialIdB64u) {
    throw new Error('Registration passkey authority is missing its credential identity');
  }
  return {
    chainTarget: args.walletKey.chainTarget,
    signingRootId: args.walletKey.signingRootId,
    signingRootVersion: args.walletKey.signingRootVersion,
    source: 'registration',
    authority: args.session.authority,
    roleLocalMaterialRef: args.walletKey.roleLocalMaterialRef,
    rpId: toRpId(args.auth.rpId),
    credentialIdB64u,
    keyHandle: token.keyHandle,
    ecdsaThresholdKeyId: args.walletKey.ecdsaThresholdKeyId,
    ethereumAddress: args.walletKey.thresholdOwnerAddress,
    relayerKeyId: args.walletKey.relayerKeyId,
    clientVerifyingShareB64u:
      args.walletKey.ecdsaRoleLocalPublicFacts.derivationClientSharePublicKey33B64u,
    thresholdEcdsaPublicKeyB64u: args.walletKey.thresholdEcdsaPublicKeyB64u,
    participantIds: [...args.walletKey.participantIds],
    runtimePolicyScope: token.runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: token.routerAbEcdsaDerivationNormalSigning,
    publicCapability: args.walletKey.publicCapability,
  };
}

function buildRegistrationPasskeyEcdsaWarmSessions(args: {
  relayerUrl: string;
  session: RegistrationEcdsaSession;
  walletKeys: RegistrationLocalEcdsaWalletKeys;
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
}): RegistrationPasskeyEcdsaWarmSession[] {
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  return args.walletKeys.map((walletKey) => {
    const ecdsaRestore = buildRegistrationPasskeyEcdsaRestoreMetadata({
      session: args.session,
      walletKey,
      auth: args.auth,
    });
    return {
      transport: {
        curve: 'ecdsa',
        authMethod: 'passkey',
        walletId: walletKey.walletId,
        chainTarget: walletKey.chainTarget,
        relayerUrl: args.relayerUrl,
        walletSessionJwt: token.walletSessionJwt,
        ecdsaRestore,
      },
    };
  });
}

async function persistRegistrationPasskeyEcdsaWarmSessions(args: {
  context: RegistrationWebContext;
  session: RegistrationEcdsaSession;
  warmSessions: readonly RegistrationPasskeyEcdsaWarmSession[];
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
}): Promise<void> {
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  const persistTransport =
    args.context.configs.signing.sessionPersistenceMode === 'sealed_refresh_v1';
  for (const warmSession of args.warmSessions) {
    await args.context.signingEngine.hydrateSigningSession({
      thresholdSessionId: token.thresholdSessionId,
      prfFirstB64u: args.auth.passkeyPrfFirstB64u,
      expiresAtMs: args.session.registrationEstablishedSession.expiresAtMs,
      remainingUses: args.session.registrationEstablishedSession.remainingUses,
      ...(persistTransport ? { transport: warmSession.transport } : {}),
    });
  }
}

function buildRegistrationPasskeyEd25519SessionState(args: {
  registrationEstablishedSession: RegistrationEstablishedSession;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  signerSlot: number;
  relayerUrl: string;
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
  authority: WalletAuthAuthorityRef;
}): ResolvedRouterAbEd25519WalletSessionState {
  const token = registrationEstablishedEd25519Session(args.registrationEstablishedSession);
  if (
    token.nearAccountId !== String(args.nearAccountId) ||
    token.nearEd25519SigningKeyId !== String(args.nearEd25519SigningKeyId) ||
    token.thresholdSessionId !== String(args.thresholdSessionId) ||
    !sameRuntimePolicyScope(token.runtimePolicyScope, args.runtimePolicyScope)
  ) {
    throw new Error('Registration-established Ed25519 session changed the signer identity');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(token.runtimePolicyScope);
  const signingRootVersion = signingRoot.signingRootVersion;
  if (!signingRootVersion) {
    throw new Error('Registration-established Ed25519 session is missing a signing-root version');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(args.walletId),
    nearAccountId: String(args.nearAccountId),
    nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId),
    walletSessionId: String(args.registrationEstablishedSession.walletSessionId),
    quotaId: String(args.registrationEstablishedSession.quotaId),
    thresholdSessionId: token.thresholdSessionId,
    remainingUses: args.registrationEstablishedSession.remainingUses,
    expiresAtMs: args.registrationEstablishedSession.expiresAtMs,
    runtimePolicyScope: token.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion,
    routerAbNormalSigning: token.routerAbNormalSigning,
    walletSessionJwt: token.walletSessionJwt,
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Registration-established Ed25519 session is unusable (${signingWalletSession.reason})`,
    );
  }
  const credentialIdB64u = String(
    args.auth.credential.rawId || args.auth.credential.id || '',
  ).trim();
  if (!credentialIdB64u) {
    throw new Error('Registration passkey authority is missing its credential identity');
  }
  return buildPasskeyRouterAbEd25519WalletSessionState({
    walletId: args.walletId,
    nearAccountId: toAccountId(args.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(args.nearEd25519SigningKeyId),
    signerSlot: args.signerSlot,
    rpId: toRpId(args.auth.rpId),
    credentialIdB64u,
    relayerUrl: args.relayerUrl,
    authority: args.authority,
    signingWalletSession: signingWalletSession.value,
  });
}

async function buildRegistrationEmailOtpEd25519SessionState(args: {
  registrationEstablishedSession: RegistrationEstablishedSession;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  signerSlot: number;
  relayerUrl: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  const token = registrationEstablishedEd25519Session(args.registrationEstablishedSession);
  if (
    token.nearAccountId !== String(args.nearAccountId) ||
    token.nearEd25519SigningKeyId !== String(args.nearEd25519SigningKeyId) ||
    token.thresholdSessionId !== String(args.thresholdSessionId) ||
    !sameRuntimePolicyScope(token.runtimePolicyScope, args.runtimePolicyScope)
  ) {
    throw new Error('Registration-established Email OTP Ed25519 session changed signer identity');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(token.runtimePolicyScope);
  const signingRootVersion = signingRoot.signingRootVersion;
  if (!signingRootVersion) {
    throw new Error('Registration-established Ed25519 session is missing a signing-root version');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(args.walletId),
    nearAccountId: String(args.nearAccountId),
    nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId),
    walletSessionId: String(args.registrationEstablishedSession.walletSessionId),
    quotaId: String(args.registrationEstablishedSession.quotaId),
    thresholdSessionId: token.thresholdSessionId,
    remainingUses: args.registrationEstablishedSession.remainingUses,
    expiresAtMs: args.registrationEstablishedSession.expiresAtMs,
    runtimePolicyScope: token.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion,
    routerAbNormalSigning: token.routerAbNormalSigning,
    walletSessionJwt: token.walletSessionJwt,
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Registration-established Email OTP Ed25519 session is unusable (${signingWalletSession.reason})`,
    );
  }
  const authority = await walletAuthAuthorityRef({
    authority: args.emailOtpAuthContext.authority,
  });
  return buildEmailOtpRouterAbEd25519WalletSessionState({
    walletId: args.walletId,
    nearAccountId: toAccountId(args.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(args.nearEd25519SigningKeyId),
    providerSubjectId: emailOtpAuthContextProviderUserId(args.emailOtpAuthContext),
    signerSlot: args.signerSlot,
    relayerUrl: args.relayerUrl,
    authority,
    signingWalletSession: signingWalletSession.value,
  });
}

async function persistRegistrationPasskeyEd25519SealedRuntime(args: {
  context: RegistrationWebContext;
  registrationEstablishedSession: RegistrationEstablishedSession;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  signerSlot: number;
  relayerUrl: string;
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
}): Promise<void> {
  const token = registrationEstablishedEd25519Session(args.registrationEstablishedSession);
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(args.metadata);
  const credentialIdB64u = String(
    args.auth.credential.rawId || args.auth.credential.id || '',
  ).trim();
  if (!credentialIdB64u) {
    throw new Error('Registration passkey authority is missing its credential identity');
  }
  const authority = await walletAuthAuthorityRef({
    authority: passkeyWalletAuthAuthorityFromCredential({
      walletId: args.walletId,
      rpId: args.auth.rpId,
      credential: args.auth.credential,
    }),
  });
  const session = buildRegistrationPasskeyEd25519SessionState({
    ...args,
    authority,
  });
  const ed25519Restore = buildPasskeyEd25519RestoreMetadata({
    rpId: args.auth.rpId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    relayerKeyId: token.routerAbNormalSigning.signingWorkerId,
    participantIds: args.metadata.participantIds,
    runtimePolicyScope: token.runtimePolicyScope,
    signerSlot: args.signerSlot,
    routerAbNormalSigning: token.routerAbNormalSigning,
    credentialIdB64u,
    materialActivation,
  });
  await persistPasskeyEd25519YaoSessionForRefresh({
    persistence: args.context.signingEngine,
    session,
    prfFirstB64u: args.auth.passkeyPrfFirstB64u,
    ed25519Restore,
    materialActivation,
  });
}

type PasskeyRegistrationEd25519MaterialPersistenceArgs = {
  facts: RegistrationEd25519MaterialFacts;
  rpId: string;
  credentialIdB64u: string;
  passkeyPrfFirstB64u: string;
};

class PasskeyRegistrationEd25519MaterialPersistencePort implements ProductEd25519YaoBrowserMaterialPersistencePortV1 {
  constructor(private readonly args: PasskeyRegistrationEd25519MaterialPersistenceArgs) {}

  async persist(
    activeClient: RouterAbEd25519YaoSealableActiveClientV1,
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    await persistPasskeyEd25519YaoSignerMaterialV1({
      store: IndexedDBManager,
      activeClient,
      identity: {
        ...this.args.facts.identity,
        rpId: this.args.rpId,
        credentialIdB64u: this.args.credentialIdB64u,
      },
      stableServerScope: this.args.facts.stableServerScope,
      passkeyPrfFirstB64u: this.args.passkeyPrfFirstB64u,
    });
    return activeClient.metadata();
  }
}

async function persistPasskeyRegistrationEd25519Material(
  args: PasskeyRegistrationEd25519MaterialPersistenceArgs & {
    pending: ProductEd25519YaoPendingRegistrationPortV1;
  },
): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
  return await args.pending.persistRegistrationMaterial({
    kind: 'browser_owned',
    persistence: new PasskeyRegistrationEd25519MaterialPersistencePort(args),
  });
}

async function persistEmailOtpRegistrationEd25519Material(args: {
  pending: ProductEd25519YaoPendingRegistrationPortV1;
  facts: RegistrationEd25519MaterialFacts;
  expectedOperationalPublicKey: string;
  providerSubject: string;
  sessionPolicy: {
    thresholdSessionId: string;
    expiresAtMs: number;
    remainingUses: number;
  };
}): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
  return await args.pending.persistRegistrationMaterial({
    kind: 'worker_owned',
    walletId: args.facts.identity.walletId,
    providerSubject: args.providerSubject,
    nearAccountId: args.facts.identity.nearAccountId,
    nearEd25519SigningKeyId: args.facts.identity.nearEd25519SigningKeyId,
    signerSlot: args.facts.identity.signerSlot,
    signingRootVersion: args.facts.identity.signingRootVersion,
    expectedOperationalPublicKey: args.expectedOperationalPublicKey,
    sessionPolicy: args.sessionPolicy,
  });
}

class RegistrationYaoWork {
  private state: RegistrationYaoWorkState;
  private persistedEmailOtpActiveClient: EmailOtpEd25519YaoWorkerActiveClientV1 | null = null;
  /** Router Server-Timing captured when the ceremony settled. Diagnostics only. */
  private routerServerTiming: string | null = null;
  /** Client-observed Yao sub-step durations. Diagnostics only. */
  private yaoClientTimings: { admissionMs: number; sessionCreateMs: number } | null = null;

  /** Wall-clock start of the Yao branch, for `yaoBranchTotalMs`. */
  private readonly startedAtMs: number = performance.now();
  /**
   * Stamped when the ceremony's own promise settles, not when the join is
   * reached. Measuring at the join would report max(ECDSA, Yao), because the
   * claim is only awaited after the ECDSA branch completes.
   */
  private settledAtMs: number | null = null;

  private constructor(state: RegistrationYaoWorkState) {
    this.state = state;
    if (state.kind === 'running') {
      void state.completion.then(
        () => this.stampSettled(),
        () => this.stampSettled(),
      );
    }
  }

  private stampSettled(): void {
    if (this.settledAtMs === null) this.settledAtMs = performance.now();
  }

  /** Duration of the Yao branch itself. Diagnostics only. */
  elapsedMs(): number {
    const settledAtMs = this.settledAtMs ?? performance.now();
    return Math.max(0, settledAtMs - this.startedAtMs);
  }

  static disabled(): RegistrationYaoWork {
    return new RegistrationYaoWork({ kind: 'disabled' });
  }

  static start(
    input: Parameters<typeof registerVerifiedPasskeyEd25519YaoV1>[0],
  ): RegistrationYaoWork {
    return new RegistrationYaoWork({
      kind: 'running',
      completion: settleRegistrationYaoResult(registerVerifiedPasskeyEd25519YaoV1(input)),
    });
  }

  static startPending(
    pending: Promise<ProductEd25519YaoPendingRegistrationPortV1>,
  ): RegistrationYaoWork {
    return new RegistrationYaoWork({
      kind: 'running',
      completion: settleRegistrationYaoPending(pending),
    });
  }

  consumeClientTimings(): { admissionMs: number; sessionCreateMs: number } | null {
    const value = this.yaoClientTimings;
    this.yaoClientTimings = null;
    return value;
  }

  consumeRouterServerTiming(): string | null {
    const value = this.routerServerTiming;
    this.routerServerTiming = null;
    return value;
  }

  async requirePending(): Promise<ProductEd25519YaoPendingRegistrationPortV1> {
    switch (this.state.kind) {
      case 'running': {
        const completion = await this.state.completion;
        if (completion.kind === 'failed') {
          this.state = completion;
          throw completion.error;
        }
        this.routerServerTiming = completion.routerServerTiming || null;
        this.yaoClientTimings = completion.clientTimings || null;
        this.state = completion;
        return completion.pending;
      }
      case 'pending':
        return this.state.pending;
      case 'disabled':
        throw new Error('Ed25519 Yao work was not requested');
      case 'failed':
        throw this.state.error;
      case 'committed':
        throw new Error('Ed25519 Yao registration is already committed');
      case 'disposed':
        throw new Error('Ed25519 Yao registration is disposed');
      default:
        return assertNever(this.state);
    }
  }

  async persistMaterial(
    args:
      | {
          kind: 'passkey';
          facts: RegistrationEd25519MaterialFacts;
          rpId: string;
          credentialIdB64u: string;
          passkeyPrfFirstB64u: string;
        }
      | {
          kind: 'email_otp';
          facts: RegistrationEd25519MaterialFacts;
          expectedOperationalPublicKey: string;
          providerSubject: string;
          sessionPolicy: {
            thresholdSessionId: string;
            expiresAtMs: number;
            remainingUses: number;
          };
        },
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    if (this.state.kind !== 'pending') {
      throw new Error('Ed25519 Yao registration must be pending before material persistence');
    }
    const pending = this.state.pending;
    let metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    switch (args.kind) {
      case 'passkey':
        metadata = await persistPasskeyRegistrationEd25519Material({ pending, ...args });
        break;
      case 'email_otp':
        metadata = await persistEmailOtpRegistrationEd25519Material({ pending, ...args });
        if (pending instanceof EmailOtpEd25519YaoWorkerPendingRegistrationV1) {
          this.persistedEmailOtpActiveClient = pending.persistedActiveClient();
        }
        break;
      default:
        return assertNever(args);
    }
    this.state = { kind: 'committed' };
    return metadata;
  }

  persistedEmailOtpYaoActiveClient(): EmailOtpEd25519YaoWorkerActiveClientV1 {
    if (!this.persistedEmailOtpActiveClient) {
      throw new Error('Email OTP Ed25519 Yao registration active material is unavailable');
    }
    return this.persistedEmailOtpActiveClient;
  }

  releasePersistedEmailOtpYaoActiveClient(): void {
    this.persistedEmailOtpActiveClient = null;
  }

  async dispose(): Promise<void> {
    switch (this.state.kind) {
      case 'running': {
        const completion = await this.state.completion;
        if (completion.kind === 'pending') await completion.pending.dispose();
        this.state = { kind: 'disposed' };
        return;
      }
      case 'pending':
        await this.state.pending.dispose();
        this.state = { kind: 'disposed' };
        return;
      case 'disabled':
      case 'failed':
        this.state = { kind: 'disposed' };
        return;
      case 'committed':
        this.persistedEmailOtpActiveClient?.dispose();
        this.persistedEmailOtpActiveClient = null;
        return;
      case 'disposed':
        return;
      default:
        return assertNever(this.state);
    }
  }
}

function registrationPasskeySignerSlot(args: RegisterEcdsaOrMixedWalletArgs): number {
  switch (args.kind) {
    case 'evm_family_ecdsa':
      return 1;
    case 'near_ed25519_and_evm_family_ecdsa':
      return args.ed25519Selection.signerSlot;
    default:
      return assertNever(args);
  }
}

function requireEcdsaEnabledRegistrationStart(
  args: RegisterEcdsaOrMixedWalletArgs,
  started: WalletRegistrationStartResponse,
): EcdsaEnabledRegistrationStart {
  if (started.kind !== args.kind) {
    throw new Error('Wallet registration start returned a different signer branch');
  }
  return started;
}

/**
 * Starts deferred passkey Yao work from respond's admission, using the setup
 * challenge and the ceremony's carried bearer credential. Never awaited by
 * registration: the ECDSA wallet is already usable.
 */
function startMixedRegistrationYaoWork(args: {
  intent: ReturnType<typeof requirePasskeyRegistrationIntent>;
  registrationIntentDigestB64u: string;
  signedSetup: string;
  registrationCeremonyId: string;
  passkeyAuthority: RegistrationPasskeyAuthority;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  relayerUrl: string;
  traceContext: RouterAbTraceContextV1;
}): RegistrationYaoWork {
  return RegistrationYaoWork.start({
    kind: 'verified_passkey_ed25519_yao_registration_input_v1',
    verifiedIntent: {
      kind: 'verified_passkey_registration_intent_v1',
      intent: args.intent,
      registrationIntentDigestB64u: args.registrationIntentDigestB64u,
      registrationBearerToken: args.signedSetup,
      registrationCeremonyId: args.registrationCeremonyId,
    },
    verifiedAuthority: {
      kind: 'verified_passkey_registration_authority_v1',
      walletId: args.intent.walletId,
      registrationIntentDigestB64u: args.registrationIntentDigestB64u,
      credentialIdB64u: String(
        args.passkeyAuthority.credential.rawId || args.passkeyAuthority.credential.id || '',
      ).trim(),
      ownedPasskeyPrfFirst: base64UrlDecode(args.passkeyAuthority.prfFirstB64u),
    },
    admissionRequest: args.deferredNear.admissionRequest,
    admissionReceipt: args.deferredNear.admissionReceipt,
    httpTransport: {
      kind: 'passkey_ed25519_yao_http_transport_v1',
      routerOrigin: new URL(args.relayerUrl).origin,
      fetch: globalThis.fetch,
      traceContext: args.traceContext,
    },
  });
}

function requireEmailOtpEd25519YaoPendingFactorHandle(
  material: EmailOtpRegistrationEnrollmentMaterial,
) {
  if (material.ed25519YaoFactor.kind !== 'issued') {
    throw new Error('Email OTP registration did not issue the required Ed25519 Yao factor');
  }
  return material.ed25519YaoFactor.pendingFactorHandle;
}

function startEmailOtpRegistrationYaoWork(args: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  walletId: string;
  providerSubject: string;
  registrationAuthorityId: string;
  signedSetup: string;
  registrationCeremonyId: string;
  relayerUrl: string;
}): RegistrationYaoWork {
  return RegistrationYaoWork.startPending(
    args.recorder.measure(
      'emailOtpYaoTotalMs',
      createEmailOtpRegistrationYaoPending.bind(undefined, args),
    ),
  );
}

async function createEmailOtpRegistrationYaoPending(args: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  walletId: string;
  providerSubject: string;
  registrationAuthorityId: string;
  signedSetup: string;
  registrationCeremonyId: string;
  relayerUrl: string;
}): Promise<ProductEd25519YaoPendingRegistrationPortV1> {
  const material = await args.recorder.measure(
    'emailOtpYaoEnrollmentMaterialWaitMs',
    requireEmailOtpRegistrationEnrollmentMaterial.bind(undefined, {
      material: args.enrollmentMaterial,
      operation: 'Ed25519 Yao activation',
    }),
  );
  return args.recorder.measure(
    'emailOtpYaoWorkerRegistrationMs',
    startEmailOtpEd25519YaoWorkerRegistrationV1.bind(undefined, {
      kind: 'verified_email_otp_ed25519_yao_registration_worker_input_v1',
      workerContext: args.context.signingEngine.getSignerWorkerContext(),
      pendingFactorHandle: requireEmailOtpEd25519YaoPendingFactorHandle(material),
      admissionRequest: args.deferredNear.admissionRequest,
      admissionReceipt: args.deferredNear.admissionReceipt,
      walletId: args.walletId,
      providerSubject: args.providerSubject,
      registrationAuthorityId: args.registrationAuthorityId,
      registrationBearerToken: args.signedSetup,
      routerOrigin: args.relayerUrl,
      onYaoDiagnostics: recordEmailOtpRegistrationYaoDiagnostics.bind(undefined, args.recorder),
    }),
  );
}

function recordEmailOtpRegistrationYaoDiagnostics(
  recorder: RegistrationTimingRecorder,
  diagnostics: EmailOtpEd25519YaoRegistrationDiagnosticsV1,
): void {
  for (const [bucket, durationMs] of parseYaoServerTimingBuckets(diagnostics.routerServerTiming)) {
    recorder.record(bucket, durationMs);
  }
  if (!diagnostics.clientTimings) return;
  recorder.record('yaoAdmissionMs', diagnostics.clientTimings.admissionMs);
  recorder.record('yaoClientSessionCreateMs', diagnostics.clientTimings.sessionCreateMs);
}

async function claimRegistrationYao(
  registrationKind: RegisterEcdsaOrMixedWalletArgs['kind'],
  work: RegistrationYaoWork,
): Promise<ClaimedRegistrationYao> {
  switch (registrationKind) {
    case 'evm_family_ecdsa':
      return { kind: 'disabled' };
    case 'near_ed25519_and_evm_family_ecdsa': {
      const pending = await work.requirePending();
      return { kind: 'pending', pending, clientPublicKey: pending.publicKey() };
    }
    default:
      return assertNever(registrationKind);
  }
}

type DeferredRegistrationFinalizeAuthMaterial =
  | { kind: 'passkey' }
  | {
      kind: 'email_otp';
      enrollment: WalletRegistrationEmailOtpEnrollmentMaterial;
      backupAck: WalletRegistrationEmailOtpBackupAck;
    };

function buildDeferredRegistrationFinalizeAuthMaterial(args: {
  auth: RegistrationPersistenceAuth;
  emailOtpEnrollment: WalletRegistrationEmailOtpEnrollmentMaterial | null;
  emailOtpBackupAck: WalletRegistrationEmailOtpBackupAck | null;
}): DeferredRegistrationFinalizeAuthMaterial {
  switch (args.auth.kind) {
    case 'passkey':
      return { kind: 'passkey' };
    case 'email_otp':
      if (!args.emailOtpEnrollment || !args.emailOtpBackupAck) {
        throw new Error('Deferred Email OTP registration requires enrollment and backup material');
      }
      return {
        kind: 'email_otp',
        enrollment: args.emailOtpEnrollment,
        backupAck: args.emailOtpBackupAck,
      };
    default:
      return assertNever(args.auth);
  }
}

type RegistrationPasskeyAuthority = Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>>;

/**
 * Commit #2. Runs after registration has already returned an ECDSA-ready
 * wallet, so every failure here is reported as a retryable NEAR-provisioning
 * state rather than raised: the ECDSA wallet is durable and must survive a
 * terminal Yao failure untouched.
 */
async function commitDeferredEd25519Registration(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationCeremonyId: string;
  /* Route 4 verifies the same payload the earlier legs carried. */
  signedSetup: string;
  headers: Record<string, string> | undefined;
  yaoWork: RegistrationYaoWork;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  plan: RegistrationPersistencePlan;
  passkeyAuthority: RegistrationPasskeyAuthority | null;
  walletId: WalletId;
  authMaterial: DeferredRegistrationFinalizeAuthMaterial;
}): Promise<NearProvisioningState> {
  const auth = args.plan.auth;
  try {
    /* The page-owned RegistrationYaoWork is the single-flight: `requirePending`
       hands out the one in-flight ceremony for this tab and claims it once. */
    const pending = await args.yaoWork.requirePending();
    const clientPublicKey = pending.publicKey();
    const activationReference = pending.activationReference();
    /* One deferred completion path for both plans: a mixed wallet's NEAR arm
       lands here exactly as an Ed25519-only wallet's sole signer does. */
    const completed = await completeWalletRegistrationNearProvisioning({
      relayerUrl: args.relayerUrl,
      registrationCeremonyId: args.registrationCeremonyId,
      signedSetup: args.signedSetup,
      headers: args.headers,
      /* Deterministic, and distinct from activate's key: the server derives
         its side-effect key from {ceremonyId, idempotencyKey}, so sharing
         activate's key would replay activate's commit, while a random key
         would poison the Yao consume on retry. */
      idempotencyKey: await deriveNearProvisioningIdempotencyKey({
        registrationCeremonyId: args.registrationCeremonyId,
        activationReference,
      }),
      ed25519: { activationReference },
      auth: args.authMaterial,
    });
    if (!completed.ok) {
      throw new Error('Deferred NEAR provisioning did not complete');
    }
    const finalized = completed;
    if (finalized.kind !== 'near_ed25519') {
      throw new Error('Deferred Ed25519 finalize returned a different signer branch');
    }
    const nearAccountId = toAccountId(finalized.ed25519.nearAccountId);
    const passkeyCredentialIdB64u =
      auth.kind === 'passkey'
        ? String(auth.credential.rawId || auth.credential.id || '').trim()
        : '';
    if (auth.kind === 'passkey') {
      requireEd25519YaoRegistrationPublicResultMatches({
        clientPublicKey,
        finalized,
        expectedRpId: auth.rpId,
        expectedWalletId: args.walletId,
      });
      const stored = await args.context.signingEngine.storeWalletEd25519RegistrationData({
        walletId: args.walletId,
        nearAccountId,
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        rpId: requireWebAuthnRpId(auth.rpId),
        credential: auth.credential,
        credentialPublicKeyB64u: auth.credentialPublicKeyB64u,
        signerSlot: finalized.ed25519.signerSlot,
        operationalPublicKey: clientPublicKey,
        relayerKeyId: finalized.ed25519.relayerKeyId,
        keyVersion: finalized.ed25519.keyVersion,
        participantIds: [...finalized.ed25519.participantIds],
      });
      if (stored.signerSlot !== finalized.ed25519.signerSlot) {
        throw new Error('Deferred Ed25519 registration persisted a different signer slot');
      }
    } else {
      requireEmailOtpEd25519YaoRegistrationPublicResultMatches({
        clientPublicKey,
        finalized,
        expectedRegistrationAuthorityId: auth.registrationAuthorityId,
        expectedWalletId: args.walletId,
      });
      const stored = await args.context.signingEngine.storeWalletEmailOtpEd25519RegistrationData({
        walletId: args.walletId,
        nearAccountId,
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        email: auth.email,
        registrationAuthorityId: auth.registrationAuthorityId,
        signerSlot: finalized.ed25519.signerSlot,
        operationalPublicKey: clientPublicKey,
        relayerKeyId: finalized.ed25519.relayerKeyId,
        keyVersion: finalized.ed25519.keyVersion,
        participantIds: [...finalized.ed25519.participantIds],
      });
      if (stored.signerSlot !== finalized.ed25519.signerSlot) {
        throw new Error(
          'Deferred Email OTP Ed25519 registration persisted a different signer slot',
        );
      }
    }
    const materialFacts = registrationEd25519MaterialFacts({
      deferredNear: args.deferredNear,
      finalized: finalized.ed25519,
      walletId: args.walletId,
      expectedRuntimePolicyScope: args.plan.ecdsa.session.clientBootstrap.runtimePolicyScope,
    });
    await args.context.signingEngine.activateAuthenticatedWalletState({
      walletId: args.walletId,
      nearAccountId,
      signerSlot: finalized.ed25519.signerSlot,
      nearClient: args.context.nearClient,
    });
    if (auth.kind === 'passkey') {
      if (!args.passkeyAuthority) {
        throw new Error('Deferred Ed25519 registration is missing its verified passkey authority');
      }
      const metadata = await args.yaoWork.persistMaterial({
        kind: 'passkey',
        facts: materialFacts,
        rpId: auth.rpId,
        credentialIdB64u: passkeyCredentialIdB64u,
        passkeyPrfFirstB64u: args.passkeyAuthority.prfFirstB64u,
      });
      await args.context.signingEngine.upsertEd25519YaoPublicCapabilityLaneReference({
        walletId: args.walletId,
        nearAccountId,
        thresholdSessionId: materialFacts.identity.thresholdSessionId,
        runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
        materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
        auth: {
          kind: 'passkey',
          rpId: toRpId(auth.rpId),
          credentialIdB64u: passkeyCredentialIdB64u,
        },
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
          finalized.ed25519.nearEd25519SigningKeyId,
        ),
        signerSlot: finalized.ed25519.signerSlot,
      });
      await persistRegistrationPasskeyEd25519SealedRuntime({
        context: args.context,
        registrationEstablishedSession: finalized.registrationEstablishedSession,
        walletId: args.walletId,
        nearAccountId,
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        thresholdSessionId: materialFacts.identity.thresholdSessionId,
        runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
        signerSlot: finalized.ed25519.signerSlot,
        relayerUrl: args.relayerUrl,
        auth,
        metadata,
      });
    } else {
      const registrationSession = registrationEstablishedEd25519Session(
        finalized.registrationEstablishedSession,
      );
      const metadata = await args.yaoWork.persistMaterial({
        kind: 'email_otp',
        facts: materialFacts,
        expectedOperationalPublicKey: clientPublicKey,
        providerSubject: emailOtpAuthContextProviderUserId(auth.emailOtpAuthContext),
        sessionPolicy: {
          thresholdSessionId: registrationSession.thresholdSessionId,
          expiresAtMs: finalized.registrationEstablishedSession.expiresAtMs,
          remainingUses: finalized.registrationEstablishedSession.remainingUses,
        },
      });
      const walletSessionState = await buildRegistrationEmailOtpEd25519SessionState({
        registrationEstablishedSession: finalized.registrationEstablishedSession,
        walletId: args.walletId,
        nearAccountId,
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        thresholdSessionId: materialFacts.identity.thresholdSessionId,
        runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
        signerSlot: finalized.ed25519.signerSlot,
        relayerUrl: args.relayerUrl,
        emailOtpAuthContext: auth.emailOtpAuthContext,
      });
      const material = {
        activeClient: args.yaoWork.persistedEmailOtpYaoActiveClient(),
        facts: nearEd25519YaoOperationMaterialFacts(walletSessionState),
      };
      await args.context.signingEngine.persistEmailOtpEd25519YaoCapabilityForRefreshInternal({
        material,
        walletSessionState,
        publicationContext: {
          rpId: args.context.signingEngine.getRpId(),
          provider: emailOtpAuthContextProvider(auth.emailOtpAuthContext),
          providerSubjectId: emailOtpAuthContextProviderUserId(auth.emailOtpAuthContext),
          emailHashHex: emailOtpAuthContextEmailHashHex(auth.emailOtpAuthContext),
          materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
        },
      });
      await args.context.signingEngine.activateVerifiedNearEd25519YaoMaterial(material);
      await args.context.signingEngine.upsertEd25519YaoPublicCapabilityLaneReference({
        walletId: args.walletId,
        nearAccountId,
        thresholdSessionId: materialFacts.identity.thresholdSessionId,
        runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
        materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
        auth: {
          kind: 'email_otp',
          providerSubjectId: emailOtpAuthContextProviderUserId(auth.emailOtpAuthContext),
        },
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
          finalized.ed25519.nearEd25519SigningKeyId,
        ),
        signerSlot: finalized.ed25519.signerSlot,
      });
      args.yaoWork.releasePersistedEmailOtpYaoActiveClient();
    }
    await persistActiveWalletSessionAuthorizationFromRegistration(walletSessionAuthorizations, {
      authority: args.plan.ecdsa.session.authority,
      authMethod: registrationPersistenceAuthMethod(auth),
      session: finalized.registrationEstablishedSession,
    });
    /* Durable first: finalize, capability persistence, and the Yao seal have
       all succeeded by here, and the record is authoritative. If this write
       throws, the catch below records a retryable failure — near_ready is
       never published on an unpersisted success. */
    await args.context.signingEngine.setWalletNearProvisioningState({
      walletId: String(args.walletId),
      status: 'near_ready',
      nearAccountId: String(nearAccountId),
    });
    return {
      status: 'near_ready',
      updatedAtMs: Date.now(),
      nearAccountId: String(nearAccountId),
    };
  } catch (error: unknown) {
    /* The ECDSA wallet is already durable, so this is reported as a retryable
       provisioning state rather than raised. */
    const errorCode = nearProvisioningErrorCode(error);
    try {
      await args.context.signingEngine.setWalletNearProvisioningState({
        walletId: String(args.walletId),
        status: 'near_failed_retryable',
        errorCode,
      });
    } catch {
      /* The page still learns the outcome even if the record could not be
         written; it must not be upgraded to ready either way. */
    }
    return {
      status: 'near_failed_retryable',
      updatedAtMs: Date.now(),
      error: getUserFriendlyErrorMessage(error, 'registration', String(args.walletId)),
      errorCode,
    };
  }
}

/* Exported for tests: the persist-before-publish ordering below is the
   lifecycle's core guarantee and is only observable by driving this runner. */
export async function runDeferredEd25519Provisioning(args: {
  context: RegistrationWebContext;
  walletId: WalletId;
  commit: Parameters<typeof commitDeferredEd25519Registration>[0];
}): Promise<void> {
  try {
    await args.context.signingEngine.setWalletNearProvisioningState({
      walletId: String(args.walletId),
      status: 'near_provisioning',
    });
  } catch (error: unknown) {
    const errorCode = nearProvisioningErrorCode(error);
    const state: NearProvisioningState = {
      status: 'near_failed_retryable',
      updatedAtMs: Date.now(),
      error: getUserFriendlyErrorMessage(error, 'registration', String(args.walletId)),
      errorCode,
    };
    try {
      await args.context.signingEngine.setWalletNearProvisioningState({
        walletId: String(args.walletId),
        status: 'near_failed_retryable',
        errorCode,
      });
    } catch {
      // The live state remains retryable when durable persistence is unavailable.
    }
    publishNearProvisioningState(args.walletId, state);
    return;
  }
  await runSingleFlightNearProvisioning({
    walletId: args.walletId,
    nowMs: Date.now,
    attempt: commitDeferredEd25519Registration.bind(undefined, args.commit),
  });
}

/** Maps a deferred-commit throw onto the closed set of provisioning codes. */
function nearProvisioningErrorCode(error: unknown): NearProvisioningErrorCode {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes('finalize')) return 'near_finalize_failed';
  if (message.includes('seal') || message.includes('Yao')) return 'near_seal_failed';
  if (message.includes('wallet session')) return 'near_capability_persist_failed';
  return 'near_provisioning_failed';
}

async function registerEcdsaOrMixedWallet(
  args: RegisterEcdsaOrMixedWalletArgs,
): Promise<RegistrationResult> {
  const { context, wallet, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const startedAt = performance.now();
  const registrationTiming = new RegistrationTimingRecorder(startedAt);
  const traceContext = createRouterAbTraceContextV1();
  let postTouchIdCompletedAt: number | null = null;
  const initialEventAccountId = registrationEventAccountId(
    wallet.kind === 'provided' ? String(wallet.walletId) : 'wallet-registration',
  );
  let yaoWork = RegistrationYaoWork.disabled();

  emitRegistrationEvent(onEvent, initialEventAccountId, {
    authMethod: args.authMethod.kind,
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    const finalizeIdempotencyKey = createRegistrationOperationIdempotencyKey(
      'wallet-registration-finalize',
    );
    const prepared = await setupRegistrationForPasskeyExecution({
      context,
      authMethod: args.authMethod,
      wallet,
      signerSelection,
      recorder: registrationTiming,
      passkeyExecution: args.passkeyExecution,
    });
    if (args.authMethod.kind === 'email_otp') {
      observeRegistrationWarmup({
        recorder: registrationTiming,
        warmup: prepared.registrationWarmup,
      });
    }
    const { relayerUrl, setup } = prepared;
    const intentResponse = {
      intent: setup.intent,
      registrationIntentDigestB64u: setup.registrationIntentDigestB64u,
    };

    const walletId = intentResponse.intent.walletId;
    const eventAccountId = registrationEventAccountId(String(walletId));
    let emailOtpEnrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null = null;
    let emailOtpRegistrationAuthorityId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
    let emailOtpProvider: EmailOtpProvider | null = null;
    let emailOtpAppSessionBinding: EmailOtpAppSessionBinding | null = null;
    let emailOtpRecoveryCodeBackup: Promise<EmailOtpRecoveryCodeBackupOutcome> | null = null;
    let passkeyAuthority: RegistrationPasskeyAuthority | null = null;
    let startAuthority:
      | {
          kind: 'passkey';
          webauthnRegistration: unknown;
        }
      | {
          kind: 'email_otp';
          emailOtpRegistrationProof: Awaited<
            ReturnType<typeof collectEmailOtpRegistrationAuthority>
          >['proof'];
        };
    if (args.authMethod.kind === 'passkey') {
      emitRegistrationEvent(onEvent, eventAccountId, {
        authMethod: args.authMethod.kind,
        phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
        status: 'waiting_for_user',
        interaction: {
          kind: 'passkey_create',
          overlay: 'show',
        },
      });
      const confirmationConfig: Partial<ConfirmationConfig> = {
        uiMode: 'modal',
        behavior: 'requireClick',
        ...(args.confirmationConfigOverride ?? options?.confirmationConfig ?? {}),
      };
      passkeyAuthority = await registrationTiming.measure('authProofMs', () =>
        resolvePasskeyRegistrationAuthority({
          context,
          walletId,
          signerSlot: registrationPasskeySignerSlot(args),
          registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
          options,
          confirmationConfigOverride: confirmationConfig,
          passkeyExecution: args.passkeyExecution,
        }),
      );
      registrationTiming.capturePasskeyAuthDiagnostics(passkeyAuthority.diagnostics);
      postTouchIdCompletedAt = performance.now();
      startAuthority = {
        kind: 'passkey',
        webauthnRegistration: passkeyAuthority.webauthnRegistration,
      };
      emitRegistrationEvent(onEvent, eventAccountId, {
        authMethod: args.authMethod.kind,
        phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
        status: 'succeeded',
        interaction: {
          kind: 'passkey_create',
          overlay: 'hide',
        },
      });
    } else {
      const emailOtpAuthMethod = args.authMethod;
      const emailAuthority = await registrationTiming.measure('authProofMs', () =>
        collectEmailOtpRegistrationAuthority({
          authMethod: emailOtpAuthMethod,
          relayUrl: relayerUrl,
          walletId: String(walletId),
          registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
          appSessionJwt: emailOtpAuthMethod.appSessionJwt,
        }),
      );
      emailOtpEnrollmentMaterial = startEmailOtpRegistrationEnrollmentMaterial({
        recorder: registrationTiming,
        context,
        authMethod: emailOtpAuthMethod,
        relayerUrl,
        walletId: String(walletId),
        providerSubject: emailAuthority.providerSubject,
        ed25519YaoFactor:
          args.kind === 'near_ed25519_and_evm_family_ecdsa'
            ? {
                kind: 'ed25519_yao_factor_requested',
                providerSubject: emailAuthority.providerSubject,
              }
            : { kind: 'ed25519_yao_factor_not_requested' },
        appSessionJwt: emailOtpAuthMethod.appSessionJwt,
      });
      emailOtpRegistrationAuthorityId = emailAuthority.registrationAuthorityId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
      emailOtpProvider = emailOtpProviderFromRegistrationProof(emailAuthority.proof);
      emailOtpRecoveryCodeBackup = startEmailOtpRecoveryCodeBackupAfterEnrollmentMaterial({
        recorder: registrationTiming,
        authMethod: emailOtpAuthMethod,
        relayerUrl,
        walletId: String(walletId),
        enrollmentMaterial: emailOtpEnrollmentMaterial,
        registrationAuthorityId: emailAuthority.registrationAuthorityId,
      });
      startAuthority = {
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      };
    }

    let materialAuthority: WalletAuthAuthorityRef;
    if (args.authMethod.kind === 'passkey') {
      if (!passkeyAuthority) {
        throw new Error('ECDSA registration is missing its verified passkey authority');
      }
      materialAuthority = await walletAuthAuthorityRef({
        authority: passkeyWalletAuthAuthorityFromCredential({
          walletId,
          rpId: args.authMethod.rpId,
          credential: passkeyAuthority.credential,
        }),
      });
    } else {
      if (!emailOtpProvider) {
        throw new Error('Email OTP registration is missing its verified provider');
      }
      materialAuthority = await walletAuthAuthorityRef({
        authority: buildEmailOtpWalletAuthAuthority({
          walletId,
          provider: emailOtpProvider,
          providerUserId: emailOtpProviderSubject,
          emailHashHex: await emailOtpEmailHashHex(emailOtpEmail),
        }),
      });
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const ceremony = await registrationTiming.measure('ecdsaRegistrationTotalMs', () =>
      runEcdsaEnabledThreeRouteRegistrationCeremony({
        context,
        relayerUrl,
        registrationCeremonyId: setup.registrationCeremonyId,
        signerPlanKind: args.kind,
        signedSetup: setup.signedSetup,
        ecdsaPrepare: setup.ecdsa,
        authority: startAuthority,
        materialAuthority,
        idempotencyKey: finalizeIdempotencyKey,
        resolveActivateEmailOtp: async () => ({
          enrollment:
            args.authMethod.kind === 'email_otp'
              ? ((
                  await requireEmailOtpRegistrationEnrollmentMaterial({
                    material: emailOtpEnrollmentMaterial,
                    operation: 'activate',
                  })
                ).emailOtpEnrollment ?? null)
              : null,
          backupAck:
            (await resolveEmailOtpBackupAck({
              authMethod: args.authMethod,
              backup: emailOtpRecoveryCodeBackup,
            })) ?? null,
        }),
        traceContext,
        registrationTiming,
        /* Started before activate and never awaited: the ECDSA wallet is
           usable without it, and blocking on Yao is the coupling 94C removes. */
        onDeferredNearWork: (deferredNear) => {
          if (args.authMethod.kind === 'passkey') {
            if (!passkeyAuthority) {
              throw new Error('Mixed passkey registration is missing its verified authority');
            }
            yaoWork = startMixedRegistrationYaoWork({
              intent: requirePasskeyRegistrationIntent(intentResponse.intent),
              registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
              signedSetup: setup.signedSetup,
              registrationCeremonyId: setup.registrationCeremonyId,
              passkeyAuthority,
              deferredNear,
              relayerUrl,
              traceContext,
            });
          } else {
            yaoWork = startEmailOtpRegistrationYaoWork({
              recorder: registrationTiming,
              context,
              enrollmentMaterial: emailOtpEnrollmentMaterial,
              deferredNear,
              walletId: String(walletId),
              providerSubject: emailOtpProviderSubject,
              registrationAuthorityId: emailOtpRegistrationAuthorityId,
              signedSetup: setup.signedSetup,
              registrationCeremonyId: setup.registrationCeremonyId,
              relayerUrl,
            });
          }
        },
      }),
    );
    const ecdsaSession = ceremony.session;
    /* Activate's response is the finalize terminal wallet plus the activation
       payload the ceremony already consumed to build the local session, so it
       is a subtype: downstream consumers read the wallet and ignore the rest. */
    if (ceremony.activated.kind !== 'evm_family_ecdsa') {
      throw new Error('Wallet registration activate returned a different signer branch');
    }
    const finalized = finalizeResponseViewFromActivatedEcdsa(ceremony.activated);
    const emailOtpEnrollment = ceremony.activateEmailOtp.enrollment;
    const emailOtpBackupAck = ceremony.activateEmailOtp.backupAck;
    /* Commit #1 finalizes the ECDSA branch alone, on both the ECDSA-only and
       the mixed plan, so this no longer compares against `args.kind`. */
    if (finalized.kind !== 'evm_family_ecdsa') {
      throw new Error('Wallet registration finalize returned a different signer branch');
    }
    if (args.authMethod.kind === 'email_otp') {
      if (!isEmailOtpWalletRegistrationFinalizeResponse(finalized)) {
        throw new Error('Email OTP registration finalize returned a different auth method');
      }
      emailOtpAppSessionBinding = emailOtpAppSessionBindingFromJwt({
        walletId: finalized.walletId,
        appSessionJwt: finalized.appSessionJwt,
      });
      if (emailOtpAppSessionBinding.providerSubject !== emailOtpProviderSubject) {
        throw new Error('Finalized Email OTP app session belongs to a different provider');
      }
    }
    registrationTiming.captureRouteDiagnostics(finalized.registrationDiagnostics);
    const walletKeys = finalized.ecdsa.walletKeys;
    if (walletKeys.length === 0) {
      throw new Error('Wallet registration finalize did not return ECDSA wallet keys');
    }
    const persistenceAuth = await buildRegistrationPersistenceAuth({
      authMethod: args.authMethod,
      configs: context.configs,
      walletId: toWalletId(finalized.walletId),
      finalized,
      passkeyAuthority,
      email: emailOtpEmail,
      providerSubject: emailOtpProviderSubject,
      registrationAuthorityId: emailOtpRegistrationAuthorityId,
    });
    const persistencePlan = buildRegistrationPersistencePlan({
      walletId: toWalletId(finalized.walletId),
      auth: persistenceAuth,
      ecdsa: buildRegistrationPersistenceEcdsa({
        session: ecdsaSession,
        walletKeys,
        expectedChainTargets: ecdsaSession.chainTargets,
      }),
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED,
      status: 'succeeded',
    });

    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    /* Commit #1. This is the whole of registration success: it writes the
       wallet profile, its auth method, and the ECDSA signers, so the wallet is
       durable and usable the moment it resolves. The Ed25519/NEAR branch is
       committed separately once the Yao ceremony settles. */
    await commitRegistrationPersistencePlan({
      context,
      relayerUrl,
      registrationTiming,
      plan: persistencePlan,
    });
    const primaryEcdsaKey = persistencePlan.ecdsa.walletKeys[0];
    /* Commit #2 is deliberately not awaited: registration returns as soon as
       the ECDSA wallet is durable, which is what takes the Yao wait off the
       critical path. It reports failure as a retryable provisioning state
       instead of rejecting, so it can never fault this returned wallet. */
    const deferredWalletId = toWalletId(finalized.walletId);
    let registrationNearProvisioning: RegistrationNearProvisioningState = { status: 'pending' };
    if (args.kind === 'near_ed25519_and_evm_family_ecdsa') {
      const deferredAuthMaterial = buildDeferredRegistrationFinalizeAuthMaterial({
        auth: persistencePlan.auth,
        emailOtpEnrollment,
        emailOtpBackupAck,
      });
      try {
        await context.signingEngine.setWalletNearProvisioningState({
          walletId: String(deferredWalletId),
          status: 'near_pending',
        });
        publishNearProvisioningState(deferredWalletId, {
          status: 'near_pending',
          updatedAtMs: Date.now(),
        });
        void runDeferredEd25519Provisioning({
          context,
          walletId: deferredWalletId,
          commit: {
            context,
            relayerUrl,
            registrationCeremonyId: setup.registrationCeremonyId,
            signedSetup: setup.signedSetup,
            headers: registrationRouteHeaders(traceContext),
            yaoWork,
            deferredNear: requireDeferredNearWork(ceremony.deferredNear),
            plan: persistencePlan,
            passkeyAuthority,
            walletId: deferredWalletId,
            authMaterial: deferredAuthMaterial,
          },
        });
      } catch (error: unknown) {
        const errorCode = nearProvisioningErrorCode(error);
        registrationNearProvisioning = {
          status: 'retryable',
          error: getUserFriendlyErrorMessage(error, 'registration', String(deferredWalletId)),
          errorCode,
        };
        publishNearProvisioningState(deferredWalletId, {
          status: 'near_failed_retryable',
          updatedAtMs: Date.now(),
          error: registrationNearProvisioning.error,
          errorCode,
        });
      }
    }
    const result: RegistrationResult =
      args.kind === 'near_ed25519_and_evm_family_ecdsa'
        ? {
            success: true,
            kind: 'ecdsa_wallet_registered_near_pending',
            walletId: finalized.walletId,
            capabilities: [
              {
                kind: 'evm_family_ecdsa',
                thresholdEcdsaEthereumAddress: primaryEcdsaKey.thresholdOwnerAddress,
                thresholdEcdsaPublicKeyB64u: primaryEcdsaKey.thresholdEcdsaPublicKeyB64u,
              },
            ],
            nearProvisioning: registrationNearProvisioning,
          }
        : {
            success: true,
            kind: 'wallet_registered',
            walletId: finalized.walletId,
            capabilities: [
              {
                kind: 'evm_family_ecdsa',
                thresholdEcdsaEthereumAddress: primaryEcdsaKey.thresholdOwnerAddress,
                thresholdEcdsaPublicKeyB64u: primaryEcdsaKey.thresholdEcdsaPublicKeyB64u,
              },
            ],
          };
    if (emailOtpAppSessionBinding) {
      rememberEmailOtpAppSessionForRegisteredWallet({
        context,
        binding: emailOtpAppSessionBinding,
      });
    }
    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });
    if (postTouchIdCompletedAt !== null) {
      const walletReadyAt = performance.now();
      emitRegistrationTimingSpan({
        callback: options.onTimingSpan,
        span: 'registration.post_touch_id',
        outcome: 'success',
        durationMs: walletReadyAt - postTouchIdCompletedAt,
        traceContext,
      });
      emitRegistrationTimingSpan({
        callback: options.onTimingSpan,
        span: 'frontend.wallet_ready',
        outcome: 'success',
        durationMs: 0,
        traceContext,
      });
    }
    emitRegistrationTimingSummary(
      createSucceededRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: args.authMethod.kind,
        signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
      }),
    );
    commitSuccessfulWalletAuthentication(args.context, result, args.authMethod.kind);
    afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    const errorCode = registrationErrorCodeFromUnknown(error);
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', initialEventAccountId);
    await cleanUpFailedWalletRegistration(yaoWork);
    if (postTouchIdCompletedAt !== null) {
      emitRegistrationTimingSpan({
        callback: options.onTimingSpan,
        span: 'registration.post_touch_id',
        outcome: 'failure',
        durationMs: performance.now() - postTouchIdCompletedAt,
        traceContext,
      });
    }
    const errorObject = registrationErrorWithCode(errorMessage, errorCode);
    onError?.(errorObject);
    emitRegistrationEvent(onEvent, initialEventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      message: errorMessage,
      interaction: {
        kind: 'passkey_create',
        overlay: 'hide',
      },
      error: {
        ...(errorCode ? { code: errorCode } : {}),
        message: errorMessage,
      },
    });
    const result: RegistrationResult = {
      success: false,
      error: errorMessage,
      ...(errorCode ? { errorCode } : {}),
    };
    emitRegistrationTimingSummary(
      createFailedRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: args.authMethod.kind,
        signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
        errorCode: errorCode || null,
      }),
    );
    afterCall?.(false);
    return result;
  }
}

function requirePasskeyRegistrationIntent(intent: RegistrationIntentV1): RegistrationIntentV1 & {
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
} {
  if (intent.authMethod.kind !== 'passkey') {
    throw new Error('Ed25519 Yao registration requires a passkey registration intent');
  }
  return {
    version: intent.version,
    walletId: intent.walletId,
    authMethod: intent.authMethod,
    signerSelection: intent.signerSelection,
    ...(intent.runtimePolicyScope ? { runtimePolicyScope: intent.runtimePolicyScope } : {}),
    nonceB64u: intent.nonceB64u,
  };
}

function requireEd25519YaoRegistrationPublicResultMatches(args: {
  clientPublicKey: string;
  finalized: Extract<
    WalletRegistrationFinalizeResponse,
    { kind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa' }
  >;
  expectedRpId: string;
  expectedWalletId: WalletId;
}): { rpId: string; credentialIdB64u: string } {
  if (args.finalized.authMethod.kind !== 'passkey' || args.finalized.rpId !== args.expectedRpId) {
    throw new Error('Ed25519 Yao finalize returned a different passkey authority');
  }
  if (args.finalized.walletId !== args.expectedWalletId) {
    throw new Error('Ed25519 Yao finalize returned a different wallet');
  }
  if (
    args.finalized.ed25519.publicKey !== args.clientPublicKey ||
    args.finalized.ed25519.nearEd25519SigningKeyId !==
      args.finalized.resolvedAccount.nearEd25519SigningKeyId ||
    args.finalized.ed25519.nearAccountId !== args.finalized.resolvedAccount.nearAccountId
  ) {
    throw new Error('Ed25519 Yao finalize returned mismatched signer identity');
  }
  return {
    rpId: args.finalized.rpId,
    credentialIdB64u: args.finalized.authMethod.credentialIdB64u,
  };
}

function requireEmailOtpEd25519YaoRegistrationPublicResultMatches(args: {
  clientPublicKey: string;
  finalized: Extract<
    WalletRegistrationFinalizeResponse,
    { kind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa' }
  >;
  expectedRegistrationAuthorityId: string;
  expectedWalletId: WalletId;
}): void {
  if (
    args.finalized.authMethod.kind !== 'email_otp' ||
    args.finalized.authMethod.registrationAuthorityId !== args.expectedRegistrationAuthorityId
  ) {
    throw new Error('Ed25519 Yao finalize returned a different Email OTP authority');
  }
  if (args.finalized.walletId !== args.expectedWalletId) {
    throw new Error('Ed25519 Yao finalize returned a different wallet');
  }
  if (
    args.finalized.ed25519.publicKey !== args.clientPublicKey ||
    args.finalized.ed25519.nearEd25519SigningKeyId !==
      args.finalized.resolvedAccount.nearEd25519SigningKeyId ||
    args.finalized.ed25519.nearAccountId !== args.finalized.resolvedAccount.nearAccountId
  ) {
    throw new Error('Ed25519 Yao finalize returned mismatched signer identity');
  }
}

type RegisterEmailOtpEd25519YaoWalletOnlyArgs = {
  context: RegistrationWebContext;
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'email_otp' }>;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  signerPlan: RegistrationSignerPlan;
  ed25519Selection: RegistrationNearEd25519SignerPlan;
  options: RegistrationHooksOptions;
  passkeyExecution: Extract<
    RegisterWalletPasskeyExecution,
    { kind: 'collect_during_registration' }
  >;
};

async function registerEmailOtpEd25519YaoWalletOnly(
  args: RegisterEmailOtpEd25519YaoWalletOnlyArgs,
): Promise<RegistrationResult> {
  const { context, options } = args;
  const initialEventAccountId = registrationEventAccountId(
    args.wallet.kind === 'provided' ? String(args.wallet.walletId) : 'wallet-registration',
  );
  const registrationTiming = new RegistrationTimingRecorder(performance.now());
  let yaoWork = RegistrationYaoWork.disabled();

  emitRegistrationEvent(options.onEvent, initialEventAccountId, {
    authMethod: 'email_otp',
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    const finalizeIdempotencyKey = createRegistrationOperationIdempotencyKey(
      'wallet-registration-finalize',
    );
    const prepared = await setupThreeRouteRegistration({
      context,
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      recorder: registrationTiming,
    });
    observeRegistrationWarmup({
      recorder: registrationTiming,
      warmup: prepared.registrationWarmup,
    });
    const { relayerUrl, setup } = prepared;
    const walletId = setup.intent.walletId;
    const eventAccountId = registrationEventAccountId(String(walletId));
    const emailAuthority = await registrationTiming.measure(
      'authProofMs',
      collectEmailOtpRegistrationAuthority.bind(undefined, {
        authMethod: args.authMethod,
        relayUrl: relayerUrl,
        walletId: String(walletId),
        registrationIntentDigestB64u: setup.registrationIntentDigestB64u,
        appSessionJwt: args.authMethod.appSessionJwt,
      }),
    );
    const enrollmentMaterial = startEmailOtpRegistrationEnrollmentMaterial({
      recorder: registrationTiming,
      context,
      authMethod: args.authMethod,
      relayerUrl,
      walletId: String(walletId),
      providerSubject: emailAuthority.providerSubject,
      ed25519YaoFactor: {
        kind: 'ed25519_yao_factor_requested',
        providerSubject: emailAuthority.providerSubject,
      },
      appSessionJwt: args.authMethod.appSessionJwt,
    });
    const recoveryCodeBackup = startEmailOtpRecoveryCodeBackupAfterEnrollmentMaterial({
      recorder: registrationTiming,
      authMethod: args.authMethod,
      relayerUrl,
      walletId: String(walletId),
      enrollmentMaterial,
      registrationAuthorityId: emailAuthority.registrationAuthorityId,
    });

    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const responded = await registrationTiming.measure(
      'walletRegisterStartMs',
      respondWalletRegistration.bind(undefined, {
        relayerUrl,
        registrationCeremonyId: setup.registrationCeremonyId,
        signerPlanKind: 'near_ed25519',
        signedSetup: setup.signedSetup,
        headers: registrationRouteHeaders(),
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      }),
    );
    if (responded.kind !== 'near_ed25519') {
      throw new Error('Ed25519-only registration respond returned a different signer branch');
    }
    yaoWork = startEmailOtpRegistrationYaoWork({
      recorder: registrationTiming,
      context,
      enrollmentMaterial,
      deferredNear: responded.ed25519,
      walletId: String(walletId),
      providerSubject: emailAuthority.providerSubject,
      registrationAuthorityId: emailAuthority.registrationAuthorityId,
      signedSetup: String(setup.signedSetup),
      registrationCeremonyId: setup.registrationCeremonyId,
      relayerUrl,
    });
    const materialForActivate = await requireEmailOtpRegistrationEnrollmentMaterial({
      material: enrollmentMaterial,
      operation: 'activate',
    });
    const emailOtpBackupAck = await resolveEmailOtpBackupAck({
      authMethod: args.authMethod,
      backup: recoveryCodeBackup,
    });
    if (!emailOtpBackupAck) {
      throw new Error('Email OTP registration requires recovery backup acknowledgment');
    }
    /* Activate before awaiting Yao: the wallet becomes durable in
       `near_pending` and registration can return, while the computation that
       produces its sole signer is still running. */
    const activated = await activateWalletRegistration({
      relayerUrl,
      registrationCeremonyId: setup.registrationCeremonyId,
      signerPlanKind: 'near_ed25519',
      signedSetup: setup.signedSetup,
      headers: registrationRouteHeaders(),
      idempotencyKey: finalizeIdempotencyKey,
      emailOtpEnrollment: materialForActivate.emailOtpEnrollment,
      ...(emailOtpBackupAck ? { emailOtpBackupAck } : {}),
    });
    if (
      activated.kind !== 'near_ed25519' ||
      activated.nearProvisioning?.status !== 'near_pending'
    ) {
      throw new Error('Ed25519-only activate did not return a wallet pending NEAR provisioning');
    }
    const pending = await yaoWork.requirePending();
    const clientPublicKey = pending.publicKey();
    const finalized = await registrationTiming.measure(
      'walletRegisterFinalizeMs',
      completeWalletRegistrationNearProvisioning.bind(undefined, {
        relayerUrl,
        registrationCeremonyId: setup.registrationCeremonyId,
        signedSetup: setup.signedSetup,
        headers: registrationRouteHeaders(),
        /* Its own key: a separate effect from activate's. */
        idempotencyKey: createRegistrationOperationIdempotencyKey(
          'wallet-registration-near-provisioning',
        ),
        ed25519: { activationReference: pending.activationReference() },
        auth: {
          kind: 'email_otp',
          enrollment: materialForActivate.emailOtpEnrollment,
          backupAck: emailOtpBackupAck,
        },
      }),
    );
    if (!finalized.ok) {
      throw new Error('Deferred NEAR provisioning did not complete');
    }
    registrationTiming.captureRouteDiagnostics(finalized.registrationDiagnostics);
    if (finalized.kind !== 'near_ed25519') {
      throw new Error('Wallet registration finalize returned a different signer branch');
    }
    if (!isEmailOtpWalletRegistrationFinalizeResponse(finalized)) {
      throw new Error('Email OTP registration finalize returned a different auth method');
    }
    const finalizedEmailOtpAppSessionBinding = emailOtpAppSessionBindingFromJwt({
      walletId: finalized.walletId,
      appSessionJwt: finalized.appSessionJwt,
    });
    if (finalizedEmailOtpAppSessionBinding.providerSubject !== emailAuthority.providerSubject) {
      throw new Error('Finalized Email OTP app session belongs to a different provider');
    }
    if (finalized.ed25519.signerSlot !== args.ed25519Selection.signerSlot) {
      throw new Error('Ed25519 Yao finalize returned a different signer slot');
    }
    requireEmailOtpEd25519YaoRegistrationPublicResultMatches({
      clientPublicKey,
      finalized,
      expectedRegistrationAuthorityId: emailAuthority.registrationAuthorityId,
      expectedWalletId: walletId,
    });
    const persistenceAuth = await buildRegistrationPersistenceAuth({
      authMethod: args.authMethod,
      configs: context.configs,
      walletId: toWalletId(finalized.walletId),
      finalized,
      passkeyAuthority: null,
      email: emailAuthority.email,
      providerSubject: emailAuthority.providerSubject,
      registrationAuthorityId: emailAuthority.registrationAuthorityId,
    });
    if (persistenceAuth.kind !== 'email_otp') {
      throw new Error('Email OTP Ed25519 registration produced a different persistence authority');
    }

    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED,
      status: 'succeeded',
    });
    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    const stored = await context.signingEngine.storeWalletEmailOtpEd25519RegistrationData({
      walletId: finalized.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
      email: persistenceAuth.email,
      registrationAuthorityId: persistenceAuth.registrationAuthorityId,
      signerSlot: finalized.ed25519.signerSlot,
      operationalPublicKey: clientPublicKey,
      relayerKeyId: finalized.ed25519.relayerKeyId,
      keyVersion: finalized.ed25519.keyVersion,
      participantIds: [...finalized.ed25519.participantIds],
    });
    if (stored.signerSlot !== finalized.ed25519.signerSlot) {
      throw new Error('Ed25519 Yao registration persisted a different signer slot');
    }
    const materialFacts = registrationEd25519MaterialFacts({
      deferredNear: responded.ed25519,
      finalized: finalized.ed25519,
      walletId,
      expectedRuntimePolicyScope: normalizeRuntimePolicyScope(setup.intent.runtimePolicyScope),
    });
    await context.signingEngine.activateAuthenticatedWalletState({
      walletId: finalized.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      signerSlot: finalized.ed25519.signerSlot,
      nearClient: context.nearClient,
    });
    const metadata = await yaoWork.persistMaterial({
      kind: 'email_otp',
      facts: materialFacts,
      expectedOperationalPublicKey: clientPublicKey,
      providerSubject: emailOtpAuthContextProviderUserId(persistenceAuth.emailOtpAuthContext),
      sessionPolicy: {
        thresholdSessionId: registrationEstablishedEd25519Session(
          finalized.registrationEstablishedSession,
        ).thresholdSessionId,
        expiresAtMs: finalized.registrationEstablishedSession.expiresAtMs,
        remainingUses: finalized.registrationEstablishedSession.remainingUses,
      },
    });
    const walletSessionState = await buildRegistrationEmailOtpEd25519SessionState({
      registrationEstablishedSession: finalized.registrationEstablishedSession,
      walletId: toWalletId(finalized.walletId),
      nearAccountId: finalized.ed25519.nearAccountId,
      nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
      thresholdSessionId: materialFacts.identity.thresholdSessionId,
      runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
      signerSlot: finalized.ed25519.signerSlot,
      relayerUrl,
      emailOtpAuthContext: persistenceAuth.emailOtpAuthContext,
    });
    const material = {
      activeClient: yaoWork.persistedEmailOtpYaoActiveClient(),
      facts: nearEd25519YaoOperationMaterialFacts(walletSessionState),
    };
    await context.signingEngine.persistEmailOtpEd25519YaoCapabilityForRefreshInternal({
      material,
      walletSessionState,
      publicationContext: {
        rpId: context.signingEngine.getRpId(),
        provider: emailOtpAuthContextProvider(persistenceAuth.emailOtpAuthContext),
        providerSubjectId: emailOtpAuthContextProviderUserId(persistenceAuth.emailOtpAuthContext),
        emailHashHex: emailOtpAuthContextEmailHashHex(persistenceAuth.emailOtpAuthContext),
        materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
      },
    });
    await context.signingEngine.activateVerifiedNearEd25519YaoMaterial(material);
    await context.signingEngine.upsertEd25519YaoPublicCapabilityLaneReference({
      walletId: finalized.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      thresholdSessionId: materialFacts.identity.thresholdSessionId,
      runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
      materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
      auth: {
        kind: 'email_otp',
        providerSubjectId: finalizedEmailOtpAppSessionBinding.providerSubject,
      },
      nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
        finalized.ed25519.nearEd25519SigningKeyId,
      ),
      signerSlot: finalized.ed25519.signerSlot,
    });
    yaoWork.releasePersistedEmailOtpYaoActiveClient();
    await persistActiveWalletSessionAuthorizationFromRegistration(walletSessionAuthorizations, {
      authority: await walletAuthAuthorityRef({
        authority: buildEmailOtpWalletAuthAuthority({
          walletId: finalized.walletId,
          provider: emailOtpAuthContextProvider(persistenceAuth.emailOtpAuthContext),
          providerUserId: emailOtpAuthContextProviderUserId(persistenceAuth.emailOtpAuthContext),
          emailHashHex: emailOtpAuthContextEmailHashHex(persistenceAuth.emailOtpAuthContext),
        }),
      }),
      authMethod: 'email_otp',
      session: finalized.registrationEstablishedSession,
    });
    rememberEmailOtpAppSessionForRegisteredWallet({
      context,
      binding: finalizedEmailOtpAppSessionBinding,
    });
    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
    });
    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });
    const result: RegistrationResult = {
      success: true,
      kind: 'wallet_registered',
      walletId: finalized.walletId,
      capabilities: [
        {
          kind: 'near_ed25519',
          accountProvisioning: finalized.accountProvisioning,
          resolvedAccount: finalized.resolvedAccount,
          nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
            finalized.ed25519.nearEd25519SigningKeyId,
          ),
          operationalPublicKey: clientPublicKey,
          nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
          transactionId:
            finalized.resolvedAccount.kind === 'sponsored_named_account'
              ? finalized.resolvedAccount.transactionHash
              : null,
        },
      ],
    };
    emitRegistrationTimingSummary(
      createSucceededRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: 'email_otp',
        signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
      }),
    );
    commitSuccessfulWalletAuthentication(context, result, 'email_otp');
    options.afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    await cleanUpFailedWalletRegistration(yaoWork);
    const errorCode = registrationErrorCodeFromUnknown(error);
    const message = getUserFriendlyErrorMessage(error, 'registration', initialEventAccountId);
    options.onError?.(registrationErrorWithCode(message, errorCode));
    emitRegistrationEvent(options.onEvent, initialEventAccountId, {
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      message,
      error: { ...(errorCode ? { code: errorCode } : {}), message },
    });
    const result: RegistrationResult = {
      success: false,
      error: message,
      ...(errorCode ? { errorCode } : {}),
    };
    emitRegistrationTimingSummary(
      createFailedRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: 'email_otp',
        signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
        errorCode: errorCode || null,
      }),
    );
    options.afterCall?.(false);
    return result;
  }
}

async function registerPasskeyEd25519YaoWalletOnly(args: {
  context: RegistrationWebContext;
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  signerPlan: RegistrationSignerPlan;
  ed25519Selection: RegistrationNearEd25519SignerPlan;
  options: RegistrationHooksOptions;
  passkeyExecution: RegisterWalletPasskeyExecution;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
  const { context, options } = args;
  const initialEventAccountId = registrationEventAccountId(
    args.wallet.kind === 'provided' ? String(args.wallet.walletId) : 'wallet-registration',
  );
  const traceContext = createRouterAbTraceContextV1();
  let postTouchIdCompletedAt: number | null = null;
  emitRegistrationEvent(options.onEvent, initialEventAccountId, {
    authMethod: 'passkey',
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });
  try {
    const finalizeIdempotencyKey = createRegistrationOperationIdempotencyKey(
      'wallet-registration-finalize',
    );
    const registrationTiming = new RegistrationTimingRecorder(performance.now());
    const prepared = await setupRegistrationForPasskeyExecution({
      context,
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      recorder: registrationTiming,
      passkeyExecution: args.passkeyExecution,
    });
    const { relayerUrl, setup } = prepared;
    const intent = requirePasskeyRegistrationIntent(setup.intent);
    const eventAccountId = registrationEventAccountId(String(intent.walletId));
    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
      status: 'waiting_for_user',
      interaction: { kind: 'passkey_create', overlay: 'show' },
    });
    const passkeyAuthority = await resolvePasskeyRegistrationAuthority({
      context,
      walletId: intent.walletId,
      signerSlot: args.ed25519Selection.signerSlot,
      registrationIntentDigestB64u: setup.registrationIntentDigestB64u,
      options,
      confirmationConfigOverride: {
        uiMode: 'modal',
        behavior: 'requireClick',
        ...(args.confirmationConfigOverride ?? options.confirmationConfig ?? {}),
      },
      passkeyExecution: args.passkeyExecution,
    });
    postTouchIdCompletedAt = performance.now();
    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
      status: 'succeeded',
      interaction: { kind: 'passkey_create', overlay: 'hide' },
    });
    const responded = await respondWalletRegistration({
      relayerUrl,
      registrationCeremonyId: setup.registrationCeremonyId,
      signerPlanKind: 'near_ed25519',
      signedSetup: setup.signedSetup,
      headers: registrationRouteHeaders(traceContext),
      kind: 'passkey',
      webauthnRegistration: passkeyAuthority.webauthnRegistration,
    });
    if (responded.kind !== 'near_ed25519') {
      throw new Error('Ed25519-only registration respond returned a different signer branch');
    }
    const yao = await registerVerifiedPasskeyEd25519YaoV1({
      kind: 'verified_passkey_ed25519_yao_registration_input_v1',
      verifiedIntent: {
        kind: 'verified_passkey_registration_intent_v1',
        intent,
        registrationIntentDigestB64u: setup.registrationIntentDigestB64u,
        registrationBearerToken: String(setup.signedSetup),
        registrationCeremonyId: setup.registrationCeremonyId,
      },
      verifiedAuthority: {
        kind: 'verified_passkey_registration_authority_v1',
        walletId: intent.walletId,
        registrationIntentDigestB64u: setup.registrationIntentDigestB64u,
        credentialIdB64u: String(
          passkeyAuthority.credential.rawId || passkeyAuthority.credential.id || '',
        ).trim(),
        ownedPasskeyPrfFirst: base64UrlDecode(passkeyAuthority.prfFirstB64u),
      },
      admissionRequest: responded.ed25519.admissionRequest,
      admissionReceipt: responded.ed25519.admissionReceipt,
      httpTransport: {
        kind: 'passkey_ed25519_yao_http_transport_v1',
        routerOrigin: new URL(relayerUrl).origin,
        fetch: globalThis.fetch,
        traceContext,
      },
    });
    if (!yao.ok) throw new Error(yao.message);
    const pending = yao.registration;
    /* Activate before the Yao computation is awaited. The wallet becomes
       durable in `near_pending` with no signer yet; being that signer's only
       source is not a reason to hold registration open, and the completion
       route installs it once the computation finishes. */
    const activated = await activateWalletRegistration({
      relayerUrl,
      registrationCeremonyId: setup.registrationCeremonyId,
      signerPlanKind: 'near_ed25519',
      signedSetup: setup.signedSetup,
      headers: registrationRouteHeaders(traceContext),
      idempotencyKey: finalizeIdempotencyKey,
    });
    if (
      activated.kind !== 'near_ed25519' ||
      activated.nearProvisioning?.status !== 'near_pending'
    ) {
      throw new Error('Ed25519-only activate did not return a wallet pending NEAR provisioning');
    }
    if (activated.authMethod.kind === 'passkey') {
      rememberPasskeyAppSessionForRegisteredWallet({
        appSessionJwt: activated.appSessionJwt,
        relayerUrl,
        walletId: activated.walletId,
      });
    }
    try {
      const clientPublicKey = pending.publicKey();
      /* Route 4 — its own idempotency key: a separate effect from activate's,
         and sharing one would let a retry replay activate's commit. */
      const finalized = await completeWalletRegistrationNearProvisioning({
        relayerUrl,
        registrationCeremonyId: setup.registrationCeremonyId,
        signedSetup: setup.signedSetup,
        headers: registrationRouteHeaders(traceContext),
        idempotencyKey: createRegistrationOperationIdempotencyKey(
          'wallet-registration-near-provisioning',
        ),
        ed25519: { activationReference: pending.activationReference() },
        auth: { kind: 'passkey' },
      });
      if (!finalized.ok || finalized.kind !== 'near_ed25519') {
        throw new Error('Deferred NEAR provisioning returned a different signer branch');
      }
      const finalizedPasskey = requireEd25519YaoRegistrationPublicResultMatches({
        clientPublicKey,
        finalized,
        expectedRpId: args.authMethod.rpId,
        expectedWalletId: intent.walletId,
      });
      const stored = await context.signingEngine.storeWalletEd25519RegistrationData({
        walletId: finalized.walletId,
        nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        rpId: requireWebAuthnRpId(finalizedPasskey.rpId),
        credential: passkeyAuthority.credential,
        credentialPublicKeyB64u: requireFinalizedPasskeyCredentialPublicKeyB64u({
          finalized,
          credential: passkeyAuthority.credential,
        }),
        signerSlot: finalized.ed25519.signerSlot,
        operationalPublicKey: clientPublicKey,
        relayerKeyId: finalized.ed25519.relayerKeyId,
        keyVersion: finalized.ed25519.keyVersion,
        participantIds: [...finalized.ed25519.participantIds],
      });
      if (stored.signerSlot !== finalized.ed25519.signerSlot) {
        throw new Error('Ed25519 Yao registration persisted a different signer slot');
      }
      await context.signingEngine.activateAuthenticatedWalletState({
        walletId: finalized.walletId,
        nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
        signerSlot: finalized.ed25519.signerSlot,
        nearClient: context.nearClient,
      });
      const materialFacts = registrationEd25519MaterialFacts({
        deferredNear: responded.ed25519,
        finalized: finalized.ed25519,
        walletId: intent.walletId,
        expectedRuntimePolicyScope: normalizeRuntimePolicyScope(intent.runtimePolicyScope),
      });
      const metadata = await persistPasskeyRegistrationEd25519Material({
        pending,
        facts: materialFacts,
        rpId: finalizedPasskey.rpId,
        credentialIdB64u: finalizedPasskey.credentialIdB64u,
        passkeyPrfFirstB64u: passkeyAuthority.prfFirstB64u,
      });
      await context.signingEngine.upsertEd25519YaoPublicCapabilityLaneReference({
        walletId: finalized.walletId,
        nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
        thresholdSessionId: materialFacts.identity.thresholdSessionId,
        runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
        materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
        auth: {
          kind: 'passkey',
          rpId: toRpId(finalizedPasskey.rpId),
          credentialIdB64u: finalizedPasskey.credentialIdB64u,
        },
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
          finalized.ed25519.nearEd25519SigningKeyId,
        ),
        signerSlot: finalized.ed25519.signerSlot,
      });
      await persistRegistrationPasskeyEd25519SealedRuntime({
        context,
        registrationEstablishedSession: finalized.registrationEstablishedSession,
        walletId: toWalletId(finalized.walletId),
        nearAccountId: finalized.ed25519.nearAccountId,
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        thresholdSessionId: materialFacts.identity.thresholdSessionId,
        runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
        signerSlot: finalized.ed25519.signerSlot,
        relayerUrl,
        auth: {
          kind: 'passkey',
          rpId: finalizedPasskey.rpId,
          credential: passkeyAuthority.credential,
          credentialPublicKeyB64u: requireFinalizedPasskeyCredentialPublicKeyB64u({
            finalized,
            credential: passkeyAuthority.credential,
          }),
          passkeyPrfFirstB64u: passkeyAuthority.prfFirstB64u,
        },
        metadata,
      });
      await persistActiveWalletSessionAuthorizationFromRegistration(walletSessionAuthorizations, {
        authority: await walletAuthAuthorityRef({
          authority: passkeyWalletAuthAuthorityFromCredential({
            walletId: finalized.walletId,
            rpId: finalizedPasskey.rpId,
            credential: passkeyAuthority.credential,
          }),
        }),
        authMethod: 'passkey',
        session: finalized.registrationEstablishedSession,
      });
      emitRegistrationEvent(options.onEvent, eventAccountId, {
        authMethod: 'passkey',
        phase: RegistrationEventPhase.STEP_11_COMPLETED,
        status: 'succeeded',
      });
      if (postTouchIdCompletedAt !== null) {
        const walletReadyAt = performance.now();
        emitRegistrationTimingSpan({
          callback: options.onTimingSpan,
          span: 'registration.post_touch_id',
          outcome: 'success',
          durationMs: walletReadyAt - postTouchIdCompletedAt,
          traceContext,
        });
        emitRegistrationTimingSpan({
          callback: options.onTimingSpan,
          span: 'frontend.wallet_ready',
          outcome: 'success',
          durationMs: 0,
          traceContext,
        });
      }
      const result: RegistrationResult = {
        success: true,
        kind: 'wallet_registered',
        walletId: finalized.walletId,
        capabilities: [
          {
            kind: 'near_ed25519',
            accountProvisioning: finalized.accountProvisioning,
            resolvedAccount: finalized.resolvedAccount,
            nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
              finalized.ed25519.nearEd25519SigningKeyId,
            ),
            operationalPublicKey: clientPublicKey,
            nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
            transactionId:
              finalized.resolvedAccount.kind === 'sponsored_named_account'
                ? finalized.resolvedAccount.transactionHash
                : null,
          },
        ],
      };
      commitSuccessfulWalletAuthentication(context, result, 'passkey');
      options.afterCall?.(true, result);
      return result;
    } catch (error) {
      pending.dispose();
      throw error;
    }
  } catch (error) {
    const errorCode = registrationErrorCodeFromUnknown(error);
    const message = getUserFriendlyErrorMessage(error, 'registration', initialEventAccountId);
    if (postTouchIdCompletedAt !== null) {
      emitRegistrationTimingSpan({
        callback: options.onTimingSpan,
        span: 'registration.post_touch_id',
        outcome: 'failure',
        durationMs: performance.now() - postTouchIdCompletedAt,
        traceContext,
      });
    }
    options.onError?.(registrationErrorWithCode(message, errorCode));
    emitRegistrationEvent(options.onEvent, initialEventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      message,
      interaction: { kind: 'passkey_create', overlay: 'hide' },
      error: { ...(errorCode ? { code: errorCode } : {}), message },
    });
    const result: RegistrationResult = {
      success: false,
      error: message,
      ...(errorCode ? { errorCode } : {}),
    };
    options.afterCall?.(false);
    return result;
  }
}

async function registerWalletInternal(
  args: RegisterWalletOperationInput & { passkeyExecution: RegisterWalletPasskeyExecution },
): Promise<RegistrationResult> {
  const signerPlan = registrationSignerPlanFromSignerSet(args.signerSelection);
  const ed25519Branch = findRegistrationSignerPlanNearEd25519Branch(signerPlan);
  if (ed25519Branch) {
    const ecdsaBranch = findRegistrationSignerPlanEvmFamilyEcdsaBranch(signerPlan);
    if (ecdsaBranch) {
      const result = await registerEcdsaOrMixedWallet({
        kind: 'near_ed25519_and_evm_family_ecdsa',
        context: args.context,
        authMethod: args.authMethod,
        wallet: args.wallet,
        signerSelection: args.signerSelection,
        signerPlan,
        ed25519Selection: ed25519Branch,
        ecdsaSelection: ecdsaBranch,
        options: args.options,
        passkeyExecution: args.passkeyExecution,
        ...(args.confirmationConfigOverride
          ? { confirmationConfigOverride: args.confirmationConfigOverride }
          : {}),
      });
      return result;
    }
    if (args.authMethod.kind === 'email_otp') {
      if (args.passkeyExecution.kind !== 'collect_during_registration') {
        throw new Error('Prepared registration authority requires passkey authentication');
      }
      const result = await registerEmailOtpEd25519YaoWalletOnly({
        context: args.context,
        authMethod: args.authMethod,
        wallet: args.wallet,
        signerSelection: args.signerSelection,
        signerPlan,
        ed25519Selection: ed25519Branch,
        options: args.options,
        passkeyExecution: args.passkeyExecution,
      });
      return result;
    }
    return await registerPasskeyEd25519YaoWalletOnly({
      context: args.context,
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      signerPlan,
      ed25519Selection: ed25519Branch,
      options: args.options,
      passkeyExecution: args.passkeyExecution,
      ...(args.confirmationConfigOverride
        ? { confirmationConfigOverride: args.confirmationConfigOverride }
        : {}),
    });
  }
  const ecdsaBranch = findRegistrationSignerPlanEvmFamilyEcdsaBranch(signerPlan);
  if (!ecdsaBranch) throw new Error('Wallet registration requires an ECDSA signer branch');
  const result = await registerEcdsaOrMixedWallet({
    kind: 'evm_family_ecdsa',
    context: args.context,
    authMethod: args.authMethod,
    wallet: args.wallet,
    signerSelection: args.signerSelection,
    signerPlan,
    ecdsaSelection: ecdsaBranch,
    options: args.options,
    passkeyExecution: args.passkeyExecution,
    ...(args.confirmationConfigOverride
      ? { confirmationConfigOverride: args.confirmationConfigOverride }
      : {}),
  });
  return result;
}

function rememberEmailOtpAppSessionForRegisteredWallet(args: {
  context: RegistrationWebContext;
  binding: EmailOtpAppSessionBinding;
}): void {
  args.context.signingEngine.rememberEmailOtpAppSessionBinding(args.binding);
}

function rememberPasskeyAppSessionForRegisteredWallet(args: {
  appSessionJwt: string | undefined;
  relayerUrl: string;
  walletId: string;
}): void {
  if (typeof window === 'undefined') return;
  if (!args.appSessionJwt) {
    throw new Error('Passkey registration activate response is missing appSessionJwt');
  }
  rememberWalletOriginAppSession({
    appSessionJwt: args.appSessionJwt,
    relayUrl: args.relayerUrl,
    walletId: args.walletId,
  });
}

function commitSuccessfulWalletAuthentication(
  context: RegistrationWebContext,
  result: Extract<RegistrationResult, { success: true }>,
  authMethod: RegistrationAuthMethodInput['kind'],
): void {
  context.signingEngine.setWalletAuthenticated({
    kind: 'authenticated',
    walletId: result.walletId,
    authMethod,
  });
}

export async function registerWallet(
  args: RegisterWalletOperationInput,
): Promise<RegistrationResult> {
  try {
    const result = await registerWalletInternal({
      context: args.context,
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      options: args.options,
      authenticatorOptions: args.authenticatorOptions,
      ...(args.confirmationConfigOverride
        ? { confirmationConfigOverride: args.confirmationConfigOverride }
        : {}),
      passkeyExecution: {
        kind: 'collect_during_registration',
      },
    });
    return result;
  } finally {
    args.context.signingEngine.closeRegistrationPreparationModal();
  }
}

type AddWalletSignerOperationArgs = {
  context: RegistrationWebContext;
  walletId: WalletId | string;
  rpId: string;
  signerSelection: AddSignerSelection;
  options: RegistrationHooksOptions;
};

type AddWalletSignerBranchInput = {
  context: RegistrationWebContext;
  walletId: WalletId;
  rpId: WebAuthnRpId;
  relayerUrl: string;
  intentResponse: Awaited<ReturnType<typeof createWalletAddSignerIntent>>;
  credential: WebAuthnAuthenticationCredential;
  credentialIdB64u: string;
  passkeyPrfFirstB64u: string;
  eventAccountId: string;
  onEvent: RegistrationHooksOptions['onEvent'];
};

function emitAddSignerEventSafely(
  onEvent: RegistrationHooksOptions['onEvent'],
  accountId: string,
  event: EmitRegistrationEventInput,
): void {
  try {
    emitRegistrationEvent(onEvent, accountId, event);
  } catch {}
}

function notifyAddSignerErrorSafely(
  onError: RegistrationHooksOptions['onError'],
  error: Error,
): void {
  try {
    onError?.(error);
  } catch {}
}

function notifyAddSignerAfterCallSafely(
  afterCall: RegistrationHooksOptions['afterCall'],
  success: boolean,
  result?: RegistrationResult,
): void {
  try {
    if (success && result) afterCall?.(true, result);
    else afterCall?.(false);
  } catch {}
}

function addSignerAllowCredentials(
  authenticators: Awaited<ReturnType<typeof IndexedDBManager.listProfileAuthenticators>>,
): Array<{ id: string; type: 'public-key'; transports: AuthenticatorTransport[] }> {
  const credentials: Array<{
    id: string;
    type: 'public-key';
    transports: AuthenticatorTransport[];
  }> = [];
  for (const authenticator of authenticators) {
    const credentialId = String(authenticator.credentialId || '').trim();
    if (!credentialId) continue;
    credentials.push({
      id: credentialId,
      type: 'public-key',
      transports: webAuthnTransportsFromRaw(authenticator.transports),
    });
  }
  if (credentials.length === 0) {
    throw new Error('Wallet add-signer requires an existing passkey credential');
  }
  return credentials;
}

function requireSelectedAddSignerCredentialId(
  credential: WebAuthnAuthenticationCredential,
  allowCredentials: readonly { id: string }[],
): string {
  const id = String(credential.id || '').trim();
  const rawId = String(credential.rawId || '').trim();
  if (!id || !rawId || id !== rawId) {
    throw new Error('Wallet add-signer selected an invalid passkey credential identity');
  }
  for (const allowed of allowCredentials) {
    if (allowed.id === rawId) return rawId;
  }
  throw new Error('Wallet add-signer selected a passkey outside the authorized wallet');
}

async function requireMatchingStartedAddSignerIntent(args: {
  started: WalletAddSignerStartResponse;
  walletId: WalletId;
  expectedDigestB64u: string;
}): Promise<void> {
  if (args.started.intent.walletId !== args.walletId) {
    throw new Error('Wallet add-signer start returned a different wallet');
  }
  const returnedDigest = await computeAddSignerIntentDigest(args.started.intent);
  if (returnedDigest !== args.expectedDigestB64u) {
    throw new Error('Wallet add-signer start returned a different intent');
  }
  if (!String(args.started.addSignerCeremonyId || '').trim()) {
    throw new Error('Wallet add-signer start returned an invalid ceremony ID');
  }
}

function sameParticipantIds(left: readonly number[], right: readonly number[]): boolean {
  return left.length === 2 && right.length === 2 && left[0] === right[0] && left[1] === right[1];
}

function sameRuntimePolicyScope(
  left: ReturnType<typeof normalizeRuntimePolicyScope>,
  right: ReturnType<typeof normalizeRuntimePolicyScope>,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function requireVerifiedEd25519AddSignerFinalize(args: {
  finalized: Extract<WalletAddSignerFinalizeResponse, { kind: 'near_ed25519' }>;
  started: Extract<WalletAddSignerStartResponse, { kind: 'near_ed25519' }>;
  walletId: WalletId;
  rpId: WebAuthnRpId;
  credentialIdB64u: string;
  clientPublicKey: string;
}): Extract<WalletAddSignerFinalizeResponse, { kind: 'near_ed25519' }> {
  const selection = args.started.intent.signerSelection;
  if (selection.mode !== 'ed25519') {
    throw new Error('Wallet add-signer start intent changed signer branch');
  }
  const requested = selection.ed25519;
  const admission = args.started.ed25519.admissionRequest;
  const finalized = args.finalized;
  const signer = finalized.ed25519;
  const expectedNearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(
    args.clientPublicKey,
  );
  if (
    finalized.walletId !== args.walletId ||
    finalized.rpId !== args.rpId ||
    finalized.credentialIdB64u !== args.credentialIdB64u ||
    signer.publicKey !== args.clientPublicKey ||
    signer.nearAccountId !== expectedNearAccountId ||
    signer.signerSlot !== requested.signerSlot ||
    signer.keyVersion !== requested.keyVersion ||
    signer.recoveryExportCapable !== true ||
    !sameParticipantIds(signer.participantIds, requested.participantIds) ||
    signer.nearEd25519SigningKeyId !== admission.application_binding.near_ed25519_signing_key_id ||
    signer.relayerKeyId !== admission.scope.signing_worker_id ||
    admission.application_binding.wallet_id !== args.walletId ||
    admission.application_binding.key_creation_signer_slot !== requested.signerSlot
  ) {
    throw new Error('Wallet add-signer finalize returned mismatched Ed25519 Yao identity');
  }
  return finalized;
}

function verifiedEd25519AddSignerIntent(
  started: Extract<WalletAddSignerStartResponse, { kind: 'near_ed25519' }>,
): Omit<typeof started.intent, 'signerSelection'> & {
  signerSelection: Extract<AddSignerSelection, { mode: 'ed25519' }>;
} {
  const selection = started.intent.signerSelection;
  if (selection.mode !== 'ed25519') {
    throw new Error('Wallet add-signer start intent changed signer branch');
  }
  return {
    version: started.intent.version,
    walletId: started.intent.walletId,
    signerSelection: selection,
    ...(started.intent.runtimePolicyScope
      ? { runtimePolicyScope: started.intent.runtimePolicyScope }
      : {}),
    nonceB64u: started.intent.nonceB64u,
  };
}

async function addPasskeyEd25519YaoWalletSigner(
  input: AddWalletSignerBranchInput & {
    started: Extract<WalletAddSignerStartResponse, { kind: 'near_ed25519' }>;
  },
): Promise<RegistrationResult> {
  const selection = input.started.intent.signerSelection;
  if (selection.mode !== 'ed25519') {
    throw new Error('Wallet add-signer start returned a different signer branch');
  }
  const ownedPasskeyPrfFirst = base64UrlDecode(input.passkeyPrfFirstB64u);
  let pending: ProductEd25519YaoPendingRegistrationPortV1 | null = null;
  let persistedMaterialTarget: { nearAccountId: string; signerSlot: number } | null = null;
  let persistedSignerRollbackReceipt: StoreWalletSignerFinalizeRollbackReceipt | null = null;
  try {
    const yao = await registerVerifiedPasskeyEd25519YaoAddSignerV1({
      kind: 'verified_passkey_ed25519_yao_add_signer_input_v1',
      verifiedIntent: {
        kind: 'verified_passkey_ed25519_add_signer_intent_v1',
        intent: verifiedEd25519AddSignerIntent(input.started),
        addSignerIntentDigestB64u: input.intentResponse.addSignerIntentDigestB64u,
        addSignerIntentGrant: input.intentResponse.addSignerIntentGrant,
        addSignerCeremonyId: input.started.addSignerCeremonyId,
      },
      verifiedAuthority: {
        kind: 'verified_passkey_ed25519_add_signer_authority_v1',
        walletId: input.walletId,
        addSignerIntentDigestB64u: input.intentResponse.addSignerIntentDigestB64u,
        credentialIdB64u: input.credentialIdB64u,
        ownedPasskeyPrfFirst,
      },
      admissionRequest: input.started.ed25519.admissionRequest,
      httpTransport: {
        kind: 'passkey_ed25519_yao_http_transport_v1',
        routerOrigin: new URL(input.relayerUrl).origin,
        fetch: globalThis.fetch,
      },
    });
    if (!yao.ok) throw new Error(yao.message);
    pending = yao.registration;
    const clientPublicKey = pending.publicKey();
    const finalizedRaw = await finalizeWalletAddSigner({
      relayerUrl: input.relayerUrl,
      walletId: input.walletId,
      addSignerCeremonyId: input.started.addSignerCeremonyId,
      idempotencyKey: createRegistrationOperationIdempotencyKey(
        'wallet-ed25519-add-signer-finalize',
      ),
      kind: 'near_ed25519',
      ed25519: { activationReference: pending.activationReference() },
    });
    if (finalizedRaw.kind !== 'near_ed25519') {
      throw new Error('Wallet add-signer finalize returned a different signer branch');
    }
    const finalized = requireVerifiedEd25519AddSignerFinalize({
      finalized: finalizedRaw,
      started: input.started,
      walletId: input.walletId,
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      clientPublicKey,
    });

    emitAddSignerEventSafely(input.onEvent, input.eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    const stored = await input.context.signingEngine.finalizeWalletEd25519SignerRegistration({
      walletId: input.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
      auth: { kind: 'passkey', credential: input.credential },
      signerSlot: finalized.ed25519.signerSlot,
      operationalPublicKey: clientPublicKey,
      relayerKeyId: finalized.ed25519.relayerKeyId,
      keyVersion: finalized.ed25519.keyVersion,
      participantIds: [...finalized.ed25519.participantIds],
    });
    if (stored.signerSlot !== finalized.ed25519.signerSlot) {
      throw new Error('Wallet add-signer persisted a different Ed25519 signer slot');
    }
    persistedSignerRollbackReceipt = stored.rollbackReceipt;
    const admission = input.started.ed25519.admissionRequest;
    const thresholdSessionId = parseThresholdEd25519SessionId(admission.scope.threshold_session_id);
    if (!thresholdSessionId.ok) {
      throw new Error('Wallet add-signer threshold-session identity is invalid');
    }
    const metadata = await persistPasskeyRegistrationEd25519Material({
      pending,
      facts: {
        identity: {
          walletId: finalized.walletId,
          nearAccountId: finalized.ed25519.nearAccountId,
          nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
          thresholdSessionId: thresholdSessionId.value,
          signerSlot: finalized.ed25519.signerSlot,
          signingRootId: admission.application_binding.signing_root_id,
          signingRootVersion: admission.scope.root_share_epoch,
          signingWorkerId: admission.scope.signing_worker_id,
        },
        stableServerScope: {
          relayerKeyId: finalized.ed25519.relayerKeyId,
          participantIds: finalized.ed25519.participantIds,
          runtimePolicyScope: normalizeRuntimePolicyScope(input.started.intent.runtimePolicyScope),
          routerAbNormalSigning: {
            kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
            signingWorkerId: admission.scope.signing_worker_id,
          },
        },
      },
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      passkeyPrfFirstB64u: input.passkeyPrfFirstB64u,
    });
    await input.context.signingEngine.upsertEd25519YaoPublicCapabilityLaneReference({
      walletId: finalized.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      thresholdSessionId: thresholdSessionId.value,
      runtimePolicyScope: normalizeRuntimePolicyScope(input.started.intent.runtimePolicyScope),
      materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
      auth: {
        kind: 'passkey',
        rpId: toRpId(input.rpId),
        credentialIdB64u: input.credentialIdB64u,
      },
      nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
        finalized.ed25519.nearEd25519SigningKeyId,
      ),
      signerSlot: finalized.ed25519.signerSlot,
    });
    persistedMaterialTarget = {
      nearAccountId: finalized.ed25519.nearAccountId,
      signerSlot: finalized.ed25519.signerSlot,
    };
    await pending.dispose();
    pending = null;
    persistedSignerRollbackReceipt = null;
    emitAddSignerEventSafely(input.onEvent, input.eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
    });
    return {
      success: true,
      kind: 'wallet_signer_added',
      walletId: finalized.walletId,
      capabilities: [
        {
          kind: 'near_ed25519',
          nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
            finalized.ed25519.nearEd25519SigningKeyId,
          ),
          operationalPublicKey: clientPublicKey,
          nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
        },
      ],
    };
  } catch (error: unknown) {
    pending?.dispose();
    const cleanupErrors: string[] = [];
    if (persistedMaterialTarget) {
      try {
        await deletePasskeyEd25519YaoSignerMaterialV1({
          store: IndexedDBManager,
          nearAccountId: persistedMaterialTarget.nearAccountId,
          signerSlot: persistedMaterialTarget.signerSlot,
        });
      } catch (cleanupError: unknown) {
        cleanupErrors.push(
          cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
        );
      }
    }
    if (persistedSignerRollbackReceipt) {
      try {
        await input.context.signingEngine.rollbackWalletEd25519SignerRegistration(
          persistedSignerRollbackReceipt,
        );
      } catch (cleanupError: unknown) {
        cleanupErrors.push(
          cleanupError instanceof Error ? cleanupError.message : String(cleanupError),
        );
      }
    }
    if (cleanupErrors.length > 0) {
      const primary = error instanceof Error ? error.message : String(error);
      throw new Error(`${primary}; add-signer cleanup failed: ${cleanupErrors.join('; ')}`);
    }
    throw error;
  } finally {
    ownedPasskeyPrfFirst.fill(0);
  }
}

async function addPasskeyEcdsaWalletSigner(
  input: AddWalletSignerBranchInput & {
    started: Extract<WalletAddSignerStartResponse, { kind: 'evm_family_ecdsa' }>;
  },
): Promise<RegistrationResult> {
  const authority = await walletAuthAuthorityRef({
    authority: passkeyWalletAuthAuthorityFromCredential({
      walletId: input.walletId,
      rpId: input.rpId,
      credential: input.credential,
    }),
  });
  const pendingLocalFinalization = await runStrictEcdsaFamilyCeremony({
    context: input.context,
    relayerUrl: input.relayerUrl,
    route: {
      kind: 'add_signer',
      walletId: input.walletId,
      addSignerCeremonyId: input.started.addSignerCeremonyId,
    },
    started: input.started.ecdsa,
    authority,
    registrationTiming: null,
  });
  const finalized = await finalizeWalletAddSigner({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addSignerCeremonyId: input.started.addSignerCeremonyId,
    idempotencyKey: createRegistrationOperationIdempotencyKey('wallet-add-signer-finalize'),
    kind: 'evm_family_ecdsa',
    ecdsa: { expectedKeyHandles: [pendingLocalFinalization.bootstrap.keyHandle] },
  });
  if (
    finalized.kind !== 'evm_family_ecdsa' ||
    finalized.walletId !== input.walletId ||
    finalized.rpId !== input.rpId
  ) {
    throw new Error('Wallet add-signer finalize returned a different ECDSA identity');
  }
  const walletKeys = finalized.ecdsa.walletKeys;
  const primaryKey = walletKeys[0];
  if (!primaryKey) {
    throw new Error('Wallet add-signer finalize did not return ECDSA wallet keys');
  }
  const session = await finalizeStrictEcdsaFamilyLocalActivation({
    context: input.context,
    pending: pendingLocalFinalization,
  });
  emitAddSignerEventSafely(input.onEvent, input.eventAccountId, {
    authMethod: 'passkey',
    phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
    status: 'running',
  });
  const localEcdsaWalletKeys =
    await input.context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
      walletId: toWalletId(input.walletId),
      session,
      walletKeys: [primaryKey, ...walletKeys.slice(1)],
    });
  await input.context.signingEngine.storeWalletEcdsaSignerRecords({
    walletId: input.walletId,
    walletKeys: localEcdsaWalletKeys,
  });
  emitAddSignerEventSafely(input.onEvent, input.eventAccountId, {
    authMethod: 'passkey',
    phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
    status: 'succeeded',
  });
  return {
    success: true,
    kind: 'wallet_signer_added',
    walletId: input.walletId,
    capabilities: [
      {
        kind: 'evm_family_ecdsa',
        thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
        thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
      },
    ],
  };
}

async function dispatchPasskeyWalletAddSigner(args: {
  input: AddWalletSignerBranchInput;
  signerSelection: AddSignerSelection;
  started: WalletAddSignerStartResponse;
}): Promise<RegistrationResult> {
  switch (args.signerSelection.mode) {
    case 'ed25519':
      if (args.started.kind !== 'near_ed25519') {
        throw new Error('Wallet add-signer start returned a different signer branch');
      }
      return await addPasskeyEd25519YaoWalletSigner({
        context: args.input.context,
        walletId: args.input.walletId,
        rpId: args.input.rpId,
        relayerUrl: args.input.relayerUrl,
        intentResponse: args.input.intentResponse,
        credential: args.input.credential,
        credentialIdB64u: args.input.credentialIdB64u,
        passkeyPrfFirstB64u: args.input.passkeyPrfFirstB64u,
        eventAccountId: args.input.eventAccountId,
        onEvent: args.input.onEvent,
        started: args.started,
      });
    case 'ecdsa':
      if (args.started.kind !== 'evm_family_ecdsa') {
        throw new Error('Wallet add-signer start returned a different signer branch');
      }
      return await addPasskeyEcdsaWalletSigner({
        context: args.input.context,
        walletId: args.input.walletId,
        rpId: args.input.rpId,
        relayerUrl: args.input.relayerUrl,
        intentResponse: args.input.intentResponse,
        credential: args.input.credential,
        credentialIdB64u: args.input.credentialIdB64u,
        passkeyPrfFirstB64u: args.input.passkeyPrfFirstB64u,
        eventAccountId: args.input.eventAccountId,
        onEvent: args.input.onEvent,
        started: args.started,
      });
    default:
      return assertNever(args.signerSelection);
  }
}

export async function addWalletSigner(
  args: AddWalletSignerOperationArgs,
): Promise<RegistrationResult> {
  const { context, signerSelection } = args;
  const options = args.options || {};
  const walletId = walletIdFromString(String(args.walletId || '').trim());
  const eventAccountId = registrationEventAccountId(String(walletId));
  const rpId = requireWebAuthnRpId(String(args.rpId || '').trim());
  emitAddSignerEventSafely(options.onEvent, eventAccountId, {
    authMethod: 'passkey',
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    const relayerUrl = String(context.configs.network.relayer.url || '').trim();
    if (!relayerUrl) throw new Error('addWalletSigner requires relayer.url');
    const managedRuntimeScope = resolveManagedRuntimeScopeBootstrap(context.configs);
    if (!managedRuntimeScope) {
      throw new Error(
        'addWalletSigner requires registration.publishableKey and registration.projectEnvironmentId',
      );
    }
    const intentResponse = await createWalletAddSignerIntent({
      relayerUrl,
      walletId,
      request: { walletId, rpId, signerSelection },
      auth: {
        publishableKey: managedRuntimeScope.publishableKey,
        environmentId: managedRuntimeScope.projectEnvironmentId,
      },
    });
    const localDigestB64u = await computeAddSignerIntentDigest(intentResponse.intent);
    if (localDigestB64u !== intentResponse.addSignerIntentDigestB64u) {
      throw new Error('Add-signer intent digest mismatch');
    }

    emitAddSignerEventSafely(options.onEvent, eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
      status: 'waiting_for_user',
      interaction: { kind: 'passkey_assert', overlay: 'show' },
    });
    const authenticators = await IndexedDBManager.listProfileAuthenticators(String(walletId));
    const allowCredentials = addSignerAllowCredentials(authenticators);
    const credential = await context.signingEngine.getAuthenticationCredentialsSerialized({
      subjectId: String(walletId),
      challengeB64u: intentResponse.addSignerIntentDigestB64u,
      allowCredentials,
      includeSecondPrfOutput: false,
    });
    const credentialIdB64u = requireSelectedAddSignerCredentialId(credential, allowCredentials);
    const passkeyPrfFirstB64u = requirePasskeyPrfFirstB64u(
      credential,
      'Wallet add-signer authorization',
    );
    emitAddSignerEventSafely(options.onEvent, eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
      status: 'succeeded',
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
    });
    const started = await startWalletAddSigner({
      relayerUrl,
      walletId,
      addSignerIntentGrant: intentResponse.addSignerIntentGrant,
      addSignerIntentDigestB64u: intentResponse.addSignerIntentDigestB64u,
      intent: intentResponse.intent,
      auth: {
        kind: 'webauthn_assertion',
        rpId,
        credential: redactCredentialExtensionOutputs(credential),
        expectedChallengeDigestB64u: intentResponse.addSignerIntentDigestB64u,
      },
    });
    await requireMatchingStartedAddSignerIntent({
      started,
      walletId,
      expectedDigestB64u: intentResponse.addSignerIntentDigestB64u,
    });
    const result = await dispatchPasskeyWalletAddSigner({
      input: {
        context,
        walletId,
        rpId,
        relayerUrl,
        intentResponse,
        credential,
        credentialIdB64u,
        passkeyPrfFirstB64u,
        eventAccountId,
        onEvent: options.onEvent,
      },
      signerSelection,
      started,
    });
    emitAddSignerEventSafely(options.onEvent, eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });
    notifyAddSignerAfterCallSafely(options.afterCall, true, result);
    return result;
  } catch (error: unknown) {
    const errorCode = registrationErrorCodeFromUnknown(error);
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', eventAccountId);
    notifyAddSignerErrorSafely(options.onError, registrationErrorWithCode(errorMessage, errorCode));
    emitAddSignerEventSafely(options.onEvent, eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      message: errorMessage,
      interaction: { kind: 'passkey_assert', overlay: 'hide' },
      error: { ...(errorCode ? { code: errorCode } : {}), message: errorMessage },
    });
    const result: RegistrationResult = {
      success: false,
      error: errorMessage,
      ...(errorCode ? { errorCode } : {}),
    };
    notifyAddSignerAfterCallSafely(options.afterCall, false);
    return result;
  }
}
