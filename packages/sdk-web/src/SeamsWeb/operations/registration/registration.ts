import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { isObject, validateNearAccountId } from '@shared/utils/validation';
import type {
  CreateRegistrationFlowEventInput,
  RegistrationFlowEvent,
  RegistrationHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { RegistrationResult, SeamsConfigsReadonly } from '@/core/types/seams';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { createRegistrationFlowEvent, RegistrationEventPhase } from '@/core/types/sdkSentEvents';
import { createManagedRegistrationFlowGrant } from '@/SeamsWeb/operations/registration/createAccountRelayServer';
import type {
  RegistrationAccountSurface,
  RegistrationSigningSurface,
  RegistrationWebContext,
} from '@/SeamsWeb/signingSurface/types';
import type { WorkerResourceWarmupDiagnostics } from '@/core/signingEngine/assembly/warmup';
import {
  buildThresholdWarmSessionRequestEnvelope,
  buildThresholdEd25519RegistrationHssClientOwnedArtifact,
  completeRegisteredThresholdEd25519Registration,
  createThresholdWarmSessionPolicyDraft,
  prepareThresholdEd25519RegistrationHssClientMaterial,
  prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst,
  prepareThresholdEd25519RegistrationHssClientRequest,
  persistRegisteredThresholdEd25519Session,
  reconstructThresholdEd25519SigningMaterialFromWarmSession,
  type ThresholdWarmSessionContext,
  type ThresholdWarmSessionPolicyDraft,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import type {
  PasskeyWalletRegistrationEcdsaPreparedClientBootstrap,
  WalletRegistrationEcdsaPreparedClientBootstrap,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { checkNearAccountExistsBestEffort } from '@/core/rpcClients/near/rpcCalls';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { normalizeRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { IndexedDBManager } from '@/core/indexedDB';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  AddSignerSelection,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationSignerSelection,
  ThresholdEcdsaRegistrationSpec,
  WalletId,
} from '@shared/utils/registrationIntent';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { computeRegistrationIntentDigest } from '@/utils/intentDigest';
import { computeAddSignerIntentDigest } from '@/utils/intentDigest';
import {
  createWalletAddSignerIntent,
  createWalletRegistrationIntent,
  finalizeWalletAddSigner,
  finalizeWalletRegistration,
  parseWalletRegistrationEcdsaHssRespond,
  prepareWalletRegistration,
  respondWalletAddSignerHss,
  respondWalletRegistrationHss,
  startWalletAddSigner,
  startWalletRegistration,
  type WalletRegistrationEcdsaHssRespondBootstrap,
  type WalletRegistrationEmailOtpBackupAck,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
} from '@/core/rpcClients/relayer/walletRegistration';
import { fetchRouterAbPublicKeysetV2 } from '@/core/rpcClients/relayer/routerAbPublicKeyset';
import { buildNearWalletRegistrationSignerSelection } from '@/SeamsWeb/operations/registration/registrationSignerSelection';
import {
  collectPasskeyRegistrationAuthority,
  type PasskeyRegistrationAuthorityDiagnostics,
} from '@/SeamsWeb/operations/authMethods/passkey/registrationAuthority';
import { backupEmailOtpRecoveryCodes } from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import type { GoogleEmailOtpRegistrationBackupEnrollmentInput } from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import type {
  GoogleEmailOtpRegistrationBackedUpEnrollmentResult,
  RegistrationFinalizeIdempotencyKey,
} from '@/SeamsWeb/publicApi/types';
import { collectEmailOtpRegistrationAuthority } from '@/SeamsWeb/operations/authMethods/emailOtp/registrationAuthority';
import {
  readEmailOtpPrewarmedRegistrationMaterial,
  type EmailOtpRegistrationEnrollmentMaterial,
} from '@/SeamsWeb/operations/authMethods/emailOtp/prewarmedRegistrationMaterial';
import { requirePasskeyPrfFirstB64u } from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionStoreSource } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  listStoredThresholdEcdsaSessionRecordsForWallet,
} from '@/core/signingEngine/session/persistence/records';
import {
  assertWalletRuntimePostconditions,
  type WalletRuntimeInventory,
} from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  parseRouterAbEcdsaHssSigningWalletSessionFromRecord,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { parseEd25519HssKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';

// Registration forces a visible, clickable confirmation for cross-origin safety.

export const REGISTRATION_TIMING_LABEL = '[Registration] wallet timing summary';
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

type EmitRegistrationEventInput = Omit<CreateRegistrationFlowEventInput, 'accountId' | 'flowId'>;

type RegistrationTimingAuthMethod = RegistrationAuthMethodInput['kind'];
type RegistrationTimingSignerMode = RegistrationSignerSelection['mode'];

type RegistrationTimingBucketValues = {
  inputValidationMs: number;
  registrationWarmupMs: number;
  registrationWarmupWaitMs: number;
  registrationWarmupAuthenticatedWalletStateMs: number;
  registrationWarmupNoncePrefetchMs: number;
  registrationWarmupKeyMaterialReadMs: number;
  registrationWarmupUiConfirmPrewarmMs: number;
  registrationWarmupSignerWorkerPrewarmMs: number;
  routerAbPublicKeysetMs: number;
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
  ed25519ClientMaterialMs: number;
  walletRegisterPrepareMs: number;
  walletRegisterPrepareWaitMs: number;
  walletRegisterStartMs: number;
  ed25519ClientRequestMs: number;
  ecdsaClientBootstrapMs: number;
  walletRegisterHssRespondMs: number;
  ed25519EvaluationArtifactMs: number;
  emailOtpRecoveryCodeBackupMs: number;
  walletRegisterFinalizeMs: number;
  ed25519CompletionParseMs: number;
  localWalletRegistrationPersistenceMs: number;
  thresholdEd25519SessionPersistenceMs: number;
  ecdsaRegistrationPersistenceMs: number;
  walletStateActivationMs: number;
  immediateSigningLaneAssertionMs: number;
};

type RegistrationTimingBucketName = keyof RegistrationTimingBucketValues;

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
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  options: RegistrationHooksOptions;
  authenticatorOptions: AuthenticatorOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
};

type Ed25519RegistrationSignerSelection =
  | Extract<RegistrationSignerSelection, { mode: 'ed25519_only' }>
  | Extract<RegistrationSignerSelection, { mode: 'ed25519_and_ecdsa' }>;

export type WalletRegistrationPrecomputeScope = {
  authMethodKind: RegistrationAuthMethodInput['kind'];
  walletScopeKey: string;
  rpId: string;
  signerMode: Extract<RegistrationSignerSelection['mode'], 'ed25519_only' | 'ed25519_and_ecdsa'>;
  nearAccountId: string;
};

type WalletRegistrationPreparedOutcome =
  | {
      ok: true;
      value: Awaited<ReturnType<typeof prepareWalletRegistration>>;
      error?: never;
    }
  | {
      ok: false;
      error: unknown;
      value?: never;
    };

type WalletRegistrationPrecomputeReady = {
  relayerUrl: string;
  intentResponse: Awaited<ReturnType<typeof createWalletRegistrationIntent>>;
  registrationWarmup: Promise<RegistrationWarmupOutcome>;
  preparedRegistrationPromise: Promise<WalletRegistrationPreparedOutcome>;
  thresholdRuntimePolicyScope: ThresholdRuntimePolicyScope;
};

export type WalletRegistrationPrecomputeHandle = {
  kind: 'wallet_registration_precompute_handle_v1';
  handleId: string;
  scope: WalletRegistrationPrecomputeScope;
};

type WalletRegistrationPrecomputeHandleInternal = WalletRegistrationPrecomputeHandle & {
  read(): Promise<WalletRegistrationPrecomputeReady>;
  snapshot(): RegistrationTimingBucketValues;
  routeDiagnosticsSnapshot(): WalletRegistrationRouteDiagnostics[];
  dispose(): void;
};

type RegisterWalletPrecomputeMode =
  | {
      kind: 'start_inside_register_wallet';
      handle?: never;
    }
  | {
      kind: 'use_started_precompute';
      handle: WalletRegistrationPrecomputeHandle;
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

type Ed25519EnabledRegistrationTiming = {
  kind: 'ed25519_enabled';
  ed25519ClientMaterialMs: number;
  ed25519ClientRequestMs: number;
  ed25519EvaluationArtifactMs: number;
  ed25519CompletionParseMs: number;
  thresholdEd25519SessionPersistenceMs: number;
};

type Ed25519DisabledRegistrationTiming = {
  kind: 'ed25519_disabled';
  ed25519ClientMaterialMs: 0;
  ed25519ClientRequestMs: 0;
  ed25519EvaluationArtifactMs: 0;
  ed25519CompletionParseMs: 0;
  thresholdEd25519SessionPersistenceMs: 0;
};

type RegistrationEd25519Timing =
  | Ed25519EnabledRegistrationTiming
  | Ed25519DisabledRegistrationTiming;

type EcdsaEnabledRegistrationTiming = {
  kind: 'ecdsa_enabled';
  ecdsaClientBootstrapMs: number;
  ecdsaRegistrationPersistenceMs: number;
};

type EcdsaDisabledRegistrationTiming = {
  kind: 'ecdsa_disabled';
  ecdsaClientBootstrapMs: 0;
  ecdsaRegistrationPersistenceMs: 0;
};

type RegistrationEcdsaTiming = EcdsaEnabledRegistrationTiming | EcdsaDisabledRegistrationTiming;

type RegistrationTimingBuckets = RegistrationTimingBucketValues & {
  auth: RegistrationAuthTiming;
  ed25519: RegistrationEd25519Timing;
  ecdsa: RegistrationEcdsaTiming;
};

type SucceededRegistrationTimingSummary = {
  kind: 'registration_timing_summary_v1';
  status: 'succeeded';
  authMethod: RegistrationTimingAuthMethod;
  signerMode: RegistrationTimingSignerMode;
  totalMs: number;
  relayDiagnostics: WalletRegistrationRouteDiagnostics[];
  errorCode?: never;
  timings: RegistrationTimingBuckets;
};

type FailedRegistrationTimingSummary = {
  kind: 'registration_timing_summary_v1';
  status: 'failed';
  authMethod: RegistrationTimingAuthMethod;
  signerMode: RegistrationTimingSignerMode;
  totalMs: number;
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
    case 'registrationHssPrepareMs':
    case 'registrationPreauthHssPrepareMs':
    case 'registrationHssServerInputDeriveMs':
    case 'registrationHssServerSessionPrepareTotalMs':
    case 'registrationHssPrepareSessionMs':
    case 'registrationHssPrepareExtractDriverStatesMs':
    case 'registrationHssPrepareClientOfferMessageMs':
    case 'registrationHssPrepareCachePreparedSessionMs':
    case 'registrationHssPrepareEncodeStatesMs':
    case 'registrationEcdsaPrepareMs':
    case 'registrationCeremonyPersistMs':
    case 'registerPrepareTotalMs':
    case 'registerStartTotalMs':
    case 'registrationHssRespondMs':
    case 'registrationHssRespondDecodeMessagesMs':
    case 'registrationHssRespondMaterializeSessionMs':
    case 'registrationHssRespondPrepareDeliveryMs':
    case 'registrationHssRespondDeliveryOtOpenJoinMs':
    case 'registrationHssRespondDeliveryServerInputOpenMs':
    case 'registrationHssRespondDeliveryServerInputShareMs':
    case 'registrationHssRespondDeliveryServerInputCommitmentMs':
    case 'registrationHssRespondDeliveryServerInputTranscriptMs':
    case 'registrationHssRespondDeliveryServerInputSealMs':
    case 'registrationHssRespondEncodeDeliveryMs':
    case 'registrationEcdsaRespondMs':
    case 'registerHssRespondTotalMs':
    case 'registrationFinalizeReplayLoadMs':
    case 'registrationCeremonyLoadMs':
    case 'registrationHssFinalizeMs':
    case 'registrationHssFinalizeDecodeArtifactMs':
    case 'registrationHssFinalizeSerializedSessionMaterializeMs':
    case 'registrationHssFinalizeReportMs':
    case 'registrationHssFinalizeEncodeReportMs':
    case 'registrationHssFinalizeOpenServerOutputMs':
    case 'registrationHssFinalizeOpenSeedOutputMs':
    case 'registrationHssFinalizeDeriveSeedKeypairMs':
    case 'registrationHssFinalizeDeriveRelayerVerifyingShareMs':
    case 'registrationHssFinalizeKeyStorePutMs':
    case 'registrationEcdsaBootstrapVerifyMs':
    case 'nearAccountCreateMs':
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
  const route =
    value.route === 'wallets_register_prepare' ||
    value.route === 'wallets_register_start' ||
    value.route === 'wallets_register_hss_respond' ||
    value.route === 'wallets_register_finalize'
      ? value.route
      : null;
  if (!route || !Array.isArray(value.entries)) return null;
  const entries: WalletRegistrationRouteDiagnostics['entries'] = [];
  for (const entry of value.entries) {
    if (!isObject(entry)) continue;
    const name = parseWalletRegistrationRouteTimingName(entry.name);
    const durationMs = Number(entry.durationMs);
    if (!name || !Number.isFinite(durationMs)) continue;
    entries.push({ name, durationMs: Math.max(0, Math.round(durationMs)) });
  }
  if (entries.length === 0) return null;
  return {
    kind: 'wallet_registration_route_diagnostics_v1',
    route,
    entries,
  };
}

function createZeroRegistrationTimingBucketValues(): RegistrationTimingBucketValues {
  return {
    inputValidationMs: 0,
    registrationWarmupMs: 0,
    registrationWarmupWaitMs: 0,
    registrationWarmupAuthenticatedWalletStateMs: 0,
    registrationWarmupNoncePrefetchMs: 0,
    registrationWarmupKeyMaterialReadMs: 0,
    registrationWarmupUiConfirmPrewarmMs: 0,
    registrationWarmupSignerWorkerPrewarmMs: 0,
    routerAbPublicKeysetMs: 0,
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
    ed25519ClientMaterialMs: 0,
    walletRegisterPrepareMs: 0,
    walletRegisterPrepareWaitMs: 0,
    walletRegisterStartMs: 0,
    ed25519ClientRequestMs: 0,
    ecdsaClientBootstrapMs: 0,
    walletRegisterHssRespondMs: 0,
    ed25519EvaluationArtifactMs: 0,
    emailOtpRecoveryCodeBackupMs: 0,
    walletRegisterFinalizeMs: 0,
    ed25519CompletionParseMs: 0,
    localWalletRegistrationPersistenceMs: 0,
    thresholdEd25519SessionPersistenceMs: 0,
    ecdsaRegistrationPersistenceMs: 0,
    walletStateActivationMs: 0,
    immediateSigningLaneAssertionMs: 0,
  };
}

function copyRegistrationTimingBucketValues(
  buckets: RegistrationTimingBucketValues,
): RegistrationTimingBucketValues {
  return {
    inputValidationMs: buckets.inputValidationMs,
    registrationWarmupMs: buckets.registrationWarmupMs,
    registrationWarmupWaitMs: buckets.registrationWarmupWaitMs,
    registrationWarmupAuthenticatedWalletStateMs:
      buckets.registrationWarmupAuthenticatedWalletStateMs,
    registrationWarmupNoncePrefetchMs: buckets.registrationWarmupNoncePrefetchMs,
    registrationWarmupKeyMaterialReadMs: buckets.registrationWarmupKeyMaterialReadMs,
    registrationWarmupUiConfirmPrewarmMs: buckets.registrationWarmupUiConfirmPrewarmMs,
    registrationWarmupSignerWorkerPrewarmMs: buckets.registrationWarmupSignerWorkerPrewarmMs,
    routerAbPublicKeysetMs: buckets.routerAbPublicKeysetMs,
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
    ed25519ClientMaterialMs: buckets.ed25519ClientMaterialMs,
    walletRegisterPrepareMs: buckets.walletRegisterPrepareMs,
    walletRegisterPrepareWaitMs: buckets.walletRegisterPrepareWaitMs,
    walletRegisterStartMs: buckets.walletRegisterStartMs,
    ed25519ClientRequestMs: buckets.ed25519ClientRequestMs,
    ecdsaClientBootstrapMs: buckets.ecdsaClientBootstrapMs,
    walletRegisterHssRespondMs: buckets.walletRegisterHssRespondMs,
    ed25519EvaluationArtifactMs: buckets.ed25519EvaluationArtifactMs,
    emailOtpRecoveryCodeBackupMs: buckets.emailOtpRecoveryCodeBackupMs,
    walletRegisterFinalizeMs: buckets.walletRegisterFinalizeMs,
    ed25519CompletionParseMs: buckets.ed25519CompletionParseMs,
    localWalletRegistrationPersistenceMs: buckets.localWalletRegistrationPersistenceMs,
    thresholdEd25519SessionPersistenceMs: buckets.thresholdEd25519SessionPersistenceMs,
    ecdsaRegistrationPersistenceMs: buckets.ecdsaRegistrationPersistenceMs,
    walletStateActivationMs: buckets.walletStateActivationMs,
    immediateSigningLaneAssertionMs: buckets.immediateSigningLaneAssertionMs,
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
  signerMode: RegistrationTimingSignerMode;
  buckets: RegistrationTimingBucketValues;
}): RegistrationEd25519Timing {
  switch (input.signerMode) {
    case 'ed25519_only':
    case 'ed25519_and_ecdsa':
      return {
        kind: 'ed25519_enabled',
        ed25519ClientMaterialMs: input.buckets.ed25519ClientMaterialMs,
        ed25519ClientRequestMs: input.buckets.ed25519ClientRequestMs,
        ed25519EvaluationArtifactMs: input.buckets.ed25519EvaluationArtifactMs,
        ed25519CompletionParseMs: input.buckets.ed25519CompletionParseMs,
        thresholdEd25519SessionPersistenceMs: input.buckets.thresholdEd25519SessionPersistenceMs,
      };
    case 'ecdsa_only':
      return {
        kind: 'ed25519_disabled',
        ed25519ClientMaterialMs: 0,
        ed25519ClientRequestMs: 0,
        ed25519EvaluationArtifactMs: 0,
        ed25519CompletionParseMs: 0,
        thresholdEd25519SessionPersistenceMs: 0,
      };
    default:
      return assertNever(input.signerMode);
  }
}

function buildRegistrationEcdsaTiming(input: {
  signerMode: RegistrationTimingSignerMode;
  buckets: RegistrationTimingBucketValues;
}): RegistrationEcdsaTiming {
  switch (input.signerMode) {
    case 'ecdsa_only':
    case 'ed25519_and_ecdsa':
      return {
        kind: 'ecdsa_enabled',
        ecdsaClientBootstrapMs: input.buckets.ecdsaClientBootstrapMs,
        ecdsaRegistrationPersistenceMs: input.buckets.ecdsaRegistrationPersistenceMs,
      };
    case 'ed25519_only':
      return {
        kind: 'ecdsa_disabled',
        ecdsaClientBootstrapMs: 0,
        ecdsaRegistrationPersistenceMs: 0,
      };
    default:
      return assertNever(input.signerMode);
  }
}

function buildRegistrationTimingBuckets(input: {
  authMethod: RegistrationTimingAuthMethod;
  signerMode: RegistrationTimingSignerMode;
  buckets: RegistrationTimingBucketValues;
}): RegistrationTimingBuckets {
  const buckets = copyRegistrationTimingBucketValues(input.buckets);
  return {
    inputValidationMs: buckets.inputValidationMs,
    registrationWarmupMs: buckets.registrationWarmupMs,
    registrationWarmupWaitMs: buckets.registrationWarmupWaitMs,
    registrationWarmupAuthenticatedWalletStateMs:
      buckets.registrationWarmupAuthenticatedWalletStateMs,
    registrationWarmupNoncePrefetchMs: buckets.registrationWarmupNoncePrefetchMs,
    registrationWarmupKeyMaterialReadMs: buckets.registrationWarmupKeyMaterialReadMs,
    registrationWarmupUiConfirmPrewarmMs: buckets.registrationWarmupUiConfirmPrewarmMs,
    registrationWarmupSignerWorkerPrewarmMs: buckets.registrationWarmupSignerWorkerPrewarmMs,
    routerAbPublicKeysetMs: buckets.routerAbPublicKeysetMs,
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
    ed25519ClientMaterialMs: buckets.ed25519ClientMaterialMs,
    walletRegisterPrepareMs: buckets.walletRegisterPrepareMs,
    walletRegisterPrepareWaitMs: buckets.walletRegisterPrepareWaitMs,
    walletRegisterStartMs: buckets.walletRegisterStartMs,
    ed25519ClientRequestMs: buckets.ed25519ClientRequestMs,
    ecdsaClientBootstrapMs: buckets.ecdsaClientBootstrapMs,
    walletRegisterHssRespondMs: buckets.walletRegisterHssRespondMs,
    ed25519EvaluationArtifactMs: buckets.ed25519EvaluationArtifactMs,
    emailOtpRecoveryCodeBackupMs: buckets.emailOtpRecoveryCodeBackupMs,
    walletRegisterFinalizeMs: buckets.walletRegisterFinalizeMs,
    ed25519CompletionParseMs: buckets.ed25519CompletionParseMs,
    localWalletRegistrationPersistenceMs: buckets.localWalletRegistrationPersistenceMs,
    thresholdEd25519SessionPersistenceMs: buckets.thresholdEd25519SessionPersistenceMs,
    ecdsaRegistrationPersistenceMs: buckets.ecdsaRegistrationPersistenceMs,
    walletStateActivationMs: buckets.walletStateActivationMs,
    immediateSigningLaneAssertionMs: buckets.immediateSigningLaneAssertionMs,
    auth: buildRegistrationAuthTiming({
      authMethod: input.authMethod,
      buckets,
    }),
    ed25519: buildRegistrationEd25519Timing({
      signerMode: input.signerMode,
      buckets,
    }),
    ecdsa: buildRegistrationEcdsaTiming({
      signerMode: input.signerMode,
      buckets,
    }),
  };
}

class RegistrationTimingRecorder {
  private readonly startedAt: number;
  private readonly buckets: RegistrationTimingBucketValues;
  private readonly relayDiagnostics: WalletRegistrationRouteDiagnostics[];

  constructor(startedAt: number) {
    this.startedAt = startedAt;
    this.buckets = createZeroRegistrationTimingBucketValues();
    this.relayDiagnostics = [];
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
    }
  }

  measureSync<K extends RegistrationTimingBucketName, T>(bucket: K, operation: () => T): T {
    const startedAt = performance.now();
    try {
      return operation();
    } finally {
      this.buckets[bucket] = roundDurationMs(startedAt);
    }
  }

  snapshot(): RegistrationTimingBucketValues {
    return copyRegistrationTimingBucketValues(this.buckets);
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
      this.relayDiagnostics.push({
        kind: diagnostics.kind,
        route: diagnostics.route,
        entries: diagnostics.entries.map((entry) => ({
          name: entry.name,
          durationMs: entry.durationMs,
        })),
      });
    }
  }

  captureWarmupDiagnostics(diagnostics: WorkerResourceWarmupDiagnostics): void {
    this.buckets.registrationWarmupAuthenticatedWalletStateMs =
      diagnostics.authenticatedWalletStateMs;
    this.buckets.registrationWarmupNoncePrefetchMs = diagnostics.noncePrefetchMs;
    this.buckets.registrationWarmupKeyMaterialReadMs = diagnostics.keyMaterialReadMs;
    this.buckets.registrationWarmupUiConfirmPrewarmMs = diagnostics.uiConfirmPrewarmMs;
    this.buckets.registrationWarmupSignerWorkerPrewarmMs = diagnostics.signerWorkerPrewarmMs;
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
    return this.relayDiagnostics.map((diagnostics) => ({
      kind: diagnostics.kind,
      route: diagnostics.route,
      entries: diagnostics.entries.map((entry) => ({
        name: entry.name,
        durationMs: entry.durationMs,
      })),
    }));
  }

  totalMs(): number {
    return roundDurationMs(this.startedAt);
  }
}

type RegistrationWarmupOutcome =
  | {
      kind: 'completed';
      diagnostics: WorkerResourceWarmupDiagnostics;
      error?: never;
    }
  | {
      kind: 'failed';
      error: unknown;
    };

type RouterAbPublicKeysetPrefetchOutcome =
  | {
      kind: 'disabled';
      error?: never;
    }
  | {
      kind: 'completed';
      error?: never;
    }
  | {
      kind: 'failed';
      error: unknown;
    };

function startRegistrationWarmup(input: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  nearAccountId?: string;
}): Promise<RegistrationWarmupOutcome> {
  return input.recorder
    .measure('registrationWarmupMs', () =>
      input.context.signingEngine.warmCriticalResources(input.nearAccountId),
    )
    .then(
      (diagnostics) => ({ kind: 'completed' as const, diagnostics }),
      (error: unknown) => ({ kind: 'failed' as const, error }),
    );
}

function startRouterAbPublicKeysetPrefetch(input: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  relayerUrl: string;
}): Promise<RouterAbPublicKeysetPrefetchOutcome> {
  const normalSigning = input.context.configs.signing.routerAb.normalSigning;
  switch (normalSigning.mode) {
    case 'disabled':
      return Promise.resolve({ kind: 'disabled' });
    case 'enabled':
      return input.recorder
        .measure('routerAbPublicKeysetMs', () =>
          fetchRouterAbPublicKeysetV2({ relayerUrl: input.relayerUrl }),
        )
        .then(
          () => ({ kind: 'completed' as const }),
          (error: unknown) => ({ kind: 'failed' as const, error }),
        );
    default:
      return assertNever(normalSigning);
  }
}

async function requireRouterAbPublicKeysetPrefetch(
  prefetch: Promise<RouterAbPublicKeysetPrefetchOutcome>,
): Promise<void> {
  const outcome = await prefetch;
  switch (outcome.kind) {
    case 'disabled':
    case 'completed':
      return;
    case 'failed':
      throw outcome.error;
    default:
      return assertNever(outcome);
  }
}

async function waitForRegistrationWarmup(input: {
  recorder: RegistrationTimingRecorder;
  warmup: Promise<RegistrationWarmupOutcome>;
}): Promise<void> {
  const outcome = await input.recorder.measure('registrationWarmupWaitMs', () => input.warmup);
  if (outcome.kind === 'completed') {
    input.recorder.captureWarmupDiagnostics(outcome.diagnostics);
  }
}

function requireEd25519RegistrationSignerSelection(
  signerSelection: RegistrationSignerSelection,
): Ed25519RegistrationSignerSelection {
  switch (signerSelection.mode) {
    case 'ed25519_only':
    case 'ed25519_and_ecdsa':
      return signerSelection;
    case 'ecdsa_only':
      throw new Error('Wallet registration precompute requires Ed25519 signer selection');
    default:
      return assertNever(signerSelection);
  }
}

function walletScopeKey(wallet: RegisterWalletInput): string {
  switch (wallet.kind) {
    case 'provided':
      return `provided:${String(wallet.walletId)}`;
    case 'server_generated':
      return 'server_generated';
    default:
      return assertNever(wallet);
  }
}

function walletRegistrationPrecomputeScopeFromArgs(args: {
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: Ed25519RegistrationSignerSelection;
}): WalletRegistrationPrecomputeScope {
  const rpId = String(args.rpId || '').trim();
  if (!rpId) throw new Error('registerWallet requires rpId');
  return {
    authMethodKind: args.authMethod.kind,
    walletScopeKey: walletScopeKey(args.wallet),
    rpId,
    signerMode: args.signerSelection.mode,
    nearAccountId: String(toAccountId(args.signerSelection.ed25519.nearAccountId)),
  };
}

function assertWalletRegistrationPrecomputeScopeMatches(input: {
  expected: WalletRegistrationPrecomputeScope;
  actual: WalletRegistrationPrecomputeScope;
}): void {
  if (
    input.expected.authMethodKind !== input.actual.authMethodKind ||
    input.expected.walletScopeKey !== input.actual.walletScopeKey ||
    input.expected.rpId !== input.actual.rpId ||
    input.expected.signerMode !== input.actual.signerMode ||
    input.expected.nearAccountId !== input.actual.nearAccountId
  ) {
    throw new Error('Started wallet registration precompute does not match registration input');
  }
}

function requireWalletRegistrationPrecomputeHandle(
  handle: WalletRegistrationPrecomputeHandle,
): WalletRegistrationPrecomputeHandleInternal {
  const candidate = handle as Partial<WalletRegistrationPrecomputeHandleInternal>;
  if (
    candidate.kind !== 'wallet_registration_precompute_handle_v1' ||
    typeof candidate.handleId !== 'string' ||
    !candidate.scope ||
    typeof candidate.read !== 'function' ||
    typeof candidate.snapshot !== 'function' ||
    typeof candidate.routeDiagnosticsSnapshot !== 'function' ||
    typeof candidate.dispose !== 'function'
  ) {
    throw new Error('Invalid wallet registration precompute handle');
  }
  return candidate as WalletRegistrationPrecomputeHandleInternal;
}

async function startWalletRegistrationPrecomputeReady(input: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: Ed25519RegistrationSignerSelection;
  recorder: RegistrationTimingRecorder;
}): Promise<WalletRegistrationPrecomputeReady> {
  const relayerUrl = String(input.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) {
    throw new Error('registerWallet requires relayer.url');
  }
  const routerAbPublicKeysetPrefetch = startRouterAbPublicKeysetPrefetch({
    recorder: input.recorder,
    context: input.context,
    relayerUrl,
  });
  const scope = walletRegistrationPrecomputeScopeFromArgs({
    authMethod: input.authMethod,
    wallet: input.wallet,
    rpId: input.rpId,
    signerSelection: input.signerSelection,
  });
  const registrationWarmup = startRegistrationWarmup({
    recorder: input.recorder,
    context: input.context,
    nearAccountId: scope.nearAccountId,
  });
  const managedGrant = await input.recorder.measure('managedRegistrationGrantMs', () =>
    createManagedRegistrationFlowGrant({
      context: input.context,
      nearAccountId: scope.nearAccountId,
      rpId: scope.rpId,
    }),
  );
  const intentResponse = await input.recorder.measure('registrationIntentMs', () =>
    createWalletRegistrationIntent({
      relayerUrl,
      request: {
        wallet: input.wallet,
        rpId: scope.rpId,
        authMethod: input.authMethod,
        signerSelection: input.signerSelection,
      },
      headers: {
        Authorization: `Bearer ${managedGrant.token}`,
      },
    }),
  );
  const localDigestB64u = await input.recorder.measure('registrationIntentDigestMs', () =>
    computeRegistrationIntentDigest(intentResponse.intent),
  );
  if (localDigestB64u !== intentResponse.registrationIntentDigestB64u) {
    throw new Error('Registration intent digest mismatch');
  }
  await requireRouterAbPublicKeysetPrefetch(routerAbPublicKeysetPrefetch);
  const ecdsaSelection =
    input.signerSelection.mode === 'ed25519_and_ecdsa' ? input.signerSelection.ecdsa : null;
  const preparedRegistrationPromise = input.recorder
    .measure('walletRegisterPrepareMs', () =>
      prepareWalletRegistration({
        relayerUrl,
        registrationIntentGrant: intentResponse.registrationIntentGrant,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        intent: intentResponse.intent,
        headers: registrationRouteDiagnosticsHeaders(),
        work: {
          kind: ecdsaSelection ? 'ed25519_hss_and_ecdsa' : 'ed25519_hss',
        },
      }),
    )
    .then(
      (value) => ({ ok: true as const, value }),
      (error: unknown) => ({ ok: false as const, error }),
    );
  const runtimePolicyScope = intentResponse.intent.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('Registration intent is missing runtime policy scope');
  }
  if (!runtimePolicyScope.signingRootVersion) {
    throw new Error('Registration intent is missing signing root version');
  }
  const thresholdRuntimePolicyScope: ThresholdRuntimePolicyScope = {
    orgId: runtimePolicyScope.orgId,
    projectId: runtimePolicyScope.projectId,
    envId: runtimePolicyScope.envId,
    signingRootVersion: runtimePolicyScope.signingRootVersion,
  };
  return {
    relayerUrl,
    intentResponse,
    registrationWarmup,
    preparedRegistrationPromise,
    thresholdRuntimePolicyScope,
  };
}

export function startWalletRegistrationPrecompute(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
}): WalletRegistrationPrecomputeHandle {
  const signerSelection = requireEd25519RegistrationSignerSelection(args.signerSelection);
  const scope = walletRegistrationPrecomputeScopeFromArgs({
    authMethod: args.authMethod,
    wallet: args.wallet,
    rpId: args.rpId,
    signerSelection,
  });
  const startedAt = performance.now();
  const recorder = new RegistrationTimingRecorder(startedAt);
  const handleId = createRegistrationOperationIdempotencyKey(
    'wallet-registration-precompute',
  ) as string;
  let disposed = false;
  const ready = startWalletRegistrationPrecomputeReady({
    context: args.context,
    authMethod: args.authMethod,
    wallet: args.wallet,
    rpId: args.rpId,
    signerSelection,
    recorder,
  });
  void ready.catch(() => undefined);
  const handle: WalletRegistrationPrecomputeHandleInternal = {
    kind: 'wallet_registration_precompute_handle_v1',
    handleId,
    scope,
    async read() {
      if (disposed) throw new Error('Wallet registration precompute has been disposed');
      const value = await ready;
      if (disposed) throw new Error('Wallet registration precompute has been disposed');
      return value;
    },
    snapshot() {
      return recorder.snapshot();
    },
    routeDiagnosticsSnapshot() {
      return recorder.routeDiagnosticsSnapshot();
    },
    dispose() {
      disposed = true;
    },
  };
  return handle;
}

export function disposeWalletRegistrationPrecompute(
  handle: WalletRegistrationPrecomputeHandle,
): void {
  requireWalletRegistrationPrecomputeHandle(handle).dispose();
}

function createSucceededRegistrationTimingSummary(input: {
  recorder: RegistrationTimingRecorder;
  authMethod: RegistrationTimingAuthMethod;
  signerMode: RegistrationTimingSignerMode;
}): SucceededRegistrationTimingSummary {
  return {
    kind: 'registration_timing_summary_v1',
    status: 'succeeded',
    authMethod: input.authMethod,
    signerMode: input.signerMode,
    totalMs: input.recorder.totalMs(),
    relayDiagnostics: input.recorder.routeDiagnosticsSnapshot(),
    timings: buildRegistrationTimingBuckets({
      authMethod: input.authMethod,
      signerMode: input.signerMode,
      buckets: input.recorder.snapshot(),
    }),
  };
}

function createFailedRegistrationTimingSummary(input: {
  recorder: RegistrationTimingRecorder;
  authMethod: RegistrationTimingAuthMethod;
  signerMode: RegistrationTimingSignerMode;
  errorCode: string | null;
}): FailedRegistrationTimingSummary {
  return {
    kind: 'registration_timing_summary_v1',
    status: 'failed',
    authMethod: input.authMethod,
    signerMode: input.signerMode,
    totalMs: input.recorder.totalMs(),
    errorCode: input.errorCode,
    relayDiagnostics: input.recorder.routeDiagnosticsSnapshot(),
    timings: buildRegistrationTimingBuckets({
      authMethod: input.authMethod,
      signerMode: input.signerMode,
      buckets: input.recorder.snapshot(),
    }),
  };
}

function emitRegistrationTimingSummary(summary: RegistrationTimingSummary): void {
  console.info(REGISTRATION_TIMING_LABEL, summary);
}

function registrationRouteDiagnosticsHeaders(): Record<string, string> | undefined {
  return isRegistrationBenchmarkDiagnosticsEnabled()
    ? { 'X-Seams-Benchmark-Diagnostics': 'registration-flow' }
    : undefined;
}

function createRegistrationOperationIdempotencyKey(
  label: string,
): RegistrationFinalizeIdempotencyKey {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi && typeof cryptoApi.randomUUID === 'function') {
    return `${label}:${cryptoApi.randomUUID()}` as RegistrationFinalizeIdempotencyKey;
  }
  const bytes = new Uint8Array(16);
  if (cryptoApi && typeof cryptoApi.getRandomValues === 'function') {
    cryptoApi.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${label}:${hex}` as RegistrationFinalizeIdempotencyKey;
}

function googleEmailOtpFinalizeIdempotencyKey(
  authMethod: RegistrationAuthMethodInput,
): RegistrationFinalizeIdempotencyKey | undefined {
  if (authMethod.kind !== 'email_otp' || authMethod.proofKind !== 'google_sso_registration') {
    return undefined;
  }
  return createRegistrationOperationIdempotencyKey('google-email-otp-registration-finalize');
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
  rpId: string;
  appSessionJwt: string;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  if (input.authMethod.kind !== 'email_otp') {
    throw new Error('Email OTP enrollment material requires Email OTP auth');
  }
  const prewarmed = readEmailOtpPrewarmedRegistrationMaterial(input.authMethod);
  if (prewarmed) {
    if (input.authMethod.proofKind !== 'google_sso_registration') {
      throw new Error('Prewarmed Email OTP material requires Google SSO registration');
    }
    if (
      prewarmed.offerId !== input.authMethod.googleEmailOtpRegistrationOfferId ||
      prewarmed.candidateId !== input.authMethod.googleEmailOtpRegistrationCandidateId ||
      prewarmed.walletId !== input.walletId ||
      prewarmed.providerSubject !== input.providerSubject
    ) {
      throw new Error('Prewarmed Email OTP material does not match the active registration offer');
    }
    return prewarmed.material;
  }
  return await input.context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
    relayUrl: input.relayerUrl,
    walletId: toWalletId(input.walletId),
    userId: input.providerSubject,
    rpId: input.rpId,
    appSessionJwt: input.appSessionJwt,
  });
}

export function createRegistrationLifecycleEvent(input: {
  accountId: string;
  event: EmitRegistrationEventInput;
}): RegistrationFlowEvent {
  const authMethod = input.event.authMethod || 'passkey';
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

function requirePasskeyEcdsaPreparedClientBootstrap(
  prepared: WalletRegistrationEcdsaPreparedClientBootstrap,
): PasskeyWalletRegistrationEcdsaPreparedClientBootstrap {
  if (prepared.materialSource !== 'passkey_prf_first') {
    throw new Error('Passkey ECDSA persistence requires passkey-prepared material');
  }
  return prepared;
}

function passkeyEcdsaCredentialIdFromPrepared(
  prepared: WalletRegistrationEcdsaPreparedClientBootstrap,
): string {
  const passkeyPrepared = requirePasskeyEcdsaPreparedClientBootstrap(prepared);
  const credentialIdB64u = passkeyPrepared.credentialIdB64u.trim();
  if (!credentialIdB64u) {
    throw new Error('Passkey ECDSA persistence requires a credential id');
  }
  return credentialIdB64u;
}

function emitRegistrationEvent(
  onEvent: RegistrationHooksOptions['onEvent'] | undefined,
  accountId: string,
  event: EmitRegistrationEventInput,
): void {
  onEvent?.(createRegistrationLifecycleEvent({ accountId, event }));
}

/**
 * Core registration function that handles passkey registration
 *
 * Legacy proof-derived flows have been removed from the lite threshold-signer stack. Registration is now:
 * 1) Collect a standard WebAuthn registration credential (passkey).
 * 2) Derive a deterministic threshold client verifying share from PRF.first (default registration policy).
 *    Optionally derive/store encrypted local NEAR key material (v3 vault) as backup/export data.
 * 3) Create/register the account via the relayer using threshold key enrollment.
 */
async function registerPasskeyWithAuthenticatorOptions(
  context: RegistrationWebContext,
  nearAccountId: AccountId,
  options: RegistrationHooksOptions,
  authenticatorOptions: AuthenticatorOptions,
  confirmationConfigOverride?: Partial<ConfirmationConfig>,
): Promise<RegistrationResult> {
  const accountId = toAccountId(nearAccountId);
  const iframeRpId = String(context.configs.wallet.iframe.rpIdOverride || '').trim();
  const rpId = iframeRpId || context.signingEngine.getRpId();
  if (!rpId) {
    throw new Error('Missing rpId for relay registration');
  }
  return await registerWallet({
    context,
    wallet: {
      kind: 'provided',
      walletId: walletIdFromString(String(accountId)),
    },
    rpId,
    authMethod: { kind: 'passkey' },
    signerSelection: buildNearWalletRegistrationSignerSelection({
      configs: context.configs,
      nearAccountId: String(accountId),
      options,
    }),
    options,
    authenticatorOptions,
    ...(confirmationConfigOverride ? { confirmationConfigOverride } : {}),
  });
}

function buildRegistrationEmailOtpAuthContext(args: {
  configs: SeamsConfigsReadonly;
  providerSubject: string;
}): ThresholdEcdsaEmailOtpAuthContext {
  const policy = args.configs.signing.emailOtp.authPolicy;
  const authSubjectId = String(args.providerSubject || '').trim();
  if (!authSubjectId) {
    throw new Error('Email OTP registration auth context requires providerSubject');
  }
  return {
    policy,
    retention: 'session',
    reason: 'login',
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
    authSubjectId,
  };
}

function registrationEcdsaStoreSource(
  authMethod: 'passkey' | 'email_otp',
): ThresholdEcdsaSessionStoreSource {
  switch (authMethod) {
    case 'passkey':
      return 'registration';
    case 'email_otp':
      return 'email_otp';
    default: {
      const exhaustive: never = authMethod;
      throw new Error(`[Registration][postcondition] unsupported auth method: ${exhaustive}`);
    }
  }
}

type RegistrationPersistedSigningLane = {
  signingGrantId: string;
  thresholdSessionId: string;
};

type RegistrationPersistedSigningInventory = {
  walletId: string;
  ed25519?: RegistrationPersistedSigningLane;
  ecdsaByTarget: ReadonlyMap<string, RegistrationPersistedSigningLane>;
};

function assertStrictRegistrationEd25519SigningRecord(args: {
  walletId: string;
}): RegistrationPersistedSigningLane {
  const record = getStoredThresholdEd25519SessionRecordForAccount(args.walletId);
  const parsed = classifyRouterAbEd25519PersistedSigningRecord(record);
  if (parsed.kind !== 'runtime_validated') {
    throw new Error(
      `[Registration][postcondition] Ed25519 Router A/B signable state missing: ${parsed.reason}`,
    );
  }
  return {
    signingGrantId: parsed.value.signingGrantId,
    thresholdSessionId: parsed.value.thresholdSessionId,
  };
}

function assertStrictRegistrationEcdsaSigningRecord(args: {
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  chainTarget: ThresholdEcdsaChainTarget;
}): RegistrationPersistedSigningLane {
  const source = registrationEcdsaStoreSource(args.authMethod);
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const records = listStoredThresholdEcdsaSessionRecordsForWallet(args.walletId, {
    chainTarget: args.chainTarget,
    source,
  });
  if (records.length !== 1) {
    const reason = records.length === 0 ? 'missing_record' : 'ambiguous_record';
    throw new Error(
      `[Registration][postcondition] ECDSA Router A/B signable state missing for ${targetKey}: ${reason}:${records.length}`,
    );
  }
  const record = records[0];
  const parsed = parseRouterAbEcdsaHssSigningWalletSessionFromRecord(record);
  if (!parsed.ok) {
    throw new Error(
      `[Registration][postcondition] ECDSA Router A/B signable state missing for ${targetKey}: ${parsed.reason}`,
    );
  }
  return {
    signingGrantId: parsed.value.signingGrantId,
    thresholdSessionId: parsed.value.thresholdSessionId,
  };
}

function assertStrictRegistrationSigningRecords(args: {
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  expectEd25519: boolean;
  expectedEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
}): RegistrationPersistedSigningInventory {
  let ed25519: RegistrationPersistedSigningLane | undefined;
  if (args.expectEd25519) {
    ed25519 = assertStrictRegistrationEd25519SigningRecord({ walletId: args.walletId });
  }
  const ecdsaByTarget = new Map<string, RegistrationPersistedSigningLane>();
  for (const chainTarget of args.expectedEcdsaChainTargets) {
    const lane = assertStrictRegistrationEcdsaSigningRecord({
      walletId: args.walletId,
      authMethod: args.authMethod,
      chainTarget,
    });
    ecdsaByTarget.set(thresholdEcdsaChainTargetKey(chainTarget), lane);
  }
  return {
    walletId: args.walletId,
    ...(ed25519 ? { ed25519 } : {}),
    ecdsaByTarget,
  };
}

function createRegistrationThresholdWarmSessionPolicyDraft(args: {
  context: ThresholdWarmSessionContext;
  participantIds: readonly number[];
  ecdsaSession:
    | {
        preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
        bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
      }
    | null;
}): ThresholdWarmSessionPolicyDraft | null {
  const participantIds = [...args.participantIds];
  if (!args.ecdsaSession) {
    return createThresholdWarmSessionPolicyDraft(args.context, {
      kind: 'generated_signing_grant',
      participantIds,
    });
  }

  const clientBootstrap = args.ecdsaSession.preparedClientBootstrap.clientBootstrap;
  const serverBootstrap = args.ecdsaSession.bootstrap;
  const clientSigningGrantId = String(clientBootstrap.signingGrantId || '').trim();
  const serverSigningGrantId = String(serverBootstrap.signingGrantId || '').trim();
  if (!clientSigningGrantId || clientSigningGrantId !== serverSigningGrantId) {
    throw new Error(
      '[Registration] combined Ed25519/ECDSA registration has mismatched signing grant',
    );
  }
  if (Math.floor(Number(clientBootstrap.remainingUses)) !== serverBootstrap.remainingUses) {
    throw new Error(
      '[Registration] combined Ed25519/ECDSA registration has mismatched signing budget limits',
    );
  }
  return createThresholdWarmSessionPolicyDraft(args.context, {
    kind: 'shared_signing_grant',
    signingGrantId: clientSigningGrantId,
    ttlMs: clientBootstrap.ttlMs,
    remainingUses: serverBootstrap.remainingUses,
    participantIds,
  });
}

async function assertImmediateRegistrationSigningLanes(args: {
  signingEngine: RegistrationSigningSurface;
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  expectEd25519: boolean;
  expectedEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  requireSharedSigningGrant: boolean;
}): Promise<void> {
  const persistedInventory = assertStrictRegistrationSigningRecords(args);
  const inventory = args.expectEd25519
    ? await assertWalletRuntimePostconditions({
        source: 'registration_finalize',
        walletId: args.walletId,
        authMethod: args.authMethod,
        requiredTargets: [{ curve: 'ed25519' }],
        readPersistedAvailableSigningLanes: async (input) =>
          await args.signingEngine.readPersistedAvailableSigningLanes(input),
      })
    : {
        walletId: args.walletId,
        authMethod: args.authMethod,
        ecdsaByTarget: new Map(),
      };
  if (args.requireSharedSigningGrant) {
    assertCombinedRegistrationSharedSigningGrant({
      walletId: args.walletId,
      inventory,
      persistedInventory,
      expectedEcdsaChainTargets: args.expectedEcdsaChainTargets,
    });
  }
}

function assertCombinedRegistrationSharedSigningGrant(args: {
  walletId: string;
  inventory: WalletRuntimeInventory;
  persistedInventory: RegistrationPersistedSigningInventory;
  expectedEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
}): void {
  const ed25519GrantId = String(
    args.persistedInventory.ed25519?.signingGrantId || args.inventory.ed25519?.signingGrantId || '',
  ).trim();
  if (!ed25519GrantId) {
    throw new Error(
      `[Registration][postcondition] combined registration missing Ed25519 signing grant for ${args.walletId}`,
    );
  }
  for (const chainTarget of args.expectedEcdsaChainTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const ecdsaGrantId = String(
      args.persistedInventory.ecdsaByTarget.get(targetKey)?.signingGrantId || '',
    ).trim();
    if (ecdsaGrantId !== ed25519GrantId) {
      throw new Error(
        `[Registration][postcondition] combined registration split signing budget for ${args.walletId}:${targetKey}`,
      );
    }
  }
}

function expectedEcdsaChainTargetsFromRegistrationSpec(
  ecdsa: ThresholdEcdsaRegistrationSpec,
): ThresholdEcdsaChainTarget[] {
  return ecdsa.chainTargets.map((target) =>
    parseRegistrationEcdsaChainTarget(target, '[Registration][postcondition]'),
  );
}

function parseRegistrationEcdsaChainTarget(
  target: unknown,
  source: string,
): ThresholdEcdsaChainTarget {
  if (!isObject(target)) {
    throw new Error(`${source} invalid ECDSA chain target`);
  }
  return thresholdEcdsaChainTargetFromRequest(target);
}

// Public wrapper without explicit confirmationConfig override.
export async function registerPasskey(
  context: RegistrationWebContext,
  nearAccountId: AccountId,
  options: RegistrationHooksOptions,
  authenticatorOptions: AuthenticatorOptions,
): Promise<RegistrationResult> {
  return registerPasskeyWithAuthenticatorOptions(
    context,
    nearAccountId,
    options,
    authenticatorOptions,
    undefined,
  );
}

async function registerEcdsaWalletOnly(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: Extract<RegistrationSignerSelection, { mode: 'ecdsa_only' }>;
  options: RegistrationHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
  const { context, wallet, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const startedAt = performance.now();
  const registrationTiming = new RegistrationTimingRecorder(startedAt);
  const rpId = String(args.rpId || '').trim();
  const initialEventAccountId = registrationEventAccountId(
    wallet.kind === 'provided' ? String(wallet.walletId) : 'wallet-registration',
  );

  if (!rpId) {
    throw new Error('registerWallet requires rpId');
  }

  emitRegistrationEvent(onEvent, initialEventAccountId, {
    authMethod: args.authMethod.kind,
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    const relayerUrl = String(context.configs.network.relayer.url || '').trim();
    if (!relayerUrl) {
      throw new Error('registerWallet requires relayer.url');
    }
    const finalizeIdempotencyKey = googleEmailOtpFinalizeIdempotencyKey(args.authMethod);
    const registrationWarmup = startRegistrationWarmup({
      recorder: registrationTiming,
      context,
    });

    const managedGrant = await registrationTiming.measure('managedRegistrationGrantMs', () =>
      createManagedRegistrationFlowGrant({
        context,
        ...(wallet.kind === 'provided' ? { walletId: String(wallet.walletId || '').trim() } : {}),
        rpId,
      }),
    );
    const intentResponse = await registrationTiming.measure('registrationIntentMs', () =>
      createWalletRegistrationIntent({
        relayerUrl,
        request: {
          wallet,
          rpId,
          authMethod: args.authMethod,
          signerSelection,
        },
        headers: {
          Authorization: `Bearer ${managedGrant.token}`,
        },
      }),
    );
    const localDigestB64u = await registrationTiming.measure('registrationIntentDigestMs', () =>
      computeRegistrationIntentDigest(intentResponse.intent),
    );
    if (localDigestB64u !== intentResponse.registrationIntentDigestB64u) {
      throw new Error('Registration intent digest mismatch');
    }

    const walletId = intentResponse.intent.walletId;
    const eventAccountId = registrationEventAccountId(String(walletId));
    let passkeyPrfFirstB64u = '';
    let emailOtpClientRootShareHandle:
      | EmailOtpRegistrationEnrollmentMaterial['clientRootShareHandle']
      | null = null;
    let emailOtpRegistrationAuthorityId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
    let emailOtpEnrollment: EmailOtpRegistrationEnrollmentMaterial['emailOtpEnrollment'] | null =
      null;
    let emailOtpRecoveryCodeBackup: Promise<EmailOtpRecoveryCodeBackupOutcome> | null = null;
    let passkeyAuthority: Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>> | null =
      null;
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
    await waitForRegistrationWarmup({
      recorder: registrationTiming,
      warmup: registrationWarmup,
    });
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
        collectPasskeyRegistrationAuthority({
          context,
          walletId: String(walletId),
          signerSlot: 1,
          registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
          options,
          confirmationConfigOverride: confirmationConfig,
          walletIframeActivation: options.walletIframeActivation,
        }),
      );
      registrationTiming.capturePasskeyAuthDiagnostics(passkeyAuthority.diagnostics);
      passkeyPrfFirstB64u = passkeyAuthority.prfFirstB64u;
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
      const enrollment = await registrationTiming.measure('emailOtpEnrollmentMaterialMs', () =>
        resolveEmailOtpRegistrationEnrollmentMaterial({
          context,
          authMethod: emailOtpAuthMethod,
          relayerUrl,
          walletId: String(walletId),
          providerSubject: emailAuthority.providerSubject,
          rpId,
          appSessionJwt: emailOtpAuthMethod.appSessionJwt,
        }),
      );
      emailOtpClientRootShareHandle = enrollment.clientRootShareHandle;
      emailOtpEnrollment = enrollment.emailOtpEnrollment;
      emailOtpRegistrationAuthorityId = emailAuthority.registrationAuthorityId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
      emailOtpRecoveryCodeBackup = startEmailOtpRecoveryCodeBackup({
        recorder: registrationTiming,
        authMethod: emailOtpAuthMethod,
        relayerUrl,
        walletId: String(walletId),
        enrollmentMaterial: enrollment,
        registrationAuthorityId: emailAuthority.registrationAuthorityId,
      });
      startAuthority = {
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      };
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const startedCeremony = await registrationTiming.measure('walletRegisterStartMs', () =>
      startWalletRegistration({
        relayerUrl,
        registrationIntentGrant: intentResponse.registrationIntentGrant,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        intent: intentResponse.intent,
        headers: registrationRouteDiagnosticsHeaders(),
        ...startAuthority,
      }),
    );
    registrationTiming.captureRouteDiagnostics(startedCeremony.registrationDiagnostics);
    if (!startedCeremony.ecdsa) {
      throw new Error('Wallet registration start did not return ECDSA HSS material');
    }
    const ecdsaPrepare = startedCeremony.ecdsa.prepare;
    const ecdsaChainTarget = startedCeremony.ecdsa.chainTargets[0];
    const preparedClientBootstrap = await registrationTiming.measure(
      'ecdsaClientBootstrapMs',
      async () =>
        args.authMethod.kind === 'email_otp'
          ? await (async () => {
              if (!emailOtpClientRootShareHandle) {
                throw new Error('Email OTP ECDSA registration prepare is missing worker handle');
              }
              return await context.signingEngine.prepareEmailOtpEcdsaBootstrap({
                prepare: ecdsaPrepare,
                clientRootShareHandle: emailOtpClientRootShareHandle,
                chainTarget: ecdsaChainTarget,
              });
            })()
          : await context.signingEngine.preparePasskeyEcdsaBootstrap({
              prepare: ecdsaPrepare,
              chainTarget: ecdsaChainTarget,
              passkeyPrfFirstB64u,
              credentialIdB64u: String(
                passkeyAuthority?.credential.rawId || passkeyAuthority?.credential.id || '',
              ).trim(),
            }),
    );
    const responded = await registrationTiming.measure('walletRegisterHssRespondMs', () =>
      respondWalletRegistrationHss({
        relayerUrl,
        headers: registrationRouteDiagnosticsHeaders(),
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        ecdsa: { clientBootstrap: preparedClientBootstrap.clientBootstrap },
      }),
    );
    if (!responded.ecdsa?.bootstrap) {
      throw new Error('Wallet registration HSS respond did not return ECDSA bootstrap material');
    }
    registrationTiming.captureRouteDiagnostics(responded.registrationDiagnostics);
    const ecdsaBootstrap = parseWalletRegistrationEcdsaHssRespond({
      clientBootstrap: preparedClientBootstrap.clientBootstrap,
      serverBootstrap: responded.ecdsa.bootstrap,
    });
    const emailOtpBackupAck = await resolveEmailOtpBackupAck({
      authMethod: args.authMethod,
      backup: emailOtpRecoveryCodeBackup,
    });
    const finalized = await registrationTiming.measure('walletRegisterFinalizeMs', () =>
      finalizeWalletRegistration({
        relayerUrl,
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        headers: registrationRouteDiagnosticsHeaders(),
        ...(finalizeIdempotencyKey ? { idempotencyKey: finalizeIdempotencyKey } : {}),
        ecdsa: {
          expectedKeyHandles: [ecdsaBootstrap.keyHandle],
        },
        ...(emailOtpEnrollment ? { emailOtpEnrollment } : {}),
        ...(emailOtpBackupAck ? { emailOtpBackupAck } : {}),
      }),
    );
    registrationTiming.captureRouteDiagnostics(finalized.registrationDiagnostics);
    if ('kind' in finalized && finalized.kind === 'already_finalized_restore_required') {
      const result = alreadyFinalizedRestoreRequiredResult(finalized.walletId);
      emitRegistrationTimingSummary(
        createFailedRegistrationTimingSummary({
          recorder: registrationTiming,
          authMethod: args.authMethod.kind,
          signerMode: signerSelection.mode,
          errorCode: 'already_finalized_restore_required',
        }),
      );
      afterCall?.(false);
      return result;
    }
    const walletKeys = finalized.ecdsa?.walletKeys || [];
    if (walletKeys.length === 0) {
      throw new Error('Wallet registration finalize did not return ECDSA wallet keys');
    }
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
    await registrationTiming.measure('ecdsaRegistrationPersistenceMs', async () => {
      await context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
        walletId: toWalletId(finalized.walletId),
        relayerUrl,
        preparedClientBootstrap,
        bootstrap: ecdsaBootstrap,
        walletKeys,
        auth:
          args.authMethod.kind === 'email_otp'
            ? {
                kind: 'email_otp',
                emailOtpAuthContext: buildRegistrationEmailOtpAuthContext({
                  configs: context.configs,
                  providerSubject: emailOtpProviderSubject,
                }),
              }
            : {
                kind: 'passkey',
                credentialIdB64u: passkeyEcdsaCredentialIdFromPrepared(preparedClientBootstrap),
              },
      });
      if (args.authMethod.kind === 'passkey') {
        if (!passkeyAuthority) {
          throw new Error('Passkey registration authority was not collected');
        }
        await context.signingEngine.finalizeWalletEcdsaRegistration({
          walletId: finalized.walletId,
          credential: passkeyAuthority.credential,
          walletKeys,
        });
      } else {
        await context.signingEngine.storeWalletEmailOtpEcdsaRegistrationData({
          walletId: finalized.walletId,
          email: emailOtpEmail,
          registrationAuthorityId: emailOtpRegistrationAuthorityId,
          walletKeys,
        });
      }
    });
    await registrationTiming.measure('immediateSigningLaneAssertionMs', () =>
      assertImmediateRegistrationSigningLanes({
        signingEngine: context.signingEngine,
        walletId: finalized.walletId,
        authMethod: args.authMethod.kind,
        expectEd25519: false,
        expectedEcdsaChainTargets: expectedEcdsaChainTargetsFromRegistrationSpec(
          signerSelection.ecdsa,
        ),
        requireSharedSigningGrant: false,
      }),
    );
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
    const primaryKey = walletKeys[0];
    const result: RegistrationResult = {
      success: true,
      thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
    };
    emitRegistrationTimingSummary(
      createSucceededRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: args.authMethod.kind,
        signerMode: signerSelection.mode,
      }),
    );
    afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    const errorCode = registrationErrorCodeFromUnknown(error);
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', initialEventAccountId);
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
        signerMode: signerSelection.mode,
        errorCode: errorCode || null,
      }),
    );
    afterCall?.(false);
    return result;
  }
}

async function registerWalletInternal(
  args: RegisterWalletOperationInput & {
    precomputeMode: RegisterWalletPrecomputeMode;
  },
): Promise<RegistrationResult> {
  const { context, wallet, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const registrationStartedAt = performance.now();
  const registrationTiming = new RegistrationTimingRecorder(registrationStartedAt);
  const registrationState = {
    accountCreated: false,
    contractRegistered: false,
    databaseStored: false,
    contractTransactionId: null as string | null,
  };

  if (signerSelection.mode === 'ecdsa_only') {
    return await registerEcdsaWalletOnly({
      context,
      authMethod: args.authMethod,
      wallet,
      rpId: args.rpId,
      signerSelection,
      options,
      ...(args.confirmationConfigOverride
        ? { confirmationConfigOverride: args.confirmationConfigOverride }
        : {}),
    });
  }
  if (signerSelection.mode !== 'ed25519_only' && signerSelection.mode !== 'ed25519_and_ecdsa') {
    throw new Error(
      'Unified wallet registration currently supports ed25519_only, ecdsa_only, and ed25519_and_ecdsa signer selection',
    );
  }

  const ed25519Selection = signerSelection.ed25519;
  const ecdsaSelection =
    signerSelection.mode === 'ed25519_and_ecdsa' ? signerSelection.ecdsa : null;
  const nearAccountId = toAccountId(ed25519Selection.nearAccountId);
  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('registerWallet requires rpId');
  }

  emitRegistrationEvent(onEvent, nearAccountId, {
    authMethod: args.authMethod.kind,
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    await registrationTiming.measure('inputValidationMs', () =>
      validateRegistrationInputs(context, nearAccountId, args.authMethod.kind, onEvent, onError),
    );

    const finalizeIdempotencyKey = googleEmailOtpFinalizeIdempotencyKey(args.authMethod);
    const expectedPrecomputeScope = walletRegistrationPrecomputeScopeFromArgs({
      authMethod: args.authMethod,
      wallet,
      rpId,
      signerSelection: requireEd25519RegistrationSignerSelection(signerSelection),
    });
    let startedPrecomputeHandle: WalletRegistrationPrecomputeHandleInternal | null = null;
    let precomputeReady: WalletRegistrationPrecomputeReady;
    switch (args.precomputeMode.kind) {
      case 'use_started_precompute': {
        const handle = requireWalletRegistrationPrecomputeHandle(args.precomputeMode.handle);
        startedPrecomputeHandle = handle;
        assertWalletRegistrationPrecomputeScopeMatches({
          expected: expectedPrecomputeScope,
          actual: handle.scope,
        });
        precomputeReady = await handle.read();
        registrationTiming.mergeSnapshot(handle.snapshot());
        registrationTiming.captureRouteDiagnosticsSnapshot(handle.routeDiagnosticsSnapshot());
        break;
      }
      case 'start_inside_register_wallet':
        precomputeReady = await startWalletRegistrationPrecomputeReady({
          context,
          authMethod: args.authMethod,
          wallet,
          rpId,
          signerSelection: requireEd25519RegistrationSignerSelection(signerSelection),
          recorder: registrationTiming,
        });
        break;
      default:
        assertNever(args.precomputeMode);
    }
    const {
      relayerUrl,
      intentResponse,
      registrationWarmup,
      preparedRegistrationPromise,
      thresholdRuntimePolicyScope,
    } = precomputeReady;
    let ed25519PrfFirstB64u = '';
    let ecdsaPasskeyPrfFirstB64u = '';
    let emailOtpClientRootShareHandle:
      | EmailOtpRegistrationEnrollmentMaterial['clientRootShareHandle']
      | null = null;
    let emailOtpRegistrationAuthorityId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
    let emailOtpEnrollment: EmailOtpRegistrationEnrollmentMaterial['emailOtpEnrollment'] | null =
      null;
    let emailOtpRecoveryCodeBackup: Promise<EmailOtpRecoveryCodeBackupOutcome> | null = null;
    let passkeyAuthority: Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>> | null =
      null;
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
    await waitForRegistrationWarmup({
      recorder: registrationTiming,
      warmup: registrationWarmup,
    });
    if (args.authMethod.kind === 'passkey') {
      emitRegistrationEvent(onEvent, nearAccountId, {
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
        collectPasskeyRegistrationAuthority({
          context,
          walletId: String(intentResponse.intent.walletId),
          signerSlot: ed25519Selection.signerSlot,
          registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
          options,
          confirmationConfigOverride: confirmationConfig,
          walletIframeActivation: options.walletIframeActivation,
        }),
      );
      registrationTiming.capturePasskeyAuthDiagnostics(passkeyAuthority.diagnostics);
      ed25519PrfFirstB64u = passkeyAuthority.prfFirstB64u;
      ecdsaPasskeyPrfFirstB64u = passkeyAuthority.prfFirstB64u;
      startAuthority = {
        kind: 'passkey',
        webauthnRegistration: passkeyAuthority.webauthnRegistration,
      };
      emitRegistrationEvent(onEvent, nearAccountId, {
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
          walletId: String(intentResponse.intent.walletId),
          registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
          appSessionJwt: emailOtpAuthMethod.appSessionJwt,
        }),
      );
      const enrollment = await registrationTiming.measure('emailOtpEnrollmentMaterialMs', () =>
        resolveEmailOtpRegistrationEnrollmentMaterial({
          context,
          authMethod: emailOtpAuthMethod,
          relayerUrl,
          walletId: String(intentResponse.intent.walletId),
          providerSubject: emailAuthority.providerSubject,
          rpId,
          appSessionJwt: emailOtpAuthMethod.appSessionJwt,
        }),
      );
      ed25519PrfFirstB64u = enrollment.thresholdEd25519RecoveryCodeSecret32B64u;
      emailOtpClientRootShareHandle = enrollment.clientRootShareHandle;
      emailOtpEnrollment = enrollment.emailOtpEnrollment;
      emailOtpRegistrationAuthorityId = emailAuthority.registrationAuthorityId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
      emailOtpRecoveryCodeBackup = startEmailOtpRecoveryCodeBackup({
        recorder: registrationTiming,
        authMethod: emailOtpAuthMethod,
        relayerUrl,
        walletId: String(intentResponse.intent.walletId),
        enrollmentMaterial: enrollment,
        registrationAuthorityId: emailAuthority.registrationAuthorityId,
      });
      startAuthority = {
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      };
    }

    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED,
      status: 'running',
    });
    const hssClientMaterial = await registrationTiming.measure(
      'ed25519ClientMaterialMs',
      async () =>
        args.authMethod.kind === 'passkey'
          ? await prepareThresholdEd25519RegistrationHssClientMaterial({
              context,
              credential: passkeyAuthority!.credential,
              runtimePolicyScope: thresholdRuntimePolicyScope,
              nearAccountId,
              keyPurpose: ed25519Selection.keyPurpose,
              ed25519HssKeyVersion: parseEd25519HssKeyVersion(ed25519Selection.keyVersion),
              participantIds: ed25519Selection.participantIds,
              derivationVersion: ed25519Selection.derivationVersion,
            })
          : await prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst({
              context,
              prfFirstB64u: ed25519PrfFirstB64u,
              runtimePolicyScope: thresholdRuntimePolicyScope,
              nearAccountId,
              keyPurpose: ed25519Selection.keyPurpose,
              ed25519HssKeyVersion: parseEd25519HssKeyVersion(ed25519Selection.keyVersion),
              participantIds: ed25519Selection.participantIds,
              derivationVersion: ed25519Selection.derivationVersion,
            }),
    );
    const preparedRegistrationOutcome = await registrationTiming.measure(
      'walletRegisterPrepareWaitMs',
      () => preparedRegistrationPromise,
    );
    if (startedPrecomputeHandle) {
      registrationTiming.mergeSnapshot(startedPrecomputeHandle.snapshot());
      registrationTiming.captureRouteDiagnosticsSnapshot(
        startedPrecomputeHandle.routeDiagnosticsSnapshot(),
      );
    }
    if (!preparedRegistrationOutcome.ok) throw preparedRegistrationOutcome.error;
    const preparedRegistration = preparedRegistrationOutcome.value;
    registrationTiming.captureRouteDiagnostics(preparedRegistration.registrationDiagnostics);
    const startedCeremony = await registrationTiming.measure('walletRegisterStartMs', () =>
      startWalletRegistration({
        relayerUrl,
        registrationIntentGrant: intentResponse.registrationIntentGrant,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        intent: intentResponse.intent,
        registrationPreparationId: preparedRegistration.registrationPreparationId,
        headers: registrationRouteDiagnosticsHeaders(),
        ...startAuthority,
      }),
    );
    registrationTiming.captureRouteDiagnostics(startedCeremony.registrationDiagnostics);
    if (!startedCeremony.ed25519) {
      throw new Error('Wallet registration start did not return Ed25519 HSS material');
    }
    if (ecdsaSelection && !startedCeremony.ecdsa) {
      throw new Error('Wallet registration start did not return ECDSA HSS material');
    }
    const startedEd25519 = startedCeremony.ed25519;
    const ecdsaPrepare = startedCeremony.ecdsa?.prepare;
    const ecdsaChainTarget = startedCeremony.ecdsa?.chainTargets[0];
    const ecdsaPreparedClientBootstrapPromise =
      ecdsaSelection && ecdsaPrepare && ecdsaChainTarget
        ? registrationTiming.measure('ecdsaClientBootstrapMs', async () =>
            args.authMethod.kind === 'email_otp'
              ? await (async () => {
                  if (!emailOtpClientRootShareHandle) {
                    throw new Error(
                      'Email OTP ECDSA registration prepare is missing worker handle',
                    );
                  }
                  return await context.signingEngine.prepareEmailOtpEcdsaBootstrap({
                    prepare: ecdsaPrepare,
                    clientRootShareHandle: emailOtpClientRootShareHandle,
                    chainTarget: ecdsaChainTarget,
                  });
                })()
              : await context.signingEngine.preparePasskeyEcdsaBootstrap({
                  prepare: ecdsaPrepare,
                  chainTarget: ecdsaChainTarget,
                  passkeyPrfFirstB64u: ecdsaPasskeyPrfFirstB64u,
                  credentialIdB64u: String(
                    passkeyAuthority?.credential.rawId || passkeyAuthority?.credential.id || '',
                  ).trim(),
                }),
          )
        : Promise.resolve(null);

    const ed25519ClientRequestPromise = registrationTiming.measure('ed25519ClientRequestMs', () =>
      prepareThresholdEd25519RegistrationHssClientRequest({
        context,
        material: hssClientMaterial,
        preparedSession: startedEd25519.preparedSession,
        clientOtOfferMessageB64u: startedEd25519.clientOtOfferMessageB64u,
        ceremonyHandle: startedEd25519.ceremonyHandle,
      }),
    );
    const [ecdsaPreparedClientBootstrap, { clientRequest, clientOutputMaskB64u }] =
      await Promise.all([ecdsaPreparedClientBootstrapPromise, ed25519ClientRequestPromise]);
    const responded = await registrationTiming.measure('walletRegisterHssRespondMs', () =>
      respondWalletRegistrationHss({
        relayerUrl,
        headers: registrationRouteDiagnosticsHeaders(),
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        ed25519: {
          clientRequest: {
            clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
          },
        },
        ...(ecdsaPreparedClientBootstrap
          ? { ecdsa: { clientBootstrap: ecdsaPreparedClientBootstrap.clientBootstrap } }
          : {}),
      }),
    );
    if (!responded.ed25519) {
      throw new Error('Wallet registration HSS respond did not return Ed25519 server input');
    }
    registrationTiming.captureRouteDiagnostics(responded.registrationDiagnostics);
    const respondedEd25519 = responded.ed25519;
    if (ecdsaSelection && !responded.ecdsa?.bootstrap) {
      throw new Error('Wallet registration HSS respond did not return ECDSA bootstrap material');
    }
    const ecdsaBootstrap =
      ecdsaPreparedClientBootstrap && responded.ecdsa?.bootstrap
        ? parseWalletRegistrationEcdsaHssRespond({
            clientBootstrap: ecdsaPreparedClientBootstrap.clientBootstrap,
            serverBootstrap: responded.ecdsa.bootstrap,
          })
        : null;
    const evaluationResult = await registrationTiming.measure('ed25519EvaluationArtifactMs', () =>
      buildThresholdEd25519RegistrationHssClientOwnedArtifact({
        context,
        preparedSession: startedEd25519.preparedSession,
        clientRequest,
        serverInputDelivery: respondedEd25519,
        clientOutputMaskB64u,
      }),
    );

    const requestedPolicy = createRegistrationThresholdWarmSessionPolicyDraft({
      context,
      participantIds: hssClientMaterial.hssContext.participantIds,
      ecdsaSession:
        ecdsaPreparedClientBootstrap && ecdsaBootstrap
          ? {
              preparedClientBootstrap: ecdsaPreparedClientBootstrap,
              bootstrap: ecdsaBootstrap,
            }
          : null,
    });
    if (!requestedPolicy) {
      throw new Error('Threshold warm-session defaults are disabled for registration');
    }
    const emailOtpBackupAck = await resolveEmailOtpBackupAck({
      authMethod: args.authMethod,
      backup: emailOtpRecoveryCodeBackup,
    });
    const finalized = await registrationTiming.measure('walletRegisterFinalizeMs', () =>
      finalizeWalletRegistration({
        relayerUrl,
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        headers: registrationRouteDiagnosticsHeaders(),
        ...(finalizeIdempotencyKey ? { idempotencyKey: finalizeIdempotencyKey } : {}),
        ed25519: {
          evaluationResult,
          sessionPolicy: buildThresholdWarmSessionRequestEnvelope({
            rpId,
            requestedPolicy,
            nearAccountId: String(nearAccountId),
          }).session_policy,
          sessionKind: 'jwt',
        },
        ...(ecdsaBootstrap
          ? {
              ecdsa: {
                expectedKeyHandles: [ecdsaBootstrap.keyHandle],
              },
            }
          : {}),
        ...(emailOtpEnrollment ? { emailOtpEnrollment } : {}),
        ...(emailOtpBackupAck ? { emailOtpBackupAck } : {}),
      }),
    );
    registrationTiming.captureRouteDiagnostics(finalized.registrationDiagnostics);
    if ('kind' in finalized && finalized.kind === 'already_finalized_restore_required') {
      const result = alreadyFinalizedRestoreRequiredResult(finalized.walletId);
      emitRegistrationTimingSummary(
        createFailedRegistrationTimingSummary({
          recorder: registrationTiming,
          authMethod: args.authMethod.kind,
          signerMode: signerSelection.mode,
          errorCode: 'already_finalized_restore_required',
        }),
      );
      afterCall?.(false);
      return result;
    }
    if (!finalized.ed25519) {
      throw new Error('Wallet registration finalize did not return Ed25519 key material');
    }
    const finalizedEd25519 = finalized.ed25519;
    const ecdsaWalletKeys = finalized.ecdsa?.walletKeys || [];
    if (ecdsaSelection && ecdsaWalletKeys.length === 0) {
      throw new Error('Wallet registration finalize did not return ECDSA wallet keys');
    }
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED,
      status: 'succeeded',
      data: {
        verified: true,
        nearPublicKey: finalizedEd25519.publicKey,
      },
    });

    registrationState.accountCreated = ed25519Selection.createNearAccount;
    registrationState.contractRegistered = true;
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_STARTED,
      status: 'running',
    });
    const completedThresholdEd25519Registration = registrationTiming.measureSync(
      'ed25519CompletionParseMs',
      () =>
        completeRegisteredThresholdEd25519Registration({
          thresholdEd25519: finalizedEd25519,
          expectedSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
            rpId,
            requestedPolicy,
            nearAccountId: String(nearAccountId),
            relayerKeyId: finalizedEd25519.relayerKeyId,
          }).session_policy,
        }),
    );
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_SUCCEEDED,
      status: 'succeeded',
    });

    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    const storedRegistration = await registrationTiming.measure(
      'localWalletRegistrationPersistenceMs',
      async () => {
        const stored =
          args.authMethod.kind === 'passkey'
            ? await context.signingEngine.storeWalletEd25519RegistrationData({
                walletId: finalized.walletId,
                nearAccountId,
                credential: passkeyAuthority!.credential,
                operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
                signerSlot: ed25519Selection.signerSlot,
                relayerKeyId: finalizedEd25519.relayerKeyId,
                keyVersion: finalizedEd25519.keyVersion,
                participantIds: finalizedEd25519.participantIds,
                clientParticipantId: finalizedEd25519.clientParticipantId,
                relayerParticipantId: finalizedEd25519.relayerParticipantId,
              })
            : await context.signingEngine.storeWalletEmailOtpEd25519RegistrationData({
                walletId: finalized.walletId,
                nearAccountId,
                email: emailOtpEmail,
                registrationAuthorityId: emailOtpRegistrationAuthorityId,
                operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
                signerSlot: ed25519Selection.signerSlot,
                relayerKeyId: finalizedEd25519.relayerKeyId,
                keyVersion: finalizedEd25519.keyVersion,
                participantIds: finalizedEd25519.participantIds,
                clientParticipantId: finalizedEd25519.clientParticipantId,
                relayerParticipantId: finalizedEd25519.relayerParticipantId,
              });
        const persistedUser = await context.signingEngine.getUserBySignerSlot(
          nearAccountId,
          stored.signerSlot,
        );
        if (!persistedUser) {
          throw new Error(
            `[Registration] profile/account mapping was not persisted for ${String(
              nearAccountId,
            )} signer slot ${stored.signerSlot}`,
          );
        }
        return stored;
      },
    );
    const signerSlot = storedRegistration.signerSlot;
    const thresholdEd25519RegistrationSessionPolicy = buildThresholdWarmSessionRequestEnvelope({
      rpId,
      requestedPolicy,
      nearAccountId: String(nearAccountId),
      relayerKeyId: finalizedEd25519.relayerKeyId,
    }).session_policy;
    await registrationTiming.measure('thresholdEd25519SessionPersistenceMs', async () => {
      if (args.authMethod.kind === 'email_otp') {
        await persistRegisteredThresholdEd25519Session({
          signingEngine: context.signingEngine,
          nearAccountId,
          signerSlot,
          auth: {
            kind: 'email_otp',
            emailOtpAuthContext: buildRegistrationEmailOtpAuthContext({
              configs: context.configs,
              providerSubject: emailOtpProviderSubject,
            }),
          },
          rpId,
          relayerUrl,
          prfFirstB64u: hssClientMaterial.prfFirstB64u,
          registrationHssClientMaterial: hssClientMaterial,
          registrationSessionPolicy: thresholdEd25519RegistrationSessionPolicy,
          completedRegistration: completedThresholdEd25519Registration,
        });
      } else {
        await persistRegisteredThresholdEd25519Session({
          signingEngine: context.signingEngine,
          nearAccountId,
          signerSlot,
          auth: { kind: 'passkey' },
          rpId,
          relayerUrl,
          prfFirstB64u: hssClientMaterial.prfFirstB64u,
          registrationSessionPolicy: thresholdEd25519RegistrationSessionPolicy,
          completedRegistration: completedThresholdEd25519Registration,
        });
        const registrationWarmSession = completedThresholdEd25519Registration.registered.session;
        if (!registrationWarmSession) {
          throw new Error('Wallet registration did not return an Ed25519 warm session');
        }
        await reconstructThresholdEd25519SigningMaterialFromWarmSession({
          context,
          credential: passkeyAuthority!.credential,
          nearAccountId,
          rpId,
          relayerUrl,
          relayerKeyId: finalizedEd25519.relayerKeyId,
          signerSlot,
          session: registrationWarmSession,
          ed25519HssKeyVersion: parseEd25519HssKeyVersion(finalizedEd25519.keyVersion),
          materialCreatedAtMs: Date.now(),
          participantIdsHint: finalizedEd25519.participantIds,
        });
      }
    });
    if (ecdsaWalletKeys.length > 0) {
      if (!ecdsaPreparedClientBootstrap || !ecdsaBootstrap) {
        throw new Error('Wallet registration ECDSA session material was not prepared');
      }
      await registrationTiming.measure('ecdsaRegistrationPersistenceMs', async () => {
        await context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
          walletId: toWalletId(finalized.walletId),
          relayerUrl,
          preparedClientBootstrap: ecdsaPreparedClientBootstrap,
          bootstrap: ecdsaBootstrap,
          walletKeys: ecdsaWalletKeys,
          auth:
            args.authMethod.kind === 'email_otp'
              ? {
                  kind: 'email_otp',
                  emailOtpAuthContext: buildRegistrationEmailOtpAuthContext({
                    configs: context.configs,
                    providerSubject: emailOtpProviderSubject,
                  }),
                }
              : {
                  kind: 'passkey',
                  credentialIdB64u: passkeyEcdsaCredentialIdFromPrepared(
                    ecdsaPreparedClientBootstrap,
                  ),
                },
        });
        if (args.authMethod.kind === 'passkey') {
          await context.signingEngine.storeWalletEcdsaSignerRecords({
            walletId: finalized.walletId,
            walletKeys: ecdsaWalletKeys,
          });
        } else {
          await context.signingEngine.storeWalletEmailOtpEcdsaSignerRecords({
            walletId: finalized.walletId,
            walletKeys: ecdsaWalletKeys,
          });
        }
      });
    }
    await registrationTiming.measure('walletStateActivationMs', async () => {
      try {
        await context.signingEngine.activateAuthenticatedWalletState({
          nearAccountId,
          nearClient: context.nearClient,
        });
      } catch (initErr) {
        console.warn('Failed to initialize current user after wallet registration:', initErr);
      }
    });
    await registrationTiming.measure('immediateSigningLaneAssertionMs', () =>
      assertImmediateRegistrationSigningLanes({
        signingEngine: context.signingEngine,
        walletId: finalized.walletId,
        authMethod: args.authMethod.kind,
        expectEd25519: true,
        expectedEcdsaChainTargets: ecdsaSelection
          ? expectedEcdsaChainTargetsFromRegistrationSpec(ecdsaSelection)
          : [],
        requireSharedSigningGrant: Boolean(ecdsaSelection),
      }),
    );
    registrationState.databaseStored = true;
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
      data: {
        thresholdPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
        relayerKeyId: completedThresholdEd25519Registration.registered.relayerKeyId,
        signerSlot,
      },
    });

    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });
    const primaryEcdsaWalletKey = ecdsaWalletKeys[0] || null;
    const successResult: RegistrationResult = {
      success: true,
      nearAccountId,
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      transactionId: registrationState.contractTransactionId,
      ...(primaryEcdsaWalletKey
        ? {
            thresholdEcdsaEthereumAddress: primaryEcdsaWalletKey.thresholdOwnerAddress,
            thresholdEcdsaPublicKeyB64u: primaryEcdsaWalletKey.thresholdEcdsaPublicKeyB64u,
          }
        : {}),
    };
    emitRegistrationTimingSummary(
      createSucceededRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: args.authMethod.kind,
        signerMode: signerSelection.mode,
      }),
    );
    afterCall?.(true, successResult);
    return successResult;
  } catch (error: unknown) {
    const errorCode = registrationErrorCodeFromUnknown(error);
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', nearAccountId);
    const rollback = await performRegistrationRollback(
      registrationState,
      nearAccountId,
      context.signingEngine,
    );
    const errorObject = registrationErrorWithCode(errorMessage, errorCode);
    onError?.(errorObject);
    emitRegistrationEvent(onEvent, nearAccountId, {
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
      data: { rollback },
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
        signerMode: signerSelection.mode,
        errorCode: errorCode || null,
      }),
    );
    afterCall?.(false);
    return result;
  }
}

export async function registerWallet(
  args: RegisterWalletOperationInput,
): Promise<RegistrationResult> {
  return await registerWalletInternal({
    ...args,
    precomputeMode: { kind: 'start_inside_register_wallet' },
  });
}

export async function registerWalletWithStartedPrecompute(
  args: RegisterWalletOperationInput & {
    precompute: WalletRegistrationPrecomputeHandle;
  },
): Promise<RegistrationResult> {
  return await registerWalletInternal({
    ...args,
    precomputeMode: {
      kind: 'use_started_precompute',
      handle: args.precompute,
    },
  });
}

export async function addWalletSigner(args: {
  context: RegistrationWebContext;
  walletId: WalletId | string;
  rpId: string;
  signerSelection: AddSignerSelection;
  options: RegistrationHooksOptions;
}): Promise<RegistrationResult> {
  const { context, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const walletId = walletIdFromString(String(args.walletId || '').trim());
  const eventAccountId = registrationEventAccountId(String(walletId));
  const rpId = String(args.rpId || '').trim();
  const startedAt = performance.now();

  if (!walletId) {
    throw new Error('addWalletSigner requires walletId');
  }
  if (!rpId) {
    throw new Error('addWalletSigner requires rpId');
  }
  emitRegistrationEvent(onEvent, eventAccountId, {
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    const relayerUrl = String(context.configs.network.relayer.url || '').trim();
    if (!relayerUrl) {
      throw new Error('addWalletSigner requires relayer.url');
    }

    const managedGrant = await createManagedRegistrationFlowGrant({
      context,
      nearAccountId: String(walletId),
      rpId,
    });
    const intentResponse = await createWalletAddSignerIntent({
      relayerUrl,
      walletId,
      request: {
        walletId,
        rpId,
        signerSelection,
      },
      headers: {
        Authorization: `Bearer ${managedGrant.token}`,
      },
    });
    const localDigestB64u = await computeAddSignerIntentDigest(intentResponse.intent);
    if (localDigestB64u !== intentResponse.addSignerIntentDigestB64u) {
      throw new Error('Add-signer intent digest mismatch');
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED,
      status: 'waiting_for_user',
      interaction: {
        kind: 'passkey_assert',
        overlay: 'show',
      },
    });
    const authenticators = await IndexedDBManager.listProfileAuthenticators(String(walletId));
    const allowCredentials = authenticators.map((authenticator) => ({
      id: String(authenticator.credentialId || ''),
      type: 'public-key',
      transports: webAuthnTransportsFromRaw(authenticator.transports),
    }));
    const webauthnAuthentication =
      await context.signingEngine.getAuthenticationCredentialsSerialized({
        subjectId: String(walletId),
        challengeB64u: intentResponse.addSignerIntentDigestB64u,
        allowCredentials,
        includeSecondPrfOutput: false,
      });
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
      status: 'succeeded',
      interaction: {
        kind: 'passkey_assert',
        overlay: 'hide',
      },
    });

    const redactedAuthentication = redactCredentialExtensionOutputs(webauthnAuthentication);
    if (signerSelection.mode === 'ed25519') {
      const runtimePolicyScope = intentResponse.intent.runtimePolicyScope;
      if (!runtimePolicyScope?.signingRootVersion) {
        throw new Error('Add-signer intent is missing runtime policy scope');
      }
      const thresholdRuntimePolicyScope: ThresholdRuntimePolicyScope = {
        orgId: runtimePolicyScope.orgId,
        projectId: runtimePolicyScope.projectId,
        envId: runtimePolicyScope.envId,
        signingRootVersion: runtimePolicyScope.signingRootVersion,
      };
      const nearAccountId = toAccountId(signerSelection.ed25519.nearAccountId);
      const hssClientMaterial = await prepareThresholdEd25519RegistrationHssClientMaterial({
        context,
        credential: webauthnAuthentication,
        runtimePolicyScope: thresholdRuntimePolicyScope,
        nearAccountId,
        keyPurpose: signerSelection.ed25519.keyPurpose,
        ed25519HssKeyVersion: parseEd25519HssKeyVersion(signerSelection.ed25519.keyVersion),
        participantIds: signerSelection.ed25519.participantIds,
        derivationVersion: signerSelection.ed25519.derivationVersion,
      });
      const startedCeremony = await startWalletAddSigner({
        relayerUrl,
        walletId,
        addSignerIntentGrant: intentResponse.addSignerIntentGrant,
        addSignerIntentDigestB64u: intentResponse.addSignerIntentDigestB64u,
        intent: intentResponse.intent,
        auth: {
          kind: 'webauthn_assertion',
          credential: redactedAuthentication,
          expectedChallengeDigestB64u: intentResponse.addSignerIntentDigestB64u,
        },
      });
      if (!startedCeremony.ed25519) {
        throw new Error('Wallet add-signer start did not return Ed25519 HSS material');
      }
      const { clientRequest, clientOutputMaskB64u } =
        await prepareThresholdEd25519RegistrationHssClientRequest({
          context,
          material: hssClientMaterial,
          preparedSession: startedCeremony.ed25519.preparedSession,
          clientOtOfferMessageB64u: startedCeremony.ed25519.clientOtOfferMessageB64u,
          ceremonyHandle: startedCeremony.ed25519.ceremonyHandle,
        });
      const responded = await respondWalletAddSignerHss({
        relayerUrl,
        walletId,
        addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
        ed25519: {
          clientRequest: {
            clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
          },
        },
      });
      if (!responded.ed25519) {
        throw new Error('Wallet add-signer HSS respond did not return Ed25519 server input');
      }
      const evaluationResult = await buildThresholdEd25519RegistrationHssClientOwnedArtifact({
        context,
        preparedSession: startedCeremony.ed25519.preparedSession,
        clientRequest,
        serverInputDelivery: responded.ed25519,
        clientOutputMaskB64u,
      });
      const requestedPolicy = createThresholdWarmSessionPolicyDraft(context, {
        kind: 'generated_signing_grant',
        participantIds: hssClientMaterial.hssContext.participantIds,
      });
      if (!requestedPolicy) {
        throw new Error('Threshold warm-session defaults are disabled for add-signer');
      }
      const finalized = await finalizeWalletAddSigner({
        relayerUrl,
        walletId,
        addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
        ed25519: {
          evaluationResult,
          sessionPolicy: buildThresholdWarmSessionRequestEnvelope({
            rpId,
            requestedPolicy,
            nearAccountId: String(nearAccountId),
          }).session_policy,
          sessionKind: 'jwt',
        },
      });
      if (!finalized.ed25519) {
        throw new Error('Wallet add-signer finalize did not return Ed25519 key material');
      }
      const completedThresholdEd25519Registration = completeRegisteredThresholdEd25519Registration({
        thresholdEd25519: finalized.ed25519,
        expectedSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
          rpId,
          requestedPolicy,
          nearAccountId: String(nearAccountId),
          relayerKeyId: finalized.ed25519.relayerKeyId,
        }).session_policy,
      });

      emitRegistrationEvent(onEvent, eventAccountId, {
        phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
        status: 'running',
      });
      const storedRegistration =
        await context.signingEngine.finalizeWalletEd25519SignerRegistration({
          walletId,
          nearAccountId,
          credential: redactedAuthentication,
          operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
          signerSlot: signerSelection.ed25519.signerSlot,
          relayerKeyId: finalized.ed25519.relayerKeyId,
          keyVersion: finalized.ed25519.keyVersion,
          participantIds: finalized.ed25519.participantIds,
          clientParticipantId: finalized.ed25519.clientParticipantId,
          relayerParticipantId: finalized.ed25519.relayerParticipantId,
        });
      await persistRegisteredThresholdEd25519Session({
        signingEngine: context.signingEngine,
        nearAccountId,
        signerSlot: storedRegistration.signerSlot,
        auth: { kind: 'passkey' },
        rpId,
        relayerUrl,
        prfFirstB64u: hssClientMaterial.prfFirstB64u,
        registrationSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
          rpId,
          requestedPolicy,
          nearAccountId: String(nearAccountId),
          relayerKeyId: finalized.ed25519.relayerKeyId,
        }).session_policy,
        completedRegistration: completedThresholdEd25519Registration,
      });
      emitRegistrationEvent(onEvent, eventAccountId, {
        phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
        status: 'succeeded',
      });
      emitRegistrationEvent(onEvent, eventAccountId, {
        phase: RegistrationEventPhase.STEP_11_COMPLETED,
        status: 'succeeded',
      });

      const result: RegistrationResult = {
        success: true,
        nearAccountId,
        operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      };
      console.info('[Registration] add-signer flow timings', {
        walletId: String(walletId),
        totalMs: Math.round(performance.now() - startedAt),
      });
      afterCall?.(true, result);
      return result;
    }

    const passkeyPrfFirstB64u = requirePasskeyPrfFirstB64u(
      webauthnAuthentication,
      'Wallet add-signer ECDSA bootstrap',
    );

    const startedCeremony = await startWalletAddSigner({
      relayerUrl,
      walletId,
      addSignerIntentGrant: intentResponse.addSignerIntentGrant,
      addSignerIntentDigestB64u: intentResponse.addSignerIntentDigestB64u,
      intent: intentResponse.intent,
      auth: {
        kind: 'webauthn_assertion',
        credential: redactedAuthentication,
        expectedChallengeDigestB64u: intentResponse.addSignerIntentDigestB64u,
      },
    });
    if (!startedCeremony.ecdsa) {
      throw new Error('Wallet add-signer start did not return ECDSA HSS material');
    }
    const preparedClientBootstrap = await context.signingEngine.preparePasskeyEcdsaBootstrap({
      prepare: startedCeremony.ecdsa.prepare,
      chainTarget: startedCeremony.ecdsa.chainTargets[0],
      passkeyPrfFirstB64u,
      credentialIdB64u: String(
        webauthnAuthentication.rawId || webauthnAuthentication.id || '',
      ).trim(),
    });
    const responded = await respondWalletAddSignerHss({
      relayerUrl,
      walletId,
      addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
      ecdsa: { clientBootstrap: preparedClientBootstrap.clientBootstrap },
    });
    if (!responded.ecdsa?.bootstrap) {
      throw new Error('Wallet add-signer HSS respond did not return ECDSA bootstrap material');
    }
    const ecdsaBootstrap = parseWalletRegistrationEcdsaHssRespond({
      clientBootstrap: preparedClientBootstrap.clientBootstrap,
      serverBootstrap: responded.ecdsa.bootstrap,
    });
    const finalized = await finalizeWalletAddSigner({
      relayerUrl,
      walletId,
      addSignerCeremonyId: startedCeremony.addSignerCeremonyId,
      ecdsa: {
        expectedKeyHandles: [ecdsaBootstrap.keyHandle],
      },
    });
    const walletKeys = finalized.ecdsa?.walletKeys || [];
    if (walletKeys.length === 0) {
      throw new Error('Wallet add-signer finalize did not return ECDSA wallet keys');
    }

    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    await context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
      walletId: toWalletId(walletId),
      relayerUrl,
      preparedClientBootstrap,
      bootstrap: ecdsaBootstrap,
      walletKeys,
      auth: {
        kind: 'passkey',
        credentialIdB64u: passkeyEcdsaCredentialIdFromPrepared(preparedClientBootstrap),
      },
    });
    await context.signingEngine.storeWalletEcdsaSignerRecords({
      walletId,
      walletKeys,
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
    });
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.STEP_11_COMPLETED,
      status: 'succeeded',
    });

    const primaryKey = walletKeys[0];
    const result: RegistrationResult = {
      success: true,
      thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
    };
    console.info('[Registration] add-signer flow timings', {
      walletId: String(walletId),
      totalMs: Math.round(performance.now() - startedAt),
    });
    afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    const errorCode = registrationErrorCodeFromUnknown(error);
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', eventAccountId);
    const errorObject = registrationErrorWithCode(errorMessage, errorCode);
    onError?.(errorObject);
    emitRegistrationEvent(onEvent, eventAccountId, {
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      message: errorMessage,
      interaction: {
        kind: 'passkey_assert',
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
    console.info('[Registration] add-signer flow timings', {
      walletId: String(walletId),
      totalMs: Math.round(performance.now() - startedAt),
      failed: true,
    });
    afterCall?.(false);
    return result;
  }
}

//////////////////////////////////////
// HELPER FUNCTIONS
//////////////////////////////////////

/**
 * Validates registration inputs and throws errors if invalid
 * @param nearAccountId - NEAR account ID to validate
 * @param onEvent - Optional callback for registration progress events
 * @param onError - Optional callback for error handling
 */
const validateRegistrationInputs = async (
  context: {
    configs: SeamsConfigsReadonly;
    signingEngine: RegistrationSigningSurface;
    nearClient: NearClient;
  },
  nearAccountId: AccountId,
  authMethod: RegistrationAuthMethodInput['kind'],
  onEvent?: RegistrationHooksOptions['onEvent'],
  onError?: (error: Error) => void,
) => {
  emitRegistrationEvent(onEvent, nearAccountId, {
    authMethod,
    phase: RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_STARTED,
    status: 'running',
  });

  // Validation
  if (!nearAccountId) {
    const error = new Error('NEAR account ID is required for registration.');
    onError?.(error);
    throw error;
  }
  // Validate the account ID format
  const validation = validateNearAccountId(nearAccountId);
  if (!validation.valid) {
    const error = new Error(`Invalid NEAR account ID: ${validation.error}`);
    onError?.(error);
    throw error;
  }
  if (!window.isSecureContext) {
    const error = new Error('Passkey operations require a secure context (HTTPS or localhost).');
    onError?.(error);
    throw error;
  }

  // Best-effort pre-check: avoid prompting for passkey creation if the account name
  // is already taken on-chain. Final enforcement still happens in the relay + chain.

  const accountExists = await checkNearAccountExistsBestEffort(
    context.nearClient,
    String(nearAccountId),
  );
  if (accountExists) {
    const error = new Error(`Account ${nearAccountId} already exists. Please log in instead.`);
    onError?.(error);
    throw error;
  }

  emitRegistrationEvent(onEvent, nearAccountId, {
    authMethod,
    phase: RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_SUCCEEDED,
    status: 'succeeded',
  });
  return;
};

/**
 * Rollback registration data in case of errors
 */
async function performRegistrationRollback(
  registrationState: {
    accountCreated: boolean;
    contractRegistered: boolean;
    databaseStored: boolean;
    contractTransactionId: string | null;
  },
  nearAccountId: AccountId,
  registrationAccounts: Pick<RegistrationAccountSurface, 'rollbackUserRegistration'>,
): Promise<Record<string, unknown>> {
  console.debug('Starting registration rollback...', registrationState);
  const rollback: Record<string, unknown> = {
    databaseRolledBack: false,
    databasePreserved: false,
    onChainRollbackPossible: false,
    contractTransactionId: registrationState.contractTransactionId,
  };

  try {
    if (registrationState.databaseStored) {
      if (registrationState.accountCreated || registrationState.contractRegistered) {
        rollback.databasePreserved = true;
        rollback.databaseRollbackSkippedReason = 'on_chain_account_created';
        console.debug(
          'Preserving local registration data because on-chain account state is immutable',
        );
      } else {
        console.debug('Rolling back database storage...');
        await registrationAccounts.rollbackUserRegistration(nearAccountId);
        rollback.databaseRolledBack = true;
        console.debug('Database rollback completed');
      }
    }

    if (registrationState.contractRegistered) {
      console.debug('Registration transaction cannot be rolled back (immutable blockchain state)');
      rollback.onChainStateImmutable = true;
    }
    console.debug('Registration rollback completed');
  } catch (rollbackError: unknown) {
    console.error('Rollback failed:', rollbackError);
    rollback.rollbackError =
      rollbackError && typeof rollbackError === 'object' && 'message' in rollbackError
        ? String((rollbackError as { message?: unknown }).message || '')
        : String(rollbackError || '');
  }
  return rollback;
}
