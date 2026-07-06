import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { isObject, validateNearAccountId } from '@shared/utils/validation';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import type {
  CreateRegistrationFlowEventInput,
  RegistrationFlowEvent,
  RegistrationHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { RegistrationResult, SeamsConfigsReadonly } from '@/core/types/seams';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { createRegistrationFlowEvent, RegistrationEventPhase } from '@/core/types/sdkSentEvents';
import { createManagedRegistrationFlowGrant } from '@/SeamsWeb/operations/registration/createAccountRouterApiServer';
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
  type CompletedThresholdEd25519Registration,
  type ThresholdEd25519FinalizedRegistrationHssMaterial,
  type ThresholdEd25519RegistrationHssClientMaterial,
  type ThresholdWarmSessionContext,
  type ThresholdWarmSessionPolicyDraft,
  type ThresholdWarmSessionRequestEnvelope,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import type {
  PasskeyWalletRegistrationEcdsaPreparedClientBootstrap,
  WalletRegistrationEcdsaPreparedClientBootstrap,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap';
import type {
  FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket,
  FinalizeWalletRegistrationEcdsaSessionsDiagnostics,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { sha256HexUtf8 } from '@shared/utils/digests';
import { checkNearAccountExistsBestEffort } from '@/core/rpcClients/near/rpcCalls';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { normalizeRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { IndexedDBManager } from '@/core/indexedDB';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  AddSignerSelection,
  NearEd25519SigningKeyId,
  RegistrationAuthMethodInput,
  RegistrationEd25519AuthorityScope,
  RegistrationEvmFamilyEcdsaSignerPlan,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationNearAccountProvisioning,
  RegistrationNearEd25519SignerPlan,
  RegistrationSignerPlan,
  RegistrationSignerPlanBranch,
  RegisterWalletInput,
  RegistrationSignerSetSelection,
  ThresholdEcdsaRegistrationSpec,
  ThresholdEd25519RegistrationSpec,
  WalletId,
} from '@shared/utils/registrationIntent';
import {
  computeRegistrationNearEd25519SigningKeyId,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  nearEd25519SigningKeyIdFromString,
  registrationProvisioningScopeKey,
  registrationSignerPlanFromSelection,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { parseEmailOtpProviderUserId } from '@shared/utils/domainIds';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  deriveEvmFamilySigningKeySlotId,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
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
  advanceWalletRegistrationHssState,
  finalizeWalletAddSigner,
  finalizeWalletRegistration,
  parseWalletRegistrationEcdsaHssRespond,
  prepareWalletRegistration,
  respondWalletAddSignerHss,
  respondWalletRegistrationHss,
  startWalletAddSigner,
  startWalletRegistration,
  type RegistrationPreparationId,
  type WalletRegistrationEcdsaHssRespondBootstrap,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEmailOtpBackupAck,
  type WalletRegistrationFinalizeResponse,
  type WalletRegistrationHssRespondResponse,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
} from '@/core/rpcClients/relayer/walletRegistration';
import { fetchRouterAbPublicKeysetV2 } from '@/core/rpcClients/relayer/routerAbPublicKeyset';
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
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

// Registration forces a visible, clickable confirmation for cross-origin safety.

export const REGISTRATION_TIMING_LABEL = '[Registration] wallet timing summary';
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

function emailOtpRegistrationEd25519AuthorityScope(args: {
  proofKind: Extract<RegistrationAuthMethodInput, { kind: 'email_otp' }>['proofKind'];
  providerSubject: string;
}): Extract<RegistrationEd25519AuthorityScope, { kind: 'email_otp' }> {
  const providerUserId = parseEmailOtpProviderUserId(args.providerSubject);
  if (!providerUserId.ok) {
    throw new Error(providerUserId.error.message);
  }
  return {
    kind: 'email_otp',
    provider: args.proofKind === 'google_sso_registration' ? 'google' : 'email',
    providerUserId: providerUserId.value,
  };
}

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
type RegistrationTimingSignerBranch = 'near_ed25519' | 'evm_family_ecdsa';
type RegistrationTimingSignerSet = {
  kind: 'signer_set';
  branches: readonly RegistrationTimingSignerBranch[];
};

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
  ed25519AddStageRequestMs: number;
  walletRegisterHssAdvanceStateMs: number;
  ed25519EvaluationArtifactMs: number;
  emailOtpRecoveryCodeBackupMs: number;
  walletRegisterFinalizeMs: number;
  ed25519CompletionParseMs: number;
  localWalletRegistrationPersistenceMs: number;
  thresholdEd25519SessionPersistenceMs: number;
  thresholdEd25519KeyMaterialPersistenceMs: number;
  thresholdEd25519SessionNormalizeMs: number;
  thresholdEd25519WarmMaterialValidationMs: number;
  thresholdEd25519WarmCapabilityPersistenceMs: number;
  thresholdEd25519WorkerMaterialPersistenceMs: number;
  thresholdEd25519SigningSessionHydrationMs: number;
  thresholdEd25519SealedSessionPersistenceMs: number;
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
  walletStateActivationMs: number;
  immediateSigningLaneAssertionMs: number;
};

type RegistrationTimingBucketName = keyof RegistrationTimingBucketValues;

type RegistrationCriticalPathBucket = {
  name: RegistrationTimingBucketName;
  durationMs: number;
};

type RegistrationCriticalPathSummary = {
  kind: 'registration_critical_path_summary_v1';
  totalElapsedMs: number;
  measuredWorkMs: number;
  overlappedOrBackgroundMs: number;
  topBuckets: readonly RegistrationCriticalPathBucket[];
};

type EmailOtpRegistrationAuthMethod = Extract<RegistrationAuthMethodInput, { kind: 'email_otp' }>;
type EmailOtpRegistrationEcdsaBootstrapInput = Parameters<
  RegistrationSigningSurface['prepareEmailOtpEcdsaBootstrap']
>[0];
type EmailOtpRegistrationEcdsaRootMaterialRequest =
  | {
      kind: 'ecdsa_root_requested';
      targets: readonly [
        {
          chainTarget: ThresholdEcdsaChainTarget;
          evmFamilySigningKeySlotId: string;
        },
        ...{
          chainTarget: ThresholdEcdsaChainTarget;
          evmFamilySigningKeySlotId: string;
        }[],
      ];
    }
  | {
      kind: 'ecdsa_root_not_requested';
      targets?: never;
    };

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

type NearEd25519RegistrationBranch = RegistrationNearEd25519SignerPlan;
type EvmFamilyEcdsaRegistrationBranch = RegistrationEvmFamilyEcdsaSignerPlan;

export type WalletRegistrationPrecomputeScope = {
  authMethodKind: RegistrationAuthMethodInput['kind'];
  walletScopeKey: string;
  authorityScopeKey: string;
  signerSetScopeKey: string;
  accountProvisioningScopeKey: string;
};

type WalletRegistrationPrecomputeReady = {
  relayerUrl: string;
  intentResponse: Awaited<ReturnType<typeof createWalletRegistrationIntent>>;
  registrationWarmup: Promise<RegistrationWarmupOutcome>;
  thresholdRuntimePolicyScope: ThresholdRuntimePolicyScope;
};
type WalletRegistrationIntentResponse = Awaited<ReturnType<typeof createWalletRegistrationIntent>>;

type WalletRegistrationPrecomputeScopeField = keyof WalletRegistrationPrecomputeScope;

type WalletRegistrationPrecomputeScopeMismatch = {
  field: WalletRegistrationPrecomputeScopeField;
  expected: string;
  actual: string;
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
  ed25519AddStageRequestMs: number;
  walletRegisterHssAdvanceStateMs: number;
  ed25519EvaluationArtifactMs: number;
  ed25519CompletionParseMs: number;
  thresholdEd25519SessionPersistenceMs: number;
  thresholdEd25519KeyMaterialPersistenceMs: number;
  thresholdEd25519SessionNormalizeMs: number;
  thresholdEd25519WarmMaterialValidationMs: number;
  thresholdEd25519WarmCapabilityPersistenceMs: number;
  thresholdEd25519WorkerMaterialPersistenceMs: number;
  thresholdEd25519SigningSessionHydrationMs: number;
  thresholdEd25519SealedSessionPersistenceMs: number;
};

type Ed25519DisabledRegistrationTiming = {
  kind: 'ed25519_disabled';
  ed25519ClientMaterialMs: 0;
  ed25519ClientRequestMs: 0;
  ed25519AddStageRequestMs: 0;
  walletRegisterHssAdvanceStateMs: 0;
  ed25519EvaluationArtifactMs: 0;
  ed25519CompletionParseMs: 0;
  thresholdEd25519SessionPersistenceMs: 0;
  thresholdEd25519KeyMaterialPersistenceMs: 0;
  thresholdEd25519SessionNormalizeMs: 0;
  thresholdEd25519WarmMaterialValidationMs: 0;
  thresholdEd25519WarmCapabilityPersistenceMs: 0;
  thresholdEd25519WorkerMaterialPersistenceMs: 0;
  thresholdEd25519SigningSessionHydrationMs: 0;
  thresholdEd25519SealedSessionPersistenceMs: 0;
};

type RegistrationEd25519Timing =
  | Ed25519EnabledRegistrationTiming
  | Ed25519DisabledRegistrationTiming;

type EcdsaEnabledRegistrationTiming = {
  kind: 'ecdsa_enabled';
  ecdsaClientBootstrapMs: number;
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
};

type SucceededRegistrationTimingSummary = {
  kind: 'registration_timing_summary_v1';
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
  kind: 'registration_timing_summary_v1';
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

function requireNearEd25519RegistrationBranch(
  plan: RegistrationSignerPlan,
): RegistrationNearEd25519SignerPlan {
  const branch = findRegistrationSignerPlanNearEd25519Branch(plan);
  if (!branch) {
    throw new Error('Wallet registration requires a NEAR Ed25519 signer branch');
  }
  return branch;
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

function registrationSignerPlanBranchScopeKey(branch: RegistrationSignerPlanBranch): string {
  return branch.branchKey;
}

function registrationSignerSetScopeKey(plan: RegistrationSignerPlan): string {
  return plan.branches.map(registrationSignerPlanBranchScopeKey).join(',');
}

function registrationTimingSignerSetHasBranch(
  signerSet: RegistrationTimingSignerSet,
  branch: RegistrationTimingSignerBranch,
): boolean {
  return signerSet.branches.includes(branch);
}

function registrationAuthorityScopeKey(authMethod: RegistrationAuthMethodInput): string {
  switch (authMethod.kind) {
    case 'passkey':
      return JSON.stringify({ kind: 'passkey', rpId: authMethod.rpId });
    case 'email_otp':
      return JSON.stringify({
        kind: 'email_otp_pre_auth',
        proofKind: authMethod.proofKind,
        email: authMethod.email.toLowerCase(),
      });
    default: {
      const exhaustive: never = authMethod;
      return exhaustive;
    }
  }
}

type ManagedRegistrationFlowGrantAuthority = Parameters<
  typeof createManagedRegistrationFlowGrant
>[0]['authority'];

function registrationBootstrapGrantAuthority(input: {
  authMethod: RegistrationAuthMethodInput;
  operation: string;
}): ManagedRegistrationFlowGrantAuthority {
  if (input.authMethod.kind !== 'passkey') return { kind: 'wallet_auth' };
  const rpId = String(input.authMethod.rpId || '').trim();
  if (!rpId) {
    throw new Error(`${input.operation} requires configured rpId for managed registration grant`);
  }
  return { kind: 'passkey_rp', rpId };
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
    case 'registrationHssAdvanceStateCeremonyLoadMs':
    case 'registrationHssAdvanceStateDigestMs':
    case 'registrationHssAdvanceStateWasmMs':
    case 'registrationHssAdvanceStateDecodeStateMs':
    case 'registrationHssAdvanceStateSerializedSessionMaterializeMs':
    case 'registrationHssAdvanceStateSerializedSessionDecodeMs':
    case 'registrationHssAdvanceStateMaterializeRuntimeMs':
    case 'registrationHssAdvanceStateMaterializeEvaluatorSessionMs':
    case 'registrationHssAdvanceStateMaterializeGarblerSessionMs':
    case 'registrationHssAdvanceStateAddStageResponseMs':
    case 'registrationHssAdvanceStateMessageScheduleRoundsMs':
    case 'registrationHssAdvanceStateRoundCoreRoundsMs':
    case 'registrationHssAdvanceStateOutputProjectionMs':
    case 'registrationHssAdvanceStateEncodeAdvancedStateMs':
    case 'registrationHssAdvanceStatePersistenceMs':
    case 'registerHssAdvanceStateTotalMs':
    case 'registrationFinalizeReplayLoadMs':
    case 'registrationCeremonyLoadMs':
    case 'registrationHssFinalizeMs':
    case 'registrationHssFinalizeDecodeArtifactMs':
    case 'registrationHssFinalizeSerializedSessionMaterializeMs':
    case 'registrationHssFinalizeSerializedSessionDecodeMs':
    case 'registrationHssFinalizeMaterializeRuntimeMs':
    case 'registrationHssFinalizeMaterializeEvaluatorSessionMs':
    case 'registrationHssFinalizeMaterializeGarblerSessionMs':
    case 'registrationHssFinalizeAdvanceAddStageResponseMs':
    case 'registrationHssFinalizeAdvanceMessageScheduleRoundsMs':
    case 'registrationHssFinalizeAdvanceRoundCoreRoundsMs':
    case 'registrationHssFinalizeAdvanceOutputProjectionMs':
    case 'registrationHssFinalizeReportMs':
    case 'registrationHssFinalizePacketAssemblyMs':
    case 'registrationHssFinalizeEncodeReportMs':
    case 'registrationHssFinalizeOpenServerOutputMs':
    case 'registrationHssFinalizeOpenSeedOutputMs':
    case 'registrationHssFinalizeDeriveSeedKeypairMs':
    case 'registrationHssFinalizeDeriveRelayerVerifyingShareMs':
    case 'registrationHssFinalizeKeyStorePutMs':
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
  const route =
    value.route === 'wallets_register_prepare' ||
    value.route === 'wallets_register_start' ||
    value.route === 'wallets_register_hss_respond' ||
    value.route === 'wallets_register_hss_advance_state' ||
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
  const ed25519HssFinalizeSource = parseEd25519HssFinalizeSource(
    isObject(value.ed25519HssFinalize) ? value.ed25519HssFinalize.source : undefined,
  );
  const ed25519HssAdvanceSource = parseEd25519HssAdvanceSource(
    isObject(value.ed25519HssAdvance) ? value.ed25519HssAdvance.source : undefined,
  );
  const diagnostics: WalletRegistrationRouteDiagnostics = {
    kind: 'wallet_registration_route_diagnostics_v1',
    route,
    entries,
  };
  if (ed25519HssAdvanceSource) {
    diagnostics.ed25519HssAdvance = {
      source: ed25519HssAdvanceSource,
    };
  }
  if (ed25519HssFinalizeSource) {
    diagnostics.ed25519HssFinalize = {
      source: ed25519HssFinalizeSource,
    };
  }
  return diagnostics;
}

function copyWalletRegistrationRouteDiagnostics(
  diagnostics: WalletRegistrationRouteDiagnostics,
): WalletRegistrationRouteDiagnostics {
  const copy: WalletRegistrationRouteDiagnostics = {
    kind: diagnostics.kind,
    route: diagnostics.route,
    entries: diagnostics.entries.map((entry) => ({
      name: entry.name,
      durationMs: entry.durationMs,
    })),
  };
  if (diagnostics.ed25519HssAdvance) {
    copy.ed25519HssAdvance = {
      source: diagnostics.ed25519HssAdvance.source,
    };
  }
  if (diagnostics.ed25519HssFinalize) {
    copy.ed25519HssFinalize = {
      source: diagnostics.ed25519HssFinalize.source,
    };
  }
  return copy;
}

function parseEd25519HssAdvanceSource(
  value: unknown,
): NonNullable<WalletRegistrationRouteDiagnostics['ed25519HssAdvance']>['source'] | null {
  switch (value) {
    case 'durable_workerd_wasm':
      return value;
    default:
      return null;
  }
}

function parseEd25519HssFinalizeSource(
  value: unknown,
): NonNullable<WalletRegistrationRouteDiagnostics['ed25519HssFinalize']>['source'] | null {
  switch (value) {
    case 'durable_advanced_eval':
    case 'durable_finalized_report':
    case 'serialized_replay':
      return value;
    default:
      return null;
  }
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
    ed25519AddStageRequestMs: 0,
    walletRegisterHssAdvanceStateMs: 0,
    ed25519EvaluationArtifactMs: 0,
    emailOtpRecoveryCodeBackupMs: 0,
    walletRegisterFinalizeMs: 0,
    ed25519CompletionParseMs: 0,
    localWalletRegistrationPersistenceMs: 0,
    thresholdEd25519SessionPersistenceMs: 0,
    thresholdEd25519KeyMaterialPersistenceMs: 0,
    thresholdEd25519SessionNormalizeMs: 0,
    thresholdEd25519WarmMaterialValidationMs: 0,
    thresholdEd25519WarmCapabilityPersistenceMs: 0,
    thresholdEd25519WorkerMaterialPersistenceMs: 0,
    thresholdEd25519SigningSessionHydrationMs: 0,
    thresholdEd25519SealedSessionPersistenceMs: 0,
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
    ed25519AddStageRequestMs: buckets.ed25519AddStageRequestMs,
    walletRegisterHssAdvanceStateMs: buckets.walletRegisterHssAdvanceStateMs,
    ed25519EvaluationArtifactMs: buckets.ed25519EvaluationArtifactMs,
    emailOtpRecoveryCodeBackupMs: buckets.emailOtpRecoveryCodeBackupMs,
    walletRegisterFinalizeMs: buckets.walletRegisterFinalizeMs,
    ed25519CompletionParseMs: buckets.ed25519CompletionParseMs,
    localWalletRegistrationPersistenceMs: buckets.localWalletRegistrationPersistenceMs,
    thresholdEd25519SessionPersistenceMs: buckets.thresholdEd25519SessionPersistenceMs,
    thresholdEd25519KeyMaterialPersistenceMs: buckets.thresholdEd25519KeyMaterialPersistenceMs,
    thresholdEd25519SessionNormalizeMs: buckets.thresholdEd25519SessionNormalizeMs,
    thresholdEd25519WarmMaterialValidationMs: buckets.thresholdEd25519WarmMaterialValidationMs,
    thresholdEd25519WarmCapabilityPersistenceMs:
      buckets.thresholdEd25519WarmCapabilityPersistenceMs,
    thresholdEd25519WorkerMaterialPersistenceMs:
      buckets.thresholdEd25519WorkerMaterialPersistenceMs,
    thresholdEd25519SigningSessionHydrationMs: buckets.thresholdEd25519SigningSessionHydrationMs,
    thresholdEd25519SealedSessionPersistenceMs: buckets.thresholdEd25519SealedSessionPersistenceMs,
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
  signerSet: RegistrationTimingSignerSet;
  buckets: RegistrationTimingBucketValues;
}): RegistrationEd25519Timing {
  if (registrationTimingSignerSetHasBranch(input.signerSet, 'near_ed25519')) {
    return {
      kind: 'ed25519_enabled',
      ed25519ClientMaterialMs: input.buckets.ed25519ClientMaterialMs,
      ed25519ClientRequestMs: input.buckets.ed25519ClientRequestMs,
      ed25519AddStageRequestMs: input.buckets.ed25519AddStageRequestMs,
      walletRegisterHssAdvanceStateMs: input.buckets.walletRegisterHssAdvanceStateMs,
      ed25519EvaluationArtifactMs: input.buckets.ed25519EvaluationArtifactMs,
      ed25519CompletionParseMs: input.buckets.ed25519CompletionParseMs,
      thresholdEd25519SessionPersistenceMs: input.buckets.thresholdEd25519SessionPersistenceMs,
      thresholdEd25519KeyMaterialPersistenceMs:
        input.buckets.thresholdEd25519KeyMaterialPersistenceMs,
      thresholdEd25519SessionNormalizeMs: input.buckets.thresholdEd25519SessionNormalizeMs,
      thresholdEd25519WarmMaterialValidationMs:
        input.buckets.thresholdEd25519WarmMaterialValidationMs,
      thresholdEd25519WarmCapabilityPersistenceMs:
        input.buckets.thresholdEd25519WarmCapabilityPersistenceMs,
      thresholdEd25519WorkerMaterialPersistenceMs:
        input.buckets.thresholdEd25519WorkerMaterialPersistenceMs,
      thresholdEd25519SigningSessionHydrationMs:
        input.buckets.thresholdEd25519SigningSessionHydrationMs,
      thresholdEd25519SealedSessionPersistenceMs:
        input.buckets.thresholdEd25519SealedSessionPersistenceMs,
    };
  }
  return {
    kind: 'ed25519_disabled',
    ed25519ClientMaterialMs: 0,
    ed25519ClientRequestMs: 0,
    ed25519AddStageRequestMs: 0,
    walletRegisterHssAdvanceStateMs: 0,
    ed25519EvaluationArtifactMs: 0,
    ed25519CompletionParseMs: 0,
    thresholdEd25519SessionPersistenceMs: 0,
    thresholdEd25519KeyMaterialPersistenceMs: 0,
    thresholdEd25519SessionNormalizeMs: 0,
    thresholdEd25519WarmMaterialValidationMs: 0,
    thresholdEd25519WarmCapabilityPersistenceMs: 0,
    thresholdEd25519WorkerMaterialPersistenceMs: 0,
    thresholdEd25519SigningSessionHydrationMs: 0,
    thresholdEd25519SealedSessionPersistenceMs: 0,
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
  'inputValidationMs',
  'registrationWarmupWaitMs',
  'routerAbPublicKeysetMs',
  'managedRegistrationGrantMs',
  'registrationIntentMs',
  'registrationIntentDigestMs',
  'authProofMs',
  'emailOtpEnrollmentMaterialMs',
  'ed25519ClientMaterialMs',
  'walletRegisterPrepareMs',
  'walletRegisterPrepareWaitMs',
  'walletRegisterStartMs',
  'ed25519ClientRequestMs',
  'ecdsaClientBootstrapMs',
  'walletRegisterHssRespondMs',
  'ed25519AddStageRequestMs',
  'walletRegisterHssAdvanceStateMs',
  'ed25519EvaluationArtifactMs',
  'emailOtpRecoveryCodeBackupMs',
  'walletRegisterFinalizeMs',
  'ed25519CompletionParseMs',
  'localWalletRegistrationPersistenceMs',
  'thresholdEd25519KeyMaterialPersistenceMs',
  'thresholdEd25519SessionNormalizeMs',
  'thresholdEd25519WarmMaterialValidationMs',
  'thresholdEd25519WarmCapabilityPersistenceMs',
  'thresholdEd25519WorkerMaterialPersistenceMs',
  'thresholdEd25519SigningSessionHydrationMs',
  'thresholdEd25519SealedSessionPersistenceMs',
  'ecdsaRegistrationPersistenceMs',
  'walletStateActivationMs',
  'immediateSigningLaneAssertionMs',
];

function buildRegistrationCriticalPathSummary(input: {
  totalElapsedMs: number;
  buckets: RegistrationTimingBucketValues;
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
  return {
    kind: 'registration_critical_path_summary_v1',
    totalElapsedMs: input.totalElapsedMs,
    measuredWorkMs,
    overlappedOrBackgroundMs: Math.max(0, measuredWorkMs - input.totalElapsedMs),
    topBuckets,
  };
}

function buildRegistrationTimingBuckets(input: {
  authMethod: RegistrationTimingAuthMethod;
  signerSet: RegistrationTimingSignerSet;
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
    ed25519AddStageRequestMs: buckets.ed25519AddStageRequestMs,
    walletRegisterHssAdvanceStateMs: buckets.walletRegisterHssAdvanceStateMs,
    ed25519EvaluationArtifactMs: buckets.ed25519EvaluationArtifactMs,
    emailOtpRecoveryCodeBackupMs: buckets.emailOtpRecoveryCodeBackupMs,
    walletRegisterFinalizeMs: buckets.walletRegisterFinalizeMs,
    ed25519CompletionParseMs: buckets.ed25519CompletionParseMs,
    localWalletRegistrationPersistenceMs: buckets.localWalletRegistrationPersistenceMs,
    thresholdEd25519SessionPersistenceMs: buckets.thresholdEd25519SessionPersistenceMs,
    thresholdEd25519KeyMaterialPersistenceMs: buckets.thresholdEd25519KeyMaterialPersistenceMs,
    thresholdEd25519SessionNormalizeMs: buckets.thresholdEd25519SessionNormalizeMs,
    thresholdEd25519WarmMaterialValidationMs: buckets.thresholdEd25519WarmMaterialValidationMs,
    thresholdEd25519WarmCapabilityPersistenceMs:
      buckets.thresholdEd25519WarmCapabilityPersistenceMs,
    thresholdEd25519WorkerMaterialPersistenceMs:
      buckets.thresholdEd25519WorkerMaterialPersistenceMs,
    thresholdEd25519SigningSessionHydrationMs: buckets.thresholdEd25519SigningSessionHydrationMs,
    thresholdEd25519SealedSessionPersistenceMs: buckets.thresholdEd25519SealedSessionPersistenceMs,
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
    walletStateActivationMs: buckets.walletStateActivationMs,
    immediateSigningLaneAssertionMs: buckets.immediateSigningLaneAssertionMs,
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

  record<K extends RegistrationTimingBucketName>(bucket: K, durationMs: number): void {
    const rounded = Math.max(0, Math.round(durationMs));
    this.buckets[bucket] += rounded;
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
      this.relayDiagnostics.push(copyWalletRegistrationRouteDiagnostics(diagnostics));
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
    return this.relayDiagnostics.map(copyWalletRegistrationRouteDiagnostics);
  }

  totalMs(): number {
    return roundDurationMs(this.startedAt);
  }
}

class RegistrationEcdsaSessionFinalizeDiagnostics implements FinalizeWalletRegistrationEcdsaSessionsDiagnostics {
  constructor(private readonly registrationTiming: RegistrationTimingRecorder) {}

  recordDuration(
    bucket: FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket,
    durationMs: number,
  ): void {
    switch (bucket) {
      case 'client_finalize':
        this.registrationTiming.record('ecdsaRegistrationClientFinalizeMs', durationMs);
        return;
      case 'client_material_store':
        this.registrationTiming.record('ecdsaRegistrationClientMaterialStoreMs', durationMs);
        return;
      case 'server_bootstrap':
        this.registrationTiming.record('ecdsaRegistrationServerBootstrapMs', durationMs);
        return;
      case 'passkey_bootstrap_store':
        this.registrationTiming.record('ecdsaRegistrationPasskeyBootstrapStoreMs', durationMs);
        return;
      case 'passkey_role_local_ready_record':
        this.registrationTiming.record('ecdsaRegistrationRoleLocalRecordPersistenceMs', durationMs);
        return;
      case 'passkey_warm_session_hydration':
        this.registrationTiming.record('ecdsaRegistrationWarmSessionHydrationMs', durationMs);
        return;
      case 'passkey_warm_session_worker_ready':
        this.registrationTiming.record('ecdsaRegistrationWarmSessionWorkerReadyMs', durationMs);
        return;
      case 'passkey_warm_session_worker_put':
        this.registrationTiming.record('ecdsaRegistrationWarmSessionWorkerPutMs', durationMs);
        return;
      case 'passkey_warm_session_sealed_record_persist':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealedRecordPersistMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_resolve_transport':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealResolveTransportMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_existing_read':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealExistingRecordReadMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_policy_read':
        this.registrationTiming.record('ecdsaRegistrationWarmSessionSealPolicyReadMs', durationMs);
        return;
      case 'passkey_warm_session_sealed_record_apply_server_seal':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealApplyServerSealMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_apply_runtime_setup':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_apply_client_seal':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealApplyClientSealMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_apply_server_route':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealApplyServerRouteMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_apply_client_unseal':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealApplyClientUnsealMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_apply_policy_update':
        this.registrationTiming.record(
          'ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs',
          durationMs,
        );
        return;
      case 'passkey_warm_session_sealed_record_register':
        this.registrationTiming.record('ecdsaRegistrationWarmSessionSealRegisterMs', durationMs);
        return;
      case 'passkey_warm_session_sealed_record_verify_read':
        this.registrationTiming.record('ecdsaRegistrationWarmSessionSealVerifyReadMs', durationMs);
        return;
      case 'email_otp_session_commit':
        this.registrationTiming.record('ecdsaRegistrationEmailOtpSessionCommitMs', durationMs);
        return;
      default:
        assertNever(bucket);
    }
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
}): Promise<RegistrationWarmupOutcome> {
  return input.recorder
    .measure('registrationWarmupMs', () =>
      input.context.signingEngine.warmCriticalResources({ kind: 'none' }),
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

function startRouterAbPublicKeysetPrefetchForRegistration(input: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  relayerUrl: string;
  evmFamilyEcdsa: EvmFamilyEcdsaRegistrationBranch | null;
}): Promise<RouterAbPublicKeysetPrefetchOutcome> {
  if (!input.evmFamilyEcdsa) {
    return Promise.resolve({ kind: 'disabled' });
  }
  return startRouterAbPublicKeysetPrefetch({
    recorder: input.recorder,
    context: input.context,
    relayerUrl: input.relayerUrl,
  });
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

async function verifyWalletRegistrationIntentResponse(input: {
  recorder: RegistrationTimingRecorder;
  intentResponse: WalletRegistrationIntentResponse;
}): Promise<WalletRegistrationIntentResponse> {
  const localDigestB64u = await input.recorder.measure('registrationIntentDigestMs', () =>
    computeRegistrationIntentDigest(input.intentResponse.intent),
  );
  if (localDigestB64u !== input.intentResponse.registrationIntentDigestB64u) {
    throw new Error('Registration intent digest mismatch');
  }
  return input.intentResponse;
}

function walletScopeKey(wallet: RegisterWalletInput): string {
  switch (wallet.kind) {
    case 'provided':
      return `provided:${String(wallet.walletId)}`;
    case 'server_allocated':
      return 'server_allocated';
    default:
      return assertNever(wallet);
  }
}

type RegistrationGrantIdentity =
  | {
      kind: 'near_account';
      nearAccountId: string;
      walletId?: never;
    }
  | {
      kind: 'wallet';
      walletId: string;
      nearAccountId?: never;
    }
  | {
      kind: 'none';
      nearAccountId?: never;
      walletId?: never;
    };

type RegistrationAccountPreflight =
  | {
      kind: 'implicit_account';
      eventAccountId: string;
      nearAccountId?: never;
    }
  | {
      kind: 'sponsored_named_account';
      nearAccountId: AccountId;
      eventAccountId?: never;
    };

function sponsoredNamedRegistrationAccountId(
  provisioning: RegistrationNearAccountProvisioning,
): string | null {
  switch (provisioning.kind) {
    case 'implicit_account':
      return null;
    case 'sponsored_named_account':
      return String(provisioning.requestedAccountId);
    default: {
      const exhaustive: never = provisioning;
      return exhaustive;
    }
  }
}

function registrationGrantIdentityFromEd25519Selection(args: {
  wallet: RegisterWalletInput;
  signerSelection: NearEd25519RegistrationBranch;
}): RegistrationGrantIdentity {
  const sponsoredNamedAccountId = sponsoredNamedRegistrationAccountId(
    args.signerSelection.accountProvisioning,
  );
  if (sponsoredNamedAccountId) {
    return { kind: 'near_account', nearAccountId: sponsoredNamedAccountId };
  }
  switch (args.wallet.kind) {
    case 'provided':
      return { kind: 'wallet', walletId: String(args.wallet.walletId) };
    case 'server_allocated':
      return { kind: 'none' };
    default:
      return assertNever(args.wallet);
  }
}

function initialRegistrationEventAccountId(args: {
  wallet: RegisterWalletInput;
  signerSelection: NearEd25519RegistrationBranch;
}): string {
  const grantIdentity = registrationGrantIdentityFromEd25519Selection(args);
  switch (grantIdentity.kind) {
    case 'near_account':
      return grantIdentity.nearAccountId;
    case 'wallet':
      return grantIdentity.walletId;
    case 'none':
      return 'wallet-registration';
    default:
      return assertNever(grantIdentity);
  }
}

function registrationPreflightFromEd25519Selection(args: {
  wallet: RegisterWalletInput;
  signerSelection: NearEd25519RegistrationBranch;
}): RegistrationAccountPreflight {
  const sponsoredNamedAccountId = sponsoredNamedRegistrationAccountId(
    args.signerSelection.accountProvisioning,
  );
  if (sponsoredNamedAccountId) {
    return {
      kind: 'sponsored_named_account',
      nearAccountId: toAccountId(sponsoredNamedAccountId),
    };
  }
  return {
    kind: 'implicit_account',
    eventAccountId: initialRegistrationEventAccountId(args),
  };
}

async function ed25519RegistrationKeyScopeIdFromIntent(intent: {
  walletId: WalletId;
  authorityScope: RegistrationEd25519AuthorityScope;
  runtimePolicyScope?: {
    projectId: string;
    envId: string;
    signingRootVersion?: string;
  };
  signerSelection: Parameters<typeof registrationSignerPlanFromSelection>[0];
}): Promise<NearEd25519SigningKeyId> {
  const signerPlan = registrationSignerPlanFromIntentSelection({
    selection: intent.signerSelection,
  });
  const nearEd25519 = requireNearEd25519RegistrationBranch(signerPlan);
  const runtimePolicyScope = intent.runtimePolicyScope;
  if (!runtimePolicyScope?.signingRootVersion) {
    throw new Error('Ed25519 registration key scope requires signing root scope');
  }
  return await computeRegistrationNearEd25519SigningKeyId({
    walletId: intent.walletId,
    authorityScope: intent.authorityScope,
    signingRootId: deriveSigningRootId(runtimePolicyScope),
    signingRootVersion: runtimePolicyScope.signingRootVersion,
    ed25519: thresholdEd25519RegistrationSpecFromBranch(nearEd25519),
  });
}

function plannedEvmFamilySigningKeySlotIdFromRegistrationIntent(intent: {
  walletId: string;
  runtimePolicyScope?: {
    projectId: string;
    envId: string;
    signingRootVersion?: string;
  };
  chainTarget: ThresholdEcdsaChainTarget;
}): string {
  const runtimePolicyScope = intent.runtimePolicyScope;
  if (!runtimePolicyScope?.signingRootVersion) {
    throw new Error('ECDSA registration signing key slot requires signing root scope');
  }
  return deriveEvmFamilySigningKeySlotId({
    walletId: intent.walletId,
    signingRootId: deriveSigningRootId(runtimePolicyScope),
    signingRootVersion: runtimePolicyScope.signingRootVersion,
    chainTarget: intent.chainTarget,
  });
}

function expectedEcdsaChainTargetsFromBranch(
  branch: RegistrationEvmFamilyEcdsaSignerPlan,
): readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]] {
  const targets = expectedEcdsaChainTargetsFromRegistrationSpec(
    thresholdEcdsaRegistrationSpecFromBranch(branch),
  );
  const firstTarget = targets[0];
  if (!firstTarget) {
    throw new Error('ECDSA registration requires at least one expected chain target');
  }
  return [firstTarget, ...targets.slice(1)];
}

function emailOtpRegistrationEcdsaRootTargetsFromBranch(args: {
  walletId: string;
  runtimePolicyScope: RegistrationIntentV1['runtimePolicyScope'];
  branch: RegistrationEvmFamilyEcdsaSignerPlan;
}): Extract<
  EmailOtpRegistrationEcdsaRootMaterialRequest,
  { kind: 'ecdsa_root_requested' }
>['targets'] {
  const targets: {
    chainTarget: ThresholdEcdsaChainTarget;
    evmFamilySigningKeySlotId: string;
  }[] = [];
  for (const chainTarget of expectedEcdsaChainTargetsFromBranch(args.branch)) {
    targets.push({
      chainTarget,
      evmFamilySigningKeySlotId: plannedEvmFamilySigningKeySlotIdFromRegistrationIntent({
        walletId: args.walletId,
        runtimePolicyScope: args.runtimePolicyScope,
        chainTarget,
      }),
    });
  }
  const first = targets[0];
  if (!first) {
    throw new Error('Email OTP registration ECDSA material requires expected targets');
  }
  return [first, ...targets.slice(1)];
}

function walletRegistrationPrecomputeScopeFromArgs(args: {
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerPlan: RegistrationSignerPlan;
  nearEd25519: NearEd25519RegistrationBranch;
}): WalletRegistrationPrecomputeScope {
  return {
    authMethodKind: args.authMethod.kind,
    walletScopeKey: walletScopeKey(args.wallet),
    authorityScopeKey: registrationAuthorityScopeKey(args.authMethod),
    signerSetScopeKey: registrationSignerSetScopeKey(args.signerPlan),
    accountProvisioningScopeKey: registrationProvisioningScopeKey(
      args.nearEd25519.accountProvisioning,
    ),
  };
}

function assertWalletRegistrationPrecomputeScopeMatches(input: {
  expected: WalletRegistrationPrecomputeScope;
  actual: WalletRegistrationPrecomputeScope;
}): void {
  const mismatches = walletRegistrationPrecomputeScopeMismatches(input);
  if (mismatches.length > 0) {
    throw new Error(formatWalletRegistrationPrecomputeScopeMismatchError(mismatches));
  }
}

function walletRegistrationPrecomputeScopeMismatches(input: {
  expected: WalletRegistrationPrecomputeScope;
  actual: WalletRegistrationPrecomputeScope;
}): readonly WalletRegistrationPrecomputeScopeMismatch[] {
  const fields: readonly WalletRegistrationPrecomputeScopeField[] = [
    'authMethodKind',
    'walletScopeKey',
    'authorityScopeKey',
    'signerSetScopeKey',
    'accountProvisioningScopeKey',
  ];
  const mismatches: WalletRegistrationPrecomputeScopeMismatch[] = [];
  for (const field of fields) {
    if (input.expected[field] !== input.actual[field]) {
      mismatches.push({
        field,
        expected: input.expected[field],
        actual: input.actual[field],
      });
    }
  }
  return mismatches;
}

function formatWalletRegistrationPrecomputeScopeMismatchError(
  mismatches: readonly WalletRegistrationPrecomputeScopeMismatch[],
): string {
  const details = mismatches
    .map(
      (mismatch) =>
        `${mismatch.field} expected=${JSON.stringify(mismatch.expected)} actual=${JSON.stringify(
          mismatch.actual,
        )}`,
    )
    .join('; ');
  return `Started wallet registration precompute scope mismatch: ${details}`;
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
  signerSelection: RegistrationSignerSetSelection;
  signerPlan: RegistrationSignerPlan;
  nearEd25519: NearEd25519RegistrationBranch;
  evmFamilyEcdsa: EvmFamilyEcdsaRegistrationBranch | null;
  recorder: RegistrationTimingRecorder;
}): Promise<WalletRegistrationPrecomputeReady> {
  const relayerUrl = String(input.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) {
    throw new Error('registerWallet requires relayer.url');
  }
  const routerAbPublicKeysetPrefetch = startRouterAbPublicKeysetPrefetchForRegistration({
    recorder: input.recorder,
    context: input.context,
    relayerUrl,
    evmFamilyEcdsa: input.evmFamilyEcdsa,
  });
  const scope = walletRegistrationPrecomputeScopeFromArgs({
    authMethod: input.authMethod,
    wallet: input.wallet,
    signerPlan: input.signerPlan,
    nearEd25519: input.nearEd25519,
  });
  const grantIdentity = registrationGrantIdentityFromEd25519Selection({
    wallet: input.wallet,
    signerSelection: input.nearEd25519,
  });
  const registrationWarmup = startRegistrationWarmup({
    recorder: input.recorder,
    context: input.context,
  });
  const managedGrant = await input.recorder.measure('managedRegistrationGrantMs', () =>
    createManagedRegistrationFlowGrant({
      context: input.context,
      identity: grantIdentity,
      authority: registrationBootstrapGrantAuthority({
        authMethod: input.authMethod,
        operation: 'registerWallet',
      }),
    }),
  );
  const intentResponse = await verifyWalletRegistrationIntentResponse({
    recorder: input.recorder,
    intentResponse: await input.recorder.measure('registrationIntentMs', () =>
      createWalletRegistrationIntent({
        relayerUrl,
        request: {
          wallet: input.wallet,
          authMethod: input.authMethod,
          signerSelection: input.signerSelection,
        },
        headers: {
          Authorization: `Bearer ${managedGrant.token}`,
        },
      }),
    ),
  });
  await requireRouterAbPublicKeysetPrefetch(routerAbPublicKeysetPrefetch);
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
    thresholdRuntimePolicyScope,
  };
}

export function startWalletRegistrationPrecompute(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
}): WalletRegistrationPrecomputeHandle {
  const signerPlan = registrationSignerPlanFromSignerSet(args.signerSelection);
  const nearEd25519 = requireNearEd25519RegistrationBranch(signerPlan);
  const evmFamilyEcdsa = findRegistrationSignerPlanEvmFamilyEcdsaBranch(signerPlan);
  const scope = walletRegistrationPrecomputeScopeFromArgs({
    authMethod: args.authMethod,
    wallet: args.wallet,
    signerPlan,
    nearEd25519,
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
    signerSelection: args.signerSelection,
    signerPlan,
    nearEd25519,
    evmFamilyEcdsa,
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
  signerSet: RegistrationTimingSignerSet;
}): SucceededRegistrationTimingSummary {
  const totalMs = input.recorder.totalMs();
  const buckets = input.recorder.snapshot();
  return {
    kind: 'registration_timing_summary_v1',
    status: 'succeeded',
    authMethod: input.authMethod,
    signerSet: input.signerSet,
    totalMs,
    criticalPath: buildRegistrationCriticalPathSummary({
      totalElapsedMs: totalMs,
      buckets,
    }),
    relayDiagnostics: input.recorder.routeDiagnosticsSnapshot(),
    timings: buildRegistrationTimingBuckets({
      authMethod: input.authMethod,
      signerSet: input.signerSet,
      buckets,
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
    kind: 'registration_timing_summary_v1',
    status: 'failed',
    authMethod: input.authMethod,
    signerSet: input.signerSet,
    totalMs,
    criticalPath: buildRegistrationCriticalPathSummary({
      totalElapsedMs: totalMs,
      buckets,
    }),
    errorCode: input.errorCode,
    relayDiagnostics: input.recorder.routeDiagnosticsSnapshot(),
    timings: buildRegistrationTimingBuckets({
      authMethod: input.authMethod,
      signerSet: input.signerSet,
      buckets,
    }),
  };
}

function emitRegistrationTimingSummary(summary: RegistrationTimingSummary): void {
  console.info(REGISTRATION_TIMING_LABEL, summary);
  console.info(`${REGISTRATION_TIMING_LABEL} ${JSON.stringify(summary)}`);
}

function logRegistrationProgress(stage: string, details?: Record<string, unknown>): void {
  console.info('[Registration] progress', {
    stage,
    ...(details || {}),
  });
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

function startEmailOtpRegistrationEnrollmentMaterial(input: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  authMethod: EmailOtpRegistrationAuthMethod;
  relayerUrl: string;
  walletId: string;
  providerSubject: string;
  ecdsaRootMaterial: EmailOtpRegistrationEcdsaRootMaterialRequest;
  appSessionJwt: string;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  return input.recorder.measure('emailOtpEnrollmentMaterialMs', () =>
    resolveEmailOtpRegistrationEnrollmentMaterial({
      context: input.context,
      authMethod: input.authMethod,
      relayerUrl: input.relayerUrl,
      walletId: input.walletId,
      providerSubject: input.providerSubject,
      ecdsaRootMaterial: input.ecdsaRootMaterial,
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

function requireEmailOtpRegistrationEcdsaClientRootShareHandle(input: {
  enrollmentMaterial: EmailOtpRegistrationEnrollmentMaterial;
  chainTarget: ThresholdEcdsaChainTarget;
}): EmailOtpRegistrationEcdsaBootstrapInput['clientRootShareHandle'] {
  switch (input.enrollmentMaterial.clientRootShareHandle.kind) {
    case 'available':
      return emailOtpRegistrationEcdsaClientRootShareHandleForTarget({
        handles: input.enrollmentMaterial.clientRootShareHandle.handles,
        chainTarget: input.chainTarget,
      });
    case 'not_requested':
      throw new Error('Email OTP registration ECDSA bootstrap requires requested ECDSA material');
    default:
      return assertNever(input.enrollmentMaterial.clientRootShareHandle);
  }
}

function emailOtpRegistrationEcdsaClientRootShareHandleForTarget(input: {
  handles: readonly EmailOtpRegistrationEcdsaBootstrapInput['clientRootShareHandle'][];
  chainTarget: ThresholdEcdsaChainTarget;
}): EmailOtpRegistrationEcdsaBootstrapInput['clientRootShareHandle'] {
  const targetKey = thresholdEcdsaChainTargetKey(input.chainTarget);
  let selected: EmailOtpRegistrationEcdsaBootstrapInput['clientRootShareHandle'] | null = null;
  for (const handle of input.handles) {
    if (thresholdEcdsaChainTargetKey(handle.chainTarget) !== targetKey) continue;
    if (selected) {
      throw new Error(
        `Email OTP registration ECDSA material has duplicate handle for ${targetKey}`,
      );
    }
    selected = handle;
  }
  if (!selected) {
    throw new Error(`Email OTP registration ECDSA material is missing handle for ${targetKey}`);
  }
  return selected;
}

function emailOtpRegistrationEcdsaRootTargetForChain(input: {
  request: Extract<EmailOtpRegistrationEcdsaRootMaterialRequest, { kind: 'ecdsa_root_requested' }>;
  chainTarget: ThresholdEcdsaChainTarget;
}): Extract<
  EmailOtpRegistrationEcdsaRootMaterialRequest,
  { kind: 'ecdsa_root_requested' }
>['targets'][number] {
  const targetKey = thresholdEcdsaChainTargetKey(input.chainTarget);
  let selected:
    | Extract<
        EmailOtpRegistrationEcdsaRootMaterialRequest,
        { kind: 'ecdsa_root_requested' }
      >['targets'][number]
    | null = null;
  for (const target of input.request.targets) {
    if (thresholdEcdsaChainTargetKey(target.chainTarget) !== targetKey) continue;
    if (selected) {
      throw new Error(`Email OTP registration ECDSA material request duplicates ${targetKey}`);
    }
    selected = target;
  }
  if (!selected) {
    throw new Error(`Email OTP registration ECDSA material request is missing ${targetKey}`);
  }
  return selected;
}

function assertEmailOtpEnrollmentMaterialMatchesEcdsaRootRequest(input: {
  material: EmailOtpRegistrationEnrollmentMaterial;
  request: EmailOtpRegistrationEcdsaRootMaterialRequest;
}): void {
  switch (input.request.kind) {
    case 'ecdsa_root_requested':
      if (input.material.clientRootShareHandle.kind !== 'available') {
        throw new Error('Email OTP registration ECDSA material request returned no ECDSA handle');
      }
      for (const target of input.request.targets) {
        const handle = emailOtpRegistrationEcdsaClientRootShareHandleForTarget({
          handles: input.material.clientRootShareHandle.handles,
          chainTarget: target.chainTarget,
        });
        if (handle.evmFamilySigningKeySlotId !== target.evmFamilySigningKeySlotId) {
          throw new Error('Email OTP registration ECDSA material slot mismatch');
        }
      }
      for (const handle of input.material.clientRootShareHandle.handles) {
        emailOtpRegistrationEcdsaRootTargetForChain({
          request: input.request,
          chainTarget: handle.chainTarget,
        });
      }
      return;
    case 'ecdsa_root_not_requested':
      if (input.material.clientRootShareHandle.kind !== 'not_requested') {
        throw new Error('Email OTP Ed25519-only registration received ECDSA material');
      }
      return;
    default:
      return assertNever(input.request);
  }
}

async function prepareEmailOtpRegistrationEcdsaBootstrap(input: {
  context: RegistrationWebContext;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  prepare: EmailOtpRegistrationEcdsaBootstrapInput['prepare'];
  chainTarget: EmailOtpRegistrationEcdsaBootstrapInput['chainTarget'];
}): Promise<Awaited<ReturnType<RegistrationSigningSurface['prepareEmailOtpEcdsaBootstrap']>>> {
  const enrollmentMaterial = await requireEmailOtpRegistrationEnrollmentMaterial({
    material: input.enrollmentMaterial,
    operation: 'ECDSA bootstrap',
  });
  return await input.context.signingEngine.prepareEmailOtpEcdsaBootstrap({
    prepare: input.prepare,
    clientRootShareHandle: requireEmailOtpRegistrationEcdsaClientRootShareHandle({
      enrollmentMaterial,
      chainTarget: input.chainTarget,
    }),
    chainTarget: input.chainTarget,
  });
}

async function prepareEmailOtpThresholdEd25519RegistrationHssClientMaterial(input: {
  context: RegistrationWebContext;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  participantIds: readonly number[];
}): Promise<ThresholdEd25519RegistrationHssClientMaterial> {
  const enrollmentMaterial = await requireEmailOtpRegistrationEnrollmentMaterial({
    material: input.enrollmentMaterial,
    operation: 'Ed25519 material',
  });
  return await prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst({
    context: input.context,
    prfFirstB64u: enrollmentMaterial.thresholdEd25519RecoveryCodeSecret32B64u,
    runtimePolicyScope: input.runtimePolicyScope,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    participantIds: [...input.participantIds],
  });
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
  ecdsaRootMaterial: EmailOtpRegistrationEcdsaRootMaterialRequest;
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
    assertEmailOtpEnrollmentMaterialMatchesEcdsaRootRequest({
      material: prewarmed.material,
      request: input.ecdsaRootMaterial,
    });
    return prewarmed.material;
  }
  const material =
    await input.context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
      relayUrl: input.relayerUrl,
      walletId: toWalletId(input.walletId),
      userId: input.providerSubject,
      appSessionJwt: input.appSessionJwt,
      ...input.ecdsaRootMaterial,
    });
  assertEmailOtpEnrollmentMaterialMatchesEcdsaRootRequest({
    material,
    request: input.ecdsaRootMaterial,
  });
  return material;
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

function requireFinalizedPasskeyCredentialPublicKeyB64u(args: {
  finalized: WalletRegistrationFinalizeResponse;
  credential: WebAuthnRegistrationCredential;
}): string {
  if ('kind' in args.finalized && args.finalized.kind === 'already_finalized_restore_required') {
    throw new Error('Passkey registration did not finalize with credential material');
  }
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

async function buildRegistrationEmailOtpAuthContext(args: {
  configs: SeamsConfigsReadonly;
  walletId: WalletId;
  email: string;
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
    provider: 'google',
    providerUserId,
  });
}

function createRegistrationThresholdWarmSessionPolicyDraft(args: {
  context: ThresholdWarmSessionContext;
  participantIds: readonly number[];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
}): ThresholdWarmSessionPolicyDraft | null {
  const participantIds = [...args.participantIds];
  return createThresholdWarmSessionPolicyDraft(args.context, {
    kind: 'generated_signing_grant',
    participantIds,
    runtimePolicyScope: args.runtimePolicyScope,
  });
}

type FinalizedRegistrationEd25519 = NonNullable<WalletRegistrationFinalizeResponse['ed25519']>;

function buildThresholdEd25519FinalizedRegistrationHssMaterial(args: {
  preparedSession: ThresholdEd25519FinalizedRegistrationHssMaterial['preparedSession'];
  ceremonyHandle: string;
  finalized: FinalizedRegistrationEd25519;
}): ThresholdEd25519FinalizedRegistrationHssMaterial {
  const ceremonyHandle = String(args.ceremonyHandle || '').trim();
  const report = args.finalized.registrationWorkerMaterialReport;
  if (!ceremonyHandle) {
    throw new Error('Ed25519 registration worker material is missing ceremony handle');
  }
  if (
    report.kind !== 'threshold_ed25519_registration_worker_material_report_v1' ||
    !report.contextBindingB64u ||
    !report.clientOutputMessageB64u ||
    report.seedOutputMessageB64u !== undefined
  ) {
    throw new Error('Ed25519 registration worker material report is invalid');
  }
  if (report.contextBindingB64u !== args.preparedSession.contextBindingB64u) {
    throw new Error('Ed25519 registration worker material report context mismatch');
  }
  return {
    preparedSession: args.preparedSession,
    clientOutputMaskRelayerKeyId: `registration:${ceremonyHandle}`,
    workerMaterialReport: report,
  };
}

type RegistrationPersistenceAuth =
  | {
      kind: 'passkey';
      rpId: string;
      credential: WebAuthnRegistrationCredential;
      credentialPublicKeyB64u: string;
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

type RegistrationPersistenceEd25519 =
  | {
      kind: 'near_ed25519';
      nearAccountId: AccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      signerSlot: number;
      rpId: string;
      finalized: FinalizedRegistrationEd25519;
      completedRegistration: CompletedThresholdEd25519Registration;
      registrationSessionPolicy: ThresholdWarmSessionRequestEnvelope['session_policy'];
      hssClientMaterial: ThresholdEd25519RegistrationHssClientMaterial;
      finalizedHssMaterial: ThresholdEd25519FinalizedRegistrationHssMaterial;
      prfFirstB64u: string;
    }
  | {
      kind: 'ed25519_absent';
      nearAccountId?: never;
      nearEd25519SigningKeyId?: never;
      signerSlot?: never;
      rpId?: never;
      finalized?: never;
      completedRegistration?: never;
      registrationSessionPolicy?: never;
      hssClientMaterial?: never;
      finalizedHssMaterial?: never;
      prfFirstB64u?: never;
    };

type RegistrationPersistenceEcdsa =
  | {
      kind: 'evm_family_ecdsa';
      sessions: readonly [
        {
          chainTarget: ThresholdEcdsaChainTarget;
          preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
          bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
        },
        ...{
          chainTarget: ThresholdEcdsaChainTarget;
          preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
          bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
        }[],
      ];
      walletKeys: readonly [
        WalletRegistrationEcdsaWalletKey,
        ...WalletRegistrationEcdsaWalletKey[],
      ];
      expectedChainTargets: readonly ThresholdEcdsaChainTarget[];
    }
  | {
      kind: 'ecdsa_absent';
      sessions?: never;
      walletKeys?: never;
      expectedChainTargets?: never;
    };

type RegistrationPersistenceWalletProfileSubject =
  | {
      kind: 'wallet_and_near_profile_rows';
      walletId: WalletId;
      nearAccountId: AccountId;
    }
  | {
      kind: 'wallet_profile_row';
      walletId: WalletId;
      nearAccountId?: never;
    };

type RegistrationPersistenceAuthMethodSubject =
  | {
      kind: 'passkey_auth_method_row';
      walletId: WalletId;
      credentialIdB64u: string;
    }
  | {
      kind: 'email_otp_auth_method_row';
      walletId: WalletId;
      emailHashHex: string;
      registrationAuthorityId: string;
    };

type RegistrationPersistenceSignerActivationSubject =
  | {
      kind: 'near_ed25519_wallet_signer_activation';
      walletId: WalletId;
      nearAccountId: AccountId;
      signerSlot: number;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    }
  | {
      kind: 'evm_family_ecdsa_signer_activation';
      walletId: WalletId;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
    };

type RegistrationPersistenceKeyMaterialSubject =
  | {
      kind: 'near_ed25519_key_material_row';
      walletId: WalletId;
      nearAccountId: AccountId;
      operationalPublicKey: string;
    }
  | {
      kind: 'evm_family_ecdsa_key_material_row';
      walletId: WalletId;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
      thresholdOwnerAddress: string;
    };

type RegistrationPersistenceRuntimeSessionSubject =
  | {
      kind: 'near_ed25519_runtime_session_row';
      walletId: WalletId;
      thresholdSessionId: string;
      signingGrantId: string;
    }
  | {
      kind: 'evm_family_ecdsa_runtime_session_row';
      walletId: WalletId;
      thresholdSessionId: string;
      signingGrantId: string;
      chainTarget: ThresholdEcdsaChainTarget;
    };

type RegistrationPersistenceSelectedWalletStateSubject =
  | {
      kind: 'near_authenticated_wallet_state';
      walletId: WalletId;
      nearAccountId: AccountId;
    }
  | {
      kind: 'ecdsa_only_wallet_profile_not_activated';
      walletId: WalletId;
      nearAccountId?: never;
    };

type RegistrationPersistenceWriteSubjects = {
  kind: 'registration_persistence_write_subjects_v1';
  walletProfile: RegistrationPersistenceWalletProfileSubject;
  authMethod: RegistrationPersistenceAuthMethodSubject;
  signerActivations: readonly [
    RegistrationPersistenceSignerActivationSubject,
    ...RegistrationPersistenceSignerActivationSubject[],
  ];
  keyMaterialRows: readonly [
    RegistrationPersistenceKeyMaterialSubject,
    ...RegistrationPersistenceKeyMaterialSubject[],
  ];
  runtimeSessionRows: readonly [
    RegistrationPersistenceRuntimeSessionSubject,
    ...RegistrationPersistenceRuntimeSessionSubject[],
  ];
  selectedWalletState: RegistrationPersistenceSelectedWalletStateSubject;
};

type RegistrationPersistencePlan = {
  kind: 'registration_persistence_plan_v1';
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
  ed25519: RegistrationPersistenceEd25519;
  ecdsa: RegistrationPersistenceEcdsa;
  writeSubjects: RegistrationPersistenceWriteSubjects;
};

type RegistrationActiveEd25519State =
  | {
      kind: 'near_ed25519_ready';
      identity: ExactEd25519SigningLaneIdentity;
    }
  | {
      kind: 'ed25519_absent';
      identity?: never;
    };

type RegistrationActiveEcdsaState =
  | {
      kind: 'evm_family_ecdsa_ready';
      identities: readonly [ExactEcdsaSigningLaneIdentity, ...ExactEcdsaSigningLaneIdentity[]];
    }
  | {
      kind: 'ecdsa_absent';
      identities?: never;
    };

type RegistrationActiveRuntimeState = {
  kind: 'registration_active_runtime_state_v1';
  walletId: WalletId;
  authMethod: RegistrationAuthMethodInput['kind'];
  ed25519: RegistrationActiveEd25519State;
  ecdsa: RegistrationActiveEcdsaState;
};

type RegistrationPersistenceCommitResult =
  | {
      kind: 'near_ed25519_committed';
      signerSlot: number;
      activeState: RegistrationActiveRuntimeState;
    }
  | {
      kind: 'ecdsa_only_committed';
      signerSlot?: never;
      activeState: RegistrationActiveRuntimeState;
    };

async function buildRegistrationPersistenceAuth(args: {
  authMethod: RegistrationAuthMethodInput;
  configs: SeamsConfigsReadonly;
  walletId: WalletId;
  finalized: WalletRegistrationFinalizeResponse;
  passkeyAuthority: Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>> | null;
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
      };
    }
    case 'email_otp': {
      const email = String(args.email || '').trim();
      const providerSubject = String(args.providerSubject || '').trim();
      const registrationAuthorityId = String(args.registrationAuthorityId || '').trim();
      if (!email || !providerSubject || !registrationAuthorityId) {
        throw new Error('Email OTP registration persistence requires provider identity');
      }
      return {
        kind: 'email_otp',
        email,
        registrationAuthorityId,
        emailOtpAuthContext: await buildRegistrationEmailOtpAuthContext({
          configs: args.configs,
          walletId: args.walletId,
          email,
          providerSubject,
        }),
      };
    }
    default:
      return assertNever(args.authMethod);
  }
}

function buildRegistrationPersistenceEcdsa(args: {
  sessions: readonly {
    chainTarget: ThresholdEcdsaChainTarget;
    preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
    bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
  }[];
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  expectedChainTargets: readonly ThresholdEcdsaChainTarget[];
}): RegistrationPersistenceEcdsa {
  if (args.walletKeys.length === 0) {
    if (args.sessions.length > 0 || args.expectedChainTargets.length > 0) {
      throw new Error('ECDSA registration persistence has material without wallet keys');
    }
    return { kind: 'ecdsa_absent' };
  }
  if (args.sessions.length === 0) {
    throw new Error('Wallet registration ECDSA session material was not prepared');
  }
  if (args.expectedChainTargets.length === 0) {
    throw new Error('ECDSA registration persistence requires expected chain targets');
  }
  if (args.sessions.length !== args.expectedChainTargets.length) {
    throw new Error('ECDSA registration persistence requires one session per expected target');
  }
  const [firstWalletKey, ...remainingWalletKeys] = args.walletKeys;
  const [firstSession, ...remainingSessions] = args.sessions;
  if (!firstSession) {
    throw new Error('ECDSA registration persistence requires session material');
  }
  return {
    kind: 'evm_family_ecdsa',
    sessions: [firstSession, ...remainingSessions],
    walletKeys: [firstWalletKey, ...remainingWalletKeys],
    expectedChainTargets: args.expectedChainTargets,
  };
}

type PreparedRegistrationEcdsaTarget = {
  chainTarget: ThresholdEcdsaChainTarget;
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
};

type RegistrationEcdsaSession = {
  chainTarget: ThresholdEcdsaChainTarget;
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
  bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
};

function registrationEcdsaResponseBootstrapForTarget(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  bootstraps: NonNullable<WalletRegistrationHssRespondResponse['ecdsa']>['bootstraps'];
}): NonNullable<WalletRegistrationHssRespondResponse['ecdsa']>['bootstraps'][number] {
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  for (const entry of args.bootstraps) {
    if (thresholdEcdsaChainTargetKey(entry.chainTarget) === targetKey) return entry;
  }
  throw new Error(`Wallet registration HSS respond is missing ECDSA bootstrap for ${targetKey}`);
}

function buildRegistrationEcdsaSessions(args: {
  preparedTargets: readonly PreparedRegistrationEcdsaTarget[];
  responseBootstraps: NonNullable<WalletRegistrationHssRespondResponse['ecdsa']>['bootstraps'];
}): readonly RegistrationEcdsaSession[] {
  const sessions: RegistrationEcdsaSession[] = [];
  for (const prepared of args.preparedTargets) {
    const responseBootstrap = registrationEcdsaResponseBootstrapForTarget({
      chainTarget: prepared.chainTarget,
      bootstraps: args.responseBootstraps,
    });
    sessions.push({
      chainTarget: prepared.chainTarget,
      preparedClientBootstrap: prepared.preparedClientBootstrap,
      bootstrap: parseWalletRegistrationEcdsaHssRespond({
        clientBootstrap: prepared.preparedClientBootstrap.clientBootstrap,
        serverBootstrap: responseBootstrap.bootstrap,
      }),
    });
  }
  return sessions;
}

function firstRegistrationEcdsaSession(
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>,
): Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>['sessions'][number] {
  const first = ecdsa.sessions[0];
  if (!first) {
    throw new Error('Registration ECDSA persistence requires at least one session');
  }
  return first;
}

function registrationEcdsaClientBootstrapEntries(
  preparedTargets: readonly PreparedRegistrationEcdsaTarget[],
): NonNullable<Parameters<typeof respondWalletRegistrationHss>[0]['ecdsa']>['clientBootstraps'] {
  const entries: NonNullable<
    Parameters<typeof respondWalletRegistrationHss>[0]['ecdsa']
  >['clientBootstraps'] = [];
  for (const target of preparedTargets) {
    entries.push({
      chainTarget: target.chainTarget,
      clientBootstrap: target.preparedClientBootstrap.clientBootstrap,
    });
  }
  return entries;
}

function registrationEcdsaExpectedKeyHandles(
  sessions: readonly RegistrationEcdsaSession[],
): string[] {
  const keyHandles: string[] = [];
  for (const session of sessions) {
    keyHandles.push(session.bootstrap.keyHandle);
  }
  return keyHandles;
}

function buildRegistrationPersistencePlan(args: {
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
  ed25519: RegistrationPersistenceEd25519;
  ecdsa: RegistrationPersistenceEcdsa;
}): RegistrationPersistencePlan {
  return {
    kind: 'registration_persistence_plan_v1',
    walletId: args.walletId,
    auth: args.auth,
    ed25519: args.ed25519,
    ecdsa: args.ecdsa,
    writeSubjects: buildRegistrationPersistenceWriteSubjects(args),
  };
}

function buildRegistrationPersistenceWriteSubjects(args: {
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
  ed25519: RegistrationPersistenceEd25519;
  ecdsa: RegistrationPersistenceEcdsa;
}): RegistrationPersistenceWriteSubjects {
  const signerActivations = registrationPersistenceSignerActivationSubjects(args);
  const keyMaterialRows = registrationPersistenceKeyMaterialSubjects(args);
  const runtimeSessionRows = registrationPersistenceRuntimeSessionSubjects(args);
  return {
    kind: 'registration_persistence_write_subjects_v1',
    walletProfile: registrationPersistenceWalletProfileSubject(args),
    authMethod: registrationPersistenceAuthMethodSubject(args),
    signerActivations,
    keyMaterialRows,
    runtimeSessionRows,
    selectedWalletState: registrationPersistenceSelectedWalletStateSubject(args),
  };
}

function registrationPersistenceWalletProfileSubject(args: {
  walletId: WalletId;
  ed25519: RegistrationPersistenceEd25519;
}): RegistrationPersistenceWalletProfileSubject {
  if (args.ed25519.kind === 'near_ed25519') {
    return {
      kind: 'wallet_and_near_profile_rows',
      walletId: args.walletId,
      nearAccountId: args.ed25519.nearAccountId,
    };
  }
  return {
    kind: 'wallet_profile_row',
    walletId: args.walletId,
  };
}

function registrationPersistenceAuthMethodSubject(args: {
  walletId: WalletId;
  auth: RegistrationPersistenceAuth;
}): RegistrationPersistenceAuthMethodSubject {
  switch (args.auth.kind) {
    case 'passkey':
      return {
        kind: 'passkey_auth_method_row',
        walletId: args.walletId,
        credentialIdB64u: registrationPasskeyCredentialId(args.auth),
      };
    case 'email_otp':
      return {
        kind: 'email_otp_auth_method_row',
        walletId: args.walletId,
        emailHashHex: emailOtpAuthContextEmailHashHex(args.auth.emailOtpAuthContext),
        registrationAuthorityId: args.auth.registrationAuthorityId,
      };
    default:
      return assertNever(args.auth);
  }
}

function registrationPasskeyCredentialId(
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>,
): string {
  return requireRegistrationActiveStateString(
    String(auth.credential.rawId || auth.credential.id || ''),
    'passkey credential id',
  );
}

function registrationPersistenceSignerActivationSubjects(args: {
  walletId: WalletId;
  ed25519: RegistrationPersistenceEd25519;
  ecdsa: RegistrationPersistenceEcdsa;
}): readonly [
  RegistrationPersistenceSignerActivationSubject,
  ...RegistrationPersistenceSignerActivationSubject[],
] {
  const subjects: RegistrationPersistenceSignerActivationSubject[] = [];
  if (args.ed25519.kind === 'near_ed25519') {
    subjects.push({
      kind: 'near_ed25519_wallet_signer_activation',
      walletId: args.walletId,
      nearAccountId: args.ed25519.nearAccountId,
      signerSlot: args.ed25519.signerSlot,
      nearEd25519SigningKeyId: args.ed25519.nearEd25519SigningKeyId,
    });
  }
  if (args.ecdsa.kind === 'evm_family_ecdsa') {
    for (const walletKey of args.ecdsa.walletKeys) {
      subjects.push({
        kind: 'evm_family_ecdsa_signer_activation',
        walletId: args.walletId,
        chainTarget: walletKey.chainTarget,
        keyHandle: walletKey.keyHandle,
      });
    }
  }
  return requireRegistrationPersistenceSubjectList(subjects, 'signer activation');
}

function registrationPersistenceKeyMaterialSubjects(args: {
  walletId: WalletId;
  ed25519: RegistrationPersistenceEd25519;
  ecdsa: RegistrationPersistenceEcdsa;
}): readonly [
  RegistrationPersistenceKeyMaterialSubject,
  ...RegistrationPersistenceKeyMaterialSubject[],
] {
  const subjects: RegistrationPersistenceKeyMaterialSubject[] = [];
  if (args.ed25519.kind === 'near_ed25519') {
    subjects.push({
      kind: 'near_ed25519_key_material_row',
      walletId: args.walletId,
      nearAccountId: args.ed25519.nearAccountId,
      operationalPublicKey: args.ed25519.completedRegistration.operationalPublicKey,
    });
  }
  if (args.ecdsa.kind === 'evm_family_ecdsa') {
    for (const walletKey of args.ecdsa.walletKeys) {
      subjects.push({
        kind: 'evm_family_ecdsa_key_material_row',
        walletId: args.walletId,
        chainTarget: walletKey.chainTarget,
        keyHandle: walletKey.keyHandle,
        thresholdOwnerAddress: walletKey.thresholdOwnerAddress,
      });
    }
  }
  return requireRegistrationPersistenceSubjectList(subjects, 'key material');
}

function registrationPersistenceRuntimeSessionSubjects(args: {
  walletId: WalletId;
  ed25519: RegistrationPersistenceEd25519;
  ecdsa: RegistrationPersistenceEcdsa;
}): readonly [
  RegistrationPersistenceRuntimeSessionSubject,
  ...RegistrationPersistenceRuntimeSessionSubject[],
] {
  const subjects: RegistrationPersistenceRuntimeSessionSubject[] = [];
  if (args.ed25519.kind === 'near_ed25519') {
    subjects.push({
      kind: 'near_ed25519_runtime_session_row',
      walletId: args.walletId,
      thresholdSessionId: args.ed25519.registrationSessionPolicy.thresholdSessionId,
      signingGrantId: args.ed25519.registrationSessionPolicy.signingGrantId,
    });
  }
  if (args.ecdsa.kind === 'evm_family_ecdsa') {
    for (const session of args.ecdsa.sessions) {
      subjects.push({
        kind: 'evm_family_ecdsa_runtime_session_row',
        walletId: args.walletId,
        thresholdSessionId: session.preparedClientBootstrap.clientBootstrap.thresholdSessionId,
        signingGrantId: session.preparedClientBootstrap.clientBootstrap.signingGrantId,
        chainTarget: session.chainTarget,
      });
    }
  }
  return requireRegistrationPersistenceSubjectList(subjects, 'runtime session');
}

function registrationPersistenceSelectedWalletStateSubject(args: {
  walletId: WalletId;
  ed25519: RegistrationPersistenceEd25519;
}): RegistrationPersistenceSelectedWalletStateSubject {
  if (args.ed25519.kind === 'near_ed25519') {
    return {
      kind: 'near_authenticated_wallet_state',
      walletId: args.walletId,
      nearAccountId: args.ed25519.nearAccountId,
    };
  }
  return {
    kind: 'ecdsa_only_wallet_profile_not_activated',
    walletId: args.walletId,
  };
}

function requireRegistrationPersistenceSubjectList<T>(
  subjects: readonly T[],
  label: string,
): readonly [T, ...T[]] {
  const [first, ...remaining] = subjects;
  if (!first) {
    throw new Error(`Registration persistence plan requires at least one ${label} subject`);
  }
  return [first, ...remaining];
}

async function storeRegistrationEd25519AccountData(args: {
  context: RegistrationWebContext;
  plan: RegistrationPersistencePlan;
  ed25519: Extract<RegistrationPersistenceEd25519, { kind: 'near_ed25519' }>;
}): Promise<{ signerSlot: number }> {
  const plan = args.plan;
  const ed25519 = args.ed25519;
  switch (plan.auth.kind) {
    case 'passkey': {
      return await args.context.signingEngine.storeWalletEd25519RegistrationData({
        walletId: plan.walletId,
        nearAccountId: ed25519.nearAccountId,
        nearEd25519SigningKeyId: ed25519.finalized.nearEd25519SigningKeyId,
        credential: plan.auth.credential,
        credentialPublicKeyB64u: plan.auth.credentialPublicKeyB64u,
        operationalPublicKey: ed25519.completedRegistration.operationalPublicKey,
        signerSlot: ed25519.signerSlot,
        relayerKeyId: ed25519.finalized.relayerKeyId,
        keyVersion: ed25519.finalized.keyVersion,
        participantIds: ed25519.finalized.participantIds,
        clientParticipantId: ed25519.finalized.clientParticipantId,
        relayerParticipantId: ed25519.finalized.relayerParticipantId,
      });
    }
    case 'email_otp': {
      return await args.context.signingEngine.storeWalletEmailOtpEd25519RegistrationData({
        walletId: plan.walletId,
        nearAccountId: ed25519.nearAccountId,
        nearEd25519SigningKeyId: ed25519.finalized.nearEd25519SigningKeyId,
        email: plan.auth.email,
        registrationAuthorityId: plan.auth.registrationAuthorityId,
        operationalPublicKey: ed25519.completedRegistration.operationalPublicKey,
        signerSlot: ed25519.signerSlot,
        relayerKeyId: ed25519.finalized.relayerKeyId,
        keyVersion: ed25519.finalized.keyVersion,
        participantIds: ed25519.finalized.participantIds,
        clientParticipantId: ed25519.finalized.clientParticipantId,
        relayerParticipantId: ed25519.finalized.relayerParticipantId,
      });
    }
    default:
      return assertNever(plan.auth);
  }
}

async function persistRegistrationEd25519Session(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  plan: RegistrationPersistencePlan;
  ed25519: Extract<RegistrationPersistenceEd25519, { kind: 'near_ed25519' }>;
  signerSlot: number;
  registrationTiming: RegistrationTimingRecorder;
}): Promise<void> {
  const plan = args.plan;
  const ed25519 = args.ed25519;
  const base = {
    signingEngine: args.context.signingEngine,
    walletId: plan.walletId,
    nearAccountId: ed25519.nearAccountId,
    nearEd25519SigningKeyId: ed25519.nearEd25519SigningKeyId,
    signerSlot: args.signerSlot,
    rpId: ed25519.rpId,
    relayerUrl: args.relayerUrl,
    prfFirstB64u: ed25519.prfFirstB64u,
    registrationHssClientMaterial: ed25519.hssClientMaterial,
    finalizedRegistrationHssMaterial: ed25519.finalizedHssMaterial,
    registrationSessionPolicy: ed25519.registrationSessionPolicy,
    completedRegistration: ed25519.completedRegistration,
    registrationTiming: args.registrationTiming,
  };
  switch (plan.auth.kind) {
    case 'passkey': {
      await persistRegisteredThresholdEd25519Session({
        ...base,
        auth: {
          kind: 'passkey',
          credential: plan.auth.credential,
        },
      });
      return;
    }
    case 'email_otp': {
      await persistRegisteredThresholdEd25519Session({
        ...base,
        auth: {
          kind: 'email_otp',
          emailOtpAuthContext: plan.auth.emailOtpAuthContext,
        },
        workerCtx: args.context.signingEngine.getSignerWorkerContext(),
      });
      return;
    }
    default:
      return assertNever(plan.auth);
  }
}

async function persistRegistrationEcdsaSessionsAndSigners(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>;
}): Promise<void> {
  const plan = args.plan;
  args.registrationTiming.record('ecdsaRegistrationTargetCount', args.ecdsa.walletKeys.length);
  await finalizeRegistrationEcdsaSessions({
    context: args.context,
    relayerUrl: args.relayerUrl,
    registrationTiming: args.registrationTiming,
    plan,
    ecdsa: args.ecdsa,
  });
  await persistRegistrationEcdsaLocalRecords({
    context: args.context,
    registrationTiming: args.registrationTiming,
    plan,
    ecdsa: args.ecdsa,
  });
}

async function finalizeRegistrationEcdsaSessions(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>;
}): Promise<void> {
  const startedAt = performance.now();
  try {
    await args.context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
      walletId: toWalletId(args.plan.walletId),
      relayerUrl: args.relayerUrl,
      sessions: [...args.ecdsa.sessions],
      walletKeys: [...args.ecdsa.walletKeys],
      diagnostics: new RegistrationEcdsaSessionFinalizeDiagnostics(args.registrationTiming),
      auth:
        args.plan.auth.kind === 'email_otp'
          ? {
              kind: 'email_otp',
              emailOtpAuthContext: args.plan.auth.emailOtpAuthContext,
            }
          : {
              kind: 'passkey',
              credentialIdB64u: passkeyEcdsaCredentialIdFromPrepared(
                firstRegistrationEcdsaSession(args.ecdsa).preparedClientBootstrap,
              ),
              rpId: args.plan.auth.rpId,
            },
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
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>;
}): Promise<void> {
  const startedAt = performance.now();
  try {
    await persistRegistrationEcdsaLocalRecordsWithoutTiming(args);
  } finally {
    args.registrationTiming.record(
      'ecdsaRegistrationLocalRecordPersistenceMs',
      roundDurationMs(startedAt),
    );
  }
}

async function persistRegistrationEcdsaLocalRecordsWithoutTiming(args: {
  context: RegistrationWebContext;
  plan: RegistrationPersistencePlan;
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>;
}): Promise<void> {
  const plan = args.plan;
  if (plan.ed25519.kind === 'near_ed25519') {
    if (plan.auth.kind === 'passkey') {
      await args.context.signingEngine.storeWalletEcdsaSignerRecords({
        walletId: plan.walletId,
        walletKeys: args.ecdsa.walletKeys,
      });
      return;
    }
    await args.context.signingEngine.storeWalletEmailOtpEcdsaSignerRecords({
      walletId: plan.walletId,
      walletKeys: args.ecdsa.walletKeys,
    });
    return;
  }
  if (plan.auth.kind === 'passkey') {
    await args.context.signingEngine.finalizeWalletEcdsaRegistration({
      walletId: plan.walletId,
      credential: plan.auth.credential,
      credentialPublicKeyB64u: plan.auth.credentialPublicKeyB64u,
      walletKeys: args.ecdsa.walletKeys,
    });
    return;
  }
  await args.context.signingEngine.storeWalletEmailOtpEcdsaRegistrationData({
    walletId: plan.walletId,
    email: plan.auth.email,
    registrationAuthorityId: plan.auth.registrationAuthorityId,
    walletKeys: args.ecdsa.walletKeys,
  });
}

async function activateRegistrationWalletState(args: {
  context: RegistrationWebContext;
  plan: RegistrationPersistencePlan;
  ed25519: Extract<RegistrationPersistenceEd25519, { kind: 'near_ed25519' }>;
}): Promise<void> {
  try {
    await args.context.signingEngine.activateAuthenticatedWalletState({
      walletId: args.plan.walletId,
      nearAccountId: args.ed25519.nearAccountId,
      nearClient: args.context.nearClient,
    });
  } catch (initErr) {
    console.warn('Failed to initialize current user after wallet registration:', initErr);
  }
}

function buildRegistrationActiveRuntimeState(args: {
  plan: RegistrationPersistencePlan;
  ed25519SignerSlot: number | null;
}): RegistrationActiveRuntimeState {
  const ed25519 =
    args.plan.ed25519.kind === 'near_ed25519'
      ? buildRegistrationActiveEd25519State({
          plan: args.plan,
          ed25519: args.plan.ed25519,
          signerSlot: args.ed25519SignerSlot,
        })
      : { kind: 'ed25519_absent' as const };
  const ecdsa =
    args.plan.ecdsa.kind === 'evm_family_ecdsa'
      ? {
          kind: 'evm_family_ecdsa_ready' as const,
          identities: buildRegistrationActiveEcdsaIdentities({
            plan: args.plan,
            ecdsa: args.plan.ecdsa,
          }),
        }
      : { kind: 'ecdsa_absent' as const };
  return {
    kind: 'registration_active_runtime_state_v1',
    walletId: args.plan.walletId,
    authMethod: args.plan.auth.kind,
    ed25519,
    ecdsa,
  };
}

function registrationActiveSigningLaneAuthBinding(
  auth: RegistrationPersistenceAuth,
): SigningLaneAuthBinding {
  switch (auth.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: toRpId(auth.rpId),
        credentialIdB64u: requireRegistrationActiveStateString(
          String(auth.credential.rawId || auth.credential.id || ''),
          'passkey credential id',
        ),
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: requireRegistrationActiveStateString(
          emailOtpAuthContextProviderUserId(auth.emailOtpAuthContext),
          'Email OTP provider subject id',
        ),
      };
    default:
      return assertNever(auth);
  }
}

function requireRegistrationActiveStateString(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`Registration active state requires ${label}`);
  }
  return trimmed;
}

function buildRegistrationActiveEd25519State(args: {
  plan: RegistrationPersistencePlan;
  ed25519: Extract<RegistrationPersistenceEd25519, { kind: 'near_ed25519' }>;
  signerSlot: number | null;
}): Extract<RegistrationActiveEd25519State, { kind: 'near_ed25519_ready' }> {
  if (args.signerSlot === null) {
    throw new Error('Registration active state requires committed Ed25519 signer slot');
  }
  return {
    kind: 'near_ed25519_ready',
    identity: exactEd25519SigningLaneIdentity({
      signer: nearEd25519SignerBindingFromBoundaryFields({
        walletId: args.plan.walletId,
        nearAccountId: args.ed25519.nearAccountId,
        nearEd25519SigningKeyId: args.ed25519.nearEd25519SigningKeyId,
        signerSlot: args.signerSlot,
      }),
      auth: registrationActiveSigningLaneAuthBinding(args.plan.auth),
      signingGrantId: requireRegistrationActiveStateString(
        args.ed25519.registrationSessionPolicy.signingGrantId,
        'Ed25519 signing grant id',
      ),
      thresholdSessionId: requireRegistrationActiveStateString(
        args.ed25519.registrationSessionPolicy.thresholdSessionId,
        'Ed25519 threshold session id',
      ),
    }),
  };
}

function buildRegistrationActiveEcdsaIdentities(args: {
  plan: RegistrationPersistencePlan;
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>;
}): readonly [ExactEcdsaSigningLaneIdentity, ...ExactEcdsaSigningLaneIdentity[]] {
  const identities: ExactEcdsaSigningLaneIdentity[] = [];
  const auth = registrationActiveSigningLaneAuthBinding(args.plan.auth);
  for (const chainTarget of args.ecdsa.expectedChainTargets) {
    const walletKey = registrationEcdsaWalletKeyForTarget({ ecdsa: args.ecdsa, chainTarget });
    const session = registrationEcdsaSessionForTarget({ ecdsa: args.ecdsa, chainTarget });
    identities.push(
      exactEcdsaSigningLaneIdentity({
        signer: buildEvmFamilyEcdsaSignerBinding({
          walletId: toWalletId(args.plan.walletId),
          chainTarget,
          keyHandle: toEvmFamilyEcdsaKeyHandle(walletKey.keyHandle),
          key: buildBaseEvmFamilyEcdsaKeyIdentity({
            walletId: toWalletId(walletKey.walletId),
            evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
            ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
            signingRootId: walletKey.signingRootId,
            signingRootVersion: walletKey.signingRootVersion,
            participantIds: walletKey.participantIds,
            thresholdOwnerAddress: walletKey.thresholdOwnerAddress,
          }),
        }),
        auth,
        signingGrantId: requireRegistrationActiveStateString(
          session.preparedClientBootstrap.clientBootstrap.signingGrantId,
          'ECDSA signing grant id',
        ),
        thresholdSessionId: requireRegistrationActiveStateString(
          session.preparedClientBootstrap.clientBootstrap.thresholdSessionId,
          'ECDSA threshold session id',
        ),
      }),
    );
  }
  const [firstIdentity, ...remainingIdentities] = identities;
  if (!firstIdentity) {
    throw new Error('Registration active state requires at least one exact ECDSA lane identity');
  }
  return [firstIdentity, ...remainingIdentities];
}

function registrationEcdsaWalletKeyForTarget(args: {
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>;
  chainTarget: ThresholdEcdsaChainTarget;
}): WalletRegistrationEcdsaWalletKey {
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  for (const walletKey of args.ecdsa.walletKeys) {
    if (thresholdEcdsaChainTargetKey(walletKey.chainTarget) === targetKey) {
      return walletKey;
    }
  }
  throw new Error(`Registration active state is missing ECDSA wallet key for ${targetKey}`);
}

function registrationEcdsaSessionForTarget(args: {
  ecdsa: Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>;
  chainTarget: ThresholdEcdsaChainTarget;
}): Extract<RegistrationPersistenceEcdsa, { kind: 'evm_family_ecdsa' }>['sessions'][number] {
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  for (const session of args.ecdsa.sessions) {
    if (thresholdEcdsaChainTargetKey(session.chainTarget) === targetKey) {
      return session;
    }
  }
  throw new Error(`Registration active state is missing ECDSA session for ${targetKey}`);
}

function logRegistrationActiveRuntimeState(activeState: RegistrationActiveRuntimeState): void {
  const ed25519Identity =
    activeState.ed25519.kind === 'near_ed25519_ready' ? activeState.ed25519.identity : null;
  const firstEcdsaIdentity =
    activeState.ecdsa.kind === 'evm_family_ecdsa_ready' ? activeState.ecdsa.identities[0] : null;
  logRegistrationProgress('registration_active_runtime_state_constructed', {
    walletId: activeState.walletId,
    authMethod: activeState.authMethod,
    ed25519: activeState.ed25519.kind,
    ed25519ThresholdSessionId: ed25519Identity?.thresholdSessionId || null,
    ed25519SigningGrantId: ed25519Identity?.signingGrantId || null,
    ecdsa: activeState.ecdsa.kind,
    ecdsaThresholdSessionId: firstEcdsaIdentity?.thresholdSessionId || null,
    ecdsaSigningGrantId: firstEcdsaIdentity?.signingGrantId || null,
    ecdsaTargetCount:
      activeState.ecdsa.kind === 'evm_family_ecdsa_ready' ? activeState.ecdsa.identities.length : 0,
  });
}

async function commitRegistrationPersistencePlan(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  plan: RegistrationPersistencePlan;
}): Promise<RegistrationPersistenceCommitResult> {
  let signerSlot: number | null = null;
  if (args.plan.ed25519.kind === 'near_ed25519') {
    const ed25519 = args.plan.ed25519;
    logRegistrationProgress('local_ed25519_persistence_started', {
      walletId: args.plan.walletId,
      nearAccountId: String(ed25519.nearAccountId),
      authMethod: args.plan.auth.kind,
    });
    const storedRegistration = await args.registrationTiming.measure(
      'localWalletRegistrationPersistenceMs',
      () =>
        storeRegistrationEd25519AccountData({
          context: args.context,
          plan: args.plan,
          ed25519,
        }),
    );
    const committedSignerSlot = storedRegistration.signerSlot;
    signerSlot = committedSignerSlot;
    logRegistrationProgress('local_ed25519_record_stored', {
      walletId: args.plan.walletId,
      signerSlot: committedSignerSlot,
    });
    await args.registrationTiming.measure('thresholdEd25519SessionPersistenceMs', () =>
      persistRegistrationEd25519Session({
        context: args.context,
        relayerUrl: args.relayerUrl,
        plan: args.plan,
        ed25519,
        signerSlot: committedSignerSlot,
        registrationTiming: args.registrationTiming,
      }),
    );
    logRegistrationProgress(`threshold_ed25519_${args.plan.auth.kind}_session_persisted`, {
      walletId: args.plan.walletId,
      signerSlot: committedSignerSlot,
    });
  }
  if (args.plan.ecdsa.kind === 'evm_family_ecdsa') {
    const ecdsa = args.plan.ecdsa;
    logRegistrationProgress('ecdsa_registration_persistence_started', {
      walletId: args.plan.walletId,
      walletKeyCount: ecdsa.walletKeys.length,
    });
    await args.registrationTiming.measure('ecdsaRegistrationPersistenceMs', () =>
      persistRegistrationEcdsaSessionsAndSigners({
        context: args.context,
        relayerUrl: args.relayerUrl,
        registrationTiming: args.registrationTiming,
        plan: args.plan,
        ecdsa,
      }),
    );
    logRegistrationProgress('ecdsa_registration_sessions_finalized', {
      walletId: args.plan.walletId,
      walletKeyCount: ecdsa.walletKeys.length,
    });
  }
  if (args.plan.ed25519.kind === 'near_ed25519') {
    const ed25519 = args.plan.ed25519;
    logRegistrationProgress('wallet_state_activation_started', {
      walletId: args.plan.walletId,
      nearAccountId: String(ed25519.nearAccountId),
    });
    await args.registrationTiming.measure('walletStateActivationMs', () =>
      activateRegistrationWalletState({
        context: args.context,
        plan: args.plan,
        ed25519,
      }),
    );
    logRegistrationProgress('wallet_state_activation_completed', {
      walletId: args.plan.walletId,
    });
  }
  const activeState = buildRegistrationActiveRuntimeState({
    plan: args.plan,
    ed25519SignerSlot: signerSlot,
  });
  logRegistrationActiveRuntimeState(activeState);
  if (args.plan.ed25519.kind === 'near_ed25519') {
    if (signerSlot === null) {
      throw new Error('Registration persistence plan did not commit Ed25519 signer state');
    }
    return { kind: 'near_ed25519_committed', signerSlot, activeState };
  }
  return { kind: 'ecdsa_only_committed', activeState };
}

function thresholdEd25519RegistrationSpecFromBranch(
  branch: RegistrationNearEd25519SignerPlan,
): ThresholdEd25519RegistrationSpec {
  return {
    accountProvisioning: branch.accountProvisioning,
    signerSlot: branch.signerSlot,
    participantIds: [...branch.participantIds],
    keyPurpose: branch.keyPurpose,
    keyVersion: branch.keyVersion,
    derivationVersion: branch.derivationVersion,
  };
}

function thresholdEcdsaRegistrationSpecFromBranch(
  branch: RegistrationEvmFamilyEcdsaSignerPlan,
): ThresholdEcdsaRegistrationSpec {
  return {
    chainTargets: [...branch.chainTargets],
    participantIds: [...branch.participantIds],
  };
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

async function registerEcdsaWalletOnly(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  signerPlan: RegistrationSignerPlan;
  ecdsaSelection: EvmFamilyEcdsaRegistrationBranch;
  options: RegistrationHooksOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
  const { context, wallet, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const startedAt = performance.now();
  const registrationTiming = new RegistrationTimingRecorder(startedAt);
  const initialEventAccountId = registrationEventAccountId(
    wallet.kind === 'provided' ? String(wallet.walletId) : 'wallet-registration',
  );

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
        identity:
          wallet.kind === 'provided'
            ? { kind: 'wallet', walletId: String(wallet.walletId || '').trim() }
            : { kind: 'none' },
        authority: registrationBootstrapGrantAuthority({
          authMethod: args.authMethod,
          operation: 'registerWallet',
        }),
      }),
    );
    const intentResponse = await verifyWalletRegistrationIntentResponse({
      recorder: registrationTiming,
      intentResponse: await registrationTiming.measure('registrationIntentMs', () =>
        createWalletRegistrationIntent({
          relayerUrl,
          request: {
            wallet,
            authMethod: args.authMethod,
            signerSelection,
          },
          headers: {
            Authorization: `Bearer ${managedGrant.token}`,
          },
        }),
      ),
    });

    const walletId = intentResponse.intent.walletId;
    const eventAccountId = registrationEventAccountId(String(walletId));
    let passkeyPrfFirstB64u = '';
    let emailOtpEnrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null = null;
    let emailOtpRegistrationAuthorityId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
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
      emailOtpEnrollmentMaterial = startEmailOtpRegistrationEnrollmentMaterial({
        recorder: registrationTiming,
        context,
        authMethod: emailOtpAuthMethod,
        relayerUrl,
        walletId: String(walletId),
        providerSubject: emailAuthority.providerSubject,
        ecdsaRootMaterial: {
          kind: 'ecdsa_root_requested',
          targets: emailOtpRegistrationEcdsaRootTargetsFromBranch({
            walletId: String(walletId),
            runtimePolicyScope: intentResponse.intent.runtimePolicyScope,
            branch: args.ecdsaSelection,
          }),
        },
        appSessionJwt: emailOtpAuthMethod.appSessionJwt,
      });
      emailOtpRegistrationAuthorityId = emailAuthority.registrationAuthorityId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
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
    const startedEcdsa = startedCeremony.ecdsa;
    const preparedTargets = await registrationTiming.measure('ecdsaClientBootstrapMs', async () => {
      const targets: PreparedRegistrationEcdsaTarget[] = [];
      for (const target of startedEcdsa.targets) {
        const preparedClientBootstrap =
          args.authMethod.kind === 'email_otp'
            ? await prepareEmailOtpRegistrationEcdsaBootstrap({
                context,
                enrollmentMaterial: emailOtpEnrollmentMaterial,
                prepare: target.prepare,
                chainTarget: target.chainTarget,
              })
            : await context.signingEngine.preparePasskeyEcdsaBootstrap({
                prepare: target.prepare,
                rpId: args.authMethod.rpId,
                chainTarget: target.chainTarget,
                passkeyPrfFirstB64u,
                credentialIdB64u: String(
                  passkeyAuthority?.credential.rawId || passkeyAuthority?.credential.id || '',
                ).trim(),
              });
        targets.push({
          chainTarget: target.chainTarget,
          preparedClientBootstrap,
        });
      }
      return targets;
    });
    const responded = await registrationTiming.measure('walletRegisterHssRespondMs', () =>
      respondWalletRegistrationHss({
        relayerUrl,
        headers: registrationRouteDiagnosticsHeaders(),
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        ecdsa: {
          clientBootstraps: registrationEcdsaClientBootstrapEntries(preparedTargets),
        },
      }),
    );
    if (!responded.ecdsa?.bootstraps || responded.ecdsa.bootstraps.length === 0) {
      throw new Error('Wallet registration HSS respond did not return ECDSA bootstrap material');
    }
    registrationTiming.captureRouteDiagnostics(responded.registrationDiagnostics);
    const ecdsaSessions = buildRegistrationEcdsaSessions({
      preparedTargets,
      responseBootstraps: responded.ecdsa.bootstraps,
    });
    const emailOtpEnrollmentMaterialForFinalize =
      args.authMethod.kind === 'email_otp'
        ? await requireEmailOtpRegistrationEnrollmentMaterial({
            material: emailOtpEnrollmentMaterial,
            operation: 'finalize',
          })
        : null;
    const emailOtpEnrollment = emailOtpEnrollmentMaterialForFinalize?.emailOtpEnrollment ?? null;
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
          expectedKeyHandles: registrationEcdsaExpectedKeyHandles(ecdsaSessions),
        },
        ...(emailOtpEnrollment ? { emailOtpEnrollment } : {}),
        ...(emailOtpBackupAck ? { emailOtpBackupAck } : {}),
      }),
    );
    logRegistrationProgress('finalize_response_received', {
      walletId: finalized.walletId,
      hasEd25519: Boolean(finalized.ed25519),
      ecdsaWalletKeyCount: finalized.ecdsa?.walletKeys?.length || 0,
    });
    registrationTiming.captureRouteDiagnostics(finalized.registrationDiagnostics);
    if ('kind' in finalized && finalized.kind === 'already_finalized_restore_required') {
      const result = alreadyFinalizedRestoreRequiredResult(finalized.walletId);
      emitRegistrationTimingSummary(
        createFailedRegistrationTimingSummary({
          recorder: registrationTiming,
          authMethod: args.authMethod.kind,
          signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
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
      ed25519: { kind: 'ed25519_absent' },
      ecdsa: buildRegistrationPersistenceEcdsa({
        sessions: ecdsaSessions,
        walletKeys,
        expectedChainTargets: startedEcdsa.targets.map((target) => target.chainTarget),
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
    await commitRegistrationPersistencePlan({
      context,
      relayerUrl,
      registrationTiming,
      plan: persistencePlan,
    });
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
      kind: 'ecdsa_wallet_registered',
      walletId: finalized.walletId,
      thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
    };
    emitRegistrationTimingSummary(
      createSucceededRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: args.authMethod.kind,
        signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
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
        signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
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
  const signerPlan = registrationSignerPlanFromSignerSet(signerSelection);
  const ed25519Branch = findRegistrationSignerPlanNearEd25519Branch(signerPlan);
  const ecdsaBranch = findRegistrationSignerPlanEvmFamilyEcdsaBranch(signerPlan);

  if (!ed25519Branch) {
    if (!ecdsaBranch) {
      throw new Error('Wallet registration requires at least one signer branch');
    }
    return await registerEcdsaWalletOnly({
      context,
      authMethod: args.authMethod,
      wallet,
      signerSelection,
      signerPlan,
      ecdsaSelection: ecdsaBranch,
      options,
      ...(args.confirmationConfigOverride
        ? { confirmationConfigOverride: args.confirmationConfigOverride }
        : {}),
    });
  }

  const ed25519Selection = ed25519Branch;
  const ecdsaSelection = ecdsaBranch;
  let eventAccountId = registrationEventAccountId(
    initialRegistrationEventAccountId({
      wallet,
      signerSelection: ed25519Selection,
    }),
  );
  let finalizedNearAccountId: AccountId | null = null;

  emitRegistrationEvent(onEvent, eventAccountId, {
    authMethod: args.authMethod.kind,
    phase: RegistrationEventPhase.STEP_01_STARTED,
    status: 'started',
  });

  try {
    await registrationTiming.measure('inputValidationMs', () =>
      validateRegistrationInputs(
        context,
        registrationPreflightFromEd25519Selection({
          wallet,
          signerSelection: ed25519Selection,
        }),
        args.authMethod.kind,
        onEvent,
        onError,
      ),
    );

    const finalizeIdempotencyKey = googleEmailOtpFinalizeIdempotencyKey(args.authMethod);
    const expectedPrecomputeScope = walletRegistrationPrecomputeScopeFromArgs({
      authMethod: args.authMethod,
      wallet,
      signerPlan,
      nearEd25519: ed25519Selection,
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
          signerSelection,
          signerPlan,
          nearEd25519: ed25519Selection,
          evmFamilyEcdsa: ecdsaSelection,
          recorder: registrationTiming,
        });
        break;
      default:
        assertNever(args.precomputeMode);
    }
    const { relayerUrl, intentResponse, registrationWarmup, thresholdRuntimePolicyScope } =
      precomputeReady;
    eventAccountId = registrationEventAccountId(String(intentResponse.intent.walletId));
    const registrationSessionRpId = requiredRegistrationRpId({
      context,
      authMethod: args.authMethod,
      operation: 'registerWallet',
    });
    let registrationSessionAuthority: WalletAuthAuthority | null = null;
    let registrationAuthorityScope: RegistrationEd25519AuthorityScope | null = null;
    let ed25519PrfFirstB64u = '';
    let ecdsaPasskeyPrfFirstB64u = '';
    let emailOtpEnrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null = null;
    let emailOtpRegistrationAuthorityId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
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
      registrationAuthorityScope = {
        kind: 'passkey',
        rpId: args.authMethod.rpId,
      };
      registrationSessionAuthority = passkeyWalletAuthAuthorityFromCredential({
        walletId: intentResponse.intent.walletId,
        rpId: args.authMethod.rpId,
        credential: passkeyAuthority.credential,
      });
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
          walletId: String(intentResponse.intent.walletId),
          registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
          appSessionJwt: emailOtpAuthMethod.appSessionJwt,
        }),
      );
      const ecdsaRootMaterial: EmailOtpRegistrationEcdsaRootMaterialRequest = ecdsaSelection
        ? {
            kind: 'ecdsa_root_requested',
            targets: emailOtpRegistrationEcdsaRootTargetsFromBranch({
              walletId: String(intentResponse.intent.walletId),
              runtimePolicyScope: intentResponse.intent.runtimePolicyScope,
              branch: ecdsaSelection,
            }),
          }
        : { kind: 'ecdsa_root_not_requested' };
      emailOtpEnrollmentMaterial = startEmailOtpRegistrationEnrollmentMaterial({
        recorder: registrationTiming,
        context,
        authMethod: emailOtpAuthMethod,
        relayerUrl,
        walletId: String(intentResponse.intent.walletId),
        providerSubject: emailAuthority.providerSubject,
        ecdsaRootMaterial,
        appSessionJwt: emailOtpAuthMethod.appSessionJwt,
      });
      emailOtpRegistrationAuthorityId = emailAuthority.registrationAuthorityId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
      registrationAuthorityScope = emailOtpRegistrationEd25519AuthorityScope({
        proofKind: emailOtpAuthMethod.proofKind,
        providerSubject: emailAuthority.providerSubject,
      });
      registrationSessionAuthority = (
        await buildRegistrationEmailOtpAuthContext({
          configs: context.configs,
          walletId: toWalletId(intentResponse.intent.walletId),
          email: emailAuthority.email,
          providerSubject: emailAuthority.providerSubject,
        })
      ).authority;
      emailOtpRecoveryCodeBackup = startEmailOtpRecoveryCodeBackupAfterEnrollmentMaterial({
        recorder: registrationTiming,
        authMethod: emailOtpAuthMethod,
        relayerUrl,
        walletId: String(intentResponse.intent.walletId),
        enrollmentMaterial: emailOtpEnrollmentMaterial,
        registrationAuthorityId: emailAuthority.registrationAuthorityId,
      });
      startAuthority = {
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      };
    }
    if (!registrationAuthorityScope) {
      throw new Error('Wallet registration Ed25519 authority scope is missing');
    }
    if (!registrationSessionAuthority) {
      throw new Error('Wallet registration Ed25519 session authority is missing');
    }
    const ed25519SessionAuthority = registrationSessionAuthority;
    const nearEd25519SigningKeyId = await ed25519RegistrationKeyScopeIdFromIntent({
      ...intentResponse.intent,
      authorityScope: registrationAuthorityScope,
    });

    emitRegistrationEvent(onEvent, eventAccountId, {
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
              nearEd25519SigningKeyId,
              participantIds: [...ed25519Selection.participantIds],
            })
          : await prepareEmailOtpThresholdEd25519RegistrationHssClientMaterial({
              context,
              enrollmentMaterial: emailOtpEnrollmentMaterial,
              runtimePolicyScope: thresholdRuntimePolicyScope,
              nearEd25519SigningKeyId,
              participantIds: [...ed25519Selection.participantIds],
            }),
    );
    if (startedPrecomputeHandle) {
      registrationTiming.mergeSnapshot(startedPrecomputeHandle.snapshot());
      registrationTiming.captureRouteDiagnosticsSnapshot(
        startedPrecomputeHandle.routeDiagnosticsSnapshot(),
      );
    }
    const preparedRegistration = await registrationTiming.measure('walletRegisterPrepareMs', () =>
      prepareWalletRegistration({
        relayerUrl,
        registrationIntentGrant: intentResponse.registrationIntentGrant,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        intent: intentResponse.intent,
        headers: registrationRouteDiagnosticsHeaders(),
        work: {
          kind: ecdsaSelection ? 'ed25519_hss_and_ecdsa' : 'ed25519_hss',
        },
        ...startAuthority,
      }),
    );
    registrationTiming.captureRouteDiagnostics(preparedRegistration.registrationDiagnostics);
    const startedCeremony = await registrationTiming.measure('walletRegisterStartMs', () =>
      startWalletRegistration({
        relayerUrl,
        registrationIntentGrant: intentResponse.registrationIntentGrant,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        intent: intentResponse.intent,
        registrationPreparationId: preparedRegistration.registrationPreparationId,
        headers: registrationRouteDiagnosticsHeaders(),
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
    const startedEcdsa = startedCeremony.ecdsa;
    const ecdsaPreparedTargetsPromise =
      ecdsaSelection && startedEcdsa
        ? registrationTiming.measure('ecdsaClientBootstrapMs', async () => {
            const targets: PreparedRegistrationEcdsaTarget[] = [];
            for (const target of startedEcdsa.targets) {
              const preparedClientBootstrap =
                args.authMethod.kind === 'email_otp'
                  ? await prepareEmailOtpRegistrationEcdsaBootstrap({
                      context,
                      enrollmentMaterial: emailOtpEnrollmentMaterial,
                      prepare: target.prepare,
                      chainTarget: target.chainTarget,
                    })
                  : await context.signingEngine.preparePasskeyEcdsaBootstrap({
                      prepare: target.prepare,
                      rpId: args.authMethod.rpId,
                      chainTarget: target.chainTarget,
                      passkeyPrfFirstB64u: ecdsaPasskeyPrfFirstB64u,
                      credentialIdB64u: String(
                        passkeyAuthority?.credential.rawId || passkeyAuthority?.credential.id || '',
                      ).trim(),
                    });
              targets.push({
                chainTarget: target.chainTarget,
                preparedClientBootstrap,
              });
            }
            return targets;
          })
        : Promise.resolve([]);

    const ed25519ClientRequestPromise = registrationTiming.measure('ed25519ClientRequestMs', () =>
      prepareThresholdEd25519RegistrationHssClientRequest({
        context,
        material: hssClientMaterial,
        preparedSession: startedEd25519.preparedSession,
        clientOtOfferMessageB64u: startedEd25519.clientOtOfferMessageB64u,
        ceremonyHandle: startedEd25519.ceremonyHandle,
      }),
    );
    const [ecdsaPreparedTargets, { clientRequest, clientOutputMaskHandle }] = await Promise.all([
      ecdsaPreparedTargetsPromise,
      ed25519ClientRequestPromise,
    ]);
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
        ...(ecdsaPreparedTargets.length > 0
          ? {
              ecdsa: {
                clientBootstraps: registrationEcdsaClientBootstrapEntries(ecdsaPreparedTargets),
              },
            }
          : {}),
      }),
    );
    if (!responded.ed25519) {
      throw new Error('Wallet registration HSS respond did not return Ed25519 server input');
    }
    registrationTiming.captureRouteDiagnostics(responded.registrationDiagnostics);
    const respondedEd25519 = responded.ed25519;
    if (
      ecdsaSelection &&
      (!responded.ecdsa?.bootstraps || responded.ecdsa.bootstraps.length === 0)
    ) {
      throw new Error('Wallet registration HSS respond did not return ECDSA bootstrap material');
    }
    const ecdsaSessions =
      ecdsaPreparedTargets.length > 0 && responded.ecdsa?.bootstraps
        ? buildRegistrationEcdsaSessions({
            preparedTargets: ecdsaPreparedTargets,
            responseBootstraps: responded.ecdsa.bootstraps,
          })
        : [];
    const preparedAddStageRequest = await registrationTiming.measure(
      'ed25519AddStageRequestMs',
      () =>
        context.signingEngine.prepareThresholdEd25519HssAddStageRequestMessage({
          preparedSession: startedEd25519.preparedSession,
          clientRequest,
          serverInputDelivery: respondedEd25519,
          expectedContextBindingB64u: startedEd25519.preparedSession.contextBindingB64u,
        }),
    );
    const advanceStatePromise = registrationTiming.measure('walletRegisterHssAdvanceStateMs', () =>
      advanceWalletRegistrationHssState({
        relayerUrl,
        headers: registrationRouteDiagnosticsHeaders(),
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        ed25519: {
          addStageRequestMessageB64u: preparedAddStageRequest.addStageRequestMessageB64u,
        },
      }),
    );
    const evaluationResultPromise = registrationTiming.measure('ed25519EvaluationArtifactMs', () =>
      buildThresholdEd25519RegistrationHssClientOwnedArtifact({
        context,
        preparedSession: startedEd25519.preparedSession,
        clientRequest,
        serverInputDelivery: respondedEd25519,
        clientOutputMaskHandle,
        addStage: {
          kind: 'prepared',
          request: preparedAddStageRequest,
        },
      }),
    );
    const [advancedState, evaluationResult] = await Promise.all([
      advanceStatePromise,
      evaluationResultPromise,
    ]);
    if (!advancedState.ok) {
      throw new Error(advancedState.message || 'Wallet registration HSS advance-state failed');
    }
    registrationTiming.captureRouteDiagnostics(advancedState.registrationDiagnostics);

    const requestedPolicy = createRegistrationThresholdWarmSessionPolicyDraft({
      context,
      participantIds: hssClientMaterial.hssContext.participantIds,
      runtimePolicyScope: thresholdRuntimePolicyScope,
    });
    if (!requestedPolicy) {
      throw new Error('Threshold warm-session defaults are disabled for registration');
    }
    const emailOtpEnrollmentMaterialForFinalize =
      args.authMethod.kind === 'email_otp'
        ? await requireEmailOtpRegistrationEnrollmentMaterial({
            material: emailOtpEnrollmentMaterial,
            operation: 'finalize',
          })
        : null;
    if (emailOtpEnrollmentMaterialForFinalize) {
      ed25519PrfFirstB64u =
        emailOtpEnrollmentMaterialForFinalize.thresholdEd25519RecoveryCodeSecret32B64u;
    }
    const emailOtpEnrollment = emailOtpEnrollmentMaterialForFinalize?.emailOtpEnrollment ?? null;
    const emailOtpBackupAck = await resolveEmailOtpBackupAck({
      authMethod: args.authMethod,
      backup: emailOtpRecoveryCodeBackup,
    });
    const sponsoredNamedAccountId = sponsoredNamedRegistrationAccountId(
      ed25519Selection.accountProvisioning,
    );
    const finalized = await registrationTiming.measure('walletRegisterFinalizeMs', () =>
      finalizeWalletRegistration({
        relayerUrl,
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        headers: registrationRouteDiagnosticsHeaders(),
        ...(finalizeIdempotencyKey ? { idempotencyKey: finalizeIdempotencyKey } : {}),
        ed25519: {
          evaluationResult,
          sessionPolicy: buildThresholdWarmSessionRequestEnvelope({
            authority: ed25519SessionAuthority,
            requestedPolicy,
            ...(sponsoredNamedAccountId ? { nearAccountId: sponsoredNamedAccountId } : {}),
          }).session_policy,
          sessionKind: 'jwt',
        },
        ...(ecdsaSessions.length > 0
          ? {
              ecdsa: {
                expectedKeyHandles: registrationEcdsaExpectedKeyHandles(ecdsaSessions),
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
          signerSet: registrationTimingSignerSetFromPlan(signerPlan),
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
    const nearAccountId = toAccountId(finalizedEd25519.nearAccountId);
    finalizedNearAccountId = nearAccountId;
    eventAccountId = registrationEventAccountId(String(nearAccountId));
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

    registrationState.accountCreated = Boolean(sponsoredNamedAccountId);
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
            authority: ed25519SessionAuthority,
            requestedPolicy,
            walletId: finalized.walletId,
            nearAccountId: String(nearAccountId),
            nearEd25519SigningKeyId: finalizedEd25519.nearEd25519SigningKeyId,
            relayerKeyId: finalizedEd25519.relayerKeyId,
          }).session_policy,
          expectedIdentity: {
            walletId: finalized.walletId,
            nearAccountId: String(nearAccountId),
            nearEd25519SigningKeyId: finalizedEd25519.nearEd25519SigningKeyId,
          },
        }),
    );
    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_SUCCEEDED,
      status: 'succeeded',
    });
    logRegistrationProgress('ed25519_completion_parsed', {
      walletId: finalized.walletId,
      nearAccountId: String(nearAccountId),
      nearEd25519SigningKeyId: finalizedEd25519.nearEd25519SigningKeyId,
    });
    const thresholdEd25519RegistrationSessionPolicy = buildThresholdWarmSessionRequestEnvelope({
      authority: ed25519SessionAuthority,
      requestedPolicy,
      walletId: finalized.walletId,
      nearAccountId: String(nearAccountId),
      nearEd25519SigningKeyId: finalizedEd25519.nearEd25519SigningKeyId,
      relayerKeyId: finalizedEd25519.relayerKeyId,
    }).session_policy;
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
      ed25519: {
        kind: 'near_ed25519',
        nearAccountId,
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
          finalizedEd25519.nearEd25519SigningKeyId,
        ),
        signerSlot: ed25519Selection.signerSlot,
        rpId: registrationSessionRpId,
        finalized: finalizedEd25519,
        completedRegistration: completedThresholdEd25519Registration,
        registrationSessionPolicy: thresholdEd25519RegistrationSessionPolicy,
        hssClientMaterial,
        finalizedHssMaterial: buildThresholdEd25519FinalizedRegistrationHssMaterial({
          preparedSession: startedEd25519.preparedSession,
          ceremonyHandle: startedEd25519.ceremonyHandle,
          finalized: finalizedEd25519,
        }),
        prfFirstB64u: ed25519PrfFirstB64u,
      },
      ecdsa: buildRegistrationPersistenceEcdsa({
        sessions: ecdsaSessions,
        walletKeys: ecdsaWalletKeys,
        expectedChainTargets: ecdsaSelection
          ? expectedEcdsaChainTargetsFromRegistrationSpec(
              thresholdEcdsaRegistrationSpecFromBranch(ecdsaSelection),
            )
          : [],
      }),
    });

    emitRegistrationEvent(onEvent, nearAccountId, {
      authMethod: args.authMethod.kind,
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
      status: 'running',
    });
    const persistenceCommit = await commitRegistrationPersistencePlan({
      context,
      relayerUrl,
      registrationTiming,
      plan: persistencePlan,
    });
    if (persistenceCommit.kind !== 'near_ed25519_committed') {
      throw new Error('Registration persistence did not commit Ed25519 signer state');
    }
    const signerSlot = persistenceCommit.signerSlot;
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
      kind: 'near_wallet_registered',
      walletId: finalized.walletId,
      nearAccountId,
      accountProvisioning: finalized.accountProvisioning,
      resolvedAccount: finalized.resolvedAccount,
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
        finalizedEd25519.nearEd25519SigningKeyId,
      ),
      operationalPublicKey: completedThresholdEd25519Registration.operationalPublicKey,
      transactionId:
        finalized.resolvedAccount.kind === 'sponsored_named_account'
          ? finalized.resolvedAccount.transactionHash
          : null,
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
        signerSet: registrationTimingSignerSetFromPlan(signerPlan),
      }),
    );
    afterCall?.(true, successResult);
    return successResult;
  } catch (error: unknown) {
    const errorCode = registrationErrorCodeFromUnknown(error);
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', eventAccountId);
    const rollback = finalizedNearAccountId
      ? await performRegistrationRollback(
          registrationState,
          finalizedNearAccountId,
          context.signingEngine,
        )
      : skippedRegistrationRollback('near_account_unresolved');
    const errorObject = registrationErrorWithCode(errorMessage, errorCode);
    onError?.(errorObject);
    emitRegistrationEvent(onEvent, eventAccountId, {
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
        signerSet: registrationTimingSignerSetFromPlan(signerPlan),
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
  const rpIdRaw = String(args.rpId || '').trim();
  const startedAt = performance.now();

  if (!walletId) {
    throw new Error('addWalletSigner requires walletId');
  }
  if (!rpIdRaw) {
    throw new Error('addWalletSigner requires rpId');
  }
  const rpId = requireWebAuthnRpId(rpIdRaw);
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
      identity: { kind: 'wallet', walletId: String(walletId) },
      authority: { kind: 'passkey_rp', rpId },
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
    const addSignerSessionAuthority = passkeyWalletAuthAuthorityFromCredential({
      walletId,
      rpId,
      credential: redactedAuthentication,
    });
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
      const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(String(nearAccountId));
      const hssClientMaterial = await prepareThresholdEd25519RegistrationHssClientMaterial({
        context,
        credential: webauthnAuthentication,
        runtimePolicyScope: thresholdRuntimePolicyScope,
        nearEd25519SigningKeyId,
        participantIds: signerSelection.ed25519.participantIds,
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
      const { clientRequest, clientOutputMaskHandle } =
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
      const preparedAddStageRequest =
        await context.signingEngine.prepareThresholdEd25519HssAddStageRequestMessage({
          preparedSession: startedCeremony.ed25519.preparedSession,
          clientRequest,
          serverInputDelivery: responded.ed25519,
          expectedContextBindingB64u: startedCeremony.ed25519.preparedSession.contextBindingB64u,
        });
      const evaluationResult = await buildThresholdEd25519RegistrationHssClientOwnedArtifact({
        context,
        preparedSession: startedCeremony.ed25519.preparedSession,
        clientRequest,
        serverInputDelivery: responded.ed25519,
        clientOutputMaskHandle,
        addStage: {
          kind: 'prepared',
          request: preparedAddStageRequest,
        },
      });
      const requestedPolicy = createThresholdWarmSessionPolicyDraft(context, {
        kind: 'generated_signing_grant',
        participantIds: hssClientMaterial.hssContext.participantIds,
        runtimePolicyScope: thresholdRuntimePolicyScope,
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
            authority: addSignerSessionAuthority,
            requestedPolicy,
            walletId: String(walletId),
            nearAccountId: String(nearAccountId),
            nearEd25519SigningKeyId: String(nearEd25519SigningKeyId),
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
          authority: addSignerSessionAuthority,
          requestedPolicy,
          walletId: String(walletId),
          nearAccountId: String(nearAccountId),
          nearEd25519SigningKeyId: String(nearEd25519SigningKeyId),
          relayerKeyId: finalized.ed25519.relayerKeyId,
        }).session_policy,
        expectedIdentity: {
          walletId: String(walletId),
          nearAccountId: String(nearAccountId),
          nearEd25519SigningKeyId: String(nearEd25519SigningKeyId),
        },
      });

      emitRegistrationEvent(onEvent, eventAccountId, {
        phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
        status: 'running',
      });
      const storedRegistration =
        await context.signingEngine.finalizeWalletEd25519SignerRegistration({
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
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
        walletId: String(walletId),
        nearAccountId,
        nearEd25519SigningKeyId,
        signerSlot: storedRegistration.signerSlot,
        auth: {
          kind: 'passkey',
          credential: webauthnAuthentication,
        },
        rpId,
        relayerUrl,
        prfFirstB64u: hssClientMaterial.prfFirstB64u,
        registrationHssClientMaterial: hssClientMaterial,
        finalizedRegistrationHssMaterial: buildThresholdEd25519FinalizedRegistrationHssMaterial({
          preparedSession: startedCeremony.ed25519.preparedSession,
          ceremonyHandle: startedCeremony.ed25519.ceremonyHandle,
          finalized: finalized.ed25519,
        }),
        registrationSessionPolicy: buildThresholdWarmSessionRequestEnvelope({
          authority: addSignerSessionAuthority,
          requestedPolicy,
          walletId: String(walletId),
          nearAccountId: String(nearAccountId),
          nearEd25519SigningKeyId: String(nearEd25519SigningKeyId),
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
        kind: 'near_ed25519_signer_added',
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
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
    const addSignerEcdsaTarget = startedCeremony.ecdsa.targets[0];
    if (!addSignerEcdsaTarget) {
      throw new Error('Wallet add-signer start did not return ECDSA target material');
    }
    const preparedClientBootstrap = await context.signingEngine.preparePasskeyEcdsaBootstrap({
      prepare: addSignerEcdsaTarget.prepare,
      rpId,
      chainTarget: addSignerEcdsaTarget.chainTarget,
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
      sessions: [
        {
          chainTarget: addSignerEcdsaTarget.chainTarget,
          preparedClientBootstrap,
          bootstrap: ecdsaBootstrap,
        },
      ],
      walletKeys,
      auth: {
        kind: 'passkey',
        credentialIdB64u: passkeyEcdsaCredentialIdFromPrepared(preparedClientBootstrap),
        rpId,
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
      kind: 'ecdsa_signer_added',
      walletId,
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

const validateRegistrationInputs = async (
  context: {
    configs: SeamsConfigsReadonly;
    signingEngine: RegistrationSigningSurface;
    nearClient: NearClient;
  },
  preflight: RegistrationAccountPreflight,
  authMethod: RegistrationAuthMethodInput['kind'],
  onEvent?: RegistrationHooksOptions['onEvent'],
  onError?: (error: Error) => void,
) => {
  const eventAccountId =
    preflight.kind === 'sponsored_named_account'
      ? preflight.nearAccountId
      : preflight.eventAccountId;
  emitRegistrationEvent(onEvent, eventAccountId, {
    authMethod,
    phase: RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_STARTED,
    status: 'running',
  });

  if (!window.isSecureContext) {
    const error = new Error('Passkey operations require a secure context (HTTPS or localhost).');
    onError?.(error);
    throw error;
  }

  switch (preflight.kind) {
    case 'implicit_account':
      emitRegistrationEvent(onEvent, eventAccountId, {
        authMethod,
        phase: RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_SUCCEEDED,
        status: 'succeeded',
      });
      return;
    case 'sponsored_named_account': {
      const nearAccountId = preflight.nearAccountId;
      if (!nearAccountId) {
        const error = new Error('NEAR account ID is required for registration.');
        onError?.(error);
        throw error;
      }
      const validation = validateNearAccountId(nearAccountId);
      if (!validation.valid) {
        const error = new Error(`Invalid NEAR account ID: ${validation.error}`);
        onError?.(error);
        throw error;
      }
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
    }
    default:
      assertNever(preflight);
  }
};

/**
 * Rollback registration data in case of errors
 */
function skippedRegistrationRollback(reason: string): Record<string, unknown> {
  return {
    databaseRolledBack: false,
    databasePreserved: false,
    onChainRollbackPossible: false,
    contractTransactionId: null,
    rollbackSkippedReason: reason,
  };
}

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
