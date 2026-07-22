import { isObject } from '@shared/utils/validation';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import type {
  CreateRegistrationFlowEventInput,
  RegistrationFlowEvent,
  RegistrationHooksOptions,
  WalletFlowAuthMethod,
} from '@/core/types/sdkSentEvents';
import type { RegistrationResult, SeamsConfigsReadonly } from '@/core/types/seams';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { createRegistrationFlowEvent, RegistrationEventPhase } from '@/core/types/sdkSentEvents';
import { createManagedRegistrationFlowGrant } from '@/SeamsWeb/operations/registration/createAccountRouterApiServer';
import type {
  RegistrationSigningSurface,
  RegistrationWebContext,
} from '@/SeamsWeb/signingSurface/types';
import type { WorkerResourceWarmupDiagnostics } from '@/core/signingEngine/assembly/warmup';
import type {
  FinalizeWalletRegistrationEcdsaSessionsDiagnosticBucket,
  FinalizeWalletRegistrationEcdsaSessionsDiagnostics,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { alphabetizeStringify, sha256HexUtf8 } from '@shared/utils/digests';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { normalizeRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { IndexedDBManager } from '@/core/indexedDB';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
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
import { base64UrlDecode } from '@shared/utils/base64';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
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
import {
  cancelWalletRegistrationIntent,
  activateWalletAddSignerEcdsa,
  activateWalletRegistrationEcdsa,
  createWalletAddSignerIntent,
  createWalletRegistrationIntent,
  finalizeWalletAddSigner,
  finalizeWalletRegistration,
  isEmailOtpWalletRegistrationFinalizeResponse,
  parseWalletRegistrationEcdsaDerivationRespond,
  respondWalletAddSignerEcdsa,
  respondWalletRegistrationEcdsa,
  startWalletAddSigner,
  startWalletRegistration,
  type RegistrationPreparationId,
  type WalletRegistrationEcdsaDerivationRespondBootstrap,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEmailOtpEnrollmentMaterial,
  type WalletRegistrationEmailOtpBackupAck,
  type WalletRegistrationFinalizeResponse,
  type WalletRegistrationEcdsaRespondResponse,
  type WalletRegistrationEcdsaPreparePayload,
  type WalletRegistrationStartResponse,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
  type WalletAddSignerFinalizeResponse,
  type WalletAddSignerStartResponse,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { FinalizeRouterAbEcdsaRegistrationActivationResultV1 } from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
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
import { registrationFinalizeIdempotencyKeyFromString } from '@/SeamsWeb/publicApi/types';
import { collectEmailOtpRegistrationAuthority } from '@/SeamsWeb/operations/authMethods/emailOtp/registrationAuthority';
import type { PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult as EmailOtpRegistrationEnrollmentMaterial } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import { requirePasskeyPrfFirstB64u } from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { startEmailOtpEd25519YaoWorkerRegistrationV1 } from '@/core/signingEngine/session/emailOtp/ed25519YaoWorkerClient';
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
import { registerVerifiedPasskeyEd25519YaoV1 } from '@/core/signingEngine/flows/registration/services/passkeyEd25519YaoRegistration';
import { registerVerifiedPasskeyEd25519YaoAddSignerV1 } from '@/core/signingEngine/flows/registration/services/passkeyEd25519YaoAddSigner';
import type { ProductEd25519YaoPendingRegistrationPortV1 } from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import {
  deletePasskeyEd25519YaoLocalMaterialV1,
  persistPasskeyEd25519YaoLocalMaterialV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { resolveRouterAbEd25519WalletSessionStateFromRecord } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { persistPasskeyEd25519YaoSessionForRefresh } from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  clearStoredThresholdEd25519SessionRecordForLaneKey,
  thresholdEd25519SessionRecordKeyFromRecord,
  type ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';
import { toAccountId } from '@/core/types/accountIds';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import {
  emailOtpAppSessionBindingFromJwt,
  type EmailOtpAppSessionBinding,
} from '@/core/signingEngine/session/emailOtp/appSessionJwtCache';

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
  walletRegisterStartMs: number;
  ecdsaClientBootstrapMs: number;
  walletRegisterDerivationRespondMs: number;
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

type RegistrationCriticalPathBucket = {
  name: RegistrationTimingBucketName;
  durationMs: number;
};

type RegistrationCriticalPathSummary = {
  kind: 'registration_critical_path_summary_v1';
  totalElapsedMs: number;
  measuredWorkMs: number;
  unattributedElapsedMs: number;
  overlappedOrBackgroundMs: number;
  topBuckets: readonly RegistrationCriticalPathBucket[];
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

type RegisterWalletPasskeyExecution = {
  kind: 'collect_during_registration';
};

type WalletRegistrationIntentResponse = Awaited<ReturnType<typeof createWalletRegistrationIntent>>;

type ActiveWalletRegistrationIntent = {
  relayerUrl: string;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
};

async function cancelActiveWalletRegistrationIntent(
  activeIntent: ActiveWalletRegistrationIntent | null,
): Promise<void> {
  if (!activeIntent) return;
  try {
    await cancelWalletRegistrationIntent(activeIntent);
  } catch {}
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

type RegistrationEd25519Timing = { kind: 'ed25519_yao_enabled' } | { kind: 'ed25519_disabled' };

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
    walletRegisterStartMs: 0,
    ecdsaClientBootstrapMs: 0,
    walletRegisterDerivationRespondMs: 0,
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
    walletRegisterStartMs: buckets.walletRegisterStartMs,
    ecdsaClientBootstrapMs: buckets.ecdsaClientBootstrapMs,
    walletRegisterDerivationRespondMs: buckets.walletRegisterDerivationRespondMs,
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

function buildRegistrationEd25519Timing(
  signerSet: RegistrationTimingSignerSet,
): RegistrationEd25519Timing {
  return registrationTimingSignerSetHasBranch(signerSet, 'near_ed25519')
    ? { kind: 'ed25519_yao_enabled' }
    : { kind: 'ed25519_disabled' };
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
  'registrationWarmupWaitMs',
  'managedRegistrationGrantMs',
  'registrationIntentMs',
  'registrationIntentDigestMs',
  'authProofMs',
  'emailOtpEnrollmentMaterialMs',
  'walletRegisterStartMs',
  'ecdsaClientBootstrapMs',
  'walletRegisterDerivationRespondMs',
  'emailOtpRecoveryCodeBackupMs',
  'walletRegisterFinalizeMs',
  'ecdsaRegistrationPersistenceMs',
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
    unattributedElapsedMs: Math.max(0, input.totalElapsedMs - measuredWorkMs),
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
    registrationWarmupMs: buckets.registrationWarmupMs,
    registrationWarmupWaitMs: buckets.registrationWarmupWaitMs,
    registrationWarmupAuthenticatedWalletStateMs:
      buckets.registrationWarmupAuthenticatedWalletStateMs,
    registrationWarmupNoncePrefetchMs: buckets.registrationWarmupNoncePrefetchMs,
    registrationWarmupKeyMaterialReadMs: buckets.registrationWarmupKeyMaterialReadMs,
    registrationWarmupUiConfirmPrewarmMs: buckets.registrationWarmupUiConfirmPrewarmMs,
    registrationWarmupSignerWorkerPrewarmMs: buckets.registrationWarmupSignerWorkerPrewarmMs,
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
    walletRegisterStartMs: buckets.walletRegisterStartMs,
    ecdsaClientBootstrapMs: buckets.ecdsaClientBootstrapMs,
    walletRegisterDerivationRespondMs: buckets.walletRegisterDerivationRespondMs,
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
    ed25519: buildRegistrationEd25519Timing(input.signerSet),
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
      case 'session_bootstrap':
        this.registrationTiming.record('ecdsaRegistrationServerBootstrapMs', durationMs);
        return;
      case 'public_anchor_persist':
        this.registrationTiming.record('ecdsaRegistrationPasskeyBootstrapStoreMs', durationMs);
        return;
      case 'runtime_session_commit':
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
      default:
        return assertNever(bucket);
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

function registrationWarmupWork(
  context: RegistrationWebContext,
): () => Promise<WorkerResourceWarmupDiagnostics> {
  return context.signingEngine.warmCriticalResources.bind(context.signingEngine, { kind: 'none' });
}

function completedRegistrationWarmup(
  diagnostics: WorkerResourceWarmupDiagnostics,
): RegistrationWarmupOutcome {
  return { kind: 'completed', diagnostics };
}

function failedRegistrationWarmup(error: unknown): RegistrationWarmupOutcome {
  return { kind: 'failed', error };
}

function startRegistrationWarmup(input: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
}): Promise<RegistrationWarmupOutcome> {
  return input.recorder
    .measure('registrationWarmupMs', registrationWarmupWork(input.context))
    .then(completedRegistrationWarmup, failedRegistrationWarmup);
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

type WalletRegistrationPrecomputeReady = {
  relayerUrl: string;
  intentResponse: WalletRegistrationIntentResponse;
  registrationWarmup: Promise<RegistrationWarmupOutcome>;
};

function activeWalletRegistrationIntentFromReady(
  ready: WalletRegistrationPrecomputeReady,
): ActiveWalletRegistrationIntent {
  return {
    relayerUrl: ready.relayerUrl,
    registrationIntentGrant: ready.intentResponse.registrationIntentGrant,
    registrationIntentDigestB64u: ready.intentResponse.registrationIntentDigestB64u,
  };
}

async function startWalletRegistrationPrecomputeReady(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  recorder: RegistrationTimingRecorder;
}): Promise<WalletRegistrationPrecomputeReady> {
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) throw new Error('registerWallet requires relayer.url');
  const registrationWarmup = startRegistrationWarmup({
    recorder: args.recorder,
    context: args.context,
  });
  let activeIntent: ActiveWalletRegistrationIntent | null = null;
  try {
    const managedGrant = await args.recorder.measure('managedRegistrationGrantMs', () =>
      createManagedRegistrationFlowGrant({
        context: args.context,
        identity:
          args.wallet.kind === 'provided'
            ? { kind: 'wallet', walletId: String(args.wallet.walletId) }
            : { kind: 'none' },
        authority: registrationBootstrapGrantAuthority({
          authMethod: args.authMethod,
          operation: 'registerWallet',
        }),
      }),
    );
    const intentResponse = await verifyWalletRegistrationIntentResponse({
      recorder: args.recorder,
      intentResponse: await args.recorder.measure('registrationIntentMs', () =>
        createWalletRegistrationIntent({
          relayerUrl,
          request: {
            wallet: args.wallet,
            authMethod: args.authMethod,
            signerSelection: args.signerSelection,
          },
          headers: { Authorization: `Bearer ${managedGrant.token}` },
        }),
      ),
    });
    activeIntent = {
      relayerUrl,
      registrationIntentGrant: intentResponse.registrationIntentGrant,
      registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
    };
    return { relayerUrl, intentResponse, registrationWarmup };
  } catch (error) {
    await cancelActiveWalletRegistrationIntent(activeIntent);
    throw error;
  }
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

async function startWalletRegistrationPrecomputeUnderModal(args: {
  context: RegistrationWebContext;
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  recorder: RegistrationTimingRecorder;
}): Promise<WalletRegistrationPrecomputeReady> {
  const modalPromise = args.context.signingEngine.openRegistrationPreparationModal({
    walletLabel: registrationPreparationWalletLabel(args.wallet),
    signerSlot: registrationPreparationSignerSlot(args.signerSelection),
  });
  const readyPromise = startWalletRegistrationPrecomputeReady(args);
  try {
    const [ready] = await Promise.all([readyPromise, modalPromise]);
    return ready;
  } catch (error) {
    args.context.signingEngine.closeRegistrationPreparationModal();
    try {
      const ready = await readyPromise;
      await cancelWalletRegistrationPrecomputeReady(ready);
    } catch {}
    throw error;
  }
}

async function cancelWalletRegistrationPrecomputeReady(
  ready: WalletRegistrationPrecomputeReady,
): Promise<void> {
  await cancelActiveWalletRegistrationIntent(activeWalletRegistrationIntentFromReady(ready));
}

async function resolvePasskeyRegistrationReady(args: {
  context: RegistrationWebContext;
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
  wallet: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  recorder: RegistrationTimingRecorder;
}): Promise<WalletRegistrationPrecomputeReady> {
  return await startWalletRegistrationPrecomputeUnderModal({
    context: args.context,
    authMethod: args.authMethod,
    wallet: args.wallet,
    signerSelection: args.signerSelection,
    recorder: args.recorder,
  });
}

async function resolvePasskeyRegistrationAuthority(args: {
  context: RegistrationWebContext;
  walletId: WalletId;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  options: RegistrationHooksOptions;
  confirmationConfigOverride: Partial<ConfirmationConfig>;
}): Promise<Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>>> {
  return await collectPasskeyRegistrationAuthority({
    context: args.context,
    walletId: args.walletId,
    signerSlot: args.signerSlot,
    registrationIntentDigestB64u: args.registrationIntentDigestB64u,
    options: args.options,
    confirmationConfigOverride: args.confirmationConfigOverride,
  });
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
  if (!isRegistrationBenchmarkDiagnosticsEnabled()) return;
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

type RegistrationEcdsaSession = {
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  roleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
  clientPublicFacts: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicFacts'];
  publicCapability: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicCapability'];
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

type MixedRegistrationEd25519Session = Extract<
  WalletRegistrationFinalizeResponse,
  { kind: 'near_ed25519_and_evm_family_ecdsa' }
>['ed25519']['session'];

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

function assertMixedRegistrationSharedSigningBudget(args: {
  readonly walletId: WalletId;
  readonly ed25519Session: MixedRegistrationEd25519Session;
  readonly ecdsa: RegistrationPersistenceEcdsa;
}): void {
  const ed25519Session = args.ed25519Session;
  if (ed25519Session.walletId !== args.walletId) {
    throw new Error('Mixed registration Ed25519 signing budget has a walletId mismatch');
  }
  const clientBootstrap = args.ecdsa.session.clientBootstrap;
  const serverBootstrap = args.ecdsa.session.bootstrap;
  if (
    clientBootstrap.walletId !== args.walletId ||
    serverBootstrap.walletId !== args.walletId ||
    clientBootstrap.signingGrantId !== ed25519Session.signingGrantId ||
    serverBootstrap.signingGrantId !== ed25519Session.signingGrantId ||
    clientBootstrap.remainingUses !== ed25519Session.remainingUses ||
    serverBootstrap.remainingUses !== ed25519Session.remainingUses ||
    serverBootstrap.expiresAtMs !== ed25519Session.expiresAtMs ||
    !registrationParticipantIdsMatch(clientBootstrap.participantIds, serverBootstrap.participantIds)
  ) {
    throw new Error('Mixed registration must persist one signing budget across Ed25519 and ECDSA');
  }
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

function registrationEcdsaExpectedKeyHandles(session: RegistrationEcdsaSession): string[] {
  const keyHandle = String(session.bootstrap.keyHandle || '').trim();
  if (!keyHandle) throw new Error('Registration ECDSA session is missing keyHandle');
  return [keyHandle];
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
    signingGrantId: prepare.signingGrantId,
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
  strictRegistration: Awaited<
    ReturnType<RegistrationWebContext['signingEngine']['createRouterAbEcdsaRegistrationCeremony']>
  >['registrationRequest'];
}) {
  switch (args.route.kind) {
    case 'registration':
      return await respondWalletRegistrationEcdsa({
        relayerUrl: args.relayerUrl,
        headers: registrationRouteDiagnosticsHeaders(),
        registrationCeremonyId: args.route.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: args.strictRegistration,
        },
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

async function activateStrictEcdsaFamilyRegistration(args: {
  relayerUrl: string;
  route: StrictEcdsaFamilyCeremonyRoute;
  publicFacts: Parameters<typeof activateWalletRegistrationEcdsa>[0]['publicFacts'];
}) {
  switch (args.route.kind) {
    case 'registration':
      return await activateWalletRegistrationEcdsa({
        relayerUrl: args.relayerUrl,
        headers: registrationRouteDiagnosticsHeaders(),
        registrationCeremonyId: args.route.registrationCeremonyId,
        publicFacts: args.publicFacts,
      });
    case 'add_signer':
      return await activateWalletAddSignerEcdsa({
        relayerUrl: args.relayerUrl,
        walletId: args.route.walletId,
        addSignerCeremonyId: args.route.addSignerCeremonyId,
        publicFacts: args.publicFacts,
      });
    default:
      return assertNever(args.route);
  }
}

async function runStrictEcdsaFamilyCeremony(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  route: StrictEcdsaFamilyCeremonyRoute;
  started: WalletRegistrationEcdsaPreparePayload;
}): Promise<RegistrationEcdsaSession> {
  const [firstChainTarget, ...remainingChainTargets] = args.started.chainTargets;
  if (!firstChainTarget) {
    throw new Error('Strict ECDSA ceremony requires at least one EVM-family target');
  }
  const ceremonyId = strictEcdsaFamilyCeremonyId(args.route);
  try {
    const created = await args.context.signingEngine.createRouterAbEcdsaRegistrationCeremony({
      kind: 'create_router_ab_ecdsa_registration_ceremony_v1',
      ceremonyId,
      registration: args.started.strictRegistration,
    });
    const forwarded = await forwardStrictEcdsaFamilyRegistration({
      relayerUrl: args.relayerUrl,
      route: args.route,
      strictRegistration: created.registrationRequest,
    });
    const verified = await args.context.signingEngine.verifyRouterAbEcdsaRegistrationClientProofs({
      kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1',
      ceremonyId,
      clientProofFinalization: {
        kind: 'finalize_encrypted_client_proof_bundles_v1',
        bundles: forwarded.ecdsa.strictResult.response.bundles,
      },
    });
    const activated = await activateStrictEcdsaFamilyRegistration({
      relayerUrl: args.relayerUrl,
      route: args.route,
      publicFacts: verified.publicFacts,
    });
    const finalized = await args.context.signingEngine.finalizeRouterAbEcdsaRegistrationActivation({
      kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
      ceremonyId,
      relayerKeyId: args.started.prepare.relayerKeyId,
      activationReceipt: activated.ecdsa.activation,
    });
    const clientBootstrap = buildStrictRegistrationClientBootstrap({
      prepare: args.started.prepare,
      verified: verified.clientBootstrap,
    });
    return {
      chainTargets: [firstChainTarget, ...remainingChainTargets],
      clientBootstrap,
      bootstrap: parseWalletRegistrationEcdsaDerivationRespond({
        clientBootstrap,
        serverBootstrap: activated.ecdsa.bootstrap,
        activationEpoch: finalized.publicCapability.activation_epoch,
      }),
      roleLocalMaterial: finalized.roleLocalMaterial,
      clientPublicFacts: finalized.publicFacts,
      publicCapability: finalized.publicCapability,
    };
  } catch (error: unknown) {
    await closeStrictEcdsaRegistrationCeremony({
      context: args.context,
      ceremonyId,
    });
    throw error;
  }
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

function registrationEcdsaFinalizeAuth(auth: RegistrationPersistenceAuth):
  | {
      kind: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    }
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      rpId: string;
      passkeyPrfFirstB64u: string;
    } {
  switch (auth.kind) {
    case 'email_otp':
      return {
        kind: 'email_otp',
        emailOtpAuthContext: auth.emailOtpAuthContext,
      };
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: String(auth.credential.rawId),
        rpId: auth.rpId,
        passkeyPrfFirstB64u: auth.passkeyPrfFirstB64u,
      };
  }
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
      relayerUrl: args.relayerUrl,
      session: args.plan.ecdsa.session,
      walletKeys: [...args.plan.ecdsa.walletKeys],
      diagnostics: new RegistrationEcdsaSessionFinalizeDiagnostics(args.registrationTiming),
      auth: registrationEcdsaFinalizeAuth(args.plan.auth),
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

type RegistrationYaoWorkState =
  | { kind: 'disabled' }
  | {
      kind: 'running';
      result: ReturnType<typeof registerVerifiedPasskeyEd25519YaoV1>;
    }
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
    }
  | { kind: 'failed' }
  | { kind: 'committed' }
  | { kind: 'disposed' };

type ClaimedRegistrationYao =
  | { kind: 'disabled' }
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
      clientPublicKey: string;
    };

class RegistrationYaoWork {
  private state: RegistrationYaoWorkState;

  private constructor(state: RegistrationYaoWorkState) {
    this.state = state;
  }

  static disabled(): RegistrationYaoWork {
    return new RegistrationYaoWork({ kind: 'disabled' });
  }

  static start(
    input: Parameters<typeof registerVerifiedPasskeyEd25519YaoV1>[0],
  ): RegistrationYaoWork {
    return new RegistrationYaoWork({
      kind: 'running',
      result: registerVerifiedPasskeyEd25519YaoV1(input),
    });
  }

  static fromPending(pending: ProductEd25519YaoPendingRegistrationPortV1): RegistrationYaoWork {
    return new RegistrationYaoWork({ kind: 'pending', pending });
  }

  async requirePending(): Promise<ProductEd25519YaoPendingRegistrationPortV1> {
    switch (this.state.kind) {
      case 'running': {
        const result = await this.state.result;
        if (!result.ok) {
          this.state = { kind: 'failed' };
          throw new Error(result.message);
        }
        this.state = { kind: 'pending', pending: result.registration };
        return result.registration;
      }
      case 'pending':
        return this.state.pending;
      case 'disabled':
        throw new Error('Ed25519 Yao work was not requested');
      case 'failed':
        throw new Error('Ed25519 Yao registration failed');
      case 'committed':
        throw new Error('Ed25519 Yao registration is already committed');
      case 'disposed':
        throw new Error('Ed25519 Yao registration is disposed');
      default:
        return assertNever(this.state);
    }
  }

  async commit(
    args: Parameters<ProductEd25519YaoPendingRegistrationPortV1['commit']>[0],
  ): Promise<void> {
    if (this.state.kind !== 'pending') {
      throw new Error('Ed25519 Yao registration must be pending before commit');
    }
    await this.state.pending.commit(args);
    this.state = { kind: 'committed' };
  }

  async commitPasskey(args: {
    activation: Parameters<ProductEd25519YaoPendingRegistrationPortV1['commit']>[0]['activation'];
    walletSessionState: Parameters<
      ProductEd25519YaoPendingRegistrationPortV1['commit']
    >[0]['walletSessionState'];
    rpId: string;
    credentialIdB64u: string;
    passkeyPrfFirstB64u: string;
  }): Promise<void> {
    if (this.state.kind !== 'pending') {
      throw new Error('Ed25519 Yao registration must be pending before passkey commit');
    }
    const pending = this.state.pending;
    const source = pending.localMaterialSource();
    if (source.kind !== 'wasm_activated_client') {
      throw new Error('Passkey Ed25519 registration requires browser WASM Client material');
    }
    await persistPasskeyEd25519YaoLocalMaterialV1({
      store: IndexedDBManager,
      activeClient: source.activeClient,
      walletSessionState: args.walletSessionState,
      rpId: args.rpId,
      credentialIdB64u: args.credentialIdB64u,
      passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
    });
    try {
      await pending.commit({
        activation: args.activation,
        walletSessionState: args.walletSessionState,
      });
      this.state = { kind: 'committed' };
    } catch (error: unknown) {
      await deletePasskeyEd25519YaoLocalMaterialV1({
        store: IndexedDBManager,
        walletSessionState: args.walletSessionState,
        rpId: args.rpId,
        credentialIdB64u: args.credentialIdB64u,
      });
      throw error;
    }
  }

  async dispose(): Promise<void> {
    switch (this.state.kind) {
      case 'running': {
        try {
          const result = await this.state.result;
          if (result.ok) await result.registration.dispose();
        } catch {}
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
      case 'disposed':
        return;
      default:
        return assertNever(this.state);
    }
  }
}

async function commitPendingPasskeyEd25519YaoRegistration(args: {
  pending: ProductEd25519YaoPendingRegistrationPortV1;
  activation: Parameters<ProductEd25519YaoPendingRegistrationPortV1['commit']>[0]['activation'];
  walletSessionState: Parameters<
    ProductEd25519YaoPendingRegistrationPortV1['commit']
  >[0]['walletSessionState'];
  rpId: string;
  credentialIdB64u: string;
  passkeyPrfFirstB64u: string;
}): Promise<void> {
  const source = args.pending.localMaterialSource();
  if (source.kind !== 'wasm_activated_client') {
    throw new Error('Passkey Ed25519 registration requires browser WASM Client material');
  }
  await persistPasskeyEd25519YaoLocalMaterialV1({
    store: IndexedDBManager,
    activeClient: source.activeClient,
    walletSessionState: args.walletSessionState,
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
    passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
  });
  try {
    await args.pending.commit({
      activation: args.activation,
      walletSessionState: args.walletSessionState,
    });
  } catch (error: unknown) {
    await deletePasskeyEd25519YaoLocalMaterialV1({
      store: IndexedDBManager,
      walletSessionState: args.walletSessionState,
      rpId: args.rpId,
      credentialIdB64u: args.credentialIdB64u,
    });
    throw error;
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

function startMixedRegistrationYaoWork(args: {
  intent: ReturnType<typeof requirePasskeyRegistrationIntent>;
  intentResponse: WalletRegistrationIntentResponse;
  passkeyAuthority: Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>>;
  started: Extract<WalletRegistrationStartResponse, { kind: 'near_ed25519_and_evm_family_ecdsa' }>;
  relayerUrl: string;
}): RegistrationYaoWork {
  return RegistrationYaoWork.start({
    kind: 'verified_passkey_ed25519_yao_registration_input_v1',
    verifiedIntent: {
      kind: 'verified_passkey_registration_intent_v1',
      intent: args.intent,
      registrationIntentDigestB64u: args.intentResponse.registrationIntentDigestB64u,
      registrationIntentGrant: args.intentResponse.registrationIntentGrant,
      registrationCeremonyId: args.started.registrationCeremonyId,
    },
    verifiedAuthority: {
      kind: 'verified_passkey_registration_authority_v1',
      walletId: args.intent.walletId,
      registrationIntentDigestB64u: args.intentResponse.registrationIntentDigestB64u,
      credentialIdB64u: String(
        args.passkeyAuthority.credential.rawId || args.passkeyAuthority.credential.id || '',
      ).trim(),
      ownedPasskeyPrfFirst: base64UrlDecode(args.passkeyAuthority.prfFirstB64u),
    },
    admissionRequest: args.started.ed25519.admissionRequest,
    httpTransport: {
      kind: 'passkey_ed25519_yao_http_transport_v1',
      routerOrigin: new URL(args.relayerUrl).origin,
      fetch: globalThis.fetch,
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

async function startEmailOtpRegistrationYaoWork(args: {
  context: RegistrationWebContext;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  started: Extract<
    WalletRegistrationStartResponse,
    { kind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa' }
  >;
  walletId: string;
  providerSubject: string;
  registrationAuthorityId: string;
  registrationIntentGrant: string;
  relayerUrl: string;
}): Promise<RegistrationYaoWork> {
  const material = await requireEmailOtpRegistrationEnrollmentMaterial({
    material: args.enrollmentMaterial,
    operation: 'Ed25519 Yao activation',
  });
  const pending = await startEmailOtpEd25519YaoWorkerRegistrationV1({
    kind: 'verified_email_otp_ed25519_yao_registration_worker_input_v1',
    workerContext: args.context.signingEngine.getSignerWorkerContext(),
    pendingFactorHandle: requireEmailOtpEd25519YaoPendingFactorHandle(material),
    admissionRequest: args.started.ed25519.admissionRequest,
    walletId: args.walletId,
    providerSubject: args.providerSubject,
    registrationAuthorityId: args.registrationAuthorityId,
    registrationIntentGrant: args.registrationIntentGrant,
    routerOrigin: args.relayerUrl,
  });
  return RegistrationYaoWork.fromPending(pending);
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

async function finalizeEcdsaOrMixedRegistration(args: {
  relayerUrl: string;
  registrationCeremonyId: string;
  headers: Record<string, string> | undefined;
  idempotencyKey: RegistrationFinalizeIdempotencyKey;
  expectedKeyHandles: string[];
  claimedYao: ClaimedRegistrationYao;
  emailOtpEnrollment: WalletRegistrationEmailOtpEnrollmentMaterial | null;
  emailOtpBackupAck: WalletRegistrationEmailOtpBackupAck | null;
}): Promise<WalletRegistrationFinalizeResponse> {
  const optionalEmailMaterial = {
    ...(args.emailOtpEnrollment ? { emailOtpEnrollment: args.emailOtpEnrollment } : {}),
    ...(args.emailOtpBackupAck ? { emailOtpBackupAck: args.emailOtpBackupAck } : {}),
  };
  switch (args.claimedYao.kind) {
    case 'disabled':
      return await finalizeWalletRegistration({
        relayerUrl: args.relayerUrl,
        registrationCeremonyId: args.registrationCeremonyId,
        headers: args.headers,
        idempotencyKey: args.idempotencyKey,
        kind: 'evm_family_ecdsa',
        ecdsa: { expectedKeyHandles: args.expectedKeyHandles },
        ...optionalEmailMaterial,
      });
    case 'pending':
      return await finalizeWalletRegistration({
        relayerUrl: args.relayerUrl,
        registrationCeremonyId: args.registrationCeremonyId,
        headers: args.headers,
        idempotencyKey: args.idempotencyKey,
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ed25519: { activationReference: args.claimedYao.pending.activationReference() },
        ecdsa: { expectedKeyHandles: args.expectedKeyHandles },
        ...optionalEmailMaterial,
      });
    default:
      return assertNever(args.claimedYao);
  }
}

async function persistAndActivateMixedRegistration(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  registrationTiming: RegistrationTimingRecorder;
  persistencePlan: RegistrationPersistencePlan;
  finalized: Extract<
    WalletRegistrationFinalizeResponse,
    { kind: 'near_ed25519_and_evm_family_ecdsa' }
  >;
  claimedYao: Extract<ClaimedRegistrationYao, { kind: 'pending' }>;
  yaoWork: RegistrationYaoWork;
  passkeyAuthority: Awaited<ReturnType<typeof collectPasskeyRegistrationAuthority>> | null;
}): Promise<RegistrationResult> {
  assertMixedRegistrationSharedSigningBudget({
    walletId: args.persistencePlan.walletId,
    ed25519Session: args.finalized.ed25519.session,
    ecdsa: args.persistencePlan.ecdsa,
  });
  const localEcdsaWalletKeys = await finalizeRegistrationEcdsaSessions({
    context: args.context,
    relayerUrl: args.relayerUrl,
    registrationTiming: args.registrationTiming,
    plan: args.persistencePlan,
  });
  const persistenceStartedAt = performance.now();
  let record: ThresholdEd25519SessionRecord;
  let stored: { signerSlot: number; storedSigners: readonly unknown[] };
  const session = args.finalized.ed25519.session;
  switch (args.persistencePlan.auth.kind) {
    case 'passkey': {
      if (!args.passkeyAuthority) {
        throw new Error('Mixed passkey registration is missing its verified authority');
      }
      const finalizedPasskey = requireEd25519YaoRegistrationPublicResultMatches({
        clientPublicKey: args.claimedYao.clientPublicKey,
        finalized: args.finalized,
        expectedRpId: args.persistencePlan.auth.rpId,
        expectedWalletId: args.persistencePlan.walletId,
      });
      stored = await args.context.signingEngine.storeWalletMixedRegistrationData({
        walletId: args.finalized.walletId,
        nearAccountId: toAccountId(args.finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: args.finalized.ed25519.nearEd25519SigningKeyId,
        credential: args.passkeyAuthority.credential,
        credentialPublicKeyB64u: requireFinalizedPasskeyCredentialPublicKeyB64u({
          finalized: args.finalized,
          credential: args.passkeyAuthority.credential,
        }),
        signerSlot: args.finalized.ed25519.signerSlot,
        operationalPublicKey: args.claimedYao.clientPublicKey,
        relayerKeyId: args.finalized.ed25519.relayerKeyId,
        keyVersion: args.finalized.ed25519.keyVersion,
        participantIds: [...args.finalized.ed25519.participantIds],
        walletKeys: localEcdsaWalletKeys,
      });
      record = persistWarmSessionEd25519Capability({
        kind: 'jwt_passkey',
        walletId: args.finalized.walletId,
        nearAccountId: toAccountId(args.finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: args.finalized.ed25519.nearEd25519SigningKeyId,
        rpId: finalizedPasskey.rpId,
        relayerUrl: args.relayerUrl,
        relayerKeyId: args.finalized.ed25519.relayerKeyId,
        runtimePolicyScope: session.runtimePolicyScope,
        participantIds: session.participantIds,
        signerSlot: args.finalized.ed25519.signerSlot,
        routerAbNormalSigning: session.routerAbNormalSigning,
        sessionId: session.thresholdSessionId,
        signingGrantId: session.signingGrantId,
        expiresAtMs: session.expiresAtMs,
        remainingUses: session.remainingUses,
        jwt: session.walletSessionJwt,
        passkeyCredentialIdB64u: finalizedPasskey.credentialIdB64u,
        source: 'registration',
      });
      break;
    }
    case 'email_otp': {
      requireEmailOtpEd25519YaoRegistrationPublicResultMatches({
        clientPublicKey: args.claimedYao.clientPublicKey,
        finalized: args.finalized,
        expectedRegistrationAuthorityId: args.persistencePlan.auth.registrationAuthorityId,
        expectedWalletId: args.persistencePlan.walletId,
      });
      stored = await args.context.signingEngine.storeWalletEmailOtpMixedRegistrationData({
        walletId: args.finalized.walletId,
        nearAccountId: toAccountId(args.finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: args.finalized.ed25519.nearEd25519SigningKeyId,
        email: args.persistencePlan.auth.email,
        registrationAuthorityId: args.persistencePlan.auth.registrationAuthorityId,
        signerSlot: args.finalized.ed25519.signerSlot,
        operationalPublicKey: args.claimedYao.clientPublicKey,
        relayerKeyId: args.finalized.ed25519.relayerKeyId,
        keyVersion: args.finalized.ed25519.keyVersion,
        participantIds: [...args.finalized.ed25519.participantIds],
        walletKeys: localEcdsaWalletKeys,
      });
      record = persistWarmSessionEd25519Capability({
        kind: 'jwt_email_otp',
        walletId: args.finalized.walletId,
        nearAccountId: toAccountId(args.finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: args.finalized.ed25519.nearEd25519SigningKeyId,
        rpId: args.context.signingEngine.getRpId(),
        relayerUrl: args.relayerUrl,
        relayerKeyId: args.finalized.ed25519.relayerKeyId,
        runtimePolicyScope: session.runtimePolicyScope,
        participantIds: session.participantIds,
        signerSlot: args.finalized.ed25519.signerSlot,
        routerAbNormalSigning: session.routerAbNormalSigning,
        sessionId: session.thresholdSessionId,
        signingGrantId: session.signingGrantId,
        expiresAtMs: session.expiresAtMs,
        remainingUses: session.remainingUses,
        jwt: session.walletSessionJwt,
        emailOtpAuthContext: args.persistencePlan.auth.emailOtpAuthContext,
        source: 'email_otp',
      });
      break;
    }
    default:
      return assertNever(args.persistencePlan.auth);
  }
  args.registrationTiming.record(
    'ecdsaRegistrationLocalRecordPersistenceMs',
    roundDurationMs(persistenceStartedAt),
  );
  if (
    stored.signerSlot !== args.finalized.ed25519.signerSlot ||
    stored.storedSigners.length !== args.persistencePlan.ecdsa.walletKeys.length
  ) {
    throw new Error('Mixed wallet registration persisted an incomplete signer set');
  }
  await args.context.signingEngine.activateAuthenticatedWalletState({
    walletId: args.finalized.walletId,
    nearAccountId: toAccountId(args.finalized.ed25519.nearAccountId),
    signerSlot: args.finalized.ed25519.signerSlot,
    nearClient: args.context.nearClient,
  });
  const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
  if (!walletSessionState) {
    throw new Error('Mixed wallet registration produced an unusable Ed25519 session');
  }
  if (args.persistencePlan.auth.kind === 'passkey') {
    if (!args.passkeyAuthority) {
      throw new Error('Mixed passkey registration lost its verified authority');
    }
    await persistPasskeyEd25519YaoSessionForRefresh({
      persistence: args.context.signingEngine,
      session: walletSessionState,
      prfFirstB64u: args.passkeyAuthority.prfFirstB64u,
    });
  }
  if (args.persistencePlan.auth.kind === 'passkey') {
    if (!args.passkeyAuthority) {
      throw new Error('Mixed passkey registration lost its verified authority');
    }
    await args.yaoWork.commitPasskey({
      activation: args.context.signingEngine,
      walletSessionState,
      rpId: args.context.signingEngine.getRpId(),
      credentialIdB64u: String(
        args.passkeyAuthority.credential.rawId || args.passkeyAuthority.credential.id || '',
      ).trim(),
      passkeyPrfFirstB64u: args.passkeyAuthority.prfFirstB64u,
    });
  } else {
    await args.yaoWork.commit({
      activation: args.context.signingEngine,
      walletSessionState,
    });
  }
  if (args.persistencePlan.auth.kind === 'email_otp') {
    await args.context.signingEngine.persistEmailOtpEd25519YaoSessionForRefreshInternal(record);
  }
  const primaryKey = args.persistencePlan.ecdsa.walletKeys[0];
  return {
    success: true,
    kind: 'near_ed25519_and_ecdsa_wallet_registered',
    walletId: args.finalized.walletId,
    accountProvisioning: args.finalized.accountProvisioning,
    resolvedAccount: args.finalized.resolvedAccount,
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
      args.finalized.ed25519.nearEd25519SigningKeyId,
    ),
    operationalPublicKey: args.claimedYao.clientPublicKey,
    nearAccountId: toAccountId(args.finalized.ed25519.nearAccountId),
    transactionId:
      args.finalized.resolvedAccount.kind === 'sponsored_named_account'
        ? args.finalized.resolvedAccount.transactionHash
        : null,
    thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
    thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
  };
}

async function registerEcdsaOrMixedWallet(
  args: RegisterEcdsaOrMixedWalletArgs,
): Promise<RegistrationResult> {
  const { context, wallet, signerSelection } = args;
  const options = args.options || {};
  const { onEvent, onError, afterCall } = options;
  const startedAt = performance.now();
  const registrationTiming = new RegistrationTimingRecorder(startedAt);
  const initialEventAccountId = registrationEventAccountId(
    wallet.kind === 'provided' ? String(wallet.walletId) : 'wallet-registration',
  );
  let activeIntent: ActiveWalletRegistrationIntent | null = null;
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
    const prepared =
      args.authMethod.kind === 'passkey'
        ? await resolvePasskeyRegistrationReady({
            context,
            authMethod: args.authMethod,
            wallet,
            signerSelection,
            recorder: registrationTiming,
          })
        : await startWalletRegistrationPrecomputeReady({
            context,
            authMethod: args.authMethod,
            wallet,
            signerSelection,
            recorder: registrationTiming,
          });
    if (args.authMethod.kind === 'email_otp') {
      await waitForRegistrationWarmup({
        recorder: registrationTiming,
        warmup: prepared.registrationWarmup,
      });
    }
    const { relayerUrl, intentResponse } = prepared;
    activeIntent = activeWalletRegistrationIntentFromReady(prepared);

    const walletId = intentResponse.intent.walletId;
    const eventAccountId = registrationEventAccountId(String(walletId));
    let emailOtpEnrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null = null;
    let emailOtpRegistrationAuthorityId = '';
    let emailOtpEmail = '';
    let emailOtpProviderSubject = '';
    let emailOtpAppSessionBinding: EmailOtpAppSessionBinding | null = null;
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
        }),
      );
      registrationTiming.capturePasskeyAuthDiagnostics(passkeyAuthority.diagnostics);
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
    const started = requireEcdsaEnabledRegistrationStart(args, startedCeremony);
    if (args.kind === 'near_ed25519_and_evm_family_ecdsa') {
      if (started.kind !== 'near_ed25519_and_evm_family_ecdsa') {
        throw new Error('Mixed wallet registration start is missing Ed25519 Yao material');
      }
      if (args.authMethod.kind === 'passkey') {
        if (!passkeyAuthority) {
          throw new Error('Mixed passkey registration is missing its verified authority');
        }
        yaoWork = startMixedRegistrationYaoWork({
          intent: requirePasskeyRegistrationIntent(intentResponse.intent),
          intentResponse,
          passkeyAuthority,
          started,
          relayerUrl,
        });
      } else {
        yaoWork = await startEmailOtpRegistrationYaoWork({
          context,
          enrollmentMaterial: emailOtpEnrollmentMaterial,
          started,
          walletId: String(walletId),
          providerSubject: emailOtpProviderSubject,
          registrationAuthorityId: emailOtpRegistrationAuthorityId,
          registrationIntentGrant: String(intentResponse.registrationIntentGrant),
          relayerUrl,
        });
      }
    }
    const startedEcdsa = started.ecdsa;
    const ecdsaSession = await registrationTiming.measure(
      'walletRegisterDerivationRespondMs',
      runStrictEcdsaFamilyCeremony.bind(undefined, {
        context,
        relayerUrl,
        route: {
          kind: 'registration',
          registrationCeremonyId: startedCeremony.registrationCeremonyId,
        },
        started: startedEcdsa,
      }),
    );
    const emailOtpEnrollmentMaterialForFinalize =
      args.authMethod.kind === 'email_otp'
        ? await requireEmailOtpRegistrationEnrollmentMaterial({
            material: emailOtpEnrollmentMaterial,
            operation: 'finalize',
          })
        : null;
    const emailOtpEnrollment = emailOtpEnrollmentMaterialForFinalize?.emailOtpEnrollment ?? null;
    const emailOtpBackupAck =
      (await resolveEmailOtpBackupAck({
        authMethod: args.authMethod,
        backup: emailOtpRecoveryCodeBackup,
      })) ?? null;
    const claimedYao = await claimRegistrationYao(args.kind, yaoWork);
    const finalized = await registrationTiming.measure(
      'walletRegisterFinalizeMs',
      finalizeEcdsaOrMixedRegistration.bind(undefined, {
        relayerUrl,
        registrationCeremonyId: startedCeremony.registrationCeremonyId,
        headers: registrationRouteDiagnosticsHeaders(),
        idempotencyKey: finalizeIdempotencyKey,
        expectedKeyHandles: registrationEcdsaExpectedKeyHandles(ecdsaSession),
        claimedYao,
        emailOtpEnrollment,
        emailOtpBackupAck,
      }),
    );
    if (finalized.kind !== args.kind) {
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
    logRegistrationProgress('finalize_response_received', {
      walletId: finalized.walletId,
      ecdsaWalletKeyCount: finalized.ecdsa.walletKeys.length,
    });
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
    let result: RegistrationResult;
    switch (finalized.kind) {
      case 'evm_family_ecdsa': {
        if (claimedYao.kind !== 'disabled') {
          throw new Error('ECDSA-only registration unexpectedly claimed Ed25519 Yao state');
        }
        await commitRegistrationPersistencePlan({
          context,
          relayerUrl,
          registrationTiming,
          plan: persistencePlan,
        });
        const primaryKey = persistencePlan.ecdsa.walletKeys[0];
        result = {
          success: true,
          kind: 'ecdsa_wallet_registered',
          walletId: finalized.walletId,
          thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
          thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
        };
        break;
      }
      case 'near_ed25519_and_evm_family_ecdsa': {
        if (claimedYao.kind !== 'pending') {
          throw new Error('Mixed registration is missing claimed Ed25519 Yao state');
        }
        result = await persistAndActivateMixedRegistration({
          context,
          relayerUrl,
          registrationTiming,
          persistencePlan,
          finalized,
          claimedYao,
          yaoWork,
          passkeyAuthority,
        });
        break;
      }
      default:
        result = assertNever(finalized);
    }
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
    await yaoWork.dispose();
    await cancelActiveWalletRegistrationIntent(activeIntent);
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
  let activeIntent: ActiveWalletRegistrationIntent | null = null;
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
    const prepared = await startWalletRegistrationPrecomputeReady({
      context,
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      recorder: registrationTiming,
    });
    await waitForRegistrationWarmup({
      recorder: registrationTiming,
      warmup: prepared.registrationWarmup,
    });
    activeIntent = activeWalletRegistrationIntentFromReady(prepared);
    const { relayerUrl, intentResponse } = prepared;
    const walletId = intentResponse.intent.walletId;
    const eventAccountId = registrationEventAccountId(String(walletId));
    const emailAuthority = await registrationTiming.measure(
      'authProofMs',
      collectEmailOtpRegistrationAuthority.bind(undefined, {
        authMethod: args.authMethod,
        relayUrl: relayerUrl,
        walletId: String(walletId),
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
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
    const started = await registrationTiming.measure(
      'walletRegisterStartMs',
      startWalletRegistration.bind(undefined, {
        relayerUrl,
        registrationIntentGrant: intentResponse.registrationIntentGrant,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        intent: intentResponse.intent,
        headers: registrationRouteDiagnosticsHeaders(),
        kind: 'email_otp',
        emailOtpRegistrationProof: emailAuthority.proof,
      }),
    );
    registrationTiming.captureRouteDiagnostics(started.registrationDiagnostics);
    if (started.kind !== 'near_ed25519') {
      throw new Error('Wallet registration start returned a different signer branch');
    }
    yaoWork = await startEmailOtpRegistrationYaoWork({
      context,
      enrollmentMaterial,
      started,
      walletId: String(walletId),
      providerSubject: emailAuthority.providerSubject,
      registrationAuthorityId: emailAuthority.registrationAuthorityId,
      registrationIntentGrant: String(intentResponse.registrationIntentGrant),
      relayerUrl,
    });
    const pending = await yaoWork.requirePending();
    const clientPublicKey = pending.publicKey();
    const materialForFinalize = await requireEmailOtpRegistrationEnrollmentMaterial({
      material: enrollmentMaterial,
      operation: 'finalize',
    });
    const emailOtpBackupAck = await resolveEmailOtpBackupAck({
      authMethod: args.authMethod,
      backup: recoveryCodeBackup,
    });
    const finalized = await registrationTiming.measure(
      'walletRegisterFinalizeMs',
      finalizeWalletRegistration.bind(undefined, {
        relayerUrl,
        registrationCeremonyId: started.registrationCeremonyId,
        headers: registrationRouteDiagnosticsHeaders(),
        idempotencyKey: finalizeIdempotencyKey,
        kind: 'near_ed25519',
        ed25519: { activationReference: pending.activationReference() },
        emailOtpEnrollment: materialForFinalize.emailOtpEnrollment,
        ...(emailOtpBackupAck ? { emailOtpBackupAck } : {}),
      }),
    );
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
    const session = finalized.ed25519.session;
    const record = persistWarmSessionEd25519Capability({
      kind: 'jwt_email_otp',
      walletId: finalized.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
      rpId: context.signingEngine.getRpId(),
      relayerUrl,
      relayerKeyId: finalized.ed25519.relayerKeyId,
      runtimePolicyScope: session.runtimePolicyScope,
      participantIds: session.participantIds,
      signerSlot: finalized.ed25519.signerSlot,
      routerAbNormalSigning: session.routerAbNormalSigning,
      sessionId: session.thresholdSessionId,
      signingGrantId: session.signingGrantId,
      expiresAtMs: session.expiresAtMs,
      remainingUses: session.remainingUses,
      jwt: session.walletSessionJwt,
      emailOtpAuthContext: persistenceAuth.emailOtpAuthContext,
      source: 'email_otp',
    });
    await context.signingEngine.activateAuthenticatedWalletState({
      walletId: finalized.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      signerSlot: finalized.ed25519.signerSlot,
      nearClient: context.nearClient,
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
    if (!walletSessionState) {
      throw new Error('Ed25519 Yao registration produced an unusable wallet session');
    }
    await yaoWork.commit({ activation: context.signingEngine, walletSessionState });
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
      kind: 'near_wallet_registered',
      walletId: finalized.walletId,
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
    };
    emitRegistrationTimingSummary(
      createSucceededRegistrationTimingSummary({
        recorder: registrationTiming,
        authMethod: 'email_otp',
        signerSet: registrationTimingSignerSetFromPlan(args.signerPlan),
      }),
    );
    options.afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    await yaoWork.dispose();
    await cancelActiveWalletRegistrationIntent(activeIntent);
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
  let activeIntent: ActiveWalletRegistrationIntent | null = null;
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
    const prepared = await resolvePasskeyRegistrationReady({
      context,
      authMethod: args.authMethod,
      wallet: args.wallet,
      signerSelection: args.signerSelection,
      recorder: registrationTiming,
    });
    const { relayerUrl, intentResponse } = prepared;
    const intent = requirePasskeyRegistrationIntent(intentResponse.intent);
    activeIntent = activeWalletRegistrationIntentFromReady(prepared);
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
      registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
      options,
      confirmationConfigOverride: {
        uiMode: 'modal',
        behavior: 'requireClick',
        ...(args.confirmationConfigOverride ?? options.confirmationConfig ?? {}),
      },
    });
    emitRegistrationEvent(options.onEvent, eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED,
      status: 'succeeded',
      interaction: { kind: 'passkey_create', overlay: 'hide' },
    });
    const started = await startWalletRegistration({
      relayerUrl,
      registrationIntentGrant: intentResponse.registrationIntentGrant,
      registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
      intent,
      headers: registrationRouteDiagnosticsHeaders(),
      kind: 'passkey',
      webauthnRegistration: passkeyAuthority.webauthnRegistration,
    });
    if (started.kind !== 'near_ed25519') {
      throw new Error('Wallet registration start returned a different signer branch');
    }
    const yao = await registerVerifiedPasskeyEd25519YaoV1({
      kind: 'verified_passkey_ed25519_yao_registration_input_v1',
      verifiedIntent: {
        kind: 'verified_passkey_registration_intent_v1',
        intent,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        registrationIntentGrant: intentResponse.registrationIntentGrant,
        registrationCeremonyId: started.registrationCeremonyId,
      },
      verifiedAuthority: {
        kind: 'verified_passkey_registration_authority_v1',
        walletId: intent.walletId,
        registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
        credentialIdB64u: String(
          passkeyAuthority.credential.rawId || passkeyAuthority.credential.id || '',
        ).trim(),
        ownedPasskeyPrfFirst: base64UrlDecode(passkeyAuthority.prfFirstB64u),
      },
      admissionRequest: started.ed25519.admissionRequest,
      httpTransport: {
        kind: 'passkey_ed25519_yao_http_transport_v1',
        routerOrigin: new URL(relayerUrl).origin,
        fetch: globalThis.fetch,
      },
    });
    if (!yao.ok) throw new Error(yao.message);
    const pending = yao.registration;
    try {
      const clientPublicKey = pending.publicKey();
      const finalized = await finalizeWalletRegistration({
        relayerUrl,
        registrationCeremonyId: started.registrationCeremonyId,
        headers: registrationRouteDiagnosticsHeaders(),
        idempotencyKey: finalizeIdempotencyKey,
        kind: 'near_ed25519',
        ed25519: { activationReference: pending.activationReference() },
      });
      if (finalized.kind !== 'near_ed25519') {
        throw new Error('Wallet registration finalize returned a different signer branch');
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
      const session = finalized.ed25519.session;
      const record = persistWarmSessionEd25519Capability({
        kind: 'jwt_passkey',
        walletId: finalized.walletId,
        nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        rpId: finalizedPasskey.rpId,
        relayerUrl,
        relayerKeyId: finalized.ed25519.relayerKeyId,
        runtimePolicyScope: session.runtimePolicyScope,
        participantIds: session.participantIds,
        signerSlot: finalized.ed25519.signerSlot,
        routerAbNormalSigning: session.routerAbNormalSigning,
        sessionId: session.thresholdSessionId,
        signingGrantId: session.signingGrantId,
        expiresAtMs: session.expiresAtMs,
        remainingUses: session.remainingUses,
        jwt: session.walletSessionJwt,
        passkeyCredentialIdB64u: finalizedPasskey.credentialIdB64u,
        source: 'registration',
      });
      const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
      if (!walletSessionState) {
        throw new Error('Ed25519 Yao registration produced an unusable wallet session');
      }
      await persistPasskeyEd25519YaoSessionForRefresh({
        persistence: context.signingEngine,
        session: walletSessionState,
        prfFirstB64u: passkeyAuthority.prfFirstB64u,
      });
      await commitPendingPasskeyEd25519YaoRegistration({
        pending,
        activation: context.signingEngine,
        walletSessionState,
        rpId: finalizedPasskey.rpId,
        credentialIdB64u: finalizedPasskey.credentialIdB64u,
        passkeyPrfFirstB64u: passkeyAuthority.prfFirstB64u,
      });
      emitRegistrationEvent(options.onEvent, eventAccountId, {
        authMethod: 'passkey',
        phase: RegistrationEventPhase.STEP_11_COMPLETED,
        status: 'succeeded',
      });
      const result: RegistrationResult = {
        success: true,
        kind: 'near_wallet_registered',
        walletId: finalized.walletId,
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
      };
      options.afterCall?.(true, result);
      return result;
    } catch (error) {
      pending.dispose();
      throw error;
    }
  } catch (error) {
    await cancelActiveWalletRegistrationIntent(activeIntent);
    const errorCode = registrationErrorCodeFromUnknown(error);
    const message = getUserFriendlyErrorMessage(error, 'registration', initialEventAccountId);
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

export async function registerWallet(
  args: RegisterWalletOperationInput,
): Promise<RegistrationResult> {
  try {
    return await registerWalletInternal({
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
  const session = signer.session;
  const expectedNearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(
    args.clientPublicKey,
  );
  const expectedPolicy = normalizeRuntimePolicyScope(args.started.intent.runtimePolicyScope);
  const actualPolicy = normalizeRuntimePolicyScope(session.runtimePolicyScope);
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
    session.walletId !== args.walletId ||
    session.nearAccountId !== signer.nearAccountId ||
    session.nearEd25519SigningKeyId !== signer.nearEd25519SigningKeyId ||
    session.thresholdSessionId !== admission.scope.wallet_session_id ||
    session.signingRootId !== admission.application_binding.signing_root_id ||
    session.signingRootVersion !== admission.scope.root_share_epoch ||
    session.authorityScope.kind !== 'passkey_rp' ||
    session.authorityScope.rpId !== args.rpId ||
    session.routerAbNormalSigning.signingWorkerId !== admission.scope.signing_worker_id ||
    !sameParticipantIds(session.participantIds, requested.participantIds) ||
    !sameRuntimePolicyScope(actualPolicy, expectedPolicy)
  ) {
    throw new Error('Wallet add-signer finalize returned mismatched Ed25519 Yao identity');
  }
  return finalized;
}

function clearAddSignerSessionRecord(record: ThresholdEd25519SessionRecord): void {
  const key = thresholdEd25519SessionRecordKeyFromRecord(record);
  if (!key) throw new Error('Wallet add-signer could not identify its persisted session record');
  const cleared = clearStoredThresholdEd25519SessionRecordForLaneKey(key);
  if (!cleared.ok) throw new Error(cleared.message);
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
  let persistedSession: ThresholdEd25519SessionRecord | null = null;
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
      credential: input.credential,
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
    const session = finalized.ed25519.session;
    persistedSession = persistWarmSessionEd25519Capability({
      kind: 'jwt_passkey',
      walletId: finalized.walletId,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
      nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
      rpId: input.rpId,
      relayerUrl: input.relayerUrl,
      relayerKeyId: finalized.ed25519.relayerKeyId,
      runtimePolicyScope: session.runtimePolicyScope,
      participantIds: session.participantIds,
      signerSlot: finalized.ed25519.signerSlot,
      routerAbNormalSigning: session.routerAbNormalSigning,
      sessionId: session.thresholdSessionId,
      signingGrantId: session.signingGrantId,
      expiresAtMs: session.expiresAtMs,
      remainingUses: session.remainingUses,
      jwt: session.walletSessionJwt,
      passkeyCredentialIdB64u: input.credentialIdB64u,
      source: 'add-signer',
    });
    const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(persistedSession);
    if (!walletSessionState) {
      throw new Error('Wallet add-signer produced an unusable Ed25519 Wallet Session');
    }
    await persistPasskeyEd25519YaoSessionForRefresh({
      persistence: input.context.signingEngine,
      session: walletSessionState,
      prfFirstB64u: input.passkeyPrfFirstB64u,
    });
    await commitPendingPasskeyEd25519YaoRegistration({
      pending,
      activation: input.context.signingEngine,
      walletSessionState,
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      passkeyPrfFirstB64u: input.passkeyPrfFirstB64u,
    });
    pending = null;
    persistedSession = null;
    persistedSignerRollbackReceipt = null;
    emitAddSignerEventSafely(input.onEvent, input.eventAccountId, {
      authMethod: 'passkey',
      phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED,
      status: 'succeeded',
    });
    return {
      success: true,
      kind: 'near_ed25519_signer_added',
      walletId: finalized.walletId,
      nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
        finalized.ed25519.nearEd25519SigningKeyId,
      ),
      operationalPublicKey: clientPublicKey,
      nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
    };
  } catch (error: unknown) {
    pending?.dispose();
    const cleanupErrors: string[] = [];
    if (persistedSession) {
      try {
        clearAddSignerSessionRecord(persistedSession);
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
  const session = await runStrictEcdsaFamilyCeremony({
    context: input.context,
    relayerUrl: input.relayerUrl,
    route: {
      kind: 'add_signer',
      walletId: input.walletId,
      addSignerCeremonyId: input.started.addSignerCeremonyId,
    },
    started: input.started.ecdsa,
  });
  const finalized = await finalizeWalletAddSigner({
    relayerUrl: input.relayerUrl,
    walletId: input.walletId,
    addSignerCeremonyId: input.started.addSignerCeremonyId,
    idempotencyKey: createRegistrationOperationIdempotencyKey('wallet-add-signer-finalize'),
    kind: 'evm_family_ecdsa',
    ecdsa: { expectedKeyHandles: [session.bootstrap.keyHandle] },
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
  emitAddSignerEventSafely(input.onEvent, input.eventAccountId, {
    authMethod: 'passkey',
    phase: RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED,
    status: 'running',
  });
  const localEcdsaWalletKeys =
    await input.context.signingEngine.finalizeWalletRegistrationEcdsaSessions({
      walletId: toWalletId(input.walletId),
      relayerUrl: input.relayerUrl,
      session,
      walletKeys: [primaryKey, ...walletKeys.slice(1)],
      auth: {
        kind: 'passkey',
        credentialIdB64u: input.credentialIdB64u,
        rpId: input.rpId,
        passkeyPrfFirstB64u: input.passkeyPrfFirstB64u,
      },
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
    kind: 'ecdsa_signer_added',
    walletId: input.walletId,
    thresholdEcdsaEthereumAddress: primaryKey.thresholdOwnerAddress,
    thresholdEcdsaPublicKeyB64u: primaryKey.thresholdEcdsaPublicKeyB64u,
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
    const managedGrant = await createManagedRegistrationFlowGrant({
      context,
      identity: { kind: 'wallet', walletId: String(walletId) },
      authority: { kind: 'passkey_rp', rpId },
    });
    const intentResponse = await createWalletAddSignerIntent({
      relayerUrl,
      walletId,
      request: { walletId, rpId, signerSelection },
      headers: { Authorization: `Bearer ${managedGrant.token}` },
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
