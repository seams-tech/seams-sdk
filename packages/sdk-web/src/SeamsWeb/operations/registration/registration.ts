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
import type {
  CreateRegistrationFlowEventInput,
  RegistrationFlowEvent,
  RegistrationHooksOptions,
  WalletRecoveryCodeBackupHandlerV1,
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
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import type { JoinedWalletCustodyNearEd25519KeySetV1 } from '@/SeamsWeb/signingSurface/ports';
import type { WorkerResourceWarmupDiagnostics } from '@/core/signingEngine/assembly/warmup';
import type { EmailOtpYaoPrewarmOutcome } from '@/core/signingEngine/workerManager/workerTypes';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import { getUserFriendlyErrorMessage } from '@shared/utils/errors';
import { alphabetizeStringify, sha256BytesUtf8, sha256HexUtf8 } from '@shared/utils/digests';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
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
import type {
  AddSignerSelection,
  RegistrationAuthMethodInput,
  RegistrationEvmFamilyEcdsaSignerPlan,
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
import { base58Encode } from '@shared/utils/base58';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { buildEmailOtpEnvelopeFactor, buildPasskeyEnvelopeFactor } from '@shared/passkey-custody';
import { WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND } from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { joinCustodyJsonFromEstablishedCommitPayload } from '@/core/signingEngine/walletCustody/registrationCeremony';
import {
  toParticipantId,
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
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { computeAddSignerIntentDigest } from '@/utils/intentDigest';
import type { EmailOtpRegistrationProof } from '@shared/utils/registrationIntent';
import {
  setupWalletRegistration,
  createWalletAddSignerIntent,
  finalizeWalletAddSigner,
  isEmailOtpWalletRegistrationFinalizeResponse,
  parseWalletRegistrationEcdsaDerivationRespond,
  activateWalletRegistration,
  completeWalletRegistrationNearProvisioning,
  respondWalletRegistration,
  startWalletAddSigner,
  type WalletRegistrationActivateResponseV2,
  type WalletRegistrationSetupResponseV2,
  type WalletRegistrationRespondEd25519DeferredWork,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEmailOtpEnrollmentMaterial,
  type WalletRegistrationEmailOtpBackupAck,
  type WalletRegistrationFinalizeResponse,
  type WalletRegistrationEcdsaPreparePayload,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationStartResponse,
  type WalletAddSignerFinalizeResponse,
  type WalletAddSignerStartResponse,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  collectPasskeyRegistrationAuthority,
  collectPasskeyRegistrationAuthorityFromCredential,
} from '@/SeamsWeb/operations/authMethods/passkey/registrationAuthority';
import { backupEmailOtpRecoveryCodes } from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import { showWalletRecoveryCodeBackupUi } from '@/SeamsWeb/operations/recovery/walletRecoveryCodeBackup';
import type { GoogleEmailOtpRegistrationBackupEnrollmentInput } from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import type { RegistrationFinalizeIdempotencyKey } from '@/SeamsWeb/publicApi/types';
import { registrationFinalizeIdempotencyKeyFromString } from '@/SeamsWeb/publicApi/types';
import { collectEmailOtpRegistrationAuthority } from '@/SeamsWeb/operations/authMethods/emailOtp/registrationAuthority';
import type { PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult as EmailOtpRegistrationEnrollmentMaterial } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import { requirePasskeyPrfFirstB64u } from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import { rememberWalletOriginAppSession } from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProvider,
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildEmailOtpWalletAuthAuthority,
  isEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpProvider,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { parseCanonicalEcdsaServerActivationRequest } from '@shared/utils/ecdsaCapabilityActivation';
import { registerVerifiedPasskeyEd25519YaoAddSignerV1 } from '@/core/signingEngine/flows/registration/services/passkeyEd25519YaoAddSigner';
import type { ProductEd25519YaoPendingRegistrationPortV1 } from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import { deletePasskeyEd25519YaoSignerMaterialV1 } from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { nearEd25519YaoMaterialActivationFromMetadata } from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { nearEd25519YaoOperationMaterialFacts } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';
import { toAccountId } from '@/core/types/accountIds';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { persistActiveWalletSessionAuthorizationFromRegistration } from '@/core/signingEngine/session/persistence/walletSessionAuthorizationProjection';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import {
  emailOtpAppSessionBindingFromJwt,
  type EmailOtpAppSessionBinding,
} from '@/core/signingEngine/session/emailOtp/appSessionJwtCache';
import {
  createRouterAbTraceContextV1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import {
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  RegistrationTimingRecorder,
  RegistrationWarmupDiagnostics,
  assertNever,
  createFailedRegistrationTimingSummary,
  createSucceededRegistrationTimingSummary,
  emitRegistrationTimingSpan,
  emitRegistrationTimingSummary,
  recordStrictEcdsaServerTimingBuckets,
  registrationTimingSignerSetFromPlan,
  roundDurationMs,
  zeroEmailOtpYaoPrewarmDiagnostics,
} from './registrationTiming';
import {
  RegistrationEcdsaSession,
  RegistrationLocalEcdsaWalletKeys,
  assertRegistrationEcdsaSessionMatchesWalletKeys,
  assertRegistrationWalletKeyCapabilities,
  assertSharedRegistrationEvmFamilyWalletKeyMaterial,
  buildRegistrationPasskeyEcdsaWarmSessions,
  buildStrictRegistrationClientBootstrap,
  closeStrictEcdsaRegistrationCeremony,
  finalizeStrictEcdsaFamilyLocalActivation,
  measureStrictEcdsaCeremonyStep,
  persistRegistrationPasskeyEcdsaWarmSessions,
  registrationChainTargetListsMatch,
  registrationRouteHeaders,
  runStrictEcdsaFamilyCeremony,
} from './registrationStrictEcdsa';
import {
  RegistrationPasskeyAuthority,
  buildRegistrationEmailOtpEd25519SessionState,
  passkeyWalletAuthAuthorityFromCredential,
  persistPasskeyRegistrationEd25519Material,
  persistRegistrationPasskeyEd25519SealedRuntime,
  registrationEd25519MaterialFacts,
  registrationEstablishedEd25519Session,
  requireDeferredNearWork,
  requireEd25519YaoRegistrationPublicResultMatches,
  requireEmailOtpEd25519YaoRegistrationPublicResultMatches,
  requireEmailOtpRegistrationEnrollmentMaterial,
  requirePasskeyRegistrationIntent,
} from './registrationEd25519Yao';
// Re-exported so this module's public surface is unchanged by the move.
export {
  REGISTRATION_TIMING_LABEL,
  WALLET_IFRAME_TRANSPORT_TIMING_LABEL,
  emitRegistrationTimingSpan,
  isRegistrationBenchmarkDiagnosticsEnabled,
  parseYaoServerTimingBuckets,
  recordStrictEcdsaServerTimingBuckets,
} from './registrationTiming';

// Registration forces a visible, clickable confirmation for cross-origin safety.

function requireWebAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function confirmWalletRecoveryCodesBackedUp(
  walletId: string,
  handler: WalletRecoveryCodeBackupHandlerV1 | undefined,
  recoveryCodes: readonly string[],
): Promise<void> {
  if (recoveryCodes.length !== 10 || new Set(recoveryCodes).size !== 10) {
    throw new Error('Wallet custody must issue exactly ten distinct recovery codes');
  }
  const request = {
    kind: 'wallet_recovery_code_backup_request_v1' as const,
    walletId,
    recoveryCodes,
  };
  const acknowledgement = handler
    ? await handler(request)
    : await showWalletRecoveryCodeBackupUi(request);
  if (acknowledgement?.kind !== 'wallet_recovery_codes_backed_up_v1') {
    throw new Error('Wallet recovery-code backup was not acknowledged');
  }
}

function zeroizeArrayBuffer(buffer: ArrayBuffer): void {
  if (buffer.byteLength > 0) new Uint8Array(buffer).fill(0);
}

type EmitRegistrationEventInput = Omit<
  CreateRegistrationFlowEventInput,
  'accountId' | 'flowId' | 'authMethod'
> & {
  authMethod: WalletFlowAuthMethod;
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

type EvmFamilyEcdsaRegistrationBranch = RegistrationEvmFamilyEcdsaSignerPlan;

function registrationSignerPlanFromSignerSet(
  selection: RegistrationSignerSetSelection,
): RegistrationSignerPlan {
  const plan = registrationSignerPlanFromSelection(selection);
  if (!plan.ok) {
    throw new Error(plan.message);
  }
  return plan.value;
}

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
    const warmup = await awaitHostedPasskeyRegistrationStage({
      operation: setup.registrationWarmup,
      cancellation: args.cancellation,
    });
    if (warmup.kind === 'failed') throw warmup.error;
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

function logRegistrationProgress(stage: string, details?: Record<string, unknown>): void {
  console.info('[Registration] progress', {
    stage,
    ...(details || {}),
  });
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
  clientSecret32: Uint8Array;
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
      clientSecret32: input.clientSecret32,
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
  clientSecret32: Uint8Array;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  if (input.authMethod.kind !== 'email_otp') {
    throw new Error('Email OTP enrollment material requires Email OTP auth');
  }
  try {
    const material =
      await input.context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
        relayUrl: input.relayerUrl,
        walletId: toWalletId(input.walletId),
        userId: input.providerSubject,
        appSessionJwt: input.appSessionJwt,
        ed25519YaoFactor: input.ed25519YaoFactor,
        clientSecret32: input.clientSecret32,
      });
    assertEmailOtpRegistrationHasNoLegacyEcdsaRoot(material);
    return material;
  } finally {
    input.clientSecret32.fill(0);
  }
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

export type RegistrationPersistenceAuth =
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
  | {
      kind: 'passkey';
      webauthnRegistration: unknown;
      walletCustodyFactorJson: string;
      walletCustodyFactorSecret: ArrayBuffer;
    }
  | {
      kind: 'email_otp';
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      walletCustodyFactorSecret: ArrayBuffer;
    };

async function buildThreeRouteCanonicalActivationCommand(args: {
  registrationCeremonyId: string;
  activationCorrelationId: CorrelationId;
  idempotencyKey: string;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
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

async function persistThreeRouteCanonicalActivation(args: {
  context: RegistrationWebContext;
  ceremonyId: string;
  materialAuthority: WalletAuthAuthorityRef;
  ecdsaPrepare: WalletRegistrationEcdsaPreparePayload;
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  activationCorrelationId: CorrelationId;
  activationCommand: Awaited<ReturnType<typeof buildThreeRouteCanonicalActivationCommand>>;
  clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
}) {
  const planInput = {
    authority: args.materialAuthority,
    targetMemberships: args.chainTargets,
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      args.ecdsaPrepare.prepare.evmFamilySigningKeySlotId,
      'registration ECDSA signing key slot',
    ),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(args.ecdsaPrepare.prepare.ecdsaThresholdKeyId),
    signingRootId: parseSdkEcdsaDerivationSigningRootId(args.ecdsaPrepare.prepare.signingRootId),
    signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
      args.ecdsaPrepare.prepare.signingRootVersion,
    ),
    runtimePolicyScope: args.ecdsaPrepare.prepare.runtimePolicyScope,
    clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
      args.clientActivation.derivationClientSharePublicKey33B64u,
    ),
    participantIds: [
      toParticipantId(args.ecdsaPrepare.prepare.participantIds[0]),
      toParticipantId(args.ecdsaPrepare.prepare.participantIds[1]),
    ] as const,
    relayerKeyId: parseEcdsaRelayerKeyId(args.ecdsaPrepare.prepare.relayerKeyId),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(args.clientActivation.contextBinding32B64u),
    journalId: args.activationCorrelationId,
    requestDigest: args.activationCommand.requestDigest,
    canonicalRequest: args.activationCommand.canonicalRequest,
    createdAt: parseIsoTimestamp(new Date().toISOString()),
  };
  const persisted = await args.context.signingEngine.persistInitialCanonicalEcdsaActivation({
    kind: 'persist_initial_canonical_ecdsa_activation_v1',
    bootstrapOwner: 'wallet_custody',
    clientActivation: args.clientActivation,
    ceremonyId: args.ceremonyId,
    planInput,
  });
  if (!persisted.ok) {
    throw new Error(
      `Canonical ECDSA activation persistence failed (${persisted.code}): ${persisted.message}`,
    );
  }
  return persisted;
}

function ethereumAddressFromAddress20B64u(value: string): `0x${string}` {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) throw new Error('ECDSA activation address must contain 20 bytes');
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
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
    walletCustodyFactorJson: string | null;
  }>;
  traceContext?: RouterAbTraceContextV1;
  registrationTiming: RegistrationTimingRecorder | null;
  confirmRecoveryCodesBackedUp: (recoveryCodes: readonly string[]) => Promise<void>;
  startDeferredNearCustody: (input: {
    deferredNear: WalletRegistrationRespondEd25519DeferredWork;
    establishedEvmCustodyCommit: Awaited<
      ReturnType<RegistrationWebContext['signingEngine']['establishWalletCustodyEvmFamilyKeySet']>
    >['commitPayload'];
  }) => Promise<JoinedWalletCustodyNearEd25519KeySetV1>;
}): Promise<{
  session: RegistrationEcdsaSession;
  activated: WalletRegistrationActivateResponseV2;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork | null;
  /** Returned so the deferred NEAR commit reuses it instead of resolving twice. */
  activateEmailOtp: {
    enrollment: WalletRegistrationEmailOtpEnrollmentMaterial | null;
    backupAck: WalletRegistrationEmailOtpBackupAck | null;
  };
  walletCustody: Awaited<
    ReturnType<RegistrationWebContext['signingEngine']['establishWalletCustodyEvmFamilyKeySet']>
  >;
  deferredNearCustodyWork: Promise<JoinedWalletCustodyNearEd25519KeySetV1> | null;
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
        ...(args.authority.kind === 'passkey'
          ? {
              kind: 'passkey' as const,
              webauthnRegistration: args.authority.webauthnRegistration,
            }
          : {
              kind: 'email_otp' as const,
              emailOtpRegistrationProof: args.authority.emailOtpRegistrationProof,
            }),
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
    const deferredNear =
      responded.kind === 'near_ed25519_and_evm_family_ecdsa' ? responded.ed25519 : null;
    let deferredNearCustodyWork: Promise<JoinedWalletCustodyNearEd25519KeySetV1> | null = null;

    const verified = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientProofVerifyMs',
      operation: args.context.signingEngine.verifyRouterAbEcdsaRegistrationClientProofs.bind(
        args.context.signingEngine,
        {
          kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1',
          bootstrapOwner: 'wallet_custody',
          ceremonyId,
          clientProofFinalization: {
            kind: 'finalize_encrypted_client_proof_bundles_v1',
            bundles: responded.ecdsa.strictResult.response.bundles,
          },
        },
      ),
    });
    const activateEmailOtp = await args.resolveActivateEmailOtp();
    const chainTargets = [firstChainTarget, ...remainingChainTargets] as const;
    if (verified.bootstrapOwner !== 'wallet_custody') {
      throw new Error('ECDSA registration verification returned a legacy PRF bootstrap');
    }
    const walletCustodyFactorJson =
      args.authority.kind === 'passkey'
        ? args.authority.walletCustodyFactorJson
        : activateEmailOtp.walletCustodyFactorJson;
    if (!walletCustodyFactorJson) {
      throw new Error('ECDSA registration has no wallet custody factor binding');
    }
    const walletCustodyFactorSecret = args.authority.walletCustodyFactorSecret;
    const activationHolder: {
      value?: Extract<WalletRegistrationActivateResponseV2, { ok: true; kind: 'evm_family_ecdsa' }>;
      journalId?: CorrelationId;
    } = {};
    const established = await args.context.signingEngine.establishWalletCustodyEvmFamilyKeySet({
      walletId: args.ecdsaPrepare.prepare.walletId,
      factorJson: walletCustodyFactorJson,
      factorSecret: walletCustodyFactorSecret,
      evmFamilySigningKeySlotId: args.ecdsaPrepare.prepare.evmFamilySigningKeySlotId,
      applicationBindingDigestB64u: verified.applicationBindingDigestB64u,
      confirmRecoveryCodesBackedUp: args.confirmRecoveryCodesBackedUp,
      runRelayerRound: async (bootstrap) => {
        if (deferredNear) {
          deferredNearCustodyWork = args.startDeferredNearCustody({
            deferredNear,
            establishedEvmCustodyCommit: bootstrap.preActivationCommitPayload,
          });
        }
        const clientActivation = parseRouterAbEcdsaVerifiedClientActivationFactsV1({
          registrationRequestDigestB64u: verified.registrationRequestDigestB64u,
          proofTranscriptDigestB64u: verified.proofTranscriptDigestB64u,
          contextBinding32B64u: bootstrap.contextBinding32B64u,
          derivationClientSharePublicKey33B64u: bootstrap.clientSharePublicKey33B64u,
          clientShareRetryCounter: bootstrap.clientShareRetryCounter,
          participantId: 1,
        });
        const activationCommand = await buildThreeRouteCanonicalActivationCommand({
          registrationCeremonyId: ceremonyId,
          activationCorrelationId,
          idempotencyKey: args.idempotencyKey,
          publicFacts: clientActivation,
        });
        const persisted = await persistThreeRouteCanonicalActivation({
          context: args.context,
          ceremonyId,
          materialAuthority: args.materialAuthority,
          ecdsaPrepare: args.ecdsaPrepare,
          chainTargets,
          activationCorrelationId,
          activationCommand,
          clientActivation,
        });
        const response = await measureStrictEcdsaCeremonyStep({
          registrationTiming: args.registrationTiming,
          bucket: 'ecdsaRegistrationGatewayActivateMs',
          operation: activateWalletRegistration.bind(undefined, {
            relayerUrl: args.relayerUrl,
            headers: registrationRouteHeaders(args.traceContext),
            registrationCeremonyId: ceremonyId,
            signerPlanKind: args.signerPlanKind,
            signedSetup: args.signedSetup,
            idempotencyKey: args.idempotencyKey,
            ecdsa: {
              clientActivation,
              activationCorrelationId,
              activationRequestDigestB64u: activationCommand.requestDigest,
            },
            walletCustodyCommit: bootstrap.preActivationCommitPayload,
            ...(activateEmailOtp.enrollment
              ? { emailOtpEnrollment: activateEmailOtp.enrollment }
              : {}),
            ...(activateEmailOtp.backupAck
              ? { emailOtpBackupAck: activateEmailOtp.backupAck }
              : {}),
            onServerTiming: (header) =>
              recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'activate', header),
          }),
        });
        if (response.kind !== 'evm_family_ecdsa' || !response.ecdsa) {
          throw new Error('ECDSA registration ceremony received a non-ECDSA activate result');
        }
        activationHolder.value = response;
        activationHolder.journalId = persisted.journalId;
        const identity = response.ecdsa.activation.ecdsa_activation.public_identity;
        return JSON.stringify({
          relayerKeyId: args.ecdsaPrepare.prepare.relayerKeyId,
          relayerPublicKey33B64u: identity.server_public_key33_b64u,
          groupPublicKey33B64u: identity.threshold_public_key33_b64u,
          ethereumAddress: ethereumAddressFromAddress20B64u(identity.ethereum_address20_b64u),
          relayerShareRetryCounter: identity.server_share_retry_counter,
        });
      },
    });
    if (!activationHolder.value || !activationHolder.journalId) {
      throw new Error('Wallet custody ECDSA activation did not return its committed receipt');
    }
    const activated = activationHolder.value;
    if (activated.walletCustody?.status !== 'committed') {
      const status = activated.walletCustody?.status ?? 'not_reported';
      throw new Error(`Wallet custody did not commit during ECDSA activation (${status})`);
    }
    const clientBootstrap = buildStrictRegistrationClientBootstrap({
      prepare: args.ecdsaPrepare.prepare,
      verified: established.clientBootstrap,
    });
    const registrationBootstrap = parseWalletRegistrationEcdsaDerivationRespond({
      clientBootstrap,
      serverBootstrap: activated.ecdsa.bootstrap,
      activationEpoch: activated.ecdsa.activation.ecdsa_activation.activation_epoch,
    });
    const finalized = await args.context.signingEngine.finalizeRouterAbEcdsaRegistrationActivation({
      kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
      bootstrapOwner: 'wallet_custody',
      journalId: activationHolder.journalId,
      activationReceipt: activated.ecdsa.activation,
      routerAbEcdsaDerivationNormalSigning:
        registrationBootstrap.routerAbEcdsaDerivationNormalSigning,
      readyStateBlobB64u: established.localMaterial.readyStateBlobB64u,
      walletCustodyPublicFacts: established.localMaterial.publicFacts,
    });

    if (activated.authMethod.kind === 'passkey') {
      rememberPasskeyAppSessionForRegisteredWallet({
        appSessionJwt: activated.appSessionJwt,
        relayerUrl: args.relayerUrl,
        walletId: activated.walletId,
      });
    }
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
      activateEmailOtp: {
        enrollment: activateEmailOtp.enrollment,
        backupAck: activateEmailOtp.backupAck,
      },
      walletCustody: established,
      deferredNearCustodyWork,
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

export type RegisterEcdsaOrMixedWalletArgs = RegisterEcdsaOrMixedWalletBaseArgs &
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

function startDeferredNearWalletCustody(
  base: {
    context: RegistrationWebContext;
    factorSecretOwner: { value: ArrayBuffer | null };
    registrationCeremonyId: string;
    relayerUrl: string;
    signedSetup: string;
    traceContext: RouterAbTraceContextV1;
  },
  input: {
    deferredNear: WalletRegistrationRespondEd25519DeferredWork;
    establishedEvmCustodyCommit: Awaited<
      ReturnType<RegistrationWebContext['signingEngine']['establishWalletCustodyEvmFamilyKeySet']>
    >['commitPayload'];
  },
): Promise<JoinedWalletCustodyNearEd25519KeySetV1> {
  const factorSecret = base.factorSecretOwner.value;
  if (!factorSecret) {
    throw new Error('Mixed registration has no NEAR custody factor secret');
  }
  base.factorSecretOwner.value = null;
  const admission = input.deferredNear.admissionRequest;
  return base.context.signingEngine
    .joinWalletCustodyNearEd25519KeySet({
      custodyJson: joinCustodyJsonFromEstablishedCommitPayload(input.establishedEvmCustodyCommit),
      factorSecret,
      nearEd25519SigningKeyId: admission.application_binding.near_ed25519_signing_key_id,
      registrationCeremonyId: base.registrationCeremonyId,
      admissionRequest: admission,
      admissionReceipt: input.deferredNear.admissionReceipt,
      participantIds: admission.participant_ids,
      routerOrigin: new URL(base.relayerUrl).origin,
      authorization: `Bearer ${base.signedSetup}`,
      traceContext: base.traceContext,
    })
    .finally(zeroizeArrayBuffer.bind(undefined, factorSecret));
}

function requireDeferredNearCustodyWork(
  work: Promise<JoinedWalletCustodyNearEd25519KeySetV1> | null,
): Promise<JoinedWalletCustodyNearEd25519KeySetV1> {
  if (!work) throw new Error('Mixed registration did not start its NEAR custody join');
  return work;
}

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
  nearCustodyWork: Promise<JoinedWalletCustodyNearEd25519KeySetV1>;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  plan: RegistrationPersistencePlan;
  walletId: WalletId;
  authMaterial: DeferredRegistrationFinalizeAuthMaterial;
}): Promise<NearProvisioningState> {
  const auth = args.plan.auth;
  try {
    const joined = await args.nearCustodyWork;
    const clientPublicKey = `ed25519:${base58Encode(joined.metadata.registeredPublicKey)}`;
    const activationReference = joined.activationReference;
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
      walletCustodyCommit: joined.commitPayload,
    });
    if (!completed.ok) {
      throw new Error('Deferred NEAR provisioning did not complete');
    }
    const finalized = completed;
    if (finalized.kind !== 'near_ed25519') {
      throw new Error('Deferred Ed25519 finalize returned a different signer branch');
    }
    if (finalized.walletCustody?.status !== 'joined') {
      const status = finalized.walletCustody?.status ?? 'not_reported';
      throw new Error(`Deferred NEAR custody join did not commit (${status})`);
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
    const metadata = joined.metadata;
    await args.context.signingEngine.persistWalletCustodyEd25519Material({
      binding: {
        kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        applicationBindingDigestB64u: joined.localMaterial.applicationBindingDigestB64u,
        registeredPublicKeyB64u: base64UrlEncode(metadata.registeredPublicKey),
        participantIds: metadata.participantIds,
        stateEpoch: String(metadata.stateEpoch),
        walletId: String(args.walletId),
        nearAccountId: String(nearAccountId),
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        signerSlot: finalized.ed25519.signerSlot,
        signingWorkerId: metadata.scope.signing_worker_id,
        signingWorkerVerifyingShareB64u: base64UrlEncode(metadata.signingWorkerVerifyingShare),
      },
      sealed: {
        ciphertextB64u: joined.localMaterial.b64u,
        nonceB64u: joined.localMaterial.nonceB64u,
      },
    });
    await args.context.signingEngine.upsertEd25519YaoPublicCapabilityLaneReference({
      walletId: args.walletId,
      nearAccountId,
      thresholdSessionId: materialFacts.identity.thresholdSessionId,
      runtimePolicyScope: materialFacts.stableServerScope.runtimePolicyScope,
      materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
      auth:
        auth.kind === 'passkey'
          ? {
              kind: 'passkey',
              rpId: toRpId(auth.rpId),
              credentialIdB64u: passkeyCredentialIdB64u,
            }
          : {
              kind: 'email_otp',
              providerSubjectId: emailOtpAuthContextProviderUserId(auth.emailOtpAuthContext),
            },
      nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(
        finalized.ed25519.nearEd25519SigningKeyId,
      ),
      signerSlot: finalized.ed25519.signerSlot,
    });
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
    let emailOtpWalletCustodyFactorSecret: ArrayBuffer | null = null;
    let passkeyAuthority: RegistrationPasskeyAuthority | null = null;
    let startAuthority: RegistrationThreeRouteAuthority;
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
      const custodyCredentialId = parseWebAuthnCredentialIdB64u(
        String(passkeyAuthority.credential.rawId || passkeyAuthority.credential.id || '').trim(),
      );
      if (!custodyCredentialId.ok) {
        throw new Error(`passkey credential id ${custodyCredentialId.error.message}`);
      }
      startAuthority = {
        kind: 'passkey',
        webauthnRegistration: passkeyAuthority.webauthnRegistration,
        walletCustodyFactorJson: JSON.stringify({
          envelopeId: `wallet-custody-envelope:${crypto.randomUUID()}`,
          factor: buildPasskeyEnvelopeFactor({
            rpId: requireWebAuthnRpId(args.authMethod.rpId),
            credentialIdB64u: custodyCredentialId.value,
          }),
        }),
        walletCustodyFactorSecret: base64UrlDecode(passkeyAuthority.prfFirstB64u).buffer,
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
      const emailOtpEnrollmentSecret = crypto.getRandomValues(new Uint8Array(32));
      emailOtpWalletCustodyFactorSecret = emailOtpEnrollmentSecret.slice().buffer;
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
        ed25519YaoFactor: { kind: 'ed25519_yao_factor_not_requested' },
        appSessionJwt: emailOtpAuthMethod.appSessionJwt,
        clientSecret32: emailOtpEnrollmentSecret,
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
        walletCustodyFactorSecret: emailOtpWalletCustodyFactorSecret,
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
    const walletCustodyNearJoinFactorSecretOwner = {
      value:
        args.kind === 'near_ed25519_and_evm_family_ecdsa'
          ? startAuthority.walletCustodyFactorSecret.slice(0)
          : null,
    };
    let ceremony: Awaited<ReturnType<typeof runEcdsaEnabledThreeRouteRegistrationCeremony>>;
    try {
      ceremony = await registrationTiming.measure('ecdsaRegistrationTotalMs', () =>
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
          resolveActivateEmailOtp: async () => {
            let enrollment: WalletRegistrationEmailOtpEnrollmentMaterial | null = null;
            let walletCustodyFactorJson: string | null = null;
            if (args.authMethod.kind === 'email_otp') {
              const material = await requireEmailOtpRegistrationEnrollmentMaterial({
                material: emailOtpEnrollmentMaterial,
                operation: 'activate',
              });
              enrollment = material.emailOtpEnrollment ?? null;
              walletCustodyFactorJson = JSON.stringify({
                envelopeId: `wallet-custody-envelope:${crypto.randomUUID()}`,
                factor: buildEmailOtpEnvelopeFactor({
                  enrollmentId: material.enrollmentId,
                  enrollmentSealKeyVersion: material.enrollmentSealKeyVersion,
                }),
              });
            }
            return {
              enrollment,
              walletCustodyFactorJson,
              backupAck:
                (await resolveEmailOtpBackupAck({
                  authMethod: args.authMethod,
                  backup: emailOtpRecoveryCodeBackup,
                })) ?? null,
            };
          },
          traceContext,
          registrationTiming,
          confirmRecoveryCodesBackedUp: confirmWalletRecoveryCodesBackedUp.bind(
            undefined,
            String(walletId),
            options.backupWalletRecoveryCodes,
          ),
          startDeferredNearCustody: startDeferredNearWalletCustody.bind(undefined, {
            context,
            factorSecretOwner: walletCustodyNearJoinFactorSecretOwner,
            registrationCeremonyId: setup.registrationCeremonyId,
            relayerUrl,
            signedSetup: String(setup.signedSetup),
            traceContext,
          }),
        }),
      );
    } finally {
      zeroizeArrayBuffer(startAuthority.walletCustodyFactorSecret);
      if (walletCustodyNearJoinFactorSecretOwner.value) {
        zeroizeArrayBuffer(walletCustodyNearJoinFactorSecretOwner.value);
        walletCustodyNearJoinFactorSecretOwner.value = null;
      }
    }
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
            nearCustodyWork: requireDeferredNearCustodyWork(ceremony.deferredNearCustodyWork),
            deferredNear: requireDeferredNearWork(ceremony.deferredNear),
            plan: persistencePlan,
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
    const emailOtpEnrollmentSecret = crypto.getRandomValues(new Uint8Array(32));
    const emailOtpWalletCustodyFactorSecret = emailOtpEnrollmentSecret.slice().buffer;
    const enrollmentMaterial = startEmailOtpRegistrationEnrollmentMaterial({
      recorder: registrationTiming,
      context,
      authMethod: args.authMethod,
      relayerUrl,
      walletId: String(walletId),
      providerSubject: emailAuthority.providerSubject,
      ed25519YaoFactor: { kind: 'ed25519_yao_factor_not_requested' },
      appSessionJwt: args.authMethod.appSessionJwt,
      clientSecret32: emailOtpEnrollmentSecret,
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
    const materialForActivate = await requireEmailOtpRegistrationEnrollmentMaterial({
      material: enrollmentMaterial,
      operation: 'activate',
    });
    let established: Awaited<
      ReturnType<RegistrationWebContext['signingEngine']['establishWalletCustodyNearEd25519KeySet']>
    >;
    try {
      established = await context.signingEngine.establishWalletCustodyNearEd25519KeySet({
        walletId: String(walletId),
        factorJson: JSON.stringify({
          envelopeId: `wallet-custody-envelope:${crypto.randomUUID()}`,
          factor: buildEmailOtpEnvelopeFactor({
            enrollmentId: materialForActivate.enrollmentId,
            enrollmentSealKeyVersion: materialForActivate.enrollmentSealKeyVersion,
          }),
        }),
        factorSecret: emailOtpWalletCustodyFactorSecret,
        nearEd25519SigningKeyId:
          responded.ed25519.admissionRequest.application_binding.near_ed25519_signing_key_id,
        registrationCeremonyId: setup.registrationCeremonyId,
        admissionRequest: responded.ed25519.admissionRequest,
        admissionReceipt: responded.ed25519.admissionReceipt,
        participantIds: responded.ed25519.admissionRequest.participant_ids,
        routerOrigin: new URL(relayerUrl).origin,
        authorization: `Bearer ${String(setup.signedSetup)}`,
      });
    } finally {
      zeroizeArrayBuffer(emailOtpWalletCustodyFactorSecret);
    }
    await confirmWalletRecoveryCodesBackedUp(
      String(walletId),
      options.backupWalletRecoveryCodes,
      established.recoveryCodes,
    );
    const emailOtpBackupAck = await resolveEmailOtpBackupAck({
      authMethod: args.authMethod,
      backup: recoveryCodeBackup,
    });
    if (!emailOtpBackupAck) {
      throw new Error('Email OTP registration requires recovery backup acknowledgment');
    }
    /* The custody ceremony and local recovery backup finish before activate.
       Activate stages the wallet as `near_pending`; Route 4 then commits the
       signer, custody envelope, and recovery set together. */
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
    const clientPublicKey = `ed25519:${base58Encode(established.metadata.registeredPublicKey)}`;
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
        ed25519: { activationReference: established.activationReference },
        auth: {
          kind: 'email_otp',
          enrollment: materialForActivate.emailOtpEnrollment,
          backupAck: emailOtpBackupAck,
        },
        walletCustodyCommit: established.commitPayload,
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
    if (finalized.walletCustody?.status !== 'committed') {
      const status = finalized.walletCustody?.status ?? 'not_reported';
      throw new Error(`Wallet custody did not commit (${status})`);
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
    const metadata = established.metadata;
    await context.signingEngine.persistWalletCustodyEd25519Material({
      binding: {
        kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        applicationBindingDigestB64u: established.localMaterial.applicationBindingDigestB64u,
        registeredPublicKeyB64u: base64UrlEncode(metadata.registeredPublicKey),
        participantIds: metadata.participantIds,
        stateEpoch: String(metadata.stateEpoch),
        walletId: String(finalized.walletId),
        nearAccountId: String(finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        signerSlot: finalized.ed25519.signerSlot,
        signingWorkerId: metadata.scope.signing_worker_id,
        signingWorkerVerifyingShareB64u: base64UrlEncode(metadata.signingWorkerVerifyingShare),
      },
      sealed: {
        ciphertextB64u: established.localMaterial.b64u,
        nonceB64u: established.localMaterial.nonceB64u,
      },
    });
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
    /* Refactor 100. The key set is provisioned from the wallet custody seed
       rather than the passkey PRF: the ceremony generates the seed, derives
       this key set's root under it, and seals the seed under the passkey as a
       factor. The passkey is now an unwrap factor, not the root.

       Ed25519-only wallets first, deliberately. A mixed wallet whose NEAR key
       set came from the seed while its EVM key set is still PRF-derived would
       be covered by the recovery set only halfway — recovery would restore
       NEAR and silently miss EVM, the exact failure this refactor exists to
       prevent. */
    const parsedCredentialId = parseWebAuthnCredentialIdB64u(
      String(passkeyAuthority.credential.rawId || passkeyAuthority.credential.id || '').trim(),
    );
    if (!parsedCredentialId.ok) {
      throw new Error(`passkey credential id ${parsedCredentialId.error.message}`);
    }
    const walletCustodyFactorSecret = base64UrlDecode(passkeyAuthority.prfFirstB64u)
      .buffer as ArrayBuffer;
    let established: Awaited<
      ReturnType<RegistrationWebContext['signingEngine']['establishWalletCustodyNearEd25519KeySet']>
    >;
    try {
      established = await context.signingEngine.establishWalletCustodyNearEd25519KeySet({
        walletId: String(intent.walletId),
        factorJson: JSON.stringify({
          envelopeId: `wallet-custody-envelope:${crypto.randomUUID()}`,
          factor: buildPasskeyEnvelopeFactor({
            rpId: requireWebAuthnRpId(args.authMethod.rpId),
            credentialIdB64u: parsedCredentialId.value,
          }),
        }),
        factorSecret: walletCustodyFactorSecret,
        nearEd25519SigningKeyId:
          responded.ed25519.admissionRequest.application_binding.near_ed25519_signing_key_id,
        registrationCeremonyId: setup.registrationCeremonyId,
        admissionRequest: responded.ed25519.admissionRequest,
        admissionReceipt: responded.ed25519.admissionReceipt,
        participantIds: responded.ed25519.admissionRequest.participant_ids,
        routerOrigin: new URL(relayerUrl).origin,
        authorization: `Bearer ${String(setup.signedSetup)}`,
        traceContext,
      });
    } finally {
      zeroizeArrayBuffer(walletCustodyFactorSecret);
    }
    await confirmWalletRecoveryCodesBackedUp(
      String(intent.walletId),
      options.backupWalletRecoveryCodes,
      established.recoveryCodes,
    );
    /* The custody ceremony and local recovery backup finish before activate.
       Activate stages the wallet as `near_pending`; Route 4 then commits the
       signer, custody envelope, and recovery set together. */
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
    const clientPublicKey = `ed25519:${base58Encode(established.metadata.registeredPublicKey)}`;
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
      ed25519: { activationReference: established.activationReference },
      auth: { kind: 'passkey' },
      /* The projection, not the ceremony's output: the continuity cache and
           any role-local material stay on this device. */
      walletCustodyCommit: established.commitPayload,
    });
    if (!finalized.ok || finalized.kind !== 'near_ed25519') {
      throw new Error('Deferred NEAR provisioning returned a different signer branch');
    }
    /* The custody outcome is not advisory. Activation deliberately never
         fails because of custody, so the leg reports it instead — and this run
         showed the user ten recovery codes before sending the payload. Any
         outcome but `committed` means those codes wrap a seed the server did
         not store, so the wallet is not recoverable and must not be reported
         as registered. `not_requested` is included: this path always sends a
         payload, so it would mean the payload never arrived. */
    if (established.commitPayload && finalized.walletCustody?.status !== 'committed') {
      const status = finalized.walletCustody?.status ?? 'not_reported';
      const reason =
        finalized.walletCustody?.status === 'rejected' ? `: ${finalized.walletCustody.reason}` : '';
      throw new Error(
        `Wallet custody did not commit (${status})${reason}. The recovery codes shown are not usable.`,
      );
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
    /* The wallet-scoped continuity cache, sealed by the ceremony under a key
         derived from the custody seed. One record per wallet rather than one
         per factor: a factor enrolled later opens the same envelope and so
         reaches the same cache. Persisted here rather than at establish time
         because the wallet profile it hangs off is created in between. */
    const metadata = established.metadata;
    await context.signingEngine.persistWalletCustodyEd25519Material({
      binding: {
        kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        applicationBindingDigestB64u: established.localMaterial.applicationBindingDigestB64u,
        registeredPublicKeyB64u: base64UrlEncode(metadata.registeredPublicKey),
        participantIds: metadata.participantIds,
        stateEpoch: String(metadata.stateEpoch),
        walletId: String(finalized.walletId),
        nearAccountId: String(finalized.ed25519.nearAccountId),
        nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
        signerSlot: finalized.ed25519.signerSlot,
        signingWorkerId: metadata.scope.signing_worker_id,
        signingWorkerVerifyingShareB64u: base64UrlEncode(metadata.signingWorkerVerifyingShare),
      },
      sealed: {
        ciphertextB64u: established.localMaterial.b64u,
        nonceB64u: established.localMaterial.nonceB64u,
      },
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
    walletId: input.walletId,
    addSignerCeremonyId: input.started.addSignerCeremonyId,
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
