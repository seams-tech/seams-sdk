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
import {
  buildThresholdWarmSessionRequestEnvelope,
  buildThresholdEd25519RegistrationHssClientOwnedArtifact,
  completeRegisteredThresholdEd25519Registration,
  createThresholdWarmSessionPolicyDraft,
  prewarmThresholdEd25519ClientBaseFromCredential,
  prepareThresholdEd25519RegistrationHssClientMaterial,
  prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst,
  prepareThresholdEd25519RegistrationHssClientRequest,
  persistRegisteredThresholdEd25519Session,
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
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
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
  respondWalletAddSignerHss,
  respondWalletRegistrationHss,
  startWalletAddSigner,
  startWalletRegistration,
  type WalletRegistrationEmailOtpBackupAck,
  type WalletRegistrationRouteDiagnostics,
  type WalletRegistrationRouteTimingName,
} from '@/core/rpcClients/relayer/walletRegistration';
import { buildNearWalletRegistrationSignerSelection } from '@/SeamsWeb/operations/registration/registrationSignerSelection';
import { collectPasskeyRegistrationAuthority } from '@/SeamsWeb/operations/authMethods/passkey/registrationAuthority';
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
import { assertWalletRuntimePostconditions } from '@/core/signingEngine/session/postconditions/runtimePostconditions';

// Registration forces a visible, clickable confirmation for cross-origin safety.

type EmitRegistrationEventInput = Omit<CreateRegistrationFlowEventInput, 'accountId' | 'flowId'>;

type RegistrationTimingAuthMethod = RegistrationAuthMethodInput['kind'];
type RegistrationTimingSignerMode = RegistrationSignerSelection['mode'];

type RegistrationTimingBucketValues = {
  inputValidationMs: number;
  managedRegistrationGrantMs: number;
  registrationIntentMs: number;
  registrationIntentDigestMs: number;
  authProofMs: number;
  emailOtpEnrollmentMaterialMs: number;
  ed25519ClientMaterialMs: number;
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

type PasskeyRegistrationAuthTiming = {
  kind: 'passkey';
  authProofMs: number;
  emailOtpEnrollmentMaterialMs: 0;
  emailOtpRecoveryCodeBackupMs: 0;
};

type EmailOtpRegistrationAuthTiming = {
  kind: 'email_otp';
  authProofMs: number;
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

type RegistrationEcdsaTiming =
  | EcdsaEnabledRegistrationTiming
  | EcdsaDisabledRegistrationTiming;

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
    case 'registrationAuthorityVerifyMs':
    case 'registrationHssPrepareMs':
    case 'registrationHssServerInputDeriveMs':
    case 'registrationHssServerSessionPrepareTotalMs':
    case 'registrationHssPrepareSessionMs':
    case 'registrationHssPrepareExtractDriverStatesMs':
    case 'registrationHssPrepareClientOfferMessageMs':
    case 'registrationHssPrepareCachePreparedSessionMs':
    case 'registrationHssPrepareEncodeStatesMs':
    case 'registrationEcdsaPrepareMs':
    case 'registrationCeremonyPersistMs':
    case 'registerStartTotalMs':
    case 'registrationHssRespondMs':
    case 'registrationHssRespondDecodeMessagesMs':
    case 'registrationHssRespondMaterializeSessionMs':
    case 'registrationHssRespondPrepareDeliveryMs':
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
    managedRegistrationGrantMs: 0,
    registrationIntentMs: 0,
    registrationIntentDigestMs: 0,
    authProofMs: 0,
    emailOtpEnrollmentMaterialMs: 0,
    ed25519ClientMaterialMs: 0,
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
    managedRegistrationGrantMs: buckets.managedRegistrationGrantMs,
    registrationIntentMs: buckets.registrationIntentMs,
    registrationIntentDigestMs: buckets.registrationIntentDigestMs,
    authProofMs: buckets.authProofMs,
    emailOtpEnrollmentMaterialMs: buckets.emailOtpEnrollmentMaterialMs,
    ed25519ClientMaterialMs: buckets.ed25519ClientMaterialMs,
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
        emailOtpEnrollmentMaterialMs: 0,
        emailOtpRecoveryCodeBackupMs: 0,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        authProofMs: input.buckets.authProofMs,
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
        thresholdEd25519SessionPersistenceMs:
          input.buckets.thresholdEd25519SessionPersistenceMs,
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
    managedRegistrationGrantMs: buckets.managedRegistrationGrantMs,
    registrationIntentMs: buckets.registrationIntentMs,
    registrationIntentDigestMs: buckets.registrationIntentDigestMs,
    authProofMs: buckets.authProofMs,
    emailOtpEnrollmentMaterialMs: buckets.emailOtpEnrollmentMaterialMs,
    ed25519ClientMaterialMs: buckets.ed25519ClientMaterialMs,
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

  captureRouteDiagnostics(value: unknown): void {
    const sanitized = sanitizeWalletRegistrationRouteDiagnostics(value);
    if (sanitized) this.relayDiagnostics.push(sanitized);
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
  console.info('[Registration] wallet timing summary', summary);
}

function registrationRouteDiagnosticsHeaders(): Record<string, string> | undefined {
  const globalFlag = (
    globalThis as {
      __SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS?: unknown;
    }
  ).__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS;
  return globalFlag === true
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
    error:
      'Wallet registration was already finalized. Restore or unlock the wallet to continue.',
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

async function assertImmediateRegistrationSigningLanes(args: {
  signingEngine: RegistrationSigningSurface;
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  expectEd25519: boolean;
  expectedEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
}): Promise<void> {
  await assertWalletRuntimePostconditions({
    source: 'registration_finalize',
    walletId: args.walletId,
    authMethod: args.authMethod,
    requiredTargets: [
      ...(args.expectEd25519 ? [{ curve: 'ed25519' as const }] : []),
      ...args.expectedEcdsaChainTargets.map((chainTarget) => ({
        curve: 'ecdsa' as const,
        chainTarget,
      })),
    ],
    readPersistedAvailableSigningLanes: async (input) =>
      await args.signingEngine.readPersistedAvailableSigningLanes(input),
  });
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
    let emailOtpEnrollmentMaterial: EmailOtpRegistrationEnrollmentMaterial | null = null;
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
        collectPasskeyRegistrationAuthority({
          context,
          walletId: String(walletId),
          signerSlot: 1,
          registrationIntentDigestB64u: intentResponse.registrationIntentDigestB64u,
          options,
          confirmationConfigOverride: confirmationConfig,
        }),
      );
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
      emailOtpEnrollmentMaterial = enrollment;
      emailOtpRegistrationAuthorityId = emailAuthority.registrationAuthorityId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
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
    const emailOtpBackupAck =
      args.authMethod.kind === 'email_otp' && emailOtpEnrollmentMaterial
        ? emailOtpBackupAckFromStoredBackup({
            authMethod: args.authMethod,
            backedUpEnrollment: await registrationTiming.measure(
              'emailOtpRecoveryCodeBackupMs',
              () =>
                backupEmailOtpRecoveryCodes({
                  relayUrl: relayerUrl,
                  walletId: String(intentResponse.intent.walletId),
                  appSessionJwt: args.authMethod.appSessionJwt,
                  enrollment: googleEmailOtpRegistrationMaterialToBackupEnrollment({
                    material: emailOtpEnrollmentMaterial,
                    registrationAuthorityId: emailOtpRegistrationAuthorityId,
                  }),
                }),
            ),
          })
        : undefined;
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

export async function registerWallet(args: {
  context: RegistrationWebContext;
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  options: RegistrationHooksOptions;
  authenticatorOptions: AuthenticatorOptions;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<RegistrationResult> {
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

    const relayerUrl = String(context.configs.network.relayer.url || '').trim();
    if (!relayerUrl) {
      throw new Error('registerWallet requires relayer.url');
    }
    const finalizeIdempotencyKey = googleEmailOtpFinalizeIdempotencyKey(args.authMethod);

    const managedGrant = await registrationTiming.measure('managedRegistrationGrantMs', () =>
      createManagedRegistrationFlowGrant({
        context,
        nearAccountId: String(nearAccountId),
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
    const signingRootId = signingRootScopeFromRuntimePolicyScope(
      thresholdRuntimePolicyScope,
    ).signingRootId;
    if (!signingRootId) {
      throw new Error('Registration intent is missing signing root scope');
    }

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
    let emailOtpEnrollmentMaterial: EmailOtpRegistrationEnrollmentMaterial | null = null;
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
        }),
      );
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
      ed25519PrfFirstB64u = enrollment.thresholdEd25519PrfFirstB64u;
      emailOtpClientRootShareHandle = enrollment.clientRootShareHandle;
      emailOtpEnrollment = enrollment.emailOtpEnrollment;
      emailOtpEnrollmentMaterial = enrollment;
      emailOtpRegistrationAuthorityId = emailAuthority.registrationAuthorityId;
      emailOtpEmail = emailAuthority.email;
      emailOtpProviderSubject = emailAuthority.providerSubject;
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
              signingRootId,
              nearAccountId,
              keyPurpose: ed25519Selection.keyPurpose,
              keyVersion: ed25519Selection.keyVersion,
              participantIds: ed25519Selection.participantIds,
              derivationVersion: ed25519Selection.derivationVersion,
            })
          : await prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst({
              context,
              prfFirstB64u: ed25519PrfFirstB64u,
              signingRootId,
              nearAccountId,
              keyPurpose: ed25519Selection.keyPurpose,
              keyVersion: ed25519Selection.keyVersion,
              participantIds: ed25519Selection.participantIds,
              derivationVersion: ed25519Selection.derivationVersion,
            }),
    );
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

    const ed25519ClientRequestPromise = registrationTiming.measure(
      'ed25519ClientRequestMs',
      () =>
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
    const evaluationResult = await registrationTiming.measure(
      'ed25519EvaluationArtifactMs',
      () =>
        buildThresholdEd25519RegistrationHssClientOwnedArtifact({
          context,
          preparedSession: startedEd25519.preparedSession,
          clientRequest,
          serverInputDelivery: respondedEd25519,
          clientOutputMaskB64u,
        }),
    );

    const requestedPolicy = createThresholdWarmSessionPolicyDraft(context, {
      participantIds: hssClientMaterial.hssContext.participantIds,
    });
    if (!requestedPolicy) {
      throw new Error('Threshold warm-session defaults are disabled for registration');
    }
    const emailOtpBackupAck =
      args.authMethod.kind === 'email_otp' && emailOtpEnrollmentMaterial
        ? emailOtpBackupAckFromStoredBackup({
            authMethod: args.authMethod,
            backedUpEnrollment: await registrationTiming.measure(
              'emailOtpRecoveryCodeBackupMs',
              () =>
                backupEmailOtpRecoveryCodes({
                  relayUrl: relayerUrl,
                  walletId: String(intentResponse.intent.walletId),
                  appSessionJwt: args.authMethod.appSessionJwt,
                  enrollment: googleEmailOtpRegistrationMaterialToBackupEnrollment({
                    material: emailOtpEnrollmentMaterial,
                    registrationAuthorityId: emailOtpRegistrationAuthorityId,
                  }),
                }),
            ),
          })
        : undefined;
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

    if (passkeyAuthority) {
      void prewarmThresholdEd25519ClientBaseFromCredential({
        context,
        credential: passkeyAuthority.credential,
        nearAccountId,
        signerSlot,
      }).catch(() => undefined);
    }

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
      const signingRootId = signingRootScopeFromRuntimePolicyScope(
        thresholdRuntimePolicyScope,
      ).signingRootId;
      if (!signingRootId) {
        throw new Error('Add-signer intent is missing signing root scope');
      }
      const nearAccountId = toAccountId(signerSelection.ed25519.nearAccountId);
      const hssClientMaterial = await prepareThresholdEd25519RegistrationHssClientMaterial({
        context,
        credential: webauthnAuthentication,
        signingRootId,
        nearAccountId,
        keyPurpose: signerSelection.ed25519.keyPurpose,
        keyVersion: signerSelection.ed25519.keyVersion,
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
