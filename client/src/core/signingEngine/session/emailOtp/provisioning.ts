import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildEd25519SessionPolicy,
  DEFAULT_THRESHOLD_SESSION_POLICY,
  generateThresholdSessionId,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  THRESHOLD_SESSION_POLICY_VERSION,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm,
  deriveThresholdEd25519HssClientOutputMaskWasm,
  deriveThresholdEd25519HssClientInputsWasm,
  prepareThresholdEd25519HssClientRequestWasm,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { ThresholdEd25519HssFinalizedReportEnvelope } from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import {
  completeThresholdEd25519HssClientCeremony,
  runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue,
} from '@/core/signingEngine/threshold/ed25519/hssLifecycle';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/threshold/ed25519/hssClientBase';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  BuildCurrentSealedSessionRecordInput,
  BuildCurrentSealedSessionRecordBaseInput,
  SigningSessionRestoreLeaseHandle,
  SigningSessionSealedRecordFilter,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';
import { attachEd25519SessionToEmailOtpSigningSessionSealBestEffort } from './companionSessions';

type ManagedRegistrationBootstrapGrant = {
  token: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

type RegistrationTransport =
  | { mode: 'managed'; relayerUrl: string; environmentId: string; publishableKey: string }
  | { mode: 'backend_proxy'; bootstrapUrl: string; relayerUrl: string };

export const EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION = 'threshold-ed25519-hss-v1' as const;

export type EmailOtpThresholdEd25519ProvisioningResult = {
  publicKey?: string;
  relayerKeyId: string;
  keyVersion: string;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
  jwt: string;
  xClientBaseB64u?: string;
};

export type EmailOtpEd25519RegistrationFreshIntent = {
  kind: 'registration_ed25519_provisioning';
  registrationAttemptId: string;
  walletSigningSessionId?: never;
  ecdsaThresholdSessionId?: never;
};

export type EmailOtpEd25519RegistrationCompanionProvisioningIntent = {
  kind: 'registration_ed25519_companion_provisioning';
  registrationAttemptId: string;
  walletSigningSessionId: string;
  ecdsaThresholdSessionId: string;
};

export type EmailOtpEd25519RegistrationProvisioningIntent =
  | EmailOtpEd25519RegistrationFreshIntent
  | EmailOtpEd25519RegistrationCompanionProvisioningIntent;

export type EmailOtpEd25519SessionReconstructionKey = {
  relayerKeyId: string;
  keyVersion: string;
  participantIds: number[];
};

export type EmailOtpEd25519SessionReconstructionPlan =
  | {
      kind: 'reconstruct';
      ed25519Key: EmailOtpEd25519SessionReconstructionKey;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
    }
  | {
      kind: 'defer';
      reason: 'missing_runtime_policy_scope';
      ed25519Key: EmailOtpEd25519SessionReconstructionKey;
      runtimePolicyScope?: never;
    }
  | {
      kind: 'defer';
      reason: 'missing_ed25519_key_identity' | 'not_needed_for_ecdsa';
      ed25519Key?: never;
      runtimePolicyScope?: never;
    };

type EmailOtpEd25519CommonArgs = {
  nearAccountId: AccountId | string;
  relayUrl: string;
  rpId: string;
  prfFirstB64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  participantIds?: number[];
  ttlMs?: number;
  remainingUses?: number;
};

export type RegisterEmailOtpEd25519CapabilityArgs = EmailOtpEd25519CommonArgs &
  EmailOtpEd25519RegistrationProvisioningIntent & {
    appSessionJwt?: string;
    routeAuth?: AppOrThresholdSessionAuth;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  };

export type ReconstructEmailOtpEd25519SessionArgs = Omit<
  EmailOtpEd25519CommonArgs,
  'participantIds'
> & {
  kind: 'session_ed25519_reconstruction';
  routeAuth: AppOrThresholdSessionAuth;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  walletSigningSessionId: string;
  ecdsaThresholdSessionId: string;
  ed25519Key: EmailOtpEd25519SessionReconstructionKey;
  registrationAttemptId?: never;
  appSessionJwt?: never;
};

type NormalizedEmailOtpEd25519ProvisioningCommon = {
  nearAccountId: AccountId;
  relayUrl: string;
  rpId: string;
  prfFirstB64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  ttlMs?: number;
  remainingUses?: number;
};

type NormalizedEmailOtpEd25519ProvisioningInput =
  | (NormalizedEmailOtpEd25519ProvisioningCommon & EmailOtpEd25519RegistrationFreshIntent)
  | (NormalizedEmailOtpEd25519ProvisioningCommon & {
      kind: 'registration_ed25519_companion_provisioning';
      registrationAttemptId: string;
      walletSigningSessionId: string;
      ecdsaThresholdSessionId: string;
    });

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value ?? '').trim();
  return normalized || undefined;
}

function normalizeEmailOtpEd25519ProvisioningInput(
  input: RegisterEmailOtpEd25519CapabilityArgs,
): NormalizedEmailOtpEd25519ProvisioningInput {
  const nearAccountId = toAccountId(input.nearAccountId);
  const relayUrl = String(input.relayUrl || '').trim();
  const rpId = String(input.rpId || '').trim();
  const prfFirstB64u = String(input.prfFirstB64u || '').trim();
  if (!relayUrl) {
    throw new Error('Email OTP threshold-ed25519 provisioning requires relayerUrl');
  }
  if (!rpId) throw new Error('Email OTP threshold-ed25519 provisioning requires rpId');
  if (!prfFirstB64u) {
    throw new Error('Email OTP threshold-ed25519 provisioning requires client seed material');
  }
  const common: NormalizedEmailOtpEd25519ProvisioningCommon = {
    nearAccountId,
    relayUrl,
    rpId,
    prfFirstB64u,
    emailOtpAuthContext: input.emailOtpAuthContext,
    ...(input.appSessionJwt ? { appSessionJwt: input.appSessionJwt } : {}),
    ...(input.routeAuth ? { routeAuth: input.routeAuth } : {}),
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
    ...(Array.isArray(input.participantIds) ? { participantIds: input.participantIds } : {}),
    ...(typeof input.ttlMs === 'number' ? { ttlMs: input.ttlMs } : {}),
    ...(typeof input.remainingUses === 'number' ? { remainingUses: input.remainingUses } : {}),
  };
  const registrationAttemptId = normalizeOptionalString(input.registrationAttemptId);
  if (!registrationAttemptId) {
    throw new Error('Email OTP threshold-ed25519 registration requires a registration attempt');
  }
  if (input.kind === 'registration_ed25519_provisioning') {
    return {
      ...common,
      kind: 'registration_ed25519_provisioning',
      registrationAttemptId,
    };
  }
  const walletSigningSessionId = normalizeOptionalString(input.walletSigningSessionId);
  const ecdsaThresholdSessionId = normalizeOptionalString(input.ecdsaThresholdSessionId);
  if (!walletSigningSessionId || !ecdsaThresholdSessionId) {
    throw new Error(
      'Email OTP companion threshold-ed25519 provisioning requires ECDSA session identity',
    );
  }
  return {
    ...common,
    kind: 'registration_ed25519_companion_provisioning',
    registrationAttemptId,
    walletSigningSessionId,
    ecdsaThresholdSessionId,
  };
}

export async function registerEmailOtpEd25519Capability(args: {
  input: RegisterEmailOtpEd25519CapabilityArgs;
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  persistEmailOtpThresholdEd25519LocalMetadata: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  }) => Promise<void>;
  persistWarmSessionEd25519Capability: (
    args: PersistWarmSessionEd25519CapabilityArgs,
  ) => unknown | Promise<unknown>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }) => Promise<void>;
  sessionPersistenceMode?: string | null;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  registerSigningSession: (
    record: BuildCurrentSealedSessionRecordInput,
  ) => Promise<void>;
}): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
  const input = normalizeEmailOtpEd25519ProvisioningInput(args.input);
  const nearAccountId = input.nearAccountId;
  const relayerUrl = input.relayUrl;
  const rpId = input.rpId;
  const prfFirstB64u = input.prfFirstB64u;

  const participantIds = normalizeThresholdEd25519ParticipantIds(input.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const keyVersion = EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION;
  const registrationTransport = resolveRegistrationTransportFromConfig({
    configs: args.configs,
    relayerUrl,
  });

  let runtimePolicyScope =
    input.runtimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(input.appSessionJwt) ||
    parseThresholdRuntimePolicyScopeFromJwt(input.routeAuth?.jwt);
  let managedGrantForNextRegistrationRequest: ManagedRegistrationBootstrapGrant | null = null;
  if (!runtimePolicyScope && registrationTransport.mode === 'managed') {
    managedGrantForNextRegistrationRequest = await requestManagedRegistrationBootstrapGrant({
      relayerUrl: registrationTransport.relayerUrl,
      environmentId: registrationTransport.environmentId,
      publishableKey: registrationTransport.publishableKey,
      nearAccountId: String(nearAccountId),
      rpId,
    });
    runtimePolicyScope = managedGrantForNextRegistrationRequest.runtimePolicyScope;
  }
  const orgId = String(runtimePolicyScope?.orgId || '').trim();
  const signingRootId = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope).signingRootId
    : '';
  if (!orgId || !signingRootId) {
    throw new Error(
      'Email OTP threshold-ed25519 provisioning requires canonical signing-root scope',
    );
  }

  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP threshold-ed25519 provisioning requires the dedicated emailOtp worker');
  }
  const context = {
    signingRootId,
    nearAccountId: String(nearAccountId),
    keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
    keyVersion,
    participantIds,
    derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  };
  const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: `email-otp-ed25519-registration:${String(nearAccountId)}`,
    ...context,
    prfFirstB64u,
    workerCtx,
  });

  void managedGrantForNextRegistrationRequest;
  const appSessionJwt = String(input.appSessionJwt || '').trim();
  if (!appSessionJwt) {
    throw new Error('Email OTP threshold-ed25519 registration requires app-session auth');
  }
  const authHeaders = { Authorization: `Bearer ${appSessionJwt}` };
  const registrationBodyBase = {
    kind: 'email_otp_registration',
    registrationAttemptId: input.registrationAttemptId,
    new_account_id: String(nearAccountId),
    rp_id: rpId,
    context,
  };
  const prepared = await postJsonExpectOk({
    url: joinUrlPath(relayerUrl, '/threshold-ed25519/hss/prepare'),
    headers: authHeaders,
    credentials: 'include',
    operation: 'Email OTP threshold-ed25519 registration HSS prepare',
    body: registrationBodyBase,
  });
  const ceremonyHandle = String(prepared.ceremonyHandle || '').trim();
  const preparedSession =
    prepared.preparedSession && typeof prepared.preparedSession === 'object'
      ? (prepared.preparedSession as {
          contextBindingB64u?: string;
          evaluatorDriverStateB64u?: string;
        })
      : null;
  const clientOtOfferMessageB64u = String(prepared.clientOtOfferMessageB64u || '').trim();
  if (
    !ceremonyHandle ||
    !preparedSession?.contextBindingB64u ||
    !preparedSession.evaluatorDriverStateB64u ||
    !clientOtOfferMessageB64u
  ) {
    throw new Error('Email OTP threshold-ed25519 registration HSS prepare returned incomplete data');
  }
  const preparedSessionEnvelope = {
    contextBindingB64u: preparedSession.contextBindingB64u,
    evaluatorDriverStateB64u: preparedSession.evaluatorDriverStateB64u,
  };
  const { clientOutputMaskB64u } = await deriveThresholdEd25519HssClientOutputMaskWasm({
    clientRecoverableSecretB64u: prfFirstB64u,
    context: {
      ...context,
      contextBindingB64u: preparedSessionEnvelope.contextBindingB64u,
      operation: 'registration',
      relayerKeyId: `registration:${ceremonyHandle}`,
    },
    workerCtx,
  });
  const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
    evaluatorDriverStateB64u: preparedSessionEnvelope.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u,
    clientInputs,
    workerCtx,
  });
  const responded = await postJsonExpectOk({
    url: joinUrlPath(relayerUrl, '/threshold-ed25519/hss/respond'),
    headers: authHeaders,
    credentials: 'include',
    operation: 'Email OTP threshold-ed25519 registration HSS respond',
    body: {
      ...registrationBodyBase,
      ceremonyHandle,
      clientRequest: {
        clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
      },
    },
  });
  const serverInputDeliveryB64u = String(responded.serverInputDeliveryB64u || '').trim();
  if (!serverInputDeliveryB64u) {
    throw new Error('Email OTP threshold-ed25519 registration HSS respond returned incomplete data');
  }
  const evaluationResult =
    await buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm({
      preparedSession: preparedSessionEnvelope,
      clientRequest,
      serverInputDelivery: { serverInputDeliveryB64u },
      clientOutputMaskB64u,
      workerCtx,
    });
  const sessionPolicy = {
    version: THRESHOLD_SESSION_POLICY_VERSION,
    nearAccountId: String(nearAccountId),
    rpId,
    sessionId: generateThresholdSessionId(),
    walletSigningSessionId: generateWalletSigningSessionId(),
    runtimePolicyScope,
    participantIds,
    ttlMs:
      typeof input.ttlMs === 'number'
        ? input.ttlMs
        : DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses:
      typeof input.remainingUses === 'number'
        ? input.remainingUses
        : DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  };
  const finalized = await postJsonExpectOk({
    url: joinUrlPath(relayerUrl, '/threshold-ed25519/hss/finalize'),
    headers: authHeaders,
    credentials: 'include',
    operation: 'Email OTP threshold-ed25519 registration HSS finalize',
    body: {
      ...registrationBodyBase,
      ceremonyHandle,
      evaluationResult,
      sessionKind: 'jwt',
      sessionPolicy,
    },
  });
  const publicKey = String(finalized.publicKey || '').trim();
  const relayerKeyId = String(finalized.relayerKeyId || '').trim();
  const finalizedReport = parseThresholdEd25519HssFinalizedReport(finalized.finalizedReport);
  const session =
    finalized.session && typeof finalized.session === 'object'
      ? (finalized.session as Record<string, unknown>)
      : null;
  const sessionId = String(session?.sessionId || '').trim();
  const jwt = String(session?.jwt || '').trim();
  const walletSigningSessionId = normalizeOptionalString(session?.walletSigningSessionId);
  const expiresAtMs = Number.isFinite(Number(session?.expiresAtMs))
    ? Math.floor(Number(session?.expiresAtMs))
    : session?.expiresAt
      ? Date.parse(String(session.expiresAt))
      : Date.now() + sessionPolicy.ttlMs;
  const remainingUses = Number.isFinite(Number(session?.remainingUses))
    ? Math.floor(Number(session?.remainingUses))
    : sessionPolicy.remainingUses;
  const sessionParticipantIds =
    normalizeThresholdEd25519ParticipantIds(session?.participantIds) || participantIds;
  const sessionScope =
    normalizeThresholdRuntimePolicyScope(session?.runtimePolicyScope) || runtimePolicyScope;
  if (
    !publicKey ||
    !relayerKeyId ||
    !finalizedReport ||
    !sessionId ||
    !jwt ||
    !walletSigningSessionId ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    throw new Error('Email OTP threshold-ed25519 registration finalize returned incomplete data');
  }
  const completed = await completeThresholdEd25519HssClientCeremony({
    preparedSession: preparedSessionEnvelope,
    finalizedReport,
    clientOutputMaskB64u,
    workerCtx,
  });
  if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
    throw new Error(
      completed.error || 'Email OTP threshold-ed25519 registration client output failed',
    );
  }
  const xClientBaseB64u = completed.clientOutput.xClientBaseB64u;
  await args.persistEmailOtpThresholdEd25519LocalMetadata({
    nearAccountId,
    rpId,
    relayerUrl,
    publicKey,
    relayerKeyId,
    keyVersion,
    participantIds: sessionParticipantIds,
  });
  await args.persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    runtimePolicyScope: sessionScope,
    participantIds: sessionParticipantIds,
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    jwt,
    xClientBaseB64u,
    emailOtpAuthContext: input.emailOtpAuthContext,
    source: 'email_otp',
  });
  await args.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs,
    remainingUses,
    transport: {
      curve: 'ed25519',
      walletId: String(nearAccountId),
      relayerUrl,
      walletSigningSessionId,
      thresholdSessionAuthToken: jwt,
    },
  });
  if (input.kind === 'registration_ed25519_companion_provisioning') {
    await attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
      sessionPersistenceMode: args.sessionPersistenceMode,
      ecdsaThresholdSessionId: input.ecdsaThresholdSessionId,
      ed25519ThresholdSessionId: sessionId,
      readExactSealedSession: args.readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        args.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        args.getThresholdEd25519SessionRecordByThresholdSessionId,
      registerSigningSession: args.registerSigningSession,
    });
  }
  return {
    publicKey,
    relayerKeyId,
    keyVersion,
    sessionId,
    expiresAtMs,
    remainingUses,
    participantIds: sessionParticipantIds,
    jwt,
    xClientBaseB64u,
  };
}

export async function reconstructEmailOtpEd25519Session(args: {
  input: ReconstructEmailOtpEd25519SessionArgs;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  persistWarmSessionEd25519Capability: (
    args: PersistWarmSessionEd25519CapabilityArgs,
  ) => unknown | Promise<unknown>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }) => Promise<void>;
  sessionPersistenceMode?: string | null;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  registerSigningSession: (
    record: BuildCurrentSealedSessionRecordInput,
  ) => Promise<void>;
}): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
  const input = args.input;
  const nearAccountId = toAccountId(input.nearAccountId);
  const relayerUrl = String(input.relayUrl || '').trim();
  const rpId = String(input.rpId || '').trim();
  const prfFirstB64u = String(input.prfFirstB64u || '').trim();
  const routeAuthJwt = String(input.routeAuth.jwt || '').trim();
  const walletSigningSessionId = normalizeOptionalString(input.walletSigningSessionId);
  const ecdsaThresholdSessionId = normalizeOptionalString(input.ecdsaThresholdSessionId);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(input.runtimePolicyScope);
  const participantIds = normalizeThresholdEd25519ParticipantIds(input.ed25519Key.participantIds);
  const relayerKeyId = normalizeOptionalString(input.ed25519Key.relayerKeyId);
  const keyVersion = normalizeOptionalString(input.ed25519Key.keyVersion);
  if (!relayerUrl) {
    throw new Error('Email OTP threshold-ed25519 session reconstruction requires relayerUrl');
  }
  if (!rpId) throw new Error('Email OTP threshold-ed25519 session reconstruction requires rpId');
  if (!prfFirstB64u) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires client seed material',
    );
  }
  if (!routeAuthJwt) {
    throw new Error('Email OTP threshold-ed25519 session reconstruction requires route auth');
  }
  if (!runtimePolicyScope) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires canonical runtime scope',
    );
  }
  if (!walletSigningSessionId || !ecdsaThresholdSessionId) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires ECDSA session identity',
    );
  }
  if (!relayerKeyId || !keyVersion || !participantIds) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires concrete Ed25519 key identity',
    );
  }
  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction requires the dedicated emailOtp worker',
    );
  }
  const context = {
    signingRootId: signingRootScopeFromRuntimePolicyScope(runtimePolicyScope).signingRootId,
    nearAccountId: String(nearAccountId),
    keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
    keyVersion,
    participantIds,
    derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  };
  const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: `email-otp-ed25519-reconstruction:${String(nearAccountId)}`,
    ...context,
    prfFirstB64u,
    workerCtx,
  });
  const { policy } = await buildEd25519SessionPolicy({
    nearAccountId,
    rpId,
    relayerKeyId,
    runtimePolicyScope,
    participantIds,
    walletSigningSessionId,
    ttlMs: input.ttlMs,
    remainingUses: input.remainingUses,
  });
  const minted = await postJsonExpectOk({
    url: joinUrlPath(relayerUrl, '/threshold-ed25519/session'),
    headers: { Authorization: `Bearer ${routeAuthJwt}` },
    credentials: 'include',
    operation: 'Email OTP threshold-ed25519 session reconstruction mint',
    body: {
      sessionKind: 'jwt',
      relayerKeyId,
      sessionPolicy: policy,
    },
  });
  const sessionId = String(minted.sessionId || policy.sessionId || '').trim();
  const jwt = String(minted.jwt || '').trim();
  const expiresAtMs = Number.isFinite(Number(minted.expiresAtMs))
    ? Math.floor(Number(minted.expiresAtMs))
    : minted.expiresAt
      ? Date.parse(String(minted.expiresAt))
      : Date.now() + policy.ttlMs;
  const remainingUses = Number.isFinite(Number(minted.remainingUses))
    ? Math.floor(Number(minted.remainingUses))
    : policy.remainingUses;
  const sessionScope =
    normalizeThresholdRuntimePolicyScope(minted.runtimePolicyScope) || runtimePolicyScope;
  if (!sessionId || !jwt || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error(
      'Email OTP threshold-ed25519 session reconstruction mint returned incomplete data',
    );
  }
  await args.persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    runtimePolicyScope: sessionScope,
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    jwt,
    emailOtpAuthContext: input.emailOtpAuthContext,
    source: 'email_otp',
  });
  await args.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs,
    remainingUses,
    transport: {
      curve: 'ed25519',
      walletId: String(nearAccountId),
      relayerUrl,
      walletSigningSessionId,
      thresholdSessionAuthToken: jwt,
    },
  });
  const completed = await runThresholdEd25519HssCeremonyWithSessionValue({
    relayerUrl,
    thresholdSessionAuthToken: jwt,
    relayerKeyId,
    operation: 'warm_session_reconstruction',
    context: {
      ...context,
      signingRootId: signingRootScopeFromRuntimePolicyScope(sessionScope).signingRootId,
    },
    clientInputs,
    outputProjection: {
      kind: 'client-masked-projection',
      clientRecoverableSecretB64u: prfFirstB64u,
    },
    workerCtx,
  });
  if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
    throw new Error(
      completed.error || 'Email OTP threshold-ed25519 session reconstruction failed',
    );
  }
  await args.persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    runtimePolicyScope: sessionScope,
    participantIds,
    sessionKind: 'jwt',
    sessionId,
    walletSigningSessionId,
    expiresAtMs,
    remainingUses,
    jwt,
    xClientBaseB64u: completed.clientOutput.xClientBaseB64u,
    emailOtpAuthContext: input.emailOtpAuthContext,
    source: 'email_otp',
  });
  await attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
    sessionPersistenceMode: args.sessionPersistenceMode,
    ecdsaThresholdSessionId,
    ed25519ThresholdSessionId: sessionId,
    readExactSealedSession: args.readExactSealedSession,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      args.getThresholdEcdsaSessionRecordByThresholdSessionId,
    getThresholdEd25519SessionRecordByThresholdSessionId:
      args.getThresholdEd25519SessionRecordByThresholdSessionId,
    registerSigningSession: args.registerSigningSession,
  });
  return {
    relayerKeyId,
    keyVersion,
    sessionId,
    expiresAtMs,
    remainingUses,
    participantIds,
    jwt,
    xClientBaseB64u: completed.clientOutput.xClientBaseB64u,
  };
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

function replaceUrlPathSuffix(url: string, fromPath: string, toPath: string): string {
  const raw = String(url || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.pathname === fromPath || parsed.pathname === `${fromPath}/`) {
      parsed.pathname = toPath;
      return parsed.toString();
    }
  } catch {}
  if (raw.endsWith(fromPath)) return `${raw.slice(0, raw.length - fromPath.length)}${toPath}`;
  if (raw.endsWith(`${fromPath}/`)) {
    return `${raw.slice(0, raw.length - fromPath.length - 1)}${toPath}`;
  }
  return '';
}

function resolveRegistrationTransportFromConfig(args: {
  configs: SeamsConfigsReadonly;
  relayerUrl: string;
}): RegistrationTransport {
  const registration = args.configs.registration;
  if (registration.mode === 'managed') {
    return {
      mode: 'managed',
      relayerUrl: String(args.relayerUrl || args.configs.network.relayer.url || '').trim(),
      environmentId: String(registration.environmentId || '').trim(),
      publishableKey: String(registration.publishableKey || '').trim(),
    };
  }
  return {
    mode: 'backend_proxy',
    bootstrapUrl: String(registration.bootstrapUrl || '').trim(),
    relayerUrl: String(args.relayerUrl || args.configs.network.relayer.url || '').trim(),
  };
}

async function readJsonObjectResponse(response: Response): Promise<Record<string, unknown>> {
  const parsed = await response.json().catch(() => ({}));
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

function parseThresholdEd25519HssFinalizedReport(
  input: unknown,
): ThresholdEd25519HssFinalizedReportEnvelope | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const obj = input as Record<string, unknown>;
  const contextBindingB64u = String(obj.contextBindingB64u || '').trim();
  const clientOutputMessageB64u = String(obj.clientOutputMessageB64u || '').trim();
  const seedOutputMessageB64u = String(obj.seedOutputMessageB64u || '').trim();
  if (!contextBindingB64u || !clientOutputMessageB64u) return null;
  return {
    contextBindingB64u,
    clientOutputMessageB64u,
    ...(seedOutputMessageB64u ? { seedOutputMessageB64u } : {}),
  };
}

async function postJsonExpectOk(args: {
  url: string;
  headers?: Record<string, string>;
  body: unknown;
  credentials?: RequestCredentials;
  operation: string;
}): Promise<Record<string, unknown>> {
  const response = await fetch(args.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(args.headers || {}) },
    credentials: args.credentials || 'omit',
    body: JSON.stringify(args.body),
  });
  const data = await readJsonObjectResponse(response);
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(data.message || data.code || `${args.operation} failed with HTTP ${response.status}`),
    );
  }
  return data;
}

async function requestManagedRegistrationBootstrapGrant(args: {
  relayerUrl: string;
  environmentId: string;
  publishableKey: string;
  nearAccountId: string;
  rpId: string;
}): Promise<ManagedRegistrationBootstrapGrant> {
  const data = await postJsonExpectOk({
    url: joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants'),
    headers: { Authorization: `Bearer ${args.publishableKey}` },
    operation: 'Managed registration bootstrap grant',
    body: {
      environmentId: args.environmentId,
      newAccountId: args.nearAccountId,
      rpId: args.rpId,
      flow: 'registration_v1',
    },
  });
  const grant =
    data.grant && typeof data.grant === 'object' && !Array.isArray(data.grant)
      ? (data.grant as Record<string, unknown>)
      : {};
  const token = String(grant.token || '').trim();
  const orgId = String(grant.orgId || '').trim();
  const projectId = String(grant.projectId || '').trim();
  const envId = String(grant.envId || '').trim();
  const signingRootVersion = String(grant.signingRootVersion || '').trim();
  if (!token || !orgId || !projectId || !envId || !signingRootVersion) {
    throw new Error('Managed registration grant response missing token or runtime scope');
  }
  return {
    token,
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
      signingRootVersion,
    },
  };
}
