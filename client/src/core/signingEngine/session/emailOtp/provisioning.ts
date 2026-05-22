import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  buildEd25519SessionPolicy,
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  prepareThresholdEd25519HssClientRequestWasm,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import { runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue } from '@/core/signingEngine/threshold/ed25519/hssLifecycle';
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

export type EmailOtpThresholdEd25519ProvisioningResult = {
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
  jwt: string;
  xClientBaseB64u?: string;
};

export type EmailOtpEd25519FreshProvisioningIntent = {
  kind: 'fresh_ed25519_provisioning';
  walletSigningSessionId?: never;
  ecdsaThresholdSessionId?: never;
};

export type EmailOtpEd25519CompanionProvisioningIntent = {
  kind: 'companion_to_ecdsa_provisioning';
  walletSigningSessionId: string;
  ecdsaThresholdSessionId: string;
};

export type EmailOtpEd25519ProvisioningIntent =
  | EmailOtpEd25519FreshProvisioningIntent
  | EmailOtpEd25519CompanionProvisioningIntent;

type ProvisionEmailOtpThresholdEd25519CapabilityCommonArgs = {
  nearAccountId: AccountId | string;
  relayUrl: string;
  rpId: string;
  prfFirstB64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  participantIds?: number[];
  ttlMs?: number;
  remainingUses?: number;
};

export type ProvisionEmailOtpThresholdEd25519CapabilityArgs =
  ProvisionEmailOtpThresholdEd25519CapabilityCommonArgs & EmailOtpEd25519ProvisioningIntent;

type NormalizedEmailOtpEd25519ProvisioningCommon = {
  nearAccountId: AccountId;
  relayUrl: string;
  rpId: string;
  prfFirstB64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  participantIds?: number[];
  ttlMs?: number;
  remainingUses?: number;
};

type NormalizedEmailOtpEd25519ProvisioningInput =
  | (NormalizedEmailOtpEd25519ProvisioningCommon & EmailOtpEd25519FreshProvisioningIntent)
  | (NormalizedEmailOtpEd25519ProvisioningCommon & {
      kind: 'companion_to_ecdsa_provisioning';
      walletSigningSessionId: string;
      ecdsaThresholdSessionId: string;
    });

type EmailOtpEd25519RegistrationGrantAdmission =
  | {
      kind: 'registration_grant_admitted';
      registrationAttemptId: string;
    }
  | {
      kind: 'registration_grant_forbidden';
    };

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value ?? '').trim();
  return normalized || undefined;
}

function normalizeEmailOtpEd25519ProvisioningInput(
  input: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
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
    ...(input.registrationAttemptId ? { registrationAttemptId: input.registrationAttemptId } : {}),
    ...(Array.isArray(input.participantIds) ? { participantIds: input.participantIds } : {}),
    ...(typeof input.ttlMs === 'number' ? { ttlMs: input.ttlMs } : {}),
    ...(typeof input.remainingUses === 'number' ? { remainingUses: input.remainingUses } : {}),
  };
  if (input.kind === 'fresh_ed25519_provisioning') {
    return {
      ...common,
      kind: 'fresh_ed25519_provisioning',
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
    kind: 'companion_to_ecdsa_provisioning',
    walletSigningSessionId,
    ecdsaThresholdSessionId,
  };
}

function resolveRegistrationGrantAdmission(
  input: NormalizedEmailOtpEd25519ProvisioningInput,
): EmailOtpEd25519RegistrationGrantAdmission {
  const registrationAttemptId = normalizeOptionalString(input.registrationAttemptId);
  if (registrationAttemptId) {
    return {
      kind: 'registration_grant_admitted',
      registrationAttemptId,
    };
  }
  return { kind: 'registration_grant_forbidden' };
}

export async function provisionEmailOtpEd25519Capability(args: {
  input: ProvisionEmailOtpThresholdEd25519CapabilityArgs;
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
  const keyVersion = 'threshold-ed25519-hss-v1';
  const registrationTransport = resolveRegistrationTransportFromConfig({
    configs: args.configs,
    relayerUrl,
  });
  const registrationGrantAdmission = resolveRegistrationGrantAdmission(input);

  let runtimePolicyScope =
    input.runtimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(input.appSessionJwt) ||
    parseThresholdRuntimePolicyScopeFromJwt(input.routeAuth?.jwt);
  let managedGrantForNextRegistrationRequest: ManagedRegistrationBootstrapGrant | null = null;
  if (
    !runtimePolicyScope &&
    registrationTransport.mode === 'managed' &&
    registrationGrantAdmission.kind === 'registration_grant_admitted'
  ) {
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

  const registrationHeaders = async (): Promise<Record<string, string>> => {
    if (registrationTransport.mode !== 'managed') return {};
    if (registrationGrantAdmission.kind === 'registration_grant_forbidden') {
      throw new Error(
        'Email OTP threshold-ed25519 registration bootstrap requires a registration attempt',
      );
    }
    if (managedGrantForNextRegistrationRequest) {
      const grant = managedGrantForNextRegistrationRequest;
      managedGrantForNextRegistrationRequest = null;
      return { Authorization: `Bearer ${grant.token}` };
    }
    const grant = await requestManagedRegistrationBootstrapGrant({
      relayerUrl: registrationTransport.relayerUrl,
      environmentId: registrationTransport.environmentId,
      publishableKey: registrationTransport.publishableKey,
      nearAccountId: String(nearAccountId),
      rpId,
    });
    return { Authorization: `Bearer ${grant.token}` };
  };
  const registrationUrl = (path: string): string => {
    if (registrationTransport.mode === 'managed') {
      return joinUrlPath(registrationTransport.relayerUrl, path);
    }
    return (
      replaceUrlPathSuffix(registrationTransport.bootstrapUrl, '/registration/bootstrap', path) ||
      joinUrlPath(registrationTransport.bootstrapUrl || registrationTransport.relayerUrl, path)
    );
  };

  const prepared = await postJsonExpectOk({
    url: registrationUrl('/registration/threshold-ed25519/hss/prepare'),
    headers: await registrationHeaders(),
    operation: 'Email OTP threshold-ed25519 registration prepare',
    body: {
      new_account_id: String(nearAccountId),
      rp_id: rpId,
      context,
    },
  });
  const ceremonyHandle = String(prepared.ceremonyHandle || '').trim();
  const preparedSession = prepared.preparedSession as {
    contextBindingB64u?: string;
    evaluatorDriverStateB64u?: string;
  };
  const clientOtOfferMessageB64u = String(prepared.clientOtOfferMessageB64u || '').trim();
  if (!ceremonyHandle || !preparedSession || !clientOtOfferMessageB64u) {
    throw new Error('Email OTP threshold-ed25519 registration prepare returned incomplete data');
  }
  const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
    evaluatorDriverStateB64u: String(preparedSession.evaluatorDriverStateB64u || '').trim(),
    clientOtOfferMessageB64u,
    clientInputs,
    workerCtx,
  });
  await postJsonExpectOk({
    url: registrationUrl('/registration/threshold-ed25519/hss/respond'),
    headers: await registrationHeaders(),
    operation: 'Email OTP threshold-ed25519 registration respond',
    body: {
      new_account_id: String(nearAccountId),
      rp_id: rpId,
      ceremonyHandle,
      clientRequest,
    },
  });
  const finalized = await postJsonExpectOk({
    url: registrationUrl('/registration/threshold-ed25519/hss/finalize'),
    headers: await registrationHeaders(),
    operation: 'Email OTP threshold-ed25519 registration finalize',
    body: {
      new_account_id: String(nearAccountId),
      rp_id: rpId,
      ceremonyHandle,
      account_provisioning: { mode: 'create_if_missing' },
      ...(input.registrationAttemptId
        ? { google_email_otp_registration_attempt_id: input.registrationAttemptId }
        : {}),
    },
  });
  const publicKey = String(finalized.publicKey || '').trim();
  const relayerKeyId = String(finalized.relayerKeyId || '').trim();
  if (!publicKey || !relayerKeyId) {
    throw new Error('Email OTP threshold-ed25519 registration finalize returned incomplete data');
  }
  const accountProvisioning = finalized.accountProvisioning as
    | { mode?: unknown; status?: unknown }
    | undefined;
  if (
    String(accountProvisioning?.mode || '').trim() !== 'create_if_missing' ||
    !['created', 'already_ready'].includes(String(accountProvisioning?.status || '').trim())
  ) {
    throw new Error(
      'Email OTP threshold-ed25519 registration did not provision the finalized public key on-chain',
    );
  }

  await args.persistEmailOtpThresholdEd25519LocalMetadata({
    nearAccountId,
    rpId,
    relayerUrl,
    publicKey,
    relayerKeyId,
    keyVersion,
    participantIds,
  });

  const { policy } = await buildEd25519SessionPolicy({
    nearAccountId,
    rpId,
    relayerKeyId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    participantIds,
    ...(input.kind === 'companion_to_ecdsa_provisioning'
      ? { walletSigningSessionId: input.walletSigningSessionId }
      : {}),
    ttlMs: input.ttlMs,
    remainingUses: input.remainingUses,
  });
  const walletSigningSessionId = policy.walletSigningSessionId;
  const minted = await postJsonExpectOk({
    url: joinUrlPath(relayerUrl, '/threshold-ed25519/session'),
    headers:
      input.routeAuth?.jwt || input.appSessionJwt
        ? { Authorization: `Bearer ${input.routeAuth?.jwt || input.appSessionJwt}` }
        : {},
    credentials: 'include',
    operation: 'Email OTP threshold-ed25519 session mint',
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
    throw new Error('Email OTP threshold-ed25519 session mint returned incomplete data');
  }

  await args.persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    ...(sessionScope ? { runtimePolicyScope: sessionScope } : {}),
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
      relayerUrl,
      thresholdSessionAuthToken: jwt,
    },
  });
  if (input.kind === 'companion_to_ecdsa_provisioning') {
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

  const completed = await runThresholdEd25519HssCeremonyWithSessionValue({
    relayerUrl,
    thresholdSessionAuthToken: jwt,
    relayerKeyId,
    operation: 'warm_session_reconstruction',
    context: {
      ...context,
      signingRootId: sessionScope
        ? signingRootScopeFromRuntimePolicyScope(sessionScope).signingRootId
        : signingRootId,
    },
    clientInputs,
    workerCtx,
  });
  if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
    throw new Error(
      completed.error || 'Email OTP threshold-ed25519 client-base reconstruction failed',
    );
  }
  await args.persistWarmSessionEd25519Capability({
    kind: 'jwt_email_otp',
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    ...(sessionScope ? { runtimePolicyScope: sessionScope } : {}),
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
  if (input.kind === 'companion_to_ecdsa_provisioning') {
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
