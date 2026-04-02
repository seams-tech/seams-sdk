import {
  RegistrationSSEEvent,
  RegistrationPhase,
  RegistrationStatus,
} from '../../types/sdkSentEvents';
import { PasskeyManagerContext } from '..';
import {
  serializeRegistrationCredential,
  normalizeRegistrationCredential,
} from '../../signingEngine/signers/webauthn/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';
import type { WebAuthnRegistrationCredential } from '../../types/webauthn';
import {
  cloneAuthenticatorOptions,
  type AuthenticatorOptions,
} from '../../types/authenticatorOptions';
import type {
  CreateAccountAndRegisterResult,
  CreateAccountAndRegisterSmartAccountDeployment,
  CreateAccountAndRegisterSmartAccountTarget,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientRequestEnvelope,
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPrepareForRegistrationResponse,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssServerMessageEnvelope,
  ThresholdEd25519HssEvaluationResultEnvelope,
  ThresholdEd25519HssFinalizeForRegistrationResponse,
} from '@server/core/types';
import type {
  EcdsaSessionPolicy,
  Ed25519SessionPolicy,
} from '../../signingEngine/threshold/session/sessionPolicy';
import type { ThresholdRuntimeSnapshotScope } from '../../signingEngine/threshold/session/sessionPolicy';
import { isObject } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import { computeRegistrationBootstrapRequestHashSha256 } from '@shared/utils/registrationBootstrapHash';
import type { RegistrationErrorCode } from '../../types/tatchi';

function isSerializedRegistrationCredential(
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
): credential is WebAuthnRegistrationCredential {
  if (!isObject(credential)) return false;
  const resp = (credential as { response?: unknown }).response;
  if (!isObject(resp)) return false;
  return typeof (resp as { attestationObject?: unknown }).attestationObject === 'string';
}

function improveAtomicRegistrationError(args: {
  raw: string;
  nearAccountId: string;
  relayUrl: string;
}): string {
  const raw = String(args.raw || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayUrl = String(args.relayUrl || '').trim();

  // Server validation: account creation can only create subaccounts under a specific namespace.
  const mRelayer =
    /new_account_id must be a subaccount of relayer(?:\s+signer\s+)?account\s*\(([^)]+)\)/i.exec(
      raw,
    );

  const expectedRelayer = mRelayer?.[1] ? String(mRelayer[1]).trim() : '';

  if (expectedRelayer) {
    const hint =
      `Registration accountId must be a subaccount of the relay signer account.\n` +
      `Expected: <username>.${expectedRelayer}\n` +
      (nearAccountId ? `Got: ${nearAccountId}\n` : '') +
      `Fix: set client config \`relayerAccount: '${expectedRelayer}'\` (must match relay RELAYER_ACCOUNT_ID)` +
      (relayUrl ? ` for relayer \`${relayUrl}\`` : '') +
      `.`;
    return hint;
  }

  return raw || 'Atomic registration failed';
}

const REGISTRATION_FAILURE_CODES: readonly RegistrationErrorCode[] = [
  'secret_key_missing',
  'secret_key_invalid',
  'secret_key_revoked',
  'secret_key_forbidden_scope',
  'secret_key_ip_blocked',
  'secret_key_environment_mismatch',
  'publishable_key_missing',
  'publishable_key_invalid',
  'publishable_key_revoked',
  'publishable_key_origin_blocked',
  'publishable_key_environment_mismatch',
  'publishable_key_rate_limited',
  'publishable_key_quota_exhausted',
  'invalid_environment',
  'environment_archived',
  'invalid_body',
  'payment_required',
  'payment_invalid',
  'bootstrap_token_missing',
  'bootstrap_token_invalid',
  'bootstrap_token_expired',
  'bootstrap_token_already_used',
  'bootstrap_token_request_mismatch',
  'bootstrap_token_origin_mismatch',
];

function isRegistrationErrorCode(raw: unknown): raw is RegistrationErrorCode {
  const value = String(raw || '').trim();
  return REGISTRATION_FAILURE_CODES.includes(value as RegistrationErrorCode);
}

export class RelayRegistrationError extends Error {
  readonly code: RegistrationErrorCode;
  readonly status: number;

  constructor(input: { code: RegistrationErrorCode; status: number; message: string }) {
    super(input.message);
    this.name = 'RelayRegistrationError';
    this.code = input.code;
    this.status = input.status;
  }
}

const REGISTRATION_NETWORK_TIMEOUT_MS = 30_000;

function createRegistrationTimeoutError(args: {
  operation: string;
  url: string;
  timeoutMs: number;
}): Error {
  const url = String(args.url || '').trim();
  const suffix = url ? ` (${url})` : '';
  return new Error(`${args.operation} timed out after ${args.timeoutMs}ms${suffix}`);
}

async function fetchWithRegistrationTimeout(args: {
  url: string;
  init: RequestInit;
  operation: string;
  timeoutMs?: number;
}): Promise<Response> {
  const timeoutMs = Math.max(
    1_000,
    Math.floor(Number(args.timeoutMs ?? REGISTRATION_NETWORK_TIMEOUT_MS) || 0),
  );
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(args.url, {
      ...args.init,
      signal: controller.signal,
    });
  } catch (error: unknown) {
    if (
      controller.signal.aborted ||
      (error instanceof DOMException && error.name === 'AbortError')
    ) {
      throw createRegistrationTimeoutError({
        operation: args.operation,
        url: args.url,
        timeoutMs,
      });
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

function isRelayRegistrationError(error: unknown): error is RelayRegistrationError {
  return error instanceof RelayRegistrationError;
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  if (!suffix) return base;
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
  if (raw.endsWith(fromPath)) {
    return `${raw.slice(0, raw.length - fromPath.length)}${toPath}`;
  }
  if (raw.endsWith(`${fromPath}/`)) {
    return `${raw.slice(0, raw.length - fromPath.length - 1)}${toPath}`;
  }
  return '';
}

type ResolvedRegistrationTransport =
  | {
      mode: 'backend_proxy';
      bootstrapUrl: string;
      recoveryShareUrl: string;
    }
  | {
      mode: 'managed';
      relayerUrl: string;
      environmentId: string;
      publishableKey: string;
      paymentMode?: string;
    };

function resolveRegistrationTransport(
  context: PasskeyManagerContext,
): ResolvedRegistrationTransport {
  const configs = context.configs as PasskeyManagerContext['configs'] & {
    registration?: unknown;
  };
  const registration = configs.registration;
  if (registration && typeof registration === 'object' && !Array.isArray(registration)) {
    const mode = String((registration as { mode?: unknown }).mode || 'backend_proxy').trim();
    if (mode === 'managed') {
      const relayerUrl = String(context.configs.network.relayer.url || '').trim();
      const environmentId = String(
        (registration as { environmentId?: unknown }).environmentId || '',
      ).trim();
      const publishableKey = String(
        (registration as { publishableKey?: unknown }).publishableKey || '',
      ).trim();
      const paymentMode = String(
        (registration as { paymentMode?: unknown }).paymentMode || '',
      ).trim();
      if (!relayerUrl) throw new Error('Managed registration requires relayer.url');
      if (!environmentId)
        throw new Error('Managed registration requires registration.environmentId');
      if (!publishableKey) {
        throw new Error('Managed registration requires registration.publishableKey');
      }
      return {
        mode: 'managed',
        relayerUrl,
        environmentId,
        publishableKey,
        ...(paymentMode ? { paymentMode } : {}),
      };
    }
    const bootstrapUrl = String(
      (registration as { bootstrapUrl?: unknown; registrationBootstrapUrl?: unknown })
        .bootstrapUrl ??
        (registration as { registrationBootstrapUrl?: unknown }).registrationBootstrapUrl ??
        '',
    ).trim();
    if (bootstrapUrl) {
      const recoveryShareUrl =
        replaceUrlPathSuffix(
          bootstrapUrl,
          '/registration/bootstrap',
          '/registration/recovery-share',
        ) || joinUrlPath(bootstrapUrl, '/registration/recovery-share');
      return { mode: 'backend_proxy', bootstrapUrl, recoveryShareUrl };
    }
  }
  const relayerUrl = String(context.configs.network.relayer.url || '').trim();
  return {
    mode: 'backend_proxy',
    bootstrapUrl: joinUrlPath(relayerUrl, '/registration/bootstrap'),
    recoveryShareUrl: joinUrlPath(relayerUrl, '/registration/recovery-share'),
  };
}

function buildManagedClientContext(): { sdk: string; userAgentHint?: string } {
  const userAgentHint =
    typeof navigator !== 'undefined' ? String(navigator.userAgent || '').trim() : '';
  return {
    sdk: '@tatchi-xyz/sdk',
    ...(userAgentHint ? { userAgentHint } : {}),
  };
}

type ManagedRegistrationBootstrapGrant = {
  token: string;
  expiresAt: string;
  runtimeSnapshotScope: ThresholdRuntimeSnapshotScope;
  origin?: string;
  mode?: string;
};

async function requestManagedRegistrationBootstrapGrant(args: {
  relayerUrl: string;
  publishableKey: string;
  environmentId: string;
  nearAccountId: string;
  rpId: string;
  requestHashSha256: string;
  path?: string;
}): Promise<ManagedRegistrationBootstrapGrant> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const bootstrapGrantUrl = joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants');
  const brokerResponse = await fetchWithRegistrationTimeout({
    url: bootstrapGrantUrl,
    operation: 'Managed registration bootstrap grant',
    init: {
      method: 'POST',
      headers: {
        ...headers,
        Authorization: `Bearer ${args.publishableKey}`,
      },
      body: JSON.stringify({
        environmentId: args.environmentId,
        newAccountId: args.nearAccountId,
        rpId: args.rpId,
        requestHashSha256: args.requestHashSha256,
        ...(String(args.path || '').trim() ? { path: String(args.path || '').trim() } : {}),
        clientContext: buildManagedClientContext(),
      }),
    },
  });
  const brokerResult = await readJsonObject(brokerResponse);
  const brokerCode = String(brokerResult.code || '').trim();
  const brokerMessage =
    String(brokerResult.message || '').trim() ||
    `HTTP ${brokerResponse.status}: ${brokerResponse.statusText}`;
  if (!brokerResponse.ok || brokerResult.ok === false) {
    if (isRegistrationErrorCode(brokerCode)) {
      throw new RelayRegistrationError({
        code: brokerCode,
        status: brokerResponse.status,
        message: brokerMessage,
      });
    }
    throw new Error(brokerMessage || 'Managed bootstrap grant failed');
  }

  const grant = isObject(brokerResult.grant)
    ? (brokerResult.grant as Record<string, unknown>)
    : null;
  const token = String((grant?.token as string) || '').trim();
  const orgId = String((grant?.orgId as string) || '').trim();
  const environmentId = String((grant?.environmentId as string) || '').trim();
  const projectId = String((grant?.projectId as string) || '').trim();
  if (!token) {
    throw new Error('Managed bootstrap grant response did not include a bootstrap token');
  }
  if (!orgId || !environmentId) {
    throw new Error('Managed bootstrap grant response did not include canonical runtime scope');
  }

  return {
    token,
    expiresAt: String((grant?.expiresAt as string) || '').trim(),
    runtimeSnapshotScope: {
      orgId,
      environmentId,
      ...(projectId ? { projectId } : {}),
    },
    ...(String((grant?.origin as string) || '').trim()
      ? { origin: String((grant?.origin as string) || '').trim() }
      : {}),
    ...(String((grant?.mode as string) || '').trim()
      ? { mode: String((grant?.mode as string) || '').trim() }
      : {}),
  };
}

async function readJsonObject(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text) return {};
  try {
    const parsed: unknown = JSON.parse(text);
    return isObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function issueManagedRegistrationBootstrapTokenForRequest(args: {
  registrationTransport: Extract<ResolvedRegistrationTransport, { mode: 'managed' }>;
  nearAccountId: string;
  rpId: string;
  path: string;
  requestBody: unknown;
}): Promise<string> {
  const requestHashStartedAt = performance.now();
  const requestHashSha256 = await computeRegistrationBootstrapRequestHashSha256(args.requestBody);
  console.debug('[Registration] bootstrap request hash computed', {
    path: args.path,
    durationMs: Math.round(performance.now() - requestHashStartedAt),
  });
  const grantStartedAt = performance.now();
  const grant = await requestManagedRegistrationBootstrapGrant({
    relayerUrl: args.registrationTransport.relayerUrl,
    publishableKey: args.registrationTransport.publishableKey,
    environmentId: args.registrationTransport.environmentId,
    nearAccountId: args.nearAccountId,
    rpId: args.rpId,
    requestHashSha256,
    path: args.path,
  });
  console.debug('[Registration] bootstrap grant issued', {
    path: args.path,
    durationMs: Math.round(performance.now() - grantStartedAt),
  });
  return grant.token;
}

export async function resolveManagedRegistrationRuntimeScope(args: {
  context: PasskeyManagerContext;
  nearAccountId: string;
  rpId: string;
  credential: WebAuthnRegistrationCredential | PublicKeyCredential;
  authenticatorOptions?: AuthenticatorOptions;
}): Promise<ThresholdRuntimeSnapshotScope> {
  const registrationTransport = resolveRegistrationTransport(args.context);
  if (registrationTransport.mode !== 'managed') {
    throw new Error(
      'Threshold Ed25519 Option A registration currently requires managed registration transport',
    );
  }

  const isSerialized = isSerializedRegistrationCredential(args.credential);
  const serialized: WebAuthnRegistrationCredential = isSerialized
    ? normalizeRegistrationCredential(args.credential)
    : serializeRegistrationCredential(args.credential as PublicKeyCredential);
  const serializedCredential =
    redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(serialized);
  if (!Array.isArray(serializedCredential?.response?.transports)) {
    serializedCredential.response.transports = [];
  }

  const requestBody = {
    new_account_id: String(args.nearAccountId || '').trim(),
    device_number: 1,
    rp_id: String(args.rpId || '').trim(),
    webauthn_registration: serializedCredential,
    authenticator_options: cloneAuthenticatorOptions(
      args.authenticatorOptions ?? args.context.configs.webauthn.authenticatorOptions,
    ),
  } satisfies Pick<
    CreateAccountAndRegisterUserRequest,
    'new_account_id' | 'device_number' | 'rp_id' | 'webauthn_registration' | 'authenticator_options'
  >;

  const requestHashSha256 = await computeRegistrationBootstrapRequestHashSha256(requestBody);
  const grant = await requestManagedRegistrationBootstrapGrant({
    relayerUrl: registrationTransport.relayerUrl,
    publishableKey: registrationTransport.publishableKey,
    environmentId: registrationTransport.environmentId,
    nearAccountId: requestBody.new_account_id,
    rpId: requestBody.rp_id,
    requestHashSha256,
    path: '/registration/bootstrap',
  });
  return grant.runtimeSnapshotScope;
}

export async function prepareThresholdEd25519HssServerCeremonyWithRelayRegistration(args: {
  context: PasskeyManagerContext;
  nearAccountId: string;
  rpId: string;
  hssContext: ThresholdEd25519HssCanonicalContext;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}): Promise<ThresholdEd25519HssServerMessageEnvelope> {
  const registrationTransport = resolveRegistrationTransport(args.context);
  const requestBody = {
    new_account_id: String(args.nearAccountId || '').trim(),
    rp_id: String(args.rpId || '').trim(),
    context: args.hssContext,
    preparedSession: args.preparedSession,
    clientRequest: args.clientRequest,
  };
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  let response: Response;

  if (registrationTransport.mode === 'managed') {
    const token = await issueManagedRegistrationBootstrapTokenForRequest({
      registrationTransport,
      nearAccountId: requestBody.new_account_id,
      rpId: requestBody.rp_id,
      path: '/registration/threshold-ed25519/hss/prepare',
      requestBody,
    });
    const prepareUrl = joinUrlPath(
      registrationTransport.relayerUrl,
      '/registration/threshold-ed25519/hss/prepare',
    );
    response = await fetchWithRegistrationTimeout({
      url: prepareUrl,
      operation: 'Threshold Ed25519 HSS registration prepare',
      init: {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(requestBody),
      },
    });
  } else {
    const prepareUrl =
      replaceUrlPathSuffix(
        registrationTransport.bootstrapUrl,
        '/registration/bootstrap',
        '/registration/threshold-ed25519/hss/prepare',
      ) ||
      joinUrlPath(
        registrationTransport.bootstrapUrl,
        '/registration/threshold-ed25519/hss/prepare',
      );
    response = await fetchWithRegistrationTimeout({
      url: prepareUrl,
      operation: 'Threshold Ed25519 HSS registration prepare',
      init: {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
      },
    });
  }

  const result = (await readJsonObject(
    response,
  )) as unknown as ThresholdEd25519HssPrepareForRegistrationResponse;
  if (!response.ok || result.ok !== true || !result.serverMessage) {
    const failure = result as Extract<
      ThresholdEd25519HssPrepareForRegistrationResponse,
      { ok: false }
    >;
    throw new Error(String(failure.message || failure.code || `HTTP ${response.status}`).trim());
  }
  return result.serverMessage;
}

export async function finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration(args: {
  context: PasskeyManagerContext;
  nearAccountId: string;
  rpId: string;
  hssContext: ThresholdEd25519HssCanonicalContext;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  evaluationResult: ThresholdEd25519HssEvaluationResultEnvelope;
}): Promise<ThresholdEd25519RegistrationHssFinalizeResult> {
  const finalizeStartedAt = performance.now();
  const registrationTransport = resolveRegistrationTransport(args.context);
  const requestBody = {
    new_account_id: String(args.nearAccountId || '').trim(),
    rp_id: String(args.rpId || '').trim(),
    context: args.hssContext,
    preparedSession: args.preparedSession,
    evaluationResult: args.evaluationResult,
  };
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  let response: Response;

  if (registrationTransport.mode === 'managed') {
    const token = await issueManagedRegistrationBootstrapTokenForRequest({
      registrationTransport,
      nearAccountId: requestBody.new_account_id,
      rpId: requestBody.rp_id,
      path: '/registration/threshold-ed25519/hss/finalize',
      requestBody,
    });
    const finalizeUrl = joinUrlPath(
      registrationTransport.relayerUrl,
      '/registration/threshold-ed25519/hss/finalize',
    );
    response = await fetchWithRegistrationTimeout({
      url: finalizeUrl,
      operation: 'Threshold Ed25519 HSS registration finalize',
      init: {
        method: 'POST',
        headers: {
          ...headers,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(requestBody),
      },
    });
  } else {
    const finalizeUrl =
      replaceUrlPathSuffix(
        registrationTransport.bootstrapUrl,
        '/registration/bootstrap',
        '/registration/threshold-ed25519/hss/finalize',
      ) ||
      joinUrlPath(
        registrationTransport.bootstrapUrl,
        '/registration/threshold-ed25519/hss/finalize',
      );
    response = await fetchWithRegistrationTimeout({
      url: finalizeUrl,
      operation: 'Threshold Ed25519 HSS registration finalize',
      init: {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
      },
    });
  }

  const result = (await readJsonObject(
    response,
  )) as unknown as ThresholdEd25519HssFinalizeForRegistrationResponse;
  console.debug('[Registration] threshold-ed25519 HSS finalize response received', {
    durationMs: Math.round(performance.now() - finalizeStartedAt),
    status: response.status,
  });
  if (!response.ok || result.ok !== true || !result.finalizedReport) {
    const failure = result as Extract<
      ThresholdEd25519HssFinalizeForRegistrationResponse,
      { ok: false }
    >;
    throw new Error(String(failure.message || failure.code || `HTTP ${response.status}`).trim());
  }
  return {
    finalizedReport: result.finalizedReport,
    publicKey: String(result.publicKey || '').trim(),
    relayerKeyId: String(result.relayerKeyId || '').trim(),
  };
}

/**
 * HTTP Request body for the relay server's /registration/bootstrap endpoint
 */
type ThresholdEd25519RegistrationSessionPolicy = Omit<Ed25519SessionPolicy, 'relayerKeyId'> & {
  relayerKeyId?: string;
};
type ThresholdEcdsaRegistrationSessionPolicy = Omit<EcdsaSessionPolicy, 'relayerKeyId'> & {
  relayerKeyId?: string;
};

export interface CreateAccountAndRegisterThresholdEd25519Input {
  keyVersion: string;
  recoveryExportCapable: true;
  publicKey: string;
  relayerKeyId: string;
  sessionPolicy: ThresholdEd25519RegistrationSessionPolicy;
  sessionKind: 'jwt' | 'cookie';
}

export type CreateAccountAndRegisterThresholdEd25519Response = {
  keyVersion: string;
  recoveryExportCapable: true;
  publicKey: string;
  relayerKeyId: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  session?: {
    sessionKind: 'jwt' | 'cookie';
    sessionId: string;
    expiresAtMs: number;
    expiresAt?: string;
    participantIds?: number[];
    remainingUses?: number;
    runtimeSnapshotScope?: ThresholdRuntimeSnapshotScope;
    jwt?: string;
  };
};

export type ThresholdEd25519RegistrationHssFinalizeResult = {
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  publicKey: string;
  relayerKeyId: string;
};

function buildThresholdEd25519RegistrationRequest(
  input?: CreateAccountAndRegisterThresholdEd25519Input,
): CreateAccountAndRegisterUserRequest['threshold_ed25519'] | undefined {
  const thresholdEd25519 = input;
  if (!thresholdEd25519?.relayerKeyId) return undefined;
  return {
    key_version: thresholdEd25519.keyVersion,
    recovery_export_capable: thresholdEd25519.recoveryExportCapable,
    public_key: thresholdEd25519.publicKey,
    relayer_key_id: thresholdEd25519.relayerKeyId,
    session_policy: thresholdEd25519.sessionPolicy,
    session_kind: thresholdEd25519.sessionKind,
  };
}

function normalizeThresholdEd25519RegistrationResult(
  thresholdEd25519: CreateAccountAndRegisterResult['thresholdEd25519'],
): CreateAccountAndRegisterThresholdEd25519Response | undefined {
  if (!thresholdEd25519) return undefined;
  const keyVersion = String(thresholdEd25519.keyVersion || '').trim();
  const publicKey = String(thresholdEd25519.publicKey || '').trim();
  const relayerKeyId = String(thresholdEd25519.relayerKeyId || '').trim();
  if (
    !keyVersion ||
    thresholdEd25519.recoveryExportCapable !== true ||
    !publicKey ||
    !relayerKeyId
  ) {
    throw new Error('Atomic registration returned incomplete threshold-ed25519 key material');
  }
  return {
    keyVersion,
    recoveryExportCapable: true,
    publicKey,
    relayerKeyId,
    clientParticipantId: thresholdEd25519.clientParticipantId,
    relayerParticipantId: thresholdEd25519.relayerParticipantId,
    participantIds: thresholdEd25519.participantIds,
    session: thresholdEd25519.session
      ? {
          sessionKind: thresholdEd25519.session.sessionKind,
          sessionId: thresholdEd25519.session.sessionId,
          expiresAtMs: thresholdEd25519.session.expiresAtMs,
          expiresAt: thresholdEd25519.session.expiresAt,
          participantIds: thresholdEd25519.session.participantIds,
          remainingUses: thresholdEd25519.session.remainingUses,
          runtimeSnapshotScope: thresholdEd25519.session.runtimeSnapshotScope,
          jwt: thresholdEd25519.session.jwt,
        }
      : undefined,
  };
}

export interface CreateAccountAndRegisterUserRequest {
  new_account_id: string;
  device_number: number;
  threshold_ed25519?: {
    key_version: string;
    recovery_export_capable: boolean;
    public_key: string;
    relayer_key_id: string;
    session_policy: ThresholdEd25519RegistrationSessionPolicy;
    session_kind: 'jwt' | 'cookie';
  };
  threshold_ecdsa?: {
    client_verifying_share_b64u: string;
    session_policy: ThresholdEcdsaRegistrationSessionPolicy;
    session_kind: 'jwt' | 'cookie';
    smart_account_targets?: CreateAccountAndRegisterSmartAccountTarget[];
  };
  rp_id: string;
  webauthn_registration: WebAuthnRegistrationCredential;
  authenticator_options?: AuthenticatorOptions;
}

/**
 * Create account and register user using relay-server atomic endpoint
 * Makes a single call to the relay-server's /registration/bootstrap endpoint
 */
export async function createAccountAndRegisterWithRelayServer(
  context: PasskeyManagerContext,
  nearAccountId: string,
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
  rpId: string,
  authenticatorOptions?: AuthenticatorOptions,
  onEvent?: (event: RegistrationSSEEvent) => void,
  opts?: {
    thresholdEd25519?: CreateAccountAndRegisterThresholdEd25519Input;
    thresholdEcdsa?: {
      clientVerifyingShareB64u: string;
      sessionPolicy: ThresholdEcdsaRegistrationSessionPolicy;
      sessionKind: 'jwt' | 'cookie';
      smartAccountTargets?: CreateAccountAndRegisterSmartAccountTarget[];
    };
  },
): Promise<{
  success: boolean;
  transactionId?: string;
  thresholdEd25519?: CreateAccountAndRegisterThresholdEd25519Response;
  thresholdEcdsa?: {
    relayerKeyId: string;
    groupPublicKeyB64u: string;
    ethereumAddress: string;
    relayerVerifyingShareB64u: string;
    participantIds?: number[];
    session?: {
      sessionKind: 'jwt' | 'cookie';
      sessionId: string;
      expiresAtMs: number;
      expiresAt?: string;
      participantIds?: number[];
      remainingUses?: number;
      runtimeSnapshotScope?: ThresholdRuntimeSnapshotScope;
      jwt?: string;
    };
  };
  smartAccountDeployments?: CreateAccountAndRegisterSmartAccountDeployment[];
  error?: string;
  errorCode?: RegistrationErrorCode;
}> {
  const { configs } = context;

  if (!configs.network.relayer.url) {
    throw new Error('Relay server URL is required for atomic registration');
  }

  try {
    onEvent?.({
      step: 4,
      phase: RegistrationPhase.STEP_4_ACCESS_KEY_ADDITION,
      status: RegistrationStatus.PROGRESS,
      message: 'Creating account and adding access key...',
    });

    // Serialize the WebAuthn credential properly for the contract.
    // Accept both live PublicKeyCredential and already-serialized credentials from secureConfirm.
    const isSerialized = isSerializedRegistrationCredential(credential);

    // Ensure proper serialization + normalization regardless of source
    const serialized: WebAuthnRegistrationCredential = isSerialized
      ? normalizeRegistrationCredential(credential)
      : serializeRegistrationCredential(credential);

    // Strip PRF outputs before sending to relay/contract
    const serializedCredential =
      redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(serialized);
    // Normalize transports to an array (avoid null)
    if (!Array.isArray(serializedCredential?.response?.transports)) {
      serializedCredential.response.transports = [];
    }

    const thresholdEd25519Request = buildThresholdEd25519RegistrationRequest(
      opts?.thresholdEd25519,
    );

    const requestData: CreateAccountAndRegisterUserRequest = {
      new_account_id: nearAccountId,
      device_number: 1, // First device gets device number 1 (1-indexed)
      ...(thresholdEd25519Request ? { threshold_ed25519: thresholdEd25519Request } : {}),
      ...(opts?.thresholdEcdsa?.clientVerifyingShareB64u
        ? {
            threshold_ecdsa: {
              client_verifying_share_b64u: opts.thresholdEcdsa.clientVerifyingShareB64u,
              session_policy: opts.thresholdEcdsa.sessionPolicy,
              session_kind: opts.thresholdEcdsa.sessionKind,
              ...(Array.isArray(opts.thresholdEcdsa.smartAccountTargets) &&
              opts.thresholdEcdsa.smartAccountTargets.length > 0
                ? { smart_account_targets: opts.thresholdEcdsa.smartAccountTargets }
                : {}),
            },
          }
        : {}),
      rp_id: String(rpId || '').trim(),
      webauthn_registration: serializedCredential,
      authenticator_options: cloneAuthenticatorOptions(
        authenticatorOptions ?? context.configs.webauthn.authenticatorOptions,
      ),
    };

    onEvent?.({
      step: 5,
      phase: RegistrationPhase.STEP_5_CONTRACT_REGISTRATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Registering user with relay...',
    });

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const registrationTransport = resolveRegistrationTransport(context);
    let response: Response;
    let result: CreateAccountAndRegisterResult;

    if (registrationTransport.mode === 'managed') {
      const requestHashSha256 = await computeRegistrationBootstrapRequestHashSha256(requestData);
      const managedGrant = await requestManagedRegistrationBootstrapGrant({
        relayerUrl: registrationTransport.relayerUrl,
        publishableKey: registrationTransport.publishableKey,
        environmentId: registrationTransport.environmentId,
        nearAccountId,
        rpId: requestData.rp_id,
        requestHashSha256,
      });
      const registrationBootstrapUrl = joinUrlPath(
        configs.network.relayer.url,
        '/registration/bootstrap',
      );
      if (!registrationBootstrapUrl) {
        throw new Error('Relay server URL is required for managed passkey registration');
      }
      response = await fetchWithRegistrationTimeout({
        url: registrationBootstrapUrl,
        operation: 'Managed passkey registration bootstrap',
        init: {
          method: 'POST',
          headers: {
            ...headers,
            Authorization: `Bearer ${managedGrant.token}`,
          },
          body: JSON.stringify(requestData),
        },
      });
      result = (await readJsonObject(response)) as unknown as CreateAccountAndRegisterResult;
    } else {
      if (!registrationTransport.bootstrapUrl) {
        throw new Error('Registration bootstrap URL is required for passkey registration');
      }
      response = await fetchWithRegistrationTimeout({
        url: registrationTransport.bootstrapUrl,
        operation: 'Passkey registration bootstrap',
        init: {
          method: 'POST',
          headers,
          body: JSON.stringify(requestData),
        },
      });
      result = (await readJsonObject(response)) as unknown as CreateAccountAndRegisterResult;
    }

    const responseCode = String(result.code || '').trim();
    const responseMessage =
      result.error || result.message || `HTTP ${response.status}: ${response.statusText}`;

    if (!response.ok) {
      if (isRegistrationErrorCode(responseCode)) {
        throw new RelayRegistrationError({
          code: responseCode,
          status: response.status,
          message: responseMessage,
        });
      }
      throw new Error(
        improveAtomicRegistrationError({
          raw: responseMessage,
          nearAccountId,
          relayUrl: configs.network.relayer.url,
        }),
      );
    }

    if (!result.success) {
      if (isRegistrationErrorCode(responseCode)) {
        throw new RelayRegistrationError({
          code: responseCode,
          status: response.status,
          message: responseMessage,
        });
      }
      throw new Error(responseMessage || 'Atomic registration failed');
    }

    const normalizedThresholdEd25519 = normalizeThresholdEd25519RegistrationResult(
      result.thresholdEd25519,
    );

    onEvent?.({
      step: 5,
      phase: RegistrationPhase.STEP_5_CONTRACT_REGISTRATION,
      status: RegistrationStatus.SUCCESS,
      message: 'User registered successfully',
    });

    return {
      success: true,
      transactionId: result.transactionHash,
      thresholdEd25519: normalizedThresholdEd25519,
      thresholdEcdsa: result.thresholdEcdsa
        ? {
            relayerKeyId: result.thresholdEcdsa.relayerKeyId,
            groupPublicKeyB64u: result.thresholdEcdsa.groupPublicKeyB64u,
            ethereumAddress: result.thresholdEcdsa.ethereumAddress,
            relayerVerifyingShareB64u: result.thresholdEcdsa.relayerVerifyingShareB64u,
            participantIds: result.thresholdEcdsa.participantIds,
            session: result.thresholdEcdsa.session
              ? {
                  sessionKind: result.thresholdEcdsa.session.sessionKind,
                  sessionId: result.thresholdEcdsa.session.sessionId,
                  expiresAtMs: result.thresholdEcdsa.session.expiresAtMs,
                  expiresAt: result.thresholdEcdsa.session.expiresAt,
                  participantIds: result.thresholdEcdsa.session.participantIds,
                  remainingUses: result.thresholdEcdsa.session.remainingUses,
                  jwt: result.thresholdEcdsa.session.jwt,
                }
              : undefined,
          }
        : undefined,
      smartAccountDeployments: Array.isArray(result.smartAccountDeployments)
        ? result.smartAccountDeployments
        : undefined,
    };
  } catch (error: unknown) {
    console.error('Atomic registration failed:', error);
    const code = isRelayRegistrationError(error) ? error.code : undefined;

    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: 'Registration failed',
      error: errorMessage(error),
    });

    return {
      success: false,
      error: errorMessage(error),
      ...(code ? { errorCode: code } : {}),
    };
  }
}
